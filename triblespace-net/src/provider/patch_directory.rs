//! A representation experiment, not another provider protocol.
//!
//! One segmented PATCH owns memberships, exact-key counts, and responsibility
//! and rank order. A second PATCH orders deadlines. Differential tests keep the
//! current receiver-local TTL, bounded pruning, bottom-k sampling, and eviction
//! policy. Nothing here persists leases, changes trust, or changes live host
//! behavior.

use super::*;

triblespace_core::key_segmentation!(MembershipSegments, 64, [32, 32]);
triblespace_core::key_schema!(MembershipOrder, MembershipSegments, 64, [0, 1]);

struct PatchDirectory {
    local_id: PeerId,
    salt: [u8; 32],
    sampler: StdRng,
    // !(locator XOR local) | !rank: the first key is the farthest locator's
    // largest-ranked member, and a locator's first suffix is its own. XOR is
    // bijective, so the first segment also identifies an exact locator. The
    // rank hides the provider, so the value carries it.
    members: PATCH<64, MembershipOrder, (PeerId, Mono, ProviderToken)>,
    // deadline | locator | provider preserves the old prune tie-breaking too.
    deadlines: PATCH<72>,
    limits: DirectoryLimits,
}

impl PatchDirectory {
    /// The salt is the sampler's first draw, as in [`ProviderDirectory`].
    fn new(local_id: PeerId, limits: DirectoryLimits, mut sampler: StdRng) -> Self {
        Self {
            local_id,
            salt: sampler.r#gen(),
            sampler,
            members: PATCH::new(),
            deadlines: PATCH::new(),
            limits,
        }
    }

    fn prefix(&self, locator: ProviderKey) -> [u8; 32] {
        std::array::from_fn(|i| !(locator[i] ^ self.local_id[i]))
    }

    fn key(&self, locator: ProviderKey, provider: PeerId) -> [u8; 64] {
        let mut block = [0; 64];
        block[..32].copy_from_slice(&locator);
        block[32..].copy_from_slice(&provider);
        let rank = blake3::keyed_hash(&self.salt, &block);
        let mut key = [0; 64];
        key[..32].copy_from_slice(&self.prefix(locator));
        key[32..].copy_from_slice(&rank.as_bytes().map(|byte| !byte));
        key
    }

    fn decode(&self, key: [u8; 64]) -> (ProviderKey, PeerId) {
        (
            std::array::from_fn(|i| !key[i] ^ self.local_id[i]),
            self.members.get(&key).unwrap().0,
        )
    }

    fn deadline_key(deadline: Mono, locator: ProviderKey, provider: PeerId) -> [u8; 72] {
        let mut key = [0; 72];
        key[..8].copy_from_slice(&deadline.as_nanos().to_be_bytes());
        key[8..40].copy_from_slice(&locator);
        key[40..].copy_from_slice(&provider);
        key
    }

    fn retained_counts(&self) -> (usize, usize) {
        (
            self.members.len() as usize,
            self.members.segmented_len(&[]) as usize,
        )
    }

    fn stored_cap(&self) -> u64 {
        ((self.limits.memberships as u64).saturating_sub(self.members.len())
            / self.members.segmented_len(&[]).max(1))
        .max(MAX_PROVIDERS_PER_REPLY as u64)
    }

    fn largest(&self, prefix: [u8; 32]) -> Option<[u8; 64]> {
        let suffix = self
            .members
            .first_infix_range(&prefix, &[0; 32], &[255; 32])?;
        let mut key = [0; 64];
        key[..32].copy_from_slice(&prefix);
        key[32..].copy_from_slice(&suffix);
        Some(key)
    }

    fn farthest(&self) -> Option<[u8; 64]> {
        // Ordered descent, not an allocated ordered iterator for just one key.
        let prefix = self.members.first_infix_range(&[], &[0; 32], &[255; 32])?;
        self.largest(prefix)
    }

    fn remove(&mut self, key: [u8; 64]) {
        let Some((provider, deadline, _)) = self.members.get(&key).copied() else {
            return;
        };
        let (locator, _) = self.decode(key);
        self.deadlines
            .remove(&Self::deadline_key(deadline, locator, provider));
        self.members.remove(&key);
    }

    fn prune(&mut self, now: Mono) {
        for _ in 0..MAX_EXPIRED_PROVIDER_MEMBERSHIPS_PER_CALL {
            let Some(key) = self.deadlines.first_infix_range(&[], &[0; 72], &[255; 72]) else {
                break;
            };
            if key[..8] > now.as_nanos().to_be_bytes()[..] {
                break;
            }
            let locator = key[8..40].try_into().unwrap();
            let provider = key[40..].try_into().unwrap();
            self.remove(self.key(locator, provider));
        }
    }

    fn fit(&mut self, locator: ProviderKey, now: Mono) -> bool {
        let prefix = self.prefix(locator);
        if self.members.segmented_len(&prefix) < self.stored_cap() {
            return false;
        }
        let mut expired = Vec::new();
        self.members.infixes(&prefix, |suffix: &[u8; 32]| {
            let mut key = [0; 64];
            key[..32].copy_from_slice(&prefix);
            key[32..].copy_from_slice(suffix);
            if self.members.get(&key).unwrap().1 <= now {
                expired.push(key);
            }
        });
        for key in expired {
            self.remove(key);
        }
        while self.members.segmented_len(&prefix) > self.stored_cap() {
            self.remove(self.largest(prefix).unwrap());
        }
        self.members.segmented_len(&prefix) >= self.stored_cap()
    }

    fn put(
        &mut self,
        locator: ProviderKey,
        provider: PeerId,
        token: ProviderToken,
        now: Mono,
    ) -> bool {
        self.prune(now);
        let full = self.fit(locator, now);
        let key = self.key(locator, provider);
        if let Some((_, old, _)) = self.members.get(&key).copied() {
            self.deadlines
                .remove(&Self::deadline_key(old, locator, provider));
        } else if full {
            let largest = self.largest(self.prefix(locator)).unwrap();
            if key <= largest {
                return false;
            }
            self.remove(largest);
        } else if self.members.len() >= self.limits.memberships as u64 {
            let Some(farthest) = self.farthest() else {
                return false;
            };
            if key <= farthest {
                return false;
            }
            self.remove(farthest);
        }
        let deadline = now + self.limits.lease;
        self.members
            .replace(&PatchEntry::with_value(&key, (provider, deadline, token)));
        self.deadlines.insert(&PatchEntry::new(&Self::deadline_key(
            deadline, locator, provider,
        )));
        true
    }

    fn get(&mut self, locator: ProviderKey, now: Mono) -> Vec<(PeerId, ProviderToken)> {
        self.prune(now);
        self.fit(locator, now);
        let prefix = self.prefix(locator);
        let mut live = Vec::with_capacity(self.members.segmented_len(&prefix) as usize);
        self.members.infixes(&prefix, |suffix: &[u8; 32]| {
            let mut key = [0; 64];
            key[..32].copy_from_slice(&prefix);
            key[32..].copy_from_slice(suffix);
            let (provider, deadline, token) = self.members.get(&key).unwrap();
            if *deadline > now {
                live.push((*provider, *token));
            }
        });
        live.sort_unstable_by_key(|entry| entry.0);
        if live.len() > MAX_PROVIDERS_PER_REPLY {
            live = live
                .choose_multiple(&mut self.sampler, MAX_PROVIDERS_PER_REPLY)
                .copied()
                .collect();
            live.sort_unstable_by_key(|entry| entry.0);
        }
        live
    }
}

fn same_state(reference: &ProviderDirectory, candidate: &PatchDirectory) {
    assert_eq!(reference.retained_counts(), candidate.retained_counts());
    let members = candidate
        .members
        .iter()
        .map(|key| {
            let (_, deadline, token) = *candidate.members.get(key).unwrap();
            (candidate.decode(*key), (deadline, token))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(reference.memberships, members);
    let deadlines = reference
        .deadlines
        .iter()
        .map(|(deadline, locator, provider)| {
            PatchDirectory::deadline_key(*deadline, *locator, *provider)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(deadlines, candidate.deadlines.iter().copied().collect());
    assert_eq!(candidate.members.len(), candidate.deadlines.len());
    let farthest = reference
        .ranked
        .last()
        .map(|(distance, _, provider)| (reference.distance(*distance), *provider));
    assert_eq!(
        farthest,
        candidate.farthest().map(|key| candidate.decode(key))
    );
}

#[test]
fn patch_directory_matches_capacity_renewal_expiry_and_removal() {
    // Enough live providers on one locator to fill its stored cap, so
    // newcomers must outrank a member, plus many other locators so bounded
    // expiry can leave unrelated entries.
    let mut rng = StdRng::seed_from_u64(181);
    let locators: Vec<ProviderKey> = (0..128).map(|_| rng.r#gen()).collect();
    let providers: Vec<PeerId> = (0..160).map(|_| rng.r#gen()).collect();
    for capacity in [0, 1, 31, 64, 65, 512] {
        let local = rng.r#gen();
        let limits = DirectoryLimits {
            lease: Duration::from_secs(60),
            memberships: capacity,
        };
        let seed = rng.r#gen();
        let mut reference = ProviderDirectory {
            limits,
            ..ProviderDirectory::with_sampler(local, StdRng::seed_from_u64(seed))
        };
        let mut candidate = PatchDirectory::new(local, limits, StdRng::seed_from_u64(seed));
        let mut now = crate::clock::mono_now();
        for step in 0..4000 {
            let locator = locators[if step % 3 == 0 {
                0
            } else {
                rng.gen_range(0..locators.len())
            }];
            let provider = providers[rng.gen_range(0..providers.len())];
            match rng.gen_range(0..10) {
                0 => {
                    reference.remove_membership(locator, provider);
                    candidate.remove(candidate.key(locator, provider));
                }
                1 | 2 => assert_eq!(reference.get(locator, now), candidate.get(locator, now)),
                _ => {
                    let token = rng.r#gen();
                    assert_eq!(
                        reference.put(locator, provider, token, now),
                        candidate.put(locator, provider, token, now)
                    );
                }
            }
            if step % 211 == 0 {
                now = now + Duration::from_secs(13);
            }
            same_state(&reference, &candidate);
        }
    }
}

#[test]
fn patch_directory_keeps_exact_prune_ties_and_full_key_renewal() {
    let local = [0x5a; 32];
    let limits = DirectoryLimits {
        lease: Duration::from_secs(10),
        memberships: 256,
    };
    let mut reference = ProviderDirectory {
        limits,
        ..ProviderDirectory::with_sampler(local, StdRng::seed_from_u64(182))
    };
    let mut candidate = PatchDirectory::new(local, limits, StdRng::seed_from_u64(182));
    let now = crate::clock::mono_now();
    for locator in [[0; 32], [1; 32], [2; 32]] {
        for byte in 0..64 {
            assert!(reference.put(locator, [byte; 32], [byte; 32], now));
            assert!(candidate.put(locator, [byte; 32], [byte; 32], now));
        }
    }
    // Each key is at its stored cap: newcomers must outrank a member, and a
    // renewal keeps its place.
    for (provider, at) in [(65, now), (32, now + Duration::from_secs(1))] {
        for locator in [[0; 32], [1; 32]] {
            assert_eq!(
                reference.put(locator, [provider; 32], [255; 32], at),
                candidate.put(locator, [provider; 32], [255; 32], at)
            );
            same_state(&reference, &candidate);
        }
    }
    let expired = now + Duration::from_secs(10);
    assert_eq!(
        reference.get([2; 32], expired),
        candidate.get([2; 32], expired)
    );
    same_state(&reference, &candidate); // Exactly the same first 64 removals.
    assert!(reference.put([2; 32], [66; 32], [66; 32], expired));
    assert!(candidate.put([2; 32], [66; 32], [66; 32], expired));
    same_state(&reference, &candidate);
    assert_eq!(
        reference.get([1; 32], expired),
        candidate.get([1; 32], expired)
    );
    same_state(&reference, &candidate);
}

#[test]
#[ignore = "manual directory representation comparison; run each mode in a fresh process"]
fn patch_directory_scale_probe() {
    use std::hint::black_box;
    use std::time::Instant;

    let count = std::env::var("TRIBLESPACE_DIRECTORY_KEYS")
        .ok()
        .map(|value| value.parse().unwrap())
        .unwrap_or(100_000usize);
    let fanout = std::env::var("TRIBLESPACE_DIRECTORY_PROVIDERS")
        .ok()
        .map(|value| value.parse().unwrap())
        .unwrap_or(1usize);
    assert!((1..=64).contains(&fanout));
    let mode = std::env::var("TRIBLESPACE_DIRECTORY_REPRESENTATION")
        .unwrap_or_else(|_| "patch".to_owned());
    let bytes = |domain, index: usize| {
        *blake3::Hasher::new_derive_key(domain)
            .update(&index.to_le_bytes())
            .finalize()
            .as_bytes()
    };
    let entries = (0..count)
        .map(|i| {
            (
                bytes("directory-test-locator", i),
                bytes("directory-test-token", i),
            )
        })
        .collect::<Vec<_>>();
    let providers = (0..fanout)
        .map(|i| bytes("directory-test-provider", i))
        .collect::<Vec<_>>();
    let local = bytes("directory-test-local", 0);
    let limits = DirectoryLimits {
        lease: PROVIDER_LEASE_LIFETIME,
        memberships: count * fanout,
    };
    let now = crate::clock::mono_now();
    let rss = || -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
                .map(|n| n * 1024)
        })
    };
    // Dispatch once: no dyn-call overhead in either measured operation loop.
    macro_rules! measure {
        ($directory:expr) => {{
            let mut directory = $directory;
            let before = rss();
            let start = Instant::now();
            for (locator, token) in &entries {
                for provider in &providers {
                    assert!(directory.put(*locator, *provider, *token, now));
                }
            }
            let insert = start.elapsed();
            let after = rss();
            assert_eq!(directory.retained_counts(), (count * fanout, count));
            let start = Instant::now();
            for (locator, _) in &entries {
                assert_eq!(black_box(directory.get(*locator, now)).len(), fanout);
            }
            let get = start.elapsed();
            let start = Instant::now();
            for (locator, token) in &entries {
                for provider in &providers {
                    assert!(directory.put(*locator, *provider, *token, now + Duration::from_secs(1)));
                }
            }
            let renew = start.elapsed();
            let retained = after.zip(before).map(|(a, b)| a.saturating_sub(b));
            println!("directory_representation mode={mode} keys={count} providers={fanout} memberships={} insert_seconds={:.6} get_seconds={:.6} renew_seconds={:.6} rss_delta_bytes={retained:?}", count * fanout, insert.as_secs_f64(), get.as_secs_f64(), renew.as_secs_f64());
            black_box(directory);
        }};
    }
    match mode.as_str() {
        "patch" => measure!(PatchDirectory::new(local, limits, StdRng::seed_from_u64(0))),
        "btree" => measure!(ProviderDirectory {
            limits,
            ..ProviderDirectory::new(local)
        }),
        _ => panic!("choose patch or btree"),
    }
}
