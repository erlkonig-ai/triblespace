//! Differential and scale checks for the live two-PATCH provider directory.
//!
//! The four-index BTree reference preserves the previous receiver-local policy.
//! Historical measurements remain in the book: lower retained index memory
//! came with slower renewal and some slower multi-provider insertions.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

// Independent four-index reference retained only for differential tests.
struct BTreeDirectory {
    local_id: PeerId,
    memberships: BTreeMap<(ProviderKey, PeerId), (Mono, ProviderToken)>,
    providers_by_key: BTreeMap<ProviderKey, BTreeSet<PeerId>>,
    deadlines: BTreeSet<(Mono, ProviderKey, PeerId)>,
    responsibility: BTreeSet<([u8; 32], ProviderKey, PeerId)>,
    limits: DirectoryLimits,
}

impl Default for BTreeDirectory {
    fn default() -> Self {
        Self::new([0; 32])
    }
}

impl BTreeDirectory {
    fn new(local_id: PeerId) -> Self {
        Self {
            local_id,
            memberships: BTreeMap::new(),
            providers_by_key: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            responsibility: BTreeSet::new(),
            limits: DirectoryLimits {
                lease: PROVIDER_LEASE_LIFETIME,
                memberships: MAX_PROVIDER_MEMBERSHIPS,
            },
        }
    }

    /// O(1) retained soft-state counts; expired entries may await bounded prune.
    fn retained_counts(&self) -> (usize, usize) {
        (self.memberships.len(), self.providers_by_key.len())
    }

    /// Install or renew one exact membership. Capacity pressure never prevents
    /// an already-admitted live membership from renewing.
    fn put(&mut self, key: ProviderKey, provider: PeerId, token: ProviderToken, now: Mono) -> bool {
        self.prune_expired(now);
        let membership = (key, provider);
        if let Some((previous, _)) = self.memberships.get(&membership).copied() {
            self.deadlines.remove(&(previous, key, provider));
        } else {
            self.prune_expired_key(key, now);
            if self
                .providers_by_key
                .get(&key)
                .is_some_and(|providers| providers.len() >= MAX_PROVIDERS_PER_KEY)
            {
                return false;
            }
            if self.memberships.len() >= self.limits.memberships {
                let candidate = (self.distance(key), key, provider);
                let Some(farthest) = self.responsibility.last().copied() else {
                    return false;
                };
                if candidate >= farthest {
                    return false;
                }
                self.remove_membership(farthest.1, farthest.2);
            }
            self.providers_by_key
                .entry(key)
                .or_default()
                .insert(provider);
            self.responsibility
                .insert((self.distance(key), key, provider));
        }

        let expires_at = now + self.limits.lease;
        self.memberships.insert(membership, (expires_at, token));
        self.deadlines.insert((expires_at, key, provider));
        true
    }

    /// Reclaim the at-most-64 stale memberships that can block this exact key.
    /// Global expiry cleanup remains bounded too, but unrelated older entries
    /// must never make a live insertion spuriously observe a saturated key.
    fn prune_expired_key(&mut self, key: ProviderKey, now: Mono) {
        let expired = self
            .providers_by_key
            .get(&key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|provider| {
                self.memberships
                    .get(&(key, *provider))
                    .is_some_and(|(expires_at, _)| *expires_at <= now)
            })
            .collect::<Vec<_>>();
        for provider in expired {
            self.remove_membership(key, provider);
        }
    }

    /// Return every live provider retained for one exact rendezvous key.
    fn get(&mut self, key: ProviderKey, now: Mono) -> Vec<(PeerId, ProviderToken)> {
        self.prune_expired(now);
        let Some(providers) = self.providers_by_key.get(&key) else {
            return Vec::new();
        };
        let mut result = Vec::with_capacity(MAX_PROVIDERS_PER_KEY.min(providers.len()));
        for provider in providers.iter().copied() {
            if self
                .memberships
                .get(&(key, provider))
                .is_some_and(|(expires_at, _)| *expires_at > now)
            {
                result.push((provider, self.memberships[&(key, provider)].1));
            }
        }
        result
    }

    fn prune_expired(&mut self, now: Mono) {
        for _ in 0..MAX_EXPIRED_PROVIDER_MEMBERSHIPS_PER_CALL {
            let Some((expires_at, key, provider)) = self.deadlines.first().copied() else {
                break;
            };
            if expires_at > now {
                break;
            }
            self.deadlines.remove(&(expires_at, key, provider));
            let membership = (key, provider);
            if self
                .memberships
                .get(&membership)
                .is_none_or(|(deadline, _)| *deadline != expires_at)
            {
                continue;
            }
            self.remove_membership(key, provider);
        }
    }

    fn distance(&self, key: ProviderKey) -> [u8; 32] {
        std::array::from_fn(|index| key[index] ^ self.local_id[index])
    }

    fn remove_membership(&mut self, key: ProviderKey, provider: PeerId) {
        let Some((deadline, _)) = self.memberships.remove(&(key, provider)) else {
            return;
        };
        self.deadlines.remove(&(deadline, key, provider));
        self.responsibility
            .remove(&(self.distance(key), key, provider));
        let remove_key = {
            let providers = self
                .providers_by_key
                .get_mut(&key)
                .expect("stored membership contributes to its exact-key index");
            providers.remove(&provider);
            providers.is_empty()
        };
        if remove_key {
            self.providers_by_key.remove(&key);
        }
    }
}

fn same_state(reference: &BTreeDirectory, candidate: &ProviderDirectory) {
    assert_eq!(reference.retained_counts(), candidate.retained_counts());
    let members = candidate
        .memberships
        .iter()
        .map(|key| {
            (
                candidate.decode_membership(*key),
                *candidate.memberships.get(key).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(reference.memberships, members);
    let deadlines = reference
        .deadlines
        .iter()
        .map(|(deadline, locator, provider)| {
            ProviderDirectory::deadline_key(*deadline, *locator, *provider)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(deadlines, candidate.deadlines.iter().copied().collect());
    assert_eq!(candidate.memberships.len(), candidate.deadlines.len());
    let farthest = reference
        .responsibility
        .last()
        .map(|(_, locator, provider)| (*locator, *provider));
    assert_eq!(
        farthest,
        candidate
            .farthest()
            .map(|key| candidate.decode_membership(key))
    );
}

#[test]
fn patch_directory_matches_capacity_renewal_expiry_and_removal() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    // Enough repeated providers on one locator to exercise the per-key limit,
    // plus many other locators so bounded expiry can leave unrelated entries.
    let mut rng = StdRng::seed_from_u64(181);
    let locators: Vec<ProviderKey> = (0..128).map(|_| rng.r#gen()).collect();
    let providers: Vec<PeerId> = (0..80).map(|_| rng.r#gen()).collect();
    for capacity in [0, 1, 31, 64, 65, 512] {
        let local = rng.r#gen();
        let limits = DirectoryLimits {
            lease: Duration::from_secs(20),
            memberships: capacity,
        };
        let mut reference = BTreeDirectory {
            limits,
            ..BTreeDirectory::new(local)
        };
        let mut candidate = ProviderDirectory {
            limits,
            ..ProviderDirectory::new(local)
        };
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
                    candidate.remove_membership(locator, provider);
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
    let mut reference = BTreeDirectory {
        limits,
        ..BTreeDirectory::new(local)
    };
    let mut candidate = ProviderDirectory {
        limits,
        ..ProviderDirectory::new(local)
    };
    let now = crate::clock::mono_now();
    for locator in [[0; 32], [1; 32], [2; 32]] {
        for byte in 0..64 {
            assert!(reference.put(locator, [byte; 32], [byte; 32], now));
            assert!(candidate.put(locator, [byte; 32], [byte; 32], now));
        }
    }
    assert!(!reference.put([1; 32], [65; 32], [65; 32], now));
    assert!(!candidate.put([1; 32], [65; 32], [65; 32], now));
    let later = now + Duration::from_secs(1);
    assert!(reference.put([1; 32], [32; 32], [255; 32], later));
    assert!(candidate.put([1; 32], [32; 32], [255; 32], later));
    same_state(&reference, &candidate);
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
        "patch" => measure!(ProviderDirectory {
            limits,
            ..ProviderDirectory::new(local)
        }),
        "btree" => measure!(BTreeDirectory {
            limits,
            ..BTreeDirectory::new(local)
        }),
        _ => panic!("choose patch or btree"),
    }
}
