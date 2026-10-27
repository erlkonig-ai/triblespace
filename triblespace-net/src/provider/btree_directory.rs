//! The four-index BTree directory this crate shipped until the dense
//! [`ProviderDirectory`] replaced it, kept verbatim as a test-only reference.
//! Differential tests hold the dense layout to its exact behaviour: every
//! capacity decision, lease, reply, sample, and bounded-prune order.

#![allow(dead_code)]

use super::*;

/// A membership's place: its key's XOR distance from this node, then its rank.
pub(super) type RankedMembership = ([u8; 32], ProviderRank, PeerId);

pub(super) struct BTreeDirectory {
    pub(super) local_id: PeerId,
    pub(super) salt: [u8; 32],
    pub(super) sampler: StdRng,
    pub(super) ranked: BTreeMap<RankedMembership, (Mono, ProviderToken)>,
    pub(super) members_per_key: BTreeMap<ProviderKey, usize>,
    pub(super) deadlines: BTreeSet<(Mono, ProviderKey, PeerId)>,
    pub(super) limits: DirectoryLimits,
}

impl BTreeDirectory {
    pub(super) fn new(local_id: PeerId) -> Self {
        Self::with_sampler(local_id, StdRng::from_entropy())
    }

    /// The salt is the sampler's first draw.
    pub(super) fn with_sampler(local_id: PeerId, mut sampler: StdRng) -> Self {
        Self {
            local_id,
            salt: sampler.r#gen(),
            sampler,
            ranked: BTreeMap::new(),
            members_per_key: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            limits: DirectoryLimits {
                lease: PROVIDER_LEASE_LIFETIME,
                memberships: MAX_PROVIDER_MEMBERSHIPS,
            },
        }
    }

    /// O(1) retained soft-state counts; expired entries may await bounded prune.
    pub(super) fn retained_counts(&self) -> (usize, usize) {
        (self.ranked.len(), self.members_per_key.len())
    }

    /// Install or renew one exact membership. A renewal keeps its place and
    /// only extends its lease. A newcomer to a key at its stored cap is kept
    /// only if it ranks below the key's largest-ranked member, which it evicts.
    pub(super) fn put(
        &mut self,
        key: ProviderKey,
        provider: PeerId,
        token: ProviderToken,
        now: Mono,
    ) -> bool {
        self.prune_expired(now);
        let full = self.fit_key(key, now);
        let place = self.place(key, provider);
        if let Some((previous, _)) = self.ranked.get(&place).copied() {
            self.deadlines.remove(&(previous, key, provider));
        } else {
            if full {
                let (largest, _) = self
                    .key_range(key)
                    .next_back()
                    .expect("a key at its stored cap has members");
                let largest = *largest;
                if place >= largest {
                    return false;
                }
                self.remove_membership(key, largest.2);
            } else if self.ranked.len() >= self.limits.memberships {
                let Some((&farthest, _)) = self.ranked.last_key_value() else {
                    return false;
                };
                if place >= farthest {
                    return false;
                }
                // XOR with the local id is its own inverse.
                self.remove_membership(self.distance(farthest.0), farthest.2);
            }
            *self.members_per_key.entry(key).or_default() += 1;
        }

        let expires_at = now + self.limits.lease;
        self.ranked.insert(place, (expires_at, token));
        self.deadlines.insert((expires_at, key, provider));
        true
    }

    /// Per-key storage: an even share of the remaining membership budget,
    /// never less than one full reply nor more than the per-key ceiling. It
    /// shrinks as memberships and keys grow.
    pub(super) fn stored_cap(&self) -> usize {
        (self.limits.memberships.saturating_sub(self.ranked.len())
            / self.members_per_key.len().max(1))
        .clamp(MAX_PROVIDERS_PER_REPLY, MAX_PROVIDERS_STORED_PER_KEY)
    }

    pub(super) fn key_len(&self, key: ProviderKey) -> usize {
        self.members_per_key.get(&key).copied().unwrap_or(0)
    }

    /// Bring one key within its stored cap, which may have shrunk since the
    /// key last grew: expired members go first, then the largest-ranked live
    /// ones. Returns whether the key is still full, so a newcomer must outrank
    /// a member. Global expiry cleanup remains bounded, but unrelated older
    /// entries must never make a live insertion spuriously observe a full key.
    pub(super) fn fit_key(&mut self, key: ProviderKey, now: Mono) -> bool {
        if self.key_len(key) < self.stored_cap() {
            return false;
        }
        let expired = self
            .key_range(key)
            .filter(|(_, (expires_at, _))| *expires_at <= now)
            .map(|((_, _, provider), _)| *provider)
            .collect::<Vec<_>>();
        for provider in expired {
            self.remove_membership(key, provider);
        }
        while self.key_len(key) > self.stored_cap() {
            let ((_, _, largest), _) = self
                .key_range(key)
                .next_back()
                .expect("a key above its stored cap has members");
            self.remove_membership(key, *largest);
        }
        self.key_len(key) >= self.stored_cap()
    }

    /// Return the live providers retained for one exact rendezvous key, in
    /// peer-id order. Above the reply limit each call draws a fresh uniform
    /// sample, so repeated requests reach every stored member.
    pub(super) fn get(&mut self, key: ProviderKey, now: Mono) -> Vec<(PeerId, ProviderToken)> {
        self.prune_expired(now);
        self.fit_key(key, now);
        let mut live = self
            .key_range(key)
            .filter(|(_, (expires_at, _))| *expires_at > now)
            .map(|((_, _, provider), (_, token))| (*provider, *token))
            .collect::<Vec<_>>();
        live.sort_unstable_by_key(|(provider, _)| *provider);
        if live.len() > MAX_PROVIDERS_PER_REPLY {
            live = live
                .choose_multiple(&mut self.sampler, MAX_PROVIDERS_PER_REPLY)
                .copied()
                .collect();
            live.sort_unstable_by_key(|(provider, _)| *provider);
        }
        live
    }

    /// The token-bearing hints this node answers for one exact key: its
    /// directory sample, led by this node's own current hint when `resident`
    /// names the blob behind the key. That hint replaces any stored self
    /// entry and, in a full reply, one uniformly chosen other entry.
    pub(super) fn hints(
        &mut self,
        key: ProviderKey,
        now: Mono,
        resident: Option<[u8; 32]>,
    ) -> Vec<(PeerId, ProviderToken)> {
        let mut hints = self.get(key, now);
        if let Some(handle) = resident {
            hints.retain(|(provider, _)| *provider != self.local_id);
            if hints.len() == MAX_PROVIDERS_PER_REPLY {
                hints.remove(self.sampler.gen_range(0..hints.len()));
            }
            hints.insert(
                0,
                (self.local_id, blob_provider_token(handle, self.local_id)),
            );
        }
        hints
    }

    pub(super) fn prune_expired(&mut self, now: Mono) {
        for _ in 0..MAX_EXPIRED_PROVIDER_MEMBERSHIPS_PER_CALL {
            let Some((expires_at, key, provider)) = self.deadlines.first().copied() else {
                break;
            };
            if expires_at > now {
                break;
            }
            self.deadlines.remove(&(expires_at, key, provider));
            if self
                .ranked
                .get(&self.place(key, provider))
                .is_none_or(|(deadline, _)| *deadline != expires_at)
            {
                continue;
            }
            self.remove_membership(key, provider);
        }
    }

    pub(super) fn distance(&self, key: ProviderKey) -> [u8; 32] {
        std::array::from_fn(|index| key[index] ^ self.local_id[index])
    }

    pub(super) fn rank(&self, key: ProviderKey, provider: PeerId) -> ProviderRank {
        let mut block = [0; 64];
        block[..32].copy_from_slice(&key);
        block[32..].copy_from_slice(&provider);
        *blake3::keyed_hash(&self.salt, &block).as_bytes()
    }

    pub(super) fn place(&self, key: ProviderKey, provider: PeerId) -> RankedMembership {
        (self.distance(key), self.rank(key, provider), provider)
    }

    /// One key's ranked members with their leases, smallest rank first.
    pub(super) fn key_range(
        &self,
        key: ProviderKey,
    ) -> impl DoubleEndedIterator<Item = (&RankedMembership, &(Mono, ProviderToken))> {
        let distance = self.distance(key);
        self.ranked
            .range((distance, [0; 32], [0; 32])..=(distance, [u8::MAX; 32], [u8::MAX; 32]))
    }

    pub(super) fn remove_membership(&mut self, key: ProviderKey, provider: PeerId) {
        let Some((deadline, _)) = self.ranked.remove(&self.place(key, provider)) else {
            return;
        };
        self.deadlines.remove(&(deadline, key, provider));
        let remove_key = {
            let members = self
                .members_per_key
                .get_mut(&key)
                .expect("stored membership counts toward its exact key");
            *members -= 1;
            *members == 0
        };
        if remove_key {
            self.members_per_key.remove(&key);
        }
    }

    pub(super) fn with_limits(lease: Duration, memberships: usize) -> Self {
        Self {
            limits: DirectoryLimits { lease, memberships },
            ..Self::new([0; 32])
        }
    }
}

mod tests {
    use super::*;

    type Lease = (Mono, ProviderToken);
    /// Every membership with its lease, every `(deadline, key, provider)`,
    /// and the farthest membership.
    type State = (
        BTreeMap<(ProviderKey, PeerId), Lease>,
        BTreeSet<(Mono, ProviderKey, PeerId)>,
        Option<(ProviderKey, PeerId)>,
    );

    fn reference_state(directory: &BTreeDirectory) -> State {
        let members = directory
            .ranked
            .iter()
            .map(|((distance, _, provider), lease)| {
                ((directory.distance(*distance), *provider), *lease)
            })
            .collect();
        let farthest = directory
            .ranked
            .last_key_value()
            .map(|((distance, _, provider), _)| (directory.distance(*distance), *provider));
        (members, directory.deadlines.clone(), farthest)
    }

    /// The dense directory's state, after checking its internal invariants:
    /// strict rank order within each group, the membership count, the
    /// deadline index, and the provider table's reference counts.
    fn dense_state(directory: &ProviderDirectory) -> State {
        let mut members = BTreeMap::new();
        let mut deadlines = BTreeSet::new();
        let mut indexed = BTreeSet::new();
        let mut references = HashMap::<PeerId, u32>::new();
        for (distance, group) in &directory.groups {
            assert!(!group.is_empty(), "groups are never empty");
            let key = directory.distance(*distance);
            let order = group
                .iter()
                .map(|member| {
                    let provider = directory.peers.peer(member.provider);
                    (directory.rank(key, provider), provider)
                })
                .collect::<Vec<_>>();
            assert!(order.windows(2).all(|pair| pair[0] < pair[1]));
            for member in group.iter() {
                let provider = directory.peers.peer(member.provider);
                members.insert((key, provider), (member.expires_at, member.token));
                deadlines.insert((member.expires_at, key, provider));
                indexed.insert((member.expires_at, key));
                *references.entry(provider).or_default() += 1;
            }
        }
        assert_eq!(members.len(), directory.memberships);
        assert_eq!(indexed, directory.deadlines);
        assert_eq!(references.len(), directory.peers.index.len());
        for (provider, count) in references {
            let index = directory.peers.find(provider).unwrap();
            assert_eq!(directory.peers.slots[index as usize], (provider, count));
        }
        let farthest = directory.groups.last_key_value().map(|(distance, group)| {
            (
                directory.distance(*distance),
                directory.peers.peer(group.last().unwrap().provider),
            )
        });
        (members, deadlines, farthest)
    }

    fn same(reference: &BTreeDirectory, dense: &ProviderDirectory) {
        assert_eq!(reference.retained_counts(), dense.retained_counts());
        assert_eq!(reference_state(reference), dense_state(dense));
    }

    fn pair(
        local: PeerId,
        seed: u64,
        limits: DirectoryLimits,
    ) -> (BTreeDirectory, ProviderDirectory) {
        (
            BTreeDirectory {
                limits,
                ..BTreeDirectory::with_sampler(local, StdRng::seed_from_u64(seed))
            },
            ProviderDirectory {
                limits,
                ..ProviderDirectory::with_sampler(local, StdRng::seed_from_u64(seed))
            },
        )
    }

    #[test]
    fn dense_directory_matches_the_btree_reference() {
        let mut rng = StdRng::seed_from_u64(0xD15E_C7);
        let locators: Vec<ProviderKey> = (0..96).map(|_| rng.r#gen()).collect();
        let providers: Vec<PeerId> = (0..160).map(|_| rng.r#gen()).collect();
        for capacity in [0, 1, 31, 64, 65, 200, 512, 4096] {
            for lease in [Duration::from_secs(1), Duration::from_secs(60)] {
                let limits = DirectoryLimits {
                    lease,
                    memberships: capacity,
                };
                let (mut reference, mut dense) = pair(rng.r#gen(), rng.r#gen(), limits);
                let mut now = crate::clock::mono_now();
                for step in 0..3000 {
                    // Runs at one instant tie deadlines; long jumps expire
                    // more than one prune budget at once.
                    match rng.gen_range(0..100) {
                        0..=59 => {}
                        60..=94 => now = now + Duration::from_millis(rng.gen_range(1..400)),
                        _ => now = now + lease * rng.gen_range(1..4),
                    }
                    // Half the traffic goes to four locators, which fill
                    // their stored caps.
                    let locator = if rng.gen_bool(0.5) {
                        locators[rng.gen_range(0..4)]
                    } else {
                        locators[rng.gen_range(0..locators.len())]
                    };
                    let provider = providers[rng.gen_range(0..providers.len())];
                    match rng.gen_range(0..10) {
                        0..=6 => {
                            let token: ProviderToken = rng.r#gen();
                            assert_eq!(
                                reference.put(locator, provider, token, now),
                                dense.put(locator, provider, token, now),
                                "put at step {step}"
                            );
                        }
                        7..=8 => assert_eq!(
                            reference.get(locator, now),
                            dense.get(locator, now),
                            "get at step {step}"
                        ),
                        _ => {
                            let resident = rng.gen_bool(0.5).then(|| rng.r#gen());
                            assert_eq!(
                                reference.hints(locator, now, resident),
                                dense.hints(locator, now, resident),
                                "hints at step {step}"
                            );
                        }
                    }
                    same(&reference, &dense);
                }
            }
        }
    }

    /// One key's equal deadlines are pruned in provider order, and a prune
    /// budget that ends inside them leaves the same members behind.
    #[test]
    fn equal_deadlines_prune_in_provider_order_across_budgets() {
        let mut rng = StdRng::seed_from_u64(0xD15E_C8);
        let lease = Duration::from_secs(1);
        let limits = DirectoryLimits {
            lease,
            memberships: 1 << 16,
        };
        let (mut reference, mut dense) = pair(rng.r#gen(), rng.r#gen(), limits);
        let now = crate::clock::mono_now();
        let keys: Vec<ProviderKey> = (0..3).map(|_| rng.r#gen()).collect();
        for (index, key) in keys.iter().enumerate() {
            for _ in 0..(50 + 37 * index) {
                let provider: PeerId = rng.r#gen();
                let token: ProviderToken = rng.r#gen();
                assert!(reference.put(*key, provider, token, now));
                assert!(dense.put(*key, provider, token, now));
            }
        }
        same(&reference, &dense);
        let unrelated: ProviderKey = rng.r#gen();
        let later = now + lease;
        for _ in 0..5 {
            assert_eq!(reference.get(unrelated, later), dense.get(unrelated, later));
            same(&reference, &dense);
        }
        assert_eq!(dense.retained_counts(), (0, 0));
    }

    #[repr(C)]
    #[derive(Debug)]
    struct Mallinfo2 {
        arena: usize,
        ordblks: usize,
        smblks: usize,
        hblks: usize,
        hblkhd: usize,
        usmblks: usize,
        fsmblks: usize,
        uordblks: usize,
        fordblks: usize,
        keepcost: usize,
    }

    unsafe extern "C" {
        fn mallinfo2() -> Mallinfo2;
    }

    /// glibc's in-use heap bytes across every arena, mmapped chunks included.
    fn in_use_bytes() -> usize {
        // SAFETY: mallinfo2 takes no arguments and only reads allocator state.
        let info = unsafe { mallinfo2() };
        info.uordblks + info.hblkhd
    }

    /// Allocator bytes in use per retained membership, for one representation
    /// per process: `cargo test -p triblespace-net --features sim --lib
    /// directory_bytes_per_membership_probe -- --ignored --nocapture
    /// --test-threads=1`. `TRIBLESPACE_DIRECTORY_REPRESENTATION` is `dense`
    /// (default) or `btree`; `TRIBLESPACE_DIRECTORY_KEYS` (default 2,000,000)
    /// random keys each get `TRIBLESPACE_DIRECTORY_PROVIDERS` (default 1)
    /// providers. Every put is one nanosecond after the last, so no two
    /// memberships share a deadline.
    #[test]
    #[ignore = "manual allocator measurement; glibc only"]
    fn directory_bytes_per_membership_probe() {
        let parameter = |name: &str, default: usize| {
            std::env::var(name).map_or(default, |value| value.parse().unwrap())
        };
        let keys = parameter("TRIBLESPACE_DIRECTORY_KEYS", 2_000_000);
        let fanout = parameter("TRIBLESPACE_DIRECTORY_PROVIDERS", 1);
        let mode = std::env::var("TRIBLESPACE_DIRECTORY_REPRESENTATION")
            .unwrap_or_else(|_| "dense".to_owned());
        let mut rng = StdRng::seed_from_u64(0x379);
        let entries: Vec<(ProviderKey, ProviderToken)> =
            (0..keys).map(|_| (rng.r#gen(), rng.r#gen())).collect();
        let providers: Vec<PeerId> = (0..fanout).map(|_| rng.r#gen()).collect();
        let local: PeerId = rng.r#gen();
        let start = crate::clock::mono_now();
        macro_rules! measure {
            ($directory:expr) => {{
                let before = in_use_bytes();
                let mut directory = $directory;
                let mut now = start;
                let inserting = std::time::Instant::now();
                for (key, token) in &entries {
                    for provider in &providers {
                        now = now + Duration::from_nanos(1);
                        assert!(directory.put(*key, *provider, *token, now));
                    }
                }
                let insert = inserting.elapsed();
                let after = in_use_bytes();
                let renewing = std::time::Instant::now();
                for (key, token) in &entries {
                    for provider in &providers {
                        now = now + Duration::from_nanos(1);
                        assert!(directory.put(*key, *provider, *token, now));
                    }
                }
                let renew = renewing.elapsed();
                let getting = std::time::Instant::now();
                for (key, _) in &entries {
                    assert_eq!(std::hint::black_box(directory.get(*key, now)).len(), fanout);
                }
                let get = getting.elapsed();
                let memberships = keys * fanout;
                assert_eq!(directory.retained_counts(), (memberships, keys));
                let bytes = after.saturating_sub(before);
                println!(
                    "directory_bytes mode={mode} keys={keys} providers_per_key={fanout} memberships={memberships} in_use_delta_bytes={bytes} bytes_per_membership={:.1} insert_seconds={:.3} renew_seconds={:.3} get_seconds={:.3}",
                    bytes as f64 / memberships as f64,
                    insert.as_secs_f64(),
                    renew.as_secs_f64(),
                    get.as_secs_f64(),
                );
                std::hint::black_box(directory);
            }};
        }
        match mode.as_str() {
            "dense" => measure!(ProviderDirectory::new(local)),
            "btree" => measure!(BTreeDirectory::new(local)),
            _ => panic!("choose dense or btree"),
        }
    }
}
