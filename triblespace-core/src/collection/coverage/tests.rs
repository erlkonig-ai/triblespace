//! The fold's laws, stated as the questions a consumer actually asks.

use ed25519_dalek::SigningKey;

use super::*;
use crate::collection::empty_metadata_handle;
use crate::collection::records::{
    CollectionCommit, CollectionDerive, CollectionHandle, CollectionMerge,
};

fn signer(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn collection(byte: u8) -> CollectionHandle {
    Inline::new([byte; 32])
}

fn data(byte: u8) -> CollectionData {
    Inline::new([byte; 32])
}

fn commit(key: u8, into: CollectionHandle, payload: CollectionData) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &signer(key),
        into,
        payload,
        empty_metadata_handle(),
    ))
}

/// A merge or derive names its input PAYLOAD. This used to wrap it
/// beside a fingerprint citing a record that produced it; nothing
/// cites anything now, so it is just the payload.
fn merge(
    key: u8,
    into: CollectionHandle,
    low: CollectionData,
    high: CollectionData,
    result: CollectionData,
) -> CollectionRecord {
    CollectionRecord::Merge(CollectionMerge::sign(
        &signer(key),
        into,
        low,
        high,
        result,
    ))
}

fn derive(
    key: u8,
    target: CollectionHandle,
    input: CollectionData,
    output: CollectionData,
) -> CollectionRecord {
    CollectionRecord::Derive(CollectionDerive::sign(
        &signer(key),
        target,
        input,
        output,
    ))
}

/// Maps a derived collection to the one it derives from; anything unnamed is
/// a lineage root. Real collections answer this from their descriptor, which
/// is the single hop `StoreWriters` reads.
struct Lineages(std::collections::BTreeMap<CollectionHandle, CollectionHandle>);

impl RecordAdmission for Lineages {
    fn source(&self, collection: CollectionHandle) -> SourceResolution {
        match self.0.get(&collection) {
            Some(source) => SourceResolution::Derived(*source),
            None => SourceResolution::Root,
        }
    }

    fn admits(
        &self,
        _collection: CollectionHandle,
        _signer: Inline<crate::inline::encodings::ed25519::ED25519PublicKey>,
    ) -> Admittance {
        Admittance::Admitted
    }
}

fn projection(hop: usize) -> CollectionHandle {
    let mut raw = [0xEEu8; 32];
    raw[0] = hop as u8;
    Inline::new(raw)
}

fn members(
    index: &CoverageIndex,
    lineage: CollectionHandle,
    node: CollectionData,
) -> Vec<[u8; 32]> {
    index
        .coverage(lineage, node)
        .map(|coverage| coverage.iter_ordered().copied().collect())
        .unwrap_or_default()
}

#[test]
fn a_commit_is_its_own_foundation() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    assert_eq!(members(&index, c, data(1)), vec![[1u8; 32]]);
}

#[test]
fn a_node_nobody_attested_has_no_row_at_all() {
    let index = CoverageIndex::new();
    let c = collection(0);
    assert!(index.coverage(c, data(9)).is_none());
    assert!(!index.covers(c, data(9), data(9)));
}

#[test]
fn a_merge_covers_both_sides() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(2), data(3)), &AdmitEveryRecord);
    assert_eq!(members(&index, c, data(3)), vec![[1u8; 32], [2u8; 32]]);
}

#[test]
fn a_derive_carries_the_support_across_the_lattice_boundary() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, source, data(1)), &lineages);
    index.apply(&commit(1, source, data(2)), &lineages);
    index.apply(&merge(1, source, data(1), data(2), data(3)), &lineages);
    index.apply(&derive(1, target, data(3), data(4)), &lineages);
    // The derived image denotes the same logical value, so it stands for the
    // same foundation commits — not for its own payload. It is a node in the
    // target, reading a node in the source.
    assert_eq!(members(&index, target, data(4)), vec![[1u8; 32], [2u8; 32]]);
}

#[test]
fn records_arriving_before_their_inputs_still_land() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    // Reverse causal order: the derive first, then the merge it consumes, then
    // finally the commits underneath.
    index.apply(&derive(1, target, data(3), data(4)), &lineages);
    index.apply(&merge(1, source, data(1), data(2), data(3)), &lineages);
    assert!(index.coverage(source, data(3)).is_none());
    index.apply(&commit(1, source, data(1)), &lineages);
    // One side is not enough: a merge attests a join, not either half.
    assert!(index.coverage(source, data(3)).is_none());
    index.apply(&commit(1, source, data(2)), &lineages);
    assert_eq!(members(&index, source, data(3)), vec![[1u8; 32], [2u8; 32]]);
    // And the growth propagated through the derive that was already parked.
    assert_eq!(members(&index, target, data(4)), vec![[1u8; 32], [2u8; 32]]);
}

#[test]
fn a_row_that_grows_later_widens_everything_downstream_of_it() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, source, data(1)), &lineages);
    index.apply(&commit(1, source, data(2)), &lineages);
    index.apply(&merge(1, source, data(1), data(2), data(3)), &lineages);
    index.apply(&derive(1, target, data(3), data(4)), &lineages);
    assert_eq!(members(&index, target, data(4)), vec![[1u8; 32], [2u8; 32]]);

    // An alternative route attests that the same result also stands for a
    // third commit. Coverage is a union over routes, so the derived image
    // widens with it without replaying anything.
    index.apply(&commit(1, source, data(5)), &lineages);
    index.apply(&merge(1, source, data(1), data(5), data(3)), &lineages);
    assert_eq!(
        members(&index, target, data(4)),
        vec![[1u8; 32], [2u8; 32], [5u8; 32]]
    );
}

#[test]
fn folding_the_same_record_twice_changes_nothing() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    let records = [
        commit(1, c, data(1)),
        commit(1, c, data(2)),
        merge(1, c, data(1), data(2), data(3)),
    ];
    for record in &records {
        index.apply(record, &AdmitEveryRecord);
    }
    let once = members(&index, c, data(3));
    for record in &records {
        index.apply(record, &AdmitEveryRecord);
    }
    assert_eq!(members(&index, c, data(3)), once);
    assert_eq!(index.len(), 3);
}

#[test]
fn a_cycle_between_a_node_and_its_own_merge_terminates() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    // MERGE(1, 2) -> 1: the result is also one of its own inputs.
    index.apply(&merge(1, c, data(1), data(2), data(1)), &AdmitEveryRecord);
    assert_eq!(members(&index, c, data(1)), vec![[1u8; 32], [2u8; 32]]);
}

/// Admission decided once, at fold time.
struct OnlySigner(u8);

impl RecordAdmission for OnlySigner {
    fn source(&self, _collection: CollectionHandle) -> SourceResolution {
        SourceResolution::Root
    }

    fn admits(
        &self,
        _collection: CollectionHandle,
        candidate: Inline<crate::inline::encodings::ed25519::ED25519PublicKey>,
    ) -> Admittance {
        if candidate.raw == signer(self.0).verifying_key().to_bytes() {
            Admittance::Admitted
        } else {
            Admittance::Pending
        }
    }
}

#[test]
fn a_record_whose_signer_is_not_admitted_yet_is_parked_not_dropped() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &OnlySigner(1));
    index.apply(&commit(2, c, data(2)), &OnlySigner(1));
    index.apply(&merge(2, c, data(1), data(2), data(3)), &OnlySigner(1));

    assert_eq!(members(&index, c, data(1)), vec![[1u8; 32]]);
    assert!(index.coverage(c, data(2)).is_none());
    assert_eq!(index.parked_on_signers(), 2);

    // The proofs arrive, so the oracle's answer changes and the index is
    // re-offered everything it parked. Draining cascades through the merge
    // that needed the newly admitted commit.
    index.resolve(&AdmitEveryRecord);
    assert_eq!(index.parked_on_signers(), 0);
    assert_eq!(members(&index, c, data(2)), vec![[2u8; 32]]);
    assert_eq!(members(&index, c, data(3)), vec![[1u8; 32], [2u8; 32]]);
}

#[test]
fn an_unadmitted_route_contributes_nothing_to_a_node_an_admitted_route_reached() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &OnlySigner(1));
    index.apply(&commit(1, c, data(2)), &OnlySigner(1));
    index.apply(&commit(1, c, data(5)), &OnlySigner(1));
    index.apply(&merge(1, c, data(1), data(2), data(3)), &OnlySigner(1));
    // A second, unadmitted attestation about the same result.
    index.apply(&merge(2, c, data(1), data(5), data(3)), &OnlySigner(1));
    assert_eq!(members(&index, c, data(3)), vec![[1u8; 32], [2u8; 32]]);
}

/// Only a projection needs a descriptor to know where to read.
///
/// A commit and a merge name their own collection and stay inside it, so an
/// unresolvable descriptor never stops them — admission still does, but that
/// is a different question with a different key. A derive is the one
/// attestation whose input lives somewhere the record does not name, and it
/// parks on the exact descriptor whose arrival would tell it where.
#[test]
fn only_a_projection_parks_on_an_unresolvable_descriptor() {
    /// Knows no descriptor at all, which is what a store looks like before
    /// one is resident.
    struct NoDescriptor;
    impl RecordAdmission for NoDescriptor {
        fn source(&self, collection: CollectionHandle) -> SourceResolution {
            SourceResolution::Missing(collection)
        }
        fn admits(
            &self,
            _collection: CollectionHandle,
            _signer: Inline<crate::inline::encodings::ed25519::ED25519PublicKey>,
        ) -> Admittance {
            Admittance::Admitted
        }
    }

    let source = collection(0);
    let target = collection(7);
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, source, data(1)), &NoDescriptor);
    index.apply(&commit(1, source, data(2)), &NoDescriptor);
    index.apply(&merge(1, source, data(1), data(2), data(3)), &NoDescriptor);
    index.apply(&derive(1, target, data(3), data(4)), &NoDescriptor);

    // The source lattice folded without any descriptor at all.
    assert_eq!(members(&index, source, data(3)), vec![[1u8; 32], [2u8; 32]]);
    // The projection could not know which collection to read, so it waits.
    assert!(index.coverage(target, data(4)).is_none());
    assert_eq!(index.parked_on_lineages(), 1);
    assert_eq!(index.parked_on_signers(), 0);

    // The descriptor lands and the projection completes.
    index.settle(
        &Lineages([(target, source)].into_iter().collect()),
        [target],
        false,
    );
    assert_eq!(members(&index, target, data(4)), vec![[1u8; 32], [2u8; 32]]);
    assert_eq!(index.parked(), 0);
}

/// A drain costs the arrivals that happened, not the size of the backlog.
///
/// This is what makes the design work under continuous sync rather than only
/// at the end of a replay: a refresh carrying no descriptor and no proof
/// leaves an un-admittable backlog completely untouched.
#[test]
fn settling_without_the_awaited_arrival_does_nothing() {
    let source = collection(0);
    let target = collection(7);
    let _lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, source, data(1)), &OnlySigner(1));
    index.apply(&commit(2, source, data(2)), &OnlySigner(1));
    assert_eq!(index.parked_on_signers(), 1);

    // A batch with neither a descriptor nor a proof in it.
    index.settle(&OnlySigner(1), [], false);
    assert_eq!(index.parked_on_signers(), 1);
    assert!(index.coverage(source, data(2)).is_none());

    // A batch carrying a proof wakes it.
    index.settle(&AdmitEveryRecord, [], true);
    assert_eq!(index.parked(), 0);
    assert_eq!(members(&index, source, data(2)), vec![[2u8; 32]]);
}

#[test]
fn set_algebra_between_two_nodes_is_patch_algebra() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    for byte in 1..=3u8 {
        index.apply(&commit(1, c, data(byte)), &AdmitEveryRecord);
    }
    index.apply(&merge(1, c, data(1), data(2), data(4)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(2), data(3), data(5)), &AdmitEveryRecord);

    let left = index.coverage(c, data(4)).expect("left row").clone();
    let right = index.coverage(c, data(5)).expect("right row").clone();
    let shared: Vec<_> = left.intersect(&right).iter_ordered().copied().collect();
    assert_eq!(shared, vec![[2u8; 32]]);
    let only_left: Vec<_> = left.difference(&right).iter_ordered().copied().collect();
    assert_eq!(only_left, vec![[1u8; 32]]);
}

/// Two collections holding the same payload bytes do not share a row.
///
/// Content addressing makes a shared handle genuinely the same bytes, but the
/// commits underneath it belong to a collection, and commits from two
/// collections are not comparable. Scoping each row by its collection is what
/// keeps them apart — and it is free, because the commit set is a separate
/// nested trie either way.
#[test]
fn one_payload_in_two_lattices_keeps_two_rows() {
    let mut index = CoverageIndex::new();
    let ledger = collection(0);
    let tally = collection(1);
    let shared = data(3);

    // `shared` is committed on its own authority into `ledger`.
    index.apply(&commit(1, ledger, shared), &AdmitEveryRecord);
    // The very same bytes are the join of two commits in `tally`.
    index.apply(&commit(1, tally, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, tally, data(2)), &AdmitEveryRecord);
    index.apply(&merge(1, tally, data(1), data(2), shared), &AdmitEveryRecord);

    assert_eq!(members(&index, ledger, shared), vec![[3u8; 32]]);
    assert_eq!(
        members(&index, tally, shared),
        vec![[1u8; 32], [2u8; 32]]
    );
}

/// The subsumption verdict a bare result key used to flip.
///
/// Asking "does this node cover everything I need" was always safe, because
/// the needed set is a known universe and a foreign member can never satisfy
/// a real requirement. Asking "does this node subsume that one" — how a cover
/// is minimised — has no universe to intersect against, so a foreign member
/// could make a needed node read as redundant. `alias` covers only commit 1
/// inside `tally`; a foreign lattice attesting that the same payload stands
/// for commit 2 must not reach that row.
#[test]
fn a_foreign_member_cannot_flip_a_subsumption_verdict() {
    let tally = collection(0);
    let ledger = collection(1);
    let alias = data(3);

    let mut index = CoverageIndex::new();
    index.apply(&commit(1, tally, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, tally, data(2)), &AdmitEveryRecord);
    index.apply(&merge(1, tally, data(1), data(1), alias), &AdmitEveryRecord);
    index.apply(&merge(1, tally, data(1), data(2), data(5)), &AdmitEveryRecord);
    // The foreign lattice commits its own copy of the same payload bytes and
    // reaches `alias` by its own route.
    index.apply(&commit(1, ledger, data(2)), &AdmitEveryRecord);
    index.apply(&merge(1, ledger, data(2), data(2), alias), &AdmitEveryRecord);

    let alias_row = index.coverage(tally, alias).expect("row").clone();
    let pair = index.coverage(tally, data(5)).expect("row").clone();
    assert_eq!(
        alias_row.iter_ordered().copied().collect::<Vec<_>>(),
        vec![[1u8; 32]]
    );
    assert!(
        !pair.difference(&alias_row).is_empty(),
        "a node tally still needs must not read as redundant"
    );
    // The foreign route kept its own row, and it says what it actually knows.
    assert_eq!(members(&index, ledger, alias), vec![[2u8; 32]]);
}
/// What building the index on store open actually costs.
///
/// Framing rule: the printed figure is **microseconds per record folded**, in
/// a `--release` build, for one synthetic lattice of `commits` foundation
/// commits LSM-merged pairwise to a single root and then projected through
/// `derive_hops` derived collections. It is the whole cost of
/// [`CoverageIndex`] construction — admission is stubbed open, because the
/// question here is what the fold costs, not what descriptor resolution costs.
/// The alternative it is measured against is the existing per-record work in a
/// maintenance pass, ~9 ms per record in a faculty write chain.
///
/// Measured 2026-09-18 on the GB10 `sky` (aarch64, release): 5.95 µs/record at
/// 821 records, then 2.65 / 2.85 / 2.94 µs/record at 3 445 / 29 961 / 200 001
/// records. Flat across two orders of magnitude, so the fold is linear in
/// records and the doubly nested PATCH is sharing rather than copying. In
/// absolute terms the largest probe — 100 000 commits compacted to one root —
/// builds in 587 ms once, at open; a 30 000-record collection builds in 85 ms.
/// That is about three thousand times cheaper per record than the maintenance
/// pass it serves, which answers whether an index rebuilt on every open is
/// affordable: it is.
#[test]
#[ignore = "timing probe; run with --ignored --nocapture"]
fn folding_a_realistic_lattice_is_cheap_enough_to_do_on_open() {
    fn probe(commits: usize, derive_hops: usize) {
        let source = collection(0);
        let mut records = Vec::new();
        let mut tier: Vec<CollectionData> = Vec::with_capacity(commits);
        for index in 0..commits {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let payload = Inline::new(raw);
            records.push(commit(1, source, payload));
            tier.push(payload);
        }
        // Pairwise compaction upward, exactly the LSM geometry maintenance
        // produces: `commits - 1` joins for `commits` leaves.
        let mut next_result = commits as u64;
        while tier.len() > 1 {
            let mut above = Vec::with_capacity(tier.len().div_ceil(2));
            for pair in tier.chunks(2) {
                if let [low, high] = pair {
                    let mut raw = [0u8; 32];
                    raw[..8].copy_from_slice(&next_result.to_be_bytes());
                    next_result += 1;
                    let result = Inline::new(raw);
                    records.push(merge(1, source, *low, *high, result));
                    above.push(result);
                } else {
                    above.push(pair[0]);
                }
            }
            tier = above;
        }
        let mut carried = tier[0];
        for hop in 0..derive_hops {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&next_result.to_be_bytes());
            next_result += 1;
            let output = Inline::new(raw);
            records.push(derive(1, projection(hop), carried, output));
            carried = output;
        }

        // Each hop derives from the one before it, exactly as a real chain of
        // derived collections does.
        let lineages = Lineages(
            (0..derive_hops)
                .map(|hop| {
                    let from = if hop == 0 { source } else { projection(hop - 1) };
                    (projection(hop), from)
                })
                .collect(),
        );
        let started = std::time::Instant::now();
        let mut index = CoverageIndex::new();
        for record in &records {
            index.apply(record, &lineages);
        }
        let elapsed = started.elapsed();
        let last = if derive_hops == 0 {
            source
        } else {
            projection(derive_hops - 1)
        };
        assert_eq!(
            index.coverage(last, carried).map(|row| row.len()),
            Some(commits as u64)
        );
        println!(
            "{:>7} records ({commits} commits, {derive_hops} derive hops): \
             {:>8.2?} total, {:>6.2} us/record",
            records.len(),
            elapsed,
            elapsed.as_secs_f64() * 1e6 / records.len() as f64,
        );
    }

    probe(410, 2);
    probe(1_722, 2);
    probe(14_980, 2);
    probe(100_000, 2);
}


fn frontier(index: &CoverageIndex, collection: CollectionHandle) -> Vec<[u8; 32]> {
    index
        .published()
        .frontier(collection)
        .map(|node| node.raw)
        .collect()
}

#[test]
fn the_frontier_is_the_set_of_unmerged_nodes() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    for payload in 1..=4 {
        index.apply(&commit(1, c, data(payload)), &AdmitEveryRecord);
    }
    assert_eq!(
        frontier(&index, c),
        vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]
    );
    index.apply(&merge(1, c, data(1), data(2), data(5)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(3), data(4), data(6)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[5u8; 32], [6u8; 32]]);
    index.apply(&merge(1, c, data(5), data(6), data(7)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[7u8; 32]]);
    let (support, unattested) = index.published().frontier_support(c);
    assert!(unattested.is_empty());
    assert_eq!(
        support.iter_ordered().copied().collect::<Vec<_>>(),
        vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]
    );
}

#[test]
fn a_merge_arriving_before_its_inputs_settles_on_the_same_frontier() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&merge(1, c, data(1), data(2), data(5)), &AdmitEveryRecord);
    assert!(frontier(&index, c).is_empty());
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    // One side of a join that is not driven yet stays attachable on its own.
    assert_eq!(frontier(&index, c), vec![[1u8; 32]]);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
}

#[test]
fn a_commit_arriving_after_the_merge_that_consumes_it_is_not_put_back() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(2), data(5)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
    // Driving the same records again moves nothing.
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(2), data(5)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
}

#[test]
fn two_routes_to_one_result_consume_both_routes() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    for payload in 1..=4 {
        index.apply(&commit(1, c, data(payload)), &AdmitEveryRecord);
    }
    index.apply(&merge(1, c, data(1), data(2), data(5)), &AdmitEveryRecord);
    // A second route producing the same payload: its support only grows.
    index.apply(&merge(1, c, data(3), data(4), data(5)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
    assert_eq!(
        members(&index, c, data(5)),
        vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]
    );
}

#[test]
fn a_self_merge_keeps_its_node_on_the_frontier() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(1), data(1)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[1u8; 32]]);
}

#[test]
fn images_join_the_target_frontier_and_a_carry_consumes_them() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, source, data(1)), &lineages);
    index.apply(&commit(1, source, data(2)), &lineages);
    index.apply(&derive(1, target, data(1), data(11)), &lineages);
    index.apply(&derive(1, target, data(2), data(12)), &lineages);
    assert_eq!(frontier(&index, target), vec![[11u8; 32], [12u8; 32]]);
    // The source's frontier is its own: images consume nothing there.
    assert_eq!(frontier(&index, source), vec![[1u8; 32], [2u8; 32]]);
    // A carry inside the target consumes the two images.
    index.apply(&merge(1, target, data(11), data(12), data(13)), &lineages);
    assert_eq!(frontier(&index, target), vec![[13u8; 32]]);
    assert_eq!(members(&index, target, data(13)), vec![[1u8; 32], [2u8; 32]]);
    // A source merge changes the source's frontier, and an image of it lands
    // on the target's beside the carry that already covers the same commits.
    index.apply(&merge(1, source, data(1), data(2), data(3)), &lineages);
    assert_eq!(frontier(&index, source), vec![[3u8; 32]]);
    index.apply(&derive(1, target, data(3), data(13)), &lineages);
    assert_eq!(frontier(&index, target), vec![[13u8; 32]]);
}

#[test]
fn a_commit_written_into_a_derived_collection_attests_nothing() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, target, data(9)), &lineages);
    assert!(index.coverage(target, data(9)).is_none());
    assert!(frontier(&index, target).is_empty());
    assert_eq!(index.parked(), 0);
}
