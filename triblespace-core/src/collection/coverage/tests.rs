//! The fold's laws, stated as the questions a consumer actually asks.

use ed25519_dalek::SigningKey;

use super::*;
use crate::collection::empty_metadata_handle;
use crate::collection::records::{
    CollectionCommit, CollectionDerive, CollectionHandle, CollectionMerge,
    CollectionRecordFingerprint,
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

/// Witness fields are still part of the signed shape; the fold never consults
/// them, which is exactly the property under test.
fn witnessed(
    into: CollectionHandle,
    payload: CollectionData,
) -> (CollectionData, CollectionRecordFingerprint) {
    (payload, commit(31, into, payload).fingerprint())
}

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
        witnessed(into, low),
        witnessed(into, high),
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
        witnessed(target, input),
        output,
    ))
}

fn members(index: &CoverageIndex, node: CollectionData) -> Vec<[u8; 32]> {
    index
        .coverage(node)
        .map(|coverage| coverage.iter_ordered().copied().collect())
        .unwrap_or_default()
}

#[test]
fn a_commit_is_its_own_foundation() {
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, collection(0), data(1)), &AdmitEveryRecord);
    assert_eq!(members(&index, data(1)), vec![[1u8; 32]]);
}

#[test]
fn a_node_nobody_attested_has_no_row_at_all() {
    let index = CoverageIndex::new();
    assert!(index.coverage(data(9)).is_none());
    assert!(!index.covers(data(9), data(9)));
}

#[test]
fn a_merge_covers_both_sides() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(2), data(3)), &AdmitEveryRecord);
    assert_eq!(members(&index, data(3)), vec![[1u8; 32], [2u8; 32]]);
}

#[test]
fn a_derive_carries_the_support_across_the_lattice_boundary() {
    let mut index = CoverageIndex::new();
    let source = collection(0);
    let target = collection(7);
    index.apply(&commit(1, source, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, source, data(2)), &AdmitEveryRecord);
    index.apply(
        &merge(1, source, data(1), data(2), data(3)),
        &AdmitEveryRecord,
    );
    index.apply(&derive(1, target, data(3), data(4)), &AdmitEveryRecord);
    // The derived image denotes the same logical value, so it stands for the
    // same foundation commits — not for its own payload.
    assert_eq!(members(&index, data(4)), vec![[1u8; 32], [2u8; 32]]);
}

#[test]
fn records_arriving_before_their_inputs_still_land() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    // Reverse causal order: the derive first, then the merge it consumes, then
    // finally the commits underneath.
    index.apply(&derive(1, collection(7), data(3), data(4)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(2), data(3)), &AdmitEveryRecord);
    assert!(index.coverage(data(3)).is_none());
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    // One side is not enough: a merge attests a join, not either half.
    assert!(index.coverage(data(3)).is_none());
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    assert_eq!(members(&index, data(3)), vec![[1u8; 32], [2u8; 32]]);
    // And the growth propagated through the derive that was already parked.
    assert_eq!(members(&index, data(4)), vec![[1u8; 32], [2u8; 32]]);
}

#[test]
fn a_row_that_grows_later_widens_everything_downstream_of_it() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(2), data(3)), &AdmitEveryRecord);
    index.apply(&derive(1, collection(7), data(3), data(4)), &AdmitEveryRecord);
    assert_eq!(members(&index, data(4)), vec![[1u8; 32], [2u8; 32]]);

    // An alternative route attests that the same result also stands for a
    // third commit. Coverage is a union over routes, so the derived image
    // widens with it without replaying anything.
    index.apply(&commit(1, c, data(5)), &AdmitEveryRecord);
    index.apply(&merge(1, c, data(1), data(5), data(3)), &AdmitEveryRecord);
    assert_eq!(
        members(&index, data(4)),
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
    let once = members(&index, data(3));
    for record in &records {
        index.apply(record, &AdmitEveryRecord);
    }
    assert_eq!(members(&index, data(3)), once);
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
    assert_eq!(members(&index, data(1)), vec![[1u8; 32], [2u8; 32]]);
}

/// Admission decided once, at fold time.
struct OnlySigner(u8);

impl RecordAdmission for OnlySigner {
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

    assert_eq!(members(&index, data(1)), vec![[1u8; 32]]);
    assert!(index.coverage(data(2)).is_none());
    assert_eq!(index.parked_on_signers(), 2);

    // The proof arrives. Draining one signer cascades through every record it
    // was blocking, including the merge that needed its output.
    index.admit_signer(Inline::new(signer(2).verifying_key().to_bytes()));
    assert_eq!(index.parked_on_signers(), 0);
    assert_eq!(members(&index, data(2)), vec![[2u8; 32]]);
    assert_eq!(members(&index, data(3)), vec![[1u8; 32], [2u8; 32]]);
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
    assert_eq!(members(&index, data(3)), vec![[1u8; 32], [2u8; 32]]);
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

    let left = index.coverage(data(4)).expect("left row").clone();
    let right = index.coverage(data(5)).expect("right row").clone();
    let shared: Vec<_> = left.intersect(&right).iter_ordered().copied().collect();
    assert_eq!(shared, vec![[2u8; 32]]);
    let only_left: Vec<_> = left.difference(&right).iter_ordered().copied().collect();
    assert_eq!(only_left, vec![[1u8; 32]]);
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
            records.push(derive(1, collection(8 + hop as u8), carried, output));
            carried = output;
        }

        let started = std::time::Instant::now();
        let mut index = CoverageIndex::new();
        for record in &records {
            index.apply(record, &AdmitEveryRecord);
        }
        let elapsed = started.elapsed();
        assert_eq!(index.coverage(carried).map(|row| row.len()), Some(commits as u64));
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
