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
