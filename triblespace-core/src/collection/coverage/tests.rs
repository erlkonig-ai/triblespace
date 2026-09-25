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

fn public(byte: u8) -> Inline<ED25519PublicKey> {
    Inline::new(signer(byte).verifying_key().to_bytes())
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

/// A merge names its input PAYLOADS, two to sixteen of them.
fn merge(
    key: u8,
    into: CollectionHandle,
    inputs: &[CollectionData],
    result: CollectionData,
) -> CollectionRecord {
    CollectionRecord::Merge(
        CollectionMerge::sign(&signer(key), into, inputs.iter().copied(), result)
            .expect("fixture merges join two to sixteen distinct inputs"),
    )
}

/// A leaf of `target` mapping the source foundation whose handle is `source`.
fn derive(
    key: u8,
    target: CollectionHandle,
    source: CollectionData,
    output: CollectionData,
) -> CollectionRecord {
    CollectionRecord::Derive(CollectionDerive::sign(
        &signer(key),
        target,
        SourceLocator::of(source.raw),
        output,
    ))
}

/// Maps a derived collection to the one it derives from; anything unnamed is
/// a root. Real collections answer this from their descriptor, which is the
/// one read `StoreWriters` makes for the kind check.
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
fn a_merge_covers_every_input() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    for payload in 1..=3 {
        index.apply(&commit(1, c, data(payload)), &AdmitEveryRecord);
    }
    index.apply(
        &merge(1, c, &[data(1), data(2), data(3)], data(9)),
        &AdmitEveryRecord,
    );
    assert_eq!(
        members(&index, c, data(9)),
        vec![[1u8; 32], [2u8; 32], [3u8; 32]]
    );
    assert_eq!(frontier(&index, c), vec![[9u8; 32]]);
}

/// A k-way join publishes nothing until every one of its inputs has a row,
/// and then all of them at once.
#[test]
fn an_n_ary_join_is_all_or_nothing() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(
        &merge(1, c, &[data(1), data(2), data(3)], data(9)),
        &AdmitEveryRecord,
    );
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    // Two of three inputs: still nothing, and still blocked.
    assert!(index.coverage(c, data(9)).is_none());
    assert!(index.published().has_blocked(c));
    assert_eq!(frontier(&index, c), vec![[1u8; 32], [2u8; 32]]);
    index.apply(&commit(1, c, data(3)), &AdmitEveryRecord);
    assert_eq!(
        members(&index, c, data(9)),
        vec![[1u8; 32], [2u8; 32], [3u8; 32]]
    );
    assert!(!index.published().has_blocked(c));
    assert_eq!(frontier(&index, c), vec![[9u8; 32]]);
}

/// A DERIVE is a foundation of the derived collection: it stands for its own
/// output and reads nothing, not even whether the source holds its input.
#[test]
fn a_leaf_contributes_its_own_output_and_reads_no_row() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    // Nothing is in the source at all.
    index.apply(&derive(1, target, data(3), data(4)), &lineages);
    assert_eq!(members(&index, target, data(4)), vec![[4u8; 32]]);
    assert_eq!(frontier(&index, target), vec![[4u8; 32]]);
    assert!(!index.published().has_blocked(target));
    assert!(index.coverage(source, data(3)).is_none());
    // Source records never reach the target's rows.
    index.apply(&commit(1, source, data(3)), &lineages);
    index.apply(&commit(1, source, data(5)), &lineages);
    index.apply(&merge(1, source, &[data(3), data(5)], data(6)), &lineages);
    assert_eq!(members(&index, target, data(4)), vec![[4u8; 32]]);
    assert_eq!(frontier(&index, target), vec![[4u8; 32]]);
}

#[test]
fn records_arriving_before_their_inputs_still_land() {
    let c = collection(0);
    let mut index = CoverageIndex::new();
    // Reverse causal order: the upper merge first, then the merge it
    // consumes, then finally the commits underneath.
    index.apply(
        &merge(1, c, &[data(3), data(4)], data(5)),
        &AdmitEveryRecord,
    );
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(3)),
        &AdmitEveryRecord,
    );
    index.apply(&commit(1, c, data(4)), &AdmitEveryRecord);
    assert!(index.coverage(c, data(3)).is_none());
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    // One side is not enough: a merge attests a join, not either half.
    assert!(index.coverage(c, data(3)).is_none());
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    assert_eq!(members(&index, c, data(3)), vec![[1u8; 32], [2u8; 32]]);
    // And the growth propagated through the upper merge already registered.
    assert_eq!(
        members(&index, c, data(5)),
        vec![[1u8; 32], [2u8; 32], [4u8; 32]]
    );
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
}

#[test]
fn a_row_that_grows_later_widens_everything_downstream_of_it() {
    let c = collection(0);
    let mut index = CoverageIndex::new();
    for payload in [1, 2, 6] {
        index.apply(&commit(1, c, data(payload)), &AdmitEveryRecord);
    }
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(3)),
        &AdmitEveryRecord,
    );
    index.apply(
        &merge(1, c, &[data(3), data(6)], data(7)),
        &AdmitEveryRecord,
    );
    assert_eq!(
        members(&index, c, data(7)),
        vec![[1u8; 32], [2u8; 32], [6u8; 32]]
    );

    // An alternative route attests that the same result also stands for a
    // fifth commit. Coverage is a union over routes, so everything downstream
    // widens with it without replaying anything.
    index.apply(&commit(1, c, data(5)), &AdmitEveryRecord);
    index.apply(
        &merge(1, c, &[data(1), data(5)], data(3)),
        &AdmitEveryRecord,
    );
    assert_eq!(
        members(&index, c, data(7)),
        vec![[1u8; 32], [2u8; 32], [5u8; 32], [6u8; 32]]
    );
}

#[test]
fn folding_the_same_record_twice_changes_nothing() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    let records = [
        commit(1, c, data(1)),
        commit(1, c, data(2)),
        merge(1, c, &[data(1), data(2)], data(3)),
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
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(1)),
        &AdmitEveryRecord,
    );
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
    index.apply(&merge(2, c, &[data(1), data(2)], data(3)), &OnlySigner(1));

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

/// The whole-pile figure cannot be acted on; the per-collection one can.
///
/// "This pile holds 127,912 unadmitted records" is true of almost any live
/// pile, never changes much, and tells nobody where to look. "This collection
/// holds 204" names the thing to carry. A reader that marks collections needs
/// the second, which is why the backlog's per-entry collection is worth
/// reading back out.
#[test]
fn unadmitted_is_attributed_to_the_collection_that_holds_it() {
    let mut index = CoverageIndex::new();
    let a = collection(0);
    let b = collection(1);
    let untouched = collection(2);

    // Signer 2 is not admitted anywhere: two of its attestations land in a,
    // one in b.
    index.apply(&commit(2, a, data(1)), &OnlySigner(1));
    index.apply(&commit(2, a, data(2)), &OnlySigner(1));
    index.apply(&commit(2, b, data(3)), &OnlySigner(1));

    assert_eq!(index.parked_on_signers(), 3, "the aggregate is the sum");
    assert_eq!(index.unadmitted_in(a), 2);
    assert_eq!(index.unadmitted_in(b), 1);
    // A collection with nothing parked reports its own zero, not the total.
    assert_eq!(index.unadmitted_in(untouched), 0);

    // And it empties with the aggregate when the proofs arrive, rather than
    // going stale behind it.
    index.resolve(&AdmitEveryRecord);
    assert_eq!(index.parked_on_signers(), 0);
    assert_eq!(index.unadmitted_in(a), 0);
    assert_eq!(index.unadmitted_in(b), 0);
}

/// A count marks a collection; only a set of members marks a node.
///
/// A view draws one shape per member, so "this collection holds 2 unadmitted
/// records" cannot be painted: it does not say which two shapes to colour.
/// Naming the members is what turns the number into a mark. And it is a SET
/// because two signers attesting one result is agreement about a single
/// member, not two unadmitted members.
#[test]
fn unadmitted_members_are_named_not_merely_counted() {
    let mut index = CoverageIndex::new();
    let a = collection(0);
    let b = collection(1);
    let untouched = collection(2);

    // The same shape as the count test above, so the two read together.
    index.apply(&commit(2, a, data(1)), &OnlySigner(1));
    index.apply(&commit(2, a, data(2)), &OnlySigner(1));
    index.apply(&commit(2, b, data(3)), &OnlySigner(1));

    assert_eq!(
        index.unadmitted_nodes_in(a),
        BTreeSet::from([data(1), data(2)]),
        "the members themselves, not how many of them there are"
    );
    assert_eq!(index.unadmitted_nodes_in(b), BTreeSet::from([data(3)]));
    // Not a's members, and not the index's: its own empty set.
    assert!(index.unadmitted_nodes_in(untouched).is_empty());

    // A second unadmitted signer agreeing about data(1) adds a waiting
    // ATTESTATION without adding a waiting MEMBER, so the count goes to three
    // while the set stays at two. Both are right; they answer different
    // questions, which is why the view wants the set and the operator's
    // summary line wants the count.
    index.apply(&commit(3, a, data(1)), &OnlySigner(1));
    assert_eq!(index.unadmitted_in(a), 3);
    assert_eq!(
        index.unadmitted_nodes_in(a),
        BTreeSet::from([data(1), data(2)])
    );

    // And a member stops being named the moment a proof admits it, rather
    // than lingering as a stale mark on something that has since arrived.
    index.resolve(&AdmitEveryRecord);
    assert!(index.unadmitted_nodes_in(a).is_empty());
    assert!(index.unadmitted_nodes_in(b).is_empty());
}

#[test]
fn an_unadmitted_route_contributes_nothing_to_a_node_an_admitted_route_reached() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &OnlySigner(1));
    index.apply(&commit(1, c, data(2)), &OnlySigner(1));
    index.apply(&commit(1, c, data(5)), &OnlySigner(1));
    index.apply(&merge(1, c, &[data(1), data(2)], data(3)), &OnlySigner(1));
    // A second, unadmitted attestation about the same result.
    index.apply(&merge(2, c, &[data(1), data(5)], data(3)), &OnlySigner(1));
    assert_eq!(members(&index, c, data(3)), vec![[1u8; 32], [2u8; 32]]);
}

/// Only a leaf needs its collection's descriptor before admission: whether
/// a DERIVE is a foundation depends on its target being derived.
///
/// A commit and a merge stay inside the collection they name, so an
/// unresolvable descriptor never stops them here — admission still does, but
/// that is a different question with a different key. A derive waits on its
/// OWN collection's descriptor; nothing about its source is ever read.
#[test]
fn only_a_leaf_parks_on_its_unresolvable_descriptor() {
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
    index.apply(
        &merge(1, source, &[data(1), data(2)], data(3)),
        &NoDescriptor,
    );
    index.apply(&derive(1, target, data(3), data(4)), &NoDescriptor);

    // The source lattice folded without any descriptor at all.
    assert_eq!(members(&index, source, data(3)), vec![[1u8; 32], [2u8; 32]]);
    // The leaf cannot know whether its target is derived, so it waits.
    assert!(index.coverage(target, data(4)).is_none());
    assert_eq!(index.parked_on_lineages(), 1);
    assert_eq!(index.parked_on_signers(), 0);

    // The target's descriptor lands and the leaf is a foundation of it.
    index.settle(
        &Lineages([(target, source)].into_iter().collect()),
        [target],
        false,
    );
    assert_eq!(members(&index, target, data(4)), vec![[4u8; 32]]);
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
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(4)),
        &AdmitEveryRecord,
    );
    index.apply(
        &merge(1, c, &[data(2), data(3)], data(5)),
        &AdmitEveryRecord,
    );

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
/// foundations underneath it belong to a collection, and foundations from two
/// collections are not comparable. Scoping each row by its collection is what
/// keeps them apart — and it is free, because the foundation set is a
/// separate nested trie either way.
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
    index.apply(
        &merge(1, tally, &[data(1), data(2)], shared),
        &AdmitEveryRecord,
    );

    assert_eq!(members(&index, ledger, shared), vec![[3u8; 32]]);
    assert_eq!(members(&index, tally, shared), vec![[1u8; 32], [2u8; 32]]);
}

/// The subsumption verdict a bare result key used to flip.
///
/// Asking "does this node cover everything I need" was always safe, because
/// the needed set is a known universe and a foreign member can never satisfy
/// a real requirement. Asking "does this node subsume that one" — how a cover
/// is minimised — has no universe to intersect against, so a foreign member
/// could make a needed node read as redundant. `alias` covers only commits 1
/// and 4 inside `tally`; a foreign lattice attesting that the same payload
/// stands for commit 2 must not reach that row.
#[test]
fn a_foreign_member_cannot_flip_a_subsumption_verdict() {
    let tally = collection(0);
    let ledger = collection(1);
    let alias = data(3);

    let mut index = CoverageIndex::new();
    for payload in [1, 2, 4] {
        index.apply(&commit(1, tally, data(payload)), &AdmitEveryRecord);
    }
    index.apply(
        &merge(1, tally, &[data(1), data(4)], alias),
        &AdmitEveryRecord,
    );
    index.apply(
        &merge(1, tally, &[data(1), data(2)], data(5)),
        &AdmitEveryRecord,
    );
    // The foreign lattice commits its own copies of payload bytes and
    // reaches `alias` by its own route.
    index.apply(&commit(1, ledger, data(2)), &AdmitEveryRecord);
    index.apply(&commit(1, ledger, data(6)), &AdmitEveryRecord);
    index.apply(
        &merge(1, ledger, &[data(2), data(6)], alias),
        &AdmitEveryRecord,
    );

    let alias_row = index.coverage(tally, alias).expect("row").clone();
    let pair = index.coverage(tally, data(5)).expect("row").clone();
    assert_eq!(
        alias_row.iter_ordered().copied().collect::<Vec<_>>(),
        vec![[1u8; 32], [4u8; 32]]
    );
    assert!(
        !pair.difference(&alias_row).is_empty(),
        "a node tally still needs must not read as redundant"
    );
    // The foreign route kept its own row, and it says what it actually knows.
    assert_eq!(members(&index, ledger, alias), vec![[2u8; 32], [6u8; 32]]);
}

/// Who produced a node: the signer of every believed record naming it as
/// its result, including a merge that absorbs a node another signer holds.
#[test]
fn owners_name_the_signer_of_every_believed_producer() {
    let c = collection(0);
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, c, data(1)), &OnlySigner(1));
    index.apply(&commit(2, c, data(2)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(4)), &OnlySigner(1));
    index.apply(
        &merge(3, c, &[data(1), data(2)], data(5)),
        &AdmitEveryRecord,
    );
    // Absorption: signer 1 absorbs node 4 into node 5, which it then owns too.
    index.apply(&merge(1, c, &[data(4), data(5)], data(5)), &OnlySigner(1));
    // Signer 4 is not admitted: its attestation owns nothing yet.
    index.apply(&commit(4, c, data(6)), &OnlySigner(1));

    let published = index.published();
    assert_eq!(published.owners(c, data(1)), vec![public(1)]);
    assert_eq!(published.owners(c, data(2)), vec![public(2)]);
    let mut owners_of_five = vec![public(1), public(3)];
    owners_of_five.sort();
    assert_eq!(published.owners(c, data(5)), owners_of_five);
    assert!(published.owned_by(c, data(5), public(3)));
    assert!(!published.owned_by(c, data(2), public(1)));
    assert!(published.owners(c, data(6)).is_empty());
    // Ownership is per collection.
    assert!(published.owners(collection(9), data(1)).is_empty());

    index.resolve(&AdmitEveryRecord);
    assert_eq!(index.published().owners(c, data(6)), vec![public(4)]);
}

/// `leaves` answers "has source foundation H been derived into T, and to
/// what?" by the DERIVE relation's own key, `L(H)`.
#[test]
fn leaves_are_published_by_source_locator() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    index.apply(&derive(1, target, data(1), data(11)), &lineages);
    index.apply(&derive(2, target, data(2), data(12)), &lineages);
    // A DERIVE into a root is no leaf of anything.
    index.apply(&derive(1, source, data(3), data(13)), &lineages);

    let published = index.published();
    let first = SourceLocator::of(data(1).raw);
    let second = SourceLocator::of(data(2).raw);
    assert!(published.has_leaf(target, first));
    assert_eq!(published.leaf_outputs(target, first), vec![data(11)]);
    assert_eq!(published.leaf_outputs(target, second), vec![data(12)]);
    assert!(!published.has_leaf(target, SourceLocator::of(data(3).raw)));
    assert!(!published.has_leaf(source, SourceLocator::of(data(3).raw)));
    // The locator is not the handle: nothing is keyed by H itself.
    assert!(!published.has_leaf(target, SourceLocator::from_raw(data(1).raw)));
    let mut expected = vec![(first, data(11)), (second, data(12))];
    expected.sort();
    assert_eq!(published.leaves(target), expected);
    assert!(published.leaves(source).is_empty());
    assert_eq!(published.owners(target, data(12)), vec![public(2)]);
}

#[test]
fn a_derive_into_a_root_attests_nothing() {
    let root = collection(0);
    let lineages = Lineages(std::collections::BTreeMap::new());
    let mut index = CoverageIndex::new();
    index.apply(&derive(1, root, data(3), data(4)), &lineages);
    assert!(index.coverage(root, data(4)).is_none());
    assert!(frontier(&index, root).is_empty());
    assert!(index.published().owners(root, data(4)).is_empty());
    assert_eq!(index.parked(), 0);
}

/// What building the index on store open actually costs.
///
/// Framing rule: the printed figure is **microseconds per record folded**, in
/// a `--release` build, for one synthetic lattice of `commits` foundation
/// commits LSM-merged eight at a time to a single root, plus `derive_hops`
/// derived collections each holding one leaf. It is the whole cost of
/// [`CoverageIndex`] construction — admission is stubbed open, because the
/// question here is what the fold costs, not what descriptor resolution costs.
///
/// Measured 2026-09-18 on the GB10 `sky` (aarch64, release) with binary
/// merges and cross-collection images: 5.95 µs/record at 821 records, then
/// 2.65 / 2.85 / 2.94 µs/record at 3 445 / 29 961 / 200 001 records. Not yet
/// re-measured for n-ary merges and collection-local leaves.
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
        // Eight-way compaction upward, the LSM geometry maintenance
        // produces.
        let mut next_result = commits as u64;
        while tier.len() > 1 {
            let mut above = Vec::with_capacity(tier.len().div_ceil(8));
            for group in tier.chunks(8) {
                if group.len() >= 2 {
                    let mut raw = [0u8; 32];
                    raw[..8].copy_from_slice(&next_result.to_be_bytes());
                    next_result += 1;
                    let result = Inline::new(raw);
                    records.push(merge(1, source, group, result));
                    above.push(result);
                } else {
                    above.push(group[0]);
                }
            }
            tier = above;
        }
        let root = tier[0];
        for hop in 0..derive_hops {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&next_result.to_be_bytes());
            next_result += 1;
            records.push(derive(1, projection(hop), root, Inline::new(raw)));
        }

        let lineages = Lineages(
            (0..derive_hops)
                .map(|hop| {
                    let from = if hop == 0 {
                        source
                    } else {
                        projection(hop - 1)
                    };
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
        assert_eq!(
            index.coverage(source, root).map(|row| row.len()),
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
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(5)),
        &AdmitEveryRecord,
    );
    index.apply(
        &merge(1, c, &[data(3), data(4)], data(6)),
        &AdmitEveryRecord,
    );
    assert_eq!(frontier(&index, c), vec![[5u8; 32], [6u8; 32]]);
    index.apply(
        &merge(1, c, &[data(5), data(6)], data(7)),
        &AdmitEveryRecord,
    );
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
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(5)),
        &AdmitEveryRecord,
    );
    assert!(frontier(&index, c).is_empty());
    assert!(index.published().has_blocked(c));
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    // One side of a join that is not driven yet stays attachable on its own.
    assert_eq!(frontier(&index, c), vec![[1u8; 32]]);
    assert!(index.published().has_blocked(c));
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
    assert!(!index.published().has_blocked(c));
}

/// Whether a collection still holds a blocked join depends only on which
/// records are believed. A second route to the same result -- here a driven
/// join -- must not clear a join that still lacks an input, whichever came
/// first; and a join that blocked for a while leaves no trace once driven.
#[test]
fn blocked_joins_do_not_depend_on_arrival_order() {
    let c = collection(0);
    let driven = merge(1, c, &[data(1), data(2)], data(20));
    let stuck = merge(1, c, &[data(3), data(9)], data(20));
    let foundations = [
        commit(1, c, data(1)),
        commit(1, c, data(2)),
        commit(1, c, data(3)),
    ];
    let fold = |records: &[&CollectionRecord]| {
        let mut index = CoverageIndex::new();
        for record in records {
            index.apply(record, &AdmitEveryRecord);
        }
        index
    };
    let [a, b, d] = &foundations;
    let driven_first = fold(&[a, b, d, &driven, &stuck]);
    let stuck_first = fold(&[a, b, d, &stuck, &driven]);
    assert!(driven_first.published().has_blocked(c));
    assert!(stuck_first.published().has_blocked(c));
    assert_eq!(driven_first.published(), stuck_first.published());

    // A join that arrives ahead of its inputs and is then driven publishes
    // exactly what the in-order history does.
    let in_order = fold(&[a, b, &driven]);
    let reversed = fold(&[&driven, b, a]);
    assert!(!in_order.published().has_blocked(c));
    assert!(!reversed.published().has_blocked(c));
    assert_eq!(in_order.published(), reversed.published());
}

#[test]
fn a_commit_arriving_after_the_merge_that_consumes_it_is_not_put_back() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(3)), &AdmitEveryRecord);
    index.apply(
        &merge(1, c, &[data(1), data(2), data(3)], data(5)),
        &AdmitEveryRecord,
    );
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
    // Driving the same records again moves nothing.
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(
        &merge(1, c, &[data(1), data(2), data(3)], data(5)),
        &AdmitEveryRecord,
    );
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
}

#[test]
fn two_routes_to_one_result_consume_both_routes() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    for payload in 1..=4 {
        index.apply(&commit(1, c, data(payload)), &AdmitEveryRecord);
    }
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(5)),
        &AdmitEveryRecord,
    );
    // A second route producing the same payload: its support only grows.
    index.apply(
        &merge(1, c, &[data(3), data(4)], data(5)),
        &AdmitEveryRecord,
    );
    assert_eq!(frontier(&index, c), vec![[5u8; 32]]);
    assert_eq!(
        members(&index, c, data(5)),
        vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]
    );
}

/// `MERGE(a, c) -> c` absorbs `a` into `c`: `a` leaves the frontier and `c`,
/// the result among the inputs, stays on it.
#[test]
fn absorption_keeps_the_absorbing_node_on_the_frontier() {
    let mut index = CoverageIndex::new();
    let c = collection(0);
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(&commit(1, c, data(2)), &AdmitEveryRecord);
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(2)),
        &AdmitEveryRecord,
    );
    assert_eq!(frontier(&index, c), vec![[2u8; 32]]);
    assert_eq!(members(&index, c, data(2)), vec![[1u8; 32], [2u8; 32]]);
    // Replaying the absorption, or the absorbed commit, changes nothing.
    index.apply(&commit(1, c, data(1)), &AdmitEveryRecord);
    index.apply(
        &merge(1, c, &[data(1), data(2)], data(2)),
        &AdmitEveryRecord,
    );
    assert_eq!(frontier(&index, c), vec![[2u8; 32]]);
}

#[test]
fn leaves_join_the_target_frontier_and_a_target_merge_consumes_them() {
    let source = collection(0);
    let target = collection(7);
    let lineages = Lineages([(target, source)].into_iter().collect());
    let mut index = CoverageIndex::new();
    index.apply(&commit(1, source, data(1)), &lineages);
    index.apply(&commit(1, source, data(2)), &lineages);
    index.apply(&derive(1, target, data(1), data(11)), &lineages);
    index.apply(&derive(1, target, data(2), data(12)), &lineages);
    assert_eq!(frontier(&index, target), vec![[11u8; 32], [12u8; 32]]);
    // A leaf whose source foundation is not here stands anyway: nothing
    // blocks on a source.
    index.apply(&derive(1, target, data(9), data(19)), &lineages);
    assert!(!index.published().has_blocked(target));
    assert_eq!(
        frontier(&index, target),
        vec![[11u8; 32], [12u8; 32], [19u8; 32]]
    );
    // The source's frontier is its own: leaves consume nothing there.
    assert_eq!(frontier(&index, source), vec![[1u8; 32], [2u8; 32]]);
    // A merge inside the target consumes its leaves; its support is the
    // target's own foundations.
    index.apply(
        &merge(1, target, &[data(11), data(12), data(19)], data(13)),
        &lineages,
    );
    assert_eq!(frontier(&index, target), vec![[13u8; 32]]);
    assert_eq!(
        members(&index, target, data(13)),
        vec![[11u8; 32], [12u8; 32], [19u8; 32]]
    );
    // A source merge changes the source's frontier and nothing in the target.
    index.apply(&merge(1, source, &[data(1), data(2)], data(3)), &lineages);
    assert_eq!(frontier(&index, source), vec![[3u8; 32]]);
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
    assert!(index.published().owners(target, data(9)).is_empty());
    assert_eq!(index.parked(), 0);
}
