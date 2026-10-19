use super::*;
use crate::walk::Value;
use crate::walk_stream::Frame;
use ed25519_dalek::SigningKey;
use triblespace_core::collection::observed_store::ObservedStore;
use triblespace_core::collection::{
    CollectionCommit, CollectionDerive, CollectionMap, CollectionStore, SourceLocator,
};
use triblespace_core::inline::Inline;
use triblespace_core::repo::{pile::PileFile, SnapshotSource};

fn overlay_value(overlay: &CollectionRecordPatch, record: CollectionRecord) -> Value {
    let key = record.fingerprint().raw();
    match record {
        CollectionRecord::Commit(_) => Value::Commit(overlay.commits().get(&key).unwrap().clone()),
        CollectionRecord::Derive(_) => Value::Derive(overlay.derives().get(&key).unwrap().clone()),
        _ => panic!("not a foundation"),
    }
}

fn value_body(value: &Value) -> anybytes::Bytes {
    match value {
        Value::Commit(v) => v.clone().bytes(),
        Value::Derive(v) => v.clone().bytes(),
        _ => panic!("not a foundation"),
    }
}

#[test]
fn observed_and_borrowed_wrappers_forward_views_without_owned_fallback() {
    struct ViewOnly(Vec<CollectionRecordView>);
    impl CollectionRead for ViewOnly {
        type RecordsError = std::convert::Infallible;
        type RecordIter<'a> = std::iter::Empty<Result<CollectionRecord, Self::RecordsError>>;
        fn records(&self) -> Result<Self::RecordIter<'_>, Self::RecordsError> {
            panic!("owned enumeration")
        }
        fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
            panic!("global enumeration")
        }
        fn select_records(
            &self,
            _: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
            panic!("owned selection")
        }
        fn select_record_changes(
            &self,
            _: &Self,
            _: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<(Vec<CollectionRecord>, Vec<CollectionRecord>), Self::RecordsError> {
            panic!("owned delta")
        }
        fn select_record_views(
            &self,
            _: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<CollectionRecordView>, Self::RecordsError> {
            Ok(self.0.clone())
        }
        fn select_record_view_changes(
            &self,
            _: &Self,
            _: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<triblespace_core::collection::RecordViewChanges, Self::RecordsError>
        {
            Ok(triblespace_core::collection::RecordViewChanges::Append(self.0.clone()))
        }
    }
    let c = Inline::new([30; 32]);
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[95; 32]),
        c,
        Inline::new([31; 32]),
        Inline::new([32; 32]),
    ));
    let before = ObservedStore::new(ViewOnly(vec![]));
    let after = ObservedStore::new(ViewOnly(vec![record.into()]));
    let initial = collection_record_patch(&&before, c).unwrap();
    let advanced = update_collection_record_patch(&&after, &&before, &initial).unwrap();
    assert_eq!(advanced.get(record.fingerprint()), Some(record));
    let expected = BTreeSet::from([CollectionRecordSelector::Foundations(c)]);
    assert_eq!(before.dependencies().records, expected);
    assert_eq!(after.dependencies().records, expected);
    assert!(!before.dependencies().all_records && !after.dependencies().all_records);

    // An empty semantic delta still observes both sides of the selection.
    let empty_before = ObservedStore::new(ViewOnly(vec![]));
    let empty_after = ObservedStore::new(ViewOnly(vec![]));
    let empty = collection_record_patch(&&empty_before, c).unwrap();
    let same = update_collection_record_patch(&&empty_after, &&empty_before, &empty).unwrap();
    assert!(same.is_empty());
    assert_eq!(empty_before.dependencies().records, expected);
    assert_eq!(empty_after.dependencies().records, expected);
}

#[test]
fn typed_foundation_generations_are_independent_and_old_pins_survive() {
    use crate::host::StoreSnapshot;
    use crate::walk::WalkKind;
    use crate::walk::tests::walking::{Node, open};
    use triblespace_core::repo::{StoreChanges, StoreSnapshot as _};
    use std::sync::Arc;
    let mut node = Node::new(195);
    let c = node.hold("typed-kind-generations", open());
    let before = node.store.snapshot().unwrap();
    let first = StoreSnapshot::from_store_changes(before.clone(), &node.active,
        node.key.verifying_key(), None, None, StoreChanges::ALL).unwrap();
    let old_pin = first.collection(c).unwrap();
    let empty_commit = old_pin.cache(WalkKind::Commit);
    let empty_derive = old_pin.cache(WalkKind::Derive);
    let commit = node.commit(c, 42);
    let middle = node.store.snapshot().unwrap();
    let second = StoreSnapshot::from_store_changes(middle.clone(), &node.active,
        node.key.verifying_key(), Some(&before), Some(&first), middle.changes_since(&before)).unwrap();
    let middle_pin = second.collection(c).unwrap();
    assert!(!Arc::ptr_eq(&empty_commit, &middle_pin.cache(WalkKind::Commit)));
    assert!(Arc::ptr_eq(&empty_derive, &middle_pin.cache(WalkKind::Derive)));
    let retained = middle_pin.repair().records().commits().get(&commit.fingerprint().raw()).unwrap().clone();
    let derive = CollectionRecord::Derive(CollectionDerive::sign(&node.key, c,
        SourceLocator::of([42; 32]), Inline::new([43; 32])));
    node.store.insert(derive).unwrap();
    let after = node.store.snapshot().unwrap();
    let third = StoreSnapshot::from_store_changes(after.clone(), &node.active,
        node.key.verifying_key(), Some(&middle), Some(&second), after.changes_since(&middle)).unwrap();
    let last = third.collection(c).unwrap();
    assert!(Arc::ptr_eq(&middle_pin.cache(WalkKind::Commit), &last.cache(WalkKind::Commit)));
    assert!(!Arc::ptr_eq(&empty_derive, &last.cache(WalkKind::Derive)));
    assert_eq!(empty_derive.summary().leaf_count(), 0);
    assert_eq!(last.cache(WalkKind::Derive).summary().leaf_count(), 1);
    assert_ne!(last.cache(WalkKind::Commit).key(), last.cache(WalkKind::Derive).key());
    assert!(last.repair().records().commits().get(&derive.fingerprint().raw()).is_none());
    assert!(last.repair().records().derives().get(&commit.fingerprint().raw()).is_none());
    drop((node, before, middle, after, first, second, third, old_pin, middle_pin, last));
    assert_eq!(retained.body_bytes(), &commit.to_bytes());
}

#[test]
fn typed_structural_views_cannot_bypass_foreign_kind_signature_or_identity_checks() {
    use crate::walk::{WalkKind, admit_value};
    use crate::walk::tests::walking::{Node, open};
    use triblespace_core::collection::EncodedCommit;
    let mut node = Node::new(196);
    let c = node.hold("typed-ingress", open());
    node.observe();
    let commit = CollectionRecord::Commit(CollectionCommit::sign(&node.key, c,
        Inline::new([44; 32]), Inline::new([45; 32])));
    let derive = CollectionRecord::Derive(CollectionDerive::sign(&node.key, c,
        SourceLocator::of([44; 32]), Inline::new([45; 32])));
    for (kind, wrong_kind, record) in [(WalkKind::Commit, WalkKind::Derive, commit),
        (WalkKind::Derive, WalkKind::Commit, derive)] {
        let key = record.fingerprint().raw();
        let bytes = record.to_bytes();
        assert!(admit_value(kind, c, key, &bytes).is_ok());
        assert!(admit_value(wrong_kind, c, key, &bytes).is_err());
        assert!(admit_value(kind, Inline::new([99; 32]), key, &bytes).is_err());
        assert!(admit_value(kind, c, [0; 32], &bytes).is_err());
        assert!(admit_value(kind, c, key, &bytes[..192]).is_err());
        let mut trailing = bytes.clone(); trailing.push(0);
        assert!(admit_value(kind, c, key, &trailing).is_err());
        let mut invalid = bytes.clone(); *invalid.last_mut().unwrap() ^= 1;
        assert!(admit_value(kind, c, key, &invalid).is_err());
    }
    let mut invalid = commit.to_bytes(); *invalid.last_mut().unwrap() ^= 1;
    let structural = anybytes::Bytes::from_source(invalid.to_vec())
        .view::<EncodedCommit>().unwrap();
    assert!(structural.to_record().is_err());
    assert!(admit_value(WalkKind::Commit, c, structural.fingerprint().raw(), &invalid).is_err());
}

#[test]
fn native_body_overlay_eager_bytes_and_observed_delta_survive_all_source_drops() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overlay-bodies.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    let c = Inline::new([20; 32]);
    let records = [
        CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            c,
            Inline::new([21; 32]),
            Inline::new([22; 32]),
        )),
        CollectionRecord::Derive(CollectionDerive::sign(
            &key,
            c,
            SourceLocator::of([23; 32]),
            Inline::new([24; 32]),
        )),
    ];
    for record in records {
        pile.insert(record).unwrap();
    }
    let before = ObservedStore::new(pile.snapshot().unwrap());
    let overlay = collection_record_patch(&before, c).unwrap();
    let selectors = BTreeSet::from([CollectionRecordSelector::Foundations(c)]);
    let native_views = before.select_record_views(&selectors).unwrap();
    for expected in records {
        let value = overlay_value(&overlay, expected);
        let native = native_views
            .iter()
            .find(|v| v.fingerprint() == expected.fingerprint())
            .unwrap();
        assert_eq!(
            value_body(&value).as_ptr(),
            native.body().as_ptr(),
            "overlay points at native leaf, not an enum-serialization copy"
        );
        assert_eq!(overlay.get(expected.fingerprint()), Some(expected));
        let body = value.bytes(c).unwrap();
        assert_eq!(body, encode_record(c, expected).unwrap());
        let (_, frame) = Frame::Value {
            key: expected.fingerprint().raw(),
            bytes: body,
        }
        .encode();
        assert_eq!(&frame[..32], &expected.fingerprint().raw());
        assert_eq!(&frame[32..], expected.to_bytes());
        assert_eq!(decode_record(c, &frame[32..]).unwrap(), expected);
        assert!(value
            .bytes(Inline::new([255; 32]))
            .is_none());
    }
    let added = CollectionRecord::Commit(CollectionCommit::sign(
        &key,
        c,
        Inline::new([25; 32]),
        Inline::new([26; 32]),
    ));
    pile.insert(added).unwrap();
    let after = ObservedStore::new(pile.snapshot().unwrap());
    let advanced = update_collection_record_patch(&after, &before, &overlay).unwrap();
    assert_eq!(advanced.len(), 3);
    assert_eq!(overlay.len(), 2);
    assert_eq!(before.dependencies().records, selectors);
    assert_eq!(after.dependencies().records, selectors);
    assert!(!before.dependencies().all_records && !after.dependencies().all_records);
    let single = overlay_value(&overlay, records[0]);
    let weak = value_body(&single).downgrade();
    drop(native_views);
    drop(advanced);
    drop(overlay);
    drop(before);
    drop(after);
    pile.close().unwrap();
    assert_eq!(single.bytes(c).unwrap(), records[0].to_bytes());
    assert!(weak.upgrade().is_some());
    drop(single);
    assert!(weak.upgrade().is_none());
}

#[test]
fn body_views_keep_kind_identity_and_reject_nonfoundation_eager_values() {
    let key = SigningKey::from_bytes(&[92; 32]);
    let c = Inline::new([27; 32]);
    let commit = CollectionRecord::Commit(CollectionCommit::sign(
        &key,
        c,
        Inline::new([28; 32]),
        Inline::new([29; 32]),
    ));
    let map = CollectionRecord::Map(CollectionMap::sign(
        &key,
        c,
        Inline::new([28; 32]),
        Inline::new([29; 32]),
    ));
    let view: CollectionRecordView = commit.into();
    let independent: CollectionRecordView = commit.into();
    assert_eq!(view, independent);
    assert_ne!(view.body().as_ptr(), independent.body().as_ptr());
    assert_eq!(view.fingerprint(), commit.fingerprint());
    let map_view: CollectionRecordView = map.into();
    assert!(!map_view.is_foundation());
    assert!(Value::from_record_view(&map_view).is_none());
    assert!(matches!(
        canonical_records(c, [map_view]),
        Err(CollectionDeltaError::NotReplicated)
    ));
    let mut foreign = view.to_bytes();
    foreign[..32].copy_from_slice(&triblespace_core::collection::KIND_COLLECTION_DERIVE);
    assert!(
        decode_record(c, &foreign).is_err(),
        "wire ingress still verifies the literal existing kind's signature"
    );
}

#[test]
fn occurrence_append_and_replacement_preserve_semantic_peer_inventory() {
    use std::io::Write;
    use triblespace_core::collection::RecordViewChanges;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two-copies.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let c = Inline::new([71; 32]);
    let make = |n| CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[72; 32]), c, Inline::new([73; 32]), Inline::new([n; 32]),
    ));
    let a = make(74);
    let b = make(75); // same C/member, different signed body
    pile.insert(a).unwrap();
    let frame = std::fs::read(&path).unwrap();
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(&frame).unwrap();
    let before = pile.snapshot().unwrap();
    assert_eq!(before.records().unwrap().count(), 2);
    let initial = collection_record_patch(&before, c).unwrap();
    assert_eq!(initial.len(), 1);
    let held = overlay_value(&initial, a);
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(&frame).unwrap();
    let after = pile.snapshot().unwrap();
    let selectors = BTreeSet::from([CollectionRecordSelector::Foundations(c)]);
    assert!(matches!(after.select_record_view_changes(&before, &selectors).unwrap(),
        RecordViewChanges::Append(v) if v.len() == 1));
    let appended = update_collection_record_patch(&after, &before, &initial).unwrap();
    assert_eq!(appended.len(), 1);
    assert_eq!(value_body(&overlay_value(&appended, a)).as_ptr(), value_body(&held).as_ptr(),
        "duplicate append retains the first canonical body owner");

    let one_path = dir.path().join("one-copy.pile");
    std::fs::write(&one_path, &frame).unwrap();
    let mut one = PileFile::open(&one_path).unwrap();
    let one_snapshot = one.snapshot().unwrap();
    assert!(matches!(one_snapshot.select_record_view_changes(&after, &selectors).unwrap(), RecordViewChanges::Rebuild));
    let rebuilt = update_collection_record_patch(&one_snapshot, &after, &appended).unwrap();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt.get(a.fingerprint()), Some(a));

    let different_path = dir.path().join("different-body.pile");
    std::fs::File::create(&different_path).unwrap();
    let mut different = PileFile::open(&different_path).unwrap();
    different.insert(b).unwrap();
    let different_snapshot = different.snapshot().unwrap();
    let replaced = update_collection_record_patch(&different_snapshot, &one_snapshot, &rebuilt).unwrap();
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced.get(a.fingerprint()), None);
    assert_eq!(replaced.get(b.fingerprint()), Some(b));

    let empty_path = dir.path().join("empty.pile");
    std::fs::File::create(&empty_path).unwrap();
    let mut empty = PileFile::open(&empty_path).unwrap();
    let empty_snapshot = empty.snapshot().unwrap();
    assert!(update_collection_record_patch(&empty_snapshot, &different_snapshot, &replaced).unwrap().is_empty());
    drop((before, after, one_snapshot, different_snapshot, empty_snapshot, initial, appended, rebuilt, replaced));
    pile.close().unwrap(); one.close().unwrap(); different.close().unwrap(); empty.close().unwrap();
    assert_eq!(held.bytes(c).unwrap(), a.to_bytes());
}
