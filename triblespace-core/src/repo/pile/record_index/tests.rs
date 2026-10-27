use super::*;
use crate::collection::{CollectionRead, CollectionStore, RecordViewChanges};
use crate::repo::{SnapshotSource, StoreChanges, StoreDependencies, StoreSnapshot};
use std::io::Write;

fn record(metadata: u8) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        Inline::new([1; 32]), Inline::new([2; 32]), Inline::new([metadata; 32]),
    ))
}

fn append(path: &std::path::Path, record: CollectionRecord) {
    std::fs::OpenOptions::new().append(true).open(path).unwrap()
        .write_all(&collection_record_header(&record)).unwrap();
}

fn additions(change: RecordViewChanges) -> Vec<CollectionRecord> {
    match change {
        RecordViewChanges::Append(views) => views.iter().map(CollectionRecordView::to_record).collect(),
        other => panic!("expected occurrence append, got {other:?}"),
    }
}

#[test]
fn occurrence_same_coordinate_check_keeps_first_body_root_and_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coordinate.pile");
    let original = collection_record_header(&record(3));
    std::fs::write(&path, &original).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let before = pile.snapshot().unwrap();
    let key = collection_record_key(&record(3), 0);
    let pointer = before.collection_records.commits.get(&key).unwrap().as_bytes().as_ptr();
    // Both calls are occupied, so neither adopts the temporary body storage.
    checked_insert(&mut pile.collection_records.commits, &key, &record(3).to_bytes(), &pile.mmap).unwrap();
    assert!(pile.collection_records.shares_root(&before.collection_records));
    assert!(matches!(checked_insert(&mut pile.collection_records.commits, &key,
        &record(4).to_bytes(), &pile.mmap), Err(ReadError::IoError(_))));
    assert!(pile.collection_records.shares_root(&before.collection_records));
    assert_eq!(pile.collection_records.commits.get(&key).unwrap().as_bytes().as_ptr(), pointer);
    assert_eq!(std::fs::read(&path).unwrap(), original);
    pile.close().unwrap();
}

#[test]
fn occurrence_duplicate_keeps_both_offsets_and_actual_mapping_owners() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owner.pile");
    let frame = collection_record_header(&record(3));
    std::fs::write(&path, &frame).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let first = pile.snapshot().unwrap();
    let old = Arc::downgrade(&first.mmap);
    let key = collection_record_key(&record(3), 0);
    let pointer = first.collection_records.commits.get(&key).unwrap().as_bytes().as_ptr();
    pile.ensure_mapped(pile.mmap.len() + 1).unwrap();
    let new = Arc::downgrade(&pile.mmap);
    append(&path, record(3));
    let after = pile.snapshot().unwrap();
    assert!(!first.collection_records.shares_root(&after.collection_records));
    assert_eq!(after.collection_records.commits.len(), 2);
    let original = after.collection_records.commits.get(&key).unwrap().clone();
    let second_key = collection_record_key(&record(3), frame.len());
    let duplicate = after.collection_records.commits.get(&second_key).unwrap().clone();
    assert_eq!(original.as_bytes().as_ptr(), pointer);
    assert_ne!(duplicate.as_bytes().as_ptr(), pointer);
    drop(first); drop(after); pile.close().unwrap();
    assert!(old.upgrade().is_some() && new.upgrade().is_some());
    drop(duplicate);
    assert!(new.upgrade().is_none());
    assert!(old.upgrade().is_some());
    drop(original);
    assert!(old.upgrade().is_none());
}

#[test]
fn occurrence_origin_guard_precedes_equal_keys_and_notifies_selected_readers() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.pile");
    let b = dir.path().join("b.pile");
    std::fs::write(&a, collection_record_header(&record(3))).unwrap();
    std::fs::write(&b, collection_record_header(&record(4))).unwrap();
    let mut pa = PileFile::open(&a).unwrap();
    let mut pb = PileFile::open(&b).unwrap();
    let sa = pa.snapshot().unwrap();
    let sb = pb.snapshot().unwrap();
    // Equal source-local coordinates are NOT equal signed assertions.
    assert_eq!(sa.collection_records.commits, sb.collection_records.commits);
    let selectors = BTreeSet::from([CollectionRecordSelector::Foundations(record(3).collection())]);
    assert!(matches!(sb.select_record_view_changes(&sa, &selectors).unwrap(), RecordViewChanges::Rebuild));
    assert!(sb.changes_since(&sa).contains(StoreChanges::COLLECTION_RECORDS));
    let dependencies = StoreDependencies { records: selectors.iter().copied().collect(), ..Default::default() };
    assert!(sb.changes_for(&sa, &dependencies).contains(StoreChanges::COLLECTION_RECORDS));
    assert_eq!(sb.select_record_changes(&sa, &selectors).unwrap(), (vec![record(4)], vec![record(3)]));
    let mut fresh = Vec::new();
    crate::collection::covered::RecordDelta::for_each_record_since(&sb, Some(&sa), &mut |record| fresh.push(*record));
    assert_eq!(fresh, vec![record(4)]);
    pa.close().unwrap(); pb.close().unwrap();
}

#[test]
fn occurrence_stream_is_lazy_snapshot_ordered_and_keeps_needed_owners() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stream.pile");
    let reversed = dir.path().join("reversed.pile");
    let mut records: Vec<_> = (3..19).map(record).collect();
    records.push(record(3));
    std::fs::write(&path, records.iter().flat_map(collection_record_header).collect::<Vec<_>>()).unwrap();
    std::fs::write(&reversed, records.iter().rev().flat_map(collection_record_header).collect::<Vec<_>>()).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let mut other = PileFile::open(&reversed).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let independent = other.snapshot().unwrap();
    let expected = snapshot.collection_records.clone().into_fixed().collect::<Vec<_>>();
    let mut oracle = records.clone(); oracle.sort_unstable();
    let mut actual = expected.clone(); actual.sort_unstable();
    assert_eq!(actual, oracle);
    let mut reversed_actual = independent.collection_records.clone().into_fixed().collect::<Vec<_>>();
    reversed_actual.sort_unstable();
    assert_eq!(reversed_actual, oracle); // no cross-source traversal-order promise
    assert_eq!(snapshot.collection_records.clone().into_fixed().collect::<Vec<_>>(), expected);
    let owners = Arc::strong_count(&snapshot.mmap);
    COLLECTION_RECORD_READS.set(0);
    let mut cursor = snapshot.collection_records.clone().into_fixed();
    assert_eq!(COLLECTION_RECORD_READS.get(), 0);
    assert_eq!(Arc::strong_count(&snapshot.mmap), owners, "cursor does not clone every View");
    assert_eq!(cursor.next().unwrap(), expected[0]);
    assert_eq!(COLLECTION_RECORD_READS.get(), 1);
    let collection = record(3).collection();
    let overlapping = BTreeSet::from([
        CollectionRecordSelector::Foundations(collection),
        CollectionRecordSelector::CommitMember(collection, Inline::new([2; 32])),
    ]);
    assert_eq!(snapshot.select_records(&overlapping).unwrap(), expected);
    let selectors = BTreeSet::from([CollectionRecordSelector::Foundations(collection)]);
    let views = snapshot.select_record_views(&selectors).unwrap();
    assert_eq!(views.iter().map(CollectionRecordView::to_record).collect::<Vec<_>>(), expected);
    for view in &views {
        assert_eq!(view.to_bytes(), view.to_record().to_bytes());
        assert_eq!(view.fingerprint(), view.to_record().fingerprint());
    }
    let survivor = views[0].clone();
    let owner = Arc::downgrade(&snapshot.mmap);
    drop(views); drop(snapshot); drop(independent);
    pile.close().unwrap(); other.close().unwrap();
    assert_eq!(cursor.collect::<Vec<_>>(), expected[1..]);
    assert!(owner.upgrade().is_some());
    std::thread::spawn(move || assert_eq!(survivor.to_bytes(), survivor.to_record().to_bytes())).join().unwrap();
    assert!(owner.upgrade().is_none());
}

#[test]
fn occurrence_view_updates_distinguish_append_rebuild_and_semantic_delta() {
    use crate::collection::CollectionMerge;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("updates.pile");
    std::fs::write(&path, collection_record_header(&record(3))).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let before = pile.snapshot().unwrap();
    let selectors = BTreeSet::from([CollectionRecordSelector::Foundations(record(3).collection())]);
    assert!(before.select_record_views(&BTreeSet::new()).unwrap().is_empty());
    assert!(additions(before.select_record_view_changes(&before, &BTreeSet::new()).unwrap()).is_empty());
    append(&path, record(3));
    pile.insert(record(4)).unwrap();
    let after = pile.snapshot().unwrap();
    assert_eq!(additions(after.select_record_view_changes(&before, &selectors).unwrap()), vec![record(3), record(4)]);
    assert_eq!(after.select_record_changes(&before, &selectors).unwrap(), (vec![record(4)], vec![]));
    assert!(matches!(before.select_record_view_changes(&after, &selectors).unwrap(), RecordViewChanges::Rebuild));
    let merge = CollectionRecord::Merge(CollectionMerge::sign(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]), record(3).collection(),
        (0..8).map(|n| Inline::new([n; 32])), Inline::new([31; 32]),
    ).unwrap());
    pile.insert(merge).unwrap(); append(&path, merge);
    let later = pile.snapshot().unwrap();
    let all = BTreeSet::from([CollectionRecordSelector::Collection(record(3).collection())]);
    assert_eq!(additions(later.select_record_view_changes(&after, &all).unwrap()), vec![merge, merge]);
    assert_eq!(later.select_record_changes(&after, &all).unwrap(), (vec![merge], vec![]));
    assert_eq!(before.select_record_views(&selectors).unwrap().len(), 1);
    pile.close().unwrap();
}
