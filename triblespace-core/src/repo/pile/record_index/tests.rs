use super::*;
use crate::repo::SnapshotSource;
use crate::collection::CollectionRead;
use crate::patch::PatchHash;

fn record(metadata: u8) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        Inline::new([1; 32]), Inline::new([2; 32]), Inline::new([metadata; 32]),
    ))
}
struct ForcedCollision;
impl ForcedCollision { fn enter() -> Self { FORCE_COLLISION.set(true); Self } }
impl Drop for ForcedCollision { fn drop(&mut self) { FORCE_COLLISION.set(false); } }

#[test]
fn compact_collision_refuses_without_repair_or_source_truncation() {
    let _forced = ForcedCollision::enter();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("collision.pile");
    let original: Vec<u8> = [record(3), record(4)].iter().flat_map(collection_record_header).collect();
    std::fs::write(&path, &original).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    assert!(matches!(pile.snapshot(), Err(ReadError::IoError(e)) if e.to_string().contains("discriminator collision")));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), original.len() as u64);
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(pile.collection_records.clone().into_fixed().collect::<Vec<_>>(), vec![record(3)]);
    pile.close().unwrap();
}

#[test]
fn compact_independent_root_collision_is_documented_key_only_delta_limit() {
    let _forced = ForcedCollision::enter();
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.pile");
    let b = dir.path().join("b.pile");
    std::fs::write(&a, collection_record_header(&record(3))).unwrap();
    std::fs::write(&b, collection_record_header(&record(4))).unwrap();
    let mut pa = PileFile::open(&a).unwrap();
    let mut pb = PileFile::open(&b).unwrap();
    let sa = pa.snapshot().unwrap();
    let sb = pb.snapshot().unwrap();
    assert_ne!(sa.records().unwrap().next().unwrap().unwrap(), sb.records().unwrap().next().unwrap().unwrap());
    assert_eq!(sa.collection_records.commits, sb.collection_records.commits);
    assert!(sa.collection_records.difference(&sb.collection_records).is_empty());
    assert!(sb.collection_records.difference(&sa.collection_records).is_empty());
    // This is a COUNTEREXAMPLE to unconditional exact-byte identity, not success
    // at collision recovery. Both original signed bodies remain independently
    // readable, but compact key algebra cannot observe their differing values.
    pa.close().unwrap(); pb.close().unwrap();
}

#[test]
fn compact_duplicate_keeps_original_pointer_and_drops_remapped_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owner.pile");
    std::fs::write(&path, collection_record_header(&record(3))).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let first = pile.snapshot().unwrap();
    let old = Arc::downgrade(&first.mmap);
    let key = compact_key(&record(3).to_bytes());
    let pointer = first.collection_records.commits.get(&key).unwrap().as_bytes().as_ptr();
    pile.ensure_mapped(pile.mmap.len() + 1).unwrap();
    let unused = Arc::downgrade(&pile.mmap);
    use std::io::Write;
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(&collection_record_header(&record(3))).unwrap();
    let after = pile.snapshot().unwrap();
    assert!(first.collection_records.shares_root(&after.collection_records));
    let survivor = after.collection_records.commits.get(&key).unwrap().clone();
    assert_eq!(survivor.as_bytes().as_ptr(), pointer);
    drop(first); drop(after); pile.close().unwrap();
    assert!(unused.upgrade().is_none());
    assert!(old.upgrade().is_some());
    assert_eq!(survivor.to_record_trusted(), match record(3) { CollectionRecord::Commit(r) => r, _ => unreachable!() });
    drop(survivor);
    assert!(old.upgrade().is_none());
}

#[test]
fn compact_discriminator_is_not_cached_patch_digest_or_unique_member() {
    let a = record(3).to_bytes();
    let b = record(4).to_bytes();
    let ka = compact_key(&a); let kb = compact_key(&b);
    assert_eq!(&ka[..64], &kb[..64]);
    assert_ne!(ka, kb);
    XorSip128::init();
    assert_ne!(XorSip128::leaf(&a), XorSip128::leaf(&ka));
    assert_eq!(&ka[64..], &record(3).fingerprint().raw());
    println!("compact sizes: key={} typed_view={} trusted_carrier={}", KEY_LEN,
        std::mem::size_of::<View<EncodedCommit>>(), std::mem::size_of::<CollectionRecordView>());
}

#[test]
fn valued_collision_keeps_shared_root_first_body_and_source_after_refresh_error() {
    let _forced = ForcedCollision::enter();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared-collision.pile");
    std::fs::write(&path, collection_record_header(&record(3))).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let before = pile.snapshot().unwrap();
    let original: Vec<u8> = [record(3), record(4)].iter().flat_map(collection_record_header).collect();
    use std::io::Write;
    std::fs::OpenOptions::new().append(true).open(&path).unwrap()
        .write_all(&collection_record_header(&record(4))).unwrap();
    assert!(matches!(pile.refresh(), Err(ReadError::IoError(_))));
    assert!(pile.collection_records.shares_root(&before.collection_records));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(before.collection_records.clone().into_fixed().collect::<Vec<_>>(), vec![record(3)]);
    pile.close().unwrap();
}

#[test]
fn valued_stream_is_lazy_deterministic_and_keeps_only_needed_owners() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stream.pile");
    let reversed = dir.path().join("reversed.pile");
    let records: Vec<_> = (3..19).map(record).collect();
    std::fs::write(&path, records.iter().flat_map(collection_record_header).collect::<Vec<_>>()).unwrap();
    std::fs::write(&reversed, records.iter().rev().flat_map(collection_record_header).collect::<Vec<_>>()).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let mut other = PileFile::open(&reversed).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let independent = other.snapshot().unwrap();
    let expected = snapshot.collection_records.clone().into_fixed().collect::<Vec<_>>();
    assert_eq!(expected.iter().copied().collect::<BTreeSet<_>>(), records.iter().copied().collect());
    assert_eq!(expected.len(), records.len());
    assert_eq!(independent.collection_records.clone().into_fixed().collect::<Vec<_>>(), expected);
    let owners = Arc::strong_count(&snapshot.mmap);
    COLLECTION_RECORD_READS.set(0);
    let mut cursor = snapshot.collection_records.clone().into_fixed();
    assert_eq!(COLLECTION_RECORD_READS.get(), 0, "constructing a cursor does not decode the collection");
    assert_eq!(Arc::strong_count(&snapshot.mmap), owners, "persistent leaf handles do not clone Views");
    let first = cursor.next().unwrap();
    assert_eq!(first, expected[0]);
    assert_eq!(COLLECTION_RECORD_READS.get(), 1);
    let selectors = BTreeSet::from([CollectionRecordSelector::Foundations(records[0].collection())]);
    let views = snapshot.select_record_views(&selectors).unwrap();
    assert_eq!(views.iter().map(CollectionRecordView::to_record).collect::<Vec<_>>(), expected);
    for view in &views { assert_eq!(view.fingerprint(), view.to_record().fingerprint()); }
    let survivor = views[0].clone();
    let owner = Arc::downgrade(&snapshot.mmap);
    drop(views);
    drop(snapshot);
    drop(independent);
    pile.close().unwrap();
    other.close().unwrap();
    assert_eq!(cursor.collect::<Vec<_>>(), expected[1..]);
    assert!(owner.upgrade().is_some());
    assert_eq!(survivor.to_record(), expected[0]);
    drop(survivor);
    assert!(owner.upgrade().is_none());
}

#[test]
fn valued_body_view_deltas_preserve_empty_cross_owner_and_mixed_fallback_paths() {
    use crate::collection::{CollectionMerge, CollectionStore, KIND_COLLECTION_COMMIT, KIND_COLLECTION_DERIVE};
    use std::io::Write;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let collection = Inline::new([1; 32]);
    let derive = |n| CollectionRecord::Derive(CollectionDerive::sign(
        &signer, collection, SourceLocator::of([n; 32]), Inline::new([9; 32]),
    ));
    let records = [record(3), derive(4), record(5), derive(6)];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("views.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    for record in records { pile.insert(record).unwrap(); }
    let before = pile.snapshot().unwrap();
    let weak = Arc::downgrade(&before.mmap);
    let selectors = BTreeSet::from([CollectionRecordSelector::Foundations(collection)]);
    let bodies = before.select_record_views(&selectors).unwrap();
    assert_eq!(bodies.len(), 4);
    assert_eq!(bodies.iter().map(CollectionRecordView::to_record).collect::<Vec<_>>(), before.select_records(&selectors).unwrap());
    assert!(before.select_record_views(&BTreeSet::new()).unwrap().is_empty());
    let empty_delta = before.select_record_view_changes(&before, &BTreeSet::new()).unwrap();
    assert!(empty_delta.0.is_empty() && empty_delta.1.is_empty());
    std::fs::OpenOptions::new().append(true).open(&path).unwrap()
        .write_all(&collection_record_header(&records[0])).unwrap();
    let duplicate = pile.snapshot().unwrap();
    assert!(duplicate.collection_records.shares_root(&before.collection_records));
    let unchanged = duplicate.select_record_view_changes(&before, &selectors).unwrap();
    assert!(unchanged.0.is_empty() && unchanged.1.is_empty());
    drop(duplicate);
    for body in &bodies {
        let record = body.to_record();
        assert!(records.contains(&record));
        let kind = match record {
            CollectionRecord::Commit(_) => KIND_COLLECTION_COMMIT,
            CollectionRecord::Derive(_) => KIND_COLLECTION_DERIVE,
            _ => unreachable!(),
        };
        assert_eq!(body.body_bytes().len(), 224);
        assert_eq!(body.body_bytes()[..32], kind);
        assert_eq!(body.body_bytes()[32..64], collection.raw);
        assert_eq!(body.to_bytes(), record.to_bytes());
        assert_eq!(body.fingerprint(), record.fingerprint());
        record.verify_strict().unwrap();
    }
    let added = record(7);
    pile.insert(added).unwrap();
    let after = pile.snapshot().unwrap();
    let (delta, removed) = after.select_record_view_changes(&before, &selectors).unwrap();
    assert_eq!(delta.iter().map(CollectionRecordView::to_record).collect::<Vec<_>>(), vec![added]);
    assert!(removed.is_empty());
    let other_path = dir.path().join("independent.pile");
    std::fs::File::create(&other_path).unwrap();
    let mut other = PileFile::open(&other_path).unwrap();
    other.insert(added).unwrap();
    for record in records.into_iter().rev() { other.insert(record).unwrap(); }
    let independent = other.snapshot().unwrap();
    let cross_owner = independent.select_record_view_changes(&after, &selectors).unwrap();
    assert!(cross_owner.0.is_empty() && cross_owner.1.is_empty());
    assert_eq!(before.select_record_views(&selectors).unwrap().len(), 4);
    other.insert(CollectionRecord::Merge(CollectionMerge::sign(
        &signer, collection, (0..8).map(|n| Inline::new([n; 32])), Inline::new([31; 32]),
    ).unwrap())).unwrap();
    let later = other.snapshot().unwrap();
    let all = BTreeSet::from([CollectionRecordSelector::Collection(collection)]);
    for (current, previous) in [(&later, &independent), (&independent, &later), (&later, &after)] {
        let owned = current.select_record_changes(previous, &all).unwrap();
        let views = current.select_record_view_changes(previous, &all).unwrap();
        assert_eq!(views.0.iter().map(CollectionRecordView::to_record).collect::<Vec<_>>(), owned.0);
        assert_eq!(views.1.iter().map(CollectionRecordView::to_record).collect::<Vec<_>>(), owned.1);
    }
    drop(delta);
    drop(before); drop(after); drop(independent); drop(later);
    pile.close().unwrap(); other.close().unwrap();
    assert!(weak.upgrade().is_some());
    let thread_bodies = bodies.clone();
    std::thread::spawn(move || {
        for body in thread_bodies { assert_eq!(body.to_bytes(), body.to_record().to_bytes()); }
    }).join().unwrap();
    drop(bodies);
    assert!(weak.upgrade().is_none());
}
