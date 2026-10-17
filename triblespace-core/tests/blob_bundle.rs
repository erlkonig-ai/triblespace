use ed25519_dalek::SigningKey;
use triblespace_core::blob::Bytes;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};
use triblespace_core::prelude::blobencodings::{RawBytes, SimpleArchive, UTF8String};
use triblespace_core::prelude::inlineencodings::{GenId, Handle};
use triblespace_core::prelude::*;

attributes! {
    bundle_text: Handle<UTF8String>;
    bundle_archive: Handle<SimpleArchive>;
    bundle_bytes: Handle<RawBytes>;
    bundle_other_bytes: Handle<RawBytes>;
    bundle_child: GenId;
}

#[test]
fn construction_includes_the_root_and_preserves_all_supplied_attachments() {
    // These encoding markers implement neither Clone nor Debug. The carrier's
    // convenience traits must not accidentally require either marker bound.
    let root: Blob<UTF8String> = "a typed root".to_blob();
    let expected_root = root.get_handle();
    let mut attachments = MemoryBlobStore::new();
    let extra = attachments.insert::<RawBytes>(b"unrelated extra".as_slice().to_blob());
    attachments.insert(root.clone());

    let bundle = Bundle::new(root, attachments);
    let _: Inline<Handle<UTF8String>> = bundle.root();
    assert_eq!(bundle.root(), expected_root);
    assert_eq!(bundle.blobs().len(), 2, "the existing root deduplicates");
    assert!(format!("{bundle:?}").starts_with("Bundle"));

    let (root, mut blobs) = bundle.clone().into_parts();
    assert_eq!(root, bundle.root());
    assert_eq!(&blobs, bundle.blobs());
    let reader = blobs.snapshot().unwrap();
    let text: View<str> = reader.get(root).unwrap();
    let extra_bytes: Bytes = reader.get(extra).unwrap();
    assert_eq!(&*text, "a typed root");
    assert_eq!(&*extra_bytes, b"unrelated extra");

    blobs.insert::<RawBytes>(b"only the clone changes".as_slice().to_blob());
    assert_eq!(bundle.blobs().len(), 2);
    assert_eq!(blobs.len(), 3);
}

#[test]
fn spread_emits_one_typed_root_and_attachment_only_extras() {
    let root: Blob<RawBytes> = b"".as_slice().to_blob();
    let expected_root = root.get_handle();
    let bundle = Bundle::new(root, MemoryBlobStore::new());

    let (roots, extras) = bundle.spread();
    let roots: Vec<Inline<Handle<RawBytes>>> = roots.collect();
    assert_eq!(roots, [expected_root]);
    assert!(extras.exports().next().is_none());
    assert!(extras.facts().is_empty());
    assert!(extras.metafacts().is_empty());
    assert_eq!(extras.blobs().len(), 1);

    let mut blobs = extras.blobs().clone();
    let bytes: Bytes = blobs.snapshot().unwrap().get(expected_root).unwrap();
    assert!(bytes.is_empty(), "even an empty root's bytes are carried");
}

#[test]
fn nested_entity_spreading_carries_an_archive_without_merging_its_inner_graph() {
    let inner = entity! { bundle_text*: ["first inner text", "second inner text"] };
    let inner_facts = inner.facts().clone();
    let root: Blob<SimpleArchive> = inner.facts().to_blob();
    let mut attachments = inner.blobs().clone();
    let extra = attachments.insert::<RawBytes>(b"also carried".as_slice().to_blob());
    let bundle = Bundle::new(root, attachments);
    let root_handle: Inline<Handle<SimpleArchive>> = bundle.root();
    let mut carried = bundle.blobs().clone();
    let carried = carried.snapshot().unwrap();

    let outer = entity! { bundle_archive*: bundle };
    let outer_id = outer.root().unwrap();
    assert_eq!(outer.facts().len(), 1);
    let parent = entity! { bundle_child*: outer };
    assert_eq!(parent.facts().len(), 2);
    assert!(exists!(
        pattern!(&parent, [{ outer_id @ bundle_archive: root_handle }])
    ));
    assert!(!exists!(pattern!(&parent, [{ bundle_text: _?text }])));
    assert!(!exists!(pattern!(parent.metafacts(), [{
        triblespace_core::metadata::attribute: bundle_text.id()
    }])));

    let mut blobs = parent.blobs().clone();
    let reader = blobs.snapshot().unwrap();
    let archived: TribleSet = reader.get(root_handle).unwrap();
    assert_eq!(archived, inner_facts);
    for (handle, expected) in carried {
        let actual: Blob<blobencodings::UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(actual, expected);
    }
    let extra_bytes: Bytes = reader.get(extra).unwrap();
    assert_eq!(&*extra_bytes, b"also carried");
}

#[test]
fn independently_spread_bundles_deduplicate_shared_blobs() {
    let root: Blob<RawBytes> = b"shared root".as_slice().to_blob();
    let mut attachments = MemoryBlobStore::new();
    let shared = attachments.insert::<UTF8String>("shared attachment".to_blob());
    let left = Bundle::new(root.clone(), attachments.clone());
    let right = Bundle::new(root, attachments);
    let root = left.root();

    let fragment = entity! {
        bundle_bytes*: left,
        bundle_other_bytes*: right,
    };

    assert_eq!(fragment.facts().len(), 2);
    let mut blobs = fragment.blobs().clone();
    let reader = blobs.snapshot().unwrap();
    assert_eq!(
        reader
            .iter()
            .filter(|(handle, _)| handle.raw == root.raw)
            .count(),
        1
    );
    assert_eq!(
        reader
            .iter()
            .filter(|(handle, _)| handle.raw == shared.raw)
            .count(),
        1
    );
    let bytes: Bytes = reader.get(root).unwrap();
    let text: View<str> = reader.get(shared).unwrap();
    assert_eq!(&*bytes, b"shared root");
    assert_eq!(&*text, "shared attachment");
}

#[test]
fn construction_does_not_require_referenced_blobs_to_be_present() {
    let missing: Blob<UTF8String> = "not supplied".to_blob();
    let inner = entity! { bundle_text: missing.get_handle() };
    let root: Blob<SimpleArchive> = inner.facts().to_blob();
    let bundle = Bundle::new(root, MemoryBlobStore::new());
    assert_eq!(bundle.blobs().len(), 1);

    let mut blobs = bundle.blobs().clone();
    let reader = blobs.snapshot().unwrap();
    let archived: TribleSet = reader.get(bundle.root()).unwrap();
    assert_eq!(&archived, inner.facts());
    assert!(reader
        .get::<View<str>, UTF8String>(missing.get_handle())
        .is_err());
}

#[test]
fn ordinary_fragment_commit_publishes_the_root_and_every_carried_attachment() {
    let inner = entity! { bundle_text*: ["first committed text", "second committed text"] };
    let expected_inner = inner.facts().clone();
    let mut attachments = inner.blobs().clone();
    attachments.insert::<RawBytes>(b"unreferenced but published".as_slice().to_blob());
    let root: Blob<SimpleArchive> = inner.facts().to_blob();
    let bundle = Bundle::new(root, attachments);
    let root = bundle.root();
    let mut carried = bundle.blobs().clone();
    let carried = carried.snapshot().unwrap();
    let fragment = entity! { bundle_archive*: bundle };
    let expected_outer = fragment.facts().clone();
    let expected_meta = fragment.metafacts().clone();

    let authority = SigningKey::from_bytes(&[47; 32]);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "bundle-publication",
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority.verifying_key()),
                AdmissionPolicy::direct(authority.verifying_key()),
            ),
        )
        .unwrap();
    let commit = store.commit(collection, &authority, fragment).unwrap();
    let reader = store.snapshot().unwrap();

    let outer: TribleSet = collection.read(&reader).unwrap();
    let inner: TribleSet = reader.get(root).unwrap();
    let metadata: TribleSet = reader.get(commit.metadata()).unwrap();
    assert_eq!(outer, expected_outer);
    assert_eq!(inner, expected_inner);
    assert_eq!(metadata, expected_meta);
    for (handle, expected) in carried {
        let actual: Blob<blobencodings::UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(actual, expected);
    }
}
