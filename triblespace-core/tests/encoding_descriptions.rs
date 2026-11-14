//! Fragments carry the description of each attribute's value ENCODING in their
//! metafacts, not only the encoding's id.
//!
//! An attribute record says `value_encoding: <id>`. Without the encoding's own
//! facts that id names an entity the pile never describes, so a reader cannot
//! tell, for example, that a `Handle<T>` value is a handle. These tests pin
//! that both declared (`attributes!`) and runtime (`anchored`, `named`, `iri`)
//! attributes carry those facts into `entity!` fragments and from there into a
//! commit's metadata archive, and that nothing about identity moves.

use anybytes::View;
use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::rawbytes::RawBytes;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::prelude::inlineencodings::GenId;
use triblespace_core::prelude::*;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreGet, SnapshotSource};

attributes! {
    /// A declared text handle (bare name: identity from name and encoding).
    ed_text: Handle<UTF8String>;
    /// A declared byte handle with an anchored identity.
    "693E4E7361C76E7105649B19D9DFE2B6" as ed_bytes: Handle<RawBytes>;
    /// A declared link with an anchored identity.
    "9D829DC0BD9DB524C7270838234E9FF0" as ed_link: GenId;
}

/// The blob encoding a `Handle` encoding's description names, if the given
/// fact set describes `encoding` as a handle.
fn described_blob_encoding(facts: &TribleSet, encoding: Id) -> Option<Id> {
    find!(
        (blob: Id),
        pattern!(facts, [{ encoding @ metadata::blob_encoding: ?blob }])
    )
    .map(|(blob,)| blob)
    .next()
}

fn described_name(fragment: &Fragment, facts: &TribleSet, entity: Id) -> Option<String> {
    let handle = find!(
        (name: Inline<Handle<UTF8String>>),
        pattern!(facts, [{ entity @ metadata::name: ?name }])
    )
    .map(|(name,)| name)
    .next()?;
    let mut store = fragment.blobs().clone();
    let reader = store.snapshot().expect("fragment blob-store snapshot");
    let name: View<str> = reader.get::<View<str>, UTF8String>(handle).ok()?;
    Some(name.to_string())
}

fn has_description(facts: &TribleSet, entity: Id) -> bool {
    exists!(pattern!(facts, [{ entity @ metadata::description: _?text }]))
}

/// Checks that `fragment`'s metafacts describe `Handle<T>` as a handle to `T`,
/// with both encodings named and documented, and that the name bytes travel
/// in the fragment's own store.
fn assert_describes_handle<T>(fragment: &Fragment, label: &str)
where
    T: BlobEncoding + MetaDescribe,
{
    let handle = <Handle<T> as MetaDescribe>::id();
    let blob = <T as MetaDescribe>::id();
    let meta = fragment.metafacts();
    assert_eq!(
        described_blob_encoding(meta, handle),
        Some(blob),
        "{label}: metafacts must say Handle<T> is a handle to T"
    );
    assert_eq!(
        described_name(fragment, meta, handle).as_deref(),
        Some("handle"),
        "{label}: the handle encoding is named, and its name blob is carried"
    );
    assert!(
        has_description(meta, handle),
        "{label}: the handle encoding is documented"
    );
    assert!(
        described_name(fragment, meta, blob).is_some(),
        "{label}: the blob encoding is named"
    );
    assert!(
        has_description(meta, blob),
        "{label}: the blob encoding is documented"
    );
    assert!(
        described_blob_encoding(fragment.facts(), handle).is_none(),
        "{label}: encoding descriptions stay out of the content facts"
    );
}

#[test]
fn declared_attributes_carry_their_encodings_description() {
    let fragment = entity! {
        ed_text: "declared text",
        ed_bytes: &b"declared bytes"[..],
    };
    assert_describes_handle::<UTF8String>(&fragment, "declared bare-name");
    assert_describes_handle::<RawBytes>(&fragment, "declared anchored");

    // The cached record itself holds it, so `describe()` of the declaring
    // module hands out the same thing `entity!` does.
    let described = describe();
    assert_eq!(
        described_blob_encoding(described.facts(), <Handle<UTF8String>>::id()),
        Some(UTF8String::id())
    );
}

#[test]
fn declared_inline_encodings_are_described_too() {
    let other = Id::from_hex("6C04AB7BF8163FF659F73F4BDE10C478").unwrap();
    let fragment = entity! { ed_link: &other };
    let genid = <GenId as MetaDescribe>::id();
    let meta = fragment.metafacts();
    assert!(exists!(pattern!(
        meta,
        [{ genid @ metadata::tag: metadata::KIND_INLINE_ENCODING }]
    )));
    assert_eq!(
        described_name(&fragment, meta, genid).as_deref(),
        Some("genid")
    );
}

#[test]
fn runtime_attributes_carry_their_encodings_description() {
    let named = Attribute::<Handle<RawBytes>>::named("ed_runtime_named");
    let anchored = Attribute::<Handle<UTF8String>>::anchored(
        Id::from_hex("AC48E140B8BB4B632F2ED6C06FB95D49").unwrap(),
    );
    let iri = Attribute::<Handle<RawBytes>>::iri("http://example.org/ed#runtime");

    // Each encoding is one that no metadata attribute in the identity uses,
    // so only the runtime path can have described it. (`metadata::name` and
    // `metadata::iri` are `Handle<UTF8String>`, so `named` and `iri` use
    // RawBytes; `anchored`'s identity is all GenId.)
    let fragment = entity! { named: &b"runtime bytes"[..] };
    assert_describes_handle::<RawBytes>(&fragment, "runtime named");
    let fragment = entity! { anchored: "anchored text" };
    assert_describes_handle::<UTF8String>(&fragment, "runtime anchored");
    let fragment = entity! { iri: &b"iri bytes"[..] };
    assert_describes_handle::<RawBytes>(&fragment, "runtime iri");

    // The description sits in the identity fragment's metafacts, beside (not
    // in) the identity facts.
    let identity = named.fragment();
    let handle = <Handle<RawBytes>>::id();
    assert_eq!(
        described_blob_encoding(identity.metafacts(), handle),
        Some(RawBytes::id())
    );
    assert!(described_blob_encoding(identity.facts(), handle).is_none());
}

#[test]
fn a_commits_metadata_archive_holds_the_encodings_description() {
    let signer = SigningKey::from_bytes(&[41; 32]);
    let root = signer.verifying_key();
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "encoding-descriptions",
            CollectionPolicy::new(
                AdmissionPolicy::delegable(root),
                AdmissionPolicy::direct(root),
            ),
        )
        .unwrap();

    let named = Attribute::<Handle<RawBytes>>::named("ed_committed_runtime");
    let mut fragment = entity! { ed_text: "committed text" };
    fragment += entity! { named: &b"committed bytes"[..] };
    let commit = store.commit(collection, &signer, fragment).unwrap();

    let snapshot = store.snapshot().unwrap();
    let metadata = snapshot
        .get::<TribleSet, SimpleArchive>(commit.metadata())
        .expect("the metadata archive is stored");
    assert_eq!(
        described_blob_encoding(&metadata, <Handle<UTF8String>>::id()),
        Some(UTF8String::id())
    );
    assert_eq!(
        described_blob_encoding(&metadata, <Handle<RawBytes>>::id()),
        Some(RawBytes::id())
    );

    // The description's text is in the store too, not only its handle.
    let text_handle = <Handle<UTF8String>>::id();
    let handle_name = find!(
        (name: Inline<Handle<UTF8String>>),
        pattern!(&metadata, [{ text_handle @ metadata::name: ?name }])
    )
    .map(|(name,)| name)
    .next()
    .expect("the handle encoding is named in the archive");
    let text: View<str> = snapshot.get::<View<str>, UTF8String>(handle_name).unwrap();
    assert_eq!(&*text, "handle");

    let data = snapshot
        .get::<TribleSet, SimpleArchive>(Handle::<SimpleArchive>::from_hash(commit.data()))
        .expect("the data archive is stored");
    assert!(
        described_blob_encoding(&data, <Handle<UTF8String>>::id()).is_none(),
        "descriptions never reach the data archive"
    );
}

/// The old constructors, verbatim: the identity fragment with no encoding
/// description. Every id and root must come out the same as the new ones.
fn before_named<S: InlineEncoding + MetaDescribe>(name: &str) -> Attribute<S> {
    Attribute::from_fragment_unchecked(entity! {
        metadata::name: name.to_owned(),
        metadata::value_encoding: <S as MetaDescribe>::id(),
        metadata::tag: metadata::KIND_ATTRIBUTE,
    })
}

fn before_anchored<S: InlineEncoding + MetaDescribe>(anchor: Id) -> Attribute<S> {
    Attribute::from_fragment_unchecked(entity! {
        metadata::anchor: GenId::inline_from(anchor),
        metadata::value_encoding: <S as MetaDescribe>::id(),
        metadata::tag: metadata::KIND_ATTRIBUTE,
    })
}

fn before_iri<S: InlineEncoding + MetaDescribe>(iri: &str) -> Attribute<S> {
    Attribute::from_fragment_unchecked(entity! {
        metadata::iri: iri.to_owned(),
        metadata::value_encoding: <S as MetaDescribe>::id(),
        metadata::tag: metadata::KIND_ATTRIBUTE,
    })
}

#[test]
fn ids_and_roots_are_unchanged() {
    let anchor = Id::from_hex("AC48E140B8BB4B632F2ED6C06FB95D49").unwrap();
    let iri_text = "http://example.org/ed#runtime";

    let named = Attribute::<Handle<RawBytes>>::named("ed_runtime_named");
    let anchored = Attribute::<Handle<UTF8String>>::anchored(anchor);
    let iri = Attribute::<Handle<UTF8String>>::iri(iri_text);
    let old_named = before_named::<Handle<RawBytes>>("ed_runtime_named");
    let old_anchored = before_anchored::<Handle<UTF8String>>(anchor);
    let old_iri = before_iri::<Handle<UTF8String>>(iri_text);

    // Against the pre-change construction, in this build.
    assert_eq!(named.id(), old_named.id());
    assert_eq!(anchored.id(), old_anchored.id());
    assert_eq!(iri.id(), old_iri.id());
    assert_eq!(named.fragment().facts(), old_named.fragment().facts());
    assert_eq!(anchored.fragment().facts(), old_anchored.fragment().facts());
    assert_eq!(iri.fragment().facts(), old_iri.fragment().facts());
    assert_eq!(named.fragment().root(), old_named.fragment().root());

    // Against values printed by the same expressions at triblespace-rs
    // c0b4ba08 (origin/main before this change), so the comparison does not
    // depend on this build's notion of "before".
    let golden = [
        ("named", named.id(), "77F4080BEA2676AFC59D4A1C7FE1B4F5"),
        (
            "anchored",
            anchored.id(),
            "06D3E5E4AC67C87E50C6673F57DB33EF",
        ),
        ("iri", iri.id(), "AED635CFA5D3430F1BE9A89A2E8C9F35"),
        ("ed_text", ed_text.id(), "12F03AE5BF441EFE48B3E28A29A838F2"),
        (
            "ed_bytes",
            ed_bytes.id(),
            "2B6D9FC3FC7087778814987FCC7F6D25",
        ),
        ("ed_link", ed_link.id(), "1788F53F3439A9CCF6D7484DEAF59624"),
    ];

    // A fragment over declared and runtime attributes: root and facts.
    let link = Id::from_hex("153C8E673A1F8E2C0F11C63ECE9D0664").unwrap();
    let new = entity! {
        ed_text: "root text",
        ed_bytes: &b"root bytes"[..],
        ed_link: &link,
        named: &b"runtime root bytes"[..],
        anchored: "anchored root text",
        iri: "iri root text",
    };
    let old = entity! {
        ed_text: "root text",
        ed_bytes: &b"root bytes"[..],
        ed_link: &link,
        old_named: &b"runtime root bytes"[..],
        old_anchored: "anchored root text",
        old_iri: "iri root text",
    };
    assert_eq!(new.root(), old.root());
    assert_eq!(new.facts(), old.facts());
    let root = new.root().expect("rooted");

    let mut printed = String::new();
    for (label, id, _) in golden {
        printed.push_str(&format!("{label} {id:X}\n"));
    }
    printed.push_str(&format!("root {root:X}\n"));
    for (label, id, expected) in golden {
        assert_eq!(
            format!("{id:X}"),
            expected,
            "{label} id moved; all printed:\n{printed}"
        );
    }
    assert_eq!(
        format!("{root:X}"),
        "98165E90767D80B7AFF4B7280497BE5A",
        "fragment root moved; all printed:\n{printed}"
    );
}
