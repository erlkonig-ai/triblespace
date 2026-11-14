//! An attribute record's encoding description must not depend on what the
//! process built before it.
//!
//! Records are built lazily, under a guard that makes nested attributes fall
//! back to their identity fragment, but a nested attribute whose record is
//! already cached hands out the whole record. If a record took the encoding
//! description's metafacts, a record built after the metadata records were
//! cached would carry those records too, and one built before would not. The
//! same fragment would then produce a different metadata archive, and a
//! different COMMIT, depending on the order of earlier work in the process.
//!
//! This is its own test binary, with one test, so the first build below is
//! cold.

use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::metadata;
use triblespace_core::prelude::*;

attributes! {
    /// Probe whose record is built while no metadata record is cached.
    ///
    /// Literal-pinned on purpose, and the only such declaration this test
    /// needs. An anchored or bare-name declaration derives its id from
    /// `<Handle<UTF8String> as MetaDescribe>::id()` when it is first touched,
    /// outside the record guard, and that builds and caches the metadata
    /// records before this probe's record exists, so the "cold" build would
    /// not be cold. The pinned form's identity fragment is built without any
    /// description. Id minted with `trible genid` on 2026-11-14.
    "8FB3A4220C32676B9246108482E69CF8" unsafe as cold_probe: Handle<UTF8String>;
    /// Probe whose record is built after every metadata record is cached.
    /// Anchor minted with `trible genid` on 2026-11-14.
    "F54402257C73E52988426F38E2383247" as warm_probe: Handle<UTF8String>;
}

/// Metafacts about anything but the probe attribute and its usage entity:
/// the part of the record contributed by the encoding description.
fn encoding_part(fragment: &Fragment, probe: Id) -> TribleSet {
    let usages: Vec<Id> = find!(
        (usage: Id),
        pattern!(fragment.metafacts(), [{ ?usage @ metadata::attribute: probe }])
    )
    .map(|(usage,)| usage)
    .collect();
    let mut part = TribleSet::new();
    for trible in fragment.metafacts().iter() {
        let e = *trible.e();
        if e != probe && !usages.contains(&e) {
            part.insert(trible);
        }
    }
    part
}

#[test]
fn a_records_encoding_description_does_not_depend_on_build_order() {
    let cold = entity! { cold_probe: "payload" };

    let _ = metadata::name.meta();
    let _ = metadata::description.meta();
    let _ = metadata::tag.meta();
    let _ = metadata::blob_encoding.meta();
    let _ = metadata::hash_schema.meta();
    let _ = metadata::value_formatter.meta();
    let _ = metadata::value_encoding.meta();

    let warm = entity! { warm_probe: "payload" };

    let cold_part = encoding_part(&cold, cold_probe.id());
    let warm_part = encoding_part(&warm, warm_probe.id());
    assert!(!cold_part.is_empty(), "the encoding is described at all");
    assert_eq!(
        cold_part.len(),
        warm_part.len(),
        "the encoding description depends on which records were cached first"
    );
    assert_eq!(cold_part, warm_part);
    assert_eq!(cold.blobs().len(), warm.blobs().len());
}
