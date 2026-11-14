//! The metadata attributes are described with metadata attributes, and their
//! encodings' descriptions are written with them too. Building those records
//! from a cold process must terminate.
//!
//! This is its own test binary, with one test, so every lazy cache below is
//! cold when the test starts: no other test can have built them first.

use std::sync::mpsc;
use std::time::Duration;

use triblespace_core::blob::encodings::rawbytes::RawBytes;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::encodings::wasmcode::WasmCode;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::prelude::inlineencodings::GenId;
use triblespace_core::prelude::*;

fn blob_encoding_of(facts: &TribleSet, encoding: Id) -> Option<Id> {
    find!(
        (blob: Id),
        pattern!(facts, [{ encoding @ metadata::blob_encoding: ?blob }])
    )
    .map(|(blob,)| blob)
    .next()
}

fn is_tagged(facts: &TribleSet, entity: Id, kind: Id) -> bool {
    exists!(pattern!(facts, [{ entity @ metadata::tag: kind }]))
}

#[test]
fn building_the_metadata_attributes_descriptions_terminates() {
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        // First touch of each record, in an order that starts from the
        // attributes every other description is written with.
        let value_encoding = metadata::value_encoding.meta().clone();
        let blob_encoding = metadata::blob_encoding.meta().clone();
        let name = metadata::name.meta().clone();
        let description = metadata::description.meta().clone();
        let tag = metadata::tag.meta().clone();
        let value_formatter = metadata::value_formatter.meta().clone();
        let module = metadata::describe();
        // And a runtime attribute, whose encoding is described with the same
        // attributes. RawBytes, because no metadata attribute uses it: only
        // the runtime path can describe it.
        let runtime = Attribute::<Handle<RawBytes>>::named("bootstrap_probe");
        let used = entity! { runtime: &b"bootstrap payload"[..] };
        done.send((
            value_encoding,
            blob_encoding,
            name,
            description,
            tag,
            value_formatter,
            module,
            used,
        ))
        .unwrap();
    });
    let (value_encoding, blob_encoding, name, description, tag, value_formatter, module, used) =
        finished
            .recv_timeout(Duration::from_secs(60))
            .expect("building metadata attribute descriptions did not finish within 60 s");

    let genid = <GenId as MetaDescribe>::id();
    let text_handle = <Handle<UTF8String> as MetaDescribe>::id();
    let wasm_handle = <Handle<WasmCode> as MetaDescribe>::id();

    // Each record describes its own encoding.
    for (label, record) in [
        ("value_encoding", &value_encoding),
        ("blob_encoding", &blob_encoding),
        ("tag", &tag),
    ] {
        assert!(
            is_tagged(record.facts(), genid, metadata::KIND_INLINE_ENCODING),
            "{label}: GenId is described"
        );
    }
    for (label, record) in [("name", &name), ("description", &description)] {
        assert_eq!(
            blob_encoding_of(record.facts(), text_handle),
            Some(<UTF8String as MetaDescribe>::id()),
            "{label}: Handle<UTF8String> is described as a handle"
        );
    }
    assert_eq!(
        blob_encoding_of(value_formatter.facts(), wasm_handle),
        Some(<WasmCode as MetaDescribe>::id()),
        "value_formatter: Handle<WasmCode> is described as a handle"
    );

    // The module description is the union of those records.
    assert_eq!(
        blob_encoding_of(module.facts(), wasm_handle),
        Some(<WasmCode as MetaDescribe>::id())
    );

    // The cached records are stable: a second read returns the same record.
    assert_eq!(&value_encoding, metadata::value_encoding.meta());
    assert_eq!(&name, metadata::name.meta());

    assert_eq!(
        blob_encoding_of(used.metafacts(), <Handle<RawBytes> as MetaDescribe>::id()),
        Some(<RawBytes as MetaDescribe>::id())
    );
}
