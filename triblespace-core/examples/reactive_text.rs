//! Run: cargo run -p triblespace-core --no-default-features --example reactive_text
//! Synthetic text matching, not clinical decision support.

use std::collections::BTreeMap;
use std::fmt::Write;

use ed25519_dalek::SigningKey;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
use triblespace_core::prelude::blobencodings::UTF8String;
use triblespace_core::prelude::inlineencodings::{GenId, Handle};
use triblespace_core::prelude::*;
use triblespace_core::query::register::Resolution;
use triblespace_core::reactive::collection::{schema as c, CollectionEnvironment};
use triblespace_core::reactive::{text, Progress};
use triblespace_core::repo::memoryrepo::MemoryRepo;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn program(attributes: [Id; 5], ward42: Id) -> Result<(Fragment, Id)> {
    // The caller mints every identity before authoring. The parser never does.
    let mut ids: BTreeMap<&str, Id> = [
        "revision",
        "patient",
        "unit",
        "note",
        "needle",
        "alert",
        "c_ward",
        "c_note",
        "k_contains",
        "c_patient",
        "c_unit",
        "c_description",
        "c_backlink",
    ]
    .into_iter()
    .map(|name| (name, *genid()))
    .collect();
    ids.extend(
        [
            "ward",
            "clinical_note",
            "subject",
            "description",
            "alert_for",
        ]
        .into_iter()
        .zip(attributes),
    );
    ids.insert("ward42", ward42);
    let mut source = String::new();
    for (name, id) in &ids {
        writeln!(source, "alias {name} = id\"{id:x}\";")?;
    }
    source.push_str(
        r#"
// ANCHOR: reactive_text_rule
rule @revision {
  operation POSITIVE;
  matches @c_ward (?patient @ward ?unit);
  matches @c_note (?patient @clinical_note ?note);
  literal ?unit genid(@ward42);
  literal ?needle utf8("fever");
  constraint @k_contains STRING_CONTAINS(?note, ?needle);
  core @c_patient (?alert @subject ?patient);
  core @c_unit (?alert @ward ?unit);
  emits @c_description (?alert @description ?note);
  emits @c_backlink (?patient @alert_for ?alert);
}
// ANCHOR_END: reactive_text_rule
"#,
    );
    Ok((text::parse(source.into_bytes().into())?, ids["revision"]))
}

// Also exercised by the integration test, so the documented scenario stays runnable.
pub fn run(print_projection: bool) -> Result<()> {
    let ward = Attribute::<GenId>::anchored(*genid());
    let note = Attribute::<Handle<UTF8String>>::anchored(*genid());
    let subject = Attribute::<GenId>::anchored(*genid());
    let description = Attribute::<Handle<UTF8String>>::anchored(*genid());
    let alert_for = Attribute::<GenId>::anchored(*genid());
    let (ward42, patient, anchor, reading) = (genid(), genid(), genid(), genid());
    let attrs = [
        ward.id(),
        note.id(),
        subject.id(),
        description.id(),
        alert_for.id(),
    ];
    let (first, first_revision) = program(attrs, *ward42)?;
    let (second, second_revision) = program(attrs, *ward42)?;
    if print_projection {
        let mut rendered = String::new();
        text::write(first.facts(), &mut rendered)?;
        assert_eq!(
            text::parse(rendered.clone().into_bytes().into())?.facts(),
            first.facts()
        );
        println!("{rendered}");
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut store = MemoryRepo::for_host(key.verifying_key());
    let policy = AdmissionPolicy::direct(key.verifying_key());
    let root = store.collection(
        "synthetic matching",
        CollectionPolicy::new(policy.clone(), policy),
    )?;
    store.commit(root, &key, first + second)?;
    let mut env = CollectionEnvironment::new(root, *anchor);
    assert_eq!(env.observe(&store.snapshot()?)?, Resolution::Empty);
    store.commit(
        root,
        &key,
        entity! { &reading @
            c::reading_of: &anchor, c::selects*: [first_revision, second_revision]
        },
    )?;
    // Neither input commit satisfies the conjunction independently.
    store.commit(root, &key, entity! { &patient @ ward: &ward42 })?;
    let snapshot = store.snapshot()?;
    assert_eq!(env.observe(&snapshot)?, Resolution::Sole(*reading));
    assert!(env.advance(16, &snapshot)?.firings.is_empty());
    assert!(env.publish(&mut store, &key)?.is_none());
    // A joined row alone is insufficient: the parsed content constraint must
    // reject this note before either positive case can produce an alert.
    store.commit(
        root,
        &key,
        entity! { &patient @ note: "routine observation" },
    )?;
    let snapshot = store.snapshot()?;
    env.observe(&snapshot)?;
    assert!(env.advance(16, &snapshot)?.firings.is_empty());
    assert!(env.publish(&mut store, &key)?.is_none());
    let expected = entity! { subject: &patient, ward: &ward42 };
    let alert = expected.root().unwrap();
    for observed_note in ["reported fever", "fever subsiding"] {
        store.commit(root, &key, entity! { &patient @ note: observed_note })?;
        let snapshot = store.snapshot()?;
        env.observe(&snapshot)?;
        let advanced = env.advance(16, &snapshot)?;
        assert_eq!(advanced.progress, Progress::Quiescent);
        assert_eq!(advanced.firings.len(), 2);
        for firing in advanced.firings {
            assert_eq!(
                firing.constructed.values().copied().collect::<Vec<_>>(),
                vec![alert]
            );
        }
        let annotation: Inline<Handle<UTF8String>> = observed_note.to_inline();
        assert!(exists!(pattern!(env.facts(), [
            { alert @ description: annotation, subject: &patient, ward: &ward42 },
            { *patient @ alert_for: alert }
        ])));
        assert!(env.publish(&mut store, &key)?.is_some());
    }
    let durable: TribleSet = root.read(&store.snapshot()?)?;
    assert_eq!(durable, *env.facts());
    let mut reopened = CollectionEnvironment::new(root, *anchor);
    let snapshot = store.snapshot()?;
    reopened.observe(&snapshot)?;
    assert_eq!(reopened.advance(16, &snapshot)?.firings.len(), 4);
    assert!(reopened.publish(&mut store, &key)?.is_none());
    println!("Two revisions and two notes converge on one native core, with both descriptions published.");
    Ok(())
}

#[allow(dead_code)]
fn main() -> Result<()> {
    run(true)
}
