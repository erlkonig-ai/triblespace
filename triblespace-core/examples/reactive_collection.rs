//! Run: cargo run -p triblespace-core --no-default-features --example reactive_collection

use ed25519_dalek::SigningKey;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
use triblespace_core::metadata;
use triblespace_core::prelude::*;
use triblespace_core::query::register::Resolution;
use triblespace_core::reactive::collection::{schema as c, CollectionEnvironment};
use triblespace_core::reactive::{schema as r, Progress};
use triblespace_core::repo::memoryrepo::MemoryRepo;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut store = MemoryRepo::default();
    let policy = AdmissionPolicy::direct(key.verifying_key());
    let root = store.collection(
        "additive rules",
        CollectionPolicy::new(policy.clone(), policy),
    )?;
    let (anchor, rule, reading, subject, input, output, observed, inferred) = (
        genid(),
        genid(),
        genid(),
        genid(),
        genid(),
        genid(),
        genid(),
        genid(),
    );
    let input_value: Inline<inlineencodings::GenId> = (&observed).to_inline();
    let output_value: Inline<inlineencodings::GenId> = (&inferred).to_inline();
    let mut program = entity! { &rule @ r::operation: r::POSITIVE };
    let matches = entity! {
        r::subject: &subject,
        r::predicate: metadata::tag.id(),
        r::object: &input,
    };
    let emits = entity! {
        r::subject: &subject,
        r::predicate: metadata::tag.id(),
        r::object: &output,
    };
    program += entity! { &rule @ r::matches*: matches, r::emits*: emits };
    program += entity! { &input @ r::literal: input_value.transmute::<UnknownInline>() };
    program += entity! { &output @ r::literal: output_value.transmute::<UnknownInline>() };
    program += entity! { &reading @ c::reading_of: &anchor, c::selects: &rule };
    store.commit(root, &key, program)?;
    let item = genid();
    store.commit(root, &key, entity! { &item @ metadata::tag: &observed })?;

    // ANCHOR: reactive_collection_run
    let mut environment = CollectionEnvironment::new(root, *anchor);
    let snapshot = store.snapshot()?;
    let resolution = environment.observe(&snapshot)?;
    if !matches!(resolution, Resolution::Sole(_)) {
        println!("execution reading needs an explicit choice: {resolution:?}");
        return Ok(());
    }
    loop {
        let computation = environment.advance(16, &snapshot);
        // A later failing binding may follow successful new conclusions.
        // Settle publication even when computation returned an error, and keep
        // both outcomes visible. A failed publication leaves the batch intact.
        let publication = environment.publish(&mut store, &key);
        if let Err(error) = &publication {
            eprintln!("publication: {error}");
        }
        if let Err(error) = &computation {
            eprintln!("evaluation: {error}");
        }
        publication?;
        let advance = computation?;
        if advance.progress == Progress::Quiescent {
            break;
        }
    }
    // ANCHOR_END: reactive_collection_run
    assert!(exists!(pattern!(environment.facts(), [
        { *item @ metadata::tag: &inferred }
    ])));
    println!("The inferred tag is now an ordinary published fact.");
    Ok(())
}
