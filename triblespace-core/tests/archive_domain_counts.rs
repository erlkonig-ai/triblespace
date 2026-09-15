//! What `SuccinctArchive`'s domain counts actually mean.
//!
//! # Why this exists
//!
//! A benchmark census — `number-of-subjects`, `-objects`, `-literals` — was
//! measured at 26.4% of a full-scale run (5,438,076 of 20,596,797 ms over
//! 561M tribles). All three enumerate EVERY trible and hash-dedupe in Rust
//! to produce one integer:
//!
//! ```ignore
//! let all: HashSet<Id> = find!(
//!     (e: Id, a: Id, v: Inline<UnknownInline>),
//!     pattern!(&ds.facts, [{ ?e @ ?a: ?v }])
//! ).map(|(e, _, _)| e).collect();
//! ```
//!
//! The archive already stores `entity_count` / `attribute_count` /
//! `value_count` as public fields. The proposal to answer count-distinct
//! from them is only worth anything if those fields mean what their names
//! suggest, so this pins the semantics rather than assuming them — the
//! difference between "the index probably knows" and "here is the
//! substitution".
//!
//! It deliberately uses a set where the three counts DIFFER and where
//! entities also appear in value position, because a fixture in which every
//! count coincides cannot distinguish "distinct entities" from "distinct
//! anything".

use std::collections::HashSet;

use triblespace_core::blob::encodings::succinctarchive::{OrderedUniverse, SuccinctArchive};
use triblespace_core::id::{rngid, Id};
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::prelude::*;

mod ns {
    use triblespace_core::prelude::*;
    attributes! {
        "9AC1C1DB25E0FE02FE302C96300EBEA1" unsafe as pub knows: inlineencodings::GenId;
        "D401D639C2DE979CD77D7BB277B3DE2E" unsafe as pub label: inlineencodings::ShortString;
        "20D8DCFDFDA35E52E3ED4CD2E0A66D52" unsafe as pub note: inlineencodings::ShortString;
    }
}

#[test]
fn domain_counts_are_the_distinct_values_in_each_position() {
    // Three entities, two of which also appear as VALUES (via `knows`), so
    // "distinct entities" and "distinct values" are genuinely different
    // questions about this set.
    let a = rngid();
    let b = rngid();
    let c = rngid();

    let mut set = TribleSet::new();
    set += entity! { &a @ ns::label: "alpha", ns::knows: &b };
    set += entity! { &b @ ns::label: "beta", ns::knows: &c };
    set += entity! { &c @ ns::label: "gamma", ns::note: "gamma" };
    // A repeated value: two entities share the label text "alpha".
    let d = rngid();
    set += entity! { &d @ ns::label: "alpha" };

    let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

    // Ground truth computed the expensive way — the same thing the census
    // query does, which is the point of comparison.
    let entities: HashSet<Id> = find!(
        (e: Id, at: Id, v: Inline<UnknownInline>),
        pattern!(&set, [{ ?e @ ?at: ?v }])
    )
    .map(|(e, _, _)| e)
    .collect();
    let attributes: HashSet<Id> = find!(
        (e: Id, at: Id, v: Inline<UnknownInline>),
        pattern!(&set, [{ ?e @ ?at: ?v }])
    )
    .map(|(_, at, _)| at)
    .collect();
    let values: HashSet<Inline<UnknownInline>> = find!(
        (e: Id, at: Id, v: Inline<UnknownInline>),
        pattern!(&set, [{ ?e @ ?at: ?v }])
    )
    .map(|(_, _, v)| v)
    .collect();

    assert_eq!(
        archive.entity_count(),
        entities.len(),
        "entity_count must be the distinct entities in subject position"
    );
    assert_eq!(
        archive.attribute_count(),
        attributes.len(),
        "attribute_count must be the distinct attributes"
    );
    assert_eq!(
        archive.value_count(),
        values.len(),
        "value_count must be the distinct values"
    );

    // The fixture has to be able to tell these apart, or the assertions
    // above are vacuous.
    assert_ne!(
        entities.len(),
        attributes.len(),
        "fixture must distinguish entity from attribute counts"
    );
    assert_ne!(
        entities.len(),
        values.len(),
        "fixture must distinguish entity from value counts"
    );
}
