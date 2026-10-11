//! Data import and conversion helpers bridging external formats into Trible Space.
//!
//! This module hosts adapters that translate common interchange formats into
//! [`TribleSet`](crate::trible::TribleSet) changes ready to merge into a
//! repository or workspace.

pub mod json;
pub mod json_tree;
pub mod ntriples;
pub mod scanner;

use triblespace_core_macros::attributes;

use crate::blob::encodings::utf8string::UTF8String;
use crate::inline::encodings::hash::Handle;

attributes! {
    /// The canonical RDF URI for an entity. Use this when importing data
    /// from an external vocabulary where the entity's identity is a URI —
    /// the same URI always deterministically maps to the same triblespace
    /// Id by round-tripping through an `rdf_uri` fragment.
    "AA68DE115445A63D62A63FF3284D030C" unsafe as pub rdf_uri: Handle<UTF8String>;

    /// BCP-47 language tag for a reified language-tagged literal entity.
    ///
    /// RDF's `"text"@lang` form is reified as a small entity with two
    /// attributes — `rdf_lang` (the BCP-47 tag) and `rdf_text` (the
    /// lexical form), both `UTF8String` blobs referenced by handle.
    /// Two literals with the same `(lang, text)` pair derive the same
    /// intrinsic id, giving content-addressed deduplication for free.
    "904DCA1F8C0BF087B02C0581F69EDF4D" as pub rdf_lang: Handle<UTF8String>;

    /// Lexical form of a reified language-tagged literal entity. See
    /// [`rdf_lang`] for the full encoding rationale.
    "02923632852C6AF8CD0D2596ACC343D2" unsafe as pub rdf_text: Handle<UTF8String>;
}
