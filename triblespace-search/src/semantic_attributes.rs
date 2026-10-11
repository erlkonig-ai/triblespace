//! Shared semantic descriptor arguments, independent of an embedder runtime.

use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::inline::encodings::{genid::GenId, hash::Handle};
use triblespace_core::inline::{Inline, IntoInline, RawInline};
use triblespace_core::macros::attributes;

attributes! {
    /// An attribute whose values are handles to content bytes; repeatable.
    /// Every distinct value under any selected attribute gets at most one
    /// row per derivation, when the index's model has something to read in
    /// its bytes; the joined index holds one row per differing embedding of
    /// it and a reader binds the value once. Minted 2026-09-13.
    "13E4B93C65EA173282139D7DEBC1CC9B" as pub semantic_content_attribute: GenId;
    /// The compute class this index is canonical on; see [`local_compute`].
    /// Minted 2026-09-13.
    "1B1FFA9CC2BC1FCA50D2389F1B980BAC" as pub semantic_compute: Handle<UTF8String>;
}

/// Every compute class a semantic descriptor can name: the values
/// `local_compute` reports, of which `gb10` is canonical.
pub const COMPUTE_CLASSES: [&str; 3] = ["gb10", "apple", "other"];

/// The compute class a descriptor's [`semantic_compute`] argument names.
///
/// A descriptor carries the text by handle and a loaded descriptor carries no
/// blobs, so the class is recognised by comparing content handles against
/// the known names. A class this build does not know is `None`.
pub fn compute_class(raw: RawInline) -> Option<&'static str> {
    let value = Inline::<Handle<UTF8String>>::new(raw);
    COMPUTE_CLASSES
        .into_iter()
        .find(|name| value == (*name).to_inline())
}

// Preserve the historical doc link when documenting the Nomic API. The new
// WeMM mapping does not use this architecture heuristic for its capability.
#[cfg(feature = "semantic")]
use crate::semantic::local_compute;
