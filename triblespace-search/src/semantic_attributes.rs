//! Shared semantic descriptor arguments, independent of an embedder runtime.

use triblespace_core::inline::encodings::{genid::GenId, shortstring::ShortString};
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
    "1B1FFA9CC2BC1FCA50D2389F1B980BAC" as pub semantic_compute: ShortString;
}

// Preserve the historical doc link when documenting the Nomic API. The new
// WeMM mapping does not use this architecture heuristic for its capability.
#[cfg(feature = "semantic")]
use crate::semantic::local_compute;
