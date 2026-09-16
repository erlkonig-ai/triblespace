// Prefer explicit `?` variable bindings in patterns instead of relying on
// parenthesisation. Do not suppress `unused_parens` at the crate level.
#![cfg_attr(nightly, feature(rustc_attrs, decl_macro, file_lock))]

extern crate self as triblespace_core;

#[allow(unused_extern_crates)]
extern crate proc_macro;

#[cfg(not(all(target_pointer_width = "64", target_endian = "little")))]
compile_error!("triblespace-rs requires a 64-bit little-endian target");

/// Whether this exact Core build contains its parallel execution paths.
///
/// Cargo can unify dependency features across consumers, so a caller's own
/// feature flags cannot answer this. This value does not initialize a Rayon
/// pool, count threads, select a backend, or claim that parallel work is active.
pub const PARALLEL_COMPILED: bool = cfg!(feature = "parallel");

/// Shared structural attributes for signed records and attestations.
pub mod attestation;
pub mod attribute;
/// Blob storage, schemas, and conversion traits.
pub mod blob;
/// Store-independent, blob-native capability claims and proofs.
pub mod capability;
/// Attribute definition and usage metadata.
pub mod clock;
/// Typed collection records, storage, publication, discovery, and resolution.
pub mod collection;
/// Export utilities for serialising trible data.
pub mod export;
/// Identifier types and generation strategies.
pub mod id;
/// Import utilities for deserialising external data into tribles.
pub mod import;
/// Inline types, schemas, and conversion traits.
pub mod inline;
/// Bootstrap metadata namespace for describing schemas and attributes.
pub mod metadata;
/// Adaptive radix tree (PATCH) used as the backing store for trible indexes.
pub mod patch;
/// Commonly used re-exports for convenient glob imports.
pub mod prelude;
/// Query engine: constraints, variables, and the Atreides join algorithm.
pub mod query;
/// Blob and record stores, WANTs, and explicit legacy-pile inspection.
pub mod repo;
/// Durable Ed25519 signing-key file resolution, loading, and initialization.
pub mod signing_key_file;
/// Trible representation, sets, fragments, and spread helpers.
pub mod trible;

#[cfg(feature = "wasm")]
/// WebAssembly integration helpers.
pub mod wasm;

#[cfg(feature = "wasm")]
/// WebAssembly-based value formatter runtime.
pub mod value_formatter;

/// Diagnostic wrappers for testing and debugging the query engine.
pub mod debug;
/// Example namespaces and sample datasets for documentation and tests.
pub mod examples;

// Re-export dependencies used by generated macros so consumers
// don't need to add them explicitly.
/// Re-export of `arrayvec` used by generated macro code.
pub use arrayvec;

/// Re-exported proc-macros and helper macros for entity, pattern, and query construction.
pub mod macros {
    /// Re-export of the [`id_hex`] macro.
    pub use crate::id::id_hex;
    /// Re-export of the [`find`] macro.
    pub use crate::query::find;
    /// Re-export of all proc-macros from `triblespace_core_macros`.
    pub use triblespace_core_macros::*;
}

// Proof harnesses and integration-style documentation tests live in the
// top-level `triblespace` crate so downstream users can depend on
// `triblespace-core` without pulling in additional development-only
// dependencies.
