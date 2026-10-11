//! Metadata namespace for the `triblespace` crate.
//!
//! This namespace is used to bootstrap the meaning of other namespaces.
//! It defines meta attributes that are used to describe other attributes.

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::utf8string::UTF8String;
use crate::blob::encodings::wasmcode::WasmCode;
use crate::id::Id;
use crate::id_hex;
use crate::prelude::inlineencodings;
use crate::trible::Fragment;
use core::marker::PhantomData;
use triblespace_core_macros::attributes;

/// Describes a runtime *instance* — emits metadata about a specific value (an
/// `Attribute<S>` with its id+name+usage, etc.). For describing a Rust *type*
/// itself (schema metadata for `GenId`, `Handle<T>`, …) use
/// [`MetaDescribe`].
///
/// `describe` returns a [`Fragment`] that's self-contained — its
/// embedded [`crate::blob::MemoryBlobStore`] holds any bytes the
/// returned facts reference by handle. Consumers wanting to persist
/// the description hand the fragment to a workspace.
pub trait Describe {
    /// Produces a [`Fragment`] describing this instance, with any
    /// long-form bytes embedded in its local blob store.
    fn describe(&self) -> Fragment;

    /// Returns the id of this instance. Default: derive from
    /// `self.describe().root()`. Override when the id is cheaper to
    /// compute directly (e.g. `Attribute<S>` reads it from its
    /// stored fragment).
    fn id(&self) -> Id {
        self.describe()
            .root()
            .expect("describe returns a rooted fragment")
    }
}

/// Describes a Rust *type* — emits schema metadata about the type itself
/// without needing an instance (`GenId`, `Handle<T>`, …). For
/// describing a runtime value use [`Describe`].
///
/// Same self-contained Fragment contract as [`Describe`]: the
/// returned Fragment's local blob store holds the bytes for any
/// handles in its facts.
pub trait MetaDescribe {
    /// Produces a [`Fragment`] describing this schema type.
    fn describe() -> Fragment;

    /// Returns the id of this type. Default: derive from
    /// `Self::describe().root()`. Impls choose whether the id is
    /// *explicit* (an `entity!{ &id_hex @ … }` form inside describe)
    /// or *derived* (no `@`, intrinsic id from the facts) — either
    /// way the default reads the root the fragment carries.
    ///
    /// Impls **must not** call `Self::id()` from inside their `describe`
    /// body — that would recurse through this default. Use the literal id
    /// directly in describe() or rely on no-`@` intrinsic derivation.
    ///
    /// No caching: each call re-runs describe + root. If id() becomes a hot
    /// path, layer a `TypeId`-keyed cache on top from the call site.
    fn id() -> Id {
        <Self as MetaDescribe>::describe()
            .root()
            .expect("describe returns a rooted fragment")
    }
}

impl<S> Describe for PhantomData<S>
where
    S: MetaDescribe,
{
    fn describe(&self) -> Fragment {
        <S as MetaDescribe>::describe()
    }

    // id() uses the default (describe + root).
}

// namespace constants
/// Tag for entities that can have multiple simultaneous kinds.
pub const KIND_MULTI: Id = id_hex!("C36D9C16B34729D855BD6C36A624E1BF");
/// Tag for entities that represent inline encodings.
pub const KIND_INLINE_ENCODING: Id = id_hex!("9A169BF2383E7B1A3E019808DFE3C2EB");
/// Tag for entities that represent blob encodings.
pub const KIND_BLOB_ENCODING: Id = id_hex!("CE488DB0C494C7FDBF3DF1731AED68A6");
/// Tag for entities that describe an attribute usage in some source context.
/// Marks an entity as an attribute itself, in its identity core.
///
/// Mirrors `KIND_BLOB_ENCODING` on `Array<T>`: without a kind in identity, an
/// attribute is indistinguishable from any other entity carrying an anchor and a
/// value encoding, and "which attributes exist here" is unanswerable — which the
/// id migration needs to enumerate.
///
/// Distinct from [`KIND_ATTRIBUTE_USAGE`], which tags the codebase-local
/// annotation (Rust identifier, source module) rather than the shared attribute.
pub const KIND_ATTRIBUTE: Id = id_hex!("1611CA4D740B7077EE27EBDD5274074B");
pub const KIND_ATTRIBUTE_USAGE: Id = id_hex!("45759727A79C28D657EC06D5C6013649");
/// Tag for entities that describe a protocol.
pub const KIND_PROTOCOL: Id = id_hex!("A04AD649FA28DC5904385532E9C8EF74");

/// A self-description of one source-to-target collection mapping algorithm.
///
/// Concrete mapping instances are content-derived entities: they name one
/// algorithm of this kind and carry that algorithm's parameters.
/// Minted with `trible genid` on 2026-08-29.
pub const KIND_COLLECTION_MAPPING_ALGORITHM: Id = id_hex!("8EE0F01DE7ED458E6B69BE748AF2C99D");
/// Tag for entities that are themselves tag/marker constants (e.g. kind discriminants).
pub const KIND_TAG: Id = id_hex!("452584B4C1CAE0B77F44408E6F194A31");

attributes! {
    /// Generic link to a canonical metadata archive.
    ///
    /// The surrounding record format decides whether this handle participates
    /// in an attestation and, if so, which transcript covers it.
    "88B59BD497540AC5AECDB7518E737C87" unsafe as pub archive: inlineencodings::Handle<SimpleArchive>;
    /// Optional long-form description stored as a UTF8String handle.
    ///
    /// This attribute is general-purpose: it can describe any entity. Schema
    /// metadata uses it for documenting value/blob encodings, but it is equally
    /// valid for domain entities.
    "AE94660A55D2EE3C428D2BB299E02EC3" unsafe as description: inlineencodings::Handle<UTF8String>;
    /// Links an attribute or handle to its inline encoding identifier.
    // BOOTSTRAP: every attribute in this block must remain `unsafe as`.
    // `attributes!{}`'s anchored form derives identity by referencing
    // `metadata::anchor` and `metadata::value_encoding`, so anchoring one of
    // these would make its own initialization require itself — a reentrant
    // LazyLock, which hangs or panics at runtime rather than failing to compile.
    // This is permanent, not a migration leftover.
    "213F89E3F49628A105B3830BD3A6612C" unsafe as value_encoding: inlineencodings::GenId;
    /// A stable, hand-chosen namespace id that PARTICIPATES in a derived
    /// attribute identity rather than replacing it.
    ///
    /// Pinning an entity (`entity!{ id @ .. }`) makes the id the anchor and the
    /// facts mere annotations, so the value encoding stays outside identity and a
    /// re-typed attribute silently keeps addressing rows written under the old
    /// type. Carrying the anchor as a FIELD instead means identity is derived from
    /// `(anchor, value_encoding)`: stable under renaming, and changed by a change
    /// of type.
    "E16A3F51AF63084FFE1079E8A0BA57AB" unsafe as anchor: inlineencodings::GenId;
    /// Links a handle to its blob encoding identifier.
    "43C134652906547383054B1E31E23DF4" unsafe as blob_encoding: inlineencodings::GenId;
    /// Links an `Array<T>` schema entity to its element schema's id. Distinct
    /// from `blob_encoding` because element schemas are not themselves
    /// `BlobEncoding`s — they only carry an `ArrayElement::Native` byte-layout.
    "56C43BEE48BE99521886D99BE9026A3B" unsafe as array_item_schema: inlineencodings::GenId;
    /// Rank of a `Tensor<T, RANK>` schema entity.
    ///
    /// Written as a FACT, not only carried in the Rust type, so an attribute
    /// using this encoding is queryable by rank without a second mechanism
    /// recording it. The same facts derive the encoding's id, so the annotation
    /// and the identity cannot disagree.
    "7B094441362DD9ADEBDC5EB5D224FC56" unsafe as tensor_rank: inlineencodings::I256BE;
    /// Links a handle to the hash algorithm used for content addressing.
    "51C08CFABB2C848CE0B4A799F0EFE5EA" unsafe as hash_schema: inlineencodings::GenId;
    /// Optional WebAssembly module for formatting values governed by this schema.
    ///
    /// The value is a `Handle<WasmCode>` that points to a sandboxed
    /// formatter module (see `triblespace_core::value_formatter`).
    "1A3D520FEDA9E1A4051EBE96E43ABAC7" unsafe as value_formatter: inlineencodings::Handle<WasmCode>;
    /// Long-form display name stored as a UTF8String handle.
    ///
    /// Names are *display*-oriented and contextual: multiple usages of the
    /// same attribute may carry different names depending on the codebase
    /// or domain. Use attribute usage entities (tagged with
    /// `KIND_ATTRIBUTE_USAGE`) when you need to capture multiple names for
    /// the same attribute id.
    ///
    /// For *identity*-determining strings (an IRI for RDF, an export
    /// symbol for WASM, …), use a dedicated attribute like
    /// [`iri`](`self::iri`) instead. The id-derivation paths for dynamic
    /// attributes hash from those identity-determining attributes, not
    /// from `name`.
    "7FB28C0B48E1924687857310EE230414" unsafe as name: inlineencodings::Handle<UTF8String>;
    /// Internationalized Resource Identifier (IRI) for this entity.
    ///
    /// The canonical identity-determining string for RDF predicate URIs and
    /// RDF entity URIs. Distinct from [`name`] (display) so an IRI-derived
    /// attribute and a same-bytes JSON-field-derived attribute never
    /// collide: the (attr_id, value) pair that participates in
    /// entity-intrinsic-id derivation differs in the attr_id, even when the
    /// raw value bytes are identical.
    ///
    /// The value is stored as a `Handle<UTF8String>` — IRI-ness is a
    /// semantic property of *this attribute*, not a structural property of
    /// the bytes. Callers that need IRI-shape validation can apply
    /// it at the application boundary; the storage layer doesn't enforce
    /// it, so mistyped or placeholder IRIs ingest without rejection and
    /// queries can unify across "any string this entity has."
    "325F05DB88184B4540AAEEFAE1E9667F" unsafe as iri: inlineencodings::Handle<UTF8String>;
    /// Link a usage annotation entity to the attribute it describes.
    "F10DE6D8E60E0E86013F1B867173A85C" unsafe as attribute: inlineencodings::GenId;
    /// Optional provenance string for a usage annotation.
    "A56350FD00EC220B4567FE15A5CD68B8" unsafe as source: inlineencodings::Handle<UTF8String>;
    /// Optional module path for the usage annotation (from `module_path!()`).
    "BCB94C7439215641A3E9760CE3F4F432" unsafe as source_module: inlineencodings::Handle<UTF8String>;
    /// Generic tag edge: link any entity to a tag entity (by Id). Reusable across domains.
    "91C50E9FBB1F73E892EBD5FFDE46C251" unsafe as tag: inlineencodings::GenId;
    /// When an entity was created.
    "9B1E79DFD065F643954141593CD8B9E0" unsafe as created_at: inlineencodings::NsTAIInterval;
    /// When an entity was last updated.
    "93B7372E3443063392CD801B03A8D390" unsafe as updated_at: inlineencodings::NsTAIInterval;
    /// When a process or interval started.
    "06973030ACA83A7B2B4FC8BEBB31F77A" unsafe as started_at: inlineencodings::NsTAIInterval;
    /// When a process or interval finished.
    "9B06AA4060EF9928A923FC7E6A6B6438" unsafe as finished_at: inlineencodings::NsTAIInterval;
    /// When an entity expires or becomes invalid.
    "89FEC3B560336BA88B10759DECD3155F" unsafe as expires_at: inlineencodings::NsTAIInterval;
    /// A version that this entity supersedes (predecessor edge, repeated).
    ///
    /// Canonical versioning edge for snapshot histories: an entity's current
    /// head is the version that nothing supersedes. Append-only and
    /// merge-safe — concurrent edits produce sibling heads (an honest fork),
    /// never a clock-driven silent clobber, so "current" is a query over the
    /// supersedes DAG rather than a mutable pointer. General-purpose across
    /// domains (wiki fragments, compass reviews, relations groups, memory
    /// chunks); a merge that reconciles two heads may supersede both.
    "EA5308C6296520A185DE4E5019F779FB" unsafe as supersedes: inlineencodings::GenId;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_archive_attribute_id_is_preserved() {
        assert_eq!(
            archive.id(),
            crate::id_hex!("88B59BD497540AC5AECDB7518E737C87")
        );
    }
}
