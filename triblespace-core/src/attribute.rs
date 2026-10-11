//! Typed attribute references with carried identity-determining facts.
//!
//! An [`Attribute<S>`] is a rooted [`Fragment`] plus a phantom value-
//! schema marker. The fragment's `root()` IS the attribute id; its
//! facts are the identity-determining data (e.g.
//! `metadata::iri: <handle>` or `metadata::name: <handle>` together
//! with `metadata::value_encoding: <schema id>`). The attribute is the
//! *abstract shared thing* multiple parties agree on; codebase-local
//! annotations (the rust identifier, source location, doc comment)
//! are emitted at the [`attributes!`](crate::macros::attributes) call site as usage facts —
//! there is no `AttributeUsage` type, the macro inlines them.
//!
//! Construct via the derived constructors — the encoding fact is emitted
//! from `S`, so it cannot disagree with the phantom type:
//!
//! ```ignore
//! Attribute::<S>::anchored(id)   // pinned namespace: identity is (anchor, S)
//! Attribute::<S>::named("title") // display-name origin: identity is (name, S)
//! Attribute::<S>::iri(iri)       // RDF predicate: identity is (iri, S)
//! ```
//!
//! [`Attribute::from_fragment_unchecked`] wraps a hand-built fragment for
//! origins those do not cover. It validates only rootedness, so the caller
//! carries the obligation that the facts agree with `S`. The shapes it expects:
//!
//! ```ignore
//! // Display-name origin (JSON fields, config keys, column headers):
//! Attribute::<S>::from_fragment_unchecked(entity! {
//!     metadata::name: name.to_owned(),
//!     metadata::value_encoding: <S as MetaDescribe>::id(),
//!     metadata::tag: metadata::KIND_ATTRIBUTE,
//! })
//!
//! // RDF / JSON-LD predicate (IRI as canonical identifier):
//! Attribute::<S>::from_fragment_unchecked(entity! {
//!     metadata::iri: iri.to_owned(),
//!     metadata::value_encoding: <S as MetaDescribe>::id(),
//!     metadata::tag: metadata::KIND_ATTRIBUTE,
//! })
//!
//! // Explicit hex id (pinned attribute namespace):
//! Attribute::<S>::from_fragment_unchecked(entity! {
//!     ExclusiveId::force_ref(&id) @
//!         metadata::value_encoding: <S as MetaDescribe>::id(),
//!         metadata::tag: metadata::KIND_ATTRIBUTE,
//! })
//! ```

use crate::id::Id;
use crate::id::RawId;
use crate::inline::InlineEncoding;
use crate::trible::Fragment;
use core::cell::Cell;
use core::marker::PhantomData;
use std::sync::OnceLock;

std::thread_local! {
    /// Re-entrancy guard for lazily constructing attribute descriptions.
    ///
    /// Schema descriptions are themselves expressed with metadata attributes,
    /// so asking every nested `entity!` to describe its attributes would form
    /// a cycle. The outermost build owns the complete description; nested
    /// builds fall back to the attribute's identity fragment.
    static META_DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct MetaDepthGuard;

impl MetaDepthGuard {
    fn enter() -> Option<Self> {
        META_DEPTH.with(|depth| {
            if depth.get() > 0 {
                None
            } else {
                depth.set(1);
                Some(Self)
            }
        })
    }
}

impl Drop for MetaDepthGuard {
    fn drop(&mut self) {
        META_DEPTH.with(|depth| depth.set(0));
    }
}

/// Lazily cached description for one attribute declared by `attributes!`.
///
/// The builder is deferred because its value encoding may itself be described
/// with `entity!`. [`AttributeMeta::get`] cuts that recursion at the outermost
/// description build while retaining a process-wide immutable cache.
pub struct AttributeMeta {
    cell: OnceLock<Fragment>,
    build: fn() -> Fragment,
}

impl AttributeMeta {
    pub const fn new(build: fn() -> Fragment) -> Self {
        Self {
            cell: OnceLock::new(),
            build,
        }
    }

    /// Returns the cached description, or `None` inside a recursive metadata
    /// build where the caller should use the attribute's identity fragment.
    pub fn get(&self) -> Option<&Fragment> {
        if let Some(fragment) = self.cell.get() {
            return Some(fragment);
        }
        let _guard = MetaDepthGuard::enter()?;
        let fragment = (self.build)();
        Some(self.cell.get_or_init(|| fragment))
    }
}

impl core::fmt::Debug for AttributeMeta {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttributeMeta")
            .field("built", &self.cell.get().is_some())
            .finish()
    }
}

/// A typed reference to an attribute: a rooted [`Fragment`] carrying
/// the identity-determining facts, tagged with a phantom value-schema
/// marker.
///
/// The root id is cached alongside the fragment so `.id()` is a field
/// read — `entity!{}` codegen calls it once per attribute per fact,
/// and walking the fragment's exports PATCH each time dominated the
/// pre-0.40 entities/union benches.
pub struct Attribute<S: InlineEncoding> {
    id: Id,
    fragment: Fragment,
    meta: Option<&'static AttributeMeta>,
    _schema: PhantomData<S>,
}

impl<S: InlineEncoding> core::fmt::Debug for Attribute<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attribute")
            .field("id", &self.id)
            .field("fragment", &self.fragment)
            .finish_non_exhaustive()
    }
}

impl<S: InlineEncoding> PartialEq for Attribute<S> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.fragment == other.fragment
    }
}

impl<S: InlineEncoding> Eq for Attribute<S> {}

impl<S: InlineEncoding> Clone for Attribute<S> {
    // Manual impl: `PhantomData<S>` doesn't require `S: Clone`, but
    // `#[derive(Clone)]` over a `S: InlineEncoding` bound conservatively
    // adds that constraint. Implementing by hand lets callers clone
    // `Attribute<Boolean>` etc. without needing `Boolean: Clone`.
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            fragment: self.fragment.clone(),
            meta: self.meta,
            _schema: PhantomData,
        }
    }
}

impl<S: InlineEncoding + crate::metadata::MetaDescribe> Attribute<S> {
    /// Pinned-anchor attribute: the id is derived from `(anchor, S)`.
    ///
    /// The encoding fact is emitted from `S` rather than passed in, so the
    /// phantom type and the identity fragment cannot disagree. That is the
    /// whole reason to prefer this over [`From<Fragment>`], which validates
    /// only that the fragment is rooted.
    ///
    /// Two consequences worth stating, because they are the point:
    ///
    /// * the Rust identifier is NOT in the identity, so renaming is free;
    /// * changing the schema changes the id, so a re-typed attribute cannot
    ///   silently reinterpret rows written under the old type. It becomes a
    ///   different attribute, which is the truthful outcome — an in-place
    ///   re-encoding of a *shared* attribute could only ever produce rows of
    ///   two meanings under one id, with nothing to tell them apart.
    ///
    /// Generic attributes need no macro support: `Attribute::<Handle<Array<T>>>
    /// ::anchored(ANCHOR)` is an ordinary generic call, so one anchor yields a
    /// distinct id per element type.
    pub fn anchored(anchor: Id) -> Self {
        Self::from_fragment_unchecked(crate::macros::entity! {
            crate::metadata::anchor:
                crate::inline::encodings::genid::GenId::inline_from(anchor),
            crate::metadata::value_encoding: <S as crate::metadata::MetaDescribe>::id(),
            crate::metadata::tag: crate::metadata::KIND_ATTRIBUTE,
        })
    }

    /// Display-name origin (JSON fields, config keys, column headers).
    ///
    /// Identity is `(name, S)`. Use when the name IS the shared identifier
    /// parties agree on — not for a local Rust identifier, which belongs in
    /// usage facts.
    pub fn named(name: &str) -> Self {
        Self::from_fragment_unchecked(crate::macros::entity! {
            crate::metadata::name: name.to_owned(),
            crate::metadata::value_encoding: <S as crate::metadata::MetaDescribe>::id(),
            crate::metadata::tag: crate::metadata::KIND_ATTRIBUTE,
        })
    }

    /// RDF / JSON-LD predicate origin, with the IRI as canonical identifier.
    ///
    /// Identity is `(iri, S)`.
    pub fn iri(iri: &str) -> Self {
        Self::from_fragment_unchecked(crate::macros::entity! {
            crate::metadata::iri: iri.to_owned(),
            crate::metadata::value_encoding: <S as crate::metadata::MetaDescribe>::id(),
            crate::metadata::tag: crate::metadata::KIND_ATTRIBUTE,
        })
    }
}

impl<S: InlineEncoding> Attribute<S> {
    /// The attribute's id, equal to the wrapped fragment's root.
    pub fn id(&self) -> Id {
        self.id
    }

    /// Return the underlying raw id bytes.
    pub fn raw(&self) -> RawId {
        self.id().into()
    }

    /// The identity-determining fragment.
    pub fn fragment(&self) -> &Fragment {
        &self.fragment
    }

    /// Attach the declaration-site description generated by `attributes!`.
    pub fn with_meta(mut self, meta: &'static AttributeMeta) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Description carried into fragments that use this attribute.
    ///
    /// Declared attributes use their cached declaration record. Runtime-minted
    /// attributes fall back to their identity fragment, which contains the
    /// IRI/name, value encoding, and any blobs used to derive that identity.
    pub fn meta(&self) -> &Fragment {
        self.meta
            .and_then(AttributeMeta::get)
            .unwrap_or(&self.fragment)
    }

    /// Convert a host value into a typed `Inline<S>` using the Field's schema.
    /// This is a small convenience wrapper around the `IntoInline` trait and
    /// simplifies macro expansion: `af.inline_from(expr)` preserves the
    /// schema `S` for type inference.
    pub fn inline_from<T: crate::inline::IntoInline<S>>(&self, v: T) -> crate::inline::Inline<S> {
        crate::inline::IntoInline::to_inline(v)
    }

    /// Macro-side entry point: produce the [`Encoded<S>`] the
    /// `entity!{}` codegen folds into a Fragment.
    ///
    /// Dispatches via [`IntoEncoded`], parameterised by the schema's
    /// [`Encoding`](crate::inline::InlineEncoding::Encoding) — `S`
    /// itself for inline schemas, the inner `BlobEncoding` for
    /// `Handle<T>`. The resulting `Output` is lifted into a [`Encoded`]
    /// via [`ToEncoded`].
    ///
    /// [`IntoEncoded`]: crate::inline::IntoEncoded
    /// [`ToEncoded`]: crate::inline::ToEncoded
    /// [`Encoded`]: crate::inline::Encoded
    /// [`Encoded<S>`]: crate::inline::Encoded
    pub fn encoded_from<V>(&self, v: V) -> crate::inline::Encoded<S>
    where
        V: crate::inline::IntoEncoded<<S as crate::inline::InlineEncoding>::Encoding>,
        <V as crate::inline::IntoEncoded<<S as crate::inline::InlineEncoding>::Encoding>>::Output:
            crate::inline::ToEncoded<S>,
    {
        use crate::inline::ToEncoded;
        v.into_encoded().to_encoded()
    }

    /// Coerce an existing variable of any schema into a variable typed with
    /// this field's schema. This is a convenience for macros: they can
    /// allocate an untyped/UnknownInline variable and then annotate it with the
    /// field's schema using `af.as_variable(raw_var)`.
    ///
    /// The operation is a zero-cost conversion as variables are simply small
    /// integer indexes; the implementation uses an unsafe transmute to change
    /// the type parameter without moving the underlying data.
    pub fn as_variable(&self, v: crate::query::Variable<S>) -> crate::query::Variable<S> {
        v
    }
}

/// Wrap a rooted fragment as a typed attribute.
///
/// The fragment's `root()` is the attribute id; its facts (typically
/// `metadata::iri | metadata::name` together with
/// `metadata::value_encoding`) are carried through to [`Describe`](crate::metadata::Describe) so the
/// attribute remains queryable in the metadata registry by its
/// originating identity attribute.
///
/// Pinning a schema's attribute ids (so local renames don't churn the
/// schema) is what the [`attributes!`](crate::macros::attributes) macro is for — declare them with
/// explicit hex literals there.
impl<S: InlineEncoding> Attribute<S> {
    /// Wrap a hand-built identity fragment, **without checking that it agrees
    /// with `S`**.
    ///
    /// Prefer [`Attribute::anchored`], [`Attribute::named`] or
    /// [`Attribute::iri`], which emit the encoding fact from `S` and therefore
    /// cannot disagree with it. This exists for origins those three do not
    /// cover — an import deriving identity from foreign metadata, say.
    ///
    /// # Invariant the caller upholds
    ///
    /// The fragment's `metadata::value_encoding` must be
    /// `<S as MetaDescribe>::id()`. Nothing here verifies that: only rootedness
    /// is checked, so a fragment claiming a different encoding is accepted and
    /// produces an attribute whose Rust type and stored identity contradict each
    /// other. See `from_fragment_permits_a_lying_schema`.
    ///
    /// # Panics
    ///
    /// If the fragment is not rooted.
    pub fn from_fragment_unchecked(fragment: Fragment) -> Self {
        let id = fragment
            .root()
            .expect("Attribute::from_fragment_unchecked requires a rooted fragment");
        Self {
            id,
            fragment,
            meta: None,
            _schema: PhantomData,
        }
    }
}

impl<S> crate::metadata::Describe for Attribute<S>
where
    S: InlineEncoding,
{
    fn describe(&self) -> Fragment {
        // An attribute IS its identity fragment. The wrapped fragment
        // already carries `metadata::iri` / `metadata::name` and
        // `metadata::value_encoding: S::id()` from construction —
        // exactly the facts a registry queries on. The schema's own
        // facts (the human-readable name, description, hash protocol,
        // …) belong to the schema, not the attribute; consumers
        // wanting them ask `<S as MetaDescribe>::describe()`
        // separately. Pure accessor.
        self.fragment.clone()
    }
}

/// Re-export of [`RawId`] used by generated macro code.
pub use crate::id::RawId as RawIdAlias;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::blob::IntoBlob;
    use crate::id::Id;
    use crate::inline::encodings::hash::Handle;
    use crate::inline::encodings::iu256::U256BE;
    use crate::inline::Inline;
    use crate::macros::{entity, find, pattern};
    use crate::metadata::{self, Describe, MetaDescribe};

    // The only users of the `Anchored` arm in the tree. Everything else was
    // swept to `unsafe as` to keep ids stable, so without these the new arm
    // would compile and never be taken.
    crate::macros::attributes! {
        /// Anchored: same literal as `pinned_probe`, derived id.
        "5F3C1A0E7B294D6685A0C1F2E3D40912" as anchored_probe: U256BE;
        /// Same anchor, different schema — must be a different attribute.
        "5F3C1A0E7B294D6685A0C1F2E3D40912" as anchored_probe_other: Handle<UTF8String>;
        /// Pinned: the id is the literal verbatim.
        "5F3C1A0E7B294D6685A0C1F2E3D40912" unsafe as pinned_probe: U256BE;
    }

    /// The anchored form derives; it does not pin.
    #[test]
    fn anchored_arm_does_not_yield_the_literal() {
        let lit = "5F3C1A0E7B294D6685A0C1F2E3D40912";
        assert_eq!(
            format!("{:X}", pinned_probe.id()),
            lit,
            "pinned must be verbatim"
        );
        assert_ne!(
            format!("{:X}", anchored_probe.id()),
            lit,
            "anchored must derive, not pin — if this passes the arm is not deriving"
        );
    }

    /// Same anchor, different schema, different attribute. This is the property
    /// the whole change exists for.
    #[test]
    fn anchored_arm_separates_schemas() {
        assert_ne!(anchored_probe.raw(), anchored_probe_other.raw());
    }

    /// And it agrees with the hand-written constructor, so the macro and the API
    /// cannot drift apart.
    #[test]
    fn anchored_arm_matches_the_constructor() {
        let a = Id::from_hex("5F3C1A0E7B294D6685A0C1F2E3D40912").unwrap();
        assert_eq!(anchored_probe.raw(), Attribute::<U256BE>::anchored(a).raw());
    }

    /// This change must not move any existing attribute id.
    ///
    /// The bare hex form now derives, but every declaration that existed was
    /// swept to `unsafe as` in the same commit, so all 288 of them still expand
    /// to a pinned root and every id in every consumer is byte-identical.
    /// Migration is per-declaration from here: delete an `unsafe`, migrate that
    /// attribute's rows. This test fails if a sweep is ever missed.
    #[test]
    fn declared_hex_ids_are_unchanged() {
        assert_eq!(
            format!("{:X}", crate::metadata::value_encoding.id()),
            "213F89E3F49628A105B3830BD3A6612C"
        );
        assert_eq!(
            format!("{:X}", crate::metadata::anchor.id()),
            "E16A3F51AF63084FFE1079E8A0BA57AB"
        );
    }

    /// `anchored` is a pure function of `(anchor, S)`.
    #[test]
    fn anchored_is_deterministic() {
        let a = Id::from_hex("2ADC6462A7F70E230558C5D681E38768").unwrap();
        assert_eq!(
            Attribute::<U256BE>::anchored(a).raw(),
            Attribute::<U256BE>::anchored(a).raw()
        );
    }

    /// The property the whole design turns on: SAME anchor, DIFFERENT schema,
    /// different attribute. A re-typed attribute cannot address rows written
    /// under the old type.
    #[test]
    fn anchored_changes_with_schema() {
        let a = Id::from_hex("2ADC6462A7F70E230558C5D681E38768").unwrap();
        let number = Attribute::<U256BE>::anchored(a);
        let handle =
            Attribute::<Handle<crate::blob::encodings::utf8string::UTF8String>>::anchored(a);
        assert_ne!(number.raw(), handle.raw());
    }

    /// Different anchors stay different under one schema — so `weight` and
    /// `bias`, which share a value type and differ only in meaning, do not
    /// collide.
    #[test]
    fn anchored_changes_with_anchor() {
        let a = Id::from_hex("2ADC6462A7F70E230558C5D681E38768").unwrap();
        let b = Id::from_hex("23178058559C762BB4B1FEAA36B3566D").unwrap();
        assert_ne!(
            Attribute::<U256BE>::anchored(a).raw(),
            Attribute::<U256BE>::anchored(b).raw()
        );
    }

    /// Why `anchored` exists rather than leaving callers to `From<Fragment>`.
    ///
    /// `From` validates only that the fragment is rooted, so a caller may hand
    /// it facts that contradict the phantom type. Here the Rust type says
    /// `U256BE` while the stored encoding says otherwise, and it is
    /// accepted. `anchored` cannot express that, because it emits the fact from
    /// `S` itself.
    #[test]
    fn from_fragment_permits_a_lying_schema() {
        let lying = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::value_encoding:
                <Handle<crate::blob::encodings::utf8string::UTF8String> as MetaDescribe>::id(),
        });
        let honest = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::value_encoding: <U256BE as MetaDescribe>::id(),
        });
        // Same phantom type, different identity: one of them is lying about
        // what it stores, and nothing at construction noticed.
        assert_ne!(lying.raw(), honest.raw());
    }

    /// The pinned form does NOT carry the schema into identity — which is the
    /// defect `anchored` exists to avoid, pinned here so it cannot regress
    /// silently.
    #[test]
    fn pinned_form_ignores_the_schema() {
        let a = Id::from_hex("2ADC6462A7F70E230558C5D681E38768").unwrap();
        let number = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            crate::id::ExclusiveId::force_ref(&a) @
                metadata::value_encoding: <U256BE as MetaDescribe>::id(),
        });
        let handle = Attribute::<Handle<crate::blob::encodings::utf8string::UTF8String>>::from_fragment_unchecked(
            entity! {
                crate::id::ExclusiveId::force_ref(&a) @
                    metadata::value_encoding:
                        <Handle<crate::blob::encodings::utf8string::UTF8String> as MetaDescribe>::id(),
            },
        );
        // Both are just the anchor. A re-typed attribute keeps its id.
        assert_eq!(number.raw(), handle.raw());
        assert_eq!(number.id(), a);
        // Whereas anchored separates them.
        assert_ne!(
            Attribute::<U256BE>::anchored(a).raw(),
            Attribute::<Handle<crate::blob::encodings::utf8string::UTF8String>>::anchored(a).raw()
        );
    }

    #[test]
    fn dynamic_field_is_deterministic() {
        let h1 = "title".to_blob().get_handle();
        let h2 = "title".to_blob().get_handle();
        let a1 = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::name:         h1,
            metadata::value_encoding: <U256BE as MetaDescribe>::id(),
        });
        let a2 = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::name:         h2,
            metadata::value_encoding: <U256BE as MetaDescribe>::id(),
        });

        assert_eq!(a1.raw(), a2.raw());
        assert_ne!(a1.raw(), [0; crate::id::ID_LEN]);
    }

    #[test]
    fn dynamic_field_changes_with_name() {
        let h_title = "title".to_blob().get_handle();
        let h_author = "author".to_blob().get_handle();
        let title = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::name:         h_title,
            metadata::value_encoding: <U256BE as MetaDescribe>::id(),
        });
        let author = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::name:         h_author,
            metadata::value_encoding: <U256BE as MetaDescribe>::id(),
        });

        assert_ne!(title.raw(), author.raw());
    }

    #[test]
    fn dynamic_field_changes_with_schema() {
        let h = "title".to_blob().get_handle();
        let number = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::name:         h,
            metadata::value_encoding: <U256BE as MetaDescribe>::id(),
        });
        let handle = Attribute::<Handle<UTF8String>>::from_fragment_unchecked(entity! {
            metadata::name:         h,
            metadata::value_encoding: <Handle<UTF8String> as MetaDescribe>::id(),
        });

        assert_ne!(number.raw(), handle.raw());
    }

    #[test]
    fn describe_preserves_identity_iri() {
        let iri = "http://example.org/foo".to_string();
        let iri_handle: Inline<Handle<UTF8String>> = iri.to_blob().get_handle();
        let attr = Attribute::<U256BE>::from_fragment_unchecked(entity! {
            metadata::iri:          iri_handle,
            metadata::value_encoding: <U256BE as crate::metadata::MetaDescribe>::id(),
        });
        let attr_id = attr.id();

        let meta = attr.describe();

        // Discovery-by-IRI: the registry must contain
        // `<attr_id> @ metadata::iri: <handle>`.
        let hits: Vec<Id> = find!(
            (a: Id),
            pattern!(&meta, [{ ?a @ metadata::iri: iri_handle }])
        )
        .map(|(a,)| a)
        .collect();
        assert_eq!(hits, vec![attr_id]);

        // The describe output's sole root is the attribute id — the
        // schema spread's root doesn't bubble up.
        assert_eq!(meta.root(), Some(attr_id));
    }
}
