//! Instrumented procedural-macro wrappers for TribleSpace.
//!
//! Compile-time metadata emission is optional. It is enabled when
//! `TRIBLESPACE_METADATA_PILE`, `TRIBLESPACE_METADATA_COLLECTION_NAME`, and
//! `TRIBLESPACE_METADATA_SIGNING_KEY` are all set to valid values. Each macro
//! invocation is accumulated as one self-contained [`Fragment`] and published
//! as one signed collection commit; partial configuration is inert.

use proc_macro::Span;
use proc_macro::TokenStream;

use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};

use std::path::Path;

use ed25519_dalek::SigningKey;
use hex::FromHex;

use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
use triblespace_core::id::fucid;
use triblespace_core::id::Id;
use triblespace_core::repo::pile::Pile;
use triblespace_core::trible::Fragment;

use syn::parse::Parse;
use syn::parse::ParseStream;
use syn::Attribute;
use syn::Ident;
use syn::LitStr;
use syn::Token;
use syn::Type;
use syn::Visibility;

use triblespace_macros_common::{
    attributes_impl, entity_impl, pattern_changes_impl, pattern_impl, value_formatter_impl,
};

mod path_expr;

mod instrumentation_attributes {
    /// Attributes specific to compile-time attribute definition instrumentation.
    /// Reuses `metadata::name`, `metadata::attribute`, and `metadata::tag` for
    /// fields that match their runtime `describe()` counterparts.
    pub(crate) mod attribute {
        use triblespace_core::blob::encodings::utf8string::UTF8String;
        use triblespace_core::prelude::inlineencodings::Handle;
        use triblespace_core_macros::attributes;

        attributes! {
            // Instrumentation-specific: link back to the macro invocation entity.
            "19D4972B2DF977FA64541FC967C4B133" as invocation: Handle<UTF8String>;
            // Instrumentation-specific: the Rust type tokens for this attribute's inline encoding.
            "D97A427FF782B0BF08B55AC84877B486" unsafe as attribute_type: Handle<UTF8String>;
        }
    }

    pub(crate) mod invocation {
        use triblespace_core::blob::encodings::utf8string::UTF8String;
        use triblespace_core::prelude::inlineencodings::{Handle, LineLocation};
        use triblespace_core_macros::attributes;

        attributes! {
            "1CED5213A71C9DD60AD9B3698E5548F4" as macro_kind: Handle<UTF8String>;
            "E413CB09A4352D7B46B65FC635C18CCC" unsafe as manifest_dir: Handle<UTF8String>;
            "8ED33DA54C226ADEA0FFF7863563DF5F" unsafe as source_range: LineLocation;
            "B981AEA9437561F8DB96E7EECBB94BFD" unsafe as source_tokens: Handle<UTF8String>;
            "92EF719DA3DD2405E89B953837E076A5" as crate_name: Handle<UTF8String>;
        }
    }
}

use instrumentation_attributes::attribute;
use instrumentation_attributes::invocation;

fn invocation_span(input: &TokenStream) -> Span {
    let mut iter = input.clone().into_iter();
    iter.next()
        .map(|tt| tt.span())
        .unwrap_or_else(Span::call_site)
}

fn parse_signing_key(value: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::from_hex(value).ok()
}

fn metadata_signing_key() -> Option<SigningKey> {
    let value = std::env::var("TRIBLESPACE_METADATA_SIGNING_KEY").ok()?;
    let bytes = parse_signing_key(&value)?;
    Some(SigningKey::from_bytes(&bytes))
}

fn metadata_collection_policy(signing_key: &SigningKey) -> CollectionPolicy {
    let root = signing_key.verifying_key();
    CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root))
}

fn publish_metadata(
    pile_path: &Path,
    collection_name: &str,
    signing_key: SigningKey,
    fragment: Fragment,
) {
    let mut pile = match Pile::open(pile_path) {
        Ok(pile) => pile,
        Err(_) => return,
    };
    let policy = metadata_collection_policy(&signing_key);
    let Ok(collection) = pile.collection(collection_name, policy) else {
        let _ = pile.close();
        return;
    };
    let _ = pile.commit(collection, &signing_key, fragment);
    let _ = pile.close();
}

struct MetadataContext {
    fragment: Fragment,
    invocation_id: triblespace_core::id::Id,
    input: TokenStream2,
}

impl MetadataContext {
    fn fragment(&mut self) -> &mut Fragment {
        &mut self.fragment
    }

    fn invocation_id(&self) -> triblespace_core::id::Id {
        self.invocation_id
    }

    fn tokens(&self) -> &TokenStream2 {
        &self.input
    }
}

fn emit_metadata<F>(kind: &str, input: &TokenStream, extra: F)
where
    F: FnOnce(&mut MetadataContext),
{
    let pile_path = match std::env::var("TRIBLESPACE_METADATA_PILE") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => return,
    };

    let name_value = match std::env::var("TRIBLESPACE_METADATA_COLLECTION_NAME") {
        Ok(name) if !name.trim().is_empty() => name,
        _ => return,
    };

    let signing_key = match metadata_signing_key() {
        Some(key) => key,
        None => return,
    };

    let span = invocation_span(input);
    let mut fragment = Fragment::empty();
    let entity = fucid();
    let invocation_id = entity.id;

    fragment += ::triblespace_core::macros::entity! {
        &entity @
        invocation::macro_kind: kind,
        invocation::source_range: span
    };

    if let Ok(crate_name) = std::env::var("CARGO_PKG_NAME") {
        fragment +=
            ::triblespace_core::macros::entity! { &entity @ invocation::crate_name: crate_name };
    }

    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        if !dir.trim().is_empty() {
            let handle = fragment.put(dir);
            fragment +=
                ::triblespace_core::macros::entity! { &entity @ invocation::manifest_dir: handle };
        }
    }

    let tokens = input.to_string();
    if !tokens.is_empty() {
        let handle = fragment.put(tokens);
        fragment +=
            ::triblespace_core::macros::entity! { &entity @ invocation::source_tokens: handle };
    }

    let mut context = MetadataContext {
        fragment,
        invocation_id,
        input: TokenStream2::from(input.clone()),
    };
    extra(&mut context);

    // Build the complete self-contained fragment before opening storage. The
    // collection store then publishes exactly one immutable COMMIT; there is
    // no mutable branch head, parent selection, push, or retry protocol here.
    publish_metadata(
        Path::new(&pile_path),
        &name_value,
        signing_key,
        context.fragment,
    );
}

struct AttributeDefinition {
    id: LitStr,
    name: Ident,
    ty: Type,
}

struct AttributeDefinitions {
    entries: Vec<AttributeDefinition>,
}

impl Parse for AttributeDefinitions {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut entries = Vec::new();
        while !input.is_empty() {
            let _ = input.call(Attribute::parse_outer)?;
            if input.peek(Token![pub]) {
                let v: Visibility = input.parse()?;
                return Err(syn::Error::new_spanned(
                    v,
                    "visibility must appear after `as` and before the attribute name (e.g. `\"...\" as pub name: Type;`)",
                ));
            }

            let id: LitStr = input.parse()?;
            input.parse::<Token![unsafe]>()?;
            input.parse::<Token![as]>()?;
            if input.peek(Token![pub]) {
                let _: Visibility = input.parse()?;
            }
            let name: Ident = input.parse()?;
            input.parse::<Token![:]>()?;
            let ty: Type = input.parse()?;
            input.parse::<Token![;]>()?;

            entries.push(AttributeDefinition { id, name, ty });
        }
        Ok(AttributeDefinitions { entries })
    }
}

fn emit_attribute_definitions(context: &mut MetadataContext) {
    use triblespace_core::inline::encodings::genid::GenId;
    use triblespace_core::metadata;
    use triblespace_core::prelude::InlineEncoding;

    let Ok(parsed) = syn::parse2::<AttributeDefinitions>(context.tokens().clone()) else {
        return;
    };
    if parsed.entries.is_empty() {
        return;
    }

    let invocation_hex = format!("{:X}", context.invocation_id());

    for definition in parsed.entries {
        let entity = fucid();

        // Parse the attribute hex ID into a proper Id for GenId storage.
        let Some(attr_id) = Id::from_hex(&definition.id.value()) else {
            continue;
        };

        let name_handle = context.fragment().put(definition.name.to_string());
        let mut definition_fragment = ::triblespace_core::macros::entity! {
            &entity @
            metadata::attribute: GenId::inline_from(attr_id),
            metadata::name: name_handle,
            metadata::tag: metadata::KIND_ATTRIBUTE_USAGE,
            attribute::invocation: invocation_hex.as_str()
        };

        let ty_tokens = definition.ty.to_token_stream().to_string();
        if !ty_tokens.is_empty() {
            let handle = context.fragment().put(ty_tokens);
            definition_fragment +=
                ::triblespace_core::macros::entity! { &entity @ attribute::attribute_type: handle };
        }

        *context.fragment() += definition_fragment;
    }
}

/// Defines typed attributes that can be used with `entity!`, `pattern!`, and
/// path queries.
///
/// Each entry has the form:
///
/// - `"HEX_ANCHOR" as [vis] name: Schema;` for an id derived from the
///   stable anchor and value encoding
/// - `"HEX_ID" unsafe as [vis] name: Schema;` to use a pre-existing id
///   literally, without letting the value encoding participate in identity
/// - `[vis] name: Schema;` for an id derived from the attribute name and
///   value encoding
///
/// Doc comments attached to each entry become description metadata, and the
/// macro also generates a `describe` helper for archiving those definitions.
///
/// ```rust,ignore
/// mod social {
///     use triblespace::prelude::*;
///     use triblespace::prelude::blobencodings::UTF8String;
///     use triblespace::prelude::inlineencodings::{GenId, Handle};
///
///     attributes! {
///         /// A person's display name.
///         "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<UTF8String>;
///         pub friend: GenId;
///     }
/// }
/// ```
#[proc_macro]
pub fn attributes(input: TokenStream) -> TokenStream {
    let clone = input.clone();
    emit_metadata("attributes", &clone, |context| {
        emit_attribute_definitions(context)
    });
    let base_path: TokenStream2 = quote!(::triblespace::core);
    let tokens = TokenStream2::from(input);
    match attributes_impl(tokens, &base_path) {
        Ok(ts) => TokenStream::from(ts),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Expands a bracketed trible pattern into a query constraint.
///
/// `pattern!` is the main macro for matching entity/attribute/value structure
/// against a set. Inside each `{ ... }` clause:
///
/// - `?name` refers to an existing query variable from the surrounding query
/// - `_?name` introduces a local helper variable scoped to this pattern
/// - literal expressions are turned into equality constraints
///
/// The overall form is:
///
/// `pattern!(set_expr, [{ entity @ attr: value, ... }, ...])`
///
/// ```rust,ignore
/// find!(
///     (person: Inline<_>, friend: Inline<_>),
///     pattern!(&kb, [
///         { ?person @ social::friend: ?friend },
///         { ?friend @ social::name: "Bob" }
///     ])
/// )
/// ```
#[proc_macro]
pub fn pattern(input: TokenStream) -> TokenStream {
    let clone = input.clone();
    emit_metadata("pattern", &clone, |_context| {});
    let base_path: TokenStream2 = quote!(::triblespace::core);
    let tokens = TokenStream2::from(input);
    match pattern_impl(tokens, &base_path) {
        Ok(ts) => TokenStream::from(ts),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Matches a pattern against incremental changes while still joining against
/// the full current state.
///
/// The syntax mirrors [`pattern!`], but takes both the current full set and a
/// delta set:
///
/// `pattern_changes!(current_set, delta_set, [{ ... }])`
///
/// This is useful for incremental processing where at least one trible in each
/// match must come from `delta_set`, while the rest of the join may come from
/// `current_set`.
///
/// Alternative delta placements of the same complete binding collapse within
/// one invocation. A surrounding [`find!`] still has bag semantics, however:
/// complete bindings that differ only in hidden witnesses remain distinct rows
/// even when they project to the same declared tuple. The query keeps no
/// history between invocations, so a later disjoint delta may legitimately
/// publish that tuple again through a newly introduced witness. Collect the
/// projected tuples into a set when projection-level or once-only uniqueness
/// is required, or project the witness variables when those derivations should
/// remain distinguishable.
///
/// ```rust,ignore
/// for (work,) in find!(
///     (work: Inline<_>),
///     pattern_changes!(&full, &delta, [
///         { ?work @ literature::author: &shakespeare }
///     ])
/// ) {
///     // process only newly introduced matches
/// }
/// ```
#[proc_macro]
pub fn pattern_changes(input: TokenStream) -> TokenStream {
    let clone = input.clone();
    emit_metadata("pattern_changes", &clone, |_context| {});
    let base_path: TokenStream2 = quote!(::triblespace::core);
    let tokens = TokenStream2::from(input);
    match pattern_changes_impl(tokens, &base_path) {
        Ok(ts) => TokenStream::from(ts),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Builds a rooted fragment from entity facts.
///
/// The form is:
///
/// `entity! { [id_expr] @ attr: value, attr?: option, attr*: repeated }`
///
/// If the id is omitted, the macro derives a deterministic plain `Id` by
/// sorting and deduplicating the complete `NIL || attribute || value` rows and
/// hashing their contiguous bytes. Supplying an explicit subject instead
/// requires an `ExclusiveId`, the write capability for incrementally extending
/// that identity. `attr?:` inserts a fact only when the option is `Some`, and
/// `attr*:` spreads repeated values into multiple facts.
///
/// ```rust,ignore
/// let alice = fucid();
/// let facts = entity! { &alice @
///     social::name: "Alice",
///     social::nickname?: Some("Al"),
///     social::tag*: ["friend", "researcher"],
/// };
/// ```
#[proc_macro]
pub fn entity(input: TokenStream) -> TokenStream {
    let clone = input.clone();
    emit_metadata("entity", &clone, |_context| {});
    let base_path: TokenStream2 = quote!(::triblespace::core);
    let tokens = TokenStream2::from(input);
    match entity_impl(tokens, &base_path) {
        Ok(ts) => TokenStream::from(ts),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Instrumented wrapper around the core `find!` query macro.
///
/// The syntax and semantics are the same as `triblespace::core::query::find!`;
/// this wrapper exists so the facade crate can export `find!` alongside the
/// other procedural macros while still recording compile-time macro metadata
/// when that feature is configured.
///
/// ```rust,ignore
/// let names: Vec<_> = find!(
///     (name: Inline<_>),
///     pattern!(&kb, [{ ?person @ social::name: ?name }])
/// ).collect();
/// ```
#[proc_macro]
pub fn find(input: TokenStream) -> TokenStream {
    let clone = input.clone();
    emit_metadata("find", &clone, |_context| {});
    let inner = TokenStream2::from(input);
    TokenStream::from(quote!(::triblespace::core::macros::find!(#inner)))
}

/// A regular path expression written like a regex over attribute paths,
/// lowered to `triblespace_paths::PathExpr` builder calls through the grammar
/// the `trible` command line shares.
///
/// ```rust,ignore
/// let expr = path_expr!(social::friend (social::friend | ^social::friend)* social::name?);
/// let automaton = expr.compile();
/// ```
///
/// Atoms are Rust paths naming attributes (anything with an `.id()`), or
/// `{ expression }`. Juxtaposition is sequence, `|` alternation, `*`, `+` and
/// `?` repetition, `^` reverse, parentheses group. The generated code names
/// `::triblespace_paths`, so it must be a dependency of the calling crate.
#[proc_macro]
pub fn path_expr(input: TokenStream) -> TokenStream {
    let clone = input.clone();
    emit_metadata("path_expr", &clone, |_context| {});
    match path_expr::path_expr_impl(TokenStream2::from(input)) {
        Ok(tokens) => TokenStream::from(tokens),
        Err(error) => TokenStream::from(error.to_compile_error()),
    }
}

/// Instrumented wrapper around the core `exists!` query macro.
///
/// Supports both `exists!(constraint)` and `exists!((vars...), constraint)`.
///
/// ```rust,ignore
/// let has_bob = exists!(pattern!(&kb, [{ ?person @ social::name: "Bob" }]));
/// ```
#[proc_macro]
pub fn exists(input: TokenStream) -> TokenStream {
    let clone = input.clone();
    emit_metadata("exists", &clone, |_context| {});
    let inner = TokenStream2::from(input);
    TokenStream::from(quote!(::triblespace::core::exists!(#inner)))
}

/// Compiles a value formatter function to a wasm byte array constant.
///
/// The annotated function must have the signature:
///
/// `fn(raw: &[u8; 32], out: &mut impl core::fmt::Write) -> Result<(), u32>`
///
/// Optional macro arguments:
///
/// - `const_wasm = NAME` to override the generated constant name
/// - `vis(pub(...))` to override the constant visibility
///
/// ```rust,ignore
/// #[value_formatter(const_wasm = MY_FORMATTER_WASM, vis(pub(crate)))]
/// fn format_short_string(
///     raw: &[u8; 32],
///     out: &mut impl core::fmt::Write,
/// ) -> Result<(), u32> {
///     write!(out, "{raw:02X?}").map_err(|_| 1)
/// }
/// ```
#[proc_macro_attribute]
pub fn value_formatter(attr: TokenStream, item: TokenStream) -> TokenStream {
    let clone = item.clone();
    emit_metadata("value_formatter", &clone, |_context| {});

    match value_formatter_impl(TokenStream2::from(attr), TokenStream2::from(item)) {
        Ok(tokens) => TokenStream::from(tokens),
        Err(err) => err.to_compile_error().into(),
    }
}

#[cfg(test)]
mod instrumentation_tests {
    use super::*;

    use std::fs::File;

    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::blob::encodings::utf8string::UTF8String;
    use triblespace_core::blob::Blob;
    use triblespace_core::collection::{
        descriptor, CollectionRead, CollectionRecord, CollectionStoreExt,
    };
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStoreGet, SnapshotSource, StorageClose};
    use triblespace_core::trible::TribleSet;

    #[test]
    fn attribute_metadata_joins_the_invocation_fragment_with_its_attachments() {
        let invocation_entity = fucid();
        let mut fragment = Fragment::empty();
        fragment += triblespace_core::macros::entity! {
            &invocation_entity @ invocation::macro_kind: "attributes"
        };
        let mut context = MetadataContext {
            fragment,
            invocation_id: invocation_entity.id,
            input: quote! {
                "11111111111111111111111111111111" unsafe as pub first: FirstEncoding;
                "22222222222222222222222222222222" unsafe as second: SecondEncoding;
            },
        };

        emit_attribute_definitions(&mut context);

        let facts = context.fragment.facts();
        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.a() == &triblespace_core::metadata::attribute.id())
                .count(),
            2
        );
        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.a() == &attribute::invocation.id())
                .count(),
            2
        );

        let handles = facts
            .iter()
            .filter(|fact| {
                fact.a() == &triblespace_core::metadata::name.id()
                    || fact.a() == &attribute::attribute_type.id()
            })
            .map(|fact| *fact.v::<Handle<UTF8String>>())
            .collect::<Vec<_>>();
        assert_eq!(handles.len(), 4);

        let mut blobs = context.fragment.blobs().clone();
        let snapshot = blobs.snapshot().unwrap();
        for handle in handles {
            let _: Blob<UTF8String> = snapshot.get(handle).unwrap();
        }
    }

    #[test]
    fn publication_emits_one_self_contained_target_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("instrumentation.pile");
        File::create(&path).unwrap();

        let entity = fucid();
        let mut fragment = Fragment::empty();
        let attachment = fragment.put("fn example() {}".to_owned());
        fragment += triblespace_core::macros::entity! {
            &entity @
            invocation::macro_kind: "entity",
            invocation::source_tokens: attachment
        };

        let name = "macro-metadata";
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let authority = signing_key.verifying_key();
        let policy = metadata_collection_policy(&signing_key);
        publish_metadata(&path, name, signing_key.clone(), fragment.clone());
        publish_metadata(&path, name, signing_key, fragment);

        let mut pile = Pile::open(&path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let records = snapshot
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            records.len(),
            1,
            "one target commit is the only native record"
        );
        let mut expected_store = MemoryRepo::default();
        let expected_collection = expected_store
            .collection(name, policy.clone())
            .expect("register expected collection");
        let target = expected_collection.handle();
        let commit = records
            .into_iter()
            .find_map(|record| match record {
                CollectionRecord::Commit(commit) if commit.collection() == target => Some(commit),
                _ => None,
            })
            .expect("single target collection commit");
        commit.verify_strict().unwrap();

        let descriptor_blob: Blob<SimpleArchive> = snapshot.get(commit.collection()).unwrap();
        let descriptor =
            <TribleSet as triblespace_core::blob::TryFromBlob<SimpleArchive>>::try_from_blob(
                descriptor_blob,
            )
            .unwrap();
        assert_eq!(descriptor::policy(&descriptor).unwrap(), policy);
        assert_eq!(
            descriptor::representation(&descriptor).unwrap(),
            <SimpleArchive as triblespace_core::metadata::MetaDescribe>::id()
        );
        let name_handle = descriptor::name(&descriptor).unwrap().unwrap();
        let name_blob: Blob<UTF8String> = snapshot.get(name_handle).unwrap();
        assert_eq!(name_blob.bytes.as_ref(), name.as_bytes());
        assert_eq!(authority.to_bytes(), commit.public_key().raw);

        let _: Blob<UTF8String> = snapshot.get(attachment).unwrap();
        drop(snapshot);
        StorageClose::close(pile).unwrap();
    }
}
