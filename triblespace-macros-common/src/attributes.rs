use proc_macro2::TokenStream as TokenStream2;
use quote::format_ident;
use quote::quote;
use syn::parse::Parse;
use syn::parse::ParseStream;
use syn::spanned::Spanned;
use syn::Attribute;
use syn::Expr;
use syn::ExprLit;
use syn::Ident;
use syn::LitStr;
use syn::Meta;
use syn::Token;
use syn::Type;
use syn::Visibility;

enum AttributeId {
    /// `"hex" unsafe as` — the id IS the literal. Asserted, not derived, so the
    /// value encoding never reaches identity and a re-typed attribute keeps
    /// addressing rows written under the old type.
    ///
    /// The caller carries the obligation that the type has not changed since the
    /// id was minted, which is why the syntax says `unsafe`.
    Pinned(LitStr),
    /// `"hex" as` — identity is derived from `(anchor, value_encoding)`. Stable
    /// under renaming; a change of type yields a different attribute.
    Anchored(LitStr),
    /// bare name — identity is derived from `(name, value_encoding)`.
    Derived,
}

struct AttributesDef {
    attrs: Vec<Attribute>,
    vis: Option<Visibility>,
    id: AttributeId,
    name: Ident,
    ty: Type,
}

struct AttributesInput {
    attributes: Vec<AttributesDef>,
}

fn lit_str_from_expr(expr: Expr) -> syn::Result<LitStr> {
    match expr {
        Expr::Lit(ExprLit {
            lit: syn::Lit::Str(lit),
            ..
        }) => Ok(lit),
        other => Err(syn::Error::new(other.span(), "expected a string literal")),
    }
}

fn split_attrs(attrs: Vec<Attribute>) -> syn::Result<(Vec<Attribute>, Option<LitStr>)> {
    let mut kept = Vec::new();
    let mut description = None;
    let mut doc_lines = Vec::<String>::new();

    for attr in attrs {
        if attr.path().is_ident("doc") {
            if let Meta::NameValue(nv) = &attr.meta {
                let lit = lit_str_from_expr(nv.value.clone())?;
                doc_lines.push(lit.value().trim_start().to_owned());
            }
            kept.push(attr);
            continue;
        }
        kept.push(attr);
    }

    if !doc_lines.is_empty() {
        let joined = doc_lines.join("\n");
        description = Some(LitStr::new(&joined, proc_macro2::Span::call_site()));
    }

    Ok((kept, description))
}

impl Parse for AttributesInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let content = input;
        let mut attributes = Vec::new();
        while !content.is_empty() {
            let attrs = content.call(Attribute::parse_outer)?;
            if content.peek(LitStr) {
                let id_lit: LitStr = content.parse()?;
                // `unsafe` sits on `as` rather than leading the entry: it marks
                // the operation that is actually unchecked — the literal becoming
                // the id verbatim instead of feeding into one — and it keeps the
                // block readable as a column of ids.
                let pinned = content.peek(Token![unsafe]);
                if pinned {
                    content.parse::<Token![unsafe]>()?;
                }
                content.parse::<Token![as]>()?;
                let vis: Option<Visibility> = if content.peek(Token![pub]) {
                    Some(content.parse()?)
                } else {
                    None
                };
                let name: Ident = content.parse()?;
                content.parse::<Token![:]>()?;
                let ty: Type = content.parse()?;
                content.parse::<Token![;]>()?;
                attributes.push(AttributesDef {
                    attrs,
                    vis,
                    id: if pinned {
                        AttributeId::Pinned(id_lit)
                    } else {
                        AttributeId::Anchored(id_lit)
                    },
                    name,
                    ty,
                });
            } else {
                let vis: Option<Visibility> = if content.peek(Token![pub]) {
                    Some(content.parse()?)
                } else {
                    None
                };
                let name: Ident = content.parse()?;
                content.parse::<Token![:]>()?;
                let ty: Type = content.parse()?;
                content.parse::<Token![;]>()?;
                attributes.push(AttributesDef {
                    attrs,
                    vis,
                    id: AttributeId::Derived,
                    name,
                    ty,
                });
            }
        }
        Ok(AttributesInput { attributes })
    }
}

pub fn attributes_impl(input: TokenStream2, base_path: &TokenStream2) -> syn::Result<TokenStream2> {
    let AttributesInput { attributes } = syn::parse2(input)?;

    let mut out: TokenStream2 = TokenStream2::new();
    // Per-attribute records the top-level `describe()` needs in order
    // to emit identity + usage facts inline at the declaration site.
    let mut per_attr: Vec<(Ident, Ident, LitStr, Option<LitStr>, Type)> = Vec::new();
    for AttributesDef {
        mut attrs,
        vis,
        id,
        name,
        ty,
    } in attributes
    {
        let (parsed_attrs, description) = split_attrs(attrs)?;
        attrs = parsed_attrs;
        let ident_name = name.to_string();
        let name_lit = LitStr::new(&ident_name, name.span());
        let meta_ident = format_ident!("__attribute_meta_{}", name, span = name.span());

        let vis_ts = match vis {
            Some(v) => quote! { #v },
            None => quote! { pub },
        };
        // Both branches build a rooted fragment whose root IS the
        // attribute id. The Hex branch constructs the fragment via
        // the low-level `Fragment::rooted` API rather than `entity!{}`
        // — bootstrapping attributes like `metadata::value_encoding` are
        // themselves declared via `attributes!{}`, and any reference
        // to them from inside their own LazyLock init would deadlock.
        // Derived attributes expand `entity_impl` directly (same
        // crate as us) so the expansion uses our `base_path` instead
        // of routing through a sibling proc-macro shim.
        let body_fragment = match id {
            // Unchanged on purpose: this is what keeps every existing id
            // byte-identical. The fragment is empty, so the id is the literal.
            AttributeId::Pinned(lit) => quote! {
                {
                    let __id: #base_path::id::Id = #base_path::id::Id::new(
                        #base_path::id::_hex_literal_hex!(#lit)
                    )
                    .expect("attributes!{} hex id must be non-nil");
                    #base_path::trible::Fragment::rooted(
                        __id,
                        #base_path::trible::TribleSet::new(),
                    )
                }
            },
            // The anchor participates in identity instead of replacing it, which
            // is the only difference from `Pinned` and the whole point.
            //
            // BOOTSTRAP CONSTRAINT, and it is load-bearing: this arm dereferences
            // `metadata::anchor` and `metadata::value_encoding`, which are
            // THEMSELVES declared by `attributes!{}`. An attribute that this arm
            // depends on cannot itself be anchored — its LazyLock init would
            // require its own value. That fails as a hang or a reentrant-init
            // panic at RUNTIME, not as a compile error, so it will not be caught
            // by building.
            //
            // Every attribute in `metadata` must therefore stay `unsafe as`
            // permanently. That is not a migration state to be cleaned up later;
            // it is why the `Pinned` arm builds an EMPTY fragment via the
            // low-level `Fragment::rooted` rather than `entity!{}`.
            AttributeId::Anchored(lit) => {
                let entity_input = quote! {
                    #base_path::metadata::anchor: {
                        let __id: #base_path::id::Id = #base_path::id::Id::new(
                            #base_path::id::_hex_literal_hex!(#lit)
                        )
                        .expect("attributes!{} hex id must be non-nil");
                        <#base_path::inline::encodings::genid::GenId
                            as #base_path::inline::InlineEncoding>::inline_from(__id)
                    },
                    #base_path::metadata::value_encoding: <#ty as #base_path::metadata::MetaDescribe>::id(),
                    #base_path::metadata::tag: #base_path::metadata::KIND_ATTRIBUTE,
                };
                crate::entity_impl_no_meta(entity_input, base_path)?
            }
            AttributeId::Derived => {
                let entity_input = quote! {
                    #base_path::metadata::name:         #name_lit,
                    #base_path::metadata::value_encoding: <#ty as #base_path::metadata::MetaDescribe>::id(),
                    #base_path::metadata::tag: #base_path::metadata::KIND_ATTRIBUTE,
                };
                crate::entity_impl_no_meta(entity_input, base_path)?
            }
        };

        out.extend(quote! {
            #(#attrs)*
            #[allow(non_upper_case_globals)]
            #vis_ts static #name: ::std::sync::LazyLock<#base_path::attribute::Attribute<#ty>> =
                ::std::sync::LazyLock::new(|| {
                    // The macro supplies the encoding fact itself in both branches, so this
                    // conversion is checked by construction rather than by the callee.
                    // Deliberately explicit: `From<Fragment>` gave the UNCHECKED path the
                    // shortest name in Rust, which is why it was removed.
                    #base_path::attribute::Attribute::<#ty>::from_fragment_unchecked(#body_fragment)
                        .with_meta(&#meta_ident)
                });
        });
        per_attr.push((name, meta_ident, name_lit, description, ty));
    }

    // Build one cached description per declaration. `entity!` and the module's
    // explicit `describe()` use this same fragment, so the automatic and manual
    // paths cannot drift. Every internal expansion suppresses automatic
    // metafacts to cut the metadata attributes' bootstrap cycle.
    let mut meta_statics = TokenStream2::new();
    let mut describe_blocks = Vec::new();
    for (name, meta_ident, name_lit, description, ty) in per_attr {
        // Pinned attributes have an empty identity fragment, while anchored and
        // derived attributes already carry these two facts. Re-emitting them is
        // harmless set union and gives all three forms one complete record.
        let attribute_core_tokens = crate::entity_impl_no_meta(
            quote! {
                __attr_ref @
                #base_path::metadata::value_encoding:
                    <#ty as #base_path::metadata::MetaDescribe>::id(),
                #base_path::metadata::tag: #base_path::metadata::KIND_ATTRIBUTE,
            },
            base_path,
        )?;

        let usage_core_tokens = crate::entity_impl_no_meta(
            quote! {
                #base_path::metadata::attribute:     __attr_id,
                #base_path::metadata::source_module: module_path!(),
            },
            base_path,
        )?;

        let annotation_tokens = if let Some(desc_lit) = description {
            crate::entity_impl_no_meta(
                quote! {
                    __usage_ref @
                    #base_path::metadata::name:        #name_lit,
                    #base_path::metadata::tag:         #base_path::metadata::KIND_ATTRIBUTE_USAGE,
                    #base_path::metadata::description: #desc_lit,
                },
                base_path,
            )?
        } else {
            crate::entity_impl_no_meta(
                quote! {
                    __usage_ref @
                    #base_path::metadata::name: #name_lit,
                    #base_path::metadata::tag:  #base_path::metadata::KIND_ATTRIBUTE_USAGE,
                },
                base_path,
            )?
        };

        meta_statics.extend(quote! {
            #[doc(hidden)]
            #[allow(non_upper_case_globals)]
            static #meta_ident: #base_path::attribute::AttributeMeta =
                #base_path::attribute::AttributeMeta::new(|| {
                    let mut __fragment = #base_path::trible::Fragment::default();

                    // Preserve identity-determining facts (anchor/name/IRI).
                    __fragment += <#base_path::attribute::Attribute<_>
                        as #base_path::metadata::Describe>::describe(&*#name);

                    // Add the universal attribute schema/kind facts, including
                    // for the deliberately factless pinned form.
                    let __attr_id = #name.id();
                    let __attr_ref = #base_path::id::ExclusiveId::force_ref(&__attr_id);
                    __fragment += #attribute_core_tokens;

                    // The value encoding's own description. `value_encoding`
                    // above names the encoding only by id; these facts say
                    // what it is (for a `Handle<T>`, its `blob_encoding`), so a
                    // reader of the pile can type values without this crate.
                    __fragment += #base_path::attribute::encoding_description::<#ty>();

                    // Usage identity is derived only from attribute + source
                    // module. Human-facing name and docs are annotations on it.
                    let mut __usage = #usage_core_tokens;
                    let __usage_id = __usage.root().expect("usage core must be rooted");
                    let __usage_ref = #base_path::id::ExclusiveId::force_ref(&__usage_id);
                    __usage += #annotation_tokens;
                    __fragment += __usage;
                    __fragment
                });
        });

        describe_blocks.push(quote! {
            if let Some(__meta) = #meta_ident.get() {
                __fragment += __meta.clone();
            }
        });
    }

    out.extend(meta_statics);
    out.extend(quote! {
        /// Returns the same descriptions that `entity!` carries automatically,
        /// for callers that need a schema fragment without accompanying data.
        pub fn describe() -> #base_path::trible::Fragment {
            let mut __fragment = #base_path::trible::Fragment::default();
            #( #describe_blocks )*
            __fragment
        }
    });

    Ok(out)
}

impl From<LitStr> for AttributeId {
    fn from(lit: LitStr) -> Self {
        AttributeId::Pinned(lit)
    }
}
