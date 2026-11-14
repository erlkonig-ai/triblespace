use proc_macro2::Span;
use proc_macro2::TokenStream as TokenStream2;
use quote::format_ident;
use quote::quote;
use quote::ToTokens;
use syn::braced;
use syn::bracketed;
use syn::parse::Parse;
use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::Expr;
use syn::Ident;
use syn::Token;

mod attributes;
mod find;
mod value_formatter;

pub use attributes::attributes_impl;
pub use find::find_impl;
pub use value_formatter::value_formatter_impl;

struct PatternInput {
    set: Expr,
    pattern: Vec<Entity>,
}

struct Entity {
    id: Option<Inline>,
    attributes: Vec<Attribute>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttributeMode {
    Required,
    Optional,
    Repeated,
}

enum Inline {
    Var(Ident),
    LocalVar(Ident),
    Expr(Expr),
}

struct Attribute {
    /// Attribute identifier in the pattern's `name: value` slot.
    /// Three shapes are supported:
    ///   - `Inline::Expr(e)`     — known attribute constant, e.g.
    ///                            `cwork_title`. The macro resolves
    ///                            the attribute Id and uses its
    ///                            schema to type the value.
    ///   - `Inline::Var(ident)`  — free attribute, bound to a
    ///                            `find!`-projected
    ///                            `Variable<GenId>`. The value
    ///                            position is required to be a
    ///                            `Variable<UnknownInline>` — the
    ///                            macro emits a compile-time type
    ///                            assertion to that effect.
    ///                            Without a fixed predicate the
    ///                            value bytes can come from any
    ///                            schema, so the user must take an
    ///                            explicit `try_from_inline::<S>()`
    ///                            step to decode them and that
    ///                            transmutation has to live at the
    ///                            use site rather than the
    ///                            projection.
    ///   - `Inline::LocalVar(_)` — pattern-local helper variable in
    ///                            the attribute slot. Free-attribute
    ///                            in the value slot is rejected
    ///                            (no schema to infer); the user
    ///                            should project a `Variable<UnknownInline>`
    ///                            via `find!` instead.
    name: Inline,
    mode: AttributeMode,
    value: Inline,
}

impl Parse for PatternInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let set: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let content;
        bracketed!(content in input);

        let pattern = Punctuated::<_, Token![,]>::parse_terminated(&content)?
            .into_iter()
            .collect();

        Ok(PatternInput { set, pattern })
    }
}

impl Parse for Entity {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let content;
        braced!(content in input);

        let mut id: Option<Inline> = None;
        {
            let fork = content.fork();
            // Special-case `_ @` so callers can be explicit about content-derived identity
            // without colliding with a Rust identifier.
            if fork.peek(Token![_]) {
                let fork2 = fork;
                fork2.parse::<Token![_]>()?;
                if fork2.peek(Token![@]) {
                    content.parse::<Token![_]>()?;
                    content.parse::<Token![@]>()?;
                }
            }
        }
        if id.is_none() {
            let fork = content.fork();
            if fork.parse::<Inline>().is_ok() && fork.peek(Token![@]) {
                let pv: Inline = content.parse()?;
                content.parse::<Token![@]>()?;
                id = Some(pv);
            }
        }

        let attributes = Punctuated::<_, Token![,]>::parse_terminated(&content)?
            .into_iter()
            .collect();

        Ok(Entity { id, attributes })
    }
}

impl Parse for Attribute {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        // Support explicit fact modifiers while keeping `attr: value` flexible:
        // - `attr: value`   (required, attr can be any expression OR `?ident` / `_?ident`)
        // - `attr?: value`  (optional, value must be `Option<T>`)
        // - `attr*: value`  (repeated, value must be an `IntoIterator<Item = T>`)
        //
        // The `?:` and `*:` modifiers only make sense for known
        // attribute constants (Optional/Repeated need the
        // attribute's schema to type the value), so they're parsed
        // only after a path-like attribute reference. Free
        // attributes (`?attr`, `_?attr`) are required-mode only.
        let fork = input.fork();
        if let Ok(expr_path) = fork.parse::<syn::ExprPath>() {
            if fork.peek(Token![?]) {
                let fork2 = fork.fork();
                fork2.parse::<Token![?]>()?;
                if fork2.peek(Token![:]) {
                    let name = Inline::Expr(Expr::Path(input.parse::<syn::ExprPath>()?));
                    input.parse::<Token![?]>()?;
                    input.parse::<Token![:]>()?;
                    let value: Inline = input.parse()?;
                    return Ok(Attribute {
                        name,
                        mode: AttributeMode::Optional,
                        value,
                    });
                }
            }

            if fork.peek(Token![*]) {
                let fork2 = fork.fork();
                fork2.parse::<Token![*]>()?;
                if fork2.peek(Token![:]) {
                    let name = Inline::Expr(Expr::Path(input.parse::<syn::ExprPath>()?));
                    input.parse::<Token![*]>()?;
                    input.parse::<Token![:]>()?;
                    let value: Inline = input.parse()?;
                    return Ok(Attribute {
                        name,
                        mode: AttributeMode::Repeated,
                        value,
                    });
                }
            }

            // Path-like required fact: fall through to the generic
            // Inline branch below, which also accepts `?ident` /
            // `_?ident`.
            let _ = expr_path;
        }

        let name: Inline = input.parse()?;
        input.parse::<Token![:]>()?;
        let value: Inline = input.parse()?;
        Ok(Attribute {
            name,
            mode: AttributeMode::Required,
            value,
        })
    }
}

impl Parse for Inline {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.peek(Token![_]) {
            let fork = input.fork();
            fork.parse::<Token![_]>()?;
            if fork.peek(Token![?]) {
                input.parse::<Token![_]>()?;
                input.parse::<Token![?]>()?;
                let var_ident: Ident = input.parse()?;
                return Ok(Inline::LocalVar(var_ident));
            }
        }
        if input.peek(Token![?]) {
            input.parse::<Token![?]>()?;
            let var_ident: Ident = input.parse()?;
            Ok(Inline::Var(var_ident))
        } else {
            let expr: Expr = input.parse()?;
            Ok(Inline::Expr(expr))
        }
    }
}

pub fn pattern_impl(input: TokenStream2, base_path: &TokenStream2) -> syn::Result<TokenStream2> {
    let PatternInput { set, pattern } = syn::parse2(input)?;

    let ctx_ident = format_ident!("__ctx", span = Span::mixed_site());
    let set_ident = format_ident!("__set", span = Span::mixed_site());

    let mut entity_tokens = TokenStream2::new();
    let mut attr_tokens = TokenStream2::new();

    use std::collections::HashMap;
    let mut attr_idx = 0usize;
    let mut val_idx = 0usize;
    // Tuple in the map is (attribute variable ident, optional
    // attribute-constant reference ident). The reference is None
    // for free-attribute patterns (`?attr` / `_?attr`) where no
    // `Attribute` constant is available.
    let mut attr_map: HashMap<String, (Ident, Option<Ident>)> = HashMap::new();
    let mut local_tokens = TokenStream2::new();
    let mut local_map: HashMap<String, Ident> = HashMap::new();
    let mut local_idx = 0usize;
    let mut get_local_var = |ident: &Ident| {
        let key = format!("_?{}", ident);
        local_map
            .entry(key)
            .or_insert_with(|| {
                let ident = format_ident!("__local{}", local_idx, span = Span::mixed_site());
                local_idx += 1;
                local_tokens.extend(quote! {
                    let #ident = #ctx_ident.next_variable();
                });
                ident
            })
            .clone()
    };

    for (entity_idx, entity) in pattern.into_iter().enumerate() {
        let e_ident = format_ident!("__e{}", entity_idx, span = Span::mixed_site());
        // Track the entity's variable identity so we can detect
        // self-referencing patterns like `{ _?e @ attr: _?e }` or
        // `{ ?e @ attr: ?e }` and desugar them with EqualityConstraint.
        let entity_var_key: Option<(bool, String)> = match entity.id {
            Some(Inline::LocalVar(ref ident)) => Some((true, ident.to_string())),
            Some(Inline::Var(ref ident)) => Some((false, ident.to_string())),
            _ => None,
        };
        let init = if let Some(ref id_val) = entity.id {
            match id_val {
                Inline::Var(ref ident) => {
                    quote! { let #e_ident = #ident; }
                }
                Inline::LocalVar(ref ident) => {
                    let local_ident = get_local_var(ident);
                    quote! { let #e_ident = #local_ident; }
                }
                Inline::Expr(ref id_expr) => {
                    // Constant entity id: fold it into the pattern as a
                    // constant term — no hidden variable, no
                    // ConstantConstraint.
                    quote! {
                        let #e_ident: #base_path::inline::Inline<#base_path::inline::encodings::genid::GenId> = #base_path::inline::IntoInline::to_inline(#id_expr);
                    }
                }
            }
        } else {
            quote! {
                let #e_ident: #base_path::query::Variable<#base_path::inline::encodings::genid::GenId> = #ctx_ident.next_variable();
            }
        };
        entity_tokens.extend(init);

        for Attribute { name, mode, value } in entity.attributes {
            if mode != AttributeMode::Required {
                let span_for_err = match &name {
                    Inline::Expr(e) => e.to_token_stream(),
                    Inline::Var(i) => i.to_token_stream(),
                    Inline::LocalVar(i) => i.to_token_stream(),
                };
                return Err(syn::Error::new_spanned(
                    span_for_err,
                    "`?:` and `*:` are not supported in pattern!; use `attr: value`",
                ));
            }

            // Set up (or reuse) the attribute term for this slot.
            // For Inline::Expr (concrete attribute) we emit a
            // `let __af = &expr` reference to the Attribute constant
            // (so downstream value codegen can call `.inline_from(...)`
            // / `.as_variable(...)` on it) plus a constant
            // `Inline<GenId>` term carrying the attribute id — no
            // hidden variable is allocated, so the constant never
            // appears in the constraint's variable set. For
            // Inline::Var / Inline::LocalVar (free attribute) there is
            // no schema available — `__af` is `None` and the value
            // position must use the opaque `UnknownInline` schema.
            let key = match &name {
                Inline::Var(ident) => format!("?{}", ident),
                Inline::LocalVar(ident) => format!("_?{}", ident),
                Inline::Expr(expr) => expr.to_token_stream().to_string(),
            };
            let (a_var_ident, af_ident_opt) = attr_map
                .entry(key)
                .or_insert_with(|| {
                    let a_ident =
                        format_ident!("__a{}", attr_idx, span = Span::mixed_site());
                    attr_idx += 1;
                    match &name {
                        Inline::Expr(expr) => {
                            let af_ident = format_ident!(
                                "__af{}",
                                attr_idx,
                                span = Span::mixed_site()
                            );
                            attr_tokens.extend(quote! {
                                let #af_ident = &#expr;
                                let #a_ident: #base_path::inline::Inline<#base_path::inline::encodings::genid::GenId> = #base_path::inline::IntoInline::to_inline(#af_ident.id());
                            });
                            (a_ident, Some(af_ident))
                        }
                        Inline::Var(user_ident) => {
                            attr_tokens.extend(quote! {
                                let #a_ident: #base_path::query::Variable<#base_path::inline::encodings::genid::GenId> = #user_ident;
                            });
                            (a_ident, None)
                        }
                        Inline::LocalVar(local_ident) => {
                            let local_var = get_local_var(local_ident);
                            attr_tokens.extend(quote! {
                                let #a_ident: #base_path::query::Variable<#base_path::inline::encodings::genid::GenId> = #local_var;
                            });
                            (a_ident, None)
                        }
                    }
                })
                .clone();

            let val_id = {
                let v = val_idx;
                val_idx += 1;
                v
            };
            let v_tmp_ident = format_ident!("__v{}", val_id, span = Span::mixed_site());

            // Self-reference detection (only meaningful for projected
            // variables, where the entity and value bind the same
            // user variable).
            let value_var_key: Option<(bool, String)> = match value {
                Inline::Var(ref ident) => Some((false, ident.to_string())),
                Inline::LocalVar(ref ident) => Some((true, ident.to_string())),
                _ => None,
            };
            let self_ref = entity_var_key.is_some() && entity_var_key == value_var_key;

            // Emit the per-trible constraint. The shape splits along
            // two axes: Inline variant (Var / LocalVar / Expr) and
            // whether the attribute is concrete (`af_ident_opt =
            // Some`) or free (`af_ident_opt = None`).
            let triple_tokens = match (value, af_ident_opt.as_ref()) {
                // ---- concrete attribute paths (existing) ----
                (Inline::Var(ref var_ident), Some(af_ident)) if self_ref => {
                    let alias_ident = format_ident!("__alias{}", val_id, span = Span::mixed_site());
                    quote! {
                        {
                            #[allow(unused_imports)] use #base_path::query::TriblePattern;
                            let #alias_ident: #base_path::query::Variable<#base_path::inline::encodings::genid::GenId> = #ctx_ident.next_variable();
                            let v_var = #af_ident.as_variable(#alias_ident);
                            constraints.push(Box::new(#base_path::query::equalityconstraint::EqualityConstraint::new(#e_ident.index, #alias_ident.index)));
                            constraints.push(Box::new(#set_ident.pattern(#e_ident, #a_var_ident, v_var)));
                        }
                    }
                }
                (Inline::Var(ref var_ident), Some(af_ident)) => {
                    quote! {
                        {
                            #[allow(unused_imports)] use #base_path::query::TriblePattern;
                            let v_var = { #af_ident.as_variable(#var_ident) };
                            constraints.push(Box::new(#set_ident.pattern(#e_ident, #a_var_ident, v_var)));
                        }
                    }
                }
                (Inline::LocalVar(ref var_ident), Some(af_ident)) if self_ref => {
                    let _local_ident = get_local_var(var_ident);
                    let alias_ident = format_ident!("__alias{}", val_id, span = Span::mixed_site());
                    quote! {
                        {
                            #[allow(unused_imports)] use #base_path::query::TriblePattern;
                            let #alias_ident: #base_path::query::Variable<#base_path::inline::encodings::genid::GenId> = #ctx_ident.next_variable();
                            let v_var = #af_ident.as_variable(#alias_ident);
                            constraints.push(Box::new(#base_path::query::equalityconstraint::EqualityConstraint::new(#e_ident.index, #alias_ident.index)));
                            constraints.push(Box::new(#set_ident.pattern(#e_ident, #a_var_ident, v_var)));
                        }
                    }
                }
                (Inline::LocalVar(ref var_ident), Some(af_ident)) => {
                    let local_ident = get_local_var(var_ident);
                    quote! {
                        {
                            #[allow(unused_imports)] use #base_path::query::TriblePattern;
                            let v_var = { #af_ident.as_variable(#local_ident) };
                            constraints.push(Box::new(#set_ident.pattern(#e_ident, #a_var_ident, v_var)));
                        }
                    }
                }
                (Inline::Expr(ref expr), Some(af_ident)) => {
                    // Literal value: fold it into the pattern as a
                    // constant term (typed by the attribute's schema
                    // via `inline_from`) — no hidden variable, no
                    // ConstantConstraint.
                    quote! {
                        {
                            #[allow(unused_imports)] use #base_path::query::TriblePattern;
                            let #v_tmp_ident = #af_ident.inline_from(#expr);
                            constraints.push(Box::new(#set_ident.pattern(#e_ident, #a_var_ident, #v_tmp_ident)));
                        }
                    }
                }

                // ---- free attribute paths (new) ----
                //
                // No Attribute constant is available, so the macro
                // can't apply a schema cast and the engine is going
                // to match bytes regardless of the schema the user
                // typed the variable with. Letting any
                // `Variable<S>` through would compile, the join
                // would still find the right rows, but
                // `try_from_inline::<S>()` on the result would lie
                // for every row whose predicate isn't actually an
                // `S`. To make that footgun a compile-time error,
                // we emit a static type assertion that the user's
                // variable is exactly `Variable<UnknownInline>` —
                // forcing the receiver to do an explicit
                // `try_from_inline::<RealSchema>()` at the use site
                // when they know which predicate they're decoding.
                (Inline::Var(ref var_ident), None) => {
                    quote! {
                        {
                            #[allow(unused_imports)] use #base_path::query::TriblePattern;
                            // Compile-time enforcement: the value variable
                            // for a free-attribute pattern must be typed
                            // `Variable<UnknownInline>`. Any other schema
                            // is rejected here so users can't quietly
                            // misinterpret the bytes downstream.
                            let _: &#base_path::query::Variable<#base_path::inline::encodings::UnknownInline> = &#var_ident;
                            constraints.push(Box::new(#set_ident.pattern(#e_ident, #a_var_ident, #var_ident)));
                        }
                    }
                }
                (Inline::LocalVar(ref var_ident), None) => {
                    return Err(syn::Error::new_spanned(
                        var_ident,
                        "local helper variables (_?ident) in the value position are not supported with a free attribute (?attr); use a `find!`-projected `Variable<UnknownInline>` (`?val`) instead",
                    ));
                }
                (Inline::Expr(ref expr), None) => {
                    return Err(syn::Error::new_spanned(
                        expr,
                        "free attribute (?ident) requires a `Variable<UnknownInline>` query variable in the value position; concrete value expressions need a known attribute so the macro can apply its schema",
                    ));
                }
            };
            entity_tokens.extend(triple_tokens);
        }
    }

    let output = quote! {
        {
            let mut constraints: ::std::vec::Vec<Box<dyn #base_path::query::Constraint + Send + Sync>> = ::std::vec::Vec::new();
            let #ctx_ident = __local_find_context!();
            let #set_ident = #set;
            #local_tokens
            #attr_tokens
            #entity_tokens
            #base_path::query::intersectionconstraint::IntersectionConstraint::arc_or_single(constraints)
        }
    };

    Ok(output)
}

pub fn entity_impl(input: TokenStream2, base_path: &TokenStream2) -> syn::Result<TokenStream2> {
    entity_impl_with(input, base_path, true)
}

/// Internal expansion used while constructing attribute descriptions. It emits
/// the requested facts but does not recursively describe the metadata
/// attributes used to express them.
pub(crate) fn entity_impl_no_meta(
    input: TokenStream2,
    base_path: &TokenStream2,
) -> syn::Result<TokenStream2> {
    entity_impl_with(input, base_path, false)
}

fn entity_impl_with(
    input: TokenStream2,
    base_path: &TokenStream2,
    emit_meta: bool,
) -> syn::Result<TokenStream2> {
    let wrapped = quote! { { #input } };

    let Entity { id, attributes } = syn::parse2(wrapped)?;

    let state_init = quote! {
        #[allow(unused_mut)]
        let mut __meta: #base_path::trible::TribleSet =
            #base_path::trible::TribleSet::new();
        let mut __blobs: #base_path::blob::MemoryBlobStore =
            #base_path::blob::MemoryBlobStore::new();
    };
    let attr_count = attributes.len();

    let mut attr_eval_tokens = TokenStream2::new();
    let mut explicit_insert_tokens = TokenStream2::new();
    let mut intrinsic_row_tokens = TokenStream2::new();
    let mut extra_merge_tokens = TokenStream2::new();

    for (i, attr) in attributes.into_iter().enumerate() {
        let mode = attr.mode;
        // entity! requires a concrete attribute constant — there's
        // no meaningful way to "insert" a fact with a free
        // attribute Id. Free attributes are a query-only construct.
        let field_expr = match attr.name {
            Inline::Expr(e) => e,
            Inline::Var(id) => {
                return Err(syn::Error::new_spanned(
                    id,
                    "variable attribute bindings (?ident) are not allowed in entity!; use a literal attribute reference here",
                ));
            }
            Inline::LocalVar(id) => {
                return Err(syn::Error::new_spanned(
                    id,
                    "local variable attribute bindings (_?ident) are not allowed in entity!; use a literal attribute reference here",
                ));
            }
        };
        let value_expr = match attr.value {
            Inline::Expr(e) => e,
            Inline::Var(id) => {
                return Err(syn::Error::new_spanned(
                    id,
                    "variable bindings (?ident) are not allowed in entity!; use a literal expression here",
                ));
            }
            Inline::LocalVar(id) => {
                return Err(syn::Error::new_spanned(
                    id,
                    "local variable bindings (_?ident) are not allowed in entity!; use a literal expression here",
                ));
            }
        };

        let af_ident = format_ident!("__af{}", i, span = Span::mixed_site());
        let val_ident = format_ident!("__val{}", i, span = Span::mixed_site());
        let aid_ident = format_ident!("__a_id{}", i, span = Span::mixed_site());
        let extra_ident = format_ident!("__extra{}", i, span = Span::mixed_site());

        attr_eval_tokens.extend(quote! { let #af_ident = &#field_expr; });

        // An attribute description is itself a Fragment. Its two fact sets are
        // both descriptive relative to the entity being built, while its one
        // blob store remains shared with the entity's content blobs.
        let meta_tokens = if emit_meta {
            quote! {
                {
                    let __attr_meta = #af_ident.meta();
                    __meta.union(__attr_meta.facts().clone());
                    __meta.union(__attr_meta.metafacts().clone());
                    __blobs.union(__attr_meta.blobs().clone());
                }
            }
        } else {
            TokenStream2::new()
        };

        match mode {
            AttributeMode::Required => {
                attr_eval_tokens.extend(quote! {
                    let (#val_ident, __maybe_blob) =
                        #af_ident.encoded_from(#value_expr).into_parts();
                    if let Some(__b) = __maybe_blob {
                        __blobs.insert(__b);
                    }
                    #meta_tokens
                });
            }
            AttributeMode::Optional => {
                attr_eval_tokens.extend(quote! {
                    let #val_ident = {
                        let __opt: ::std::option::Option<_> = #value_expr;
                        __opt.map(|__v| {
                            let (__val, __maybe_blob) =
                                #af_ident.encoded_from(__v).into_parts();
                            if let Some(__b) = __maybe_blob {
                                __blobs.insert(__b);
                            }
                            __val
                        })
                    };
                    if #val_ident.is_some() {
                        #meta_tokens
                    }
                });
            }
            AttributeMode::Repeated => {
                attr_eval_tokens.extend(quote! {
                    let (#val_ident, #extra_ident) = {
                        let (__spread_iter, __spread_facts) =
                            #base_path::trible::Spread::spread(#value_expr);
                        let __vals = ::std::iter::IntoIterator::into_iter(__spread_iter)
                            .map(|__v| {
                                let (__val, __maybe_blob) =
                                    #af_ident.encoded_from(__v).into_parts();
                                if let Some(__b) = __maybe_blob {
                                    __blobs.insert(__b);
                                }
                                __val
                            })
                            .collect::<::std::vec::Vec<_>>();
                        (__vals, __spread_facts)
                    };
                    if !#val_ident.is_empty() {
                        #meta_tokens
                    }
                });
            }
        }
        attr_eval_tokens.extend(quote! { let #aid_ident = #af_ident.id(); });

        match mode {
            AttributeMode::Required => {
                intrinsic_row_tokens.extend(quote! {
                    __rows.push(#base_path::trible::IntrinsicEntityRow::new(
                        #aid_ident,
                        #val_ident.raw,
                    ));
                });
                explicit_insert_tokens.extend(quote! {
                    set.insert(&#base_path::trible::Trible::new(id_ref, &#aid_ident, &#val_ident));
                });
            }
            AttributeMode::Optional => {
                intrinsic_row_tokens.extend(quote! {
                    if let Some(ref __v) = #val_ident {
                        __rows.push(#base_path::trible::IntrinsicEntityRow::new(
                            #aid_ident,
                            __v.raw,
                        ));
                    }
                });
                explicit_insert_tokens.extend(quote! {
                    if let Some(ref __v) = #val_ident {
                        set.insert(&#base_path::trible::Trible::new(id_ref, &#aid_ident, __v));
                    }
                });
            }
            AttributeMode::Repeated => {
                intrinsic_row_tokens.extend(quote! {
                    for __v in #val_ident.iter() {
                        __rows.push(#base_path::trible::IntrinsicEntityRow::new(
                            #aid_ident,
                            __v.raw,
                        ));
                    }
                });
                explicit_insert_tokens.extend(quote! {
                    for __v in #val_ident.iter() {
                        set.insert(&#base_path::trible::Trible::new(id_ref, &#aid_ident, __v));
                    }
                });
                extra_merge_tokens.extend(quote! {
                    let (_, __extra_facts, __extra_metafacts, __extra_blobs) =
                        #extra_ident.into_parts();
                    set += __extra_facts;
                    __meta.union(__extra_metafacts);
                    __blobs.union(__extra_blobs);
                });
            }
        }
    }

    let entity_init: TokenStream2 = if let Some(val) = id {
        match val {
            Inline::Expr(expr) => quote! {
                let id_tmp = #expr;
                let id_ref: &#base_path::id::ExclusiveId = id_tmp.as_ref();
                let root_id = id_ref.id;
                let mut set = #base_path::trible::TribleSet::new();
                #explicit_insert_tokens
            },
            Inline::Var(ident) => {
                return Err(syn::Error::new_spanned(
                    ident,
                    "variable bindings (?ident) are not allowed in entity!; use a literal expression here",
                ));
            }
            Inline::LocalVar(ident) => {
                return Err(syn::Error::new_spanned(
                    ident,
                    "local variable bindings (_?ident) are not allowed in entity!; use a literal expression here",
                ));
            }
        }
    } else {
        quote! {
            let mut __rows: ::std::vec::Vec<#base_path::trible::IntrinsicEntityRow> =
                ::std::vec::Vec::with_capacity(#attr_count);
            #intrinsic_row_tokens
            let (root_id, mut set) = #base_path::trible::build_intrinsic_entity(__rows);
        }
    };

    let output = quote! {
        {
            #state_init
            #attr_eval_tokens
            #entity_init
            #extra_merge_tokens
            #base_path::trible::Fragment::rooted_from_parts(root_id, set, __meta, __blobs)
        }
    };

    Ok(output)
}

struct PatternChangesInput {
    curr: Expr,
    changes: Expr,
    pattern: Vec<Entity>,
}

impl Parse for PatternChangesInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let curr: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let changes: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let content;
        bracketed!(content in input);

        let mut pattern = Vec::new();
        while !content.is_empty() {
            pattern.push(content.parse()?);
            if content.peek(Token![,]) {
                content.parse::<Token![,]>()?;
            }
        }

        Ok(PatternChangesInput {
            curr,
            changes,
            pattern,
        })
    }
}

pub fn pattern_changes_impl(
    input: TokenStream2,
    base_path: &TokenStream2,
) -> syn::Result<TokenStream2> {
    use std::collections::HashMap;

    let PatternChangesInput {
        curr,
        changes,
        pattern,
    } = syn::parse2(input)?;

    let ctx_ident = format_ident!("__ctx", span = Span::mixed_site());
    let curr_ident = format_ident!("__curr", span = Span::mixed_site());
    let delta_ident = format_ident!("__delta", span = Span::mixed_site());

    let mut attr_decl_tokens = TokenStream2::new();
    let mut entity_decl_tokens = TokenStream2::new();
    let mut entity_const_tokens = TokenStream2::new();
    let mut value_decl_tokens = TokenStream2::new();

    let mut triples = Vec::<TripleInfo>::new();

    let mut attr_map: HashMap<String, (Ident, Ident)> = HashMap::new();
    let mut attr_idx = 0usize;
    let mut value_idx = 0usize;
    let mut local_decl_tokens = TokenStream2::new();
    let mut local_map: HashMap<String, Ident> = HashMap::new();
    let mut local_idx = 0usize;

    let mut get_local_var = |ident: &Ident| {
        let key = format!("_?{}", ident);
        local_map
            .entry(key)
            .or_insert_with(|| {
                let ident = format_ident!("__local{}", local_idx, span = Span::mixed_site());
                local_idx += 1;
                local_decl_tokens.extend(quote! {
                    let #ident = #ctx_ident.next_variable();
                });
                ident
            })
            .clone()
    };

    for (entity_idx, entity) in pattern.into_iter().enumerate() {
        let e_ident = format_ident!("__e{}", entity_idx, span = Span::mixed_site());
        let entity_var_key: Option<(bool, String)> = match entity.id {
            Some(Inline::LocalVar(ref ident)) => Some((true, ident.to_string())),
            Some(Inline::Var(ref ident)) => Some((false, ident.to_string())),
            _ => None,
        };
        match entity.id {
            Some(ref id_val) => match id_val {
                Inline::Var(ref ident) => {
                    entity_decl_tokens.extend(quote! { let #e_ident = #ident; });
                }
                Inline::LocalVar(ref ident) => {
                    let local_ident = get_local_var(ident);
                    entity_decl_tokens.extend(quote! { let #e_ident = #local_ident; });
                }
                Inline::Expr(ref id_expr) => {
                    // Constant entity id: folded as a constant term.
                    entity_decl_tokens.extend(quote! {
                        let #e_ident: #base_path::inline::Inline<#base_path::inline::encodings::genid::GenId> = #base_path::inline::IntoInline::to_inline(#id_expr);
                    });
                }
            },
            None => {
                entity_decl_tokens.extend(quote! {
                    let #e_ident: #base_path::query::Variable<#base_path::inline::encodings::genid::GenId> = #ctx_ident.next_variable();
                });
            }
        }

        for Attribute {
            name: attr_name,
            mode,
            value,
        } in entity.attributes
        {
            // pattern_changes! currently requires concrete attribute
            // constants — free-attribute (`?attr` / `_?attr`)
            // support is a follow-up; the incremental delta walk
            // needs more thought to remain spec-correct without a
            // known schema for the value position.
            let attr_expr = match attr_name {
                Inline::Expr(e) => e,
                Inline::Var(ident) => {
                    return Err(syn::Error::new_spanned(
                        ident,
                        "free attribute (?ident) is not yet supported in pattern_changes!; use a concrete attribute constant",
                    ));
                }
                Inline::LocalVar(ident) => {
                    return Err(syn::Error::new_spanned(
                        ident,
                        "free attribute (_?ident) is not yet supported in pattern_changes!; use a concrete attribute constant",
                    ));
                }
            };
            if mode != AttributeMode::Required {
                return Err(syn::Error::new_spanned(
                    &attr_expr,
                    "`?:` and `*:` are not supported in pattern_changes!; use `attr: value`",
                ));
            }
            let key = attr_expr.to_token_stream().to_string();
            let (a_ident, af_ident) = attr_map
                .entry(key)
                .or_insert_with(|| {
                    let a_ident = format_ident!("__a{}", attr_idx, span = Span::mixed_site());
                    let af_ident = format_ident!("__af{}", attr_idx, span = Span::mixed_site());
                    attr_idx += 1;
                    // Attribute constant: folded as a constant term —
                    // no hidden variable, no ConstantConstraint.
                    attr_decl_tokens.extend(quote! {
                        let #af_ident = &#attr_expr;
                        let #a_ident: #base_path::inline::Inline<#base_path::inline::encodings::genid::GenId> = #base_path::inline::IntoInline::to_inline(#af_ident.id());
                    });
                    (a_ident, af_ident)
                })
                .clone();

            let v_ident = format_ident!("__v{}", value_idx, span = Span::mixed_site());
            value_idx += 1;

            let value_var_key: Option<(bool, String)> = match value {
                Inline::Var(ref ident) => Some((false, ident.to_string())),
                Inline::LocalVar(ref ident) => Some((true, ident.to_string())),
                _ => None,
            };
            let self_ref = entity_var_key.is_some() && entity_var_key == value_var_key;

            match value {
                Inline::Expr(expr) => {
                    // Literal value: folded as a constant term.
                    value_decl_tokens.extend(quote! {
                        let #v_ident = #af_ident.inline_from(#expr);
                    });
                }
                Inline::Var(_) | Inline::LocalVar(_) if self_ref => {
                    // Self-referencing: create fresh alias + equality
                    let alias_ident =
                        format_ident!("__alias{}", value_idx, span = Span::mixed_site());
                    value_idx += 1;
                    value_decl_tokens.extend(quote! {
                        let #alias_ident: #base_path::query::Variable<#base_path::inline::encodings::genid::GenId> = #ctx_ident.next_variable();
                        let #v_ident = #af_ident.as_variable(#alias_ident);
                    });
                    entity_const_tokens.extend(quote! {
                        constraints.push(Box::new(#base_path::query::equalityconstraint::EqualityConstraint::new(#e_ident.index, #alias_ident.index)));
                    });
                }
                Inline::Var(var_ident) => {
                    value_decl_tokens.extend(quote! {
                        let #v_ident = #af_ident.as_variable(#var_ident);
                    });
                }
                Inline::LocalVar(ref var_ident) => {
                    let local_ident = get_local_var(var_ident);
                    value_decl_tokens.extend(quote! {
                        let #v_ident = #af_ident.as_variable(#local_ident);
                    });
                }
            }

            triples.push(TripleInfo {
                e_ident: e_ident.clone(),
                a_ident: a_ident.clone(),
                v_ident,
            });
        }
    }

    let mut case_exprs: Vec<TokenStream2> = Vec::new();
    for delta_idx in 0..triples.len() {
        let mut triple_tokens = TokenStream2::new();
        for (
            idx,
            TripleInfo {
                e_ident,
                a_ident,
                v_ident,
            },
        ) in triples.iter().enumerate()
        {
            let dataset = if idx == delta_idx {
                &delta_ident
            } else {
                &curr_ident
            };
            triple_tokens.extend(quote! {
                constraints.push(Box::new(#dataset.pattern(#e_ident, #a_ident, #v_ident)));
            });
        }

        let case = quote! {
            {
                let mut constraints: ::std::vec::Vec<Box<dyn #base_path::query::Constraint + Send + Sync>> = ::std::vec::Vec::new();
                #[allow(unused_imports)] use #base_path::query::TriblePattern;
                #triple_tokens
                #base_path::query::intersectionconstraint::IntersectionConstraint::arc_or_single(constraints)
            }
        };
        case_exprs.push(case);
    }

    let union_expr = quote! {
        ::std::sync::Arc::new(
            #base_path::query::unionconstraint::UnionConstraint::new(vec![
                #(Box::new(#case_exprs) as Box<dyn #base_path::query::Constraint + Send + Sync>),*
            ])
        )
    };

    let output = quote! {
        {
            let #ctx_ident = __local_find_context!();
            let #curr_ident = #curr;
            let #delta_ident = #changes;
            #attr_decl_tokens
            #local_decl_tokens
            #entity_decl_tokens
            #value_decl_tokens
            let mut constraints: ::std::vec::Vec<Box<dyn #base_path::query::Constraint + Send + Sync>> = ::std::vec::Vec::new();
            #[allow(unused_imports)] use #base_path::query::TriblePattern;
            #entity_const_tokens
            constraints.push(Box::new(#union_expr));
            #base_path::query::intersectionconstraint::IntersectionConstraint::arc_or_single(constraints)
        }
    };

    Ok(output)
}

struct TripleInfo {
    e_ident: Ident,
    a_ident: Ident,
    v_ident: Ident,
}
