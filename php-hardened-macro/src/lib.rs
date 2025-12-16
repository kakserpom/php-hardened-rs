use heck::{ToKebabCase, ToShoutySnakeCase};
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, punctuated::Punctuated, token::Comma, Expr, ExprLit, ItemEnum, ItemImpl, Lit,
};

/// Inserts `#[php_const] const Variant: &'static str = "variant";` (along with any
/// `/// ...` doc-comments) for each variant of the given enum into the top of the
/// annotated `impl` block.
///
/// Usage:
///
/// ```rust,ignore
/// #[php_impl]
/// #[php_enum_constants(Policy, "src/security_headers/cross_origin/embedder_policy.rs")]
/// impl Coep {
///     // … your methods …
/// }
/// ```
#[proc_macro_attribute]
pub fn php_enum_constants(attr: TokenStream, item: TokenStream) -> TokenStream {
    // 1) Parse exactly two comma‐separated expressions
    let args = parse_macro_input!(attr with Punctuated::<Expr, Comma>::parse_terminated);
    if args.len() != 2 {
        panic!("expected exactly two arguments: (EnumName, \"path/to/file.rs\")");
    }
    let mut it = args.into_iter();

    // 2) First argument: bare identifier → enum name
    let enum_ident = match it.next().unwrap() {
        Expr::Path(p) if p.path.segments.len() == 1 => p.path.segments[0].ident.clone(),
        _ => panic!("first argument must be a bare enum identifier"),
    };

    // 3) Second argument: string literal → file path
    let file_path = match it.next().unwrap() {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s.value(),
        _ => panic!("second argument must be a string literal path"),
    };

    // 4) Parse the impl block we’re annotating
    let mut imp: ItemImpl = parse_macro_input!(item as ItemImpl);

    // 5) Read & parse the target source file
    let src = std::fs::read_to_string(&file_path)
        .unwrap_or_else(|_| panic!("couldn't read `{}`", file_path));
    let syntax =
        syn::parse_file(&src).unwrap_or_else(|_| panic!("failed to parse `{}`", file_path));

    // 6) Locate the enum and generate consts
    let mut const_items = Vec::new();
    for node in syntax.items {
        if let syn::Item::Enum(ItemEnum {
            ident, variants, ..
        }) = node
        {
            if ident == enum_ident {
                for variant in variants {
                    let name = &variant.ident;
                    // capture any doc-comments
                    let docs = variant
                        .attrs
                        .iter()
                        .filter(|a| a.path().is_ident("doc"))
                        .cloned();
                    // Strip leading underscore if present (e.g. `_Self` -> `Self`)
                    // This is needed because some Rust keywords like `Self` must be prefixed
                    let name_str = name.to_string();
                    let clean_name_str = name_str.strip_prefix('_').unwrap_or(&name_str);
                    // Use SCREAMING_SNAKE_CASE for PHP constant names (e.g. `Self` -> `SELF`)
                    let const_name_str = clean_name_str.to_shouty_snake_case();
                    let const_name = syn::Ident::new(&const_name_str, name.span());
                    let lit = clean_name_str.to_kebab_case();
                    const_items.push(quote! {
                        #(#docs)*
                        #[php_const]
                        const #const_name: &'static str = #lit;
                    });
                }
                break;
            }
        }
    }

    // 7) Prepend generated consts into the impl
    let existing = std::mem::take(&mut imp.items);
    for ci in const_items {
        imp.items.push(syn::parse2(ci).unwrap());
    }
    imp.items.extend(existing);

    // 8) Emit the modified impl
    TokenStream::from(quote! { #imp })
}
