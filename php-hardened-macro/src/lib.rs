use heck::ToKebabCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, ExprLit, ExprTuple, ItemEnum, ItemImpl, Lit};

/// Inserts `#[php_const] const Variant: &'static str = "variant";` for each variant
/// of the given enum into the top of the annotated `impl` block.
///
/// Usage:
///
/// ```rust
/// #[php_impl]
/// #[php_enum_constants(PermissionsFeature, "src/security_headers/permissions.rs")]
/// impl PermissionsPolicy {
///     // … your methods …
/// }
/// ```
#[proc_macro_attribute]
pub fn php_enum_constants(attr: TokenStream, item: TokenStream) -> TokenStream {
    // 1) Parse our attribute as a two‐element tuple: (EnumName, "path/to/file.rs")
    let expr = parse_macro_input!(attr as ExprTuple);
    let mut args = expr.elems.into_iter();

    // First arg: an identifier path
    let enum_ident = match args.next() {
        Some(Expr::Path(expr_path)) if expr_path.path.segments.len() == 1 => {
            expr_path.path.segments[0].ident.clone()
        }
        _ => panic!("first argument must be a bare enum identifier"),
    };

    // Second arg: a literal string
    let file_path = match args.next() {
        Some(Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        })) => s.value(),
        _ => panic!("second argument must be a string literal path"),
    };

    // 2) Parse the impl block we’re annotating
    let mut imp: ItemImpl = parse_macro_input!(item as ItemImpl);

    // 3) Read & parse the user‐supplied file
    let src = std::fs::read_to_string(&file_path)
        .unwrap_or_else(|_| panic!("couldn't read `{}`", file_path));
    let syntax =
        syn::parse_file(&src).unwrap_or_else(|_| panic!("failed to parse `{}`", file_path));

    // 4) Find the matching enum and build `#[php_const]` items
    let mut const_items = Vec::new();
    for item in syntax.items {
        if let syn::Item::Enum(ItemEnum {
            ident, variants, ..
        }) = item
        {
            if ident == enum_ident {
                for v in variants {
                    let v_ident = &v.ident;
                    let lit = v_ident.to_string().to_kebab_case();
                    const_items.push(quote! {
                        #[php_const]
                        const #v_ident: &'static str = #lit;
                    });
                }
                break;
            }
        }
    }

    // 5) Splice them into the start of the impl block
    let existing = std::mem::take(&mut imp.items);
    for ci in const_items {
        imp.items.push(syn::parse2(ci).unwrap());
    }
    imp.items.extend(existing);

    // 6) Return the modified impl
    TokenStream::from(quote! { #imp })
}
