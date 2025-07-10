#[warn(clippy::pedantic)]
#[allow(clippy::used_underscore_items)]
mod csrf;
mod hostname;
mod html_sanitizer;
mod path;
mod rng;
mod security_headers;

use std::collections::HashSet;
use crate::csrf::Csrf;
pub use crate::hostname::Hostname;
use crate::html_sanitizer::HtmlSanitizer;
use crate::path::PathObj;
use crate::rng::Rng;
use crate::security_headers::cors::CorsPolicy;
use crate::security_headers::csp::ContentSecurityPolicy;
use crate::security_headers::hsts::Hsts;
use anyhow::{anyhow, Error};
use ext_php_rs::prelude::*;
use ext_php_rs::types::{ZendHashTable, Zval};

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
        .class::<Hostname>()
        .class::<PathObj>()
        .class::<HtmlSanitizer>()
        .class::<Rng>()
        .class::<Csrf>()
        .class::<ContentSecurityPolicy>()
        .class::<Hsts>()
        .class::<CorsPolicy>()
}

fn to_str(path: &Zval) -> Result<String, Error> {
    path.string()
        .ok_or_else(|| anyhow::anyhow!("String conversion failed"))
        .or_else(|_| {
            path.try_call_method("__toString", vec![])
                .map_err(|err| anyhow::anyhow!("{err}"))?
                .string()
                .ok_or_else(|| anyhow::anyhow!("String conversion failed"))
        })
}


fn arg_into_vec(arg: &ZendHashTable) -> PhpResult<Vec<&str>> {
    arg.values().try_fold(
        Vec::with_capacity(arg.len()),
        |mut vec, x| -> PhpResult<_> {
            vec.push(x.str().ok_or_else(|| anyhow!("not a string"))?);
            Ok(vec)
        },
    )
}
fn arg_into_hashset(arg: &ZendHashTable) -> PhpResult<HashSet<String>> {
    arg.values().try_fold(
        HashSet::with_capacity(arg.len()),
        |mut set, x| -> PhpResult<_> {
            set.insert(x.string().ok_or_else(|| anyhow!("not a string"))?);
            Ok(set)
        },
    )
}
