mod html_sanitizer;
#[warn(clippy::pedantic)]
mod hostname;
mod path;

use crate::html_sanitizer::HtmlSanitizer;
pub use crate::hostname::Hostname;
use crate::path::PathObj;
use anyhow::Error;
use ext_php_rs::prelude::*;
use ext_php_rs::types::Zval;

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
        .class::<Hostname>()
        .class::<PathObj>()
        .class::<HtmlSanitizer>()
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
