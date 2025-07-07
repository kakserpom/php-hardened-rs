#[warn(clippy::pedantic)]
mod hostname;
mod path;

use anyhow::Error;
pub use crate::hostname::Hostname;
use crate::path::PathObj;
use ext_php_rs::prelude::*;
use ext_php_rs::types::Zval;

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module.class::<Hostname>().class::<PathObj>()
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