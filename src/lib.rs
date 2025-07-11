#[warn(clippy::pedantic)]
#[allow(clippy::used_underscore_items)]
mod csrf;
mod hostname;
mod path;
mod rng;
mod sanitizers;
mod security_headers;

use crate::csrf::Csrf;
pub use crate::hostname::Hostname;
use crate::path::PathObj;
use crate::rng::Rng;
use crate::sanitizers::html::HtmlSanitizer;
use crate::security_headers::cors::CorsPolicy;
use crate::security_headers::csp::ContentSecurityPolicy;
use crate::security_headers::hsts::Hsts;
use crate::security_headers::misc::MiscHeaders;
use crate::security_headers::permissions::PermissionsPolicy;
use crate::security_headers::referrer_policy::ReferrerPolicy;
use anyhow::{Error, Result};
use ext_php_rs::prelude::*;
use ext_php_rs::types::Zval;

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
        .class::<MiscHeaders>()
        .class::<PermissionsPolicy>()
        .class::<ReferrerPolicy>()
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

/// Runs the given PHP script via the `php` CLI and returns an error if it fails.
#[cfg(test)]
fn run_php_example(name: &str) -> Result<String> {
    use anyhow::{anyhow, bail};
    use std::process::Command;

    let script_name = format!("examples/{name}.php");

    // Spawn `php -f <script_name>`
    let output = Command::new("php")
        .arg("-f")
        .arg(&script_name)
        .output()
        .map_err(|err| anyhow!("Failed to execute php on `{script_name}`: {err}"))?;

    // Print PHP stdout for debugging
    println!(
        "--- PHP stdout ---\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // If PHP wrote to stderr, print that too
    if !output.stderr.is_empty() {
        eprintln!(
            "--- PHP stderr ---\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Check exit status
    if !output.status.success() {
        bail!(
            "PHP script `{}` exited with code {}",
            script_name,
            output.status.code().unwrap_or(-1)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).parse()?)
}
