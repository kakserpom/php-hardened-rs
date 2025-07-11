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
use crate::security_headers::cross_origin::embedder_policy::EmbedderPolicy;
use crate::security_headers::cross_origin::opener_policy::OpenerPolicy;
use crate::security_headers::cross_origin::resource_sharing::ResourceSharing;
use crate::security_headers::csp::ContentSecurityPolicy;
use crate::security_headers::hsts::StrictTransportSecurity;
use crate::security_headers::whatnot::Whatnot;
use crate::security_headers::permissions::PermissionsPolicy;
use crate::security_headers::referrer_policy::ReferrerPolicy;
use anyhow::{Error, Result};
use ext_php_rs::prelude::*;
use ext_php_rs::types::Zval;
use crate::security_headers::cross_origin::resource_policy::ResourcePolicy;

#[php_module]
fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
        .class::<Hostname>()
        .class::<PathObj>()
        .class::<HtmlSanitizer>()
        .class::<Rng>()
        .class::<Csrf>()
        .class::<ContentSecurityPolicy>()
        .class::<StrictTransportSecurity>()
        .class::<Whatnot>()
        .class::<PermissionsPolicy>()
        .class::<ReferrerPolicy>()
        .class::<ResourceSharing>()
        .class::<EmbedderPolicy>()
        .class::<ResourcePolicy>()
        .class::<OpenerPolicy>()
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

    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|e| anyhow::anyhow!("env CARGO_MANIFEST_DIR: {}", e))?;
    let php_file = std::path::Path::new(&manifest)
        .join("examples")
        .join(format!("{name}.php"));

    // Spawn `php -f <script_name>`
    let output = Command::new("php")
        .arg("-f")
        .arg(&php_file)
        .output()
        .map_err(|err| anyhow!("Failed to execute php on {php_file:?}: {err}"))?;

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
            "PHP script {php_file:?} exited with code {}",
            output.status.code().unwrap_or(-1)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).parse()?)
}
