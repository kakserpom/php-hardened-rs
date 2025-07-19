#[warn(clippy::pedantic)]
#[allow(clippy::used_underscore_items)]
mod csrf;
mod hostname;
mod path;
mod rng;
mod sanitizers;
mod security_headers;
mod shell_command;

use crate::csrf::Csrf;
pub use crate::hostname::Hostname;
use crate::path::PathObj;
use crate::rng::Rng;
use crate::sanitizers::html::HtmlSanitizer;
use crate::security_headers::cross_origin::embedder_policy::EmbedderPolicy;
use crate::security_headers::cross_origin::opener_policy::OpenerPolicy;
use crate::security_headers::cross_origin::resource_policy::ResourcePolicy;
use crate::security_headers::cross_origin::resource_sharing::ResourceSharing;
use crate::security_headers::csp::ContentSecurityPolicy;
use crate::security_headers::hsts::StrictTransportSecurity;
use crate::security_headers::permissions::PermissionsPolicy;
use crate::security_headers::referrer_policy::ReferrerPolicy;
use crate::security_headers::whatnot::Whatnot;
use anyhow::{Error, Result};
use ext_php_rs::prelude::*;
use ext_php_rs::types::Zval;
#[cfg(test)]
use std::path::{Path, PathBuf};

#[cfg(not(debug_assertions))]
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[php_module]
fn get_module(mut module: ModuleBuilder) -> ModuleBuilder {
    #[cfg(feature = "shell_command")]
    {
        module = shell_command::build(module);
    }
    #[cfg(feature = "html_sanitizer")]
    {
        module = module.class::<HtmlSanitizer>();
    }
    #[cfg(feature = "hostname")]
    {
        module = module.class::<Hostname>();
    }
    #[cfg(feature = "path")]
    {
        module = module.class::<PathObj>();
    }
    #[cfg(feature = "rng")]
    {
        module = module.class::<Rng>();
    }
    #[cfg(feature = "csrf")]
    {
        module = module.class::<Csrf>();
    }
    #[cfg(feature = "headers")]
    {
        module = module.class::<ContentSecurityPolicy>();
        module = module.class::<StrictTransportSecurity>();
        module = module.class::<Whatnot>();
        module = module.class::<PermissionsPolicy>();
        module = module.class::<ReferrerPolicy>();
        module = module.class::<ResourceSharing>();
        module = module.class::<EmbedderPolicy>();
        module = module.class::<ResourcePolicy>();
        module = module.class::<OpenerPolicy>();
    }
    module
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
fn run_php_file(php_file: PathBuf) -> Result<String> {
    use anyhow::{anyhow, bail};
    use std::process::Command;
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
#[cfg(test)]
fn run_php_example(name: &str) -> Result<String> {
    run_php_file(
        Path::new(
            &std::env::var("CARGO_MANIFEST_DIR")
                .map_err(|e| anyhow::anyhow!("env CARGO_MANIFEST_DIR: {}", e))?,
        )
        .join(format!("examples/{name}.php")),
    )
}

#[cfg(test)]
fn run_php_test(name: &str) -> Result<String> {
    run_php_file(
        Path::new(
            &std::env::var("CARGO_MANIFEST_DIR")
                .map_err(|e| anyhow::anyhow!("env CARGO_MANIFEST_DIR: {}", e))?,
        )
        .join(format!("tests/{name}.php")),
    )
}
