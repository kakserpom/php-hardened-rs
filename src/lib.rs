#[warn(clippy::pedantic)]
#[allow(clippy::used_underscore_items)]
#[cfg(feature = "ct")]
pub mod constant_time;
pub mod csrf;
pub mod hostname;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "password")]
pub mod password;
pub mod path;
#[cfg(feature = "rate_limiter")]
pub mod rate_limiter;
#[cfg(feature = "redirect")]
pub mod redirect;
pub mod rng;
pub mod sanitizers;
pub mod security_headers;
pub mod shell_command;
#[cfg(feature = "ssrf")]
pub mod ssrf;
#[cfg(feature = "text")]
pub mod text;

#[cfg(feature = "ct")]
use crate::constant_time::ConstantTime;
use crate::csrf::Csrf;
pub use crate::hostname::Hostname;
#[cfg(feature = "jwt")]
use crate::jwt::JwtVerifier;
#[cfg(feature = "password")]
use crate::password::Password;
use crate::path::PathObj;
#[cfg(feature = "rate_limiter")]
use crate::rate_limiter::RateLimiter;
#[cfg(feature = "redirect")]
use crate::redirect::Redirect;
use crate::rng::Rng;
use crate::security_headers::cross_origin::embedder_policy::{
    EmbedderPolicy, Policy as EmbedderPolicyValue,
};
use crate::security_headers::cross_origin::opener_policy::OpenerPolicy;
use crate::security_headers::cross_origin::resource_policy::ResourcePolicy;
use crate::security_headers::cross_origin::resource_sharing::ResourceSharing;
use crate::security_headers::csp::{ContentSecurityPolicy, Keyword as CspKeyword, Rule as CspRule};
use crate::security_headers::hsts::StrictTransportSecurity;
use crate::security_headers::permissions::{
    Feature as PermissionsPolicyFeature, PermissionsPolicy,
};
use crate::security_headers::referrer_policy::ReferrerPolicy;
use crate::security_headers::whatnot::{
    FrameOptions, PermittedCrossDomainPolicies as CrossDomainPolicy, Whatnot, XssProtection,
};
#[cfg(feature = "ssrf")]
use crate::ssrf::SsrfGuard;
#[cfg(feature = "text")]
use crate::text::Text;
use ext_php_rs::prelude::*;
use ext_php_rs::types::Zval;
use thiserror::Error;

// Error codes for conversion errors: 1800-1899
mod conversion_error_codes {
    pub const STRING_FAILED: i32 = 1800;
    pub const TO_STRING_CALL_FAILED: i32 = 1801;
}

/// Errors for string/Zval conversion.
#[derive(Debug, Error)]
enum ConversionError {
    #[error("String conversion failed")]
    StringConversionFailed,

    #[error("__toString() call failed: {0}")]
    ToStringCallFailed(String),
}

impl ConversionError {
    #[must_use]
    fn code(&self) -> i32 {
        match self {
            ConversionError::StringConversionFailed => conversion_error_codes::STRING_FAILED,
            ConversionError::ToStringCallFailed(_) => conversion_error_codes::TO_STRING_CALL_FAILED,
        }
    }
}

impl From<ConversionError> for ext_php_rs::exception::PhpException {
    fn from(err: ConversionError) -> Self {
        let code = err.code();
        let message = err.to_string();
        ext_php_rs::exception::PhpException::new(message, code, ext_php_rs::zend::ce::exception())
    }
}
#[cfg(test)]
use std::path::{Path, PathBuf};

#[cfg(not(debug_assertions))]
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[php_module]
fn get_module(mut module: ModuleBuilder) -> ModuleBuilder {
    module = sanitizers::build(module);
    module = module.name("hardened").version(env!("CARGO_PKG_VERSION"));
    #[cfg(feature = "shell_command")]
    {
        module = shell_command::build(module);
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
    #[cfg(feature = "ct")]
    {
        module = module.class::<ConstantTime>();
    }
    #[cfg(feature = "text")]
    {
        module = module.class::<Text>();
    }
    #[cfg(feature = "redirect")]
    {
        module = module.class::<Redirect>();
    }
    #[cfg(feature = "ssrf")]
    {
        module = module.class::<SsrfGuard>();
    }
    #[cfg(feature = "password")]
    {
        module = module.class::<Password>();
    }
    #[cfg(feature = "rate_limiter")]
    {
        module = module.class::<RateLimiter>();
    }
    #[cfg(feature = "jwt")]
    {
        module = module.class::<JwtVerifier>();
    }
    #[cfg(feature = "headers")]
    {
        module = module.class::<ContentSecurityPolicy>();
        module = module.enumeration::<CspKeyword>();
        module = module.enumeration::<CspRule>();
        module = module.class::<StrictTransportSecurity>();
        module = module.class::<Whatnot>();
        module = module.enumeration::<FrameOptions>();
        module = module.enumeration::<XssProtection>();
        module = module.enumeration::<CrossDomainPolicy>();
        module = module.class::<PermissionsPolicy>();
        module = module.enumeration::<PermissionsPolicyFeature>();
        module = module.class::<ReferrerPolicy>();
        module = module.class::<ResourceSharing>();
        module = module.class::<EmbedderPolicy>();
        module = module.enumeration::<EmbedderPolicyValue>();
        module = module.class::<ResourcePolicy>();
        module = module.class::<OpenerPolicy>();
    }
    module
}

pub(crate) fn to_str(path: &Zval) -> Result<String, ConversionError> {
    path.string()
        .ok_or(ConversionError::StringConversionFailed)
        .or_else(|_| {
            path.try_call_method("__toString", vec![])
                .map_err(|err| ConversionError::ToStringCallFailed(err.to_string()))?
                .string()
                .ok_or(ConversionError::StringConversionFailed)
        })
}

/// Test result type alias using Box<dyn Error> for simplicity.
#[cfg(test)]
pub(crate) type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Runs the given PHP script via the `php` CLI and returns an error if it fails.
#[cfg(test)]
fn run_php_file(php_file: PathBuf) -> TestResult<String> {
    use std::process::Command;
    // Spawn `php -f <script_name>`
    let output = Command::new("php")
        .arg("-f")
        .arg(&php_file)
        .output()
        .map_err(|err| format!("Failed to execute php on {php_file:?}: {err}"))?;

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
        return Err(format!(
            "PHP script {php_file:?} exited with code {}",
            output.status.code().unwrap_or(-1)
        )
        .into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).parse()?)
}

#[cfg(test)]
pub(crate) fn run_php_example(name: &str) -> TestResult<String> {
    run_php_file(
        Path::new(&std::env::var("CARGO_MANIFEST_DIR")?).join(format!("examples/{name}.php")),
    )
}

#[cfg(test)]
pub(crate) fn run_php_test(name: &str) -> TestResult<String> {
    run_php_file(Path::new(&std::env::var("CARGO_MANIFEST_DIR")?).join(format!("tests/{name}.php")))
}
