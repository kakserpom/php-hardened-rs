use anyhow::anyhow;
use ext_php_rs::php_const;
#[cfg(not(test))]
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
use php_hardened_macro::php_enum_constants;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// Allowed values for the `Cross-Origin-Embedder-Policy` header.
#[derive(EnumString, Display, Debug, Clone, Copy)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum Policy {
    /// Allows the document to load cross-origin resources without giving explicit permission
    /// through CORS or `Cross-Origin-Resource-Policy`. This is the default.
    UnsafeNone,

    /// Only same-origin or resources explicitly marked via `Cross-Origin-Resource-Policy`
    /// or CORS may be loaded.
    RequireCorp,

    /// Similar to `require-corp`, but drops credentials on no-CORS requests.
    Credentialless,
}

/// Builder for `Cross-Origin-Embedder-Policy` header.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\CrossOrigin\\EmbedderPolicy")]
pub struct EmbedderPolicy {
    policy: Policy,
}

#[php_enum_constants((Policy, "src/security_headers/cross_origin/embedder_policy.rs"))]
#[php_impl]
impl EmbedderPolicy {
    /// Constructs a new COEP builder.
    ///
    /// # Parameters
    /// - `policy`: `?string` one of `"unsafe-none"`, `"require-corp"` or `"credentialless"`.
    ///   If omitted, defaults to `"unsafe-none"`.
    ///
    /// # Errors
    /// - Throws `Exception` if `policy` is invalid.
    pub fn __construct(policy: Option<String>) -> anyhow::Result<Self> {
        Ok(Self {
            policy: if let Some(p) = policy {
                Policy::from_str(&p)
                    .map_err(|_| anyhow!("Invalid Cross-Origin-Embedder-Policy value: {p}"))?
            } else {
                Policy::UnsafeNone
            },
        })
    }

    /// Change the COEP policy.
    ///
    /// # Parameters
    /// - `policy`: `string` one of `"unsafe-none"`, `"require-corp"`, or `"credentialless"`.
    ///
    /// # Errors
    /// - Throws `Exception` if `policy` is not recognized.
    pub fn set(&mut self, policy: &str) -> anyhow::Result<()> {
        self.policy = Policy::from_str(policy)
            .map_err(|_| anyhow!("Invalid Cross-Origin-Embedder-Policy value: {policy}"))?;
        Ok(())
    }

    /// Get the current Embedder-Policy value.
    ///
    /// # Returns
    /// - `string` the active policy token.
    fn get(&self) -> String {
        self.policy.to_string()
    }


    /// Render the header value.
    ///
    /// # Returns
    /// - `string`: the currently configured policy token.
    pub fn build(&self) -> String {
        self.policy.to_string()
    }

    /// Send the `Cross-Origin-Embedder-Policy` header via PHP `header()`.
    ///
    /// # Errors
    /// - Throws `Exception` if the PHP `header()` function cannot be invoked.
    fn send(&self) -> anyhow::Result<()> {
        #[cfg(not(test))]
        {
            Function::try_from_function("header")
                .ok_or_else(|| anyhow!("Could not call header()"))?
                .try_call(vec![&format!(
                    "Cross-Origin-Embedder-Policy: {}",
                    self.policy
                )])
                .map_err(|err| anyhow!("header() call failed: {err}"))?;
            Ok(())
        }
        #[cfg(test)]
        panic!("send() can not be called from tests");
    }
}

#[cfg(test)]
mod tests {
    use super::{EmbedderPolicy, Policy};
    use crate::run_php_example;

    #[test]
    fn default_policy_is_unsafe_none() {
        let coep = EmbedderPolicy::__construct(None).unwrap();
        assert_eq!(coep.build(), "unsafe-none");
    }

    #[test]
    fn construct_with_valid_policies() {
        let coep1 = EmbedderPolicy::__construct(Some("require-corp".into())).unwrap();
        assert_eq!(coep1.build(), "require-corp");

        let coep2 = EmbedderPolicy::__construct(Some("credentialless".into())).unwrap();
        assert_eq!(coep2.build(), "credentialless");

        // Case‐insensitive
        let coep3 = EmbedderPolicy::__construct(Some("Require-Corp".into())).unwrap();
        assert_eq!(coep3.build(), "require-corp");
    }

    #[test]
    fn construct_with_invalid_policy_errors() {
        let err = EmbedderPolicy::__construct(Some("invalid-token".into()));
        assert!(err.is_err());
    }

    #[test]
    fn set_updates_value() {
        let mut coep = EmbedderPolicy::__construct(None).unwrap();
        coep.set("require-corp").unwrap();
        assert_eq!(coep.build(), "require-corp");

        coep.set("credentialless").unwrap();
        assert_eq!(coep.build(), "credentialless");
    }

    #[test]
    fn set_invalid_token_errors() {
        let mut coep = EmbedderPolicy::__construct(None).unwrap();
        let err = coep.set("no-such-policy");
        assert!(err.is_err());
    }

    #[test]
    fn underlying_enum_variants_are_correct() {
        // direct enum usage
        assert_eq!(Policy::UnsafeNone.to_string(), "unsafe-none");
        assert_eq!(Policy::RequireCorp.to_string(), "require-corp");
        assert_eq!(Policy::Credentialless.to_string(), "credentialless");
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/cross-origin/embedder-policy")?;
        Ok(())
    }
}
