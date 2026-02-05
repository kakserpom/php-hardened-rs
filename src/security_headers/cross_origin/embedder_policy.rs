use super::super::{Error as SecurityHeaderError, Result};
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_enum, php_impl};
use strum_macros::Display;

/// Allowed values for the `Cross-Origin-Embedder-Policy` header.
#[php_enum]
#[php(name = "Hardened\\SecurityHeaders\\CrossOrigin\\EmbedderPolicyValue")]
#[derive(Display, Debug, Clone, Copy, PartialEq, Eq)]
#[strum(serialize_all = "kebab-case")]
pub enum Policy {
    /// Allows the document to load cross-origin resources without giving explicit permission
    /// through CORS or `Cross-Origin-Resource-Policy`. This is the default.
    #[php(value = "unsafe-none")]
    UnsafeNone,

    /// Only same-origin or resources explicitly marked via `Cross-Origin-Resource-Policy`
    /// or CORS may be loaded.
    #[php(value = "require-corp")]
    RequireCorp,

    /// Similar to `require-corp`, but drops credentials on no-CORS requests.
    #[php(value = "credentialless")]
    Credentialless,
}

/// Builder for `Cross-Origin-Embedder-Policy` header.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\CrossOrigin\\EmbedderPolicy")]
pub struct EmbedderPolicy {
    policy: Policy,
}

#[php_impl]
impl EmbedderPolicy {
    /// Create a new Cross-Origin-Embedder-Policy (COEP) builder for PHP.
    ///
    /// By default, this sets the policy to `"unsafe-none"`, allowing all embedders.
    ///
    /// # Parameters
    /// - `policy`: Optional string directive. Valid values:
    ///   - `"unsafe-none"`    — no embedder restrictions.
    ///   - `"require-corp"`   — only embedders with valid CORP headers.
    ///   - `"credentialless"` — restrict resources and omit credentials.
    ///   If omitted, defaults to `"unsafe-none"`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if an invalid token is provided.
    fn __construct(policy: Option<Policy>) -> Self {
        Self {
            policy: policy.unwrap_or(Policy::UnsafeNone),
        }
    }

    /// Update the COEP directive.
    ///
    /// # Parameters
    /// - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
    ///
    /// # Exceptions
    /// - Throws an `Exception` if `policy` cannot be parsed into a valid directive.
    fn set(&mut self, policy: Policy) {
        self.policy = policy;
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
    fn build(&self) -> String {
        self.policy.to_string()
    }

    /// Send the `Cross-Origin-Embedder-Policy` header via PHP `header()`.
    ///
    /// # Errors
    /// - Throws `Exception` if the PHP `header()` function cannot be invoked.
    fn send(&self) -> Result<()> {
        Function::try_from_function("header")
            .ok_or(SecurityHeaderError::HeaderUnavailable)?
            .try_call(vec![&format!(
                "Cross-Origin-Embedder-Policy: {}",
                self.policy
            )])
            .map_err(|err| SecurityHeaderError::HeaderCallFailed(err.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EmbedderPolicy, Policy};
    use crate::run_php_example;

    #[test]
    fn default_policy_is_unsafe_none() {
        let coep = EmbedderPolicy::__construct(None);
        assert_eq!(coep.build(), "unsafe-none");
    }

    #[test]
    fn construct_with_valid_policies() {
        let coep1 = EmbedderPolicy::__construct(Some(Policy::RequireCorp));
        assert_eq!(coep1.build(), "require-corp");

        let coep2 = EmbedderPolicy::__construct(Some(Policy::Credentialless));
        assert_eq!(coep2.build(), "credentialless");

        let coep3 = EmbedderPolicy::__construct(Some(Policy::UnsafeNone));
        assert_eq!(coep3.build(), "unsafe-none");
    }

    #[test]
    fn set_updates_value() {
        let mut coep = EmbedderPolicy::__construct(None);
        coep.set(Policy::RequireCorp);
        assert_eq!(coep.build(), "require-corp");

        coep.set(Policy::Credentialless);
        assert_eq!(coep.build(), "credentialless");
    }

    #[test]
    fn underlying_enum_variants_are_correct() {
        // direct enum usage
        assert_eq!(Policy::UnsafeNone.to_string(), "unsafe-none");
        assert_eq!(Policy::RequireCorp.to_string(), "require-corp");
        assert_eq!(Policy::Credentialless.to_string(), "credentialless");
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("security-headers/cross-origin/embedder-policy")?;
        Ok(())
    }
}
