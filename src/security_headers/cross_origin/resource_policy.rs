use anyhow::{Result, anyhow};
#[cfg(not(test))]
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// All valid Cross-Origin-Resource-Policy directives.
#[derive(EnumString, Display, Debug, Clone, Copy)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum ResourcePolicyDirective {
    /// Only same-origin resources may be loaded.
    SameOrigin,

    /// Same-site resources and same-origin resources may be loaded.
    SameSite,

    /// Any resource may be loaded, including cross-origin.
    CrossOrigin,
}

/// Builder for the `Cross-Origin-Resource-Policy` header.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\CrossOrigin\\ResourcePolicy")]
pub struct ResourcePolicy {
    policy: ResourcePolicyDirective,
}

#[php_impl]
impl ResourcePolicy {
    /// Create a new Cross-Origin-Resource-Policy builder.
    ///
    /// By default, the policy is set to `same-origin`, which restricts
    /// resource sharing to the same origin that served the document.
    ///
    /// # Parameters
    /// - `policy`: Optional directive string. If provided, must be one of:
    ///   - `"same-origin"` — only same-origin requests allowed.
    ///   - `"same-site"`   — allow same-site requests (including subdomains).
    ///   - `"cross-origin"` — allow all cross-site requests.
    ///
    /// # Exceptions
    /// - Throws an `Exception` if `policy` cannot be parsed into a valid directive.
    fn __construct(policy: Option<String>) -> Result<Self> {
        let directive = if let Some(s) = policy {
            ResourcePolicyDirective::from_str(&s)
                .map_err(|_| anyhow!("Invalid Cross-Origin-Resource-Policy value: {}", s))?
        } else {
            ResourcePolicyDirective::SameOrigin
        };
        Ok(Self { policy: directive })
    }

    /// Change the active Cross-Origin-Resource-Policy directive.
    ///
    /// This will override any previous setting or the default.
    ///
    /// # Parameters
    /// - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
    ///
    /// # Exceptions
    /// - Throws an `Exception` if `policy` cannot be parsed into a valid directive.
    fn set(&mut self, policy: &str) -> Result<()> {
        self.policy = ResourcePolicyDirective::from_str(policy)
            .map_err(|_| anyhow!("Invalid Cross-Origin-Resource-Policy value: {}", policy))?;
        Ok(())
    }

    /// Get the current Resource-Policy value.
    ///
    /// # Returns
    /// - `string` the active policy token.
    fn get(&self) -> String {
        self.policy.to_string()
    }

    /// Build the header value.
    ///
    /// # Returns
    /// - `string` the configured directive token.
    fn build(&self) -> String {
        self.policy.to_string()
    }

    /// Send the `Cross-Origin-Resource-Policy` header via PHP `header()`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the PHP `header()` function cannot be invoked.
    fn send(&self) -> Result<()> {
        #[cfg(not(test))]
        {
            Function::try_from_function("header")
                .ok_or_else(|| anyhow!("Could not call header()"))?
                .try_call(vec![&format!(
                    "Cross-Origin-Resource-Policy: {}",
                    self.build()
                )])
                .map_err(|_| anyhow!("Could not call header()"))?;
            Ok(())
        }
        #[cfg(test)]
        panic!("send() can not be called from tests");
    }
}
#[cfg(test)]
mod tests {
    use super::ResourcePolicy;
    use crate::run_php_example;

    #[test]
    fn test_default_policy() {
        // Default should be "same-origin"
        let rp = ResourcePolicy::__construct(None).unwrap();
        assert_eq!(rp.build(), "same-origin");
    }

    #[test]
    fn test_set_valid_policies() {
        let mut rp = ResourcePolicy::__construct(None).unwrap();

        rp.set("same-site").unwrap();
        assert_eq!(rp.build(), "same-site");

        rp.set("cross-origin").unwrap();
        assert_eq!(rp.build(), "cross-origin");

        // case‐insensitive
        rp.set("SaMe-OrIgIn").unwrap();
        assert_eq!(rp.build(), "same-origin");
    }

    #[test]
    fn test_set_invalid_policy() {
        // Invalid tokens should return an error
        assert!(ResourcePolicy::__construct(Some("not-a-policy".into())).is_err());

        let mut rp = ResourcePolicy::__construct(None).unwrap();
        assert!(rp.set("bogus").is_err());
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/cross-origin/resource-policy")?;
        Ok(())
    }
}
