use anyhow::{Result, anyhow};
#[cfg(not(test))]
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// All valid Referrer-Policy directives.
#[derive(EnumString, Display, Debug, Clone)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum ReferrerPolicyDirective {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

/// Referrer-Policy header builder.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\ReferrerPolicy")]
#[derive(Debug)]
pub struct ReferrerPolicy {
    policy: ReferrerPolicyDirective,
}

#[php_impl]
impl ReferrerPolicy {
    /// Constructs a new Referrer-Policy builder.
    ///
    /// # Parameters
    /// - `policy`: `?string` optional policy token to use instead of default `no-referrer`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if an invalid policy token is provided.
    fn __construct(policy: Option<String>) -> Result<Self> {
        let directive = if let Some(s) = policy {
            ReferrerPolicyDirective::from_str(s.as_str())
                .map_err(|_| anyhow!("Invalid Referrer-Policy value: {s}"))?
        } else {
            ReferrerPolicyDirective::NoReferrer
        };
        Ok(Self { policy: directive })
    }

    /// Set the Referrer-Policy directive.
    ///
    /// # Parameters
    /// - `policy`: `string` one of the valid policy tokens.
    ///
    /// # Exceptions
    /// - Throws `Exception` if an invalid policy token is provided.
    fn set_policy(&mut self, policy: &str) -> Result<()> {
        let parsed = ReferrerPolicyDirective::from_str(policy)
            .map_err(|_| anyhow!("Invalid Referrer-Policy value: {policy}"))?;
        self.policy = parsed;
        Ok(())
    }

    /// Get the current Referrer-Policy value.
    ///
    /// # Returns
    /// - `string` the active policy token.
    fn policy(&self) -> String {
        self.policy.to_string()
    }

    /// Build the `Referrer-Policy` header value.
    ///
    /// # Returns
    /// - `string` the configured policy value suitable for sending as a header.
    fn build(&self) -> String {
        self.policy.to_string()
    }

    /// Send the `Referrer-Policy` header via PHP `header()` function.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the PHP `header()` function cannot be invoked.
    fn send(&self) -> Result<()> {
        #[cfg(not(test))]
        {
            Function::try_from_function("header")
                .ok_or_else(|| anyhow!("Could not call header()"))?
                .try_call(vec![&format!("Referrer-Policy: {}", self.build())])
                .map_err(|_| anyhow!("Could not call header()"))?;
            Ok(())
        }
        #[cfg(test)]
        panic!("attribute_filter() can not be called from tests");
    }
}

#[cfg(test)]
mod tests {
    use super::ReferrerPolicy;
    use crate::run_php_example;

    #[test]
    fn test_default_policy() {
        let rp = ReferrerPolicy::__construct(None).unwrap();
        // Default should be no-referrer
        assert_eq!(rp.policy(), "no-referrer");
        assert_eq!(rp.build(), "no-referrer");
    }

    #[test]
    fn test_construct_with_valid_policy() {
        let rp = ReferrerPolicy::__construct(Some(String::from("origin"))).unwrap();
        assert_eq!(rp.policy(), "origin");
        assert_eq!(rp.build(), "origin");
    }

    #[test]
    fn test_construct_invalid_policy() {
        let err = ReferrerPolicy::__construct(Some(String::from("invalid-policy"))).unwrap_err();
        // Should be a PhpException with appropriate message
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid Referrer-Policy value"));
    }

    #[test]
    fn test_set_policy_valid() {
        let mut rp = ReferrerPolicy::__construct(None).unwrap();
        rp.set_policy("strict-origin-when-cross-origin").unwrap();
        assert_eq!(rp.policy(), "strict-origin-when-cross-origin");
        assert_eq!(rp.build(), "strict-origin-when-cross-origin");
    }

    #[test]
    fn test_set_policy_invalid() {
        let mut rp = ReferrerPolicy::__construct(None).unwrap();
        let err = rp.set_policy("not-a-policy").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid Referrer-Policy value"));
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/referrer-policy")?;
        Ok(())
    }
}
