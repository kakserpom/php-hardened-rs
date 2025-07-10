use ext_php_rs::zend::Function;
use ext_php_rs::{exception::PhpException, exception::PhpResult, php_class, php_impl};
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// All valid Referrer-Policy directives.
#[derive(EnumString, Display, Debug, Clone)]
#[strum(serialize_all = "kebab-case")]
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
    fn __construct(policy: Option<&str>) -> PhpResult<Self> {
        let directive = if let Some(s) = policy {
            ReferrerPolicyDirective::from_str(s)
                .map_err(|_| PhpException::from(format!("Invalid Referrer-Policy value: {s}")))?
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
    fn set_policy(&mut self, policy: &str) -> PhpResult<()> {
        let parsed = ReferrerPolicyDirective::from_str(policy).map_err(|_| {
            PhpException::from(format!("Invalid Referrer-Policy value: {policy}"))
        })?;
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
    fn send(&self) -> PhpResult<()> {
        Function::try_from_function("header")
            .ok_or_else(|| PhpException::from("Could not call header()"))?
            .try_call(vec![&format!("Referrer-Policy: {}", self.build())])?;
        Ok(())
    }
}
