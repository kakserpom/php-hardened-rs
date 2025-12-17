use super::{Error as SecurityHeaderError, Result};
#[cfg(not(test))]
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
use std::str::FromStr;
use strum_macros::{Display, EnumString};

#[derive(EnumString, Display, Debug, Clone)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
/// Represents the set of allowed values for the `Referrer-Policy` HTTP header,
/// which controls how much referrer information (the URL of the origin) is
/// included with requests made from a document.
///
/// See the Fetch specification for details:
/// https://fetch.spec.whatwg.org/#referrer-policy
pub enum ReferrerPolicyDirective {
    /// Do not send the `Referer` header with any requests.
    NoReferrer,

    /// Send the `Referer` header only when performing a same-protocol request;
    /// do not send it to less secure destinations (e.g., from HTTPS → HTTP).
    NoReferrerWhenDowngrade,

    /// Send only the origin (scheme, host, and port) as the referrer.
    Origin,

    /// Send the origin as referrer when the request is cross-origin;
    /// send the full URL when same-origin.
    OriginWhenCrossOrigin,

    /// Send the full URL as referrer for same-origin requests;
    /// omit it for cross-origin requests.
    SameOrigin,

    /// Send only the origin when navigating from HTTPS to other origins;
    /// otherwise send no referrer.
    StrictOrigin,

    /// Send only the origin for same-origin requests;
    /// send only the origin when navigating from HTTPS to other origins;
    /// send no referrer for less secure destinations.
    StrictOriginWhenCrossOrigin,

    /// Always send the full URL (including path and query) as the referrer,
    /// even for cross-origin requests.
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
    /// Create a new Referrer-Policy builder for PHP.
    ///
    /// By default, the referrer policy is set to `no-referrer`, which prevents
    /// the `Referer` header from being sent with any requests.
    ///
    /// # Parameters
    /// - `policy`: Optional string. If provided, must match one of these tokens:
    ///   - `"no-referrer"`                          — never send the `Referer` header.
    ///   - `"no-referrer-when-downgrade"`           — send full URL except when downgrading HTTPS→HTTP.
    ///   - `"origin"`                               — send only the origin (`scheme://host[:port]`).
    ///   - `"origin-when-cross-origin"`             — send full URL same-origin; origin for cross-origin.
    ///   - `"same-origin"`                          — send full URL only for same-origin; omit for cross-origin.
    ///   - `"strict-origin"`                        — send origin except on HTTPS→HTTP downgrade (omit then).
    ///   - `"strict-origin-when-cross-origin"`      — full URL same-origin; origin cross-origin non-downgrade; omit on downgrade.
    ///   - `"unsafe-url"`                           — always send full URL, regardless of context.
    ///
    /// # Exceptions
    /// - Throws `Exception` if `policy` is not a recognized directive.
    fn __construct(policy: Option<String>) -> Result<Self> {
        let directive = if let Some(s) = policy {
            ReferrerPolicyDirective::from_str(s.as_str())
                .map_err(|_| SecurityHeaderError::InvalidValue { header_type: "Referrer-Policy".into(), value: s })?
        } else {
            ReferrerPolicyDirective::NoReferrer
        };
        Ok(Self { policy: directive })
    }

    /// Update the active Referrer-Policy directive.
    ///
    /// # Parameters
    /// - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the provided token is invalid.
    fn set(&mut self, policy: &str) -> Result<()> {
        let parsed = ReferrerPolicyDirective::from_str(policy)
            .map_err(|_| SecurityHeaderError::InvalidValue { header_type: "Referrer-Policy".into(), value: policy.to_string() })?;
        self.policy = parsed;
        Ok(())
    }

    /// Get the current Referrer-Policy value.
    ///
    /// # Returns
    /// - `string` the active policy token.
    fn get(&self) -> String {
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
                .ok_or(SecurityHeaderError::HeaderUnavailable)?
                .try_call(vec![&format!("Referrer-Policy: {}", self.build())])
                .map_err(|err| SecurityHeaderError::HeaderCallFailed(format!("{err:?}")))?;
            Ok(())
        }
        #[cfg(test)]
        panic!("send() can not be called from tests");
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
        assert_eq!(rp.get(), "no-referrer");
        assert_eq!(rp.build(), "no-referrer");
    }

    #[test]
    fn test_construct_with_valid_policy() {
        let rp = ReferrerPolicy::__construct(Some(String::from("origin"))).unwrap();
        assert_eq!(rp.get(), "origin");
        assert_eq!(rp.build(), "origin");
    }

    #[test]
    fn test_construct_invalid_policy() {
        let err = ReferrerPolicy::__construct(Some(String::from("invalid-policy"))).unwrap_err();
        // Should be an Exception with appropriate message
        let msg = format!("{err}");
        assert!(msg.contains("Invalid"));
    }

    #[test]
    fn test_set_policy_valid() {
        let mut rp = ReferrerPolicy::__construct(None).unwrap();
        rp.set("strict-origin-when-cross-origin").unwrap();
        assert_eq!(rp.get(), "strict-origin-when-cross-origin");
        assert_eq!(rp.build(), "strict-origin-when-cross-origin");
    }

    #[test]
    fn test_set_policy_invalid() {
        let mut rp = ReferrerPolicy::__construct(None).unwrap();
        let err = rp.set("not-a-policy").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Invalid"));
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("security-headers/referrer-policy")?;
        Ok(())
    }
}
