use anyhow::anyhow;
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// Allowed values for Cross-Origin-Opener-Policy.
#[derive(EnumString, Display, Debug, Clone, Copy)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum Policy {
    /// No special opener isolation; backwards-compatible default.
    UnsafeNone,

    /// Isolate the browsing context: only same-origin windows share a global object.
    SameOrigin,

    /// Like `same-origin` but allows popups to keep the connection.
    #[strum(serialize = "same-origin-allow-popups")]
    SameOriginAllowPopups,
}

/// Builder for `Cross-Origin-Opener-Policy` header.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\CrossOrigin\\OpenerPolicy")]
pub struct OpenerPolicy {
    policy: Policy,
}

#[php_impl]
impl OpenerPolicy {
    /// Create a new Cross-Origin-Opener-Policy builder.
    ///
    /// By default, this sets the policy to `"unsafe-none"`, which imposes
    /// no special opener isolation. PHP users can call this without arguments
    /// to get the default behavior.
    ///
    /// # Parameters
    /// - `policy`: Optional string directive. If provided, must be one of:
    ///   - `"unsafe-none"` — no isolation; pages can share a browsing context.
    ///   - `"same-origin"` — only pages from the same origin can share.
    ///   - `"same-origin-allow-popups"` — same-origin pages and their popups.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the provided token is not one of the allowed values.
    pub fn __construct(policy: Option<String>) -> anyhow::Result<Self> {
        let policy = if let Some(p) = policy {
            Policy::from_str(&p)
                .map_err(|_| anyhow!("Invalid Cross-Origin-Opener-Policy value: {}", p))?
        } else {
            Policy::UnsafeNone
        };
        Ok(Self { policy })
    }

    /// Use this if you need to change the policy after construction.
    /// Calling this method will override any previous setting.
    ///
    /// # Parameters
    /// - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the given token is invalid.
    pub fn set(&mut self, policy: &str) -> anyhow::Result<()> {
        self.policy = Policy::from_str(policy)
            .map_err(|_| anyhow!("Invalid Cross-Origin-Opener-Policy value: {}", policy))?;
        Ok(())
    }

    /// Build the header value.
    ///
    /// # Returns
    /// - `string` the configured policy, e.g. `"same-origin"`.
    pub fn build(&self) -> String {
        self.policy.to_string()
    }

    /// Send the `Cross-Origin-Opener-Policy` header via PHP `header()`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the PHP `header()` function cannot be invoked.
    pub fn send(&self) -> anyhow::Result<()> {
        Function::try_from_function("header")
            .ok_or_else(|| anyhow!("Could not call header()"))?
            .try_call(vec![&format!(
                "Cross-Origin-Opener-Policy: {}",
                self.build()
            )])
            .map_err(|e| anyhow!("Could not call header(): {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::OpenerPolicy;
    use crate::run_php_example;
    use anyhow::Result;

    #[test]
    fn default_is_unsafe_none() -> Result<()> {
        let c = OpenerPolicy::__construct(None)?;
        assert_eq!(c.build(), "unsafe-none");
        Ok(())
    }

    #[test]
    fn can_set_each_policy() -> Result<()> {
        let mut c = OpenerPolicy::__construct(None)?;
        c.set("same-origin")?;
        assert_eq!(c.build(), "same-origin");

        c.set("same-origin-allow-popups")?;
        assert_eq!(c.build(), "same-origin-allow-popups");

        c.set("unsafe-none")?;
        assert_eq!(c.build(), "unsafe-none");
        Ok(())
    }

    #[test]
    fn invalid_policy_errors() {
        assert!(OpenerPolicy::__construct(Some("foo-bar".into())).is_err());
        let mut c = OpenerPolicy::__construct(None).unwrap();
        assert!(c.set("invalid").is_err());
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/cross-origin/opener-policy")?;
        Ok(())
    }
}
