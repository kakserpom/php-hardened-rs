use super::Result;
#[cfg(not(test))]
use super::Error as SecurityHeaderError;
#[cfg(not(test))]
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
/// HTTP Strict Transport Security (HSTS) header builder.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\StrictTransportSecurity")]
pub struct StrictTransportSecurity {
    max_age: u64,
    include_subdomains: bool,
    preload: bool,
}

#[php_impl]
impl StrictTransportSecurity {
    /// Constructs a new HSTS builder with default settings.
    ///
    /// # Returns
    /// - `Hsts` New instance with `max-age=0`, no subdomains, no preload.
    fn __construct() -> Self {
        Self {
            max_age: 0,
            include_subdomains: false,
            preload: false,
        }
    }

    /// Sets the `max-age` directive (in seconds).
    ///
    /// # Parameters
    /// - `maxAge`: `int` number of seconds for `max-age`.
    ///
    /// # Returns
    /// - `void`
    fn max_age(&mut self, max_age: u64) {
        self.max_age = max_age;
    }

    /// Enable or disable the `includeSubDomains` flag.
    ///
    /// # Parameters
    /// - `enable`: `bool` `true` to include subdomains, `false` to omit.
    ///
    /// # Returns
    /// - `void`
    fn include_sub_domains(&mut self, enable: bool) {
        self.include_subdomains = enable;
    }

    /// Enable or disable the `preload` flag.
    ///
    /// # Parameters
    /// - `enable`: `bool` `true` to add `preload`, `false` to omit.
    ///
    /// # Returns
    /// - `void`
    fn preload(&mut self, enable: bool) {
        self.preload = enable;
    }

    /// Builds the `Strict-Transport-Security` header value.
    ///
    /// # Returns
    /// - `string` e.g. `"max-age=31536000; includeSubDomains; preload"`.
    fn build(&self) -> String {
        let mut header = format!("max-age={}", self.max_age);
        if self.include_subdomains {
            header.push_str("; includeSubDomains");
        }
        if self.preload {
            header.push_str("; preload");
        }
        header
    }

    /// Sends the `Strict-Transport-Security` header via PHP `header()` function.
    ///
    /// # Exceptions
    /// - Throws `Exception` if PHP `header()` cannot be invoked.
    fn send(&self) -> Result<()> {
        #[cfg(not(test))]
        {
            Function::try_from_function("header")
                .ok_or(SecurityHeaderError::HeaderUnavailable)?
                .try_call(vec![&format!(
                    "Strict-Transport-Security: {}",
                    self.build()
                )])
                .map_err(|err| SecurityHeaderError::HeaderCallFailed(format!("{err:?}")))?;

            Ok(())
        }
        #[cfg(test)]
        panic!("send() can not be called from tests");
    }
}

#[cfg(test)]
mod tests {
    use super::StrictTransportSecurity;
    use crate::run_php_example;

    #[test]
    fn test_default_build() {
        let h = StrictTransportSecurity::__construct();
        assert_eq!(h.build(), "max-age=0");
    }

    #[test]
    fn test_max_age_only() {
        let mut h = StrictTransportSecurity::__construct();
        h.max_age(31536000);
        assert_eq!(h.build(), "max-age=31536000");
    }

    #[test]
    fn test_include_subdomains_only() {
        let mut h = StrictTransportSecurity::__construct();
        h.include_sub_domains(true);
        assert_eq!(h.build(), "max-age=0; includeSubDomains");
    }

    #[test]
    fn test_preload_only() {
        let mut h = StrictTransportSecurity::__construct();
        h.preload(true);
        assert_eq!(h.build(), "max-age=0; preload");
    }

    #[test]
    fn test_full_directives() {
        let mut h = StrictTransportSecurity::__construct();
        h.max_age(86400);
        h.include_sub_domains(true);
        h.preload(true);
        assert_eq!(h.build(), "max-age=86400; includeSubDomains; preload");
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/strict-transport-security")?;
        Ok(())
    }
}
