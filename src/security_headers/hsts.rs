use ext_php_rs::zend::Function;
use ext_php_rs::{exception::PhpResult, php_class, php_impl};

/// HTTP Strict Transport Security (HSTS) header builder.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\Hsts")]
pub struct Hsts {
    max_age: u64,
    include_subdomains: bool,
    preload: bool,
}

#[php_impl]
impl Hsts {
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
    fn send(&self) -> PhpResult<()> {
        Function::try_from_function("header")
            .ok_or_else(|| anyhow::anyhow!("Could not call header()"))?
            .try_call(vec![&format!(
                "Strict-Transport-Security: {}",
                self.build()
            )])?;
        Ok(())
    }
}
