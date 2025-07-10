use anyhow::anyhow;
use ext_php_rs::zend::Function;
use ext_php_rs::{exception::PhpResult, php_class, php_impl};
use std::collections::HashMap;

/// CORS policy builder for HTTP responses.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\CorsPolicy")]
pub struct CorsPolicy {
    allow_origins: Vec<String>,
    allow_methods: Vec<String>,
    allow_headers: Vec<String>,
    allow_credentials: bool,
    expose_headers: Vec<String>,
    max_age: u64,
}

#[php_impl]
impl CorsPolicy {
    /// Constructs a new CORS policy with default settings (no restrictions).
    ///
    /// # Returns
    /// - `CorsPolicy` instance where all lists are empty and flags are false/zero.
    fn __construct() -> Self {
        Self {
            allow_origins: Vec::new(),
            allow_methods: Vec::new(),
            allow_headers: Vec::new(),
            allow_credentials: false,
            expose_headers: Vec::new(),
            max_age: 0,
        }
    }

    /// Set the `Access-Control-Allow-Origin` header values.
    ///
    /// # Parameters
    /// - `origins`: `string[]` list of allowed origins, or `['*']` for wildcard.
    ///
    /// # Returns
    /// - `void`
    fn allow_origins(&mut self, origins: Vec<String>) {
        self.allow_origins = origins;
    }

    /// Set the `Access-Control-Allow-Methods` header values.
    ///
    /// # Parameters
    /// - `methods`: `string[]` list of allowed HTTP methods (e.g. `['GET','POST']`).
    ///
    /// # Returns
    /// - `void`
    fn allow_methods(&mut self, methods: Vec<String>) {
        self.allow_methods = methods;
    }

    /// Set the `Access-Control-Allow-Headers` header values.
    ///
    /// # Parameters
    /// - `headers`: `string[]` list of allowed request headers (e.g. `['Content-Type']`).
    ///
    /// # Returns
    /// - `void`
    fn allow_headers(&mut self, headers: Vec<String>) {
        self.allow_headers = headers;
    }

    /// Enable or disable the `Access-Control-Allow-Credentials` flag.
    ///
    /// # Parameters
    /// - `enable`: `bool` `true` to allow credentials, `false` to omit header.
    ///
    /// # Returns
    /// - `void`
    fn allow_credentials(&mut self, enable: bool) {
        self.allow_credentials = enable;
    }

    /// Set the `Access-Control-Expose-Headers` header values.
    ///
    /// # Parameters
    /// - `headers`: `string[]` list of response headers that can be exposed to browser.
    ///
    /// # Returns
    /// - `void`
    fn expose_headers(&mut self, headers: Vec<String>) {
        self.expose_headers = headers;
    }

    /// Set the `Access-Control-Max-Age` directive (in seconds).
    ///
    /// # Parameters
    /// - `seconds`: `int` number of seconds the preflight response may be cached.
    ///
    /// # Returns
    /// - `void`
    fn max_age(&mut self, seconds: u64) {
        self.max_age = seconds;
    }

    /// Build an associative array of CORS headers and their values.
    ///
    /// # Returns
    /// - `array<string,string>` Map of header names to header values.
    fn build(&self) -> HashMap<&'static str, String> {
        let mut headers = HashMap::new();

        if !self.allow_origins.is_empty() {
            headers.insert("Access-Control-Allow-Origin", self.allow_origins.join(", "));
        }
        if !self.allow_methods.is_empty() {
            headers.insert(
                "Access-Control-Allow-Methods",
                self.allow_methods.join(", "),
            );
        }
        if !self.allow_headers.is_empty() {
            headers.insert(
                "Access-Control-Allow-Headers",
                self.allow_headers.join(", "),
            );
        }
        if self.allow_credentials {
            headers.insert("Access-Control-Allow-Credentials", "true".into());
        }
        if !self.expose_headers.is_empty() {
            headers.insert(
                "Access-Control-Expose-Headers",
                self.expose_headers.join(", "),
            );
        }
        if self.max_age > 0 {
            headers.insert("Access-Control-Max-Age", self.max_age.to_string());
        }

        headers
    }

    /// Send all configured CORS headers via PHP's `header()` function.
    ///
    /// # Returns
    /// - `void`
    ///
    /// # Exceptions
    /// - Throws `Exception` if PHP `header()` cannot be invoked.
    fn send(&self) -> PhpResult<()> {
        let header_fn = Function::try_from_function("header")
            .ok_or_else(|| anyhow!("Could not call header()"))?;
        for (name, value) in self.build() {
            let hdr = format!("{name}: {value}");
            header_fn.try_call(vec![&hdr])?;
        }
        Ok(())
    }
}
