use anyhow::{Result, anyhow};
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_const, php_impl};
use std::collections::HashMap;

/// CORS policy builder for HTTP responses.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\CrossOrigin\\ResourceSharing")]
pub struct ResourceSharing {
    allow_origins: Vec<String>,
    allow_methods: Vec<String>,
    allow_headers: Vec<String>,
    allow_credentials: bool,
    expose_headers: Vec<String>,
    max_age: u64,
}

#[php_impl]
impl ResourceSharing {
    #[php_const]
    const SELF: &str = "self";

    /// Constructs a new CORS policy with default settings (no restrictions).
    ///
    /// # Returns
    /// - `ResourceSharing` instance where all lists are empty and flags are false/zero.
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

    /// Specify which origins are allowed to access the resource.
    ///
    /// Browsers will only allow cross-origin requests if the request’s
    /// `Origin` header matches one of these values. Use `["*"]` to allow
    /// any origin (note: this will disable credentials).
    ///
    /// # Parameters
    /// - `origins`: A list of allowed origin URLs (e.g. `["https://example.com"]`),
    ///   or `["*"]` for a wildcard that permits all origins.
    ///
    /// # Behavior
    /// - If the request’s `Origin` header is not in this list, the browser
    ///   will block the response.
    ///
    /// # Returns
    /// - `void`
    fn allow_origins(&mut self, origins: Vec<String>) {
        self.allow_origins = origins;
    }

    /// Specify which HTTP methods may be used in cross-origin requests.
    ///
    /// During a CORS preflight (`OPTIONS`) request, the browser checks
    /// this list to determine whether to allow the actual request method.
    ///
    /// # Parameters
    /// - `methods`: A list of allowed HTTP methods (e.g. `["GET", "POST", "PUT"]`).
    ///
    /// # Behavior
    /// - Methods not in this list will cause the browser to block the
    ///   corresponding cross-origin request.
    ///
    /// # Returns
    /// - `void`
    fn allow_methods(&mut self, methods: Vec<String>) {
        self.allow_methods = methods;
    }

    /// Specify which custom headers the client may include in the request.
    ///
    /// Browsers enforce that only simple headers are sent by default; to
    /// allow additional headers (e.g. `Content-Type`, `X-Custom-Header`),
    /// they must be listed here.
    ///
    /// # Parameters
    /// - `headers`: A list of allowed request header names.
    ///
    /// # Behavior
    /// - Any request header not in this list will be stripped by the browser.
    ///
    /// # Returns
    /// - `void`
    fn allow_headers(&mut self, headers: Vec<String>) {
        self.allow_headers = headers;
    }

    /// Control whether cookies or HTTP authentication information are
    /// included in cross-origin requests.
    ///
    /// # Parameters
    /// - `enable`: `true` to send credentials (cookies, HTTP auth), `false`
    ///   to omit the `Access-Control-Allow-Credentials` header.
    ///
    /// # Behavior
    /// - If enabled, you **cannot** use `"*"` for `allow_origins`.
    ///
    /// # Returns
    /// - `void`
    fn allow_credentials(&mut self, enable: bool) {
        self.allow_credentials = enable;
    }

    /// Specify which response headers can be accessed by client-side scripts.
    ///
    /// By default, browsers only expose a limited set of safe headers.
    /// To expose additional headers (e.g. `X-RateLimit-Remaining`),
    /// list them here.
    ///
    /// # Parameters
    /// - `headers`: A list of response header names that should be
    ///   made available to JavaScript via `XMLHttpRequest` or `fetch`.
    ///
    /// # Returns
    /// - `void`
    fn expose_headers(&mut self, headers: Vec<String>) {
        self.expose_headers = headers;
    }

    /// Set how long (in seconds) the results of a preflight request can
    /// be cached by the browser.
    ///
    /// A higher value reduces the number of CORS preflight requests,
    /// improving performance. A value of `0` forces the browser to
    /// perform a preflight check on every request.
    ///
    /// # Parameters
    /// - `seconds`: Number of seconds that the browser may cache the
    ///   preflight response.
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
    fn send(&self) -> Result<()> {
        let header_fn = Function::try_from_function("header")
            .ok_or_else(|| anyhow!("header() is not available"))?;
        for (name, value) in self.build() {
            let hdr = format!("{name}: {value}");
            header_fn
                .try_call(vec![&hdr])
                .map_err(|e| anyhow!("header() call failed {}", e))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceSharing;
    use crate::run_php_example;

    #[test]
    fn test_default_policy_empty() {
        let cp = ResourceSharing::__construct();
        let headers = cp.build();
        assert!(headers.is_empty(), "Expected no headers by default");
    }

    #[test]
    fn test_allow_origins_only() {
        let mut cp = ResourceSharing::__construct();
        cp.allow_origins(vec!["https://example.com".to_string(), "*".to_string()]);
        let headers = cp.build();
        assert_eq!(
            headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("https://example.com, *")
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_allow_methods_only() {
        let mut cp = ResourceSharing::__construct();
        cp.allow_methods(vec!["GET".to_string(), "POST".to_string()]);
        let headers = cp.build();
        assert_eq!(
            headers
                .get("Access-Control-Allow-Methods")
                .map(String::as_str),
            Some("GET, POST")
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_allow_headers_only() {
        let mut cp = ResourceSharing::__construct();
        cp.allow_headers(vec!["Content-Type".to_string(), "X-Custom".to_string()]);
        let headers = cp.build();
        assert_eq!(
            headers
                .get("Access-Control-Allow-Headers")
                .map(String::as_str),
            Some("Content-Type, X-Custom")
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_allow_credentials_only() {
        let mut cp = ResourceSharing::__construct();
        cp.allow_credentials(true);
        let headers = cp.build();
        assert_eq!(
            headers
                .get("Access-Control-Allow-Credentials")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_expose_headers_only() {
        let mut cp = ResourceSharing::__construct();
        cp.expose_headers(vec!["X-Exposed".to_string()]);
        let headers = cp.build();
        assert_eq!(
            headers
                .get("Access-Control-Expose-Headers")
                .map(String::as_str),
            Some("X-Exposed")
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_max_age_only() {
        let mut cp = ResourceSharing::__construct();
        cp.max_age(3600);
        let headers = cp.build();
        assert_eq!(
            headers.get("Access-Control-Max-Age").map(String::as_str),
            Some("3600")
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_full_policy_combination() {
        let mut cp = ResourceSharing::__construct();
        cp.allow_origins(vec!["https://foo".to_string()]);
        cp.allow_methods(vec!["GET".to_string()]);
        cp.allow_headers(vec!["X-Test".to_string()]);
        cp.allow_credentials(true);
        cp.expose_headers(vec!["X-Exp".to_string()]);
        cp.max_age(1200);

        let headers = cp.build();
        assert_eq!(
            headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("https://foo")
        );
        assert_eq!(
            headers
                .get("Access-Control-Allow-Methods")
                .map(String::as_str),
            Some("GET")
        );
        assert_eq!(
            headers
                .get("Access-Control-Allow-Headers")
                .map(String::as_str),
            Some("X-Test")
        );
        assert_eq!(
            headers
                .get("Access-Control-Allow-Credentials")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            headers
                .get("Access-Control-Expose-Headers")
                .map(String::as_str),
            Some("X-Exp")
        );
        assert_eq!(
            headers.get("Access-Control-Max-Age").map(String::as_str),
            Some("1200")
        );
        assert_eq!(headers.len(), 6);
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/cross-origin/resource-sharing")?;
        Ok(())
    }
}
