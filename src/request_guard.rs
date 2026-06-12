use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::{ProcessGlobals, ce};
use ext_php_rs::{php_class, php_impl};
use thiserror::Error;
use url::Url;

// Error codes for request guard errors: 3000-3099
pub mod error_codes {
    pub const INVALID_ALLOWED_ORIGIN: i32 = 3000;
    pub const CROSS_SITE_REQUEST: i32 = 3001;
    pub const DISALLOWED_ORIGIN: i32 = 3002;
    pub const DISALLOWED_REFERER: i32 = 3003;
    pub const MISSING_HEADERS: i32 = 3004;
}

/// Errors that can occur during request validation.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid allowed origin {0:?}: {1}")]
    InvalidAllowedOrigin(String, String),

    #[error("Cross-site request blocked (Sec-Fetch-Site: {0})")]
    CrossSiteRequest(String),

    #[error("Origin {0:?} is not allowed")]
    DisallowedOrigin(String),

    #[error("Referer {0:?} is not allowed")]
    DisallowedReferer(String),

    #[error("Request carries neither Sec-Fetch-Site, Origin nor Referer")]
    MissingHeaders,
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidAllowedOrigin(_, _) => error_codes::INVALID_ALLOWED_ORIGIN,
            Error::CrossSiteRequest(_) => error_codes::CROSS_SITE_REQUEST,
            Error::DisallowedOrigin(_) => error_codes::DISALLOWED_ORIGIN,
            Error::DisallowedReferer(_) => error_codes::DISALLOWED_REFERER,
            Error::MissingHeaders => error_codes::MISSING_HEADERS,
        }
    }
}

impl From<Error> for PhpException {
    fn from(err: Error) -> Self {
        let code = err.code();
        let message = err.to_string();
        PhpException::new(message, code, ce::exception())
    }
}

/// Result type alias for request guard operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A normalized web origin: scheme + host + effective port.
#[derive(PartialEq, Debug)]
struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    fn parse(value: &str) -> std::result::Result<Self, String> {
        let url = Url::parse(value).map_err(|e| e.to_string())?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("scheme {:?} is not http(s)", url.scheme()));
        }
        let host = url.host_str().ok_or("origin has no host")?.to_lowercase();
        Ok(Self {
            scheme: url.scheme().to_string(),
            host,
            port: url.port_or_known_default(),
        })
    }
}

/// Request-level cross-site request forgery guard built on browser-provided
/// metadata: `Sec-Fetch-Site`, `Origin`, and `Referer`.
///
/// Many real CSRF bypasses come from a hand-rolled Origin check with a hole
/// in it (a forgotten dev domain, a prefix match, a null-origin pass).
/// This guard implements the OWASP-recommended order: safe methods pass;
/// `Sec-Fetch-Site` is honored when the browser sends it; otherwise the
/// `Origin` (then `Referer`) must match the allowlist exactly — scheme,
/// host, and port; a request with no usable headers is rejected by default.
///
/// Defense in depth: combine with `Hardened\CsrfProtection` tokens rather
/// than replacing them.
#[php_class]
#[php(name = "Hardened\\RequestGuard")]
pub struct RequestGuard {
    allowed_origins: Vec<Origin>,
    safe_methods: Vec<String>,
    allow_same_site: bool,
    allow_missing_headers: bool,
}

impl RequestGuard {
    fn _new(allowed_origins: &[String]) -> Result<Self> {
        let allowed_origins = allowed_origins
            .iter()
            .map(|raw| Origin::parse(raw).map_err(|e| Error::InvalidAllowedOrigin(raw.clone(), e)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            allowed_origins,
            safe_methods: ["GET", "HEAD", "OPTIONS"].map(ToString::to_string).to_vec(),
            allow_same_site: false,
            allow_missing_headers: false,
        })
    }

    fn _origin_allowed(&self, value: &str) -> bool {
        Origin::parse(value).is_ok_and(|origin| self.allowed_origins.contains(&origin))
    }

    fn _check(
        &self,
        method: &str,
        origin: Option<&str>,
        referer: Option<&str>,
        sec_fetch_site: Option<&str>,
    ) -> Result<()> {
        if self
            .safe_methods
            .iter()
            .any(|safe| safe.eq_ignore_ascii_case(method))
        {
            return Ok(());
        }

        // Sec-Fetch-Site is set by all current browsers and cannot be forged
        // from a cross-origin web context.
        if let Some(site) = sec_fetch_site {
            match site.to_ascii_lowercase().as_str() {
                // same-origin, or user-initiated (address bar, bookmark)
                "same-origin" | "none" => return Ok(()),
                "same-site" if self.allow_same_site => return Ok(()),
                // For an allowlisted partner origin, fall through to the
                // Origin check; otherwise this rejects below.
                _ => {
                    if let Some(value) = origin
                        && self._origin_allowed(value)
                    {
                        return Ok(());
                    }
                    return Err(Error::CrossSiteRequest(site.to_string()));
                }
            }
        }

        if let Some(value) = origin {
            // "null" is sent for sandboxed/opaque contexts — never trust it.
            return if value.eq_ignore_ascii_case("null") || !self._origin_allowed(value) {
                Err(Error::DisallowedOrigin(value.to_string()))
            } else {
                Ok(())
            };
        }

        if let Some(value) = referer {
            return if self._origin_allowed(value) {
                Ok(())
            } else {
                Err(Error::DisallowedReferer(value.to_string()))
            };
        }

        if self.allow_missing_headers {
            Ok(())
        } else {
            Err(Error::MissingHeaders)
        }
    }

    /// Reads `(method, origin, referer, sec_fetch_site)` from `$_SERVER`.
    fn _from_server() -> (String, Option<String>, Option<String>, Option<String>) {
        let globals = ProcessGlobals::get();
        let server = globals.http_server_vars();
        let get = |key: &str| -> Option<String> {
            server
                .and_then(|table| table.get(key))
                .and_then(|zval| zval.string())
        };
        (
            get("REQUEST_METHOD").unwrap_or_else(|| "GET".to_string()),
            get("HTTP_ORIGIN"),
            get("HTTP_REFERER"),
            get("HTTP_SEC_FETCH_SITE"),
        )
    }
}

#[php_impl]
impl RequestGuard {
    /// Constructs a request guard.
    ///
    /// # Parameters
    /// - `allowed_origins`: Origins allowed to send state-changing requests,
    ///   as full origins, e.g. `["https://app.example", "https://admin.example:8443"]`.
    ///   Matching is exact on scheme, host, and effective port — no
    ///   subdomain or prefix matching.
    ///
    /// # Exceptions
    /// - Throws an exception if an entry is not a valid http(s) origin.
    fn __construct(allowed_origins: Vec<String>) -> Result<Self> {
        Self::_new(&allowed_origins)
    }

    /// Accepts `Sec-Fetch-Site: same-site` requests (subdomains of your
    /// registrable domain). Off by default: a compromised or
    /// attacker-registered subdomain is a classic CSRF hole.
    ///
    /// # Parameters
    /// - `allow`: Whether `same-site` passes.
    fn allow_same_site(&mut self, allow: bool) {
        self.allow_same_site = allow;
    }

    /// Replaces the set of methods that always pass (defaults to
    /// `GET`/`HEAD`/`OPTIONS`). Keep your safe methods side-effect free.
    ///
    /// # Parameters
    /// - `methods`: Method names, case-insensitive.
    fn set_safe_methods(&mut self, methods: Vec<String>) {
        self.safe_methods = methods;
    }

    /// Accepts state-changing requests that carry none of the checked
    /// headers. Off by default (strict); enable only if you must support
    /// non-browser clients on cookie-authenticated endpoints — better, give
    /// those clients token auth and keep this strict.
    ///
    /// # Parameters
    /// - `allow`: Whether header-less requests pass.
    fn allow_missing_headers(&mut self, allow: bool) {
        self.allow_missing_headers = allow;
    }

    /// Checks a request described by explicit values.
    ///
    /// # Parameters
    /// - `method`: The HTTP method.
    /// - `origin`: The `Origin` header, or `null`.
    /// - `referer`: The `Referer` header, or `null`.
    /// - `sec_fetch_site`: The `Sec-Fetch-Site` header, or `null`.
    ///
    /// # Returns
    /// - `bool`: `true` if the request passes the policy.
    fn check(
        &self,
        method: &str,
        origin: Option<String>,
        referer: Option<String>,
        sec_fetch_site: Option<String>,
    ) -> bool {
        self._check(
            method,
            origin.as_deref(),
            referer.as_deref(),
            sec_fetch_site.as_deref(),
        )
        .is_ok()
    }

    /// Like `check()`, but throws a descriptive exception on rejection.
    ///
    /// # Parameters
    /// - `method`: The HTTP method.
    /// - `origin`: The `Origin` header, or `null`.
    /// - `referer`: The `Referer` header, or `null`.
    /// - `sec_fetch_site`: The `Sec-Fetch-Site` header, or `null`.
    ///
    /// # Exceptions
    /// - Throws an exception naming the failed check.
    fn assert(
        &self,
        method: &str,
        origin: Option<String>,
        referer: Option<String>,
        sec_fetch_site: Option<String>,
    ) -> Result<()> {
        self._check(
            method,
            origin.as_deref(),
            referer.as_deref(),
            sec_fetch_site.as_deref(),
        )
    }

    /// Checks the current request using `$_SERVER` (`REQUEST_METHOD`,
    /// `HTTP_ORIGIN`, `HTTP_REFERER`, `HTTP_SEC_FETCH_SITE`).
    ///
    /// # Returns
    /// - `bool`: `true` if the request passes the policy.
    fn check_server(&self) -> bool {
        let (method, origin, referer, sec_fetch_site) = Self::_from_server();
        self._check(
            &method,
            origin.as_deref(),
            referer.as_deref(),
            sec_fetch_site.as_deref(),
        )
        .is_ok()
    }

    /// Like `checkServer()`, but throws a descriptive exception on rejection.
    ///
    /// # Exceptions
    /// - Throws an exception naming the failed check.
    fn assert_server(&self) -> Result<()> {
        let (method, origin, referer, sec_fetch_site) = Self::_from_server();
        self._check(
            &method,
            origin.as_deref(),
            referer.as_deref(),
            sec_fetch_site.as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, RequestGuard};
    use crate::run_php_example;

    fn guard() -> RequestGuard {
        RequestGuard::_new(&["https://app.example".to_string()]).unwrap()
    }

    #[test]
    fn test_safe_methods_pass() {
        let g = guard();
        assert!(g._check("GET", None, None, None).is_ok());
        assert!(g._check("head", None, None, None).is_ok());
        assert!(g._check("OPTIONS", None, None, Some("cross-site")).is_ok());
    }

    #[test]
    fn test_sec_fetch_site() {
        let g = guard();
        assert!(g._check("POST", None, None, Some("same-origin")).is_ok());
        assert!(g._check("POST", None, None, Some("none")).is_ok());
        assert!(matches!(
            g._check("POST", None, None, Some("cross-site")),
            Err(Error::CrossSiteRequest(_))
        ));
        assert!(g._check("POST", None, None, Some("same-site")).is_err());

        let mut lenient = guard();
        lenient.allow_same_site(true);
        assert!(
            lenient
                ._check("POST", None, None, Some("same-site"))
                .is_ok()
        );

        // Cross-site but from an allowlisted origin (e.g. trusted partner)
        assert!(
            g._check(
                "POST",
                Some("https://app.example"),
                None,
                Some("cross-site")
            )
            .is_ok()
        );
        assert!(
            g._check(
                "POST",
                Some("https://evil.example"),
                None,
                Some("cross-site")
            )
            .is_err()
        );
    }

    #[test]
    fn test_origin_allowlist() {
        let g = guard();
        assert!(
            g._check("POST", Some("https://app.example"), None, None)
                .is_ok()
        );
        // Exact origin matching: scheme, host, and port all count
        assert!(
            g._check("POST", Some("http://app.example"), None, None)
                .is_err()
        );
        assert!(
            g._check("POST", Some("https://app.example:8443"), None, None)
                .is_err()
        );
        assert!(
            g._check("POST", Some("https://app.example.evil.com"), None, None)
                .is_err()
        );
        assert!(
            g._check("POST", Some("https://evil.com"), None, None)
                .is_err()
        );
        // The opaque "null" origin never passes
        assert!(matches!(
            g._check("POST", Some("null"), None, None),
            Err(Error::DisallowedOrigin(_))
        ));
        // Default ports normalize
        assert!(
            g._check("POST", Some("https://app.example:443"), None, None)
                .is_ok()
        );
    }

    #[test]
    fn test_referer_fallback() {
        let g = guard();
        assert!(
            g._check("POST", None, Some("https://app.example/form?x=1"), None)
                .is_ok()
        );
        assert!(matches!(
            g._check("POST", None, Some("https://evil.com/form"), None),
            Err(Error::DisallowedReferer(_))
        ));
        // Origin takes precedence over Referer
        assert!(
            g._check(
                "POST",
                Some("https://evil.com"),
                Some("https://app.example/"),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn test_missing_headers() {
        let g = guard();
        assert!(matches!(
            g._check("POST", None, None, None),
            Err(Error::MissingHeaders)
        ));
        let mut lenient = guard();
        lenient.allow_missing_headers(true);
        assert!(lenient._check("POST", None, None, None).is_ok());
    }

    #[test]
    fn test_custom_safe_methods() {
        let mut g = guard();
        g.set_safe_methods(vec!["GET".to_string()]);
        assert!(g._check("OPTIONS", None, None, None).is_err());
        assert!(g._check("GET", None, None, None).is_ok());
    }

    #[test]
    fn test_invalid_allowlist_entries() {
        assert!(RequestGuard::_new(&["app.example".to_string()]).is_err());
        assert!(RequestGuard::_new(&["javascript:alert(1)".to_string()]).is_err());
        assert!(RequestGuard::_new(&["".to_string()]).is_err());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("request-guard")?;
        Ok(())
    }
}
