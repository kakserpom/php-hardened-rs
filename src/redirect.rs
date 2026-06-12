use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use thiserror::Error;
use url::{Host, Url};

// Error codes for Redirect errors: 2000-2099
pub mod error_codes {
    pub const INVALID_ALLOWED_HOST: i32 = 2000;
}

/// Errors that can occur during redirect validation.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid allowed host {0:?}: {1}")]
    InvalidAllowedHost(String, String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidAllowedHost(_, _) => error_codes::INVALID_ALLOWED_HOST,
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

/// Result type alias for redirect operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Marker host used to detect whether a candidate URL stayed same-origin
/// when resolved as a relative reference. `.invalid` is a reserved TLD
/// (RFC 2606), so no real redirect target can ever equal it.
const MARKER_HOST: &str = "php-hardened-marker.invalid";

/// Open-redirect validator.
///
/// Validates untrusted redirect targets (`?next=`, `?return_to=`, …) the way
/// a browser will actually interpret them (WHATWG URL parsing), which defeats
/// the classic bypasses: scheme-relative `//evil.com`, backslash tricks
/// `/\evil.com` and `\/\/evil.com`, missing-slash `https:/evil.com`, userinfo
/// `https://trusted@evil.com`, embedded whitespace/control bytes, and
/// percent- or unicode-encoded host variants.
///
/// A URL is considered safe if it is a same-origin relative reference, or an
/// absolute `http(s)` URL whose host matches the allowlist.
#[php_class]
#[php(name = "Hardened\\Redirect")]
pub struct Redirect {
    allowed_hosts: Vec<Host>,
    allow_subdomains: bool,
}

impl Redirect {
    fn _parse_allowed(hosts: &[String]) -> Result<Vec<Host>> {
        hosts
            .iter()
            .map(|raw| {
                let mut host = Host::parse(raw)
                    .map_err(|e| Error::InvalidAllowedHost(raw.clone(), e.to_string()))?;
                if let Host::Domain(domain) = &mut host {
                    *domain = domain.trim_end_matches('.').to_lowercase();
                }
                Ok(host)
            })
            .collect()
    }

    fn _host_matches(&self, host: &Host) -> bool {
        self.allowed_hosts.iter().any(|allowed| {
            if host == allowed {
                return true;
            }
            if self.allow_subdomains
                && let (Host::Domain(child), Host::Domain(parent)) = (host, allowed)
            {
                return child.ends_with(&format!(".{parent}"));
            }
            false
        })
    }

    /// Returns `true` if `url` is safe to redirect to.
    ///
    /// The candidate is resolved against both an `https://` and an `http://`
    /// base, because reference resolution is scheme-dependent (e.g.
    /// `https:/evil.com` stays same-origin on an https page but navigates to
    /// `evil.com` from an http page). It must be safe under both.
    fn _is_safe(&self, url: &str) -> bool {
        // Browsers strip raw control bytes before parsing, which can smuggle
        // a hostile URL past naive checks — reject them outright.
        if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return false;
        }
        for base in [
            format!("https://{MARKER_HOST}/"),
            format!("http://{MARKER_HOST}/"),
        ] {
            let base = Url::parse(&base).expect("marker base URL is valid");
            let Ok(resolved) = Url::options().base_url(Some(&base)).parse(url) else {
                return false;
            };
            if !matches!(resolved.scheme(), "http" | "https") {
                return false;
            }
            // Userinfo in a redirect target is only ever used for trickery.
            if !resolved.username().is_empty() || resolved.password().is_some() {
                return false;
            }
            let Some(host) = resolved.host() else {
                return false;
            };
            let mut host = host.to_owned();
            if let Host::Domain(domain) = &mut host {
                // The WHATWG parser keeps a trailing dot; DNS-wise it is the
                // same name, so normalize before matching the allowlist.
                *domain = domain.trim_end_matches('.').to_string();
            }
            if host == Host::Domain(MARKER_HOST.to_string()) {
                // Resolved relative to the base: a same-origin reference.
                continue;
            }
            if !self._host_matches(&host) {
                return false;
            }
        }
        true
    }
}

#[php_impl]
impl Redirect {
    /// Constructs a redirect validator.
    ///
    /// # Parameters
    /// - `allowed_hosts`: Hostnames (or IP literals) that absolute redirect
    ///   targets may point to. With an empty list only same-origin relative
    ///   URLs are considered safe.
    /// - `allow_subdomains`: Whether subdomains of allowed hosts also match
    ///   (defaults to `false`).
    ///
    /// # Exceptions
    /// - Throws an exception if any allowed host fails to parse.
    fn __construct(allowed_hosts: Vec<String>, allow_subdomains: Option<bool>) -> Result<Self> {
        Ok(Self {
            allowed_hosts: Self::_parse_allowed(&allowed_hosts)?,
            allow_subdomains: allow_subdomains.unwrap_or(false),
        })
    }

    /// Checks whether a redirect target is safe.
    ///
    /// Safe means: a same-origin relative reference, or an absolute
    /// `http(s)` URL without userinfo whose host matches the allowlist.
    ///
    /// # Parameters
    /// - `url`: The untrusted redirect target.
    ///
    /// # Returns
    /// - `bool`: `true` if the target is safe to redirect to.
    fn is_safe(&self, url: &str) -> bool {
        self._is_safe(url)
    }

    /// Returns the redirect target if it is safe, or the fallback otherwise.
    ///
    /// # Parameters
    /// - `url`: The untrusted redirect target.
    /// - `fallback`: Returned when `url` is unsafe (defaults to `"/"`).
    ///
    /// # Returns
    /// - `string`: `url` if safe, `fallback` otherwise.
    fn sanitize(&self, url: &str, fallback: Option<String>) -> String {
        if self._is_safe(url) {
            url.to_string()
        } else {
            fallback.unwrap_or_else(|| "/".to_string())
        }
    }

    /// Checks whether a redirect target is safe (static convenience).
    ///
    /// # Parameters
    /// - `url`: The untrusted redirect target.
    /// - `allowed_hosts`: Hostnames absolute targets may point to.
    /// - `allow_subdomains`: Whether subdomains of allowed hosts also match
    ///   (defaults to `false`).
    ///
    /// # Returns
    /// - `bool`: `true` if the target is safe to redirect to.
    ///
    /// # Exceptions
    /// - Throws an exception if any allowed host fails to parse.
    fn is_safe_url(
        url: &str,
        allowed_hosts: Vec<String>,
        allow_subdomains: Option<bool>,
    ) -> Result<bool> {
        Ok(Self::__construct(allowed_hosts, allow_subdomains)?._is_safe(url))
    }

    /// Returns the redirect target if it is safe, or the fallback otherwise
    /// (static convenience).
    ///
    /// # Parameters
    /// - `url`: The untrusted redirect target.
    /// - `allowed_hosts`: Hostnames absolute targets may point to.
    /// - `fallback`: Returned when `url` is unsafe (defaults to `"/"`).
    /// - `allow_subdomains`: Whether subdomains of allowed hosts also match
    ///   (defaults to `false`).
    ///
    /// # Returns
    /// - `string`: `url` if safe, `fallback` otherwise.
    ///
    /// # Exceptions
    /// - Throws an exception if any allowed host fails to parse.
    fn sanitize_url(
        url: &str,
        allowed_hosts: Vec<String>,
        fallback: Option<String>,
        allow_subdomains: Option<bool>,
    ) -> Result<String> {
        Ok(Self::__construct(allowed_hosts, allow_subdomains)?.sanitize(url, fallback))
    }
}

#[cfg(test)]
mod tests {
    use super::Redirect;
    use crate::run_php_example;

    fn validator(hosts: &[&str], subdomains: bool) -> Redirect {
        Redirect::__construct(
            hosts.iter().map(ToString::to_string).collect(),
            Some(subdomains),
        )
        .unwrap()
    }

    #[test]
    fn test_relative_urls_are_safe() {
        let v = validator(&[], false);
        assert!(v._is_safe("/dashboard"));
        assert!(v._is_safe("/a/b?c=d#e"));
        assert!(v._is_safe("relative/path"));
        assert!(v._is_safe("?query=only"));
        assert!(v._is_safe("#fragment"));
        assert!(v._is_safe(""));
    }

    #[test]
    fn test_allowlisted_hosts() {
        let v = validator(&["trusted.example"], false);
        assert!(v._is_safe("https://trusted.example/path"));
        assert!(v._is_safe("http://trusted.example/"));
        assert!(v._is_safe("https://TRUSTED.example./"));
        assert!(!v._is_safe("https://evil.example/"));
        assert!(!v._is_safe("https://sub.trusted.example/"));
        assert!(!v._is_safe("https://trusted.example.evil.com/"));
    }

    #[test]
    fn test_subdomains() {
        let v = validator(&["trusted.example"], true);
        assert!(v._is_safe("https://sub.trusted.example/"));
        assert!(v._is_safe("https://deep.sub.trusted.example/"));
        assert!(!v._is_safe("https://nottrusted.example/"));
        assert!(!v._is_safe("https://trusted.example.evil.com/"));
    }

    #[test]
    fn test_classic_bypasses_rejected() {
        let v = validator(&["trusted.example"], false);
        // Scheme-relative
        assert!(!v._is_safe("//evil.com"));
        assert!(!v._is_safe("//evil.com/path"));
        // Backslash tricks (browsers treat \ as / in special URLs)
        assert!(!v._is_safe("/\\evil.com"));
        assert!(!v._is_safe("\\/evil.com"));
        assert!(!v._is_safe("\\/\\/evil.com"));
        assert!(!v._is_safe("\\\\evil.com"));
        assert!(!v._is_safe("https:\\\\evil.com"));
        // Missing slash: scheme-dependent resolution
        assert!(!v._is_safe("https:/evil.com"));
        assert!(!v._is_safe("http:/evil.com"));
        assert!(!v._is_safe("https:evil.com"));
        // Userinfo confusion
        assert!(!v._is_safe("https://trusted.example@evil.com/"));
        assert!(!v._is_safe("https://evil.com@trusted.example/"));
        assert!(!v._is_safe("https://trusted.example:pass@evil.com/"));
        // Control bytes / whitespace smuggling
        assert!(!v._is_safe("htt\nps://evil.com"));
        assert!(!v._is_safe("https://evil\t.com"));
        assert!(!v._is_safe("\x01https://evil.com"));
        // Dangerous schemes
        assert!(!v._is_safe("javascript:alert(1)"));
        assert!(!v._is_safe("data:text/html,<script>alert(1)</script>"));
        assert!(!v._is_safe("vbscript:msgbox(1)"));
    }

    #[test]
    fn test_encoded_host_variants() {
        let v = validator(&["trusted.example"], false);
        // Percent-encoded host decodes to evil.com in a browser
        assert!(!v._is_safe("https://%65vil.com/"));
        // Unicode full-width characters normalize via IDNA
        assert!(!v._is_safe("https://ｅｖｉｌ.com/"));
    }

    #[test]
    fn test_scheme_relative_to_allowed_host() {
        let v = validator(&["trusted.example"], false);
        assert!(v._is_safe("//trusted.example/path"));
    }

    #[test]
    fn test_sanitize() {
        let v = validator(&["trusted.example"], false);
        assert_eq!(
            v.sanitize("https://trusted.example/ok", None),
            "https://trusted.example/ok"
        );
        assert_eq!(v.sanitize("https://evil.com/", None), "/");
        assert_eq!(v.sanitize("//evil.com", Some("/home".to_string())), "/home");
    }

    #[test]
    fn test_invalid_allowlist_entry() {
        assert!(Redirect::__construct(vec!["bad host".to_string()], None).is_err());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("redirect")?;
        Ok(())
    }
}
