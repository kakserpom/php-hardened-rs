use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::{Function, ce};
use ext_php_rs::{php_class, php_impl};
use thiserror::Error;

// Error codes for cookie errors: 2700-2799
pub mod error_codes {
    pub const INVALID_NAME: i32 = 2700;
    pub const INVALID_VALUE: i32 = 2701;
    pub const INVALID_ATTRIBUTE: i32 = 2702;
    pub const PREFIX_VIOLATION: i32 = 2703;
    pub const INSECURE_SAMESITE_NONE: i32 = 2704;
    pub const HEADER_UNAVAILABLE: i32 = 2705;
}

/// Errors that can occur during cookie building.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid cookie name: {0}")]
    InvalidName(String),

    #[error("Invalid cookie value: {0} (URL-encode the value first)")]
    InvalidValue(String),

    #[error("Invalid cookie attribute: {0}")]
    InvalidAttribute(String),

    #[error("Cookie prefix invariant violated: {0}")]
    PrefixViolation(String),

    #[error("SameSite=None requires the Secure attribute")]
    InsecureSameSiteNone,

    #[error("PHP header() function unavailable")]
    HeaderUnavailable,

    #[error("PHP header() call failed: {0}")]
    HeaderCallFailed(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidName(_) => error_codes::INVALID_NAME,
            Error::InvalidValue(_) => error_codes::INVALID_VALUE,
            Error::InvalidAttribute(_) => error_codes::INVALID_ATTRIBUTE,
            Error::PrefixViolation(_) => error_codes::PREFIX_VIOLATION,
            Error::InsecureSameSiteNone => error_codes::INSECURE_SAMESITE_NONE,
            Error::HeaderUnavailable | Error::HeaderCallFailed(_) => {
                error_codes::HEADER_UNAVAILABLE
            }
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

/// Result type alias for cookie operations.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, PartialEq)]
enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "lax" => Ok(Self::Lax),
            "none" => Ok(Self::None),
            other => Err(Error::InvalidAttribute(format!(
                "SameSite must be Strict, Lax or None, got {other:?}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// RFC 6265 cookie-name must be an HTTP token.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

/// RFC 6265 cookie-octet: printable US-ASCII except `"`, `,`, `;`, `\`.
fn is_valid_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E))
}

/// Formats a unix timestamp as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`).
fn http_date(unix: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let secs_of_day = unix.rem_euclid(86_400);
    let weekday = DAYS[usize::try_from(days.rem_euclid(7)).unwrap_or(0)];

    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!(
        "{weekday}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        MONTHS[usize::try_from(month - 1).unwrap_or(0)],
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60,
    )
}

/// Hardened `Set-Cookie` builder.
///
/// Secure defaults (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`) that you
/// must explicitly opt out of, RFC 6265 validation of names and values (no
/// header-splitting bytes can reach the wire), enforced `__Host-`/`__Secure-`
/// prefix invariants, and `SameSite=None` refusing to build without `Secure`.
#[php_class]
#[php(name = "Hardened\\Cookie")]
pub struct Cookie {
    name: String,
    value: String,
    path: Option<String>,
    domain: Option<String>,
    max_age: Option<i64>,
    expires: Option<i64>,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    partitioned: bool,
}

impl Cookie {
    fn _new(name: &str, value: &str) -> Result<Self> {
        if !is_valid_name(name) {
            return Err(Error::InvalidName(format!("{name:?} is not a valid token")));
        }
        if !is_valid_value(value) {
            return Err(Error::InvalidValue(format!(
                "{value:?} contains bytes not allowed in a cookie value"
            )));
        }
        Ok(Self {
            name: name.to_string(),
            value: value.to_string(),
            path: Some("/".to_string()),
            domain: None,
            max_age: None,
            expires: None,
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            partitioned: false,
        })
    }

    fn _build(&self) -> Result<String> {
        if self.same_site == SameSite::None && !self.secure {
            return Err(Error::InsecureSameSiteNone);
        }
        if self.partitioned && !self.secure {
            return Err(Error::InvalidAttribute(
                "Partitioned requires the Secure attribute".to_string(),
            ));
        }
        if self.name.starts_with("__Host-") {
            if !self.secure {
                return Err(Error::PrefixViolation(
                    "__Host- cookies must be Secure".to_string(),
                ));
            }
            if self.domain.is_some() {
                return Err(Error::PrefixViolation(
                    "__Host- cookies must not set Domain".to_string(),
                ));
            }
            if self.path.as_deref() != Some("/") {
                return Err(Error::PrefixViolation(
                    "__Host- cookies must set Path=/".to_string(),
                ));
            }
        } else if self.name.starts_with("__Secure-") && !self.secure {
            return Err(Error::PrefixViolation(
                "__Secure- cookies must be Secure".to_string(),
            ));
        }

        let mut header = format!("{}={}", self.name, self.value);
        if let Some(path) = &self.path {
            header.push_str("; Path=");
            header.push_str(path);
        }
        if let Some(domain) = &self.domain {
            header.push_str("; Domain=");
            header.push_str(domain);
        }
        if let Some(max_age) = self.max_age {
            header.push_str(&format!("; Max-Age={max_age}"));
        }
        if let Some(expires) = self.expires {
            header.push_str("; Expires=");
            header.push_str(&http_date(expires));
        }
        if self.secure {
            header.push_str("; Secure");
        }
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        header.push_str("; SameSite=");
        header.push_str(self.same_site.as_str());
        if self.partitioned {
            header.push_str("; Partitioned");
        }
        Ok(header)
    }
}

#[php_impl]
impl Cookie {
    /// Constructs a cookie with hardened defaults: `Secure`, `HttpOnly`,
    /// `SameSite=Lax`, `Path=/`.
    ///
    /// # Parameters
    /// - `name`: Cookie name (RFC 6265 token; `__Host-`/`__Secure-` prefixes
    ///   get their invariants enforced at build time).
    /// - `value`: Cookie value (URL-encode anything outside the RFC 6265
    ///   value charset first).
    ///
    /// # Exceptions
    /// - Throws an exception if the name or value contains forbidden bytes.
    fn __construct(name: &str, value: &str) -> Result<Self> {
        Self::_new(name, value)
    }

    /// Replaces the cookie value.
    ///
    /// # Parameters
    /// - `value`: The new value.
    ///
    /// # Exceptions
    /// - Throws an exception if the value contains forbidden bytes.
    fn set_value(&mut self, value: &str) -> Result<()> {
        if !is_valid_value(value) {
            return Err(Error::InvalidValue(format!(
                "{value:?} contains bytes not allowed in a cookie value"
            )));
        }
        value.clone_into(&mut self.value);
        Ok(())
    }

    /// Sets the `Path` attribute (defaults to `/`).
    ///
    /// # Parameters
    /// - `path`: Must start with `/` and contain no `;` or control bytes.
    ///
    /// # Exceptions
    /// - Throws an exception on an invalid path.
    fn set_path(&mut self, path: &str) -> Result<()> {
        if !path.starts_with('/') || path.bytes().any(|b| b == b';' || b < 0x20 || b == 0x7f) {
            return Err(Error::InvalidAttribute(format!("invalid Path {path:?}")));
        }
        self.path = Some(path.to_string());
        Ok(())
    }

    /// Sets the `Domain` attribute. Not allowed on `__Host-` cookies.
    ///
    /// # Parameters
    /// - `domain`: The domain, e.g. `"example.com"`.
    ///
    /// # Exceptions
    /// - Throws an exception on an invalid domain.
    fn set_domain(&mut self, domain: &str) -> Result<()> {
        let trimmed = domain.trim_start_matches('.');
        if trimmed.is_empty()
            || !trimmed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err(Error::InvalidAttribute(format!(
                "invalid Domain {domain:?}"
            )));
        }
        self.domain = Some(trimmed.to_string());
        Ok(())
    }

    /// Sets the `Max-Age` attribute in seconds. `0` (or negative) tells the
    /// browser to delete the cookie.
    ///
    /// # Parameters
    /// - `seconds`: Lifetime in seconds.
    fn set_max_age(&mut self, seconds: i64) {
        self.max_age = Some(seconds);
    }

    /// Sets the `Expires` attribute from a unix timestamp.
    ///
    /// # Parameters
    /// - `unix_timestamp`: Expiry time, e.g. `time() + 3600`.
    fn set_expires(&mut self, unix_timestamp: i64) {
        self.expires = Some(unix_timestamp);
    }

    /// Sets the `SameSite` attribute (defaults to `Lax`). `None` requires
    /// `Secure`, which is enforced at build time.
    ///
    /// # Parameters
    /// - `same_site`: `"Strict"`, `"Lax"`, or `"None"` (case-insensitive).
    ///
    /// # Exceptions
    /// - Throws an exception on an unknown value.
    fn set_same_site(&mut self, same_site: &str) -> Result<()> {
        self.same_site = SameSite::parse(same_site)?;
        Ok(())
    }

    /// Enables or disables the `Secure` attribute (default: enabled).
    /// Disabling it on a `__Host-`/`__Secure-` cookie or with
    /// `SameSite=None` makes `build()` throw.
    ///
    /// # Parameters
    /// - `secure`: Whether the cookie is HTTPS-only.
    fn set_secure(&mut self, secure: bool) {
        self.secure = secure;
    }

    /// Enables or disables the `HttpOnly` attribute (default: enabled).
    ///
    /// # Parameters
    /// - `http_only`: Whether the cookie is hidden from JavaScript.
    fn set_http_only(&mut self, http_only: bool) {
        self.http_only = http_only;
    }

    /// Enables the `Partitioned` attribute (CHIPS). Requires `Secure`.
    ///
    /// # Parameters
    /// - `partitioned`: Whether the cookie is partitioned by top-level site.
    fn set_partitioned(&mut self, partitioned: bool) {
        self.partitioned = partitioned;
    }

    /// Builds the `Set-Cookie` header value, validating all invariants:
    /// `__Host-` (Secure, no Domain, Path=/), `__Secure-` (Secure),
    /// `SameSite=None` and `Partitioned` (Secure).
    ///
    /// # Returns
    /// - `string`: e.g. `session=abc; Path=/; Secure; HttpOnly; SameSite=Lax`.
    ///
    /// # Exceptions
    /// - Throws an exception describing the violated invariant.
    fn build(&self) -> Result<String> {
        self._build()
    }

    /// Builds and sends the cookie via PHP's `header()` (without replacing
    /// previously sent cookies).
    ///
    /// # Exceptions
    /// - Throws an exception if validation fails or `header()` cannot be
    ///   called.
    fn send(&self) -> Result<()> {
        let header = format!("Set-Cookie: {}", self._build()?);
        Function::try_from_function("header")
            .ok_or(Error::HeaderUnavailable)?
            .try_call(vec![&header, &false])
            .map_err(|err| Error::HeaderCallFailed(format!("{err:?}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Cookie, http_date};
    use crate::run_php_example;

    #[test]
    fn test_secure_defaults() {
        let cookie = Cookie::_new("session", "abc123").unwrap();
        assert_eq!(
            cookie._build().unwrap(),
            "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn test_name_and_value_validation() {
        assert!(Cookie::_new("bad name", "v").is_err());
        assert!(Cookie::_new("bad;name", "v").is_err());
        assert!(Cookie::_new("bad=name", "v").is_err());
        assert!(Cookie::_new("", "v").is_err());
        // Header splitting is unrepresentable
        assert!(Cookie::_new("name", "v\r\nSet-Cookie: evil=1").is_err());
        assert!(Cookie::_new("name", "v;Path=/admin").is_err());
        assert!(Cookie::_new("name", "v alue").is_err());
        assert!(Cookie::_new("name", "URL%20encoded%3B").is_ok());
    }

    #[test]
    fn test_host_prefix_invariants() {
        let cookie = Cookie::_new("__Host-session", "v").unwrap();
        assert!(cookie._build().is_ok());

        let mut insecure = Cookie::_new("__Host-session", "v").unwrap();
        insecure.set_secure(false);
        assert!(insecure._build().is_err());

        let mut with_domain = Cookie::_new("__Host-session", "v").unwrap();
        with_domain.set_domain("example.com").unwrap();
        assert!(with_domain._build().is_err());

        let mut wrong_path = Cookie::_new("__Host-session", "v").unwrap();
        wrong_path.set_path("/app").unwrap();
        assert!(wrong_path._build().is_err());

        let mut secure_prefix = Cookie::_new("__Secure-token", "v").unwrap();
        secure_prefix.set_secure(false);
        assert!(secure_prefix._build().is_err());
    }

    #[test]
    fn test_samesite_none_requires_secure() {
        let mut cookie = Cookie::_new("tracker", "v").unwrap();
        cookie.set_same_site("None").unwrap();
        assert!(cookie._build().unwrap().contains("SameSite=None"));
        cookie.set_secure(false);
        assert!(cookie._build().is_err());
        assert!(cookie.set_same_site("Sideways").is_err());
    }

    #[test]
    fn test_attributes() {
        let mut cookie = Cookie::_new("pref", "dark").unwrap();
        cookie.set_path("/app").unwrap();
        cookie.set_domain(".example.com").unwrap();
        cookie.set_max_age(3600);
        cookie.set_same_site("Strict").unwrap();
        cookie.set_http_only(false);
        assert_eq!(
            cookie._build().unwrap(),
            "pref=dark; Path=/app; Domain=example.com; Max-Age=3600; Secure; SameSite=Strict"
        );
        assert!(cookie.set_path("no-slash").is_err());
        assert!(cookie.set_path("/a;b").is_err());
        assert!(cookie.set_domain("exa mple.com").is_err());
    }

    #[test]
    fn test_partitioned_requires_secure() {
        let mut cookie = Cookie::_new("__Host-id", "v").unwrap();
        cookie.set_partitioned(true);
        assert!(cookie._build().unwrap().ends_with("; Partitioned"));
        let mut insecure = Cookie::_new("id", "v").unwrap();
        insecure.set_partitioned(true);
        insecure.set_secure(false);
        assert!(insecure._build().is_err());
    }

    #[test]
    fn test_http_date() {
        // RFC 7231's own example date
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_750_000_000), "Sun, 15 Jun 2025 15:06:40 GMT");
    }

    #[test]
    fn test_expires_rendered() {
        let mut cookie = Cookie::_new("legacy", "v").unwrap();
        cookie.set_expires(784_111_777);
        assert!(
            cookie
                ._build()
                .unwrap()
                .contains("Expires=Sun, 06 Nov 1994 08:49:37 GMT")
        );
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("cookie")?;
        Ok(())
    }
}
