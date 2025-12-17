use csrf::{AesGcmCsrfProtection, CsrfCookie, CsrfProtection, CsrfToken};
use data_encoding::{BASE64, BASE64URL};
use ext_php_rs::exception::PhpException;
#[cfg(not(test))]
use ext_php_rs::types::Zval;
use ext_php_rs::zend::ce;
use ext_php_rs::zend::Function;
#[cfg(not(test))]
use ext_php_rs::zend::ProcessGlobals;
use ext_php_rs::{php_class, php_impl};
use thiserror::Error;

// Error codes for CSRF errors: 1000-1099
pub mod error_codes {
    pub const KEY_DECODE: i32 = 1000;
    pub const KEY_LENGTH: i32 = 1001;
    pub const PREVIOUS_TOKEN_DECODE: i32 = 1002;
    pub const TOKEN_GENERATION: i32 = 1003;
    pub const TOKEN_DECODE: i32 = 1004;
    pub const TOKEN_PARSE: i32 = 1005;
    pub const COOKIE_NOT_SET: i32 = 1006;
    pub const COOKIE_DECODE: i32 = 1007;
    pub const COOKIE_PARSE: i32 = 1008;
    pub const VERIFICATION: i32 = 1009;
    pub const SETCOOKIE_UNAVAILABLE: i32 = 1010;
}

/// Errors that can occur during CSRF protection operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("CSRF protection key must be valid base64url: {0}")]
    KeyDecodeError(String),

    #[error("CSRF protection key must contain exactly 32 bytes")]
    KeyLengthError,

    #[error("Failed to decode previous token: {0}")]
    PreviousTokenDecodeError(String),

    #[error("Failed to generate token pair: {0}")]
    TokenGenerationError(String),

    #[error("Token base64 decode error: {0}")]
    TokenDecodeError(String),

    #[error("Failed to parse token: {0}")]
    TokenParseError(String),

    #[error("Cookie is not set")]
    CookieNotSet,

    #[error("Cookie base64 decode error: {0}")]
    CookieDecodeError(String),

    #[error("Failed to parse cookie: {0}")]
    CookieParseError(String),

    #[error("Token verification failed: {0}")]
    VerificationError(String),

    #[error("Could not call setcookie()")]
    SetCookieUnavailable,
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::KeyDecodeError(_) => error_codes::KEY_DECODE,
            Error::KeyLengthError => error_codes::KEY_LENGTH,
            Error::PreviousTokenDecodeError(_) => error_codes::PREVIOUS_TOKEN_DECODE,
            Error::TokenGenerationError(_) => error_codes::TOKEN_GENERATION,
            Error::TokenDecodeError(_) => error_codes::TOKEN_DECODE,
            Error::TokenParseError(_) => error_codes::TOKEN_PARSE,
            Error::CookieNotSet => error_codes::COOKIE_NOT_SET,
            Error::CookieDecodeError(_) => error_codes::COOKIE_DECODE,
            Error::CookieParseError(_) => error_codes::COOKIE_PARSE,
            Error::VerificationError(_) => error_codes::VERIFICATION,
            Error::SetCookieUnavailable => error_codes::SETCOOKIE_UNAVAILABLE,
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

/// Result type alias for CSRF operations.
pub type Result<T> = std::result::Result<T, Error>;

/// CSRF protection for your application.
#[php_class]
#[php(name = "Hardened\\CsrfProtection")]
pub struct Csrf {
    pub inner: AesGcmCsrfProtection,
    pub token: CsrfToken,
    pub cookie: CsrfCookie,
    pub cookie_name: String,
}
#[php_impl]
impl Csrf {
    /// Constructs a CSRF protection instance for PHP.
    ///
    /// # Parameters
    /// - `key`: `string` Base64URL-encoded 32-byte secret key.
    /// - `ttl`: `int` token time-to-live in seconds.
    /// - `previousTokenValue`: `?string` optional Base64URL-encoded previous token for rotation.
    ///
    /// # Exceptions
    /// - Throws `Exception` if key decoding or length validation fails.
    /// - Throws `Exception` if token pair generation fails.
    fn __construct(
        key: &str,
        ttl: i64,
        previous_token_value: Option<String>,
    ) -> Result<Self> {
        let key = <[u8; 32]>::try_from(
            BASE64URL
                .decode(key.as_bytes())
                .map_err(|err| Error::KeyDecodeError(err.to_string()))?,
        )
        .map_err(|_| Error::KeyLengthError)?;
        let inner = AesGcmCsrfProtection::from_key(key);

        let previous_token_value = if let Some(previous_token_value) = previous_token_value {
            <[u8; 64]>::try_from(
                BASE64URL
                    .decode(previous_token_value.as_bytes())
                    .map_err(|err| Error::PreviousTokenDecodeError(err.to_string()))?,
            )
            .ok()
        } else {
            None
        };

        let (token, cookie) = inner
            .generate_token_pair(previous_token_value.as_ref(), ttl)
            .map_err(|err| Error::TokenGenerationError(err.to_string()))?;
        Ok(Self {
            inner,
            token,
            cookie,
            cookie_name: String::from("csrf"),
        })
    }

    fn generate_key() -> String {
        BASE64URL.encode(&rand::random::<[u8; 32]>())
    }

    /// Verifies a CSRF token & cookie pair from PHP.
    ///
    /// # Parameters
    /// - `token`: `string` Base64URL-encoded CSRF token from client.
    /// - `cookie`: `string` Base64URL-encoded CSRF cookie from client.
    ///
    /// # Returns
    /// - `void` on success.
    ///
    /// # Exceptions
    /// - Throws `Exception` if decoding fails or the token–cookie pair is invalid/expired.
    fn verify_token(
        &self,
        token: &str,
        #[allow(unused_mut)] mut cookie: Option<String>,
    ) -> Result<()> {
        let token = self
            .inner
            .parse_token(
                BASE64URL
                    .decode(token.as_bytes())
                    .map_err(|err| Error::TokenDecodeError(err.to_string()))?
                    .as_slice(),
            )
            .map_err(|err| Error::TokenParseError(err.to_string()))?;

        #[cfg(not(test))]
        if cookie.is_none() {
            cookie = ProcessGlobals::get()
                .http_cookie_vars()
                .get(self.cookie_name.as_str())
                .and_then(Zval::string);
        }

        if cookie.is_none() {
            return Err(Error::CookieNotSet);
        }

        let cookie = self
            .inner
            .parse_cookie(
                BASE64
                    .decode(cookie.unwrap().as_bytes())
                    .map_err(|err| Error::CookieDecodeError(err.to_string()))?
                    .as_slice(),
            )
            .map_err(|err| Error::CookieParseError(err.to_string()))?;

        self.inner
            .verify_token_pair(&token, &cookie)
            .map_err(|err| Error::VerificationError(err.to_string()))?;
        Ok(())
    }

    /// Returns the CSRF cookie string to send in PHP.
    ///
    /// # Returns
    /// - `string` Base64URL-encoded cookie suitable for `Set-Cookie`.
    fn cookie(&self) -> String {
        self.cookie.b64_string()
    }

    /// Returns the CSRF token string for PHP forms or headers.
    ///
    /// # Returns
    /// - `string` Base64URL-encoded token.
    fn token(&self) -> String {
        self.token.b64_url_string()
    }

    /// Sets the name of the CSRF cookie to use in PHP calls.
    ///
    /// # Parameters
    /// - `cookieName`: `string` the new name for the CSRF cookie.
    ///
    /// # Returns
    /// - `void`
    fn set_cookie_name(&mut self, cookie_name: String) {
        self.cookie_name = cookie_name;
    }

    /// Returns the configured CSRF cookie name.
    ///
    /// # Returns
    /// - `string` the name of the CSRF cookie.
    fn cookie_name(&self) -> String {
        self.cookie_name.clone()
    }

    /// Sends the CSRF cookie to the client via `setcookie()`
    ///
    /// # Parameters
    /// - `expires`: `?int` UNIX timestamp when the cookie expires (defaults to `0`, a session cookie).
    /// - `path`: `?string` Cookie path (defaults to `"/"`).
    /// - `domain`: `?string` Cookie domain (defaults to the current host).
    /// - `secure`: `?bool` Send only over HTTPS (defaults to `false`).
    /// - `httponly`: `?bool` HTTP-only flag (defaults to `true`).
    ///
    /// # Exceptions
    /// - Throws `Exception` if the PHP `setcookie()` function cannot be invoked.
    fn send_cookie(
        &mut self,
        expires: Option<i64>,
        path: Option<String>,
        domain: Option<String>,
        secure: Option<bool>,
        httponly: Option<bool>,
    ) -> Result<()> {
        let name = self.cookie_name.clone();
        let value = self.cookie.b64_string();
        let expires = expires.unwrap_or(0);
        let path = path.unwrap_or_else(|| "/".to_string());
        let domain = domain.unwrap_or_default();
        let secure = secure.unwrap_or(false);
        let httponly = httponly.unwrap_or(true);

        Function::try_from_function("setcookie")
            .ok_or(Error::SetCookieUnavailable)?
            .try_call(vec![
                &name, &value, &expires, &path, &domain, &secure, &httponly,
            ])
            .map_err(|_| Error::SetCookieUnavailable)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Csrf;
    use crate::run_php_example;
    use data_encoding::BASE64URL;

    /// Helper to generate a Base64URL-encoded 32-byte zero key.
    fn zero_key_b64() -> String {
        let key = [0u8; 32];
        BASE64URL.encode(&key)
    }

    #[test]
    fn test_construct_and_token_cookie() -> crate::TestResult {
        // Construct with zero key, 60-second TTL, no previous token
        let key = zero_key_b64();
        let csrf = Csrf::__construct(&key, 60, None)?;

        // Retrieve token and cookie strings

        let token = csrf.token();
        let cookie = csrf.cookie();

        println!("cookie = {cookie:#?}");

        assert!(!token.is_empty(), "Token should not be empty");
        assert!(!cookie.is_empty(), "Cookie should not be empty");
        // Verify the freshly generated pair
        csrf.verify_token(&token, Some(cookie.clone()))?;

        Ok(())
    }

    #[test]
    fn test_verify_token_fails_with_bad_token() -> crate::TestResult {
        let key = zero_key_b64();
        let csrf = Csrf::__construct(&key, 60, None)?;
        let bad_token = "invalid.token.value";
        let good_cookie = csrf.cookie();
        let err = csrf.verify_token(bad_token, Some(good_cookie)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Token base64 decode error") || msg.contains("parse_token"),
            "Unexpected error: {msg}"
        );
        Ok(())
    }

    #[test]
    fn test_verify_token_fails_with_bad_cookie() -> crate::TestResult {
        let key = zero_key_b64();
        let csrf = Csrf::__construct(&key, 60, None)?;
        let good_token = csrf.token();
        let bad_cookie = "invalid_cookie";
        let err = csrf
            .verify_token(&good_token, Some(bad_cookie.to_string()))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Cookie base64 decode error") || msg.contains("verify_token_pair"),
            "Unexpected error: {msg}"
        );
        Ok(())
    }

    #[test]
    fn test_cookie_name_get_set() -> crate::TestResult {
        let key = zero_key_b64();
        let mut csrf = Csrf::__construct(&key, 60, None)?;
        // default cookie name
        assert_eq!(csrf.cookie_name(), "csrf");
        // set a new cookie name
        csrf.set_cookie_name("my_csrf".to_string());
        assert_eq!(csrf.cookie_name(), "my_csrf");
        Ok(())
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("csrf-protection")?;
        Ok(())
    }
}
