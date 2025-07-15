use anyhow::{anyhow, bail};
use csrf::{AesGcmCsrfProtection, CsrfCookie, CsrfProtection, CsrfToken};
use data_encoding::{BASE64, BASE64URL};
use ext_php_rs::exception::PhpResult;
#[cfg(not(test))]
use ext_php_rs::types::Zval;
use ext_php_rs::zend::Function;
#[cfg(not(test))]
use ext_php_rs::zend::ProcessGlobals;
use ext_php_rs::{php_class, php_impl};

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
    ) -> anyhow::Result<Self> {
        let key = <[u8; 32]>::try_from(
            BASE64URL
                .decode(key.as_bytes())
                .map_err(|err| anyhow!("csrf protection key: {}", err))?,
        )
        .map_err(|_| anyhow!("csrf protection key must contain 32 bytes"))?;
        let inner = AesGcmCsrfProtection::from_key(key);

        let previous_token_value = if let Some(previous_token_value) = previous_token_value {
            <[u8; 64]>::try_from(
                BASE64URL
                    .decode(previous_token_value.as_bytes())
                    .map_err(|err| anyhow!("{}", err))?,
            )
            .ok()
        } else {
            None
        };

        let (token, cookie) = inner
            .generate_token_pair(previous_token_value.as_ref(), ttl)
            .map_err(|err| anyhow!("{}", err))?;
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
    ) -> anyhow::Result<()> {
        let token = self
            .inner
            .parse_token(
                BASE64URL
                    .decode(token.as_bytes())
                    .map_err(|err| anyhow!("Token base64 error: {}", err))?
                    .as_slice(),
            )
            .map_err(|err| anyhow!("{}", err))?;

        #[cfg(not(test))]
        if cookie.is_none() {
            cookie = ProcessGlobals::get()
                .http_cookie_vars()
                .get(self.cookie_name.as_str())
                .and_then(Zval::string);
        }

        if cookie.is_none() {
            bail!("Cookie is not set");
        }

        let cookie = self
            .inner
            .parse_cookie(
                BASE64
                    .decode(cookie.unwrap().as_bytes())
                    .map_err(|err| anyhow!("Cookie base64 error: {}", err))?
                    .as_slice(),
            )
            .map_err(|err| anyhow!("{}", err))?;

        self.inner
            .verify_token_pair(&token, &cookie)
            .map_err(|err| anyhow!("Cookie base64 error: {}", err))
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
    ) -> PhpResult<()> {
        let name = self.cookie_name.clone();
        let value = self.cookie.b64_string();
        let expires = expires.unwrap_or(0);
        let path = path.unwrap_or_else(|| "/".to_string());
        let domain = domain.unwrap_or_default();
        let secure = secure.unwrap_or(false);
        let httponly = httponly.unwrap_or(true);

        Function::try_from_function("setcookie")
            .ok_or_else(|| anyhow!("Could not call setcookie"))?
            .try_call(vec![
                &name, &value, &expires, &path, &domain, &secure, &httponly,
            ])?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Csrf;
    use crate::run_php_example;
    use anyhow::Result;
    use data_encoding::BASE64URL;

    /// Helper to generate a Base64URL-encoded 32-byte zero key.
    fn zero_key_b64() -> String {
        let key = [0u8; 32];
        BASE64URL.encode(&key)
    }

    #[test]
    fn test_construct_and_token_cookie() -> Result<()> {
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
    fn test_verify_token_fails_with_bad_token() -> Result<()> {
        let key = zero_key_b64();
        let csrf = Csrf::__construct(&key, 60, None)?;
        let bad_token = "invalid.token.value";
        let good_cookie = csrf.cookie();
        let err = csrf.verify_token(bad_token, Some(good_cookie)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Token base64 error") || msg.contains("parse_token"),
            "Unexpected error: {msg}"
        );
        Ok(())
    }

    #[test]
    fn test_verify_token_fails_with_bad_cookie() -> Result<()> {
        let key = zero_key_b64();
        let csrf = Csrf::__construct(&key, 60, None)?;
        let good_token = csrf.token();
        let bad_cookie = "invalid_cookie";
        let err = csrf
            .verify_token(&good_token, Some(bad_cookie.to_string()))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Cookie base64 error") || msg.contains("verify_token_pair"),
            "Unexpected error: {msg}"
        );
        Ok(())
    }

    #[test]
    fn test_cookie_name_get_set() -> Result<()> {
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
    fn php_example() -> Result<()> {
        run_php_example("csrf-protection")?;
        Ok(())
    }
}
