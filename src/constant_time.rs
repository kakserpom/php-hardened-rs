use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use ext_php_rs::binary_slice::BinarySlice;
use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use subtle::ConstantTimeEq;
use thiserror::Error;

// Error codes for constant-time comparison errors: 1900-1999
pub mod error_codes {
    pub const INVALID_HEX: i32 = 1900;
    pub const INVALID_BASE64: i32 = 1901;
}

/// Errors that can occur during constant-time comparison operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid hex encoding: {0}")]
    InvalidHex(String),

    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidHex(_) => error_codes::INVALID_HEX,
            Error::InvalidBase64(_) => error_codes::INVALID_BASE64,
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

/// Result type alias for constant-time comparison operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Constant-time (timing-safe) comparison helpers.
///
/// Comparing secrets (tokens, HMACs, signatures, API keys) with `==`/`===`
/// leaks how many leading bytes matched through timing. These helpers compare
/// in constant time with respect to the contents of the inputs.
/// Only the *length* of the inputs is observable.
#[php_class]
#[php(name = "Hardened\\ConstantTime")]
pub struct ConstantTime {}

impl ConstantTime {
    fn _equals(a: &[u8], b: &[u8]) -> bool {
        a.ct_eq(b).into()
    }

    fn _equals_hex(a: &str, b: &str) -> Result<bool> {
        let a = HEXLOWER_PERMISSIVE
            .decode(a.as_bytes())
            .map_err(|e| Error::InvalidHex(e.to_string()))?;
        let b = HEXLOWER_PERMISSIVE
            .decode(b.as_bytes())
            .map_err(|e| Error::InvalidHex(e.to_string()))?;
        Ok(Self::_equals(&a, &b))
    }

    fn _equals_base64(a: &str, b: &str) -> Result<bool> {
        let a = BASE64
            .decode(a.as_bytes())
            .map_err(|e| Error::InvalidBase64(e.to_string()))?;
        let b = BASE64
            .decode(b.as_bytes())
            .map_err(|e| Error::InvalidBase64(e.to_string()))?;
        Ok(Self::_equals(&a, &b))
    }
}

#[php_impl]
impl ConstantTime {
    /// Compares two byte strings in constant time.
    ///
    /// Drop-in replacement for `hash_equals()` that does not care which
    /// argument is the user-supplied one. Binary-safe.
    ///
    /// # Parameters
    /// - `a`: First string.
    /// - `b`: Second string.
    ///
    /// # Returns
    /// - `bool`: `true` if the strings are equal.
    #[allow(clippy::needless_pass_by_value)]
    fn equals(a: BinarySlice<u8>, b: BinarySlice<u8>) -> bool {
        Self::_equals(&a, &b)
    }

    /// Decodes two hex strings and compares the decoded bytes in constant time.
    ///
    /// Use this when comparing hex digests (e.g. `hash_hmac(..., false)`),
    /// so that case differences (`"AB"` vs `"ab"`) do not cause a mismatch.
    ///
    /// # Parameters
    /// - `a`: First hex string (case-insensitive).
    /// - `b`: Second hex string (case-insensitive).
    ///
    /// # Returns
    /// - `bool`: `true` if the decoded bytes are equal.
    ///
    /// # Exceptions
    /// - Throws an exception if either string is not valid hex.
    fn equals_hex(a: &str, b: &str) -> Result<bool> {
        Self::_equals_hex(a, b)
    }

    /// Decodes two base64 strings and compares the decoded bytes in constant time.
    ///
    /// # Parameters
    /// - `a`: First base64 string (standard alphabet, with padding).
    /// - `b`: Second base64 string (standard alphabet, with padding).
    ///
    /// # Returns
    /// - `bool`: `true` if the decoded bytes are equal.
    ///
    /// # Exceptions
    /// - Throws an exception if either string is not valid base64.
    fn equals_base64(a: &str, b: &str) -> Result<bool> {
        Self::_equals_base64(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::ConstantTime;
    use crate::run_php_example;

    #[test]
    fn test_equals() {
        assert!(ConstantTime::_equals(b"secret-token", b"secret-token"));
        assert!(!ConstantTime::_equals(b"secret-token", b"secret-tokeN"));
        assert!(!ConstantTime::_equals(b"short", b"longer-string"));
        assert!(ConstantTime::_equals(b"", b""));
        assert!(ConstantTime::_equals(b"\x00\x01\x02", b"\x00\x01\x02"));
    }

    #[test]
    fn test_equals_hex() {
        assert!(ConstantTime::_equals_hex("deadbeef", "DEADBEEF").unwrap());
        assert!(!ConstantTime::_equals_hex("deadbeef", "deadbeee").unwrap());
        assert!(ConstantTime::_equals_hex("", "").unwrap());
        assert!(ConstantTime::_equals_hex("zz", "zz").is_err());
    }

    #[test]
    fn test_equals_base64() {
        assert!(ConstantTime::_equals_base64("aGVsbG8=", "aGVsbG8=").unwrap());
        assert!(!ConstantTime::_equals_base64("aGVsbG8=", "aGVsbG9v").unwrap());
        assert!(ConstantTime::_equals_base64("!!!", "!!!").is_err());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("constant-time")?;
        Ok(())
    }
}
