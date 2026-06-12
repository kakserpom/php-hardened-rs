use ext_php_rs::binary::Binary;
use ext_php_rs::binary_slice::BinarySlice;
use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use thiserror::Error;

// Error codes for Text errors: 2100-2199
pub mod error_codes {
    pub const NULL_BYTE: i32 = 2100;
    pub const HEADER_INJECTION: i32 = 2101;
}

/// Errors that can occur during text sanitization operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("String contains a null byte at offset {0}")]
    NullByte(usize),

    #[error("Header value contains a forbidden control byte (0x{0:02x}) at offset {1}")]
    HeaderInjection(u8, usize),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::NullByte(_) => error_codes::NULL_BYTE,
            Error::HeaderInjection(_, _) => error_codes::HEADER_INJECTION,
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

/// Result type alias for text sanitization operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Returns `true` if `byte` is a C0 control byte (`0x00`–`0x1f`) or DEL (`0x7f`).
#[inline]
const fn is_c0_or_del(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

/// Returns `true` if the two bytes form a UTF-8 encoded C1 control
/// character (U+0080–U+009F, encoded as `0xc2 0x80`–`0xc2 0x9f`).
#[inline]
const fn is_utf8_c1(first: u8, second: u8) -> bool {
    first == 0xc2 && second >= 0x80 && second <= 0x9f
}

/// Control-character and protocol-injection sanitizers.
///
/// Untrusted strings carrying control bytes are a recurring injection vector:
/// CR/LF in HTTP/SMTP headers (response splitting, header injection), CR/LF in
/// log lines (log forging), null bytes in paths (truncation), and field
/// separators (`0x00`, `0x01`, …) in delimited backend protocols. These
/// helpers strip or reject such bytes. All methods are binary-safe.
#[php_class]
#[php(name = "Hardened\\Text")]
pub struct Text {}

impl Text {
    /// Removes C0 controls (except those in `keep`), DEL, and UTF-8 encoded
    /// C1 controls from `input`.
    fn _strip_controls(input: &[u8], keep: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            let byte = input[i];
            if i + 1 < input.len() && is_utf8_c1(byte, input[i + 1]) {
                i += 2;
                continue;
            }
            if is_c0_or_del(byte) && !keep.contains(&byte) {
                i += 1;
                continue;
            }
            out.push(byte);
            i += 1;
        }
        out
    }

    /// Returns `true` if `input` contains a C0 control (not in `keep`), DEL,
    /// or a UTF-8 encoded C1 control.
    fn _has_controls(input: &[u8], keep: &[u8]) -> bool {
        let mut i = 0;
        while i < input.len() {
            let byte = input[i];
            if i + 1 < input.len() && is_utf8_c1(byte, input[i + 1]) {
                return true;
            }
            if is_c0_or_del(byte) && !keep.contains(&byte) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Strips everything `_strip_controls` strips, keeping only horizontal tabs.
    fn _sanitize_log_line(input: &[u8]) -> Vec<u8> {
        Self::_strip_controls(input, b"\t")
    }

    /// Rejects CR, LF and NUL; strips all other controls except horizontal tab.
    fn _sanitize_header_value(input: &[u8]) -> Result<Vec<u8>> {
        if let Some(pos) = input
            .iter()
            .position(|&b| b == b'\r' || b == b'\n' || b == 0)
        {
            return Err(Error::HeaderInjection(input[pos], pos));
        }
        Ok(Self::_strip_controls(input, b"\t"))
    }

    fn _assert_no_null_bytes(input: &[u8]) -> Result<()> {
        if let Some(pos) = input.iter().position(|&b| b == 0) {
            return Err(Error::NullByte(pos));
        }
        Ok(())
    }
}

#[php_impl]
impl Text {
    /// Removes control characters from a string.
    ///
    /// Strips C0 controls (`0x00`–`0x1f`), DEL (`0x7f`), and UTF-8 encoded C1
    /// controls (U+0080–U+009F), except the bytes listed in `keep`.
    ///
    /// # Parameters
    /// - `input`: The string to sanitize.
    /// - `keep`: Control bytes to preserve (defaults to `"\t\n\r"`).
    ///
    /// # Returns
    /// - `string`: The sanitized string.
    fn strip_controls(input: BinarySlice<u8>, keep: Option<BinarySlice<u8>>) -> Binary<u8> {
        let keep: &[u8] = keep.map(<&[u8]>::from).unwrap_or(b"\t\n\r");
        Binary::from(Self::_strip_controls(&input, keep))
    }

    /// Checks whether a string contains control characters.
    ///
    /// Detects C0 controls (`0x00`–`0x1f`), DEL (`0x7f`), and UTF-8 encoded C1
    /// controls (U+0080–U+009F), except the bytes listed in `keep`.
    ///
    /// # Parameters
    /// - `input`: The string to inspect.
    /// - `keep`: Control bytes to allow (defaults to none).
    ///
    /// # Returns
    /// - `bool`: `true` if any control character is present.
    fn has_controls(input: BinarySlice<u8>, keep: Option<BinarySlice<u8>>) -> bool {
        let keep: &[u8] = keep.map(<&[u8]>::from).unwrap_or(b"");
        Self::_has_controls(&input, keep)
    }

    /// Sanitizes a string for safe inclusion in a log line.
    ///
    /// Strips CR, LF and all other control characters (C0, DEL, UTF-8 C1)
    /// except horizontal tab, preventing log forging via injected line breaks
    /// or terminal escape sequences.
    ///
    /// # Parameters
    /// - `input`: The untrusted string to log.
    ///
    /// # Returns
    /// - `string`: The sanitized string, safe to embed in a single log line.
    fn sanitize_log_line(input: BinarySlice<u8>) -> Binary<u8> {
        Binary::from(Self::_sanitize_log_line(&input))
    }

    /// Validates and sanitizes a string for use as an HTTP (or SMTP) header value.
    ///
    /// Throws if the value contains CR, LF or NUL (response splitting /
    /// header injection); strips all other control characters except
    /// horizontal tab, which is legal in header values per RFC 7230.
    ///
    /// # Parameters
    /// - `input`: The untrusted header value.
    ///
    /// # Returns
    /// - `string`: The sanitized header value.
    ///
    /// # Exceptions
    /// - Throws an exception if the value contains CR, LF, or NUL.
    fn sanitize_header_value(input: BinarySlice<u8>) -> Result<Binary<u8>> {
        Ok(Binary::from(Self::_sanitize_header_value(&input)?))
    }

    /// Asserts that a string contains no null bytes.
    ///
    /// Null bytes in filenames and paths cause truncation in C APIs and are
    /// a classic path/filename bypass. Returns the input unchanged if clean.
    ///
    /// # Parameters
    /// - `input`: The string to check.
    ///
    /// # Returns
    /// - `string`: The input, unchanged.
    ///
    /// # Exceptions
    /// - Throws an exception if the string contains a null byte.
    fn assert_no_null_bytes(input: BinarySlice<u8>) -> Result<Binary<u8>> {
        Self::_assert_no_null_bytes(&input)?;
        Ok(Binary::from(input.to_vec()))
    }

    /// Checks whether a string contains a null byte.
    ///
    /// # Parameters
    /// - `input`: The string to check.
    ///
    /// # Returns
    /// - `bool`: `true` if a null byte is present.
    fn has_null_bytes(input: BinarySlice<u8>) -> bool {
        input.contains(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::Text;
    use crate::run_php_example;

    #[test]
    fn test_strip_controls() {
        assert_eq!(
            Text::_strip_controls(b"a\x00b\x01c\x1bd\x7fe", b""),
            b"abcde"
        );
        assert_eq!(
            Text::_strip_controls(b"line1\r\nline2\ttab", b"\t\n\r"),
            b"line1\r\nline2\ttab"
        );
        // UTF-8 C1 control (U+0085 NEL) is removed, other multibyte stays
        assert_eq!(
            Text::_strip_controls("a\u{85}b\u{e9}".as_bytes(), b""),
            "ab\u{e9}".as_bytes()
        );
    }

    #[test]
    fn test_has_controls() {
        assert!(Text::_has_controls(b"a\x01b", b""));
        assert!(Text::_has_controls(b"a\nb", b""));
        assert!(!Text::_has_controls(b"a\nb", b"\n"));
        assert!(Text::_has_controls("a\u{85}b".as_bytes(), b""));
        assert!(!Text::_has_controls(b"plain text", b""));
    }

    #[test]
    fn test_sanitize_log_line() {
        assert_eq!(
            Text::_sanitize_log_line(b"user\r\n[FAKE] admin logged in\x1b[31m"),
            b"user[FAKE] admin logged in[31m"
        );
        assert_eq!(Text::_sanitize_log_line(b"keep\ttab"), b"keep\ttab");
    }

    #[test]
    fn test_sanitize_header_value() {
        assert!(Text::_sanitize_header_value(b"evil\r\nSet-Cookie: x").is_err());
        assert!(Text::_sanitize_header_value(b"evil\x00").is_err());
        assert_eq!(
            Text::_sanitize_header_value(b"ok\x01 value\t").unwrap(),
            b"ok value\t"
        );
    }

    #[test]
    fn test_null_bytes() {
        assert!(Text::_assert_no_null_bytes(b"file.php\x00.jpg").is_err());
        assert!(Text::_assert_no_null_bytes(b"file.jpg").is_ok());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("text")?;
        Ok(())
    }
}
