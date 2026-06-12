use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use regex::Regex;
use thiserror::Error;

// Error codes for secret redaction errors: 2900-2999
pub mod error_codes {
    pub const INVALID_PATTERN: i32 = 2900;
}

/// Errors that can occur during secret redaction.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid redaction pattern: {0}")]
    InvalidPattern(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidPattern(_) => error_codes::INVALID_PATTERN,
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

/// Result type alias for redaction operations.
pub type Result<T> = std::result::Result<T, Error>;

const MASK: &str = "[REDACTED]";

/// `(pattern, replacement)` pairs applied in order. Replacements may use
/// `$1`-style group references.
const DEFAULT_PATTERNS: &[(&str, &str)] = &[
    // Authorization / Proxy-Authorization header values
    (
        r"(?i)\b((?:proxy-)?authorization\s*:\s*(?:(?:bearer|basic|digest|token|negotiate|ntlm)\s+)?)[^\s,;]+",
        "$1[REDACTED]",
    ),
    // Cookie / Set-Cookie header values
    (r"(?i)\b((?:set-)?cookie\s*:\s*)[^\r\n]+", "$1[REDACTED]"),
    // PEM private key blocks
    (
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        "[REDACTED]",
    ),
    // JWTs
    (
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*",
        "[REDACTED]",
    ),
    // Provider-recognizable tokens: AWS, GitHub, Slack, Stripe, Google
    (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED]"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[REDACTED]"),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "[REDACTED]"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "[REDACTED]"),
    (r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b", "[REDACTED]"),
    (r"\bAIza[0-9A-Za-z_-]{35}\b", "[REDACTED]"),
    // Generic key/value assignments: password=..., "api_key": "...", etc.
    (
        r#"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?id|client[_-]?secret|private[_-]?key)(["']?\s*[=:]\s*["']?)[^\s"',;&]+"#,
        "$1$2[REDACTED]",
    ),
];

/// Returns `true` if `digits` passes the Luhn checksum.
fn luhn(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            let d = u32::from(d - b'0');
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Secret redactor for logs, error reports, and support dumps.
///
/// Masks `Authorization`/`Cookie` header values, PEM private keys, JWTs,
/// well-known provider tokens (AWS, GitHub, Slack, Stripe, Google), generic
/// `password=`/`"api_key":` assignments, and Luhn-valid payment card numbers
/// (PCI) — keeping the last four digits for correlation. Patterns are
/// pluggable via `addPattern()`.
#[php_class]
#[php(name = "Hardened\\SecretRedactor")]
pub struct SecretRedactor {
    patterns: Vec<(Regex, String)>,
    redact_card_numbers: bool,
}

impl SecretRedactor {
    fn _new(defaults: bool) -> Self {
        let patterns = if defaults {
            DEFAULT_PATTERNS
                .iter()
                .map(|(pattern, replacement)| {
                    (
                        Regex::new(pattern).expect("built-in pattern is valid"),
                        (*replacement).to_string(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        Self {
            patterns,
            redact_card_numbers: true,
        }
    }

    /// Masks Luhn-valid card numbers (13–19 digits, optionally separated by
    /// spaces or dashes), preserving separators and the last four digits.
    fn _redact_pans(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = String::with_capacity(input.len());
        let mut segment_start = 0;
        let mut i = 0;
        while i < bytes.len() {
            if !bytes[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            // Extend a candidate run of digits with space/dash separators.
            let run_start = i;
            let mut last_digit = i;
            let mut j = i;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit() || bytes[j] == b' ' || bytes[j] == b'-')
            {
                if bytes[j].is_ascii_digit() {
                    last_digit = j;
                }
                j += 1;
            }
            let run = &input[run_start..=last_digit];
            let digits: Vec<u8> = run.bytes().filter(u8::is_ascii_digit).collect();
            if (13..=19).contains(&digits.len()) && luhn(&digits) {
                out.push_str(&input[segment_start..run_start]);
                let mask_until = digits.len() - 4;
                let mut seen = 0;
                for byte in run.bytes() {
                    if byte.is_ascii_digit() {
                        out.push(if seen < mask_until { '*' } else { byte as char });
                        seen += 1;
                    } else {
                        out.push(byte as char);
                    }
                }
                segment_start = last_digit + 1;
            }
            i = last_digit + 1;
        }
        out.push_str(&input[segment_start..]);
        out
    }

    fn _redact(&self, input: &str) -> String {
        let mut output = input.to_string();
        for (pattern, replacement) in &self.patterns {
            output = pattern
                .replace_all(&output, replacement.as_str())
                .into_owned();
        }
        if self.redact_card_numbers {
            output = Self::_redact_pans(&output);
        }
        output
    }
}

#[php_impl]
impl SecretRedactor {
    /// Constructs a redactor.
    ///
    /// # Parameters
    /// - `defaults`: Load the built-in pattern set (defaults to `true`).
    fn __construct(defaults: Option<bool>) -> Self {
        Self::_new(defaults.unwrap_or(true))
    }

    /// Adds a custom redaction pattern, applied after the existing ones.
    ///
    /// # Parameters
    /// - `pattern`: A regular expression (Rust regex syntax — no lookarounds).
    /// - `replacement`: Replacement text; `$1`-style group references work
    ///   (defaults to `"[REDACTED]"`).
    ///
    /// # Exceptions
    /// - Throws an exception if the pattern fails to compile.
    fn add_pattern(&mut self, pattern: &str, replacement: Option<String>) -> Result<()> {
        self.patterns.push((
            Regex::new(pattern).map_err(|e| Error::InvalidPattern(e.to_string()))?,
            replacement.unwrap_or_else(|| MASK.to_string()),
        ));
        Ok(())
    }

    /// Enables or disables Luhn-aware card number masking (default: enabled).
    ///
    /// # Parameters
    /// - `redact`: Whether to mask Luhn-valid card numbers.
    fn set_redact_card_numbers(&mut self, redact: bool) {
        self.redact_card_numbers = redact;
    }

    /// Redacts secrets from the given text.
    ///
    /// # Parameters
    /// - `input`: Text that may contain secrets (log line, exception trace,
    ///   request dump).
    ///
    /// # Returns
    /// - `string`: The text with secrets masked.
    fn redact(&self, input: &str) -> String {
        self._redact(input)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretRedactor;
    use crate::run_php_example;

    fn redactor() -> SecretRedactor {
        SecretRedactor::_new(true)
    }

    #[test]
    fn test_authorization_and_cookie_headers() {
        let r = redactor();
        assert_eq!(
            r._redact("Authorization: Bearer secret-token-value"),
            "Authorization: Bearer [REDACTED]"
        );
        assert_eq!(
            r._redact("authorization: Basic dXNlcjpwYXNz"),
            "authorization: Basic [REDACTED]"
        );
        assert_eq!(
            r._redact("Cookie: session=abc; theme=dark"),
            "Cookie: [REDACTED]"
        );
        assert_eq!(
            r._redact("Set-Cookie: session=abc; HttpOnly"),
            "Set-Cookie: [REDACTED]"
        );
    }

    #[test]
    fn test_tokens_and_keys() {
        let r = redactor();
        assert_eq!(
            r._redact("key AKIAIOSFODNN7EXAMPLE in env"),
            "key [REDACTED] in env"
        );
        assert_eq!(
            r._redact("token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
            "token [REDACTED]"
        );
        assert_eq!(
            r._redact("slack xoxb-123456789012-abcdefghij"),
            "slack [REDACTED]"
        );
        assert!(
            !r._redact("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig-part")
                .contains("eyJ")
        );
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        assert_eq!(r._redact(pem), "[REDACTED]");
    }

    #[test]
    fn test_generic_assignments() {
        let r = redactor();
        assert_eq!(
            r._redact("password=hunter2 user=bob"),
            "password=[REDACTED] user=bob"
        );
        assert_eq!(
            r._redact(r#"{"api_key": "abc123", "name": "x"}"#),
            r#"{"api_key": "[REDACTED]", "name": "x"}"#
        );
        assert_eq!(
            r._redact("client_secret: s3cr3t"),
            "client_secret: [REDACTED]"
        );
    }

    #[test]
    fn test_luhn_card_masking() {
        let r = redactor();
        // Valid test PANs
        assert_eq!(
            r._redact("paid with 4111111111111111 today"),
            "paid with ************1111 today"
        );
        assert_eq!(
            r._redact("card 4111 1111 1111 1111."),
            "card **** **** **** 1111."
        );
        assert_eq!(
            r._redact("card 5500-0000-0000-0004!"),
            "card ****-****-****-0004!"
        );
        // Luhn-invalid number is left alone
        assert_eq!(r._redact("ref 4111111111111112"), "ref 4111111111111112");
        // Too short / too long sequences are left alone
        assert_eq!(
            r._redact("zip 94103 phone 5551234"),
            "zip 94103 phone 5551234"
        );
        assert_eq!(
            r._redact("id 41111111111111111111111111"),
            "id 41111111111111111111111111"
        );
    }

    #[test]
    fn test_card_masking_toggle_and_custom_patterns() {
        let mut r = SecretRedactor::_new(true);
        r.set_redact_card_numbers(false);
        assert_eq!(r._redact("4111111111111111"), "4111111111111111");

        let mut r = SecretRedactor::_new(false);
        assert_eq!(r._redact("password=hunter2"), "password=hunter2");
        r.add_pattern(r"\binternal-[a-z0-9]+\b", None).unwrap();
        assert_eq!(r._redact("id internal-abc123"), "id [REDACTED]");
        assert!(r.add_pattern("(unclosed", None).is_err());
    }

    #[test]
    fn test_multiline_and_unicode_passthrough() {
        let r = redactor();
        let input = "пользователь вошёл\nAuthorization: Bearer tok\nдальше";
        let output = r._redact(input);
        assert!(output.contains("пользователь вошёл"));
        assert!(output.contains("Authorization: Bearer [REDACTED]"));
        assert!(output.contains("дальше"));
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("secret-redactor")?;
        Ok(())
    }
}
