use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use thiserror::Error;

// Error codes for filename errors: 2600-2699
pub mod error_codes {
    pub const UNSAFE_FILENAME: i32 = 2600;
}

/// Errors that can occur during filename sanitization.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Unsafe filename: {0}")]
    UnsafeFilename(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::UnsafeFilename(_) => error_codes::UNSAFE_FILENAME,
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

/// Result type alias for filename operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Windows reserved device names; a filename whose first dot-separated
/// component matches one of these (case-insensitively) refers to a device.
const RESERVED_WINDOWS_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Extensions that execute on common server/desktop setups; any of these
/// appearing anywhere in the extension chain (`invoice.pdf.php`) is a red flag.
const DANGEROUS_EXTENSIONS: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar", "pht", "phps", "cgi", "pl",
    "py", "sh", "bash", "asp", "aspx", "jsp", "jspx", "exe", "com", "scr", "bat", "cmd", "ps1",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "msi", "jar", "hta", "cpl", "dll", "htaccess",
    "htpasswd",
];

/// Unicode characters that are invisible or reorder text: zero-widths, the
/// bidi embedding/override/isolate controls (U+202E RLO turns
/// `invoice_exe.doc` into `invoice_cod.exe` visually), word joiner and BOM.
fn is_invisible_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Maximum byte length for a sanitized filename; common filesystem limit.
const MAX_FILENAME_BYTES: usize = 255;

/// Safe filenames for downloads and uploads.
///
/// Client-supplied filenames are attacker input: path separators climb
/// directories, control bytes and Unicode bidi overrides spoof what the user
/// sees (`U+202E` makes `…cod.exe` display as `…exe.doc`), reserved Windows
/// device names (`CON`, `NUL`, `COM1`) break file handling, trailing
/// dots/spaces round-trip differently on Windows, and double extensions
/// (`invoice.pdf.php`) turn an upload into code execution.
#[php_class]
#[php(name = "Hardened\\Filename")]
pub struct Filename {}

impl Filename {
    fn _sanitize(filename: &str, replacement: &str) -> String {
        // Take the last path component: anything before / or \ is traversal.
        let base = filename
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(filename)
            .trim();

        let mut out = String::with_capacity(base.len());
        for c in base.chars() {
            if c.is_control() || is_invisible_or_bidi(c) {
                continue;
            }
            // Forbidden on Windows; ':' also carries ADS semantics there.
            if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                out.push_str(replacement);
            } else {
                out.push(c);
            }
        }

        // Trailing dots and spaces are stripped by Windows on creation,
        // making names round-trip inconsistently. Leading dots hide files
        // and enable ".htaccess"-style uploads.
        let trimmed = out.trim_matches([' ', '.']);

        let mut result = if trimmed.is_empty() {
            "file".to_string()
        } else {
            trimmed.to_string()
        };

        // Neutralize reserved Windows device names (checked against the
        // part before the first dot, per Windows semantics).
        let stem = result.split('.').next().unwrap_or(&result);
        if RESERVED_WINDOWS_NAMES
            .iter()
            .any(|name| stem.eq_ignore_ascii_case(name))
        {
            result.insert(0, '_');
        }

        // Cap length on a char boundary.
        if result.len() > MAX_FILENAME_BYTES {
            let mut end = MAX_FILENAME_BYTES;
            while !result.is_char_boundary(end) {
                end -= 1;
            }
            result.truncate(end);
            let retrimmed = result.trim_end_matches([' ', '.']).len();
            result.truncate(retrimmed);
        }

        result
    }

    fn _is_safe(filename: &str) -> bool {
        !filename.is_empty()
            && Self::_sanitize(filename, "_") == filename
            && !Self::_has_dangerous_extension(filename)
    }

    fn _has_dangerous_extension(filename: &str) -> bool {
        filename.split('.').skip(1).any(|extension| {
            let extension = extension.trim().to_ascii_lowercase();
            DANGEROUS_EXTENSIONS.contains(&extension.as_str())
        })
    }

    fn _has_double_extension(filename: &str) -> bool {
        let parts: Vec<&str> = filename.split('.').collect();
        parts.len() > 2 && parts.iter().skip(1).all(|part| !part.is_empty())
    }

    /// RFC 5987 / 8187 percent-encoding for the `filename*` parameter:
    /// attr-char stays literal, everything else is percent-encoded.
    fn _rfc5987_encode(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for byte in value.bytes() {
            match byte {
                b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'!'
                | b'#'
                | b'$'
                | b'&'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~' => out.push(byte as char),
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }

    fn _content_disposition(filename: &str, inline: bool) -> String {
        let sanitized = Self::_sanitize(filename, "_");
        // ASCII fallback for the quoted `filename` parameter.
        let ascii: String = sanitized
            .chars()
            .map(|c| {
                if c.is_ascii() && c != '"' && c != '\\' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let disposition = if inline { "inline" } else { "attachment" };
        if ascii == sanitized {
            format!("{disposition}; filename=\"{ascii}\"")
        } else {
            format!(
                "{disposition}; filename=\"{ascii}\"; filename*=UTF-8''{}",
                Self::_rfc5987_encode(&sanitized)
            )
        }
    }
}

#[php_impl]
impl Filename {
    /// Sanitizes a client-supplied filename for safe storage and display.
    ///
    /// Keeps only the last path component; removes control bytes and
    /// invisible/bidi-override characters; replaces Windows-forbidden
    /// punctuation; strips leading/trailing dots and spaces; neutralizes
    /// reserved Windows device names; caps the length at 255 bytes. Returns
    /// `"file"` if nothing survives.
    ///
    /// # Parameters
    /// - `filename`: The untrusted filename.
    /// - `replacement`: Replacement for forbidden punctuation (defaults to `"_"`).
    ///
    /// # Returns
    /// - `string`: The sanitized filename.
    fn sanitize(filename: &str, replacement: Option<String>) -> String {
        Self::_sanitize(filename, replacement.as_deref().unwrap_or("_"))
    }

    /// Checks whether a filename is already safe: it survives `sanitize()`
    /// unchanged and carries no dangerous extension anywhere in its chain.
    ///
    /// # Parameters
    /// - `filename`: The filename to check.
    ///
    /// # Returns
    /// - `bool`: `true` if the filename is safe as-is.
    fn is_safe(filename: &str) -> bool {
        Self::_is_safe(filename)
    }

    /// Checks whether any extension in the chain (not just the last) is an
    /// executable/server-interpreted type: `invoice.pdf.php`, `shell.php.jpg`
    /// and `run.exe` all return `true`.
    ///
    /// # Parameters
    /// - `filename`: The filename to check.
    ///
    /// # Returns
    /// - `bool`: `true` if a dangerous extension is present.
    fn has_dangerous_extension(filename: &str) -> bool {
        Self::_has_dangerous_extension(filename)
    }

    /// Checks whether the filename has more than one extension
    /// (`invoice.pdf.exe`), a common social-engineering pattern.
    ///
    /// # Parameters
    /// - `filename`: The filename to check.
    ///
    /// # Returns
    /// - `bool`: `true` if multiple extensions are present.
    fn has_double_extension(filename: &str) -> bool {
        Self::_has_double_extension(filename)
    }

    /// Builds a safe `Content-Disposition` header value for a download:
    /// the filename is sanitized, an ASCII fallback goes into `filename=`,
    /// and non-ASCII names additionally get an RFC 5987 `filename*=` form.
    ///
    /// ```php
    /// header("Content-Disposition: " . Filename::contentDisposition($name));
    /// ```
    ///
    /// # Parameters
    /// - `filename`: The untrusted filename.
    /// - `inline`: Use `inline` instead of `attachment` (defaults to `false`).
    ///
    /// # Returns
    /// - `string`: The header value, e.g.
    ///   `attachment; filename="report.pdf"`.
    fn content_disposition(filename: &str, inline: Option<bool>) -> String {
        Self::_content_disposition(filename, inline.unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::Filename;
    use crate::run_php_example;

    #[test]
    fn test_path_traversal_stripped() {
        assert_eq!(Filename::_sanitize("../../etc/passwd", "_"), "passwd");
        assert_eq!(Filename::_sanitize("..\\..\\boot.ini", "_"), "boot.ini");
        assert_eq!(Filename::_sanitize("/etc/shadow", "_"), "shadow");
        assert_eq!(Filename::_sanitize("a/b/c.txt", "_"), "c.txt");
    }

    #[test]
    fn test_controls_and_bidi_removed() {
        assert_eq!(Filename::_sanitize("re\x00port.pdf", "_"), "report.pdf");
        assert_eq!(Filename::_sanitize("re\nport.pdf", "_"), "report.pdf");
        // U+202E RLO: "invoice_\u{202E}cod.exe" displays as "invoice_exe.doc"
        assert_eq!(
            Filename::_sanitize("invoice_\u{202E}cod.exe", "_"),
            "invoice_cod.exe"
        );
        assert_eq!(
            Filename::_sanitize("a\u{200B}b\u{FEFF}c.txt", "_"),
            "abc.txt"
        );
    }

    #[test]
    fn test_windows_quirks() {
        assert_eq!(Filename::_sanitize("CON", "_"), "_CON");
        assert_eq!(Filename::_sanitize("con.txt", "_"), "_con.txt");
        assert_eq!(Filename::_sanitize("COM1.pdf", "_"), "_COM1.pdf");
        assert_eq!(Filename::_sanitize("Console.txt", "_"), "Console.txt");
        assert_eq!(Filename::_sanitize("report.pdf...", "_"), "report.pdf");
        assert_eq!(Filename::_sanitize("report.pdf   ", "_"), "report.pdf");
        assert_eq!(Filename::_sanitize("a<b>c:d.txt", "_"), "a_b_c_d.txt");
    }

    #[test]
    fn test_hidden_and_empty() {
        assert_eq!(Filename::_sanitize(".htaccess", "_"), "htaccess");
        assert_eq!(Filename::_sanitize("...", "_"), "file");
        assert_eq!(Filename::_sanitize("", "_"), "file");
        assert_eq!(Filename::_sanitize("\u{202E}\u{200B}", "_"), "file");
    }

    #[test]
    fn test_length_cap() {
        let long = format!("{}.txt", "a".repeat(300));
        let sanitized = Filename::_sanitize(&long, "_");
        assert!(sanitized.len() <= 255);
        let unicode = "é".repeat(200);
        let sanitized = Filename::_sanitize(&unicode, "_");
        assert!(sanitized.len() <= 255);
        assert!(sanitized.chars().all(|c| c == 'é'));
    }

    #[test]
    fn test_dangerous_and_double_extensions() {
        assert!(Filename::_has_dangerous_extension("invoice.pdf.php"));
        assert!(Filename::_has_dangerous_extension("shell.php.jpg"));
        assert!(Filename::_has_dangerous_extension("run.exe"));
        assert!(Filename::_has_dangerous_extension("a.PHTML"));
        assert!(!Filename::_has_dangerous_extension("report.pdf"));
        assert!(!Filename::_has_dangerous_extension("archive.tar.gz"));

        assert!(Filename::_has_double_extension("invoice.pdf.exe"));
        assert!(Filename::_has_double_extension("archive.tar.gz"));
        assert!(!Filename::_has_double_extension("report.pdf"));
        assert!(!Filename::_has_double_extension("no_extension"));
    }

    #[test]
    fn test_is_safe() {
        assert!(Filename::_is_safe("report.pdf"));
        assert!(Filename::_is_safe("photo-2026_06.jpg"));
        assert!(!Filename::_is_safe("../report.pdf"));
        assert!(!Filename::_is_safe("shell.php.jpg"));
        assert!(!Filename::_is_safe("CON.txt"));
        assert!(!Filename::_is_safe("report.pdf."));
        assert!(!Filename::_is_safe(""));
    }

    #[test]
    fn test_content_disposition() {
        assert_eq!(
            Filename::_content_disposition("report.pdf", false),
            "attachment; filename=\"report.pdf\""
        );
        assert_eq!(
            Filename::_content_disposition("../evil.pdf", true),
            "inline; filename=\"evil.pdf\""
        );
        // Quotes can't break out of the quoted string (backslash is a
        // path separator, so only the last component survives anyway)
        assert_eq!(
            Filename::_content_disposition("a\"b.pdf", false),
            "attachment; filename=\"a_b.pdf\""
        );
        assert_eq!(
            Filename::_content_disposition("a\"b\\c.pdf", false),
            "attachment; filename=\"c.pdf\""
        );
        // Non-ASCII gets the RFC 5987 form alongside an ASCII fallback
        assert_eq!(
            Filename::_content_disposition("отчёт.pdf", false),
            "attachment; filename=\"_____.pdf\"; filename*=UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf"
        );
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("filename")?;
        Ok(())
    }
}
