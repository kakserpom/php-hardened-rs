use ext_php_rs::{php_class, php_impl};
use unicode_normalization::UnicodeNormalization;
use unicode_security::restriction_level::{RestrictionLevel, RestrictionLevelDetection};
use unicode_security::{GeneralSecurityProfile, MixedScript, skeleton};

/// Unicode characters that are invisible or reorder text: zero-widths, bidi
/// embedding/override/isolate controls, word joiner, BOM.
fn is_invisible_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Unicode hardening for identifiers people read: usernames, display names,
/// email local-parts, organization names.
///
/// Homoglyph attacks register `pаypal` (Cyrillic `а`) next to `paypal`;
/// zero-width characters make two distinct usernames render identically;
/// mixed-script strings smuggle look-alikes past exact-match checks. These
/// helpers implement UTS #39 (confusable skeletons, restriction levels,
/// identifier profile) and NFKC/NFC normalization.
#[php_class]
#[php(name = "Hardened\\Unicode")]
pub struct Unicode {}

impl Unicode {
    fn _skeleton(input: &str) -> String {
        skeleton(input).collect()
    }

    fn _restriction_level(input: &str) -> &'static str {
        match input.detect_restriction_level() {
            RestrictionLevel::ASCIIOnly => "ascii-only",
            RestrictionLevel::SingleScript => "single-script",
            RestrictionLevel::HighlyRestrictive => "highly-restrictive",
            RestrictionLevel::ModeratelyRestrictive => "moderately-restrictive",
            RestrictionLevel::MinimallyRestrictive => "minimally-restrictive",
            RestrictionLevel::Unrestricted => "unrestricted",
        }
    }
}

#[php_impl]
impl Unicode {
    /// Applies NFKC (compatibility) normalization. This is the right
    /// normalization before storing or comparing identifiers: it folds
    /// full-width letters, ligatures and font variants into their plain
    /// forms (`ｐａｙｐａｌ` → `paypal`, `ﬁ` → `fi`).
    ///
    /// # Parameters
    /// - `input`: The string to normalize.
    ///
    /// # Returns
    /// - `string`: The NFKC-normalized string.
    fn nfkc(input: &str) -> String {
        input.nfkc().collect()
    }

    /// Applies NFC (canonical) normalization — the form to use for general
    /// text where compatibility folding would lose meaning.
    ///
    /// # Parameters
    /// - `input`: The string to normalize.
    ///
    /// # Returns
    /// - `string`: The NFC-normalized string.
    fn nfc(input: &str) -> String {
        input.nfc().collect()
    }

    /// Computes the UTS #39 confusable skeleton. Two strings whose skeletons
    /// are equal look alike to a human (`pаypal` with a Cyrillic `а` has the
    /// skeleton `paypal`). Store the skeleton of each username and enforce
    /// uniqueness on it, not on the raw string.
    ///
    /// # Parameters
    /// - `input`: The string to skeletonize.
    ///
    /// # Returns
    /// - `string`: The confusable skeleton.
    fn skeleton(input: &str) -> String {
        Self::_skeleton(input)
    }

    /// Checks whether two strings are visually confusable per UTS #39
    /// (equal skeletons). Case matters; lowercase both first for
    /// case-insensitive identifier checks.
    ///
    /// # Parameters
    /// - `a`: First string.
    /// - `b`: Second string.
    ///
    /// # Returns
    /// - `bool`: `true` if the strings look alike.
    fn confusable(a: &str, b: &str) -> bool {
        Self::_skeleton(a) == Self::_skeleton(b)
    }

    /// Checks whether the string is written in a single Unicode script.
    /// Mixed-script identifiers (`раyраl` mixing Cyrillic and Latin) are the
    /// classic homoglyph-attack shape.
    ///
    /// # Parameters
    /// - `input`: The string to check.
    ///
    /// # Returns
    /// - `bool`: `true` if all characters resolve to one script.
    fn is_single_script(input: &str) -> bool {
        input.is_single_script()
    }

    /// Returns the UTS #39 restriction level of the string, from strictest
    /// to loosest: `ascii-only`, `single-script`, `highly-restrictive`,
    /// `moderately-restrictive`, `minimally-restrictive`, `unrestricted`.
    /// A sane policy for usernames is to require at least
    /// `highly-restrictive`.
    ///
    /// # Parameters
    /// - `input`: The string to classify.
    ///
    /// # Returns
    /// - `string`: The restriction level name.
    fn restriction_level(input: &str) -> &'static str {
        Self::_restriction_level(input)
    }

    /// Checks whether the string contains invisible or reordering
    /// characters: zero-widths (U+200B–U+200F), bidi embedding/override
    /// (U+202A–U+202E) and isolate (U+2066–U+2069) controls, word joiner,
    /// BOM.
    ///
    /// # Parameters
    /// - `input`: The string to check.
    ///
    /// # Returns
    /// - `bool`: `true` if invisible characters are present.
    fn has_invisible_characters(input: &str) -> bool {
        input.chars().any(is_invisible_or_bidi)
    }

    /// Removes invisible and reordering characters (see
    /// `hasInvisibleCharacters()`).
    ///
    /// # Parameters
    /// - `input`: The string to clean.
    ///
    /// # Returns
    /// - `string`: The string without invisible characters.
    fn strip_invisible_characters(input: &str) -> String {
        input
            .chars()
            .filter(|&c| !is_invisible_or_bidi(c))
            .collect()
    }

    /// Checks whether every character is allowed in identifiers by the
    /// UTS #39 General Security Profile (excludes deprecated, private-use,
    /// and purely-decorative characters).
    ///
    /// # Parameters
    /// - `input`: The string to check.
    ///
    /// # Returns
    /// - `bool`: `true` if all characters are identifier-safe.
    fn is_identifier_safe(input: &str) -> bool {
        input
            .chars()
            .all(GeneralSecurityProfile::identifier_allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::Unicode;
    use crate::run_php_example;

    #[test]
    fn test_nfkc_folds_fullwidth_and_ligatures() {
        assert_eq!(Unicode::nfkc("ｐａｙｐａｌ"), "paypal");
        assert_eq!(Unicode::nfkc("ﬁle"), "file");
        assert_eq!(Unicode::nfkc("①"), "1");
        // NFC keeps compatibility characters as-is
        assert_eq!(Unicode::nfc("ﬁle"), "ﬁle");
        assert_eq!(Unicode::nfc("e\u{301}"), "é");
    }

    #[test]
    fn test_confusable_homoglyphs() {
        // Cyrillic а/е/р/о vs Latin
        assert!(Unicode::confusable("pаypаl", "paypal"));
        assert!(Unicode::confusable("аdmin", "admin"));
        assert!(!Unicode::confusable("paypal", "paypa1l"));
        assert_eq!(Unicode::skeleton("pаypаl"), Unicode::skeleton("paypal"));
    }

    #[test]
    fn test_mixed_script_detection() {
        assert!(Unicode::is_single_script("paypal"));
        assert!(Unicode::is_single_script("пароль"));
        // Latin + Cyrillic mix
        assert!(!Unicode::is_single_script("pаypal"));
        // Common characters (digits, punctuation) do not break single-script
        assert!(Unicode::is_single_script("user-42"));
    }

    #[test]
    fn test_restriction_levels() {
        assert_eq!(Unicode::restriction_level("admin42"), "ascii-only");
        assert_eq!(Unicode::restriction_level("пароль"), "single-script");
        // Latin mixed with Cyrillic is beyond highly-restrictive
        assert!(matches!(
            Unicode::restriction_level("pаypal"),
            "minimally-restrictive" | "unrestricted"
        ));
    }

    #[test]
    fn test_invisible_characters() {
        assert!(Unicode::has_invisible_characters("ad\u{200B}min"));
        assert!(Unicode::has_invisible_characters("a\u{202E}b"));
        assert!(!Unicode::has_invisible_characters("admin"));
        assert_eq!(
            Unicode::strip_invisible_characters("ad\u{200B}min"),
            "admin"
        );
        assert_eq!(
            Unicode::strip_invisible_characters("\u{FEFF}a\u{2066}b\u{2069}"),
            "ab"
        );
    }

    #[test]
    fn test_identifier_safe() {
        assert!(Unicode::is_identifier_safe("admin"));
        assert!(Unicode::is_identifier_safe("пользователь"));
        // U+2028 line separator is not identifier material
        assert!(!Unicode::is_identifier_safe("a\u{2028}b"));
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("unicode")?;
        Ok(())
    }
}
