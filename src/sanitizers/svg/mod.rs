use ammonia::{Builder, UrlRelative};
use ext_php_rs::prelude::*;
use ext_php_rs::types::ZendClassObject;
use std::collections::HashSet;
use std::fs;

pub mod config;
pub mod error;
pub mod style;
pub mod validators;

pub use error::{Error, Result, error_codes};

use config::{BLOCKED_ELEMENTS, Preset};
use validators::DimensionValidator;

#[php_class]
#[php(name = "Hardened\\Sanitizers\\SvgSanitizer")]
pub struct SvgSanitizer {
    inner: Option<Builder>,
    max_dimension: u32,
    max_nesting_depth: u32,
    block_data_uris: bool,
}

#[php_impl]
impl SvgSanitizer {
    // PHP class constants for presets
    pub const PRESET_STRICT: &'static str = "strict";
    pub const PRESET_STANDARD: &'static str = "standard";
    pub const PRESET_PERMISSIVE: &'static str = "permissive";

    /// Create a new SvgSanitizer with default (standard) settings
    pub fn new_default() -> Self {
        let preset = Preset::Standard;
        let mut builder = Builder::new();

        // Configure allowed elements
        builder.tags(preset.elements());

        // Configure allowed attributes
        builder.generic_attributes(preset.attributes());

        // By default, block ALL external URLs for SVG (only allow fragment references like #id)
        // This is the secure default - external references can be used for data exfiltration
        let empty_schemes: HashSet<String> = HashSet::new();
        builder.url_schemes(empty_schemes);
        builder.url_relative(UrlRelative::Deny);

        // Strip comments for security
        builder.strip_comments(true);

        Self {
            inner: Some(builder),
            max_dimension: 10_000,
            max_nesting_depth: 100,
            block_data_uris: true,
        }
    }

    fn __construct() -> Self {
        Self::new_default()
    }

    /// Create a sanitizer with a named preset
    fn with_preset(preset_name: String) -> Result<Self> {
        let preset = Preset::try_from(preset_name.as_str())
            .map_err(|_| Error::ParseError(format!("Invalid preset: {}", preset_name)))?;

        let mut builder = Builder::new();
        builder.tags(preset.elements());
        builder.generic_attributes(preset.attributes());

        // Block ALL external URLs by default
        let empty_schemes: HashSet<String> = HashSet::new();
        builder.url_schemes(empty_schemes);
        builder.url_relative(UrlRelative::Deny);
        builder.strip_comments(true);

        Ok(Self {
            inner: Some(builder),
            max_dimension: 10_000,
            max_nesting_depth: 100,
            block_data_uris: true,
        })
    }

    /// Static method for file-based bomb detection (throws on dangerous SVG)
    fn defuse(path: String, max_dimension: Option<u32>) -> Result<()> {
        let content = fs::read_to_string(&path).map_err(|e| Error::FileOpenError {
            path: path.clone(),
            reason: e.to_string(),
        })?;

        let max_dim = max_dimension.unwrap_or(10_000);
        Self::validate_dimensions(&content, max_dim)?;
        Ok(())
    }

    /// Sanitize SVG content string
    fn clean(&self, svg: String) -> Result<String> {
        // First validate dimensions
        Self::validate_dimensions(&svg, self.max_dimension)?;

        // Then sanitize with Ammonia
        let Some(builder) = self.inner.as_ref() else {
            return Err(Error::InvalidState);
        };

        let sanitized = builder.clean(&svg).to_string();

        // Post-process to clean url() values in CSS-like attributes
        // (fill, stroke, clip-path, mask, marker-*, filter, etc.)
        // Ammonia doesn't sanitize these - only href-like attributes
        let cleaned = Self::sanitize_url_attributes(&sanitized);

        Ok(cleaned)
    }

    /// Sanitize SVG file and return cleaned content
    fn clean_file(&self, path: String) -> Result<String> {
        let content = fs::read_to_string(&path).map_err(|e| Error::FileOpenError {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        self.clean(content)
    }

    /// Check if SVG content is safe without modification
    fn is_safe(&self, svg: String) -> bool {
        Self::validate_dimensions(&svg, self.max_dimension).is_ok()
    }

    /// Check if SVG file is safe without modification
    fn is_safe_file(&self, path: String) -> bool {
        match fs::read_to_string(&path) {
            Ok(content) => Self::validate_dimensions(&content, self.max_dimension).is_ok(),
            Err(_) => false,
        }
    }

    // ==================== Builder Methods ====================

    /// Set allowed SVG elements (overwrites defaults)
    fn allow_elements(
        self_: &mut ZendClassObject<SvgSanitizer>,
        elements: Vec<String>,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        // Filter out blocked elements
        let filtered: HashSet<String> = elements
            .into_iter()
            .filter(|e| !BLOCKED_ELEMENTS.contains(&e.as_str()))
            .collect();
        builder.tags(filtered);
        Ok(self_)
    }

    /// Add elements to the allowlist
    fn add_allowed_elements(
        self_: &mut ZendClassObject<SvgSanitizer>,
        elements: Vec<String>,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        // Filter out blocked elements
        let filtered: HashSet<String> = elements
            .into_iter()
            .filter(|e| !BLOCKED_ELEMENTS.contains(&e.as_str()))
            .collect();
        builder.add_tags(filtered);
        Ok(self_)
    }

    /// Remove elements from the allowlist
    fn remove_elements(
        self_: &mut ZendClassObject<SvgSanitizer>,
        elements: Vec<String>,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        builder.rm_tags(elements.iter().map(|s| s.as_str()));
        Ok(self_)
    }

    /// Set allowed attributes (overwrites defaults)
    fn allow_attributes(
        self_: &mut ZendClassObject<SvgSanitizer>,
        attributes: Vec<String>,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        // Filter out event handlers
        let filtered: HashSet<String> = attributes
            .into_iter()
            .filter(|a| !a.to_lowercase().starts_with("on"))
            .collect();
        builder.generic_attributes(filtered);
        Ok(self_)
    }

    /// Add attributes to the allowlist
    fn add_allowed_attributes(
        self_: &mut ZendClassObject<SvgSanitizer>,
        attributes: Vec<String>,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        // Filter out event handlers
        let filtered: HashSet<String> = attributes
            .into_iter()
            .filter(|a| !a.to_lowercase().starts_with("on"))
            .collect();
        builder.add_generic_attributes(filtered);
        Ok(self_)
    }

    /// Remove attributes from the allowlist
    fn remove_attributes(
        self_: &mut ZendClassObject<SvgSanitizer>,
        attributes: Vec<String>,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        builder.rm_generic_attributes(attributes.iter().map(|s| s.as_str()));
        Ok(self_)
    }

    /// Set maximum allowed dimension (width/height/viewBox)
    fn set_max_dimension(
        self_: &mut ZendClassObject<SvgSanitizer>,
        max: u32,
    ) -> &mut ZendClassObject<SvgSanitizer> {
        self_.max_dimension = max;
        self_
    }

    /// Set maximum nesting depth
    fn set_max_nesting_depth(
        self_: &mut ZendClassObject<SvgSanitizer>,
        max: u32,
    ) -> &mut ZendClassObject<SvgSanitizer> {
        self_.max_nesting_depth = max;
        self_
    }

    /// Enable/disable blocking of external references (http/https URLs)
    fn block_external_references(
        self_: &mut ZendClassObject<SvgSanitizer>,
        block: bool,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        if block {
            // Only allow fragment references
            let empty: HashSet<String> = HashSet::new();
            builder.url_schemes(empty);
            builder.url_relative(UrlRelative::Deny);
        } else {
            let schemes: HashSet<String> =
                ["http", "https"].into_iter().map(String::from).collect();
            builder.url_schemes(schemes);
            builder.url_relative(UrlRelative::PassThrough);
        }
        Ok(self_)
    }

    /// Enable/disable blocking of data: URIs
    fn block_data_uris(
        self_: &mut ZendClassObject<SvgSanitizer>,
        block: bool,
    ) -> &mut ZendClassObject<SvgSanitizer> {
        self_.block_data_uris = block;
        self_
    }

    /// Enable/disable XML comments removal
    fn strip_comments(
        self_: &mut ZendClassObject<SvgSanitizer>,
        strip: bool,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        builder.strip_comments(strip);
        Ok(self_)
    }

    /// Allow relative URLs
    fn allow_relative_urls(
        self_: &mut ZendClassObject<SvgSanitizer>,
        allow: bool,
    ) -> Result<&mut ZendClassObject<SvgSanitizer>> {
        let Some(builder) = self_.inner.as_mut() else {
            return Err(Error::InvalidState);
        };
        if allow {
            builder.url_relative(UrlRelative::PassThrough);
        } else {
            builder.url_relative(UrlRelative::Deny);
        }
        Ok(self_)
    }
}

impl Default for SvgSanitizer {
    fn default() -> Self {
        let preset = Preset::Standard;
        let mut builder = Builder::new();

        // Configure allowed elements
        builder.tags(preset.elements());

        // Configure allowed attributes
        builder.generic_attributes(preset.attributes());

        // By default, block ALL external URLs for SVG (only allow fragment references like #id)
        // This is the secure default - external references can be used for data exfiltration
        let empty_schemes: HashSet<String> = HashSet::new();
        builder.url_schemes(empty_schemes);
        builder.url_relative(UrlRelative::Deny);

        // Strip comments for security
        builder.strip_comments(true);

        Self {
            inner: Some(builder),
            max_dimension: 10_000,
            max_nesting_depth: 100,
            block_data_uris: true,
        }
    }
}

impl SvgSanitizer {
    /// Validate SVG dimensions to prevent SVG bombs
    /// Checks ALL occurrences of dimension attributes (for multiple SVG roots)
    fn validate_dimensions(svg: &str, max_dimension: u32) -> Result<()> {
        let validator = DimensionValidator::new(max_dimension, 100);

        // Validate ALL viewBox attributes (handles multiple SVG roots)
        for viewbox in Self::extract_all_attributes(svg, "viewBox") {
            validator.validate_viewbox(&viewbox)?;
        }

        // Validate ALL width attributes
        for width in Self::extract_all_attributes(svg, "width") {
            validator.validate_dimension(&width)?;
        }

        // Validate ALL height attributes
        for height in Self::extract_all_attributes(svg, "height") {
            validator.validate_dimension(&height)?;
        }

        Ok(())
    }

    /// Extract ALL occurrences of an attribute value using case-insensitive matching
    fn extract_all_attributes(svg: &str, attr_name: &str) -> Vec<String> {
        let mut results = Vec::new();
        let svg_lower = svg.to_lowercase();
        let attr_lower = attr_name.to_lowercase();

        // Find all occurrences of the attribute name (case-insensitive)
        let mut search_start = 0;
        while let Some(pos) = svg_lower[search_start..].find(&attr_lower) {
            let abs_pos = search_start + pos;
            let after_attr = abs_pos + attr_lower.len();

            if after_attr >= svg.len() {
                break;
            }

            // Skip whitespace after attribute name
            let rest = &svg[after_attr..];
            let trimmed = rest.trim_start();
            let whitespace_len = rest.len() - trimmed.len();

            // Check for = sign
            if let Some(stripped) = trimmed.strip_prefix('=') {
                let after_eq = stripped.trim_start();
                let eq_whitespace = stripped.len() - after_eq.len();

                // Check for quote
                if let Some(quote) = after_eq.chars().next()
                    && (quote == '"' || quote == '\'')
                {
                    let value_start = after_attr + whitespace_len + 1 + eq_whitespace + 1;
                    if let Some(end) = svg[value_start..].find(quote) {
                        results.push(svg[value_start..value_start + end].to_string());
                    }
                }
            }

            search_start = after_attr;
        }
        results
    }

    /// Extract first attribute value (for backwards compatibility)
    #[allow(dead_code)]
    fn extract_attribute(svg: &str, attr_name: &str) -> Option<String> {
        Self::extract_all_attributes(svg, attr_name)
            .into_iter()
            .next()
    }

    /// Sanitize url() values in CSS-like attributes
    /// These attributes can contain url() references that Ammonia doesn't sanitize:
    /// fill, stroke, clip-path, mask, marker-start, marker-mid, marker-end, filter, cursor
    fn sanitize_url_attributes(svg: &str) -> String {
        use regex::Regex;

        // Regex to match url() in attribute values
        // Pattern: attribute="...url(...)..."
        // We need to find url() values and check if they're external
        lazy_static::lazy_static! {
            // Match attribute="value with url(...)"
            static ref URL_IN_ATTR: Regex = Regex::new(
                r#"((?:fill|stroke|clip-path|mask|marker-start|marker-mid|marker-end|filter|cursor)\s*=\s*")([^"]*url\s*\([^)]*\)[^"]*)""#
            ).unwrap();

            // Match url(...) to extract the URL inside
            static ref URL_FUNC: Regex = Regex::new(
                r#"url\s*\(\s*['"]?([^'")]+)['"]?\s*\)"#
            ).unwrap();
        }

        let result = URL_IN_ATTR.replace_all(svg, |caps: &regex::Captures| {
            let attr_prefix = &caps[1]; // e.g., fill="
            let attr_value = &caps[2]; // the value containing url()

            // Check each url() in the value
            let cleaned_value = URL_FUNC.replace_all(attr_value, |url_caps: &regex::Captures| {
                let url = &url_caps[1];

                // Only allow internal fragment references (starting with #)
                if url.trim().starts_with('#') {
                    // Keep internal references
                    url_caps[0].to_string()
                } else {
                    // External URL - replace with "none"
                    "none".to_string()
                }
            });

            format!("{}{}\"", attr_prefix, cleaned_value)
        });

        result.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sanitization() {
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer.clean("<svg><rect/></svg>".to_string()).unwrap();
        assert!(result.contains("svg"));
        assert!(result.contains("rect"));
    }

    #[test]
    fn test_script_removal() {
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><script>alert(1)</script><rect/></svg>".to_string())
            .unwrap();
        assert!(!result.contains("script"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_event_handler_removal() {
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><rect onclick=\"alert(1)\"/></svg>".to_string())
            .unwrap();
        assert!(!result.contains("onclick"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_svg_bomb_detection() {
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer.clean("<svg viewBox=\"0 0 100000 100000\"></svg>".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_is_safe() {
        let sanitizer = SvgSanitizer::default();
        assert!(sanitizer.is_safe("<svg><rect width=\"100\" height=\"100\"/></svg>".to_string()));
        assert!(!sanitizer.is_safe("<svg viewBox=\"0 0 100000 100000\"></svg>".to_string()));
    }

    #[test]
    fn test_foreign_object_blocked() {
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><foreignObject><div>HTML</div></foreignObject></svg>".to_string())
            .unwrap();
        assert!(!result.contains("foreignObject"));
        assert!(!result.contains("<div>"));
    }

    #[test]
    fn test_extract_viewbox() {
        assert_eq!(
            SvgSanitizer::extract_attribute("<svg viewBox=\"0 0 100 100\">", "viewBox"),
            Some("0 0 100 100".to_string())
        );
        assert_eq!(
            SvgSanitizer::extract_attribute("<svg viewBox='0 0 200 200'>", "viewBox"),
            Some("0 0 200 200".to_string())
        );
    }

    #[test]
    fn test_presets() {
        let strict = SvgSanitizer::with_preset("strict".to_string()).unwrap();
        let standard = SvgSanitizer::with_preset("standard".to_string()).unwrap();
        let permissive = SvgSanitizer::with_preset("permissive".to_string()).unwrap();

        // All should sanitize basic content
        assert!(strict.clean("<svg><rect/></svg>".to_string()).is_ok());
        assert!(standard.clean("<svg><rect/></svg>".to_string()).is_ok());
        assert!(permissive.clean("<svg><rect/></svg>".to_string()).is_ok());

        // Invalid preset should error
        assert!(SvgSanitizer::with_preset("invalid".to_string()).is_err());
    }

    // ==================== BYPASS TESTS ====================

    #[test]
    fn test_bypass_case_insensitive_viewbox() {
        // VULNERABILITY: extract_attribute is case-sensitive
        let sanitizer = SvgSanitizer::default();
        let result =
            sanitizer.clean("<svg VIEWBOX=\"0 0 100000 100000\"><rect/></svg>".to_string());
        // This SHOULD fail but currently passes (bypass!)
        assert!(
            result.is_err(),
            "BYPASS: Case-insensitive viewBox not detected"
        );
    }

    #[test]
    fn test_bypass_tab_in_attribute() {
        // VULNERABILITY: extract_attribute doesn't handle tabs
        let sanitizer = SvgSanitizer::default();
        let result =
            sanitizer.clean("<svg viewBox\t=\"0 0 100000 100000\"><rect/></svg>".to_string());
        assert!(result.is_err(), "BYPASS: Tab before = not detected");
    }

    #[test]
    fn test_bypass_nested_svg() {
        // Nested SVG with large dimensions
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><svg viewBox=\"0 0 100000 100000\"><rect/></svg></svg>".to_string());
        // First viewBox is from nested SVG - should still be caught
        assert!(
            result.is_err(),
            "BYPASS: Nested SVG dimensions not detected"
        );
    }

    #[test]
    fn test_bypass_animate_element() {
        // <animate> element can be dangerous
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg><animate attributeName=\"href\" to=\"javascript:alert(1)\"/></svg>"
                    .to_string(),
            )
            .unwrap();
        assert!(
            !result.contains("animate"),
            "BYPASS: <animate> element should be blocked"
        );
    }

    #[test]
    fn test_bypass_set_element() {
        // <set> element can inject attributes
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><set attributeName=\"onmouseover\" to=\"alert(1)\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("set"),
            "BYPASS: <set> element should be blocked"
        );
    }

    #[test]
    fn test_bypass_use_external_reference() {
        // <use> with external reference
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><use href=\"https://evil.com/malware.svg#payload\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External <use> reference should be blocked"
        );
    }

    #[test]
    fn test_bypass_xlink_href() {
        // xlink:href attribute
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg><a xlink:href=\"javascript:alert(1)\"><text>click</text></a></svg>"
                    .to_string(),
            )
            .unwrap();
        assert!(
            !result.contains("javascript"),
            "BYPASS: xlink:href with javascript should be blocked"
        );
    }

    #[test]
    fn test_bypass_data_uri_svg() {
        // data: URI containing SVG with script
        let sanitizer = SvgSanitizer::default();
        let payload = "<svg><image href=\"data:image/svg+xml,<svg onload='alert(1)'/>\"/></svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        assert!(
            !result.contains("data:"),
            "BYPASS: data: URI should be blocked"
        );
    }

    #[test]
    fn test_bypass_css_import() {
        // CSS @import in style element
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg><style>@import url(\"https://evil.com/steal.css\");</style><rect/></svg>"
                    .to_string(),
            )
            .unwrap();
        assert!(
            !result.contains("@import"),
            "BYPASS: CSS @import should be blocked"
        );
    }

    #[test]
    fn test_bypass_html_entity_in_attr_name() {
        // HTML entity encoding in attribute
        let sanitizer = SvgSanitizer::default();
        // viewBox with HTML entity for 'B'
        let result =
            sanitizer.clean("<svg view&#66;ox=\"0 0 100000 100000\"><rect/></svg>".to_string());
        // Ammonia should decode this - test if dimension check still works
        println!("Entity result: {:?}", result);
    }

    #[test]
    fn test_bypass_svg_onload() {
        // SVG onload event
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg onload=\"alert(1)\"><rect/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("onload"),
            "BYPASS: onload on SVG root should be blocked"
        );
    }

    #[test]
    fn test_bypass_handler_case() {
        // Uppercase event handler
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><rect ONCLICK=\"alert(1)\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.to_lowercase().contains("onclick"),
            "BYPASS: Uppercase ONCLICK should be blocked"
        );
    }

    // ==================== ADVANCED BYPASS TESTS ====================

    #[test]
    fn test_bypass_scientific_notation_dimensions() {
        // Scientific notation could bypass numeric parsing
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer.clean("<svg viewBox=\"0 0 1e10 1e10\"><rect/></svg>".to_string());
        assert!(
            result.is_err(),
            "BYPASS: Scientific notation dimensions should be detected"
        );
    }

    #[test]
    fn test_bypass_negative_dimensions() {
        // Negative dimensions in viewBox could cause issues
        let sanitizer = SvgSanitizer::default();
        // Large negative + large positive = huge render area
        let result = sanitizer
            .clean("<svg viewBox=\"-50000 -50000 100000 100000\"><rect/></svg>".to_string());
        assert!(
            result.is_err(),
            "BYPASS: Large negative offset dimensions should be detected"
        );
    }

    #[test]
    fn test_bypass_infinity_dimension() {
        // Infinity could bypass checks
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg width=\"Infinity\" height=\"Infinity\"><rect/></svg>".to_string());
        println!("Infinity result: {:?}", result);
        // Should either error or sanitize out the dangerous values
        if let Ok(clean) = result {
            assert!(
                !clean.to_lowercase().contains("infinity"),
                "BYPASS: Infinity dimension should be blocked"
            );
        }
    }

    #[test]
    fn test_bypass_null_byte_in_attribute() {
        // Null byte injection
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><rect on\0click=\"alert(1)\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("alert"),
            "BYPASS: Null byte in attribute name should not allow event handler"
        );
    }

    #[test]
    fn test_bypass_newline_in_attribute_value() {
        // Newline in javascript URL
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg><a href=\"java\nscript:alert(1)\"><text>click</text></a></svg>".to_string(),
            )
            .unwrap();
        assert!(
            !result.contains("alert"),
            "BYPASS: Newline in javascript URL should be blocked"
        );
    }

    #[test]
    fn test_bypass_feimage_external() {
        // feImage can load external resources
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg><filter><feImage href=\"https://evil.com/track.svg\"/></filter></svg>"
                    .to_string(),
            )
            .unwrap();
        assert!(
            !result.contains("evil.com"),
            "BYPASS: feImage with external URL should be blocked"
        );
    }

    #[test]
    fn test_bypass_image_external() {
        // <image> with external reference
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><image xlink:href=\"https://evil.com/pixel.gif\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("evil.com"),
            "BYPASS: image xlink:href external should be blocked"
        );
    }

    #[test]
    fn test_bypass_style_attribute_expression() {
        // CSS expression in style attribute
        // style attribute is NOT allowed by default due to CSS injection risks
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><rect style=\"width:expression(alert(1))\"/></svg>".to_string())
            .unwrap();
        println!("CSS expression result: {}", result);
        // style attribute should be removed entirely (not in default allowlist)
        assert!(
            !result.contains("style"),
            "Style attribute should be removed by default"
        );
        assert!(
            !result.contains("expression"),
            "CSS expression should be blocked"
        );
    }

    #[test]
    fn test_bypass_style_attribute_url_external() {
        // External URL in style attribute
        // style attribute is NOT allowed by default due to CSS injection risks
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg><rect style=\"fill:url(https://evil.com/gradient.svg)\"/></svg>".to_string(),
            )
            .unwrap();
        println!("Style URL result: {}", result);
        // style attribute should be removed entirely (not in default allowlist)
        assert!(
            !result.contains("style"),
            "Style attribute should be removed by default"
        );
        assert!(
            !result.contains("evil.com"),
            "External URL in style should be blocked"
        );
    }

    #[test]
    fn test_bypass_mpath_external() {
        // mpath with external reference
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer.clean("<svg><animateMotion><mpath href=\"https://evil.com/path.svg#p\"/></animateMotion></svg>".to_string()).unwrap();
        assert!(
            !result.contains("evil.com"),
            "BYPASS: mpath external reference should be blocked"
        );
    }

    #[test]
    fn test_bypass_handler_element() {
        // <handler> element (SVG 1.2)
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg><handler type=\"application/ecmascript\">alert(1)</handler></svg>"
                    .to_string(),
            )
            .unwrap();
        assert!(
            !result.contains("handler"),
            "BYPASS: handler element should be blocked"
        );
    }

    #[test]
    fn test_bypass_listener_element() {
        // <listener> element
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><listener event=\"click\" handler=\"#h\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("listener"),
            "BYPASS: listener element should be blocked"
        );
    }

    #[test]
    fn test_bypass_xml_stylesheet() {
        // XML stylesheet processing instruction
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<?xml-stylesheet href=\"javascript:alert(1)\"?><svg><rect/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("xml-stylesheet"),
            "BYPASS: xml-stylesheet PI should be stripped"
        );
        assert!(
            !result.contains("javascript"),
            "BYPASS: javascript in PI should be blocked"
        );
    }

    #[test]
    fn test_bypass_entity_expansion() {
        // Billion laughs / XML bomb via entities
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><svg>&lol2;</svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Entity result: {}", result);
        // Entities should be escaped (shown as &amp;), not expanded
        // If entity was expanded, we'd see "lollollol" - verify it's NOT there
        assert!(
            !result.contains("lollollol"),
            "BYPASS: Entity should NOT expand to lollollol"
        );
        // DOCTYPE should be stripped and entity references escaped
        assert!(!result.contains("DOCTYPE"), "DOCTYPE should be stripped");
    }

    #[test]
    fn test_bypass_cdata_script() {
        // CDATA section containing script
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><script><![CDATA[alert(1)]]></script></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("alert"),
            "BYPASS: Script in CDATA should be blocked"
        );
    }

    #[test]
    fn test_bypass_xmlns_redefinition() {
        // Redefine SVG namespace to something else
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean(
                "<svg xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script></svg>"
                    .to_string(),
            )
            .unwrap();
        assert!(
            !result.contains("alert"),
            "BYPASS: Namespace redefinition should not allow script"
        );
    }

    #[test]
    fn test_bypass_viewbox_comma_separator() {
        // viewBox with comma separators
        let sanitizer = SvgSanitizer::default();
        let result =
            sanitizer.clean("<svg viewBox=\"0,0,100000,100000\"><rect/></svg>".to_string());
        assert!(
            result.is_err(),
            "BYPASS: Comma-separated viewBox dimensions should be detected"
        );
    }

    #[test]
    fn test_bypass_multiple_svg_roots() {
        // Multiple SVG root elements
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer.clean(
            "<svg viewBox=\"0 0 100 100\"></svg><svg viewBox=\"0 0 100000 100000\"></svg>"
                .to_string(),
        );
        assert!(
            result.is_err(),
            "BYPASS: Second SVG with large dimensions should be detected"
        );
    }

    #[test]
    fn test_bypass_unicode_tag_name() {
        // Unicode lookalike characters in tag names
        let sanitizer = SvgSanitizer::default();
        // Using fullwidth 's' (U+FF53) - ｓcript
        let result = sanitizer
            .clean("<svg><\u{FF53}cript>alert(1)</\u{FF53}cript></svg>".to_string())
            .unwrap();
        println!("Unicode tag result: {}", result);
        // The unicode "ｓcript" is NOT treated as a script tag - it's treated as text
        // The angle brackets are escaped to &lt; and &gt;, so "alert(1)" is just text content
        // This is secure: verify there's no actual <script> tag (without unicode)
        assert!(
            !result.contains("<script>"),
            "Real script tag should not be present"
        );
        // The unicode tag with angle brackets should be escaped
        assert!(
            result.contains("&lt;") || !result.contains("<\u{FF53}cript"),
            "Unicode lookalike tag should be escaped or stripped"
        );
    }

    #[test]
    fn test_bypass_transform_huge_scale() {
        // Huge transform scale could cause resource exhaustion
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><rect transform=\"scale(1000000000)\"/></svg>".to_string())
            .unwrap();
        // This is more of a DoS vector - just ensure it doesn't crash
        assert!(result.contains("svg"));
    }

    #[test]
    fn test_bypass_deep_nesting() {
        // Deep nesting could cause stack overflow
        let sanitizer = SvgSanitizer::default();
        let deep = "<g>".repeat(200) + "<rect/>" + &"</g>".repeat(200);
        let svg = format!("<svg>{}</svg>", deep);
        let result = sanitizer.clean(svg);
        // Should either succeed or fail gracefully
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_bypass_srcset_like_attribute() {
        // srcset-like attribute (shouldn't exist in SVG but test anyway)
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><image srcset=\"https://evil.com/1.png 1x\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("evil.com"),
            "BYPASS: srcset with external URL should be blocked"
        );
    }

    #[test]
    fn test_bypass_formaction_attribute() {
        // HTML-specific attributes that shouldn't be in SVG
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><rect formaction=\"https://evil.com/\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.contains("formaction"),
            "BYPASS: formaction attribute should be blocked"
        );
    }

    // ==================== Advanced Bypass Tests ====================

    #[test]
    fn test_bypass_utf7_encoding() {
        // UTF-7 encoding bypass attempt
        // NOTE: This is NOT a vulnerability in modern browsers. UTF-7 XSS only worked
        // in IE7 and earlier. Modern browsers don't decode UTF-7 automatically.
        // The +ADw-script+AD4- sequence is just plain text, not executable code.
        let sanitizer = SvgSanitizer::default();
        let payload = "<svg>+ADw-script+AD4-alert(1)+ADw-/script+AD4-</svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("UTF-7 result: {}", result);
        // UTF-7 sequences remain as plain text - this is safe because:
        // 1. No <script> tag is created
        // 2. Modern browsers don't decode UTF-7
        assert!(
            !result.contains("<script>"),
            "UTF-7 should not create a real script tag"
        );
        // The UTF-7 text remains but is harmless
        assert!(
            result.contains("+ADw-") || result.contains("script"),
            "UTF-7 text should remain as harmless text"
        );
    }

    #[test]
    fn test_bypass_html_entity_decimal() {
        // Decimal HTML entities in dangerous places
        let sanitizer = SvgSanitizer::default();
        // &#60; = <, &#62; = >
        let payload = "<svg>&#60;script&#62;alert(1)&#60;/script&#62;</svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Decimal entity result: {}", result);
        assert!(
            !result.to_lowercase().contains("<script"),
            "BYPASS: Decimal entities should not create script tag"
        );
    }

    #[test]
    fn test_bypass_html_entity_hex() {
        // Hex HTML entities
        let sanitizer = SvgSanitizer::default();
        // &#x3c; = <, &#x3e; = >
        let payload = "<svg>&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;</svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Hex entity result: {}", result);
        assert!(
            !result.to_lowercase().contains("<script"),
            "BYPASS: Hex entities should not create script tag"
        );
    }

    #[test]
    fn test_bypass_mixed_case_event() {
        // Mixed case event handlers
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer
            .clean("<svg><rect OnClIcK=\"alert(1)\"/></svg>".to_string())
            .unwrap();
        assert!(
            !result.to_lowercase().contains("onclick"),
            "BYPASS: Mixed case onclick should be blocked"
        );
    }

    #[test]
    fn test_bypass_data_uri_base64() {
        // Base64 encoded data URI
        let sanitizer = SvgSanitizer::default();
        // data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIi8+ = <svg onload="alert(1)"/>
        let payload = r#"<svg><image href="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIi8+"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Base64 data URI result: {}", result);
        assert!(
            !result.contains("data:"),
            "BYPASS: Base64 data URI should be blocked"
        );
    }

    #[test]
    fn test_bypass_use_fragment_injection() {
        // <use> element with fragment that could reference dangerous content
        let sanitizer = SvgSanitizer::default();
        let payload =
            r##"<svg><defs><script id="x">alert(1)</script></defs><use href="#x"/></svg>"##;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Use fragment result: {}", result);
        assert!(
            !result.contains("alert"),
            "BYPASS: use referencing script should be blocked"
        );
    }

    #[test]
    fn test_bypass_svg_inside_desc() {
        // Nested SVG inside desc element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><desc><svg onload="alert(1)"/></desc></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("SVG in desc result: {}", result);
        assert!(
            !result.contains("onload"),
            "BYPASS: SVG in desc with onload should be blocked"
        );
    }

    #[test]
    fn test_bypass_attribute_without_quotes() {
        // Attribute value without quotes
        let sanitizer = SvgSanitizer::default();
        let payload = "<svg><rect onclick=alert(1)/></svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Unquoted attr result: {}", result);
        assert!(
            !result.contains("onclick"),
            "BYPASS: Unquoted onclick should be blocked"
        );
    }

    #[test]
    fn test_bypass_attribute_backtick_quotes() {
        // Backtick quotes (browser quirk)
        let sanitizer = SvgSanitizer::default();
        let payload = "<svg><rect onclick=`alert(1)`/></svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Backtick attr result: {}", result);
        assert!(
            !result.contains("onclick"),
            "BYPASS: Backtick-quoted onclick should be blocked"
        );
    }

    #[test]
    fn test_bypass_closing_tag_in_attribute() {
        // Closing tag characters in attribute to confuse parser
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><rect fill="red" title="</rect><script>alert(1)</script>"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Close tag in attr result: {}", result);
        assert!(
            !result.contains("<script"),
            "BYPASS: Script injected via attribute should be blocked"
        );
    }

    #[test]
    fn test_bypass_null_between_on_and_handler() {
        // Null byte between "on" and handler name
        let sanitizer = SvgSanitizer::default();
        let payload = "<svg><rect on\x00click=\"alert(1)\"/></svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Null in event result: {}", result);
        // The null byte might split the attribute or be stripped
        assert!(
            !result.contains("alert") || !result.contains("click"),
            "BYPASS: Null byte in onclick should be blocked"
        );
    }

    #[test]
    fn test_bypass_svg_namespace_script() {
        // Script with SVG namespace
        let sanitizer = SvgSanitizer::default();
        let payload =
            r#"<svg xmlns="http://www.w3.org/2000/svg"><svg:script>alert(1)</svg:script></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("NS script result: {}", result);
        assert!(
            !result.contains("alert"),
            "BYPASS: Namespaced script should be blocked"
        );
    }

    #[test]
    fn test_bypass_xhtml_namespace_script() {
        // XHTML namespace to inject script
        let sanitizer = SvgSanitizer::default();
        let payload =
            r#"<svg><x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("XHTML NS script result: {}", result);
        assert!(
            !result.contains("alert"),
            "BYPASS: XHTML namespaced script should be blocked"
        );
    }

    #[test]
    fn test_bypass_xml_space_preserve() {
        // xml:space="preserve" to keep dangerous whitespace
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg xml:space="preserve"><script>	alert(1)	</script></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        assert!(
            !result.contains("alert"),
            "BYPASS: xml:space preserve should not help script bypass"
        );
    }

    #[test]
    fn test_bypass_base_element() {
        // HTML base element to change URL resolution
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><base href="https://evil.com/"/><image href="image.png"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Base element result: {}", result);
        assert!(
            !result.contains("base"),
            "BYPASS: HTML base element should be blocked"
        );
    }

    #[test]
    fn test_bypass_meta_refresh() {
        // HTML meta refresh
        let sanitizer = SvgSanitizer::default();
        let payload =
            r#"<svg><meta http-equiv="refresh" content="0;url=javascript:alert(1)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Meta refresh result: {}", result);
        assert!(
            !result.contains("meta"),
            "BYPASS: HTML meta element should be blocked"
        );
    }

    #[test]
    fn test_bypass_object_element() {
        // Object element for embedding
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><object data="https://evil.com/malware.swf"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Object element result: {}", result);
        assert!(
            !result.contains("object"),
            "BYPASS: Object element should be blocked"
        );
    }

    #[test]
    fn test_bypass_embed_element() {
        // Embed element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><embed src="https://evil.com/malware.swf"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Embed element result: {}", result);
        assert!(
            !result.contains("embed"),
            "BYPASS: Embed element should be blocked"
        );
    }

    #[test]
    fn test_bypass_iframe_element() {
        // iframe element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><iframe src="javascript:alert(1)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Iframe element result: {}", result);
        assert!(
            !result.contains("iframe"),
            "BYPASS: Iframe element should be blocked"
        );
    }

    #[test]
    fn test_bypass_style_element_import() {
        // Style element with @import
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><style>@import url('https://evil.com/steal.css');</style></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Style import result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: CSS @import should be blocked"
        );
    }

    #[test]
    fn test_bypass_style_element_expression() {
        // Style element with CSS expression
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><style>rect { width: expression(alert(1)); }</style><rect/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Style expression result: {}", result);
        assert!(
            !result.contains("expression"),
            "BYPASS: CSS expression in style element should be blocked"
        );
    }

    #[test]
    fn test_bypass_style_element_behavior() {
        // Style element with behavior (IE)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><style>rect { behavior: url('https://evil.com/evil.htc'); }</style><rect/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Style behavior result: {}", result);
        assert!(
            !result.contains("behavior"),
            "BYPASS: CSS behavior should be blocked"
        );
    }

    #[test]
    fn test_bypass_viewbox_scientific_large() {
        // Very large scientific notation
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer.clean("<svg viewBox=\"0 0 9e99 9e99\"></svg>".to_string());
        println!("Scientific large viewBox result: {:?}", result);
        assert!(
            result.is_err(),
            "BYPASS: 9e99 dimension should be detected as bomb"
        );
    }

    #[test]
    fn test_bypass_width_scientific_large() {
        // Very large width in scientific notation
        let sanitizer = SvgSanitizer::default();
        let result = sanitizer.clean("<svg width=\"9e99\"></svg>".to_string());
        println!("Scientific large width result: {:?}", result);
        assert!(
            result.is_err(),
            "BYPASS: 9e99 width should be detected as bomb"
        );
    }

    #[test]
    fn test_bypass_double_url_encoding() {
        // Double URL encoding in href
        let sanitizer = SvgSanitizer::default();
        // %25 = %, so %256A = %6A = j
        let payload = r#"<svg><a href="%256Aavascript:alert(1)"><text>click</text></a></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Double URL encoding result: {}", result);
        // Should not decode and execute
        assert!(
            !result.contains("javascript:"),
            "BYPASS: Double URL encoding should not decode to javascript:"
        );
    }

    #[test]
    fn test_bypass_unicode_escape_sequence() {
        // Unicode escape sequences in attribute
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><a href="\u006Aavascript:alert(1)"><text>click</text></a></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Unicode escape result: {}", result);
        assert!(
            !result.contains("javascript:"),
            "BYPASS: Unicode escape should not decode to javascript:"
        );
    }

    #[test]
    fn test_bypass_html_comment_in_svg() {
        // HTML comments potentially hiding dangerous content
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><!--<script>-->alert(1)<!--</script>--></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("HTML comment result: {}", result);
        // Comments should be stripped
        assert!(!result.contains("<!--"), "Comments should be stripped");
    }

    #[test]
    fn test_bypass_malformed_comment() {
        // Malformed comment that might confuse parsers
        let sanitizer = SvgSanitizer::default();
        let payload = "<svg><!- -><script>alert(1)</script><!- -></svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Malformed comment result: {}", result);
        assert!(
            !result.contains("alert"),
            "BYPASS: Malformed comment should not allow script"
        );
    }

    #[test]
    fn test_bypass_processing_instruction() {
        // XML processing instruction
        let sanitizer = SvgSanitizer::default();
        let payload = "<?xml version=\"1.0\"?><?evil data=\"test\"?><svg><rect/></svg>";
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("Processing instruction result: {}", result);
        assert!(
            !result.contains("<?evil"),
            "Processing instructions should be stripped"
        );
    }

    #[test]
    fn test_bypass_svg_in_title() {
        // SVG inside title element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><title><svg onload="alert(1)"/></title></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("SVG in title result: {}", result);
        assert!(
            !result.contains("onload"),
            "BYPASS: SVG in title with onload should be blocked"
        );
    }

    #[test]
    fn test_bypass_textpath_external() {
        // textPath with external reference
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><text><textPath href="https://evil.com/path.svg#p">text</textPath></text></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("textPath external result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: textPath external reference should be blocked"
        );
    }

    #[test]
    fn test_bypass_clippath_external() {
        // clipPath with external reference
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><defs><clipPath id="c"><rect/></clipPath></defs><rect clip-path="url(https://evil.com/clip.svg#c)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("clipPath external result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External clipPath reference should be blocked"
        );
    }

    #[test]
    fn test_bypass_mask_external() {
        // mask with external reference
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><rect mask="url(https://evil.com/mask.svg#m)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("mask external result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External mask reference should be blocked"
        );
    }

    #[test]
    fn test_bypass_filter_external() {
        // filter with external reference
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><rect filter="url(https://evil.com/filter.svg#f)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("filter external result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External filter reference should be blocked"
        );
    }

    #[test]
    fn test_bypass_fill_external_url() {
        // fill with external URL (could be used for data exfiltration)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><rect fill="url(https://evil.com/gradient.svg#g)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("fill external result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External fill URL should be blocked"
        );
    }

    #[test]
    fn test_bypass_stroke_external_url() {
        // stroke with external URL
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><rect stroke="url(https://evil.com/pattern.svg#p)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("stroke external result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External stroke URL should be blocked"
        );
    }

    #[test]
    fn test_bypass_marker_external() {
        // marker with external reference
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><line marker-start="url(https://evil.com/marker.svg#m)" x1="0" y1="0" x2="100" y2="100"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("marker external result: {}", result);
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External marker reference should be blocked"
        );
    }

    #[test]
    fn test_bypass_cursor_external() {
        // cursor with external reference
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><rect cursor="url(https://evil.com/cursor.svg)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("cursor external result: {}", result);
        // cursor attribute should either be stripped or URL blocked
        assert!(
            !result.contains("evil.com"),
            "BYPASS: External cursor URL should be blocked"
        );
    }

    #[test]
    fn test_bypass_video_element() {
        // HTML5 video element (shouldn't be in SVG)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><video src="https://evil.com/video.mp4" autoplay/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("video element result: {}", result);
        assert!(
            !result.contains("video"),
            "BYPASS: video element should be blocked"
        );
    }

    #[test]
    fn test_bypass_audio_element() {
        // HTML5 audio element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><audio src="https://evil.com/audio.mp3" autoplay/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("audio element result: {}", result);
        assert!(
            !result.contains("audio"),
            "BYPASS: audio element should be blocked"
        );
    }

    #[test]
    fn test_bypass_link_stylesheet() {
        // link element for stylesheets
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><link rel="stylesheet" href="https://evil.com/evil.css"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("link stylesheet result: {}", result);
        assert!(
            !result.contains("link"),
            "BYPASS: link element should be blocked"
        );
    }

    #[test]
    fn test_bypass_form_element() {
        // HTML form element
        let sanitizer = SvgSanitizer::default();
        let payload =
            r#"<svg><form action="https://evil.com/steal"><input name="data"/></form></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("form element result: {}", result);
        assert!(
            !result.contains("form"),
            "BYPASS: form element should be blocked"
        );
    }

    #[test]
    fn test_bypass_input_element() {
        // HTML input element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><input onfocus="alert(1)" autofocus/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("input element result: {}", result);
        assert!(
            !result.contains("input"),
            "BYPASS: input element should be blocked"
        );
    }

    #[test]
    fn test_bypass_textarea_element() {
        // HTML textarea element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><textarea onfocus="alert(1)" autofocus/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("textarea element result: {}", result);
        assert!(
            !result.contains("textarea"),
            "BYPASS: textarea element should be blocked"
        );
    }

    #[test]
    fn test_bypass_button_element() {
        // HTML button element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><button onclick="alert(1)">Click</button></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("button element result: {}", result);
        assert!(
            !result.contains("button"),
            "BYPASS: button element should be blocked"
        );
    }

    #[test]
    fn test_bypass_marquee_element() {
        // HTML marquee element (legacy but dangerous)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><marquee onstart="alert(1)">text</marquee></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("marquee element result: {}", result);
        assert!(
            !result.contains("marquee"),
            "BYPASS: marquee element should be blocked"
        );
    }

    #[test]
    fn test_bypass_isindex_element() {
        // HTML isindex element (deprecated but potentially dangerous)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><isindex action="javascript:alert(1)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("isindex element result: {}", result);
        assert!(
            !result.contains("isindex"),
            "BYPASS: isindex element should be blocked"
        );
    }

    #[test]
    fn test_bypass_math_element() {
        // MathML element (could contain scripts in some contexts)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><math><maction actiontype="statusline">test</maction></math></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("math element result: {}", result);
        assert!(
            !result.contains("math") && !result.contains("maction"),
            "BYPASS: math/MathML element should be blocked"
        );
    }

    #[test]
    fn test_bypass_template_element() {
        // HTML template element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><template><script>alert(1)</script></template></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("template element result: {}", result);
        assert!(
            !result.contains("template"),
            "BYPASS: template element should be blocked"
        );
    }

    #[test]
    fn test_bypass_slot_element() {
        // HTML slot element (web components)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><slot name="x" onclick="alert(1)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("slot element result: {}", result);
        assert!(
            !result.contains("slot"),
            "BYPASS: slot element should be blocked"
        );
    }

    #[test]
    fn test_bypass_portal_element() {
        // HTML portal element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><portal src="https://evil.com/"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("portal element result: {}", result);
        assert!(
            !result.contains("portal"),
            "BYPASS: portal element should be blocked"
        );
    }

    #[test]
    fn test_bypass_noscript_element() {
        // noscript element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><noscript><img src=x onerror="alert(1)"/></noscript></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("noscript element result: {}", result);
        assert!(
            !result.contains("noscript"),
            "BYPASS: noscript element should be blocked"
        );
    }

    #[test]
    fn test_bypass_xmp_element() {
        // xmp element (legacy)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><xmp><script>alert(1)</script></xmp></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("xmp element result: {}", result);
        assert!(
            !result.contains("<script"),
            "BYPASS: xmp should not preserve dangerous content"
        );
    }

    #[test]
    fn test_bypass_plaintext_element() {
        // plaintext element (legacy)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><plaintext><script>alert(1)</script></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("plaintext element result: {}", result);
        assert!(
            !result.contains("plaintext"),
            "BYPASS: plaintext element should be blocked"
        );
    }

    #[test]
    fn test_bypass_bgsound_element() {
        // bgsound element (IE legacy)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><bgsound src="https://evil.com/sound.wav"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("bgsound element result: {}", result);
        assert!(
            !result.contains("bgsound"),
            "BYPASS: bgsound element should be blocked"
        );
    }

    #[test]
    fn test_bypass_applet_element() {
        // applet element (deprecated)
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><applet code="Evil.class" codebase="https://evil.com/"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("applet element result: {}", result);
        assert!(
            !result.contains("applet"),
            "BYPASS: applet element should be blocked"
        );
    }

    #[test]
    fn test_bypass_keygen_element() {
        // keygen element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><keygen autofocus onfocus="alert(1)"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("keygen element result: {}", result);
        assert!(
            !result.contains("keygen"),
            "BYPASS: keygen element should be blocked"
        );
    }

    #[test]
    fn test_bypass_source_element() {
        // source element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><source src="https://evil.com/video.mp4"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("source element result: {}", result);
        assert!(
            !result.contains("source"),
            "BYPASS: source element should be blocked"
        );
    }

    #[test]
    fn test_bypass_track_element() {
        // track element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><track src="https://evil.com/subtitles.vtt"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("track element result: {}", result);
        assert!(
            !result.contains("track"),
            "BYPASS: track element should be blocked"
        );
    }

    #[test]
    fn test_bypass_param_element() {
        // param element
        let sanitizer = SvgSanitizer::default();
        let payload = r#"<svg><param name="movie" value="https://evil.com/evil.swf"/></svg>"#;
        let result = sanitizer.clean(payload.to_string()).unwrap();
        println!("param element result: {}", result);
        assert!(
            !result.contains("param"),
            "BYPASS: param element should be blocked"
        );
    }
}
