use super::error::{Error, Result};

/// Validator for SVG dimensions and nesting depth
pub struct DimensionValidator {
    pub max_dimension: u32,
    pub max_nesting_depth: u32,
}

impl DimensionValidator {
    pub fn new(max_dimension: u32, max_nesting_depth: u32) -> Self {
        Self {
            max_dimension,
            max_nesting_depth,
        }
    }

    /// Validate viewBox attribute: "minX minY width height"
    pub fn validate_viewbox(&self, viewbox: &str) -> Result<()> {
        let parts: Vec<&str> = viewbox.split_whitespace().collect();
        if parts.len() != 4 {
            // Also try comma-separated format
            let parts: Vec<&str> = viewbox.split([' ', ',']).filter(|s| !s.is_empty()).collect();
            if parts.len() != 4 {
                return Err(Error::InvalidViewBox(format!(
                    "expected 4 values, got {}",
                    parts.len()
                )));
            }
            return self.validate_viewbox_parts(&parts);
        }
        self.validate_viewbox_parts(&parts)
    }

    fn validate_viewbox_parts(&self, parts: &[&str]) -> Result<()> {
        let width: f64 = parts[2]
            .parse()
            .map_err(|_| Error::InvalidViewBox(format!("invalid width: {}", parts[2])))?;
        let height: f64 = parts[3]
            .parse()
            .map_err(|_| Error::InvalidViewBox(format!("invalid height: {}", parts[3])))?;

        if width < 0.0 || height < 0.0 {
            return Err(Error::InvalidViewBox("negative dimensions".to_string()));
        }

        if width > self.max_dimension as f64 || height > self.max_dimension as f64 {
            return Err(Error::SvgBombDimensions {
                width: width as u32,
                height: height as u32,
                max: self.max_dimension,
            });
        }
        Ok(())
    }

    /// Validate width/height attribute values like "10000", "10000px", "100%"
    pub fn validate_dimension(&self, value: &str) -> Result<()> {
        let trimmed = value.trim();
        let lower = trimmed.to_lowercase();

        // Block dangerous keywords
        if lower == "infinity" || lower == "inf" || lower == "nan" {
            return Err(Error::SvgBombDimensions {
                width: u32::MAX,
                height: 0,
                max: self.max_dimension,
            });
        }

        // Allow percentage values
        if trimmed.ends_with('%') {
            return Ok(());
        }

        // Extract numeric part (including scientific notation)
        let numeric_str: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == 'e' || *c == 'E' || *c == '+')
            .collect();

        if numeric_str.is_empty() {
            // Could be "auto" or other keywords - allow these
            return Ok(());
        }

        let numeric: f64 = numeric_str.parse().unwrap_or(0.0);

        // Check for infinity from parsing (e.g., "1e999")
        if numeric.is_infinite() || numeric.is_nan() {
            return Err(Error::SvgBombDimensions {
                width: u32::MAX,
                height: 0,
                max: self.max_dimension,
            });
        }

        if numeric > self.max_dimension as f64 {
            return Err(Error::SvgBombDimensions {
                width: numeric as u32,
                height: 0,
                max: self.max_dimension,
            });
        }
        Ok(())
    }

    /// Validate nesting depth
    pub fn validate_depth(&self, depth: u32) -> Result<()> {
        if depth > self.max_nesting_depth {
            return Err(Error::SvgBombDepth {
                depth,
                max: self.max_nesting_depth,
            });
        }
        Ok(())
    }
}

/// Check if a URL is dangerous and should be blocked
pub fn check_dangerous_url(url: &str, block_external: bool, block_data_uri: bool) -> Option<Error> {
    let url_lower = url.trim().to_lowercase();

    // Block javascript: URLs (always)
    if url_lower.starts_with("javascript:") {
        return Some(Error::JavaScriptUrl(url.to_string()));
    }

    // Block vbscript: URLs (always)
    if url_lower.starts_with("vbscript:") {
        return Some(Error::JavaScriptUrl(url.to_string()));
    }

    // Block data: URIs (if configured)
    if block_data_uri && url_lower.starts_with("data:") {
        return Some(Error::DataUri(url.to_string()));
    }

    // Block external URLs (if configured)
    if block_external {
        if url_lower.starts_with("http://")
            || url_lower.starts_with("https://")
            || url_lower.starts_with("//")
            || url_lower.starts_with("ftp://")
            || url_lower.starts_with("file://")
        {
            return Some(Error::ExternalReference(url.to_string()));
        }
    }

    // Allow internal references (#id) and relative paths
    None
}

/// Check if a URL is an internal fragment reference (starts with #)
pub fn is_internal_reference(url: &str) -> bool {
    url.trim().starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewbox_validation() {
        let validator = DimensionValidator::new(10000, 100);

        // Valid viewboxes
        assert!(validator.validate_viewbox("0 0 100 100").is_ok());
        assert!(validator.validate_viewbox("0 0 10000 10000").is_ok());
        assert!(validator.validate_viewbox("-50 -50 100 100").is_ok());

        // Invalid viewboxes
        assert!(validator.validate_viewbox("0 0 100001 100").is_err());
        assert!(validator.validate_viewbox("0 0 100 100001").is_err());
        assert!(validator.validate_viewbox("0 0 100").is_err());
    }

    #[test]
    fn test_dimension_validation() {
        let validator = DimensionValidator::new(10000, 100);

        // Valid dimensions
        assert!(validator.validate_dimension("100").is_ok());
        assert!(validator.validate_dimension("100px").is_ok());
        assert!(validator.validate_dimension("100%").is_ok());
        assert!(validator.validate_dimension("10000").is_ok());

        // Invalid dimensions
        assert!(validator.validate_dimension("100001").is_err());
        assert!(validator.validate_dimension("100001px").is_err());
    }

    #[test]
    fn test_dangerous_urls() {
        // JavaScript URLs are always blocked
        assert!(check_dangerous_url("javascript:alert(1)", true, true).is_some());
        assert!(check_dangerous_url("JavaScript:alert(1)", true, true).is_some());

        // External URLs when block_external is true
        assert!(check_dangerous_url("https://evil.com/image.svg", true, true).is_some());
        assert!(check_dangerous_url("https://evil.com/image.svg", false, true).is_none());

        // Data URIs when block_data_uri is true
        assert!(check_dangerous_url("data:image/svg+xml,...", true, true).is_some());
        assert!(check_dangerous_url("data:image/svg+xml,...", true, false).is_none());

        // Internal references are always allowed
        assert!(check_dangerous_url("#myGradient", true, true).is_none());
    }

    #[test]
    fn test_internal_reference() {
        assert!(is_internal_reference("#id"));
        assert!(is_internal_reference(" #id"));
        assert!(!is_internal_reference("http://example.com"));
        assert!(!is_internal_reference("gradient"));
    }
}
