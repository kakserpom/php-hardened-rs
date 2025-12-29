use std::collections::HashSet;

/// Sanitize a CSS style attribute value.
/// Keeps only allowed properties and removes dangerous values.
pub fn sanitize_style_attribute(style: &str, allowed_properties: &HashSet<String>) -> String {
    let mut sanitized = Vec::new();

    for declaration in style.split(';') {
        let declaration = declaration.trim();
        if declaration.is_empty() {
            continue;
        }

        if let Some((property, value)) = declaration.split_once(':') {
            let property = property.trim().to_lowercase();
            let value = value.trim();

            // Check if property is allowed
            if !allowed_properties.contains(&property) {
                continue;
            }

            // Check value for dangerous content
            if is_dangerous_css_value(value) {
                continue;
            }

            // Sanitize URL references in values
            if let Some(sanitized_value) = sanitize_css_value(value) {
                sanitized.push(format!("{}: {}", property, sanitized_value));
            }
        }
    }

    sanitized.join("; ")
}

/// Check if a CSS value contains dangerous content
fn is_dangerous_css_value(value: &str) -> bool {
    let lower = value.to_lowercase();

    // Block expression() - IE-specific JavaScript execution
    if lower.contains("expression(") {
        return true;
    }

    // Block javascript: URLs
    if lower.contains("javascript:") {
        return true;
    }

    // Block vbscript: URLs
    if lower.contains("vbscript:") {
        return true;
    }

    // Block behavior: - IE-specific
    if lower.contains("behavior:") {
        return true;
    }

    // Block -moz-binding - Firefox-specific XBL
    if lower.contains("-moz-binding") {
        return true;
    }

    false
}

/// Sanitize a CSS value, handling url() references
fn sanitize_css_value(value: &str) -> Option<String> {
    let lower = value.to_lowercase();

    // Check for url() references
    if lower.contains("url(") {
        return sanitize_url_in_css(value);
    }

    // Value is safe as-is
    Some(value.to_string())
}

/// Sanitize url() references in CSS values.
/// Only allows internal fragment references (#id).
fn sanitize_url_in_css(value: &str) -> Option<String> {
    let lower = value.to_lowercase();

    // Find url( and extract the content
    if let Some(start) = lower.find("url(") {
        let rest = &value[start + 4..];

        // Find the closing parenthesis
        let mut depth = 1;
        let mut end_idx = 0;
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = i;
                        break;
                    }
                }
                _ => {}
            }
        }

        if end_idx == 0 {
            // Malformed url(), reject
            return None;
        }

        let url_content = rest[..end_idx].trim();

        // Remove quotes if present
        let url = url_content
            .trim_start_matches(['"', '\''])
            .trim_end_matches(['"', '\''])
            .trim();

        // Only allow internal references (#id)
        if !url.starts_with('#') {
            // External URL or other reference - remove the url() part
            // but keep the rest of the value
            let before = &value[..start];
            let after = if start + 4 + end_idx + 1 < value.len() {
                &value[start + 4 + end_idx + 1..]
            } else {
                ""
            };

            let result = format!("{}{}", before.trim(), after.trim())
                .trim()
                .to_string();
            if result.is_empty() {
                return None;
            }
            return Some(result);
        }

        // Internal reference is safe
        return Some(value.to_string());
    }

    Some(value.to_string())
}

/// Sanitize the content of a <style> element.
/// This is a basic implementation that removes dangerous patterns.
pub fn sanitize_style_content(content: &str, allowed_properties: &HashSet<String>) -> String {
    let mut result = String::new();
    let mut in_rule_block = false;
    let mut current_selector = String::new();
    let mut current_declarations = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Check for dangerous patterns at the line level
        if is_dangerous_css_value(trimmed) {
            continue;
        }

        if trimmed.contains('{') {
            // Start of a rule block
            in_rule_block = true;
            if let Some(idx) = trimmed.find('{') {
                current_selector = trimmed[..idx].trim().to_string();
                let rest = trimmed[idx + 1..].trim();
                if !rest.is_empty() && rest != "}" {
                    // Declarations on the same line
                    let sanitized =
                        sanitize_style_attribute(rest.trim_end_matches('}'), allowed_properties);
                    if !sanitized.is_empty() {
                        current_declarations.push_str(&sanitized);
                        current_declarations.push_str("; ");
                    }
                }
                if rest.contains('}') {
                    // Single-line rule
                    if !current_declarations.is_empty() {
                        result.push_str(&current_selector);
                        result.push_str(" { ");
                        result.push_str(current_declarations.trim_end_matches("; "));
                        result.push_str(" }\n");
                    }
                    current_selector.clear();
                    current_declarations.clear();
                    in_rule_block = false;
                }
            }
        } else if trimmed.contains('}') {
            // End of a rule block
            if let Some(idx) = trimmed.find('}') {
                let decls = trimmed[..idx].trim();
                if !decls.is_empty() {
                    let sanitized = sanitize_style_attribute(decls, allowed_properties);
                    if !sanitized.is_empty() {
                        current_declarations.push_str(&sanitized);
                        current_declarations.push_str("; ");
                    }
                }
            }

            if !current_selector.is_empty() && !current_declarations.is_empty() {
                result.push_str(&current_selector);
                result.push_str(" { ");
                result.push_str(current_declarations.trim_end_matches("; "));
                result.push_str(" }\n");
            }
            current_selector.clear();
            current_declarations.clear();
            in_rule_block = false;
        } else if in_rule_block {
            // Inside a rule block - sanitize declarations
            let sanitized = sanitize_style_attribute(trimmed, allowed_properties);
            if !sanitized.is_empty() {
                current_declarations.push_str(&sanitized);
                current_declarations.push_str("; ");
            }
        } else {
            // Outside rule blocks - could be @rules, comments, etc.
            // For safety, only keep simple lines that don't contain dangerous patterns
            if (!trimmed.starts_with('@') || trimmed.starts_with("@charset"))
                && !trimmed.is_empty()
                && !trimmed.starts_with("/*")
            {
                result.push_str(trimmed);
                result.push('\n');
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_properties() -> HashSet<String> {
        ["fill", "stroke", "opacity", "font-size", "color"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn test_sanitize_style_attribute() {
        let props = test_properties();

        // Valid properties
        assert_eq!(
            sanitize_style_attribute("fill: red; stroke: blue", &props),
            "fill: red; stroke: blue"
        );

        // Invalid property removed
        assert_eq!(
            sanitize_style_attribute("fill: red; invalid: value", &props),
            "fill: red"
        );

        // Empty result
        assert_eq!(sanitize_style_attribute("invalid: value", &props), "");
    }

    #[test]
    fn test_dangerous_values() {
        let props = test_properties();

        // JavaScript URL blocked
        assert_eq!(
            sanitize_style_attribute("fill: url(javascript:alert(1))", &props),
            ""
        );

        // Expression blocked
        assert_eq!(
            sanitize_style_attribute("color: expression(alert(1))", &props),
            ""
        );
    }

    #[test]
    fn test_url_sanitization() {
        let props = test_properties();

        // Internal reference allowed
        let result = sanitize_style_attribute("fill: url(#myGradient)", &props);
        assert!(result.contains("url(#myGradient)"));

        // External URL removed
        let result = sanitize_style_attribute("fill: url(https://evil.com/img.svg)", &props);
        assert!(!result.contains("url("));
    }
}
