use super::{Error as SecurityHeaderError, Result};
use ext_php_rs::types::Zval;
#[cfg(not(test))]
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_impl};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt::Write;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// Values for the `X-Permitted-Cross-Domain-Policies` header.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum PermittedCrossDomainPolicies {
    None,
    MasterOnly,
    ByContentType,
    All,
}

/// Possible values for the `X-Frame-Options` header.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "UPPERCASE", ascii_case_insensitive)]
pub enum FrameOptions {
    Deny,
    SameOrigin,
    #[strum(serialize = "ALLOW-FROM")]
    AllowFrom,
}

/// Possible values for the `X-XSS-Protection` header.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum XssProtection {
    #[strum(serialize = "off", serialize = "0", to_string = "0")]
    Off,
    #[strum(serialize = "on", serialize = "1", to_string = "1")]
    On,
    #[strum(serialize = "block", to_string = "1; mode=block")]
    ModeBlock,
}
/// Allowed destinations for Integrity-Policy `blocked-destinations`.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum IntegrityBlockedDestination {
    Script,
}

/// Allowed sources for Integrity-Policy `sources`.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum IntegritySource {
    Inline,
}

/// Internal representation of a structured Integrity-Policy header.
#[derive(Debug, Clone)]
struct IntegrityPolicy {
    blocked_destinations: Vec<IntegrityBlockedDestination>,
    sources: Vec<IntegritySource>,
    endpoints: Option<Vec<String>>,
}

impl IntegrityPolicy {
    fn build(&self) -> String {
        // blocked-destinations
        let mut val = String::new();
        val.push_str("blocked-destinations=(");
        val.push_str(
            &self
                .blocked_destinations
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        val.push(')');

        // sources
        if self.sources != [IntegritySource::Inline] {
            val.push_str(",sources=(");
            val.push_str(
                &self
                    .sources
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            val.push(')');
        }

        // endpoints
        if let Some(eps) = &self.endpoints {
            write!(val, ", endpoints=({})", eps.join(" ")).expect("Could not write to string");
        }
        val
    }
}

/// Builder for miscellaneous HTTP security headers:
/// `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`,
/// `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,
/// and `Integrity-Policy-Report-Only`.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\Whatnot")]
pub struct Whatnot {
    frame: Option<(FrameOptions, Option<String>)>,
    xss: Option<(XssProtection, Option<String>)>,
    nosniff: bool,
    permitted_policies: Option<PermittedCrossDomainPolicies>,
    report_to: Option<String>,
    integrity_policy: Option<IntegrityPolicy>,
    integrity_policy_report_only: Option<String>,
}

#[php_impl]
impl Whatnot {
    /// Constructs a new builder with all headers disabled.
    fn __construct() -> Self {
        Self {
            frame: None,
            xss: None,
            nosniff: false,
            permitted_policies: None,
            report_to: None,
            integrity_policy: None,
            integrity_policy_report_only: None,
        }
    }

    /// Set `X-Frame-Options` header.
    ///
    /// # Parameters
    /// - `mode`: `"DENY"`, `"SAMEORIGIN"`, or `"ALLOW-FROM"`.
    /// - `uri`: Optional URI, required if `mode` is `"ALLOW-FROM"`.
    ///
    /// # Exceptions
    /// - Throws if `mode` is invalid or `"ALLOW-FROM"` is given without a URI.
    fn set_frame_options(&mut self, mode: &str, uri: Option<String>) -> Result<()> {
        let opt =
            FrameOptions::from_str(mode).map_err(|_| SecurityHeaderError::InvalidValue { header_type: "X-Frame-Options".into(), value: mode.into() })?;
        if opt == FrameOptions::AllowFrom && uri.is_none() {
            return Err(SecurityHeaderError::AllowFromRequiresUri.into());
        }
        self.frame = Some((opt, uri));
        Ok(())
    }

    /// Set `X-XSS-Protection` header.
    ///
    /// # Parameters
    /// - `mode`: one of `"off"`, `"on"` or `"block"`.
    /// - `report_uri`: Optional reporting URI, only allowed when `mode` is `"1"`.
    ///
    /// # Exceptions
    /// - Throws if `mode` is invalid or a `report_uri` is provided for 'off' mode.
    fn set_xss_protection(&mut self, mode: &str, report_uri: Option<String>) -> Result<()> {
        let opt =
            XssProtection::from_str(mode).map_err(|_| SecurityHeaderError::InvalidValue { header_type: "X-XSS-Protection".into(), value: mode.into() })?;
        if report_uri.is_some() && opt == XssProtection::Off {
            return Err(SecurityHeaderError::ReportUriIncompatible.into());
        }
        self.xss = Some((opt, report_uri));
        Ok(())
    }

    /// Enable or disable `X-Content-Type-Options: nosniff`.
    fn set_nosniff(&mut self, enable: bool) {
        self.nosniff = enable;
    }

    /// Set `X-Permitted-Cross-Domain-Policies` header.
    ///
    /// # Parameters
    /// - `mode`: one of `"none"`, `"master-only"`, `"by-content-type"`, or `"all"`.
    ///
    /// # Exceptions
    /// - Throws if `mode` is not a valid policy token.
    fn set_permitted_cross_domain_policies(&mut self, mode: &str) -> Result<()> {
        let policy = PermittedCrossDomainPolicies::from_str(mode)
            .map_err(|_| SecurityHeaderError::InvalidValue { header_type: "X-Permitted-Cross-Domain-Policies".into(), value: mode.into() })?;
        self.permitted_policies = Some(policy);
        Ok(())
    }

    /// Configure the `Report-To` header from structured arguments.
    ///
    /// # Parameters
    /// - `group`: report group name.
    /// - `max_age`: seconds to retain reports.
    /// - `include_subdomains`: whether to include subdomains.
    /// - `endpoints`: PHP array of endpoint names.
    ///
    /// # Exceptions
    /// - Throws if any argument is invalid.
    fn set_report_to(
        &mut self,
        group: &str,
        max_age: i64,
        include_subdomains: bool,
        endpoints: Vec<&str>,
    ) -> Result<()> {
        let eps: Vec<Value> = endpoints
            .into_iter()
            .map(|s| Value::String(s.to_string()))
            .collect::<Vec<_>>();

        let mut map = Map::new();
        map.insert("group".into(), Value::String(group.to_string()));
        map.insert("max_age".into(), Value::Number(max_age.into()));
        map.insert("include_subdomains".into(), Value::Bool(include_subdomains));
        map.insert("endpoints".into(), Value::Array(eps));

        self.report_to = Some(Value::Object(map).to_string());
        Ok(())
    }

    /// Set a structured `Integrity-Policy` header.
    ///
    /// # Parameters
    /// - `blocked_destinations`: PHP array of destinations, e.g. `['script']`.
    /// - `sources`: Optional PHP array of sources, e.g. `['inline']`.
    /// - `endpoints`: Optional PHP array of reporting endpoint names.
    ///
    /// # Exceptions
    /// - Throws if any required array is missing or contains invalid entries.
    fn set_integrity_policy(
        &mut self,
        blocked_destinations: &Zval,
        sources: Option<Vec<String>>,
        endpoints: Option<Vec<String>>,
    ) -> Result<()> {
        // blocked-destinations
        let bd_table = blocked_destinations
            .array()
            .ok_or(SecurityHeaderError::EmptyBlockedDestinations)?;
        let mut blocked = Vec::new();
        for v in bd_table.values() {
            let s = v
                .string()
                .ok_or(SecurityHeaderError::InvalidBlockedDestination)?;
            let dest = IntegrityBlockedDestination::from_str(&s)
                .map_err(|_| SecurityHeaderError::InvalidBlockedDestination)?;
            blocked.push(dest);
        }
        if blocked.is_empty() {
            return Err(SecurityHeaderError::EmptyBlockedDestinations.into());
        }

        // sources (optional)
        let sources = sources
            .map(|sources| {
                sources
                    .into_iter()
                    .map(|source| {
                        IntegritySource::from_str(&source)
                            .map_err(|_| SecurityHeaderError::InvalidSource(source))
                    })
                    .collect::<std::result::Result<Vec<IntegritySource>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        self.integrity_policy = Some(IntegrityPolicy {
            blocked_destinations: blocked,
            sources,
            endpoints,
        });
        Ok(())
    }

    /// Set `Integrity-Policy-Report-Only` header value.
    fn set_integrity_policy_report_only(&mut self, policy: &str) -> Result<()> {
        self.integrity_policy_report_only = Some(policy.to_string());
        Ok(())
    }

    /// Build an associative array of header names → values.
    fn build(&self) -> HashMap<&'static str, String> {
        let mut headers = HashMap::new();

        if let Some((mode, uri)) = &self.frame {
            let value = match (mode, uri) {
                (FrameOptions::AllowFrom, Some(u)) => format!("ALLOW-FROM {u}"),
                _ => mode.to_string(),
            };
            headers.insert("X-Frame-Options", value);
        }

        if let Some((mode, uri)) = &self.xss {
            let value = if let Some(u) = uri {
                format!("1; report={u}")
            } else {
                mode.to_string()
            };
            headers.insert("X-XSS-Protection", value);
        }

        if self.nosniff {
            headers.insert("X-Content-Type-Options", "nosniff".into());
        }

        if let Some(p) = &self.permitted_policies {
            headers.insert("X-Permitted-Cross-Domain-Policies", p.to_string());
        }

        if let Some(v) = &self.report_to {
            headers.insert("Report-To", v.clone());
        }

        if let Some(v) = &self.integrity_policy {
            headers.insert("Integrity-Policy", v.build());
        }

        if let Some(v) = &self.integrity_policy_report_only {
            headers.insert("Integrity-Policy-Report-Only", v.clone());
        }

        headers
    }

    /// Emit all configured headers via PHP `header()` calls.
    fn send(&self) -> Result<()> {
        #[cfg(not(test))]
        {
            let header_fn = Function::try_from_function("header")
                .ok_or(SecurityHeaderError::HeaderUnavailable)?;
            for (name, value) in self.build() {
                let hdr = format!("{name}: {value}");
                header_fn
                    .try_call(vec![&hdr])
                    .map_err(|err| SecurityHeaderError::HeaderCallFailed(err.to_string()))?;
            }
            Ok(())
        }
        #[cfg(test)]
        panic!("send() can not be called from tests");
    }
}

#[cfg(test)]
mod tests {
    use super::Whatnot;
    use crate::run_php_example;
    use std::collections::HashMap;

    #[test]
    fn test_default_build_empty() {
        let m = Whatnot::__construct();
        let headers = m.build();
        assert!(headers.is_empty(), "Expected no headers by default");
    }

    #[test]
    fn test_set_frame_options_deny() {
        let mut m = Whatnot::__construct();
        m.set_frame_options("DENY", None).unwrap();
        let headers = m.build();
        assert_eq!(
            headers.get("X-Frame-Options").map(String::as_str),
            Some("DENY")
        );
    }

    #[test]
    fn test_set_frame_options_allow_from() {
        let mut m = Whatnot::__construct();
        m.set_frame_options("ALLOW-FROM", Some(String::from("https://example.com")))
            .unwrap();
        let headers = m.build();
        assert_eq!(
            headers.get("X-Frame-Options").map(String::as_str),
            Some("ALLOW-FROM https://example.com")
        );
    }

    #[test]
    fn test_set_frame_options_errors() {
        let mut m = Whatnot::__construct();
        assert!(m.set_frame_options("INVALID", None).is_err());
        assert!(m.set_frame_options("ALLOW-FROM", None).is_err());
    }

    #[test]
    fn test_set_xss_protection_modes() {
        let mut m = Whatnot::__construct();
        m.set_xss_protection("off", None).unwrap();
        let headers = m.build();
        assert_eq!(
            headers.get("X-XSS-Protection").map(String::as_str),
            Some("0")
        );

        let mut m = Whatnot::__construct();
        m.set_xss_protection("on", None).unwrap();
        let headers = m.build();
        assert_eq!(
            headers.get("X-XSS-Protection").map(String::as_str),
            Some("1")
        );

        let mut m = Whatnot::__construct();
        m.set_xss_protection("block", None).unwrap();
        let headers = m.build();
        assert_eq!(
            headers.get("X-XSS-Protection").map(String::as_str),
            Some("1; mode=block")
        );
    }

    #[test]
    fn test_set_xss_protection_with_report() {
        let mut m = Whatnot::__construct();
        m.set_xss_protection("on", Some(String::from("https://report.com")))
            .unwrap();
        let headers = m.build();
        assert_eq!(
            headers.get("X-XSS-Protection").map(String::as_str),
            Some("1; report=https://report.com")
        );
    }

    #[test]
    fn test_set_xss_protection_errors() {
        let mut m = Whatnot::__construct();
        // report_uri only allowed with "on"
        assert!(
            m.set_xss_protection("off", Some(String::from("uri")))
                .is_err()
        );
        // invalid mode
        assert!(m.set_xss_protection("invalid", None).is_err());
    }

    #[test]
    fn test_set_nosniff() {
        let mut m = Whatnot::__construct();
        m.set_nosniff(true);
        let headers = m.build();
        assert_eq!(
            headers.get("X-Content-Type-Options").map(String::as_str),
            Some("nosniff")
        );
    }

    #[test]
    fn test_set_permitted_cross_domain_policies() {
        let mut m = Whatnot::__construct();
        m.set_permitted_cross_domain_policies("none").unwrap();
        let headers = m.build();
        assert_eq!(
            headers
                .get("X-Permitted-Cross-Domain-Policies")
                .map(String::as_str),
            Some("none")
        );
        // invalid
        assert!(m.set_permitted_cross_domain_policies("invalid").is_err());
    }

    #[test]
    fn test_set_report_to() {
        let mut m = Whatnot::__construct();
        m.set_report_to("grp", 3600, true, vec!["ep1", "ep2"])
            .unwrap();
        let headers = m.build();
        let val = headers.get("Report-To").unwrap();
        // Must be valid JSON containing the right fields
        assert!(val.contains(r#""group":"grp""#));
        assert!(val.contains(r#""max_age":3600"#));
        assert!(val.contains(r#""include_subdomains":true"#));
        assert!(val.contains(r#""endpoints":["ep1","ep2"]"#));
    }

    #[test]
    fn test_set_integrity_policy_report_only() {
        let mut m = Whatnot::__construct();
        m.set_integrity_policy_report_only("policy-value").unwrap();
        let headers = m.build();
        assert_eq!(
            headers
                .get("Integrity-Policy-Report-Only")
                .map(String::as_str),
            Some("policy-value")
        );
    }

    #[test]
    fn test_combined_headers() {
        let mut m = Whatnot::__construct();
        m.set_frame_options("SAMEORIGIN", None).unwrap();
        m.set_xss_protection("on", None).unwrap();
        m.set_nosniff(true);
        m.set_permitted_cross_domain_policies("all").unwrap();
        m.set_report_to("g", 10, false, vec!["e"]).unwrap();
        m.set_integrity_policy_report_only("p").unwrap();

        let headers = m.build();
        let expect: HashMap<_, _> = vec![
            ("X-Frame-Options", "SAMEORIGIN"),
            ("X-XSS-Protection", "1"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Permitted-Cross-Domain-Policies", "all"),
            ("Report-To", headers.get("Report-To").unwrap().as_str()),
            ("Integrity-Policy-Report-Only", "p"),
        ]
        .into_iter()
        .collect();

        for (k, v) in expect {
            assert_eq!(headers.get(k).map(String::as_str), Some(v));
        }
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/whatnot")?;
        Ok(())
    }
}
