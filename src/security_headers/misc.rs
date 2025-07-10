use ext_php_rs::types::Zval;
use ext_php_rs::zend::Function;
use ext_php_rs::{exception::PhpException, exception::PhpResult, php_class, php_impl};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt::Write;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

/// Values for the `X-Permitted-Cross-Domain-Policies` header.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "kebab-case")]
pub enum PermittedCrossDomainPolicies {
    None,
    MasterOnly,
    ByContentType,
    All,
}

/// Possible values for the `X-Frame-Options` header.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "UPPERCASE")]
pub enum FrameOptions {
    Deny,
    SameOrigin,
    #[strum(serialize = "ALLOW-FROM")]
    AllowFrom,
}

/// Possible values for the `X-XSS-Protection` header.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "lowercase")]
pub enum XssProtection {
    #[strum(serialize = "0", serialize = "off")]
    Off,
    #[strum(serialize = "1", serialize = "on")]
    On,
    #[strum(serialize = "1; mode=block", serialize = "block")]
    ModeBlock,
}
/// Allowed destinations for Integrity-Policy `blocked-destinations`.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "lowercase")]
pub enum IntegrityBlockedDestination {
    Script,
}

/// Allowed sources for Integrity-Policy `sources`.
#[derive(EnumString, Display, Debug, Clone, PartialEq, Eq)]
#[strum(serialize_all = "lowercase")]
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
#[php(name = "Hardened\\SecurityHeaders\\MiscHeaders")]
pub struct MiscHeaders {
    frame: Option<(FrameOptions, Option<String>)>,
    xss: Option<(XssProtection, Option<String>)>,
    nosniff: bool,
    permitted_policies: Option<PermittedCrossDomainPolicies>,
    report_to: Option<String>,
    integrity_policy: Option<IntegrityPolicy>,
    integrity_policy_report_only: Option<String>,
}

#[php_impl]
impl MiscHeaders {
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
    fn set_frame_options(&mut self, mode: &str, uri: Option<&str>) -> PhpResult<()> {
        let opt = FrameOptions::from_str(mode)
            .map_err(|_| PhpException::from(format!("Invalid Frame-Options: {mode}")))?;
        if opt == FrameOptions::AllowFrom && uri.is_none() {
            return Err(PhpException::from("`ALLOW-FROM` requires a URI"));
        }
        self.frame = Some((opt, uri.map(String::from)));
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
    fn set_xss_protection(&mut self, mode: &str, report_uri: Option<&str>) -> PhpResult<()> {
        let opt = XssProtection::from_str(mode)
            .map_err(|_| PhpException::from(format!("Invalid XSS-Protection: {mode}")))?;
        if report_uri.is_some() && opt != XssProtection::On {
            return Err(PhpException::from(
                "`report_uri` only allowed with mode \"1\"",
            ));
        }
        self.xss = Some((opt, report_uri.map(String::from)));
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
    fn set_permitted_cross_domain_policies(&mut self, mode: &str) -> PhpResult<()> {
        let policy = PermittedCrossDomainPolicies::from_str(mode).map_err(|_| {
            PhpException::from(format!("Invalid cross-domain policies value: {mode}"))
        })?;
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
        endpoints: &Zval,
    ) -> PhpResult<()> {
        let endpoint_arr = endpoints
            .array()
            .ok_or_else(|| PhpException::from("`endpoints` must be an array"))?;
        let eps: Vec<Value> = endpoint_arr
            .values()
            .map(|v| {
                v.string()
                    .ok_or_else(|| PhpException::from("Each endpoint must be a string"))
                    .map(|s| Value::String(s.to_string()))
            })
            .collect::<Result<_, _>>()?;

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
        sources: Option<&Zval>,
        endpoints: Option<&Zval>,
    ) -> PhpResult<()> {
        // blocked-destinations
        let bd_table = blocked_destinations
            .array()
            .ok_or_else(|| PhpException::from("`blocked_destinations` must be an array"))?;
        let mut blocked = Vec::new();
        for v in bd_table.values() {
            let s = v
                .string()
                .ok_or_else(|| PhpException::from("Each blocked_destination must be a string"))?;
            let dest = IntegrityBlockedDestination::from_str(&s)
                .map_err(|_| PhpException::from(format!("Invalid blocked_destination: {s}")))?;
            blocked.push(dest);
        }
        if blocked.is_empty() {
            return Err(PhpException::from("`blocked_destinations` cannot be empty"));
        }

        // sources (optional)
        let src_vec = if let Some(src_zv) = sources {
            let src_table = src_zv
                .array()
                .ok_or_else(|| PhpException::from("`sources` must be an array"))?;
            let mut v = Vec::new();
            for sv in src_table.values() {
                let s = sv
                    .string()
                    .ok_or_else(|| PhpException::from("Each source must be a string"))?;
                let src = IntegritySource::from_str(&s)
                    .map_err(|_| PhpException::from(format!("Invalid source: {s}")))?;
                v.push(src);
            }
            v
        } else {
            vec![]
        };

        // endpoints (optional)
        let ep_vec = if let Some(ep_zv) = endpoints {
            let ep_table = ep_zv
                .array()
                .ok_or_else(|| PhpException::from("`endpoints` must be an array"))?;
            let mut v = Vec::new();
            for ev in ep_table.values() {
                let s = ev
                    .string()
                    .ok_or_else(|| PhpException::from("Each endpoint must be a string"))?;
                v.push(s.to_string());
            }
            Some(v)
        } else {
            None
        };

        self.integrity_policy = Some(IntegrityPolicy {
            blocked_destinations: blocked,
            sources: src_vec,
            endpoints: ep_vec,
        });
        Ok(())
    }

    /// Set `Integrity-Policy-Report-Only` header value.
    fn set_integrity_policy_report_only(&mut self, policy: &str) -> PhpResult<()> {
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
    fn send(&self) -> PhpResult<()> {
        let header_fn = Function::try_from_function("header")
            .ok_or_else(|| PhpException::from("Could not call header()"))?;
        for (name, value) in self.build() {
            let hdr = format!("{name}: {value}");
            header_fn.try_call(vec![&hdr])?;
        }
        Ok(())
    }
}
