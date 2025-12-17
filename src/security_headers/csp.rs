use super::{Error as SecurityHeaderError, Result};
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_const, php_impl};
use fmt::Write;
use php_hardened_macro::php_enum_constants;
use rand::distr::Alphanumeric;
use rand::{Rng, rng};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use strum::EnumString;
use trim_in_place::TrimInPlace;

/// All the CSP directives you want to support.
#[derive(Debug, Eq, PartialEq, Hash, EnumString, strum_macros::Display, Ord, PartialOrd)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
/// Supported Content Security Policy (CSP) directives.
///
/// These correspond to the various directives you can set in a
/// Content-Security-Policy header.
pub enum Rule {
    /// Fallback for other fetch directives.
    DefaultSrc,

    /// Controls allowed sources for scripts.
    ScriptSrc,

    /// Controls allowed sources for stylesheets.
    StyleSrc,

    /// Controls allowed sources for images.
    ImgSrc,

    /// Restricts which parent origins can embed this resource.
    FrameAncestors,

    /// Controls allowed endpoints for fetch, XHR, WebSocket, etc.
    ConnectSrc,

    /// Controls allowed sources for font resources.
    FontSrc,

    /// Alias for controlling allowed embedding contexts.
    ChildSrc,

    /// Controls allowed sources for web app manifests.
    ManifestSrc,

    /// Controls allowed sources for media elements.
    MediaSrc,

    /// Controls allowed sources for plugin content.
    ObjectSrc,

    /// Controls allowed sources for prefetch operations.
    PrefetchSrc,

    /// Controls allowed sources for script elements.
    ScriptSrcElem,

    /// Controls allowed sources for inline event handlers.
    ScriptSrcAttr,

    /// Controls allowed sources for style elements.
    StyleSrcElem,

    /// Controls allowed sources for inline style attributes.
    StyleSrcAttr,

    /// Controls allowed sources for worker scripts.
    WorkerSrc,

    // Document-level directives:
    /// Restricts the set of URLs usable in the document’s base element.
    BaseUri,

    /// Restricts the URLs that forms can submit to.
    FormAction,

    /// Applies sandboxing rules to the document.
    Sandbox,

    /// Restricts the types of plugins that may be loaded.
    PluginTypes,

    /// Disallows all mixed HTTP content on secure pages.
    BlockAllMixedContent,

    /// Instructs browsers to upgrade insecure requests to HTTPS.
    UpgradeInsecureRequests,

    // Reporting directives:
    /// Specifies a URI to which policy violation reports are sent.
    ReportUri,

    /// Specifies a reporting group for violation reports.
    ReportTo,

    // Integrity and trust directives:
    /// Requires Subresource Integrity checks for specified resource types.
    RequireSriFor,

    /// Restricts creation of DOM sinks to a trusted-types policy.
    TrustedTypes,

    /// Enforces Trusted Types for specified sinks.
    RequireTrustedTypesFor,
}

/// All valid source keywords for CSP directives.
///
/// These include host-independent keywords, nonce placeholders, resource-type tokens,
/// and sandbox flags that can appear after a directive name.
#[derive(Clone, EnumString, strum_macros::Display)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum Keyword {
    /// The `'self'` keyword, allowing the same origin.
    #[strum(serialize = "self")]
    _Self,

    /// The `'unsafe-inline'` keyword, allowing inline scripts or styles.
    UnsafeInline,

    /// The `'unsafe-eval'` keyword, allowing `eval()` and similar.
    UnsafeEval,

    /// The `'unsafe-hashes'` keyword, allowing hash-based inline resources.
    UnsafeHashes,

    /// The `'strict-dynamic'` keyword, enabling strict dynamic loading.
    StrictDynamic,

    /// The `'nonce-…'` placeholder for single-use nonces.
    Nonce,

    // Resource-type tokens for integrity/trusted-types directives:
    /// The `script` token for SRI or Trusted Types policies.
    Script,

    /// The `style` token for SRI or Trusted Types policies.
    Style,

    // Sandbox flags for the `sandbox` directive:
    /// Allows form submission in a sandboxed context.
    AllowForms,

    /// Allows modal dialogs in a sandboxed context.
    AllowModals,

    /// Allows orientation lock in a sandboxed context.
    AllowOrientationLock,

    /// Allows pointer lock in a sandboxed context.
    AllowPointerLock,

    /// Allows presentation mode in a sandboxed context.
    AllowPresentation,

    /// Allows pop-ups in a sandboxed context.
    AllowPopups,

    /// Allows pop-ups to escape sandbox restrictions.
    AllowPopupsToEscapeSandbox,

    /// Allows same-origin access in a sandboxed context.
    AllowSameOrigin,

    /// Allows script execution in a sandboxed context.
    AllowScripts,

    /// Allows storage access via user activation in a sandbox.
    AllowStorageAccessByUserActivation,

    /// Allows top-level navigation via user activation.
    AllowTopNavigationByUserActivation,

    // Other miscellaneous keywords:
    /// Allows duplicate directives.
    AllowDuplicates,

    /// Allows WebAssembly to use `eval()`.
    WasmUnsafeEval,

    /// Enables inline speculation rules.
    InlineSpeculationRules,

    /// Includes sample reports in violation reports.
    ReportSample,
}

pub type Source = String;
pub type CspSettings = (Vec<Keyword>, Vec<Source>);

/// Your application’s CSP config.
#[php_class]
#[php(name = "Hardened\\SecurityHeaders\\ContentSecurityPolicy")]
pub struct ContentSecurityPolicy {
    pub src_map: BTreeMap<Rule, CspSettings>,
    pub nonce: Option<String>,
}
#[php_enum_constants(Keyword, "src/security_headers/csp.rs")]
#[php_enum_constants(Rule, "src/security_headers/csp.rs")]
#[php_impl]
impl ContentSecurityPolicy {
    /// Constructs a new `ContentSecurityPolicy` builder with no directives set.
    ///
    /// # Returns
    /// - `ContentSecurityPolicy` A fresh instance containing an empty rule map.
    ///
    /// # Notes
    /// - No errors are thrown.
    #[php(constructor)]
    fn __construct() -> Self {
        Self {
            src_map: Default::default(),
            nonce: None,
        }
    }

    /// Sets or replaces a CSP directive with the given keywords and host sources.
    ///
    /// # Parameters
    /// - `rule`: The directive name. One of `default-src`, `script-src`, `style-src`, `img-src`, `frame-ancestors`,
    ///   `connect-src`, `font-src`, `child-src`, `manifest-src`, `media-src`, `object-src`, `prefetch-src`,
    ///   `script-src-elem`, `script-src-attr`, `style-src-elem`, `style-src-attr`, `worker-src`,
    ///   `base-uri`, `form-action`, `sandbox`, `plugin-types`, `block-all-mixed-content`,
    ///   `upgrade-insecure-requests`, `report-uri`, `report-to`, `require-sri-for`,
    ///   `trusted-types`, `require-trusted-types-for`.
    /// - `keywords`: Slice of keyword tokens. One or more of `self`, `none`, `unsafe-inline`,
    ///   `unsafe-eval`, `unsafe-hashes`, `strict-dynamic`, `nonce`, `script`, `style`,
    ///   `allow-forms`, `allow-modals`, `allow-orientation-lock`, `allow-pointer-lock`,
    ///   `allow-presentation`, `allow-popups`, `allow-popups-to-escape-sandbox`,
    ///   `allow-same-origin`, `allow-scripts`, `allow-storage-access-by-user-activation`,
    ///   `allow-top-navigation-by-user-activation`, `allow-duplicates`, `wasm-unsafe-eval`,
    ///   `inline-speculation-rules`, `report-sample`.
    /// - `sources`: Optional list of host sources (e.g. `["example.com"]`)
    ///
    /// # Exceptions
    /// - Throws `Exception` if any array item in `keywords` is not a string.
    /// - Throws `Exception` if `rule` is not a valid CSP directive.
    fn set_rule(
        &mut self,
        rule: &str,
        keywords: Vec<&str>,
        mut sources: Option<Vec<String>>,
    ) -> Result<()> {
        let mut keywords_vec = Vec::with_capacity(keywords.len());
        for keyword in keywords {
            let keyword = Keyword::from_str(keyword)
                .map_err(|_| SecurityHeaderError::InvalidKeyword(keyword.to_string()))?;
            keywords_vec.push(keyword);
        }
        if let Some(vec_sources) = sources.as_mut() {
            for source in vec_sources {
                if source.contains(['\'', '"']) {
                    return Err(SecurityHeaderError::QuotesInSource(source.clone()).into());
                }
                source.trim_in_place();
            }
        }
        self.src_map.insert(
            Rule::from_str(rule).map_err(|_| SecurityHeaderError::InvalidRule(rule.to_string()))?,
            (keywords_vec, sources.unwrap_or_default()),
        );
        Ok(())
    }

    /// Builds the `Content-Security-Policy` header value from the configured directives.
    ///
    /// # Returns
    /// - `String` The full header value, for example:
    ///   `"default-src 'self'; script-src 'self' 'nonce-ABCD1234' example.com; …"`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if formatting the header string fails.
    fn build(&mut self) -> Result<String> {
        let mut header = String::new();

        let mut it = self.src_map.iter().peekable();
        while let Some((src, (keywords, sources))) = it.next() {
            header.push_str(src.to_string().as_str());
            if keywords.is_empty() && sources.is_empty() {
                header.push_str(" 'none'");
            } else {
                for keyword in keywords {
                    match keyword {
                        Keyword::Nonce => {
                            let nonce = if let Some(x) = self.nonce.as_ref() {
                                x
                            } else {
                                self.nonce.insert(
                                    rng()
                                        .sample_iter(Alphanumeric)
                                        .take(16)
                                        .map(char::from)
                                        .collect(),
                                )
                            };
                            write!(header, " 'nonce-{nonce}'").map_err(|err| SecurityHeaderError::FormatError(err.to_string()))?;
                        }
                        _ => {
                            write!(header, " '{keyword}'").map_err(|err| SecurityHeaderError::FormatError(err.to_string()))?;
                        }
                    }
                }

                for source in sources {
                    write!(header, " {source}").map_err(|err| SecurityHeaderError::FormatError(err.to_string()))?;
                }
            }
            if it.peek().is_some() {
                header.push(';');
            }
        }

        Ok(header)
    }

    /// Send the `Content-Security-Policy` header via PHP `header()`.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the PHP `header()` function cannot be invoked.
    fn send(&mut self) -> Result<()> {
        let _ = Function::try_from_function("header")
            .ok_or(SecurityHeaderError::HeaderUnavailable)?
            .try_call(vec![&format!("content-security-policy: {}", self.build()?)]);
        Ok(())
    }

    /// Returns the most recently generated nonce, if any.
    ///
    /// # Returns
    /// - `Option<&str>` The raw nonce string (without the `'nonce-'` prefix), or `None` if `build()` has not yet generated one.
    fn get_nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.
    fn reset_nonce(&mut self) {
        self.nonce = None;
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentSecurityPolicy, Keyword, Rule};
    use crate::run_php_example;

    #[test]
    fn build_empty_policy() {
        let mut csp = ContentSecurityPolicy::__construct();
        let header = csp.build().unwrap();
        assert!(
            header.is_empty(),
            "Empty policy should produce empty header"
        );
    }

    #[test]
    fn build_none_directive() {
        let mut csp = ContentSecurityPolicy::__construct();
        csp.src_map
            .insert(Rule::DefaultSrc, (Vec::new(), Vec::new()));
        let header = csp.build().unwrap();
        assert_eq!(header, "default-src 'none'");
    }

    #[test]
    fn build_single_keyword() {
        let mut csp = ContentSecurityPolicy::__construct();
        csp.src_map
            .insert(Rule::DefaultSrc, (vec![Keyword::_Self], Vec::new()));
        let header = csp.build().unwrap();
        assert_eq!(header, "default-src 'self'");
    }

    #[test]
    fn build_keyword_and_source() {
        let mut csp = ContentSecurityPolicy::__construct();
        csp.src_map.insert(
            Rule::DefaultSrc,
            (vec![Keyword::_Self], vec!["example.com".into()]),
        );
        let header = csp.build().unwrap();
        assert_eq!(header, "default-src 'self' example.com");
    }

    #[test]
    fn build_multiple_directives_ordered() {
        let mut csp = ContentSecurityPolicy::__construct();
        // insert in reverse order
        csp.src_map
            .insert(Rule::ScriptSrc, (vec![Keyword::_Self], Vec::new()));
        csp.src_map
            .insert(Rule::DefaultSrc, (vec![Keyword::_Self], Vec::new()));
        let header = csp.build().unwrap();
        // BTreeMap orders DefaultSrc before ScriptSrc
        assert_eq!(header, "default-src 'self';script-src 'self'");
    }

    #[test]
    fn nonce_generation_and_reset() {
        let mut csp = ContentSecurityPolicy::__construct();
        csp.src_map
            .insert(Rule::DefaultSrc, (vec![Keyword::Nonce], Vec::new()));
        // first build generates a nonce
        let header1 = csp.build().unwrap();
        assert!(header1.starts_with("default-src 'nonce-"));
        let nonce1 = csp.get_nonce().expect("nonce should be set").to_owned();
        // second build uses same nonce
        let header2 = csp.build().unwrap();
        assert!(header2.contains(&format!("'nonce-{nonce1}'")));
        // reset and build produces a new nonce
        csp.reset_nonce();
        assert!(csp.get_nonce().is_none());
        let header3 = csp.build().unwrap();
        assert!(header3.starts_with("default-src 'nonce-"));
        let nonce2 = csp.get_nonce().unwrap();
        assert_ne!(nonce1, nonce2, "nonce after reset should differ");
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("security-headers/content-security-policy")?;
        Ok(())
    }
}
