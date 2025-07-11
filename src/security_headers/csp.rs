use anyhow::{Result, anyhow, bail};
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
pub enum Rule {
    DefaultSrc,
    ScriptSrc,
    StyleSrc,
    ImgSrc,
    FrameAncestors,
    ConnectSrc,
    FontSrc,

    ChildSrc,
    ManifestSrc,
    MediaSrc,
    ObjectSrc,
    PrefetchSrc,
    ScriptSrcElem,
    ScriptSrcAttr,
    StyleSrcElem,
    StyleSrcAttr,
    WorkerSrc,

    // **Document directives**:
    BaseUri,
    FormAction,
    Sandbox,
    PluginTypes,
    BlockAllMixedContent,
    UpgradeInsecureRequests,

    // **Reporting directives**:
    ReportUri,
    ReportTo,

    // **Integrity & trust directives**:
    RequireSriFor,
    TrustedTypes,
    RequireTrustedTypesFor,
}
/// Everything that can go after a directive:
/// - a keyword like 'self'
/// - a nonce placeholder
/// - a domain string
#[derive(Clone, EnumString, strum_macros::Display)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum Keyword {
    #[strum(serialize = "self")]
    _Self,
    UnsafeInline,
    UnsafeEval,
    UnsafeHashes,
    StrictDynamic,
    Nonce,

    // Resource‐type tokens for require-sri-for & require-trusted-types-for
    Script,
    Style,

    // Sandbox flags (for the sandbox directive)
    AllowForms,
    AllowModals,
    AllowOrientationLock,
    AllowPointerLock,
    AllowPresentation,
    AllowPopups,
    AllowPopupsToEscapeSandbox,
    AllowSameOrigin,
    AllowScripts,
    AllowStorageAccessByUserActivation,
    AllowTopNavigationByUserActivation,

    AllowDuplicates,
    WasmUnsafeEval,
    InlineSpeculationRules,
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
#[php_enum_constants((Keyword, "src/security_headers/csp.rs"))]
#[php_enum_constants((Rule, "src/security_headers/csp.rs"))]
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
    pub fn __construct() -> Self {
        Self {
            src_map: Default::default(),
            nonce: None,
        }
    }

    /// Sets or replaces a CSP directive with the given keywords and host sources.
    ///
    /// # Parameters
    /// - `rule`: The directive name (e.g. `"default-src"`, `"script-src"`).
    /// - `keywords`: An array of keyword tokens (e.g. `'self'`, `'nonce'`).
    /// - `sources`: Optional vector of host strings (e.g. `"example.com"`).
    ///
    /// # Exceptions
    /// - Throws `Exception` if any array item in `keywords` is not a string.
    /// - Throws `Exception` if `rule` is not a valid CSP directive.
    pub fn set_rule(
        &mut self,
        rule: &str,
        keywords: Vec<&str>,
        mut sources: Option<Vec<String>>,
    ) -> Result<()> {
        let mut keywords_vec = Vec::with_capacity(keywords.len());
        for keyword in keywords {
            let keyword = Keyword::from_str(keyword)
                .map_err(|e| anyhow!("Invalid keyword `{keyword}`: {e}"))?;
            keywords_vec.push(keyword);
        }
        if let Some(vec_sources) = sources.as_mut() {
            for source in vec_sources {
                if source.contains(['\'', '"']) {
                    bail!("source `{source}` may not contain single quotes");
                }
                source.trim_in_place();
            }
        }
        self.src_map.insert(
            Rule::from_str(rule).map_err(|_| anyhow!("Invalid rule name: {rule}"))?,
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
    pub fn build(&mut self) -> Result<String> {
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
                            write!(header, " 'nonce-{nonce}'").map_err(|err| anyhow!("{err}"))?;
                        }
                        _ => {
                            write!(header, " '{keyword}'").map_err(|err| anyhow!("{err}"))?;
                        }
                    }
                }

                for source in sources {
                    write!(header, " {source}").map_err(|err| anyhow!("{err}"))?;
                }
            }
            if it.peek().is_some() {
                header.push(';');
            }
        }

        Ok(header)
    }

    pub fn send(&mut self) -> Result<()> {
        let _ = Function::try_from_function("header")
            .ok_or_else(|| anyhow::anyhow!("Could not call header()"))?
            .try_call(vec![&format!("content-security-policy: {}", self.build()?)]);
        Ok(())
    }

    /// Returns the most recently generated nonce, if any.
    ///
    /// # Returns
    /// - `Option<&str>` The raw nonce string (without the `'nonce-'` prefix), or `None` if `build()` has not yet generated one.
    pub fn get_nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.
    pub fn reset_nonce(&mut self) {
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
