use anyhow::anyhow;
use ext_php_rs::exception::PhpResult;
use ext_php_rs::prelude::PhpException;
use ext_php_rs::types::ZendHashTable;
use ext_php_rs::zend::Function;
use ext_php_rs::{php_class, php_const, php_impl};
use fmt::Write;
use rand::distr::Alphanumeric;
use rand::{Rng, rng};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use strum::EnumString;
use trim_in_place::TrimInPlace;

/// All the CSP directives you want to support.
#[derive(Debug, Eq, PartialEq, Hash, EnumString, strum_macros::Display, Ord, PartialOrd)]
#[strum(serialize_all = "kebab-case")]
pub enum Rule {
    DefaultSrc,
    ScriptSrc,
    StyleSrc,
    ImgSrc,
    FrameAncestors,
    ConnectSrc,
    FontSrc,
}
/// Everything that can go after a directive:
/// - a keyword like 'self'
/// - a nonce placeholder
/// - a domain string
#[derive(Clone, EnumString, strum_macros::Display)]
#[strum(serialize_all = "kebab-case")]
pub enum SpecialSource {
    #[strum(serialize = "self")]
    _Self,
    UnsafeInline,
    UnsafeEval,
    UnsafeHashes,
    StrictDynamic,
    Nonce,
}
pub type Source = String;
pub type CspSettings = (Vec<SpecialSource>, Vec<Source>);

/// Your application’s CSP config.
#[php_class]
#[php(name = "Hardened\\ContentSecurityPolicy")]
pub struct ContentSecurityPolicy {
    pub src_map: BTreeMap<Rule, CspSettings>,
    pub nonce: Option<String>,
}
#[php_impl]
impl ContentSecurityPolicy {
    #[php_const]
    const DEFAULT_SRC: &'static str = "default-src";

    #[php_const]
    const SCRIPT_SRC: &'static str = "script-src";

    #[php_const]
    const STYLE_SRC: &'static str = "style-src";

    #[php_const]
    const IMG_SRC: &'static str = "img-src";

    #[php_const]
    const FRAME_ANCESTORS: &'static str = "frame-ancestors";

    #[php_const]
    const FONT_SRC: &'static str = "font-src";

    #[php_const]
    const CONNECT_SRC: &'static str = "connect-src";

    #[php_const]
    const SELF: &'static str = "self";

    #[php_const]
    const UNSAFE_INLINE: &'static str = "unsafe-inline";

    #[php_const]
    const UNSAFE_EVAL: &'static str = "unsafe-eval";

    #[php_const]
    const UNSAFE_HASHES: &'static str = "unsafe-hashes";

    #[php_const]
    const STRICT_DYNAMIC: &'static str = "strict-dynamic";

    #[php_const]
    const NONCE: &'static str = "nonce";

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

    /// Sets or replaces a CSP directive with the given special sources and host sources.
    ///
    /// # Parameters
    /// - `rule`: The directive name (e.g. `"default-src"`, `"script-src"`).
    /// - `special_sources`: A `ZendHashTable` of keyword tokens (e.g. `'self'`, `'nonce-...'`).
    /// - `sources`: Optional vector of host strings (e.g. `"example.com"`).
    ///
    /// # Exceptions
    /// - Throws `Exception` if any array item in `special_sources` is not a string.
    /// - Throws `Exception` if `rule` is not a valid CSP directive.
    pub fn set_rule(
        &mut self,
        rule: &str,
        special_sources: &ZendHashTable,
        mut sources: Option<Vec<String>>,
    ) -> PhpResult<()> {
        let mut special_sources_vec = Vec::with_capacity(special_sources.len());
        for item in special_sources.values() {
            let s = item.str().ok_or_else(|| {
                PhpException::from("Array item of special_sources is not a string")
            })?;
            let special_source = SpecialSource::from_str(s)
                .map_err(|e| PhpException::from(format!("Invalid special source `{s}`: {e}")))?;
            special_sources_vec.push(special_source);
        }
        if let Some(vec_sources) = sources.as_mut() {
            for source in vec_sources {
                if source.contains(['\'', '"']) {
                    return Err(PhpException::from(format!(
                        "source `{source}` may not contain single quotes"
                    )));
                }
                source.trim_in_place();
            }
        }
        self.src_map.insert(
            Rule::from_str(&rule)
                .map_err(|_| PhpException::from(format!("Invalid rule name: {rule}")))?,
            (special_sources_vec, sources.unwrap_or_default()),
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
    pub fn build(&mut self) -> PhpResult<String> {
        let mut header = String::new();

        let mut it = self.src_map.iter().peekable();
        while let Some((src, (special_sources, sources))) = it.next() {
            header.push_str(src.to_string().as_str());
            if special_sources.is_empty() && sources.is_empty() {
                header.push_str(" 'none'");
            } else {
                for special_source in special_sources {
                    match special_source {
                        SpecialSource::Nonce => {
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
                            write!(header, " '{special_source}'")
                                .map_err(|err| anyhow!("{err}"))?;
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

    pub fn send(&mut self) -> PhpResult<()> {
        let var_dump = Function::try_from_function("header")
            .ok_or_else(|| anyhow!("Could not call header"))?;
        let _ = var_dump.try_call(vec![&format!("content-security-policy: {}", self.build()?)]);
        Ok(())
    }

    /// Returns the most recently generated nonce, if any.
    ///
    /// # Returns
    /// - `Option<&str>` The raw nonce string (without the `'nonce-'` prefix), or `None` if `build()` has not yet generated one.
    pub fn get_nonce(&self) -> Option<&str> {
        self.nonce.as_ref().map(String::as_str)
    }

    /// Resets nonce. It will not be set until next run of build() or send().
    pub fn reset_nonce(&mut self) {
        self.nonce = None;
    }
}
