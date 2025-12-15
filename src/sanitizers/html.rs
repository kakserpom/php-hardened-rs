use ammonia::{Builder, UrlRelative};
use anyhow::anyhow;
use anyhow::{Result, bail};
#[cfg(not(any(test, feature = "test")))]
use ext_php_rs::prelude::ZendCallable;
use ext_php_rs::types::ZendClassObject;
#[cfg(not(any(test, feature = "test")))]
use ext_php_rs::types::Zval;
use ext_php_rs::{php_class, php_impl};
use std::collections::HashSet;
#[cfg(not(any(test, feature = "test")))]
use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, Sender, channel},
};
#[cfg(not(any(test, feature = "test")))]
use std::thread;
#[cfg(not(any(test, feature = "test")))]
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};
use unicode_segmentation::UnicodeSegmentation;
use url::Url;

#[cfg(not(any(test, feature = "test")))]
type _Zval = Zval;
#[cfg(any(test, feature = "test"))]
type _Zval = str;
#[php_class]
#[php(name = "Hardened\\Sanitizers\\HtmlSanitizer")]
/// PHP class wrapping Ammonia's HTML sanitizer builder.
/// Allows customized sanitization through PHP method calls.
pub struct HtmlSanitizer {
    inner: Option<Builder>,
    #[cfg(not(any(test, feature = "test")))]
    attribute_filter: Option<Zval>,
    #[cfg(not(any(test, feature = "test")))]
    req_rx: Option<Receiver<Option<FilterRequest>>>,
    #[cfg(not(any(test, feature = "test")))]
    resp_tx: Option<Sender<FilterResponse>>,
    #[cfg(not(any(test, feature = "test")))]
    req_tx: Option<Sender<Option<FilterRequest>>>,
    pub truncation_is_safe: bool,
}
#[cfg(not(any(test, feature = "test")))]
struct FilterRequest {
    element: String,
    attribute: String,
    value: String,
}

#[cfg(not(any(test, feature = "test")))]
struct FilterResponse {
    filtered: Option<String>,
}

#[php_impl]
impl HtmlSanitizer {
    const TRUNCATE_DEFAULT_ENDING: &'static str = "…";

    /// Constructs a sanitizer with default configuration.
    ///
    /// # Returns
    /// - HtmlSanitizer A new sanitizer instance.
    #[inline]
    pub fn _default() -> Self {
        Self {
            inner: Some(Builder::default()),
            truncation_is_safe: true,
            #[cfg(not(any(test, feature = "test")))]
            attribute_filter: None,
            #[cfg(not(any(test, feature = "test")))]
            req_rx: None,
            #[cfg(not(any(test, feature = "test")))]
            resp_tx: None,
            #[cfg(not(any(test, feature = "test")))]
            req_tx: None,
        }
    }

    /// Constructs a sanitizer with default configuration.
    ///
    /// # Returns
    /// - HtmlSanitizer A new sanitizer instance.
    fn __construct() -> Self {
        Self::_default()
    }

    /// Denies all relative URLs in attributes.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn url_relative_deny(
        self_: &mut ZendClassObject<HtmlSanitizer>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.url_relative(UrlRelative::Deny);
        Ok(self_)
    }

    /// Checks whether a URL is valid according to the sanitizer’s configured
    /// URL scheme whitelist and relative-URL policy.
    ///
    /// # Parameters
    /// - `url`: The URL string to validate.
    ///
    /// # Returns
    /// - `bool`: `true` if the URL’s scheme is whitelisted, or if it is a relative URL
    ///   and relative URLs are permitted; `false` otherwise.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the sanitizer is not in a valid state.
    fn is_valid_url(&self, url: &str) -> Result<bool> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        let url = Url::parse(url);
        Ok(if let Ok(url) = url {
            inner.clone_url_schemes().contains(url.scheme())
        } else if url == Err(url::ParseError::RelativeUrlWithoutBase) {
            !inner.is_url_relative_deny()
        } else {
            false
        })
    }

    /// Passes through relative URLs unchanged.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn url_relative_passthrough(
        self_: &mut ZendClassObject<HtmlSanitizer>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.url_relative(UrlRelative::PassThrough);
        Ok(self_)
    }

    /// Rewrites relative URLs using the given base URL.
    ///
    /// # Parameters
    /// - `base_url`: The base URL to resolve relative URLs against.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `base_url` is not a valid URL.
    fn url_relative_rewrite_with_base(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        base_url: String,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.url_relative(UrlRelative::RewriteWithBase(
            Url::parse(base_url.as_str()).map_err(|err| anyhow!("{err}"))?,
        ));
        Ok(self_)
    }

    /// Rewrites relative URLs using a root URL and path prefix.
    ///
    /// # Parameters
    /// - `root`: The root URL string.
    /// - `path`: The URL path prefix.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `root` is not a valid URL.
    fn url_relative_rewrite_with_root(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        root: String,
        path: String,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.url_relative(UrlRelative::RewriteWithRoot {
            root: Url::parse(root.as_str()).map_err(|err| anyhow!("{err}"))?,
            path,
        });
        Ok(self_)
    }

    /// Sets the `rel` attribute for generated `<a>` tags.
    ///
    /// # Parameters
    /// - `value`: Optional `rel` attribute value; `None` clears it.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn link_rel(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        value: Option<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.link_rel(value);
        Ok(self_)
    }

    /// Overwrites the set of allowed tags.
    ///
    /// # Parameters
    /// - `tags`: An array of allowed tag names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `tags` is not an array.
    fn tags(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tags: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.tags(tags);
        Ok(self_)
    }

    /// Sets the tags whose contents will be completely removed from the output.
    ///
    /// # Parameters
    /// - `tags`: An array of allowed tag names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `tags` is not an array.
    /// - Adding tags which are whitelisted in tags or tag_attributes will cause a panic.
    fn clean_content_tags(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tags: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.clean_content_tags(tags);
        Ok(self_)
    }

    /// Add additional blacklisted clean-content tags without overwriting old ones.
    ///
    /// Does nothing if the tag is already there.
    ///
    /// # Parameters
    /// - `tags`: An array of tag names to add.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `tags` is not an array.
    fn add_clean_content_tags(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tags: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.add_clean_content_tags(tags);
        Ok(self_)
    }

    /// Remove already-blacklisted clean-content tags.
    ///
    /// Does nothing if the tags aren’t blacklisted.
    ///
    /// # Parameters
    /// - `tags`: An array of tag names to add.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `tags` is not an array.
    fn rm_clean_content_tags(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tags: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.rm_clean_content_tags(tags.iter());
        Ok(self_)
    }

    /// Adds additional allowed tags to the existing whitelist.
    ///
    /// # Parameters
    /// - `tags`: An array of tag names to add.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `tags` is not an array.
    fn add_tags(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tags: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        if self_.inner.is_none() {
            bail!("You cannot do this now");
        };
        if tags.iter().any(|tag_name| {
            tag_name.eq_ignore_ascii_case("script") || tag_name.eq_ignore_ascii_case("style")
        }) {
            self_.truncation_is_safe = false;
        }
        self_.inner.as_mut().unwrap().tags(tags);
        Ok(self_)
    }

    /// Removes tags from the whitelist.
    ///
    /// # Parameters
    /// - `tags`: An array of tag names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn rm_tags(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tags: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.rm_tags(tags.iter().map(String::as_str));
        self_.truncation_is_safe = !self_
            .clone_clean_content_tags()?
            .iter()
            .any(|x| x.eq_ignore_ascii_case("script") || x.eq_ignore_ascii_case("style"));
        Ok(self_)
    }

    /// Adds allowed CSS classes for a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `classes`: An array of CSS class names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn add_allowed_classes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tag: String,
        classes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.add_allowed_classes(tag, classes);
        Ok(self_)
    }

    /// Removes allowed CSS classes from a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `classes`: An array of CSS class names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn rm_allowed_classes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tag: String,
        classes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.rm_allowed_classes(tag.as_str(), classes.iter().map(String::as_str));
        Ok(self_)
    }

    /// Adds allowed attributes to a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `attributes`: An array of attribute names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn add_tag_attributes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tag: String,
        attributes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.add_tag_attributes(tag, attributes);
        Ok(self_)
    }

    /// Removes attributes from a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `classes`: An array of attribute names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn rm_tag_attributes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tag: String,
        classes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.rm_tag_attributes(tag.as_str(), classes.iter().map(String::as_str));
        Ok(self_)
    }

    /// Adds generic attributes to all tags.
    ///
    /// # Parameters
    /// - `attributes`: An array of attribute names to allow.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - `Exception` if `attributes` is not an array.
    fn add_generic_attributes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        attributes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.add_generic_attributes(attributes);
        Ok(self_)
    }

    /// Removes generic attributes from all tags.
    ///
    /// # Parameters
    /// - `attributes`: An array of attribute names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn rm_generic_attributes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        attributes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.rm_generic_attributes(attributes.iter().map(String::as_str));
        Ok(self_)
    }

    /// Adds prefixes for generic attributes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes to allow.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn add_generic_attribute_prefixes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        prefixes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.add_generic_attribute_prefixes(prefixes);
        Ok(self_)
    }

    /// Removes prefixes for generic attributes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn rm_generic_attribute_prefixes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        prefixes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.rm_generic_attribute_prefixes(prefixes.iter().map(String::as_str));
        Ok(self_)
    }

    /// Sanitizes the given HTML string, applying any configured attribute filter.
    ///
    /// # Parameters
    /// - `html`: The HTML content to sanitize.
    ///
    /// # Returns
    /// - `String` The sanitized HTML.
    ///
    /// # Notes
    /// - If an attribute filter is set, it will be invoked for each attribute.
    pub fn clean(&mut self, html: String) -> Result<String> {
        let inner = if let Some(inner) = self.inner.as_ref() {
            inner
        } else {
            bail!("inner is not available");
        };

        #[cfg(any(test, feature = "test"))]
        return Ok(inner.clean(&html).to_string());

        #[cfg(not(any(test, feature = "test")))]
        {
            let Some(filter) = self.attribute_filter.as_ref() else {
                return Ok(inner.clean(&html).to_string());
            };
            let inner = self.inner.take().unwrap();
            let req_tx_clone = self
                .req_tx
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("No tx clone"))?;
            let handle = thread::spawn(move || -> Result<_> {
                let result = inner.clean(&html).to_string();
                req_tx_clone.send(None).map_err(|err| anyhow!("{err}"))?;
                Ok((inner, result))
            });
            let callable = ZendCallable::new(filter).map_err(|err| anyhow!("{err}"))?;
            for req in self
                .req_rx
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no req tx"))?
            {
                let Some(req) = req else {
                    break;
                };
                let result = callable
                    .try_call(vec![&req.element, &req.attribute, &req.value])
                    .ok()
                    .and_then(|zval| zval.string());
                let _ = self
                    .resp_tx
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no resp tx"))?
                    .send(FilterResponse { filtered: result });
            }
            let (inner, result) = handle
                .join()
                .map_err(|err| anyhow!("thread error: {err:?}"))??;
            let _ = self.inner.insert(inner);
            Ok(result)
        }
    }

    /// Whitelists URL schemes (e.g., "http", "https").
    ///
    /// # Parameters
    /// - `schemes`: An array of scheme strings to allow.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn url_schemes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        schemes: HashSet<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.url_schemes(schemes);
        Ok(self_)
    }

    /// Enables or disables HTML comment stripping.
    ///
    /// # Parameters
    /// - `strip`: `true` to strip comments; `false` to preserve them.
    ///    Comments are stripped by default.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn strip_comments(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        strip: bool,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.strip_comments(strip);
        Ok(self_)
    }

    /// Returns whether HTML comments will be stripped.
    ///
    /// # Returns
    /// - `bool`: `true` if comments will be stripped; `false` otherwise.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn will_strip_comments(&self) -> Result<bool> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(inner.will_strip_comments())
    }

    /// Prefixes all `id` attributes with the given string.
    ///
    /// # Parameters
    /// - `prefix`: Optional string prefix to apply.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn id_prefix(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        prefix: Option<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.id_prefix(prefix);
        Ok(self_)
    }

    /// Filters CSS style properties allowed in `style` attributes.
    ///
    /// # Parameters
    /// - `props`: An array of CSS property names to allow.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn new_filter_style_properties(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        props: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.filter_style_properties(props);
        Ok(self_)
    }

    fn filter_style_properties(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        props: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.filter_style_properties(props);
        Ok(self_)
    }

    /// Sets a single tag attribute value.
    ///
    /// # Parameters
    /// - `tag`: The tag name as A string.
    /// - `attribute`: The attribute name as A string.
    /// - `value`: The value to set.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn set_tag_attribute_value(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tag: String,
        attribute: String,
        value: String,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.set_tag_attribute_value(tag, attribute, value);
        Ok(self_)
    }

    /// Returns the configured tags as a vector of strings.
    ///
    /// # Returns
    /// - `Vec<String>` The list of allowed tag names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn clone_tags(&self) -> Result<Vec<String>> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(inner.clone_tags().into_iter().collect())
    }

    /// Gets all configured clean-content tags.
    ///
    /// # Returns
    /// - `Vec<String>` The list of tags whose content is preserved.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn clone_clean_content_tags(&self) -> Result<Vec<String>> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(inner
            .clone_clean_content_tags()
            .iter()
            .map(|s| s.to_string())
            .collect())
    }

    /// Bulk overwrites generic attributes.
    ///
    /// # Parameters
    /// - `attrs`: An array of attribute names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn generic_attributes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        attrs: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.generic_attributes(attrs);
        Ok(self_)
    }

    /// Bulk overwrites generic attribute prefixes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn generic_attribute_prefixes(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        prefixes: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.generic_attribute_prefixes(prefixes);
        Ok(self_)
    }

    /// Adds tag attribute values.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `attr`: A string attribute name.
    /// - `values`: An array of values to allow.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn add_tag_attribute_values(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tag: String,
        attr: String,
        values: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.add_tag_attribute_values(tag, attr, values);
        Ok(self_)
    }

    /// Removes tag attribute values.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `attr`: A string attribute name.
    /// - `values`: An array of values to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn rm_tag_attribute_values(
        self_: &mut ZendClassObject<HtmlSanitizer>,
        tag: String,
        attr: String,
        values: Vec<String>,
    ) -> Result<&mut ZendClassObject<HtmlSanitizer>> {
        let Some(inner) = self_.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        inner.rm_tag_attribute_values(
            tag.as_str(),
            attr.as_str(),
            values.iter().map(String::as_str),
        );
        Ok(self_)
    }

    /// Gets a single tag attribute value setting.
    ///
    /// # Parameters
    /// - `tag`: The tag name as A string.
    /// - `attr`: The attribute name as A string.
    ///
    /// # Returns
    /// - `Option<String>` The configured value or `None` if unset.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn get_set_tag_attribute_value(&self, tag: &str, attr: &str) -> Result<Option<String>> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(inner
            .get_set_tag_attribute_value(tag, attr)
            .map(|s| s.to_string()))
    }

    /// Checks if URL relative policy is Deny.
    ///
    /// # Returns
    /// - `bool` `true` if the policy is Deny.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn is_url_relative_deny(&self) -> Result<bool> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(inner.is_url_relative_deny())
    }

    /// Checks if URL relative policy is PassThrough.
    ///
    /// # Returns
    /// - `bool` `true` if the policy is PassThrough.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn is_url_relative_pass_through(&self) -> Result<bool> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(inner.is_url_relative_pass_through())
    }

    /// Checks if URL relative policy is custom (Rewrite).
    ///
    /// # Returns
    /// - `bool` `true` if a custom rewrite policy is set.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    fn is_url_relative_custom(&self) -> Result<bool> {
        let Some(inner) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(inner.is_url_relative_custom())
    }

    /// Sets the attribute filter callback.
    ///
    /// # Parameters
    /// - `callable`: A PHP callable of signature `(string Element, string Attribute, string Value) -> string|null`.
    ///
    /// # Exceptions
    /// - None.
    fn attribute_filter<'a>(
        #[allow(unused_variables)] self_: &'a mut ZendClassObject<HtmlSanitizer>,
        #[allow(unused_variables)] callable: &'a _Zval,
    ) -> Result<&'a mut ZendClassObject<HtmlSanitizer>> {
        #[cfg(not(any(test, feature = "test")))]
        {
            self_.attribute_filter = Some(callable.shallow_clone());
            let (req_tx, req_rx) = channel::<Option<FilterRequest>>();
            let (resp_tx, resp_rx) = channel::<FilterResponse>();
            let resp_rx = Arc::new(Mutex::new(resp_rx));
            self_.req_tx = Some(req_tx.clone());
            self_.req_rx = Some(req_rx);
            self_.resp_tx = Some(resp_tx);
            let inner = self_
                .inner
                .as_mut()
                .ok_or_else(|| anyhow!("You cannot do this now"))?;
            inner.attribute_filter(move |element, attribute, value| {
                let _ = req_tx.send(Some(FilterRequest {
                    element: element.to_string(),
                    attribute: attribute.to_string(),
                    value: value.to_string(),
                }));

                let resp = resp_rx
                    .lock()
                    .expect("Mutex error")
                    .recv()
                    .unwrap_or(FilterResponse { filtered: None });

                resp.filtered
            });
            Ok(self_)
        }
        #[cfg(any(test, feature = "test"))]
        panic!("attribute_filter() can not be called from tests");
    }

    /// Sanitize and truncate the given HTML by extended grapheme clusters.
    ///
    /// This is a convenience wrapper that ensures no user-perceived character
    /// (including complex emoji or combined sequences) is split in half.
    ///
    /// # Parameters
    /// - `html`: Raw HTML string to sanitize and truncate.
    /// - `max_units`: Maximum number of Unicode extended grapheme clusters
    ///   to retain (including the `etc` suffix).
    /// - `etc`: Optional suffix (e.g., ellipsis) to join when truncation occurs. Default is …
    ///
    /// # Exceptions
    /// - Throws `Exception` if sanitization or truncation fails.
    pub fn clean_and_truncate(
        &mut self,
        #[allow(unused_variables)] html: String,
        #[allow(unused_variables)] max: usize,
        #[allow(unused_variables)] flags: &_Zval,
        #[allow(unused_variables)] etc: Option<String>,
    ) -> Result<String> {
        #[cfg(not(any(test, feature = "test")))]
        {
            let flags = if let Some(array) = flags.array()
                && array.has_sequential_keys()
            {
                array
                    .into_iter()
                    .map(|(_, str)| {
                        let str = str.str().ok_or_else(|| {
                            anyhow!(
                                "Incorrect flag: {str:?}. Valid flags are: {:?}",
                                Flag::iter().map(|f| f.to_string()).collect::<Vec<_>>()
                            )
                        })?;
                        Flag::try_from(str).map_err(|_| anyhow!("Incorrect flag: {str:?}"))
                    })
                    .collect::<Result<Vec<Flag>>>()?
            } else if let Some(str) = flags.str() {
                vec![Flag::try_from(str).map_err(|_| {
                    anyhow!(
                        "Incorrect flag: {str:?}. Valid flags are: {:?}",
                        Flag::iter().map(|f| f.to_string()).collect::<Vec<_>>()
                    )
                })?]
            } else {
                bail!("Wrong argument `flags`");
            };
            self._clean_and_truncate(html, max, flags.as_slice(), etc)
        }
        #[cfg(any(test, feature = "test"))]
        panic!("clean_and_truncate() can not be called from tests; use _clean_and_truncate()");
    }
}
impl HtmlSanitizer {
    /// Sanitize HTML, then truncate it safely to a specified limit without breaking UTF-8, characters, graphemes, or HTML structure.
    ///
    /// This method performs three main steps:
    /// 1. **Sanitization**: Cleans the input HTML using the existing `clean` method, removing disallowed tags and attributes.
    /// 2. **Truncation**: Computes the correct byte index to truncate based on the chosen `CountBy` mode:
    ///    - `Bytes`            — ensure valid UTF-8 by backing up to a `char` boundary.
    ///    - `Characters`       — cut at the boundary of the Nth Unicode scalar (`char`).
    ///    - `Graphemes`        — cut at the boundary of the Nth user-perceived grapheme cluster.
    ///    - `ExtendedGraphemes`— similar to `Graphemes`, but includes extended clusters (e.g. emoji sequences).
    /// 3. **Ellipsis & Resanitize**: joins the optional `etc` suffix (defaulting to an ellipsis), and re-sanitizes
    ///    to close any open tags introduced by truncation.
    ///
    /// # Parameters
    /// - `html`: `String` containing the raw HTML content to sanitize and truncate.
    /// - `max`: `usize` maximum number of *units* (bytes, characters, or graphemes) in the final output,
    ///    including the length of the `etc` suffix.
    /// - `count_by`: `&CountBy` enum selecting the unit of measurement for `max`.
    /// - `etc`:  `Option<String>` optional suffix to join when truncation occurs (e.g. ellipsis).
    ///    Defaults to [`TRUNCATE_DEFAULT_ENDING`].
    ///
    /// # Returns
    /// - `Ok(String)` containing a sanitized, well-formed HTML snippet, no longer than `max` units.
    /// - `Err(...)` if sanitization fails at any stage.
    #[inline]
    pub fn _clean_and_truncate(
        &mut self,
        html: String,
        max: usize,
        flags: &[Flag],
        etc: Option<String>,
    ) -> Result<String> {
        let etc = etc.unwrap_or_else(|| Self::TRUNCATE_DEFAULT_ENDING.into());
        let mut count_by = None;
        let mut preserve_words = false;
        if !self.truncation_is_safe {
            bail!("Truncation is not safe because you have allowed script/style tags");
        }
        for flag in flags {
            match flag {
                Flag::ExtendedGraphemes | Flag::Graphemes | Flag::Unicode | Flag::Ascii => {
                    if let Some(other) = count_by.replace(flag) {
                        bail!("Conflicting flags: {other} and {flag}");
                    }
                }
                Flag::PreserveWords => {
                    preserve_words = true;
                }
            }
        }
        let count_by = count_by.cloned().unwrap_or(Flag::Unicode);
        // Determine how many “units” of real content we can use,
        // reserving space for the ending string.
        let reserved = match count_by {
            Flag::ExtendedGraphemes => etc.graphemes(true).count(),
            Flag::Graphemes => etc.graphemes(false).count(),
            Flag::Unicode => etc.chars().count(),
            Flag::Ascii => etc.len(),
            _ => unreachable!(),
        };
        let limit = max.saturating_sub(reserved);

        // First sanitize
        let mut html = self.clean(html)?.to_string();

        #[cfg(test)]
        println!("first html sanitization: {html:?}");

        // Compute the byte index up to which to keep content.
        let mut cut_offset = match count_by {
            Flag::ExtendedGraphemes => html
                .grapheme_indices(true)
                .nth(limit)
                .map(|(byte_idx, _)| byte_idx)
                .or(Some(html.len())),
            Flag::Graphemes => html
                .grapheme_indices(false)
                .nth(limit)
                .map(|(byte_idx, _)| byte_idx)
                .or(Some(html.len())),
            Flag::Unicode => {
                // Count Unicode chars and get byte offset of the Nth char
                html.char_indices()
                    .nth(limit)
                    .map(|(byte_idx, _)| byte_idx)
                    .or(Some(html.len()))
            }
            Flag::Ascii => {
                // We want at most `limit` bytes, but ensure we cut on a char boundary:
                let bytes = html.as_bytes();
                if bytes.len() <= limit {
                    Some(bytes.len())
                } else {
                    // Scan back from `limit` down to the previous UTF-8 boundary:
                    (0..=limit).rev().find(|&i| html.is_char_boundary(i))
                }
            }
            _ => unreachable!(),
        };

        if let Some(idx) = cut_offset {
            for (steps, byte) in html.as_bytes()[..idx].iter().rev().enumerate() {
                if byte.eq(&b'>') {
                    break;
                } else if byte.eq(&b'<') {
                    let _ = cut_offset.insert(idx - steps - 1);
                    break;
                }
            }
        }

        if preserve_words {
            if let Some(idx) = cut_offset {
                let mut last_boundary = 0;
                for (byte_idx, _) in html[..idx].split_word_bound_indices() {
                    last_boundary = byte_idx;
                }
                if last_boundary > 0 && last_boundary < idx {
                    let mut spaces = last_boundary - html[..last_boundary].trim_end().len();
                    if spaces > 1 {
                        spaces -= 1;
                    }
                    cut_offset = Some(last_boundary - spaces);
                }
                #[cfg(test)]
                println!(
                    "preserve_words: trimmed to {:?}",
                    html[..last_boundary].to_string()
                );
            }
        }

        // If we actually need to truncate:
        if let Some(idx) = cut_offset
            && idx + etc.len() < html.len()
        {
            html.truncate(idx);
            html.push_str(&etc);

            #[cfg(test)]
            println!("truncated to {html:?}");

            // Re-sanitize to close any unenclosed tags introduced by truncation
            Ok(self.clean(html)?)
        } else {
            Ok(html)
        }
    }
}
#[derive(EnumIter, EnumString, Display, Debug, Clone)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub enum Flag {
    #[strum(serialize = "e", serialize = "extended-graphemes")]
    ExtendedGraphemes,
    #[strum(serialize = "g", serialize = "graphemes")]
    Graphemes,
    #[strum(serialize = "u", serialize = "unicode")]
    Unicode,
    #[strum(serialize = "a", serialize = "ascii")]
    Ascii,
    #[strum(serialize = "pw", serialize = "preserve-words")]
    PreserveWords,
}
#[cfg(test)]
mod tests {
    use super::HtmlSanitizer;
    use crate::run_php_example;
    use crate::sanitizers::html::Flag::{Ascii, Graphemes, PreserveWords};
    use ammonia::UrlRelative;
    use anyhow::{Result, anyhow, bail};
    use assertables::{assert_contains, assert_le, assert_not_contains};
    use std::collections::HashSet;
    use url::Url;

    #[test]
    fn test_strip_comments_toggle_and_clean() -> Result<()> {
        let mut s = HtmlSanitizer::_default();
        // By default comments are stripped
        assert!(s.will_strip_comments()?);
        let html = "<div><!--comment--><p>text</p></div>".to_string();
        let out = s.clean(html.clone())?;
        assert_not_contains!(out, "<!--comment-->");

        // Disable stripping
        s._strip_comments(false)?;
        assert!(!(s.will_strip_comments()?));
        let out2 = s.clean(html)?;
        assert_contains!(out2, "<!--");

        Ok(())
    }

    #[test]
    fn test_is_valid_url_and_relative_policy() -> Result<()> {
        let mut s = HtmlSanitizer::_default();
        // Absolute http/https/... are allowed by default
        assert!(s.is_valid_url("http://example.com")?);
        assert!(s.is_valid_url("https://foo/")?);
        assert!(s.is_valid_url("ftp://example.com")?);

        s._url_schemes(vec![String::from("http"), String::from("https")])?;

        // Relative without base allowed by default
        assert!(s.is_valid_url("/foo/bar")?);

        // Deny relative URLs
        s._url_relative_deny()?;
        assert!(!s.is_valid_url("/foo")?);

        // Pass through relative URLs
        s._url_relative_passthrough()?;
        assert!(s.is_valid_url("/foo")?);

        Ok(())
    }

    #[test]
    fn test_url_relative_rewrite_in_clean() -> Result<()> {
        let mut s = HtmlSanitizer::_default();
        // Rewrite relative using base
        s._url_relative_rewrite_with_base("https://example.com")?;
        let html = r#"<a href="/path/to">link</a>"#.to_string();
        let out = s.clean(html)?;
        assert_contains!(out, r#"href="https://example.com/path/to""#);
        Ok(())
    }

    #[test]
    fn test_id_prefix_applied() -> Result<()> {
        let mut s = HtmlSanitizer::_default();
        s._add_tag_attributes(String::from("div"), vec![String::from("id")])?;
        s._id_prefix(Some("pre-".to_string()))?;
        let html = r#"<div id="one">x</div>"#.to_string();
        let out = s.clean(html)?;
        assert_contains!(out, r#"id="pre-one""#);
        Ok(())
    }

    #[test]
    fn test_unenclosed_tag() -> Result<()> {
        let mut s = HtmlSanitizer::_default();
        s._tags(vec![String::from("a"), String::from("b")])?;
        let html = r#"<a><b>link</a>"#.to_string();
        let out = s.clean(html)?;
        assert_contains!(out, r#"<a rel="noopener noreferrer"><b>link</b></a>"#);
        Ok(())
    }
    /// Test that clean_and_truncate removes disallowed tags, preserves allowed ones,
    /// and truncates the text to the specified length without breaking HTML structure.
    #[test]
    fn test_clean_and_truncate() -> Result<()> {
        assert_not_contains!(
            HtmlSanitizer::_default()._clean_and_truncate(
                "<p>Курва<p>!!</p>!</p>".into(),
                20,
                &[Graphemes],
                Some(" (more)".into()),
            )?,
            "&lt;",
        );

        assert_eq!(
            HtmlSanitizer::_default()._clean_and_truncate(
                "<p>Hello     woooooooooorld!</p>".into(),
                20,
                &[Graphemes, PreserveWords],
                None,
            )?,
            "<p>Hello …</p>",
        );

        let mut s = HtmlSanitizer::_default();
        s._add_tags(vec!["script".into()])?;
        s._rm_clean_content_tags(vec!["script".into()])?;
        assert!(
            s._clean_and_truncate("<script>unenclosed script contents".into(), 20, &[], None)
                .is_err()
        );

        // 1. Set up the sanitizer to allow only <a> and <b> tags
        let mut s = HtmlSanitizer::_default();
        s._tags(vec!["a".into(), "b".into(), "p".into()])?;

        assert_eq!(
            s._clean_and_truncate(
                "<p>Привет мир</p>".into(),
                20,
                &[Graphemes],
                Some(" (more)".into())
            )?,
            "<p>Привет мир</p>"
        );

        // 2. Example HTML with:
        //    - a disallowed <script> tag (should be removed)
        //    - allowed <a> and <b> tags
        //    - an <i> tag (disallowed—should be stripped, leaving its text)
        //    - text long enough to require truncation
        let html = r#"
            <script>alert("bad")</script>
            Hello <a href="https://example.com">Example Site</a>!
            <b>BoldText</b> and <i>ItalicText</i><b>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed \
do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, \
quis nostrud exercitation ullamco laboris nisi ut aliquip exea \
commodo consequat. Duis aute irure dolor in reprehenderit \
in voluptate velit esse cillum dolore eu fugiat nulla pariatur.\
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui \
 officia deserunt mollit anim id est laborum.</b>"
        "#
            .to_string();

        let max_length = 200;

        // 3. Clean & truncate to 50 characters of text
        let out = s
            ._clean_and_truncate(html, max_length, &[Ascii], None)
            .unwrap();

        // 4. The output should:
        //    - Not contain "<script>" or "</script>"
        //    - Still contain the <a> and <b> elements
        //    - Have the <i> tags stripped but their text preserved
        //    - End with the ellipsis "…" to indicate truncation
        assert!(!out.contains("<script>"));
        assert_contains!(
            out,
            r#"<a href="https://example.com" rel="noopener noreferrer">Example Site</a>"#
        );
        assert_contains!(out, "Lorem ipsum dolor sit amet");
        assert_contains!(out, "ItalicText"); // <i> stripped
        assert_le!(out.len(), max_length + 10);
        assert_contains!(out[out.len() - 10..], "…");

        // 5. Ensure no broken tags: count opening vs closing tags for allowed set
        let open_a = out.matches("<a ").count();
        let close_a = out.matches("</a>").count();
        assert_eq!(open_a, close_a, "<a> tags must be balanced");

        let open_b = out.matches("<b>").count();
        let close_b = out.matches("</b>").count();
        assert_eq!(open_b, close_b, "<b> tags must be balanced");

        Ok(())
    }

    #[test]
    fn php_example() -> Result<()> {
        run_php_example("sanitizers/html")?;
        Ok(())
    }

    impl HtmlSanitizer {
        fn _url_relative_passthrough(&mut self) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.url_relative(UrlRelative::PassThrough);
            Ok(())
        }

        fn _url_relative_deny(&mut self) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.url_relative(UrlRelative::Deny);
            Ok(())
        }

        fn _url_relative_rewrite_with_base(&mut self, base_url: &str) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.url_relative(UrlRelative::RewriteWithBase(
                Url::parse(base_url).map_err(|err| anyhow!("{err}"))?,
            ));
            Ok(())
        }

        fn _url_relative_rewrite_with_root(&mut self, root: &str, path: String) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.url_relative(UrlRelative::RewriteWithRoot {
                root: Url::parse(root).map_err(|err| anyhow!("{err}"))?,
                path,
            });
            Ok(())
        }

        /// Must match add_tags()
        fn _add_tags(&mut self, tags: Vec<String>) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            if tags
                .iter()
                .any(|x| x.eq_ignore_ascii_case("script") || x.eq_ignore_ascii_case("style"))
            {
                self.truncation_is_safe = false;
            }
            inner.tags(tags);
            Ok(())
        }

        fn _rm_clean_content_tags(&mut self, tags: Vec<String>) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.rm_clean_content_tags(tags.iter());
            Ok(())
        }

        fn _add_tag_attributes(&mut self, tag: String, attributes: Vec<String>) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.add_tag_attributes(tag, attributes);
            Ok(())
        }

        fn _tags(&mut self, tags: Vec<String>) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.tags(tags);
            Ok(())
        }

        fn _id_prefix(&mut self, prefix: Option<String>) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.id_prefix(prefix);
            Ok(())
        }

        fn _url_schemes(&mut self, schemes: Vec<String>) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.url_schemes(HashSet::from_iter(schemes));
            Ok(())
        }

        fn _strip_comments(&mut self, strip: bool) -> Result<()> {
            let Some(inner) = self.inner.as_mut() else {
                bail!("You cannot do this now");
            };
            inner.strip_comments(strip);
            Ok(())
        }
    }
}
