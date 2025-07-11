use ammonia::{Builder, UrlRelative};
use anyhow::anyhow;
use anyhow::{Result, bail};
#[cfg(not(test))]
use ext_php_rs::prelude::ZendCallable;
#[cfg(not(test))]
use ext_php_rs::types::Zval;
use ext_php_rs::{php_class, php_impl};
use std::collections::HashSet;
#[cfg(not(test))]
use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, Sender, channel},
};
#[cfg(not(test))]
use std::thread;
use url::Url;

#[cfg(not(test))]
type _Zval = Zval;
#[cfg(test)]
type _Zval = str;
#[php_class]
#[php(name = "Hardened\\Sanitizers\\HtmlSanitizer")]
/// PHP class wrapping Ammonia's HTML sanitizer builder.
/// Allows customized sanitization through PHP method calls.
pub struct HtmlSanitizer {
    inner: Option<Builder>,
    #[cfg(not(test))]
    attribute_filter: Option<Zval>,
    #[cfg(not(test))]
    req_rx: Option<Receiver<Option<FilterRequest>>>,
    #[cfg(not(test))]
    resp_tx: Option<Sender<FilterResponse>>,
    #[cfg(not(test))]
    req_tx: Option<Sender<Option<FilterRequest>>>,
}
#[cfg(not(test))]
struct FilterRequest {
    element: String,
    attribute: String,
    value: String,
}

#[cfg(not(test))]
struct FilterResponse {
    filtered: Option<String>,
}

#[php_impl]
impl HtmlSanitizer {
    #[inline]
    /// Constructs a sanitizer with default configuration.
    ///
    /// # Returns
    /// - HtmlSanitizer A new sanitizer instance.
    ///
    /// # Notes
    /// - No exceptions are thrown.
    pub fn default() -> Self {
        Self {
            inner: Some(Builder::default()),
            #[cfg(not(test))]
            attribute_filter: None,
            #[cfg(not(test))]
            req_rx: None,
            #[cfg(not(test))]
            resp_tx: None,
            #[cfg(not(test))]
            req_tx: None,
        }
    }

    /// Denies all relative URLs in attributes.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn url_relative_deny(&mut self) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.url_relative(UrlRelative::Deny);
        Ok(())
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
    pub fn is_valid_url(&self, url: &str) -> Result<bool> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        let url = Url::parse(url);
        Ok(if let Ok(url) = url {
            x.clone_url_schemes().contains(url.scheme())
        } else if url == Err(url::ParseError::RelativeUrlWithoutBase) {
            !x.is_url_relative_deny()
        } else {
            false
        })
    }

    /// Passes through relative URLs unchanged.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn url_relative_passthrough(&mut self) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.url_relative(UrlRelative::PassThrough);
        Ok(())
    }

    /// Rewrites relative URLs using the given base URL.
    ///
    /// # Parameters
    /// - `base_url`: The base URL to resolve relative URLs against.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `base_url` is not a valid URL.
    pub fn url_relative_rewrite_with_base(&mut self, base_url: &str) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.url_relative(UrlRelative::RewriteWithBase(
            Url::parse(base_url).map_err(|err| anyhow!("{err}"))?,
        ));
        Ok(())
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
    pub fn url_relative_rewrite_with_root(&mut self, root: &str, path: String) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.url_relative(UrlRelative::RewriteWithRoot {
            root: Url::parse(root).map_err(|err| anyhow!("{err}"))?,
            path,
        });
        Ok(())
    }

    /// Sets the `rel` attribute for generated `<a>` tags.
    ///
    /// # Parameters
    /// - `value`: Optional `rel` attribute value; `None` clears it.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn link_rel(&mut self, value: Option<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.link_rel(value);
        Ok(())
    }

    /// Overwrites the set of allowed tags.
    ///
    /// # Parameters
    /// - `tags`: An array of allowed tag names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `tags` is not an array.
    pub fn tags(&mut self, tags: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.tags(tags);
        Ok(())
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
    pub fn clean_content_tags(&mut self, tags: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.clean_content_tags(tags);
        Ok(())
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
    pub fn add_clean_content_tags(&mut self, tags: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.add_clean_content_tags(tags);
        Ok(())
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
    pub fn rm_clean_content_tags(&mut self, tags: Vec<&str>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.add_clean_content_tags(tags);
        Ok(())
    }

    /// Adds additional allowed tags to the existing whitelist.
    ///
    /// # Parameters
    /// - `tags`: An array of tag names to add.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    /// - Exception if `tags` is not an array.
    pub fn add_tags(&mut self, tags: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.tags(tags);
        Ok(())
    }

    /// Removes tags from the whitelist.
    ///
    /// # Parameters
    /// - `tags`: An array of tag names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn rm_tags(&mut self, tags: Vec<&str>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.rm_tags(tags);
        Ok(())
    }

    /// Adds allowed CSS classes for a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `classes`: An array of CSS class names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn add_allowed_classes(&mut self, tag: String, classes: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.add_allowed_classes(tag, classes);
        Ok(())
    }

    /// Removes allowed CSS classes from a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `classes`: An array of CSS class names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn rm_allowed_classes(&mut self, tag: &str, classes: Vec<&str>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.rm_allowed_classes(tag, classes);
        Ok(())
    }

    /// Adds allowed attributes to a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `attributes`: An array of attribute names.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn add_tag_attributes(&mut self, tag: String, attributes: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.add_tag_attributes(tag, attributes);
        Ok(())
    }

    /// Removes attributes from a specific tag.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `classes`: An array of attribute names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn rm_tag_attributes(&mut self, tag: &str, classes: Vec<&str>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.rm_tag_attributes(tag, classes);
        Ok(())
    }

    /// Adds generic attributes to all tags.
    ///
    /// # Parameters
    /// - `attributes`: An array of attribute names to allow.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    /// - `Exception` if `attributes` is not an array.
    pub fn add_generic_attributes(&mut self, attributes: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.add_generic_attributes(attributes);
        Ok(())
    }

    /// Removes generic attributes from all tags.
    ///
    /// # Parameters
    /// - `attributes`: An array of attribute names to remove.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn rm_generic_attributes(&mut self, attributes: Vec<&str>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.rm_generic_attributes(attributes);
        Ok(())
    }

    /// Adds prefixes for generic attributes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes to allow.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn add_generic_attribute_prefixes(&mut self, prefixes: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.add_generic_attribute_prefixes(prefixes);
        Ok(())
    }

    /// Removes prefixes for generic attributes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes to remove.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn rm_generic_attribute_prefixes(&mut self, prefixes: Vec<&str>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.rm_generic_attribute_prefixes(prefixes);
        Ok(())
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
        let inner = if let Some(x) = self.inner.as_ref() {
            x
        } else {
            bail!("inner is not available");
        };

        #[cfg(test)]
        return Ok(inner.clean(&html).to_string());

        #[cfg(not(test))]
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
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn url_schemes(&mut self, schemes: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.url_schemes(HashSet::from_iter(schemes));
        Ok(())
    }

    /// Enables or disables HTML comment stripping.
    ///
    /// # Parameters
    /// - `strip`: `true` to strip comments; `false` to preserve them.
    ///    Comments are stripped by default.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn strip_comments(&mut self, strip: bool) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.strip_comments(strip);
        Ok(())
    }

    /// Returns whether HTML comments will be stripped.
    ///
    /// # Returns
    /// - `bool`: `true` if comments will be stripped; `false` otherwise.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn will_strip_comments(&self) -> Result<bool> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(x.will_strip_comments())
    }

    /// Prefixes all `id` attributes with the given string.
    ///
    /// # Parameters
    /// - `prefix`: Optional string prefix to apply.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn id_prefix(&mut self, prefix: Option<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.id_prefix(prefix);
        Ok(())
    }

    /// Filters CSS style properties allowed in `style` attributes.
    ///
    /// # Parameters
    /// - `props`: An array of CSS property names to allow.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn filter_style_properties(&mut self, props: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.filter_style_properties(props);
        Ok(())
    }

    /// Sets a single tag attribute value.
    ///
    /// # Parameters
    /// - `tag`: The tag name as A string.
    /// - `attribute`: The attribute name as A string.
    /// - `value`: The value to set.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn set_tag_attribute_value(
        &mut self,
        tag: String,
        attribute: String,
        value: String,
    ) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        let val_ref: &'static str = Box::leak(Box::new(value));
        x.set_tag_attribute_value(tag, attribute, val_ref);
        Ok(())
    }

    /// Returns the configured tags as a vector of strings.
    ///
    /// # Returns
    /// - `Vec<String>` The list of allowed tag names.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn clone_tags(&self) -> Result<Vec<String>> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(x.clone_tags().into_iter().collect())
    }

    /// Gets all configured clean-content tags.
    ///
    /// # Returns
    /// - `Vec<String>` The list of tags whose content is preserved.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn clone_clean_content_tags(&self) -> Result<Vec<String>> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(x.clone_clean_content_tags()
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
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn generic_attributes(&mut self, attrs: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.generic_attributes(attrs);
        Ok(())
    }

    /// Bulk overwrites generic attribute prefixes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn generic_attribute_prefixes(&mut self, prefixes: Vec<String>) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.generic_attribute_prefixes(prefixes);
        Ok(())
    }

    /// Adds tag attribute values.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `attr`: A string attribute name.
    /// - `values`: An array of values to allow.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn add_tag_attribute_values(
        &mut self,
        tag: String,
        attr: String,
        values: Vec<String>,
    ) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.add_tag_attribute_values(tag, attr, values);
        Ok(())
    }

    /// Removes tag attribute values.
    ///
    /// # Parameters
    /// - `tag`: A string tag name.
    /// - `attr`: A string attribute name.
    /// - `values`: An array of values to remove.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn rm_tag_attribute_values(
        &mut self,
        tag: &str,
        attr: &str,
        values: Vec<&str>,
    ) -> Result<()> {
        let Some(x) = self.inner.as_mut() else {
            bail!("You cannot do this now");
        };
        x.rm_tag_attribute_values(tag, attr, values);
        Ok(())
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
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn get_set_tag_attribute_value(&self, tag: &str, attr: &str) -> Result<Option<String>> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(x.get_set_tag_attribute_value(tag, attr)
            .map(|s| s.to_string()))
    }

    /// Checks if URL relative policy is Deny.
    ///
    /// # Returns
    /// - `bool` `true` if the policy is Deny.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn is_url_relative_deny(&self) -> Result<bool> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(x.is_url_relative_deny())
    }

    /// Checks if URL relative policy is PassThrough.
    ///
    /// # Returns
    /// - `bool` `true` if the policy is PassThrough.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn is_url_relative_pass_through(&self) -> Result<bool> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(x.is_url_relative_pass_through())
    }

    /// Checks if URL relative policy is custom (Rewrite).
    ///
    /// # Returns
    /// - `bool` `true` if a custom rewrite policy is set.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn is_url_relative_custom(&self) -> Result<bool> {
        let Some(x) = self.inner.as_ref() else {
            bail!("You cannot do this now");
        };
        Ok(x.is_url_relative_custom())
    }

    /// Sets the attribute filter callback.
    ///
    /// # Parameters
    /// - `callable`: A PHP callable of signature `(string Element, string Attribute, string Value) -> string|null`.
    ///
    /// # Exceptions
    /// - None.
    pub fn attribute_filter(&mut self, #[allow(unused_variables)] callable: &_Zval) -> Result<()> {
        #[cfg(not(test))]
        {
            self.attribute_filter = Some(callable.shallow_clone());

            let (req_tx, req_rx) = channel::<Option<FilterRequest>>();
            let (resp_tx, resp_rx) = channel::<FilterResponse>();
            let resp_rx = Arc::new(Mutex::new(resp_rx));
            self.req_tx = Some(req_tx.clone());
            self.req_rx = Some(req_rx);
            self.resp_tx = Some(resp_tx);
            let inner = self
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
            Ok(())
        }
        #[cfg(test)]
        panic!("attribute_filter() can not be called from tests");
    }
}

#[cfg(test)]
mod tests {
    use super::HtmlSanitizer;
    use crate::run_php_example;
    use assertables::{assert_contains, assert_not_contains};

    #[test]
    fn test_strip_comments_toggle_and_clean() -> anyhow::Result<()> {
        let mut s = HtmlSanitizer::default();
        // By default comments are stripped
        assert!(s.will_strip_comments()?);
        let html = "<div><!--comment--><p>text</p></div>".to_string();
        let out = s.clean(html.clone())?;
        assert_not_contains!(out, "<!--comment-->");

        // Disable stripping
        s.strip_comments(false)?;
        assert!(!(s.will_strip_comments()?));
        let out2 = s.clean(html)?;
        assert_contains!(out2, "<!--");

        Ok(())
    }

    #[test]
    fn test_is_valid_url_and_relative_policy() -> anyhow::Result<()> {
        let mut s = HtmlSanitizer::default();
        // Absolute http/https/... are allowed by default
        assert!(s.is_valid_url("http://example.com")?);
        assert!(s.is_valid_url("https://foo/")?);
        assert!(s.is_valid_url("ftp://example.com")?);

        s.url_schemes(vec![String::from("http"), String::from("https")])?;

        // Relative without base allowed by default
        assert!(s.is_valid_url("/foo/bar")?);

        // Deny relative URLs
        s.url_relative_deny()?;
        assert!(!s.is_valid_url("/foo")?);

        // Pass through relative URLs
        s.url_relative_passthrough()?;
        assert!(s.is_valid_url("/foo")?);

        Ok(())
    }

    #[test]
    fn test_url_relative_rewrite_in_clean() -> anyhow::Result<()> {
        let mut s = HtmlSanitizer::default();
        // Rewrite relative using base
        s.url_relative_rewrite_with_base("https://example.com")?;
        let html = r#"<a href="/path/to">link</a>"#.to_string();
        let out = s.clean(html)?;
        assert_contains!(out, r#"href="https://example.com/path/to""#);
        Ok(())
    }

    #[test]
    fn test_id_prefix_applied() -> anyhow::Result<()> {
        let mut s = HtmlSanitizer::default();
        s.add_tag_attributes(String::from("div"), vec![String::from("id")])?;
        s.id_prefix(Some("pre-".to_string()))?;
        let html = r#"<div id="one">x</div>"#.to_string();
        let out = s.clean(html)?;
        assert_contains!(out, r#"id="pre-one""#);
        Ok(())
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("sanitizers/html")?;
        Ok(())
    }
}
