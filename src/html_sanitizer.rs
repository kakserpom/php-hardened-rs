use ammonia::{Builder, UrlRelative};
use anyhow::anyhow;
use ext_php_rs::prelude::{PhpException, PhpResult, ZendCallable};
use ext_php_rs::types::{ZendHashTable, Zval};
use ext_php_rs::{php_class, php_impl};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use url::Url;

#[php_class]
#[php(name = "Hardened\\HtmlSanitizer")]
/// PHP class wrapping Ammonia's HTML sanitizer builder.
/// Allows customized sanitization through PHP method calls.
pub struct HtmlSanitizer {
    inner: Option<Builder<'static>>,
    attribute_filter: Option<Zval>,
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
            attribute_filter: None,
            inner: Some(Builder::default()),
        }
    }

    /// Denies all relative URLs in attributes.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn url_relative_deny(&mut self) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.url_relative(UrlRelative::Deny);
        Ok(())
    }

    /// Passes through relative URLs unchanged.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn url_relative_passthrough(&mut self) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
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
    pub fn url_relative_rewrite_with_base(&mut self, base_url: &str) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
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
    pub fn url_relative_rewrite_with_root(&mut self, root: &str, path: String) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
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
    pub fn link_rel(&mut self, value: Option<String>) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        if let Some(rel) = value {
            x.link_rel(Some(Box::leak(Box::new(rel)).as_str()));
        } else {
            x.link_rel(None);
        }
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
    pub fn tags(&mut self, tags: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.tags(arg_into_hashset(
            tags.array().ok_or_else(|| anyhow!("tags must be array"))?,
        ));
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
    pub fn clean_content_tags(&mut self, tags: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.clean_content_tags(arg_into_hashset(
            tags.array().ok_or_else(|| anyhow!("tags must be array"))?,
        ));
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
    pub fn add_clean_content_tags(&mut self, tags: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.add_clean_content_tags(arg_into_hashset(
            tags.array().ok_or_else(|| anyhow!("tags must be array"))?,
        ));
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
    pub fn rm_clean_content_tags(&mut self, tags: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.add_clean_content_tags(arg_into_hashset(
            tags.array().ok_or_else(|| anyhow!("tags must be array"))?,
        ));
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
    pub fn add_tags(&mut self, tags: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.tags(arg_into_hashset(
            tags.array().ok_or_else(|| anyhow!("tags must be array"))?,
        ));
        Ok(())
    }

    /// Removes tags from the whitelist.
    ///
    /// # Parameters
    /// - `tags`: An array of tag names to remove.
    ///
    /// # Exceptions
    /// - `Exception` if the sanitizer is not in a valid state.
    pub fn rm_tags(&mut self, tags: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.rm_tags(arg_into_hashset(
            tags.array().ok_or_else(|| anyhow!("tags must be array"))?,
        ));
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
    pub fn add_allowed_classes(&mut self, tag: &Zval, classes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.add_allowed_classes(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            arg_into_hashset(
                classes
                    .array()
                    .ok_or_else(|| anyhow!("classes must be array"))?,
            ),
        );
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
    pub fn rm_allowed_classes(&mut self, tag: &Zval, classes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.rm_allowed_classes(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            arg_into_hashset(
                classes
                    .array()
                    .ok_or_else(|| anyhow!("classes must be array"))?,
            ),
        );
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
    pub fn add_tag_attributes(&mut self, tag: &Zval, attributes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.add_tag_attributes(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            arg_into_hashset(
                attributes
                    .array()
                    .ok_or_else(|| anyhow!("classes must be array"))?,
            ),
        );
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
    pub fn rm_tag_attributes(&mut self, tag: &Zval, classes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.rm_tag_attributes(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            arg_into_hashset(
                classes
                    .array()
                    .ok_or_else(|| anyhow!("classes must be array"))?,
            ),
        );
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
    pub fn add_generic_attributes(&mut self, attributes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.add_generic_attributes(arg_into_hashset(
            attributes
                .array()
                .ok_or_else(|| anyhow!("attributes must be array"))?,
        ));
        Ok(())
    }

    /// Removes generic attributes from all tags.
    ///
    /// # Parameters
    /// - `attributes`: An array of attribute names to remove.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn rm_generic_attributes(&mut self, attributes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.rm_generic_attributes(arg_into_hashset(
            attributes
                .array()
                .ok_or_else(|| anyhow!("attributes must be array"))?,
        ));
        Ok(())
    }

    /// Adds prefixes for generic attributes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes to allow.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn add_generic_attribute_prefixes(&mut self, prefixes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.add_generic_attribute_prefixes(arg_into_hashset(
            prefixes
                .array()
                .ok_or_else(|| anyhow!("prefixes must be array"))?,
        ));
        Ok(())
    }

    /// Removes prefixes for generic attributes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes to remove.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn rm_generic_attribute_prefixes(&mut self, prefixes: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.rm_generic_attribute_prefixes(arg_into_hashset(
            prefixes
                .array()
                .ok_or_else(|| anyhow!("prefixes must be array"))?,
        ));
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
    pub fn clean(&mut self, html: String) -> String {
        if let Some(filter) = self.attribute_filter.as_ref() {
            let (req_tx, req_rx) = mpsc::channel::<Option<FilterRequest>>();
            let (resp_tx, resp_rx) = mpsc::channel::<FilterResponse>();
            let resp_rx = Arc::new(Mutex::new(resp_rx));
            let req_tx_clone = req_tx.clone();
            let resp_rx_clone = resp_rx.clone();
            let mut inner = self.inner.take().unwrap();
            let handle = thread::spawn(move || {
                inner.attribute_filter(move |element, attribute, value| {
                    let _ = req_tx.send(Some(FilterRequest {
                        element: element.to_string(),
                        attribute: attribute.to_string(),
                        value: value.to_string(),
                    }));

                    let resp = resp_rx_clone
                        .lock()
                        .unwrap()
                        .recv()
                        .unwrap_or(FilterResponse { filtered: None });

                    resp.filtered
                        .map(Cow::Owned)
                        .or_else(|| Some(Cow::Borrowed(value)))
                });
                let result = inner.clean(&html).to_string();
                req_tx_clone.send(None).unwrap();
                (inner, result)
            });

            let callable = ZendCallable::new(filter).unwrap();
            for req in req_rx {
                let Some(req) = req else {
                    break;
                };
                let result = callable
                    .try_call(vec![&req.element, &req.attribute, &req.value])
                    .ok()
                    .and_then(|z| z.string());
                let _ = resp_tx.send(FilterResponse { filtered: result });
            }
            let (inner, result) = handle.join().unwrap();
            let _ = self.inner.insert(inner);
            result
        } else {
            self.inner
                .as_ref()
                .map(|x| x.clean(&html).to_string())
                .unwrap()
        }
    }

    /// Whitelists URL schemes (e.g., "http", "https").
    ///
    /// # Parameters
    /// - `schemes`: An array of scheme strings to allow.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn url_schemes(&mut self, schemes: &Zval) -> PhpResult<()> {
        let arr = schemes
            .array()
            .ok_or_else(|| anyhow!("url_schemes must be array"))?;
        let set = arg_into_hashset(arr);
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.url_schemes(set);
        Ok(())
    }

    /// Enables or disables HTML comment stripping.
    ///
    /// # Parameters
    /// - `strip`: `true` to strip comments; `false` to preserve them.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn strip_comments(&mut self, strip: bool) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.strip_comments(strip);
        Ok(())
    }

    /// Returns whether HTML comments will be stripped.
    ///
    /// # Returns
    /// - `bool` `true` if comments will be stripped; `false` otherwise.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn will_strip_comments(&self) -> PhpResult<bool> {
        let Some(x) = self.inner.as_ref() else {
            return Err(PhpException::from("You cannot do this now"));
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
    pub fn id_prefix(&mut self, prefix: Option<String>) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        let prefix_ref = prefix.map(|s| Box::leak(Box::new(s)).as_str());
        x.id_prefix(prefix_ref);
        Ok(())
    }

    /// Filters CSS style properties allowed in `style` attributes.
    ///
    /// # Parameters
    /// - `props`: An array of CSS property names to allow.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn filter_style_properties(&mut self, props: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        let arr = props
            .array()
            .ok_or_else(|| anyhow!("filter_style_properties must be array"))?;
        let set = arg_into_hashset(arr);
        x.filter_style_properties(set);
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
        tag: &Zval,
        attribute: &Zval,
        value: String,
    ) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        let val_ref: &'static str = Box::leak(Box::new(value));
        x.set_tag_attribute_value(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            Box::leak(Box::new(attribute.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("attribute must be a string"))?,
            val_ref,
        );
        Ok(())
    }

    /// Returns the configured tags as a vector of strings.
    ///
    /// # Returns
    /// - `Vec<String>` The list of allowed tag names.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn clone_tags(&self) -> PhpResult<Vec<String>> {
        let Some(x) = self.inner.as_ref() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        Ok(x.clone_tags().iter().map(|s| s.to_string()).collect())
    }

    /// Gets all configured clean-content tags.
    ///
    /// # Returns
    /// - `Vec<String>` The list of tags whose content is preserved.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn clone_clean_content_tags(&self) -> PhpResult<Vec<String>> {
        let Some(x) = self.inner.as_ref() else {
            return Err(PhpException::from("You cannot do this now"));
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
    pub fn generic_attributes(&mut self, attrs: &Zval) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        let arr = attrs
            .array()
            .ok_or_else(|| anyhow!("generic_attributes must be array"))?;
        let set = arg_into_hashset(arr);
        x.generic_attributes(set);
        Ok(())
    }

    /// Bulk overwrites generic attribute prefixes.
    ///
    /// # Parameters
    /// - `prefixes`: An array of prefixes.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn generic_attribute_prefixes(&mut self, prefixes: &Zval) -> PhpResult<()> {
        let arr = prefixes
            .array()
            .ok_or_else(|| anyhow!("generic_attribute_prefixes must be array"))?;
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        let set = arg_into_hashset(arr);
        x.generic_attribute_prefixes(set);
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
        tag: &Zval,
        attr: &Zval,
        values: &Zval,
    ) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.add_tag_attribute_values(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            Box::leak(Box::new(attr.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("attr must be a string"))?,
            arg_into_hashset(
                values
                    .array()
                    .ok_or_else(|| anyhow!("values must be array"))?,
            ),
        );
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
        tag: &Zval,
        attr: &Zval,
        values: &Zval,
    ) -> PhpResult<()> {
        let Some(x) = self.inner.as_mut() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        x.rm_tag_attribute_values(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            Box::leak(Box::new(attr.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("attr must be a string"))?,
            arg_into_hashset(
                values
                    .array()
                    .ok_or_else(|| anyhow!("values must be array"))?,
            ),
        );
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
    pub fn get_set_tag_attribute_value(
        &self,
        tag: &Zval,
        attr: &Zval,
    ) -> PhpResult<Option<String>> {
        let Some(x) = self.inner.as_ref() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        Ok(x.get_set_tag_attribute_value(
            Box::leak(Box::new(tag.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("tag must be a string"))?,
            Box::leak(Box::new(attr.string()))
                .as_ref()
                .map(|x| x.as_str())
                .ok_or_else(|| anyhow!("attr must be a string"))?,
        )
        .map(|s| s.to_string()))
    }

    /// Checks if URL relative policy is Deny.
    ///
    /// # Returns
    /// - `bool` `true` if the policy is Deny.
    ///
    /// # Exceptions
    /// - `PhpException` if the sanitizer is not in a valid state.
    pub fn is_url_relative_deny(&self) -> PhpResult<bool> {
        let Some(x) = self.inner.as_ref() else {
            return Err(PhpException::from("You cannot do this now"));
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
    pub fn is_url_relative_pass_through(&self) -> PhpResult<bool> {
        let Some(x) = self.inner.as_ref() else {
            return Err(PhpException::from("You cannot do this now"));
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
    pub fn is_url_relative_custom(&self) -> PhpResult<bool> {
        let Some(x) = self.inner.as_ref() else {
            return Err(PhpException::from("You cannot do this now"));
        };
        Ok(x.is_url_relative_custom())
    }

    /// Sets the attribute filter callback.
    ///
    /// # Parameters
    /// - `callable`: A PHP callable of signature `(string, string, string) -> string|null`.
    ///
    /// # Exceptions
    /// - None.
    pub fn attribute_filter(&mut self, callable: &Zval) -> PhpResult<()> {
        self.attribute_filter = Some(callable.shallow_clone());
        Ok(())
    }
}

#[derive(Debug)]
struct FilterRequest {
    element: String,
    attribute: String,
    value: String,
}

struct FilterResponse {
    filtered: Option<String>,
}
fn arg_into_hashset(arg: &ZendHashTable) -> HashSet<&'static str> {
    Box::leak(Box::<HashSet<String>>::new(HashSet::from_iter(
        arg.values().filter_map(|x| x.string()),
    )))
    .iter()
    .map(|x| x.as_str())
    .collect::<HashSet<_>>()
}
