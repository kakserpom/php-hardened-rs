<?php

// Stubs for php-hardened

namespace Hardened {
    /**
     * A secured wrapper around `url::Host` for use in PHP extensions.
     * Provides hostname parsing and normalization to prevent security issues.
     */
    class Hostname {
        /**
         * Parses and normalizes a hostname string.
         *
         * # Parameters
         * - `hostname`: The hostname to parse and normalize.
         *
         * # Errors
         * Throws an exception if parsing the hostname fails.
         */
        public static function from(mixed $hostname): \Hardened\Hostname {}

        public static function fromStr(string $hostname): \Hardened\Hostname {}

        /**
         * Parses a URL and extracts its hostname.
         *
         * # Parameters
         * - `url`: The URL to parse.
         *
         * # Errors
         * Throws an exception if parsing the URL or hostname fails.
         */
        public static function fromUrl(mixed $url): \Hardened\Hostname {}

        /**
         * Compares this hostname with another string.
         *
         * # Parameters
         * - `hostname`: The hostname to compare against.
         *
         * # Errors
         * Throws an exception if parsing the provided hostname fails.
         */
        public function equals(mixed $hostname): bool {}

        public function equalsStr(string $hostname): bool {}

        /**
         * Returns true if this hostname equals any in the given list.
         *
         * # Parameters
         * - `hostnames`: List of hostname strings to compare.
         *
         * # Errors
         * Throws an exception if parsing any provided hostname fails.
         */
        public function equalsAny(mixed $hostnames): bool {}

        /**
         * Compares this hostname with the hostname extracted from a URL.
         *
         * # Parameters
         * - `url`: The URL to extract hostname from.
         *
         * # Errors
         * Throws an exception if parsing the URL or hostname fails.
         */
        public function equalsUrl(mixed $url): bool {}

        /**
         * Returns true if this hostname equals any hostname extracted from the given URLs.
         *
         * # Parameters
         * - `urls`: List of URL strings to compare.
         *
         * # Errors
         * Throws an exception if parsing any URL or hostname fails.
         */
        public function equalsAnyUrl(mixed $urls): bool {}

        /**
         * Checks if this hostname is a subdomain of the given hostname.
         *
         * # Parameters
         * - `hostname`: The parent hostname to check against.
         *
         * # Errors
         * Throws an exception if parsing the provided hostname fails.
         */
        public function subdomainOf(mixed $hostname): bool {}

        public function subdomainOfStr(string $hostname): bool {}

        /**
         * Returns true if this hostname is a subdomain of any in the given list.
         *
         * # Parameters
         * - `hosts`: List of parent hostname strings to check.
         *
         * # Errors
         * Throws an exception if parsing any provided hostname fails.
         */
        public function subdomainOfAny(mixed $hosts): bool {}

        /**
         * Checks if this hostname is a subdomain of the hostname extracted from a URL.
         *
         * # Parameters
         * - `url`: The URL to extract hostname from.
         *
         * # Errors
         * Throws an exception if parsing the URL or hostname fails.
         */
        public function subdomainOfUrl(string $url): bool {}

        /**
         * Returns true if this hostname is a subdomain of any hostname extracted from the given URLs.
         *
         * # Parameters
         * - `urls`: List of URL strings to check.
         *
         * # Errors
         * Throws an exception if parsing any URL or hostname fails.
         */
        public function subdomainOfAnyUrl(array $urls): bool {}

        public function __construct(mixed $hostname) {}
    }

    class Path {
        /**
         * Creates a new PathObj by lexically canonicalizing a given PHP value.
         *
         * # Parameters
         * - `path`: The PHP value to convert to a filesystem path.
         *
         * # Errors
         * Throws an exception if conversion from Zval to string fails.
         */
        public static function from(mixed $path): \Hardened\Path {}

        /**
         * Checks if this path starts with the given prefix path.
         *
         * # Parameters
         * - `path`: The PHP value to compare against.
         *
         * # Returns
         * `true` if this path starts with the given prefix.
         *
         * # Errors
         * Throws an exception if conversion from Zval to string fails.
         */
        public function startsWith(mixed $path): bool {}

        /**
         * Joins the given path onto this path and canonicalizes it.
         *
         * # Parameters
         * - `path`: The PHP value to join.
         *
         * # Returns
         * A new PathObj representing the joined path.
         *
         * # Errors
         * Throws an exception if conversion from Zval to string fails.
         */
        public function join(mixed $path): \Hardened\Path {}

        /**
         * Joins the given path onto this path, canonicalizes it, and ensures it's a subpath.
         *
         * # Parameters
         * - `path`: The PHP value to join.
         *
         * # Errors
         * Throws an exception if conversion from Zval to string fails or if the resulting path is not a subpath.
         */
        public function joinWithin(mixed $path): \Hardened\Path {}

        public function setFileName(mixed $file_name): \Hardened\Path {}

        public function setExtension(mixed $file_name): \Hardened\Path {}

        public function fileName(): ?string {}

        /**
         * Converts the path to its string representation.
         *
         * # Returns
         * The string representation of the path.
         *
         * # Errors
         * Throws an exception if the path cannot be converted to a string.
         */
        public function __toString(): string {}

        public function path(): string {}

        public function __construct(mixed $path) {}
    }

    /**
     * PHP class wrapping Ammonia's HTML sanitizer builder.
     * Allows customized sanitization through PHP method calls.
     */
    class HtmlSanitizer {
        /**
         * Constructs a sanitizer with default configuration.
         *
         * # Returns
         * - HtmlSanitizer A new sanitizer instance.
         *
         * # Notes
         * - No exceptions are thrown.
         */
        public static function default(): \Hardened\HtmlSanitizer {}

        /**
         * Denies all relative URLs in attributes.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function urlRelativeDeny(): mixed {}

        /**
         * Checks whether a URL is valid according to the sanitizer’s configured
         * URL scheme whitelist and relative-URL policy.
         *
         * # Parameters
         * - `url`: The URL string to validate.
         *
         * # Returns
         * - `bool`: `true` if the URL’s scheme is whitelisted, or if it is a relative URL
         *   and relative URLs are permitted; `false` otherwise.
         *
         * # Exceptions
         * - Throws `Exception` if the sanitizer is not in a valid state.
         */
        public function isValidUrl(string $url): bool {}

        /**
         * Passes through relative URLs unchanged.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function urlRelativePassthrough(): mixed {}

        /**
         * Rewrites relative URLs using the given base URL.
         *
         * # Parameters
         * - `base_url`: The base URL to resolve relative URLs against.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - Exception if `base_url` is not a valid URL.
         */
        public function urlRelativeRewriteWithBase(string $base_url): mixed {}

        /**
         * Rewrites relative URLs using a root URL and path prefix.
         *
         * # Parameters
         * - `root`: The root URL string.
         * - `path`: The URL path prefix.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - Exception if `root` is not a valid URL.
         */
        public function urlRelativeRewriteWithRoot(string $root, string $path): mixed {}

        /**
         * Sets the `rel` attribute for generated `<a>` tags.
         *
         * # Parameters
         * - `value`: Optional `rel` attribute value; `None` clears it.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function linkRel(?string $value): mixed {}

        /**
         * Overwrites the set of allowed tags.
         *
         * # Parameters
         * - `tags`: An array of allowed tag names.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - Exception if `tags` is not an array.
         */
        public function tags(mixed $tags): mixed {}

        /**
         * Sets the tags whose contents will be completely removed from the output.
         *
         * # Parameters
         * - `tags`: An array of allowed tag names.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - Exception if `tags` is not an array.
         * - Adding tags which are whitelisted in tags or tag_attributes will cause a panic.
         */
        public function cleanContentTags(mixed $tags): mixed {}

        /**
         * Add additional blacklisted clean-content tags without overwriting old ones.
         *
         * Does nothing if the tag is already there.
         *
         * # Parameters
         * - `tags`: An array of tag names to add.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - Exception if `tags` is not an array.
         */
        public function addCleanContentTags(mixed $tags): mixed {}

        /**
         * Remove already-blacklisted clean-content tags.
         *
         * Does nothing if the tags aren’t blacklisted.
         *
         * # Parameters
         * - `tags`: An array of tag names to add.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - Exception if `tags` is not an array.
         */
        public function rmCleanContentTags(mixed $tags): mixed {}

        /**
         * Adds additional allowed tags to the existing whitelist.
         *
         * # Parameters
         * - `tags`: An array of tag names to add.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - Exception if `tags` is not an array.
         */
        public function addTags(mixed $tags): mixed {}

        /**
         * Removes tags from the whitelist.
         *
         * # Parameters
         * - `tags`: An array of tag names to remove.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function rmTags(mixed $tags): mixed {}

        /**
         * Adds allowed CSS classes for a specific tag.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `classes`: An array of CSS class names.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function addAllowedClasses(mixed $tag, mixed $classes): mixed {}

        /**
         * Removes allowed CSS classes from a specific tag.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `classes`: An array of CSS class names to remove.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function rmAllowedClasses(mixed $tag, mixed $classes): mixed {}

        /**
         * Adds allowed attributes to a specific tag.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `attributes`: An array of attribute names.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function addTagAttributes(mixed $tag, mixed $attributes): mixed {}

        /**
         * Removes attributes from a specific tag.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `classes`: An array of attribute names to remove.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function rmTagAttributes(mixed $tag, mixed $classes): mixed {}

        /**
         * Adds generic attributes to all tags.
         *
         * # Parameters
         * - `attributes`: An array of attribute names to allow.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         * - `Exception` if `attributes` is not an array.
         */
        public function addGenericAttributes(mixed $attributes): mixed {}

        /**
         * Removes generic attributes from all tags.
         *
         * # Parameters
         * - `attributes`: An array of attribute names to remove.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function rmGenericAttributes(mixed $attributes): mixed {}

        /**
         * Adds prefixes for generic attributes.
         *
         * # Parameters
         * - `prefixes`: An array of prefixes to allow.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function addGenericAttributePrefixes(mixed $prefixes): mixed {}

        /**
         * Removes prefixes for generic attributes.
         *
         * # Parameters
         * - `prefixes`: An array of prefixes to remove.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function rmGenericAttributePrefixes(mixed $prefixes): mixed {}

        /**
         * Sets the attribute filter callback.
         *
         * # Parameters
         * - `callable`: A PHP callable of signature `(string Element, string Attribute, string Value) -> string|null`.
         *
         * # Exceptions
         * - None.
         */
        public function attributeFilter(mixed $callable): mixed {}

        /**
         * Sanitizes the given HTML string, applying any configured attribute filter.
         *
         * # Parameters
         * - `html`: The HTML content to sanitize.
         *
         * # Returns
         * - `String` The sanitized HTML.
         *
         * # Notes
         * - If an attribute filter is set, it will be invoked for each attribute.
         */
        public function clean(string $html): string {}

        /**
         * Whitelists URL schemes (e.g., "http", "https").
         *
         * # Parameters
         * - `schemes`: An array of scheme strings to allow.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function urlSchemes(mixed $schemes): mixed {}

        /**
         * Enables or disables HTML comment stripping.
         *
         * # Parameters
         * - `strip`: `true` to strip comments; `false` to preserve them.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function stripComments(bool $strip): mixed {}

        /**
         * Returns whether HTML comments will be stripped.
         *
         * # Returns
         * - `bool`: `true` if comments will be stripped; `false` otherwise.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function willStripComments(): bool {}

        /**
         * Prefixes all `id` attributes with the given string.
         *
         * # Parameters
         * - `prefix`: Optional string prefix to apply.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function idPrefix(?string $prefix): mixed {}

        /**
         * Filters CSS style properties allowed in `style` attributes.
         *
         * # Parameters
         * - `props`: An array of CSS property names to allow.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function filterStyleProperties(mixed $props): mixed {}

        /**
         * Sets a single tag attribute value.
         *
         * # Parameters
         * - `tag`: The tag name as A string.
         * - `attribute`: The attribute name as A string.
         * - `value`: The value to set.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function setTagAttributeValue(mixed $tag, mixed $attribute, string $value): mixed {}

        /**
         * Returns the configured tags as a vector of strings.
         *
         * # Returns
         * - `Vec<String>` The list of allowed tag names.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function cloneTags(): array {}

        /**
         * Gets all configured clean-content tags.
         *
         * # Returns
         * - `Vec<String>` The list of tags whose content is preserved.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function cloneCleanContentTags(): array {}

        /**
         * Bulk overwrites generic attributes.
         *
         * # Parameters
         * - `attrs`: An array of attribute names.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function genericAttributes(mixed $attrs): mixed {}

        /**
         * Bulk overwrites generic attribute prefixes.
         *
         * # Parameters
         * - `prefixes`: An array of prefixes.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function genericAttributePrefixes(mixed $prefixes): mixed {}

        /**
         * Adds tag attribute values.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `attr`: A string attribute name.
         * - `values`: An array of values to allow.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function addTagAttributeValues(string $tag, string $attr, mixed $values): mixed {}

        /**
         * Removes tag attribute values.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `attr`: A string attribute name.
         * - `values`: An array of values to remove.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function rmTagAttributeValues(string $tag, string $attr, mixed $values): mixed {}

        /**
         * Gets a single tag attribute value setting.
         *
         * # Parameters
         * - `tag`: The tag name as A string.
         * - `attr`: The attribute name as A string.
         *
         * # Returns
         * - `Option<String>` The configured value or `None` if unset.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function getSetTagAttributeValue(mixed $tag, mixed $attr): ?string {}

        /**
         * Checks if URL relative policy is Deny.
         *
         * # Returns
         * - `bool` `true` if the policy is Deny.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function isUrlRelativeDeny(): bool {}

        /**
         * Checks if URL relative policy is PassThrough.
         *
         * # Returns
         * - `bool` `true` if the policy is PassThrough.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function isUrlRelativePassThrough(): bool {}

        /**
         * Checks if URL relative policy is custom (Rewrite).
         *
         * # Returns
         * - `bool` `true` if a custom rewrite policy is set.
         *
         * # Exceptions
         * - `PhpException` if the sanitizer is not in a valid state.
         */
        public function isUrlRelativeCustom(): bool {}

        public function __construct() {}
    }

    /**
     * Your application’s CSP config.
     */
    class ContentSecurityPolicy {
        const DEFAULT_SRC = null;

        const SCRIPT_SRC = null;

        const STYLE_SRC = null;

        const IMG_SRC = null;

        const FRAME_ANCESTORS = null;

        const FONT_SRC = null;

        const CONNECT_SRC = null;

        const CHILD_SRC = null;

        const MANIFEST_SRC = null;

        const MEDIA_SRC = null;

        const OBJECT_SRC = null;

        const PREFETCH_SRC = null;

        const SCRIPT_SRC_ELEM = null;

        const SCRIPT_SRC_ATTR = null;

        const STYLE_SRC_ELEM = null;

        const STYLE_SRC_ATTR = null;

        const WORKER_SRC = null;

        const BASE_URI = null;

        const FORM_ACTION = null;

        const SANDBOX = null;

        const PLUGIN_TYPES = null;

        const BLOCK_ALL_MIXED_CONTENT = null;

        const UPGRADE_INSECURE_REQUESTS = null;

        const REPORT_URI = null;

        const REPORT_TO = null;

        const REQUIRE_SRI_FOR = null;

        const TRUSTED_TYPES = null;

        const REQUIRE_TRUSTED_TYPES_FOR = null;

        const SELF = null;

        const NONE = null;

        const UNSAFE_INLINE = null;

        const UNSAFE_EVAL = null;

        const UNSAFE_HASHES = null;

        const STRICT_DYNAMIC = null;

        const NONCE = null;

        const SCRIPT = null;

        const STYLE = null;

        const ALLOW_FORMS = null;

        const ALLOW_MODALS = null;

        const ALLOW_ORIENTATION_LOCK = null;

        const ALLOW_POINTER_LOCK = null;

        const ALLOW_PRESENTATION = null;

        const ALLOW_POPUPS = null;

        const ALLOW_POPUPS_TO_ESCAPE_SANDBOX = null;

        const ALLOW_SAME_ORIGIN = null;

        const ALLOW_SCRIPTS = null;

        const ALLOW_STORAGE_ACCESS_BY_USER_ACTIVATION = null;

        const ALLOW_TOP_NAVIGATION_BY_USER_ACTIVATION = null;

        const ALLOW_DUPLICATES = null;

        const INLINE_SPECULATION_RULES = null;

        const REPORT_SAMPLE = null;

        const WASM_UNSAFE_EVAL = null;

        /**
         * Sets or replaces a CSP directive with the given keywords and host sources.
         *
         * # Parameters
         * - `rule`: The directive name (e.g. `"default-src"`, `"script-src"`).
         * - `keywords`: A `ZendHashTable` of keyword tokens (e.g. `'self'`, `'nonce-...'`).
         * - `sources`: Optional vector of host strings (e.g. `"example.com"`).
         *
         * # Exceptions
         * - Throws `Exception` if any array item in `keywords` is not a string.
         * - Throws `Exception` if `rule` is not a valid CSP directive.
         */
        public function setRule(string $rule, array $keywords, ?array $sources): mixed {}

        /**
         * Builds the `Content-Security-Policy` header value from the configured directives.
         *
         * # Returns
         * - `String` The full header value, for example:
         *   `"default-src 'self'; script-src 'self' 'nonce-ABCD1234' example.com; …"`.
         *
         * # Exceptions
         * - Throws `Exception` if formatting the header string fails.
         */
        public function build(): string {}

        public function send(): mixed {}

        /**
         * Returns the most recently generated nonce, if any.
         *
         * # Returns
         * - `Option<&str>` The raw nonce string (without the `'nonce-'` prefix), or `None` if `build()` has not yet generated one.
         */
        public function getNonce(): ?string {}

        /**
         * Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.                   
         */
        public function resetNonce() {}

        public function __construct() {}
    }

    class Rng {
        /**
         * Generate a random ASCII alphanumeric string of the specified length.
         *
         * # Parameters
         * - `len`: Number of characters to generate.
         *
         * # Returns
         * - `String` containing random ASCII alphanumeric characters.
         */
        public static function alphanumeric(int $len): string {}

        /**
         * Generate a random ASCII alphabetic string of the specified length.
         *
         * # Parameters
         * - `len`: Number of characters to generate.
         *
         * # Returns
         * - `String` containing random ASCII alphabetic characters.
         */
        public static function alphabetic(int $len): string {}

        /**
         * Generate a sequence of random bytes of the specified length.
         *
         * # Parameters
         * - `len`: Number of bytes to generate.
         *
         * # Returns
         * - `Ok(Binary<u8>)` containing `len` random bytes.
         *
         * # Errors
         * - Returns `Err` if the uniform distribution for `u8` cannot be created.
         */
        public static function bytes(int $len): string {}

        /**
         * Generate a vector of random integers in the inclusive range `[low, high]`.
         *
         * # Parameters
         * - `len`: Number of integers to generate.
         * - `low`: Lower bound (inclusive).
         * - `high`: Upper bound (inclusive).
         *
         * # Returns
         * - `Ok(Vec<i64>)` of length `len`.
         *
         * # Errors
         * - Returns `Err` if the range is invalid (e.g. `low > high`) or distribution creation fails.
         */
        public static function ints(int $len, int $low, int $high): array {}

        /**
         * Generate a single random integer in the inclusive range `[low, high]`.
         *
         * # Parameters
         * - `low`: Lower bound (inclusive).
         * - `high`: Upper bound (inclusive).
         *
         * # Returns
         * - `Ok(i64)` random value.
         *
         * # Errors
         * - Returns `Err` if `low > high` or if distribution creation fails.
         */
        public static function int(int $low, int $high): int {}

        /**
         * Sample random Unicode characters (code points) from the given string.
         *
         * # Parameters
         * - `len`: Number of characters to generate.
         * - `chars`: A string whose `char` elements form the sampling pool.
         *
         * # Returns
         * - `String` of length `len`, or an empty string if `chars` is empty.
         */
        public static function customUnicodeChars(int $len, string $chars): string {}

        /**
         * Sample random Unicode grapheme clusters from the given string.
         *
         * # Parameters
         * - `len`: Number of graphemes to generate.
         * - `chars`: A string whose grapheme clusters form the sampling pool.
         *
         * # Returns
         * - `Ok(String)` of concatenated grapheme clusters, or an empty string if none are found.
         *
         * # Errors
         * - Returns `Err` if the grapheme index distribution cannot be created.
         */
        public static function customUnicodeGraphemes(int $len, string $chars): string {}

        /**
         * Sample random ASCII characters from the specified character set.
         *
         * # Parameters
         * - `len`: Number of characters to generate.
         * - `chars`: A string slice whose bytes form the sampling pool.
         *
         * # Returns
         * - `String` of length `len`, or an empty string if `chars` is empty.
         */
        public static function customAscii(int $len, string $chars): string {}

        /**
         * Randomly selects one element from the given list.
         *
         * # Parameters
         * - `choices`: PHP array of values to pick from.
         *
         * # Returns
         * - `mixed|null`: A randomly chosen element, or `null` if `choices` is empty.
         */
        public static function choose(array $choices): mixed {}

        /**
         * Randomly selects exactly `amount` distinct elements without replacement.
         *
         * # Parameters
         * - `amount`: Number of elements to select.
         * - `choices`: PHP array of values to pick from.
         *
         * # Returns
         * - `mixed[]`: Array of selected values.
         *
         * # Exceptions
         * - Throws `Exception` if `amount` is greater than the number of available choices.
         */
        public static function chooseMultiple(int $amount, array $choices): array {}

        /**
         * Randomly selects one element from weighted choices.
         *
         * # Parameters
         * - `choices`: PHP array of `[value, weight]` pairs, where `weight` is an integer.
         *
         * # Returns
         * - `array{0: mixed, 1: int}` Two‐element array: the chosen value and its weight.
         *
         * # Exceptions
         * - Throws `Exception` if any entry is not a two‐element array or weight is not an integer.
         * - Throws `Exception` if selection fails.
         */
        public static function chooseWeighted(array $choices): array {}

        /**
         * Randomly selects `amount` elements from weighted choices without replacement.
         *
         * # Parameters
         * - `amount`: Number of elements to select.
         * - `choices`: PHP array of `[value, weight]` pairs, where `weight` is a float.
         *
         * # Returns
         * - `mixed[]`: Array of selected values.
         *
         * # Exceptions
         * - Throws `Exception` if any entry is not a two‐element array or weight is not a float.
         * - Throws `Exception` if selection fails.
         */
        public static function chooseMultipleWeighted(int $amount, array $choices): array {}

        public function __construct() {}
    }
}
