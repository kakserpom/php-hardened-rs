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
         * Construct a sanitizer with default configuration.
         */
        public static function default(): \Hardened\HtmlSanitizer {}

        /**
         * Deny all relative URLs in attributes.
         */
        public function urlRelativeDeny(): mixed {}

        /**
         * Pass through relative URLs unchanged.
         */
        public function urlRelativePassthrough(): mixed {}

        /**
         * Rewrite relative URLs using the given base URL.
         */
        public function urlRelativeRewriteWithBase(string $base_url): mixed {}

        /**
         * Rewrite relative URLs using a root URL and path prefix.
         */
        public function urlRelativeRewriteWithRoot(string $root, string $path): mixed {}

        /**
         * Set the `rel` attribute for generated `<a>` tags.
         */
        public function linkRel(?string $value): mixed {}

        /**
         * Overwrite the set of allowed tags.
         */
        public function tags(mixed $tags): mixed {}

        /**
         * Add additional allowed tags to the existing whitelist.
         */
        public function addTags(mixed $tags): mixed {}

        /**
         * Remove tags from the whitelist.
         */
        public function rmTags(mixed $tags): mixed {}

        /**
         * Add allowed CSS classes for a specific tag.
         */
        public function addAllowedClasses(mixed $tag, mixed $classes): mixed {}

        /**
         * Remove allowed CSS classes from a specific tag.
         */
        public function rmAllowedClasses(mixed $tag, mixed $classes): mixed {}

        /**
         * Add allowed attributes to a specific tag.
         */
        public function addTagAttributes(mixed $tag, mixed $attributes): mixed {}

        /**
         * Remove attributes from a specific tag.
         */
        public function rmTagAttributes(mixed $tag, mixed $classes): mixed {}

        /**
         * Add generic attributes to all tags.
         */
        public function addGenericAttributes(mixed $attributes): mixed {}

        /**
         * Remove generic attributes from all tags.
         */
        public function rmGenericAttributes(mixed $attributes): mixed {}

        /**
         * Add prefixes for generic attributes.
         */
        public function addGenericAttributePrefixes(mixed $prefixes): mixed {}

        /**
         * Remove prefixes for generic attributes.
         */
        public function rmGenericAttributePrefixes(mixed $prefixes): mixed {}

        /**
         * Sanitize the given HTML string.
         */
        public function clean(string $html): string {}

        /**
         * Whitelist URL schemes (e.g., "http", "https").
         */
        public function urlSchemes(mixed $schemes): mixed {}

        /**
         * Enable or disable HTML comment stripping.
         */
        public function stripComments(bool $strip): mixed {}

        /**
         * Return whether HTML comments will be stripped.
         */
        public function willStripComments(): bool {}

        /**
         * Prefix all `id` attributes with the given string.
         */
        public function idPrefix(?string $prefix): mixed {}

        /**
         * Filter CSS style properties allowed in `style` attributes.
         */
        public function filterStyleProperties(mixed $props): mixed {}

        /**
         * Set single tag attribute value
         */
        public function setTagAttributeValue(mixed $tag, mixed $attribute, string $value): mixed {}

        /**
         * Return configured tags as a vector of strings.
         */
        public function cloneTags(): array {}

        /**
         * Get all configured clean-content tags
         */
        public function cloneCleanContentTags(): array {}

        /**
         * Bulk overwrite generic attributes
         */
        public function genericAttributes(mixed $attrs): mixed {}

        /**
         * Bulk overwrite generic attribute prefixes
         */
        public function genericAttributePrefixes(mixed $prefixes): mixed {}

        /**
         * Add tag attribute values
         */
        public function addTagAttributeValues(mixed $tag, mixed $attr, mixed $values): mixed {}

        /**
         * Remove tag attribute values
         */
        public function rmTagAttributeValues(mixed $tag, mixed $attr, mixed $values): mixed {}

        /**
         * Get a single set_tag_attribute_value
         */
        public function getSetTagAttributeValue(mixed $tag, mixed $attr): ?string {}

        /**
         * Check URL relative policy: Deny
         */
        public function isUrlRelativeDeny(): bool {}

        /**
         * Check URL relative policy: PassThrough
         */
        public function isUrlRelativePassThrough(): bool {}

        /**
         * Check URL relative policy: custom (Rewrite)
         */
        public function isUrlRelativeCustom(): bool {}

        /**
         * Set attribute filter map using a PHP callback
         */
        public function attributeFilter(mixed $callable): mixed {}

        public function __construct() {}
    }
}
