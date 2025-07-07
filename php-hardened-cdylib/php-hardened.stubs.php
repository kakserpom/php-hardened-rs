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
}
