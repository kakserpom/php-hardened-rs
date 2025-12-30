<?php

// Stubs for hardened

namespace Hardened {
    /**
     * Execute a command directly (no shell), with arguments passed explicitly.
     *
     * Unlike `shell_exec()`, this function does NOT parse the executable string.
     * The executable is used as-is, and all arguments must be passed via the array.
     * This prevents any shell injection vulnerabilities.
     *
     * # Parameters
     * - `string $executable`: Path to the executable (not parsed, used literally).
     * - `array|null $arguments`: Optional associative or indexed array of arguments:
     *   - Indexed (numeric) arrays append values in order.
     *   - Associative arrays use keys as `--key` flags followed by their value.
     *
     * # Returns
     * - `string|null`: On success, returns captured stdout as a string (or exit code as string if non-zero).
     *   Returns `null` only on error spawning the process.
     *
     * # Exceptions
     * - Throws `Exception` if the executable is empty, contains NUL bytes, or process execution fails.
     *
     * # Example
     * ```php
     * // Correct usage - executable only, arguments in array
     * $output = Hardened\safe_exec("ls", ["-la", "/tmp"]);
     *
     * // WRONG - don't put arguments in the executable string
     * // $output = Hardened\safe_exec("ls -la", ["/tmp"]); // -la is NOT parsed!
     * ```
     */
    function safe_exec(string $executable, ?array $arguments): mixed {}

    /**
     * Execute a shell command via the user's login shell, enforcing top-level command checks.
     *
     * # Parameters
     * - `string $command`: Full shell-style command line to run (e.g. `"ls -la /tmp"`).
     * - `string[]|null $expectedCommands`: Optional list of allowed top-level command names
     *   (the first word of each pipeline segment). If provided, any top-level command not in this list
     *   will abort with an exception to prevent injection.
     *
     * # Returns
     * - `string|null`: On success, returns the command's stdout output as a string (or exit code as string if non-zero).
     *   Returns `null` only on error spawning the process.
     *
     * # Exceptions
     * - Throws `Exception` if parsing fails, an unexpected top-level command is detected, or command execution fails.
     */
    function shell_exec(string $command, ?array $expected_commands): mixed {}

    /**
     * Safe subprocess launcher.
     *
     * Allows you to build up a command invocation with arguments, optionally configure
     * a timeout (seconds), and execute it without shell interpolation.
     * Returns exit codes or captures stdout/stderr.
     */
    class ShellCommand {
        /**
         * Enable passthrough mode for both stdout and stderr:
         * PHP will receive all child-process output directly.
         */
        public function passthroughBoth(): \Hardened\ShellCommand {}

        /**
         * Enable passthrough mode for stdout only.
         */
        public function passthroughStdout(): \Hardened\ShellCommand {}

        /**
         * Enable passthrough mode for stderr only.
         */
        public function passthroughStderr(): \Hardened\ShellCommand {}

        /**
         * Silently ignore both stdout and stderr.
         */
        public function ignoreBoth(): \Hardened\ShellCommand {}

        /**
         * Silently ignore stdout.
         */
        public function ignoreStdout(): \Hardened\ShellCommand {}

        /**
         * Silently ignore stderr.
         */
        public function ignoreStderr(): \Hardened\ShellCommand {}

        /**
         * Pipe both stdout and stderr through a PHP callable.
         *
         * The callable will be invoked for each chunk of output.
         */
        public function pipeCallbackBoth(mixed $callable): \Hardened\ShellCommand {}

        /**
         * Pipe stdout through a PHP callable.
         */
        public function pipeCallbackStdout(mixed $callable): \Hardened\ShellCommand {}

        /**
         * Pipe stderr through a PHP callable.
         */
        public function pipeCallbackStderr(mixed $callable): \Hardened\ShellCommand {}

        /**
         * Merge in additional environment variables for the child process.
         *
         * Existing passed-env map is extended.
         */
        public function passEnvs(array $map): \Hardened\ShellCommand {}

        /**
         * Replace the child-process environment with exactly the given map.
         */
        public function passEnvOnly(array $map): \Hardened\ShellCommand {}

        /**
         * Inherit _all_ parent environment variables.
         */
        public function inheritAllEnvs(): \Hardened\ShellCommand {}

        /**
         * Inherit only the specified environment variable names.
         */
        public function inheritEnvs(array $envs): \Hardened\ShellCommand {}

        /**
         * Pass a single environment variable to the child.
         */
        public function passEnv(string $key, string $value): \Hardened\ShellCommand {}

        /**
         * Join numeric or flag-style arguments from a PHP table.
         *
         * Numeric keys => positional args; string keys => `--key value`.
         */
        public function passArgs(array $arguments): \Hardened\ShellCommand {}

        /**
         * Adds one argument to the command line.
         *
         * # Parameters
         * - `arg`: `string` A single argument (will not be interpreted by a shell).
         */
        public function passArg(string $arg): \Hardened\ShellCommand {}

        /**
         * Sets an execution timeout in seconds.
         *
         * # Parameters
         * - `seconds`: `int` Maximum time to wait before killing the process.
         *
         * # Notes
         * - If the process does not exit within this period, it will be terminated.
         */
        public function setTimeout(int $seconds): \Hardened\ShellCommand {}

        /**
         * Sets an execution timeout in milliseconds.
         *
         * # Parameters
         * - `milliseconds`: `int` Maximum time to wait before killing the process.
         *
         * # Notes
         * - If the process does not exit within this period, it will be terminated.
         */
        public function setTimeoutMs(int $milliseconds): \Hardened\ShellCommand {}

        /**
         *
         * # Parameters
         * - `string $cmdline` Full command line to run.
         *
         * # Returns
         * - `ShellCommand`
         *
         * # Exceptions
         * - Throws `Exception` on parse errors or if disallowed characters are present.
         */
        public static function safeFromString(string $command_line): \Hardened\ShellCommand {}

        /**
         * Exactly like `shell_exec()`: pass the *raw* string to `/bin/sh -c`
         * and record the top-level command names.
         *
         * # Parameters
         * - `string $cmdline` Full shell-style command line to run.
         *
         * # Returns
         * - `ShellCommand`
         *
         * # Exceptions
         * - Throws `Exception` on parse errors (e.g. empty line).
         */
        public static function shellFromString(string $cmdline): \Hardened\ShellCommand {}

        /**
         * Constructs a new ShellCommand for the given program path.
         *
         * # Parameters
         * - `executable`: `string` Path to the executable or command name.
         *
         * # Notes
         * - Does not validate existence until execution.
         */
        public static function executable(string $executable): \Hardened\ShellCommand {}

        /**
         * Returns the list of top-level command names parsed from the original shell line.
         *
         * # Returns
         * - `Option<Vec<String>>`:
         *   - `Some(vec)` when `shell_from_string()` was used and top-level commands were recorded;
         *   - `None` otherwise.
         */
        public function topLevelCommands(): ?array {}

        /**
         * Constructs a new `ShellCommand` using the user's login shell.
         *
         * Looks up the `SHELL` environment variable, or falls back to `/bin/sh` if unset.
         *
         * # Returns
         * - `ShellCommand`: with `executable` set to the shell path and no arguments.
         */
        public static function shell(): \Hardened\ShellCommand {}

        /**
         * Runs the command, streaming stdout/stderr live (according to configured pipe modes),
         * enforces the configured timeout, and optionally captures output into PHP variables.
         *
         * # Parameters
         * - `stdout`: `?string &$stdout`
         *   Optional reference to a PHP variable; if provided, the collected stdout will be written here.
         * - `stderr`: `?string &$stderr`
         *   Optional reference to a PHP variable; if provided, the collected stderr will be written here.
         *
         * # Returns
         * - `int`
         *   The process's exit code (`0` on success, `-1` if killed by signal or timed out).
         *
         * # Exceptions
         * - Throws `Exception` if the process cannot be spawned.
         * Runs the command, streaming both stdout and stderr live, with a timeout and
         * selected environment variables passed through.
         */
        public function run(?mixed $capture_stdout, ?mixed $capture_stderr): int {}

        /**
         * Constructs a new ShellCommand for the given program path.
         *
         * # Parameters
         * - `executable`: `string` Path to the executable or command name.
         *
         * # Notes
         * - Does not validate existence until execution.
         */
        public function __construct(string $executable, ?array $arguments) {}
    }

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
        public function equalsAny(mixed ...$hostnames): bool {}

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
        public function equalsAnyUrl(mixed ...$urls): bool {}

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

        /**
         * Returns true if this hostname is a subdomain of any in the given list.
         *
         * # Parameters
         * - `hosts`: List of parent hostname strings to check.
         *
         * # Errors
         * Throws an exception if parsing any provided hostname fails.
         */
        public function subdomainOfAny(mixed ...$hosts): bool {}

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

        /**
         * Returns true if this hostname is an IPv4 address.
         *
         * # Returns
         * - `bool`: `true` if the hostname is an IPv4 address.
         */
        public function isIpv4(): bool {}

        /**
         * Returns true if this hostname is an IPv6 address.
         *
         * # Returns
         * - `bool`: `true` if the hostname is an IPv6 address.
         */
        public function isIpv6(): bool {}

        /**
         * Returns true if this hostname is an IP address (either IPv4 or IPv6).
         *
         * # Returns
         * - `bool`: `true` if the hostname is an IP address.
         */
        public function isIp(): bool {}

        /**
         * Returns true if this hostname is a domain name (not an IP address).
         *
         * # Returns
         * - `bool`: `true` if the hostname is a domain name.
         */
        public function isDomain(): bool {}

        /**
         * Returns the string representation of this hostname.
         *
         * # Returns
         * - `string`: The normalized hostname string.
         */
        public function __toString(): string {}

        /**
         * Constructs a new Hostname instance (alias for `from`).
         *
         * # Parameters
         * - `hostname`: The hostname to initialize.
         *
         * # Errors
         * Throws an exception if parsing the hostname fails.
         */
        public function __construct(mixed $hostname) {}
    }

    class Path {
        /**
         * Creates a new PathObj by lexically canonicalizing a given PHP value.
         *
         * # Parameters
         * - `path`: The PHP value to convert to a filesystem path.
         *
         * # Exceptions
         * - Throws an exception if conversion of `$path` to string fails.
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
         * # Exceptions
         * - Throws an exception if conversion from Zval to string fails.
         */
        public function startsWith(mixed $path): bool {}

        /**
         * Joins the given path onto this path and normalizes it.
         *
         * # Parameters
         * - `path`: The PHP value to join.
         *
         * # Returns
         * A new PathObj representing the joined path.
         *
         * # Exceptions
         * - Throws an exception if conversion from Zval to string fails.
         */
        public function join(mixed $path): \Hardened\Path {}

        /**
         * Joins the given path onto this path, normalizes it, and ensures it's a subpath.
         *
         * # Parameters
         * - `path`: string|Path
         *
         * # Exceptions
         * - Throws an exception if `$path` is not a string nor Path
         */
        public function joinSubpath(mixed $path): \Hardened\Path {}

        /**
         * Set the file name component of the path.
         *
         * # Parameters
         * - `fileName`: string
         */
        public function setFileName(string $file_name): \Hardened\Path {}

        /**
         * Set the file name component of the path.
         *
         * # Parameters
         * - `extension`: string
         */
        public function setExtension(string $extension): \Hardened\Path {}

        /**
         * Get the last component of the path.
         */
        public function fileName(): ?string {}

        /**
         * Get the directory name (similar to `dirname()`).
         */
        public function parent(): ?\Hardened\Path {}

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

        /**
         * Check if the path's extension is in the allowed list.
         *
         * # Parameters
         * - `allowed`: PHP array of allowed extensions (strings, without leading dot), case-insensitive.
         *
         * # Returns
         * - `bool` `true` if the file extension matches one of the allowed values.
         */
        public function validateExtension(array $allowed): bool {}

        /**
         * Check if the path's extension is a common image type.
         *
         * # Returns
         * - `bool` `true` if extension is one of `["png","jpg","jpeg","gif","webp","bmp","tiff","svg"]`.
         */
        public function validateExtensionImage(): bool {}

        /**
         * Check if the path's extension is a common video type.
         *
         * # Returns
         * - `bool` `true` if extension is one of `["mp4","mov","avi","mkv","webm","flv"]`.
         */
        public function validateExtensionVideo(): bool {}

        /**
         * Check if the path's extension is a common audio type.
         *
         * # Returns
         * - `bool` `true` if extension is one of `["mp3","wav","ogg","flac","aac"]`.
         */
        public function validateExtensionAudio(): bool {}

        /**
         * Check if the path's extension is a common document type.
         *
         * # Returns
         * - `bool` `true` if extension is one of `["pdf","doc","docx","xls","xlsx","ppt","pptx"]`.
         */
        public function validateExtensionDocument(): bool {}

        /**
         * Returns true if the path is absolute (starts with root or drive prefix).
         *
         * # Returns
         * - `bool` `true` if the path is absolute.
         */
        public function isAbsolute(): bool {}

        /**
         * Returns true if the path is relative (not absolute).
         *
         * # Returns
         * - `bool` `true` if the path is relative.
         */
        public function isRelative(): bool {}

        /**
         * Returns true if the path tried to escape its base directory during normalization.
         *
         * This is useful for detecting directory traversal attempts.
         * A path "escapes" if it contains leading `..` components that would go above
         * the starting directory, or if it starts with a root/prefix.
         *
         * # Returns
         * - `bool` `true` if the path escaped during normalization.
         */
        public function hasEscaped(): bool {}

        /**
         * Returns the file extension, if any.
         *
         * # Returns
         * - `?string` The extension without the leading dot, or `null` if none.
         */
        public function extension(): ?string {}

        /**
         * Constructs a new PathObj instance (alias for `from`).
         *
         * # Parameters
         * - `path`: The PHP value to convert to a filesystem path.
         *
         * # Exceptions
         * - Throws an exception if conversion from Zval to string fails.
         */
        public function __construct(mixed $path) {}
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
         * - `string` containing `len` random bytes.
         *
         * # Exceptions
         * - Throws an exception if the uniform distribution for `u8` cannot be created.
         */
        public static function bytes(int $len): string {}

        /**
         * Generate a vector of random integers in the inclusive range `[low, high]`.
         *
         * # Parameters
         * - `n`: Number of integers to generate.
         * - `low`: Lower bound (inclusive).
         * - `high`: Upper bound (inclusive).
         *
         * # Returns
         * - `array[int; n]` — array of random values within bounds
         *
         * # Exceptions
         * - Throws an exception if the range is invalid (e.g. `low > high`) or distribution creation fails.
         */
        public static function ints(int $n, int $low, int $high): array {}

        /**
         * Generate a single random integer in the inclusive range `[low, high]`.
         *
         * # Parameters
         * - `low`: Lower bound (inclusive).
         * - `high`: Upper bound (inclusive).
         *
         * # Returns
         * - `int` — random value within bounds
         *
         * # Exceptions
         * - Throws an exception if the range is invalid (e.g. `low > high`) or distribution creation fails.
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
         * - `string` of length `len`, or an empty string if `chars` is empty.
         *
         * # Exceptions
         * - Throws an exception if `char` does not contain at least one Unicode character.
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
         * - `string` of length `len`, or an empty string if `chars` is empty.
         *
         * # Exceptions
         * - Throws an exception if `char` does not contain at least one Unicode grapheme.
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
         *
         * # Exceptions
         * - Throws an exception if `char` does not contain at least one byte.
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

    /**
     * CSRF protection for your application.
     */
    class CsrfProtection {
        public static function generateKey(): string {}

        /**
         * Verifies a CSRF token & cookie pair from PHP.
         *
         * # Parameters
         * - `token`: `string` Base64URL-encoded CSRF token from client.
         * - `cookie`: `string` Base64URL-encoded CSRF cookie from client.
         *
         * # Returns
         * - `void` on success.
         *
         * # Exceptions
         * - Throws `Exception` if decoding fails or the token–cookie pair is invalid/expired.
         */
        public function verifyToken(string $token, ?string $cookie): mixed {}

        /**
         * Returns the CSRF cookie string to send in PHP.
         *
         * # Returns
         * - `string` Base64URL-encoded cookie suitable for `Set-Cookie`.
         */
        public function cookie(): string {}

        /**
         * Returns the CSRF token string for PHP forms or headers.
         *
         * # Returns
         * - `string` Base64URL-encoded token.
         */
        public function token(): string {}

        /**
         * Sets the name of the CSRF cookie to use in PHP calls.
         *
         * # Parameters
         * - `cookieName`: `string` the new name for the CSRF cookie.
         *
         * # Returns
         * - `void`
         */
        public function setCookieName(string $cookie_name) {}

        /**
         * Returns the configured CSRF cookie name.
         *
         * # Returns
         * - `string` the name of the CSRF cookie.
         */
        public function cookieName(): string {}

        /**
         * Sends the CSRF cookie to the client via `setcookie()`
         *
         * # Parameters
         * - `expires`: `?int` UNIX timestamp when the cookie expires (defaults to `0`, a session cookie).
         * - `path`: `?string` Cookie path (defaults to `"/"`).
         * - `domain`: `?string` Cookie domain (defaults to the current host).
         * - `secure`: `?bool` Send only over HTTPS (defaults to `false`).
         * - `httponly`: `?bool` HTTP-only flag (defaults to `true`).
         *
         * # Exceptions
         * - Throws `Exception` if the PHP `setcookie()` function cannot be invoked.
         */
        public function sendCookie(?int $expires, ?string $path, ?string $domain, ?bool $secure, ?bool $httponly): mixed {}

        /**
         * Constructs a CSRF protection instance for PHP.
         *
         * # Parameters
         * - `key`: `string` Base64URL-encoded 32-byte secret key.
         * - `ttl`: `int` token time-to-live in seconds.
         * - `previousTokenValue`: `?string` optional Base64URL-encoded previous token for rotation.
         *
         * # Exceptions
         * - Throws `Exception` if key decoding or length validation fails.
         * - Throws `Exception` if token pair generation fails.
         */
        public function __construct(string $key, int $ttl, ?string $previous_token_value) {}
    }
}

namespace Hardened\Sanitizers {
    /**
     * PHP class wrapping Ammonia's HTML sanitizer builder.
     * Allows customized sanitization through PHP method calls.
     */
    class HtmlSanitizer {
        const TRUNCATE_DEFAULT_ENDING = null;

        /**
         * Constructs a sanitizer with default configuration.
         *
         * # Returns
         * - HtmlSanitizer A new sanitizer instance.
         */
        public static function Default(): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Denies all relative URLs in attributes.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function urlRelativeDeny(): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function urlRelativePassthrough(): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function urlRelativeRewriteWithBase(string $base_url): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function urlRelativeRewriteWithRoot(string $root, string $path): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Sets the `rel` attribute for generated `<a>` tags.
         *
         * # Parameters
         * - `value`: Optional `rel` attribute value; `None` clears it.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function linkRel(?string $value): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function tags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function cleanContentTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function addCleanContentTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function rmCleanContentTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function addTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes tags from the whitelist.
         *
         * # Parameters
         * - `tags`: An array of tag names to remove.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function rmTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function addAllowedClasses(string $tag, array $classes): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function rmAllowedClasses(string $tag, array $classes): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function addTagAttributes(string $tag, array $attributes): \Hardened\Sanitizers\HtmlSanitizer {}

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
        public function rmTagAttributes(string $tag, array $classes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds generic attributes to all tags.
         *
         * # Parameters
         * - `attributes`: An array of attribute names to allow.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         * - `Exception` if `attributes` is not an array.
         */
        public function addGenericAttributes(array $attributes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes generic attributes from all tags.
         *
         * # Parameters
         * - `attributes`: An array of attribute names to remove.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function rmGenericAttributes(array $attributes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds prefixes for generic attributes.
         *
         * # Parameters
         * - `prefixes`: An array of prefixes to allow.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function addGenericAttributePrefixes(array $prefixes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes prefixes for generic attributes.
         *
         * # Parameters
         * - `prefixes`: An array of prefixes to remove.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function rmGenericAttributePrefixes(array $prefixes): \Hardened\Sanitizers\HtmlSanitizer {}

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
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function urlSchemes(array $schemes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Enables or disables HTML comment stripping.
         *
         * # Parameters
         * - `strip`: `true` to strip comments; `false` to preserve them.
         *    Comments are stripped by default.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function stripComments(bool $strip): \Hardened\Sanitizers\HtmlSanitizer {}

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
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function idPrefix(?string $prefix): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Filters CSS style properties allowed in `style` attributes.
         *
         * # Parameters
         * - `props`: An array of CSS property names to allow.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function newFilterStyleProperties(array $props): \Hardened\Sanitizers\HtmlSanitizer {}

        public function filterStyleProperties(array $props): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Sets a single tag attribute value.
         *
         * # Parameters
         * - `tag`: The tag name as A string.
         * - `attribute`: The attribute name as A string.
         * - `value`: The value to set.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function setTagAttributeValue(string $tag, string $attribute, string $value): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Returns the configured tags as a vector of strings.
         *
         * # Returns
         * - `Vec<String>` The list of allowed tag names.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function cloneTags(): array {}

        /**
         * Gets all configured clean-content tags.
         *
         * # Returns
         * - `Vec<String>` The list of tags whose content is preserved.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function cloneCleanContentTags(): array {}

        /**
         * Bulk overwrites generic attributes.
         *
         * # Parameters
         * - `attrs`: An array of attribute names.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function genericAttributes(array $attrs): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Bulk overwrites generic attribute prefixes.
         *
         * # Parameters
         * - `prefixes`: An array of prefixes.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function genericAttributePrefixes(array $prefixes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds tag attribute values.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `attr`: A string attribute name.
         * - `values`: An array of values to allow.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function addTagAttributeValues(string $tag, string $attr, array $values): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes tag attribute values.
         *
         * # Parameters
         * - `tag`: A string tag name.
         * - `attr`: A string attribute name.
         * - `values`: An array of values to remove.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function rmTagAttributeValues(string $tag, string $attr, array $values): \Hardened\Sanitizers\HtmlSanitizer {}

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
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function getSetTagAttributeValue(string $tag, string $attr): ?string {}

        /**
         * Checks if URL relative policy is Deny.
         *
         * # Returns
         * - `bool` `true` if the policy is Deny.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function isUrlRelativeDeny(): bool {}

        /**
         * Checks if URL relative policy is PassThrough.
         *
         * # Returns
         * - `bool` `true` if the policy is PassThrough.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function isUrlRelativePassThrough(): bool {}

        /**
         * Checks if URL relative policy is custom (Rewrite).
         *
         * # Returns
         * - `bool` `true` if a custom rewrite policy is set.
         *
         * # Exceptions
         * - `Exception` if the sanitizer is not in a valid state.
         */
        public function isUrlRelativeCustom(): bool {}

        /**
         * Sets the attribute filter callback.
         *
         * # Parameters
         * - `callable`: A PHP callable of signature `(string Element, string Attribute, string Value) -> string|null`.
         *
         * # Exceptions
         * - None.
         */
        public function attributeFilter(mixed $callable): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Sanitize and truncate the given HTML by extended grapheme clusters.
         *
         * This is a convenience wrapper that ensures no user-perceived character
         * (including complex emoji or combined sequences) is split in half.
         *
         * # Parameters
         * - `html`: Raw HTML string to sanitize and truncate.
         * - `max_units`: Maximum number of Unicode extended grapheme clusters
         *   to retain (including the `etc` suffix).
         * - `etc`: Optional suffix (e.g., ellipsis) to join when truncation occurs. Default is …
         *
         * # Exceptions
         * - Throws `Exception` if sanitization or truncation fails.
         */
        public function cleanAndTruncate(string $html, int $max, mixed $flags, ?string $etc): string {}

        /**
         * Constructs a sanitizer with default configuration.
         *
         * # Returns
         * - HtmlSanitizer A new sanitizer instance.
         */
        public function __construct() {}
    }

    class SvgSanitizer {
        const PRESET_STRICT = null;

        const PRESET_STANDARD = null;

        const PRESET_PERMISSIVE = null;

        /**
         * Create a new SvgSanitizer with default (standard) settings
         */
        public static function Default(): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Create a sanitizer with a named preset
         */
        public static function withPreset(string $preset_name): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Static method for file-based bomb detection (throws on dangerous SVG)
         */
        public static function defuse(string $path, ?int $max_dimension): mixed {}

        /**
         * Sanitize SVG content string
         */
        public function clean(string $svg): string {}

        /**
         * Sanitize SVG file and return cleaned content
         */
        public function cleanFile(string $path): string {}

        /**
         * Check if SVG content is safe without modification
         */
        public function isSafe(string $svg): bool {}

        /**
         * Check if SVG file is safe without modification
         */
        public function isSafeFile(string $path): bool {}

        /**
         * Set allowed SVG elements (overwrites defaults)
         */
        public function allowElements(array $elements): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Add elements to the allowlist
         */
        public function addAllowedElements(array $elements): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Remove elements from the allowlist
         */
        public function removeElements(array $elements): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Set allowed attributes (overwrites defaults)
         */
        public function allowAttributes(array $attributes): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Add attributes to the allowlist
         */
        public function addAllowedAttributes(array $attributes): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Remove attributes from the allowlist
         */
        public function removeAttributes(array $attributes): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Set maximum allowed dimension (width/height/viewBox)
         */
        public function setMaxDimension(int $max): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Set maximum nesting depth
         */
        public function setMaxNestingDepth(int $max): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Enable/disable blocking of external references (http/https URLs)
         */
        public function blockExternalReferences(bool $block): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Enable/disable blocking of data: URIs
         */
        public function blockDataUris(bool $block): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Enable/disable XML comments removal
         */
        public function stripComments(bool $strip): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Allow relative URLs
         */
        public function allowRelativeUrls(bool $allow): \Hardened\Sanitizers\SvgSanitizer {}

        public function __construct() {}
    }
}

namespace Hardened\Sanitizers\File {
    /**
     * Engine for detecting "PNG bombs" (images with unreasonable dimensions).
     */
    class PngSanitizer {
        /**
         * Scan a file at the given path and detect PNG bombs.
         *
         * # Parameters
         * - `path`: `string` Filesystem path to the PNG file.
         *
         * # Returns
         * - `bool` `true` if the file is a PNG *and* has width or height > 10000,
         *   or if it's invalid PNG with missing IHDR. Returns `false` if it's not
         *   a PNG or has acceptable dimensions.
         *
         * # Exceptions
         * - Throws an exception if the file cannot be opened, read, or the format
         *   is malformed (e.g. missing IHDR).
         *
         * ## Example
         * ```php
         * Hardened\Sanitizers\File\PngSanitizer::defuse('/tmp/image.png');
         * ```
         */
        public static function defuse(string $path): mixed {}

        public function __construct() {}
    }

    /**
     * Archive bomb detector for ZIP and RAR files.
     *
     * Provides two methods in PHP:
     *   - `scan_zip(string $path): bool`
     *   - `scan_rar(string $path, ?int $maxRatio = 1000): bool`
     */
    class ArchiveSanitizer {
        /**
         * Perform archive‐bomb detection on a file.
         *
         * This internal helper examines the file at `path` and returns an error if it
         * appears to be a "bomb" (i.e. an archive whose reported uncompressed size
         * far exceeds its on‐disk compressed size or mismatches the local header).
         *
         * **ZIP**:
         * - Reads the central directory to sum the uncompressed sizes of all entries.
         * - Reads the 4‐byte little‐endian uncompressed size from the local file header at offset 22.
         * - Fails if those two values differ.
         *
         * **RAR**:
         * - Computes the on‐disk file size.
         * - Lists the first entry's `unpacked_size` and divides by the compressed size.
         * - Fails if that ratio ≥ `max_ratio` (default 1000).
         *
         * # Parameters
         * - `path`: Filesystem path to the archive file to inspect.
         * - `max_ratio`: Optional maximum unpacked/compressed ratio for RAR; Default is 1000
         *
         * # Exceptions
         * - I/O errors opening, reading, or seeking the file.
         * - ZIP archive mismatches (central-directory total vs. local-header size).
         * - RAR archive exceeds the allowed unpacked/compressed ratio.
         */
        public static function defuse(string $path, ?int $max_ratio): mixed {}

        public function __construct() {}
    }
}

namespace Hardened\SecurityHeaders {
    /**
     * Your application’s CSP config.
     */
    class ContentSecurityPolicy {
        /**
         * Fallback for other fetch directives.
         */
        const DEFAULT_SRC = null;

        /**
         * Controls allowed sources for scripts.
         */
        const SCRIPT_SRC = null;

        /**
         * Controls allowed sources for stylesheets.
         */
        const STYLE_SRC = null;

        /**
         * Controls allowed sources for images.
         */
        const IMG_SRC = null;

        /**
         * Restricts which parent origins can embed this resource.
         */
        const FRAME_ANCESTORS = null;

        /**
         * Controls allowed endpoints for fetch, XHR, WebSocket, etc.
         */
        const CONNECT_SRC = null;

        /**
         * Controls allowed sources for font resources.
         */
        const FONT_SRC = null;

        /**
         * Alias for controlling allowed embedding contexts.
         */
        const CHILD_SRC = null;

        /**
         * Controls allowed sources for web app manifests.
         */
        const MANIFEST_SRC = null;

        /**
         * Controls allowed sources for media elements.
         */
        const MEDIA_SRC = null;

        /**
         * Controls allowed sources for plugin content.
         */
        const OBJECT_SRC = null;

        /**
         * Controls allowed sources for prefetch operations.
         */
        const PREFETCH_SRC = null;

        /**
         * Controls allowed sources for script elements.
         */
        const SCRIPT_SRC_ELEM = null;

        /**
         * Controls allowed sources for inline event handlers.
         */
        const SCRIPT_SRC_ATTR = null;

        /**
         * Controls allowed sources for style elements.
         */
        const STYLE_SRC_ELEM = null;

        /**
         * Controls allowed sources for inline style attributes.
         */
        const STYLE_SRC_ATTR = null;

        /**
         * Controls allowed sources for worker scripts.
         */
        const WORKER_SRC = null;

        /**
         * Restricts the set of URLs usable in the document’s base element.
         */
        const BASE_URI = null;

        /**
         * Restricts the URLs that forms can submit to.
         */
        const FORM_ACTION = null;

        /**
         * Applies sandboxing rules to the document.
         */
        const SANDBOX = null;

        /**
         * Restricts the types of plugins that may be loaded.
         */
        const PLUGIN_TYPES = null;

        /**
         * Disallows all mixed HTTP content on secure pages.
         */
        const BLOCK_ALL_MIXED_CONTENT = null;

        /**
         * Instructs browsers to upgrade insecure requests to HTTPS.
         */
        const UPGRADE_INSECURE_REQUESTS = null;

        /**
         * Specifies a URI to which policy violation reports are sent.
         */
        const REPORT_URI = null;

        /**
         * Specifies a reporting group for violation reports.
         */
        const REPORT_TO = null;

        /**
         * Requires Subresource Integrity checks for specified resource types.
         */
        const REQUIRE_SRI_FOR = null;

        /**
         * Restricts creation of DOM sinks to a trusted-types policy.
         */
        const TRUSTED_TYPES = null;

        /**
         * Enforces Trusted Types for specified sinks.
         */
        const REQUIRE_TRUSTED_TYPES_FOR = null;

        /**
         * The `'self'` keyword, allowing the same origin.
         */
        const SELF = null;

        /**
         * The `'unsafe-inline'` keyword, allowing inline scripts or styles.
         */
        const UNSAFE_INLINE = null;

        /**
         * The `'unsafe-eval'` keyword, allowing `eval()` and similar.
         */
        const UNSAFE_EVAL = null;

        /**
         * The `'unsafe-hashes'` keyword, allowing hash-based inline resources.
         */
        const UNSAFE_HASHES = null;

        /**
         * The `'strict-dynamic'` keyword, enabling strict dynamic loading.
         */
        const STRICT_DYNAMIC = null;

        /**
         * The `'nonce-…'` placeholder for single-use nonces.
         */
        const NONCE = null;

        /**
         * The `script` token for SRI or Trusted Types policies.
         */
        const SCRIPT = null;

        /**
         * The `style` token for SRI or Trusted Types policies.
         */
        const STYLE = null;

        /**
         * Allows form submission in a sandboxed context.
         */
        const ALLOW_FORMS = null;

        /**
         * Allows modal dialogs in a sandboxed context.
         */
        const ALLOW_MODALS = null;

        /**
         * Allows orientation lock in a sandboxed context.
         */
        const ALLOW_ORIENTATION_LOCK = null;

        /**
         * Allows pointer lock in a sandboxed context.
         */
        const ALLOW_POINTER_LOCK = null;

        /**
         * Allows presentation mode in a sandboxed context.
         */
        const ALLOW_PRESENTATION = null;

        /**
         * Allows pop-ups in a sandboxed context.
         */
        const ALLOW_POPUPS = null;

        /**
         * Allows pop-ups to escape sandbox restrictions.
         */
        const ALLOW_POPUPS_TO_ESCAPE_SANDBOX = null;

        /**
         * Allows same-origin access in a sandboxed context.
         */
        const ALLOW_SAME_ORIGIN = null;

        /**
         * Allows script execution in a sandboxed context.
         */
        const ALLOW_SCRIPTS = null;

        /**
         * Allows storage access via user activation in a sandbox.
         */
        const ALLOW_STORAGE_ACCESS_BY_USER_ACTIVATION = null;

        /**
         * Allows top-level navigation via user activation.
         */
        const ALLOW_TOP_NAVIGATION_BY_USER_ACTIVATION = null;

        /**
         * Allows duplicate directives.
         */
        const ALLOW_DUPLICATES = null;

        /**
         * Allows WebAssembly to use `eval()`.
         */
        const WASM_UNSAFE_EVAL = null;

        /**
         * Enables inline speculation rules.
         */
        const INLINE_SPECULATION_RULES = null;

        /**
         * Includes sample reports in violation reports.
         */
        const REPORT_SAMPLE = null;

        /**
         * Sets or replaces a CSP directive with the given keywords and host sources.
         *
         * # Parameters
         * - `rule`: The directive name. One of `default-src`, `script-src`, `style-src`, `img-src`, `frame-ancestors`,
         *   `connect-src`, `font-src`, `child-src`, `manifest-src`, `media-src`, `object-src`, `prefetch-src`,
         *   `script-src-elem`, `script-src-attr`, `style-src-elem`, `style-src-attr`, `worker-src`,
         *   `base-uri`, `form-action`, `sandbox`, `plugin-types`, `block-all-mixed-content`,
         *   `upgrade-insecure-requests`, `report-uri`, `report-to`, `require-sri-for`,
         *   `trusted-types`, `require-trusted-types-for`.
         * - `keywords`: Slice of keyword tokens. One or more of `self`, `none`, `unsafe-inline`,
         *   `unsafe-eval`, `unsafe-hashes`, `strict-dynamic`, `nonce`, `script`, `style`,
         *   `allow-forms`, `allow-modals`, `allow-orientation-lock`, `allow-pointer-lock`,
         *   `allow-presentation`, `allow-popups`, `allow-popups-to-escape-sandbox`,
         *   `allow-same-origin`, `allow-scripts`, `allow-storage-access-by-user-activation`,
         *   `allow-top-navigation-by-user-activation`, `allow-duplicates`, `wasm-unsafe-eval`,
         *   `inline-speculation-rules`, `report-sample`.
         * - `sources`: Optional list of host sources (e.g. `["example.com"]`)
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

        /**
         * Send the `Content-Security-Policy` header via PHP `header()`.
         *
         * # Exceptions
         * - Throws `Exception` if the PHP `header()` function cannot be invoked.
         */
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

        /**
         * Constructs a new `ContentSecurityPolicy` builder with no directives set.
         *
         * # Returns
         * - `ContentSecurityPolicy` A fresh instance containing an empty rule map.
         *
         * # Notes
         * - No errors are thrown.
         */
        public function __construct() {}
    }

    /**
     * HTTP Strict Transport Security (HSTS) header builder.
     */
    class StrictTransportSecurity {
        /**
         * Sets the `max-age` directive (in seconds).
         *
         * # Parameters
         * - `maxAge`: `int` number of seconds for `max-age`.
         *
         * # Returns
         * - `void`
         */
        public function maxAge(int $max_age) {}

        /**
         * Enable or disable the `includeSubDomains` flag.
         *
         * # Parameters
         * - `enable`: `bool` `true` to include subdomains, `false` to omit.
         *
         * # Returns
         * - `void`
         */
        public function includeSubDomains(bool $enable) {}

        /**
         * Enable or disable the `preload` flag.
         *
         * # Parameters
         * - `enable`: `bool` `true` to add `preload`, `false` to omit.
         *
         * # Returns
         * - `void`
         */
        public function preload(bool $enable) {}

        /**
         * Builds the `Strict-Transport-Security` header value.
         *
         * # Returns
         * - `string` e.g. `"max-age=31536000; includeSubDomains; preload"`.
         */
        public function build(): string {}

        /**
         * Sends the `Strict-Transport-Security` header via PHP `header()` function.
         *
         * # Exceptions
         * - Throws `Exception` if PHP `header()` cannot be invoked.
         */
        public function send(): mixed {}

        /**
         * Constructs a new HSTS builder with default settings.
         *
         * # Returns
         * - `Hsts` New instance with `max-age=0`, no subdomains, no preload.
         */
        public function __construct() {}
    }

    /**
     * Builder for miscellaneous HTTP security headers:
     * `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`,
     * `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,
     * and `Integrity-Policy-Report-Only`.
     */
    class Whatnot {
        /**
         * Set `X-Frame-Options` header.
         *
         * # Parameters
         * - `mode`: `"DENY"`, `"SAMEORIGIN"`, or `"ALLOW-FROM"`.
         * - `uri`: Optional URI, required if `mode` is `"ALLOW-FROM"`.
         *
         * # Exceptions
         * - Throws if `mode` is invalid or `"ALLOW-FROM"` is given without a URI.
         */
        public function setFrameOptions(string $mode, ?string $uri): mixed {}

        /**
         * Set `X-XSS-Protection` header.
         *
         * # Parameters
         * - `mode`: one of `"off"`, `"on"` or `"block"`.
         * - `report_uri`: Optional reporting URI, only allowed when `mode` is `"1"`.
         *
         * # Exceptions
         * - Throws if `mode` is invalid or a `report_uri` is provided for 'off' mode.
         */
        public function setXssProtection(string $mode, ?string $report_uri): mixed {}

        /**
         * Enable or disable `X-Content-Type-Options: nosniff`.
         */
        public function setNosniff(bool $enable) {}

        /**
         * Set `X-Permitted-Cross-Domain-Policies` header.
         *
         * # Parameters
         * - `mode`: one of `"none"`, `"master-only"`, `"by-content-type"`, or `"all"`.
         *
         * # Exceptions
         * - Throws if `mode` is not a valid policy token.
         */
        public function setPermittedCrossDomainPolicies(string $mode): mixed {}

        /**
         * Configure the `Report-To` header from structured arguments.
         *
         * # Parameters
         * - `group`: report group name.
         * - `max_age`: seconds to retain reports.
         * - `include_subdomains`: whether to include subdomains.
         * - `endpoints`: PHP array of endpoint names.
         *
         * # Exceptions
         * - Throws if any argument is invalid.
         */
        public function setReportTo(string $group, int $max_age, bool $include_subdomains, array $endpoints): mixed {}

        /**
         * Set a structured `Integrity-Policy` header.
         *
         * # Parameters
         * - `blocked_destinations`: PHP array of destinations, e.g. `['script']`.
         * - `sources`: Optional PHP array of sources, e.g. `['inline']`.
         * - `endpoints`: Optional PHP array of reporting endpoint names.
         *
         * # Exceptions
         * - Throws if any required array is missing or contains invalid entries.
         */
        public function setIntegrityPolicy(mixed $blocked_destinations, ?array $sources, ?array $endpoints): mixed {}

        /**
         * Set `Integrity-Policy-Report-Only` header value.
         */
        public function setIntegrityPolicyReportOnly(string $policy): mixed {}

        /**
         * Build an associative array of header names → values.
         */
        public function build(): array {}

        /**
         * Emit all configured headers via PHP `header()` calls.
         */
        public function send(): mixed {}

        /**
         * Constructs a new builder with all headers disabled.
         */
        public function __construct() {}
    }

    /**
     * Permissions-Policy header builder.
     */
    class PermissionsPolicy {
        /**
         * Controls whether the current document is allowed to gather information
         * about the acceleration of the device through the Accelerometer interface.
         */
        const ACCELEROMETER = null;

        /**
         * Controls whether the current document is allowed to gather information
         * about the amount of light in the environment around the device through
         * the AmbientLightSensor interface.
         */
        const AMBIENT_LIGHT_SENSOR = null;

        /**
         * Controls whether the current document is allowed to use the
         * Attribution Reporting API.
         */
        const ATTRIBUTION_REPORTING = null;

        /**
         * Controls whether the current document is allowed to autoplay media
         * requested through the HTMLMediaElement interface. When disabled without
         * user gesture, play() will reject with NotAllowedError.
         */
        const AUTOPLAY = null;

        /**
         * Controls whether the use of the Web Bluetooth API is allowed.
         * When disabled, Bluetooth methods will either return false or reject.
         */
        const BLUETOOTH = null;

        /**
         * Controls access to the Topics API. Disallowed calls to browsingTopics()
         * or Sec-Browsing-Topics header will fail with NotAllowedError.
         */
        const BROWSING_TOPICS = null;

        /**
         * Controls whether the current document is allowed to use video input devices.
         * When disabled, getUserMedia() will reject with NotAllowedError.
         */
        const CAMERA = null;

        /**
         * Controls access to the Compute Pressure API.
         */
        const COMPUTE_PRESSURE = null;

        /**
         * Controls whether the current document can be treated as cross-origin isolated.
         */
        const CROSS_ORIGIN_ISOLATED = null;

        /**
         * Controls the allocation of the top-level origin’s fetchLater() quota.
         */
        const DEFERRED_FETCH = null;

        /**
         * Controls the allocation of the shared cross-origin subframe fetchLater() quota.
         */
        const DEFERRED_FETCH_MINIMAL = null;

        /**
         * Controls whether the current document may capture display media via getDisplayMedia().
         * When disabled, getDisplayMedia() will reject with NotAllowedError.
         */
        const DISPLAY_CAPTURE = null;

        /**
         * Controls whether the current document is allowed to use the Encrypted Media
         * Extensions API (EME). When disabled, requestMediaKeySystemAccess() will reject.
         */
        const ENCRYPTED_MEDIA = null;

        /**
         * Controls whether the current document is allowed to use Element.requestFullscreen().
         * When disabled, requestFullscreen() will reject with TypeError.
         */
        const FULLSCREEN = null;

        /**
         * Controls whether the current document is allowed to use the Gamepad API.
         * When disabled, getGamepads() will throw SecurityError and events won’t fire.
         */
        const GAMEPAD = null;

        /**
         * Controls whether the current document is allowed to use the Geolocation Interface.
         * When disabled, geolocation callbacks will error with PERMISSION_DENIED.
         */
        const GEOLOCATION = null;

        /**
         * Controls whether the current document is allowed to gather information
         * about device orientation through the Gyroscope interface.
         */
        const GYROSCOPE = null;

        /**
         * Controls whether the current document is allowed to use the WebHID API.
         * Allows communication with HID devices like gamepads or keyboards.
         */
        const HID = null;

        /**
         * Controls whether the document may use the Federated Credential Management API
         * (FedCM) via navigator.credentials.get({identity:…}).
         */
        const IDENTITY_CREDENTIALS_GET = null;

        /**
         * Controls whether the document may use the Idle Detection API to detect user idle/active state.
         */
        const IDLE_DETECTION = null;

        /**
         * Controls access to the language detection functionality of Translator & Language Detector APIs.
         */
        const LANGUAGE_DETECTOR = null;

        /**
         * Controls whether the document may gather data on locally-installed fonts via queryLocalFonts().
         */
        const LOCAL_FONTS = null;

        /**
         * Controls whether the document may gather device orientation via the Magnetometer interface.
         */
        const MAGNETOMETER = null;

        /**
         * Controls whether the document is allowed to use audio input devices.
         * When disabled, getUserMedia() will reject with NotAllowedError.
         */
        const MICROPHONE = null;

        /**
         * Controls whether the document may use the Web MIDI API.
         * When disabled, requestMIDIAccess() will reject with SecurityError.
         */
        const MIDI = null;

        /**
         * Controls whether the document may use the WebOTP API to retrieve one-time passwords.
         */
        const OTP_CREDENTIALS = null;

        /**
         * Controls whether the document may use the Payment Request API.
         * When disabled, PaymentRequest() will throw SecurityError.
         */
        const PAYMENT = null;

        /**
         * Controls whether the document may enter Picture-in-Picture mode via the API.
         */
        const PICTURE_IN_PICTURE = null;

        /**
         * Controls whether the document may use Web Authentication API to create new credentials.
         */
        const PUBLICKEY_CREDENTIALS_CREATE = null;

        /**
         * Controls whether the document may use Web Authentication API to retrieve stored credentials.
         */
        const PUBLICKEY_CREDENTIALS_GET = null;

        /**
         * Controls whether the document may use the Screen Wake Lock API to keep the screen on.
         */
        const SCREEN_WAKE_LOCK = null;

        /**
         * Controls whether the document may use the Web Serial API to communicate with serial devices.
         */
        const SERIAL = null;

        /**
         * Controls whether the document may list and select speakers via the Output Devices API.
         */
        const SPEAKER_SELECTION = null;

        /**
         * Controls whether an embedded document may use the Storage Access API for third-party cookies.
         */
        const STORAGE_ACCESS = null;

        /**
         * Controls access to the translation functionality of Translator & Language Detector APIs.
         */
        const TRANSLATOR = null;

        /**
         * Controls access to the Summarizer API.
         */
        const SUMMARIZER = null;

        /**
         * Controls whether the document may use the WebUSB API to connect to USB devices.
         */
        const USB = null;

        /**
         * Controls whether the document may use the Web Share API (navigator.share()).
         */
        const WEB_SHARE = null;

        /**
         * Controls whether the document may use the Window Management API to manage windows.
         */
        const WINDOW_MANAGEMENT = null;

        /**
         * Controls whether the document may use the WebXR Device API to interact with XR sessions.
         */
        const XR_SPATIAL_TRACKING = null;

        const ORIGIN_SELF = null;

        const ORIGIN_ANY = null;

        const ORIGIN_SRC = null;

        /**
         * Allow a feature for the given list of origins.
         *
         * # Parameters
         * - `feature`: one of the defined `Feature` tokens.
         * - `origins`: list of allowlist entries, e.g. `"self"`, `"*"`, `"src"`, or quoted origins.
         *
         * # Errors
         * - if `feature` is not recognized.
         */
        public function allow(string $feature, array $origins): mixed {}

        /**
         * Deny a feature entirely (empty allowlist).
         *
         * # Parameters
         * - `feature`: one of the defined `Feature` tokens.
         *
         * # Errors
         * - if `feature` is not recognized.
         */
        public function deny(string $feature): mixed {}

        /**
         * Builds the Permissions-Policy header value.
         *
         * # Returns
         * - `String`, e.g.:
         *   `geolocation=(self "https://api.example.com"), camera=()`
         */
        public function build(): string {}

        /**
         * Sends the Permissions-Policy header via PHP `header()` function.
         *
         * # Errors
         * - Returns an error if PHP `header()` cannot be invoked.
         */
        public function send(): mixed {}

        /**
         * Constructs a new Permissions-Policy builder with no features allowed.
         *
         * # Returns
         * - `PermissionsPolicy` New instance with an empty feature map.
         */
        public function __construct() {}
    }

    /**
     * Referrer-Policy header builder.
     */
    class ReferrerPolicy {
        /**
         * Update the active Referrer-Policy directive.
         *
         * # Parameters
         * - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
         *
         * # Exceptions
         * - Throws `Exception` if the provided token is invalid.
         */
        public function set(string $policy): mixed {}

        /**
         * Get the current Referrer-Policy value.
         *
         * # Returns
         * - `string` the active policy token.
         */
        public function get(): string {}

        /**
         * Build the `Referrer-Policy` header value.
         *
         * # Returns
         * - `string` the configured policy value suitable for sending as a header.
         */
        public function build(): string {}

        /**
         * Send the `Referrer-Policy` header via PHP `header()` function.
         *
         * # Exceptions
         * - Throws `Exception` if the PHP `header()` function cannot be invoked.
         */
        public function send(): mixed {}

        /**
         * Create a new Referrer-Policy builder for PHP.
         *
         * By default, the referrer policy is set to `no-referrer`, which prevents
         * the `Referer` header from being sent with any requests.
         *
         * # Parameters
         * - `policy`: Optional string. If provided, must match one of these tokens:
         *   - `"no-referrer"`                          — never send the `Referer` header.
         *   - `"no-referrer-when-downgrade"`           — send full URL except when downgrading HTTPS→HTTP.
         *   - `"origin"`                               — send only the origin (`scheme://host[:port]`).
         *   - `"origin-when-cross-origin"`             — send full URL same-origin; origin for cross-origin.
         *   - `"same-origin"`                          — send full URL only for same-origin; omit for cross-origin.
         *   - `"strict-origin"`                        — send origin except on HTTPS→HTTP downgrade (omit then).
         *   - `"strict-origin-when-cross-origin"`      — full URL same-origin; origin cross-origin non-downgrade; omit on downgrade.
         *   - `"unsafe-url"`                           — always send full URL, regardless of context.
         *
         * # Exceptions
         * - Throws `Exception` if `policy` is not a recognized directive.
         */
        public function __construct(?string $policy) {}
    }
}

namespace Hardened\SecurityHeaders\CrossOrigin {
    /**
     * CORS policy builder for HTTP responses.
     */
    class ResourceSharing {
        const SELF = null;

        /**
         * Specify which origins are allowed to access the resource.
         *
         * Browsers will only allow cross-origin requests if the request's
         * `Origin` header matches one of these values. Use `["*"]` to allow
         * any origin (note: this will disable credentials).
         *
         * # Parameters
         * - `origins`: A list of allowed origin URLs (e.g. `["https://example.com"]`),
         *   or `["*"]` for a wildcard that permits all origins.
         *
         * # Behavior
         * - If the request's `Origin` header is not in this list, the browser
         *   will block the response.
         *
         * # Returns
         * - `void`
         */
        public function allowOrigins(array $origins) {}

        /**
         * Specify which HTTP methods may be used in cross-origin requests.
         *
         * During a CORS preflight (`OPTIONS`) request, the browser checks
         * this list to determine whether to allow the actual request method.
         *
         * # Parameters
         * - `methods`: A list of allowed HTTP methods (e.g. `["GET", "POST", "PUT"]`).
         *
         * # Behavior
         * - Methods not in this list will cause the browser to block the
         *   corresponding cross-origin request.
         *
         * # Returns
         * - `void`
         */
        public function allowMethods(array $methods) {}

        /**
         * Specify which custom headers the client may include in the request.
         *
         * Browsers enforce that only simple headers are sent by default; to
         * allow additional headers (e.g. `Content-Type`, `X-Custom-Header`),
         * they must be listed here.
         *
         * # Parameters
         * - `headers`: A list of allowed request header names.
         *
         * # Behavior
         * - Any request header not in this list will be stripped by the browser.
         *
         * # Returns
         * - `void`
         */
        public function allowHeaders(array $headers) {}

        /**
         * Control whether cookies or HTTP authentication information are
         * included in cross-origin requests.
         *
         * # Parameters
         * - `enable`: `true` to send credentials (cookies, HTTP auth), `false`
         *   to omit the `Access-Control-Allow-Credentials` header.
         *
         * # Behavior
         * - If enabled, you **cannot** use `"*"` for `allow_origins`.
         *
         * # Returns
         * - `void`
         */
        public function allowCredentials(bool $enable) {}

        /**
         * Specify which response headers can be accessed by client-side scripts.
         *
         * By default, browsers only expose a limited set of safe headers.
         * To expose additional headers (e.g. `X-RateLimit-Remaining`),
         * list them here.
         *
         * # Parameters
         * - `headers`: A list of response header names that should be
         *   made available to JavaScript via `XMLHttpRequest` or `fetch`.
         *
         * # Returns
         * - `void`
         */
        public function exposeHeaders(array $headers) {}

        /**
         * Set how long (in seconds) the results of a preflight request can
         * be cached by the browser.
         *
         * A higher value reduces the number of CORS preflight requests,
         * improving performance. A value of `0` forces the browser to
         * perform a preflight check on every request.
         *
         * # Parameters
         * - `seconds`: Number of seconds that the browser may cache the
         *   preflight response.
         *
         * # Returns
         * - `void`
         */
        public function maxAge(int $seconds) {}

        /**
         * Build an associative array of CORS headers and their values.
         *
         * # Returns
         * - `array<string,string>` Map of header names to header values.
         */
        public function build(): array {}

        /**
         * Send all configured CORS headers via PHP's `header()` function.
         *
         * # Returns
         * - `void`
         *
         * # Exceptions
         * - Throws `Exception` if PHP `header()` cannot be invoked.
         */
        public function send(): mixed {}

        /**
         * Constructs a new CORS policy with default settings (no restrictions).
         *
         * # Returns
         * - `ResourceSharing` instance where all lists are empty and flags are false/zero.
         */
        public function __construct() {}
    }

    /**
     * Builder for `Cross-Origin-Embedder-Policy` header.
     */
    class EmbedderPolicy {
        /**
         * Allows the document to load cross-origin resources without giving explicit permission
         * through CORS or `Cross-Origin-Resource-Policy`. This is the default.
         */
        const UNSAFE_NONE = null;

        /**
         * Only same-origin or resources explicitly marked via `Cross-Origin-Resource-Policy`
         * or CORS may be loaded.
         */
        const REQUIRE_CORP = null;

        /**
         * Similar to `require-corp`, but drops credentials on no-CORS requests.
         */
        const CREDENTIALLESS = null;

        /**
         * Update the COEP directive.
         *
         * # Parameters
         * - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
         *
         * # Exceptions
         * - Throws an `Exception` if `policy` cannot be parsed into a valid directive.
         */
        public function set(string $policy): mixed {}

        /**
         * Get the current Embedder-Policy value.
         *
         * # Returns
         * - `string` the active policy token.
         */
        public function get(): string {}

        /**
         * Render the header value.
         *
         * # Returns
         * - `string`: the currently configured policy token.
         */
        public function build(): string {}

        /**
         * Send the `Cross-Origin-Embedder-Policy` header via PHP `header()`.
         *
         * # Errors
         * - Throws `Exception` if the PHP `header()` function cannot be invoked.
         */
        public function send(): mixed {}

        /**
         * Create a new Cross-Origin-Embedder-Policy (COEP) builder for PHP.
         *
         * By default, this sets the policy to `"unsafe-none"`, allowing all embedders.
         *
         * # Parameters
         * - `policy`: Optional string directive. Valid values:
         *   - `"unsafe-none"`    — no embedder restrictions.
         *   - `"require-corp"`   — only embedders with valid CORP headers.
         *   - `"credentialless"` — restrict resources and omit credentials.
         *   If omitted, defaults to `"unsafe-none"`.
         *
         * # Exceptions
         * - Throws `Exception` if an invalid token is provided.
         */
        public function __construct(?string $policy) {}
    }

    /**
     * Builder for the `Cross-Origin-Resource-Policy` header.
     */
    class ResourcePolicy {
        /**
         * Change the active Cross-Origin-Resource-Policy directive.
         *
         * This will override any previous setting or the default.
         *
         * # Parameters
         * - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
         *
         * # Exceptions
         * - Throws an `Exception` if `policy` cannot be parsed into a valid directive.
         */
        public function set(string $policy): mixed {}

        /**
         * Get the current Resource-Policy value.
         *
         * # Returns
         * - `string` the active policy token.
         */
        public function get(): string {}

        /**
         * Build the header value.
         *
         * # Returns
         * - `string` the configured directive token.
         */
        public function build(): string {}

        /**
         * Send the `Cross-Origin-Resource-Policy` header via PHP `header()`.
         *
         * # Exceptions
         * - Throws `Exception` if the PHP `header()` function cannot be invoked.
         */
        public function send(): mixed {}

        /**
         * Create a new Cross-Origin-Resource-Policy builder.
         *
         * By default, the policy is set to `same-origin`, which restricts
         * resource sharing to the same origin that served the document.
         *
         * # Parameters
         * - `policy`: Optional directive string. If provided, must be one of:
         *   - `"same-origin"` — only same-origin requests allowed.
         *   - `"same-site"`   — allow same-site requests (including subdomains).
         *   - `"cross-origin"` — allow all cross-site requests.
         *
         * # Exceptions
         * - Throws an `Exception` if `policy` cannot be parsed into a valid directive.
         */
        public function __construct(?string $policy) {}
    }

    /**
     * Builder for `Cross-Origin-Opener-Policy` header.
     */
    class OpenerPolicy {
        /**
         * Use this if you need to change the policy after construction.
         * Calling this method will override any previous setting.
         *
         * # Parameters
         * - `policy`: Directive string. Must be one of the tokens listed above for `__construct`.
         *
         * # Exceptions
         * - Throws `Exception` if the given token is invalid.
         */
        public function set(string $policy): mixed {}

        /**
         * Build the header value.
         *
         * # Returns
         * - `string` the configured policy, e.g. `"same-origin"`.
         */
        public function build(): string {}

        /**
         * Send the `Cross-Origin-Opener-Policy` header via PHP `header()`.
         *
         * # Exceptions
         * - Throws `Exception` if the PHP `header()` function cannot be invoked.
         */
        public function send(): mixed {}

        /**
         * Create a new Cross-Origin-Opener-Policy builder.
         *
         * By default, this sets the policy to `"unsafe-none"`, which imposes
         * no special opener isolation. PHP users can call this without arguments
         * to get the default behavior.
         *
         * # Parameters
         * - `policy`: Optional string directive. If provided, must be one of:
         *   - `"unsafe-none"` — no isolation; pages can share a browsing context.
         *   - `"same-origin"` — only pages from the same origin can share.
         *   - `"same-origin-allow-popups"` — same-origin pages and their popups.
         *
         * # Exceptions
         * - Throws `Exception` if the provided token is not one of the allowed values.
         */
        public function __construct(?string $policy) {}
    }
}
