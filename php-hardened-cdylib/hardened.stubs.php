<?php

// Stubs for hardened

namespace Hardened {
    /**
     * Constant-time (timing-safe) comparison helpers.
     *
     * Comparing secrets (tokens, HMACs, signatures, API keys) with `==`/`===`
     * leaks how many leading bytes matched through timing. These helpers compare
     * in constant time with respect to the contents of the inputs.
     * Only the *length* of the inputs is observable.
     */
    class ConstantTime {
        public function __construct() {}

        /**
         * Compares two byte strings in constant time.
         *
         * Drop-in replacement for `hash_equals()` that does not care which
         * argument is the user-supplied one. Binary-safe.
         *
         * @param string $a
         * @param string $b
         * @return bool - `bool`: `true` if the strings are equal.
         */
        public static function equals(string $a, string $b): bool {}

        /**
         * Decodes two base64 strings and compares the decoded bytes in constant time.
         *
         * @param string $a
         * @param string $b
         * @return bool - `bool`: `true` if the decoded bytes are equal.
         */
        public static function equalsBase64(string $a, string $b): bool {}

        /**
         * Decodes two hex strings and compares the decoded bytes in constant time.
         *
         * Use this when comparing hex digests (e.g. `hash_hmac(..., false)`),
         * so that case differences (`"AB"` vs `"ab"`) do not cause a mismatch.
         *
         * @param string $a
         * @param string $b
         * @return bool - `bool`: `true` if the decoded bytes are equal.
         */
        public static function equalsHex(string $a, string $b): bool {}
    }

    /**
     * CSRF protection for your application.
     */
    class CsrfProtection {
        /**
         * Constructs a CSRF protection instance for PHP.
         *
         * @param string $key Base64URL-encoded 32-byte secret key.
         * @param int $ttl token time-to-live in seconds.
         * @param string|null $previous_token_value
         */
        public function __construct(string $key, int $ttl, ?string $previous_token_value = null) {}

        /**
         * Returns the CSRF cookie string to send in PHP.
         *
         * @return string - `string` Base64URL-encoded cookie suitable for `Set-Cookie`.
         */
        public function cookie(): string {}

        /**
         * Returns the configured CSRF cookie name.
         *
         * @return string - `string` the name of the CSRF cookie.
         */
        public function cookieName(): string {}

        /**
         * @return string
         */
        public static function generateKey(): string {}

        /**
         * Sends the CSRF cookie to the client via `setcookie()`
         *
         * @param ?int $expires UNIX timestamp when the cookie expires (defaults to `0`, a session cookie).
         * @param ?string $path Cookie path (defaults to `"/"`).
         * @param ?string $domain Cookie domain (defaults to the current host).
         * @param ?bool $secure Send only over HTTPS (defaults to `false`).
         * @param ?bool $httponly HTTP-only flag (defaults to `true`).
         * @return void
         */
        public function sendCookie(?int $expires = null, ?string $path = null, ?string $domain = null, ?bool $secure = null, ?bool $httponly = null): void {}

        /**
         * Sets the name of the CSRF cookie to use in PHP calls.
         *
         * @param string $cookie_name
         * @return void - `void`
         */
        public function setCookieName(string $cookie_name): void {}

        /**
         * Returns the CSRF token string for PHP forms or headers.
         *
         * @return string - `string` Base64URL-encoded token.
         */
        public function token(): string {}

        /**
         * Verifies a CSRF token & cookie pair from PHP.
         *
         * @param string $token Base64URL-encoded CSRF token from client.
         * @param string $cookie Base64URL-encoded CSRF cookie from client.
         * @return void - `void` on success.
         */
        public function verifyToken(string $token, ?string $cookie = null): void {}
    }

    /**
     * A secured wrapper around `url::Host` for use in PHP extensions.
     * Provides hostname parsing and normalization to prevent security issues.
     */
    class Hostname {
        /**
         * Constructs a new Hostname instance (alias for `from`).
         *
         * @param mixed $hostname
         * @throws \Exception Throws an exception if parsing the hostname fails.
         */
        public function __construct(mixed $hostname) {}

        /**
         * Returns the string representation of this hostname.
         *
         * @return string - `string`: The normalized hostname string.
         */
        public function __toString(): string {}

        /**
         * Compares this hostname with another string.
         *
         * @param mixed $hostname
         * @return bool
         * @throws \Exception Throws an exception if parsing the provided hostname fails.
         */
        public function equals(mixed $hostname): bool {}

        /**
         * Returns true if this hostname equals any in the given list.
         *
         * @param mixed $hostnames
         * @return bool
         * @throws \Exception Throws an exception if parsing any provided hostname fails.
         */
        public function equalsAny(mixed ...$hostnames): bool {}

        /**
         * Returns true if this hostname equals any hostname extracted from the given URLs.
         *
         * @param mixed $urls
         * @return bool
         * @throws \Exception Throws an exception if parsing any URL or hostname fails.
         */
        public function equalsAnyUrl(mixed ...$urls): bool {}

        /**
         * @param string $hostname
         * @return bool
         */
        public function equalsStr(string $hostname): bool {}

        /**
         * Compares this hostname with the hostname extracted from a URL.
         *
         * @param mixed $url
         * @return bool
         * @throws \Exception Throws an exception if parsing the URL or hostname fails.
         */
        public function equalsUrl(mixed $url): bool {}

        /**
         * Parses and normalizes a hostname string.
         *
         * @param mixed $hostname
         * @return \Hardened\Hostname
         * @throws \Exception Throws an exception if parsing the hostname fails.
         */
        public static function from(mixed $hostname): \Hardened\Hostname {}

        /**
         * @param string $hostname
         * @return \Hardened\Hostname
         */
        public static function fromStr(string $hostname): \Hardened\Hostname {}

        /**
         * Parses a URL and extracts its hostname.
         *
         * @param mixed $url
         * @return \Hardened\Hostname
         * @throws \Exception Throws an exception if parsing the URL or hostname fails.
         */
        public static function fromUrl(mixed $url): \Hardened\Hostname {}

        /**
         * Returns true if this hostname is a domain name (not an IP address).
         *
         * @return bool - `bool`: `true` if the hostname is a domain name.
         */
        public function isDomain(): bool {}

        /**
         * Returns true if this hostname is an IP address (either IPv4 or IPv6).
         *
         * @return bool - `bool`: `true` if the hostname is an IP address.
         */
        public function isIp(): bool {}

        /**
         * Returns true if this hostname is an IPv4 address.
         *
         * @return bool - `bool`: `true` if the hostname is an IPv4 address.
         */
        public function isIpv4(): bool {}

        /**
         * Returns true if this hostname is an IPv6 address.
         *
         * @return bool - `bool`: `true` if the hostname is an IPv6 address.
         */
        public function isIpv6(): bool {}

        /**
         * Checks if this hostname is a subdomain of the given hostname.
         *
         * @param mixed $hostname
         * @return bool
         * @throws \Exception Throws an exception if parsing the provided hostname fails.
         */
        public function subdomainOf(mixed $hostname): bool {}

        /**
         * Returns true if this hostname is a subdomain of any in the given list.
         *
         * @param mixed $hosts
         * @return bool
         * @throws \Exception Throws an exception if parsing any provided hostname fails.
         */
        public function subdomainOfAny(mixed ...$hosts): bool {}

        /**
         * Returns true if this hostname is a subdomain of any hostname extracted from the given URLs.
         *
         * @param array $urls
         * @return bool
         * @throws \Exception Throws an exception if parsing any URL or hostname fails.
         */
        public function subdomainOfAnyUrl(array $urls): bool {}

        /**
         * Checks if this hostname is a subdomain of the hostname extracted from a URL.
         *
         * @param string $url
         * @return bool
         * @throws \Exception Throws an exception if parsing the URL or hostname fails.
         */
        public function subdomainOfUrl(string $url): bool {}
    }

    class Path {
        /**
         * Constructs a new PathObj instance (alias for `from`).
         *
         * @param mixed $path
         */
        public function __construct(mixed $path) {}

        /**
         * Converts the path to its string representation.
         *
         * @return string The string representation of the path.
         * @throws \Exception Throws an exception if the path cannot be converted to a string.
         */
        public function __toString(): string {}

        /**
         * Returns the file extension, if any.
         *
         * @return string|null - `?string` The extension without the leading dot, or `null` if none.
         */
        public function extension(): ?string {}

        /**
         * Get the last component of the path.
         *
         * @return string|null
         */
        public function fileName(): ?string {}

        /**
         * Creates a new PathObj by lexically canonicalizing a given PHP value.
         *
         * @param mixed $path
         * @return \Hardened\Path
         */
        public static function from(mixed $path): \Hardened\Path {}

        /**
         * Get the directory name (similar to `dirname()`).
         *
         * @return \Hardened\Path|null
         */
        public function getParent(): ?\Hardened\Path {}

        /**
         * Returns true if the path tried to escape its base directory during normalization.
         *
         * This is useful for detecting directory traversal attempts.
         * A path "escapes" if it contains leading `..` components that would go above
         * the starting directory, or if it starts with a root/prefix.
         *
         * @return bool - `bool` `true` if the path escaped during normalization.
         */
        public function hasEscaped(): bool {}

        /**
         * Returns true if the path is absolute (starts with root or drive prefix).
         *
         * @return bool - `bool` `true` if the path is absolute.
         */
        public function isAbsolute(): bool {}

        /**
         * Returns true if the path is relative (not absolute).
         *
         * @return bool - `bool` `true` if the path is relative.
         */
        public function isRelative(): bool {}

        /**
         * Joins the given path onto this path and normalizes it.
         *
         * @param mixed $path
         * @return \Hardened\Path A new PathObj representing the joined path.
         */
        public function join(mixed $path): \Hardened\Path {}

        /**
         * Joins the given path onto this path, normalizes it, and ensures it's a subpath.
         *
         * @param mixed $path
         * @return \Hardened\Path
         */
        public function joinSubpath(mixed $path): \Hardened\Path {}

        /**
         * @return string
         */
        public function path(): string {}

        /**
         * Set the file name component of the path.
         *
         * @param string $extension
         * @return \Hardened\Path
         */
        public function setExtension(string $extension): \Hardened\Path {}

        /**
         * Set the file name component of the path.
         *
         * @param string $file_name
         * @return \Hardened\Path
         */
        public function setFileName(string $file_name): \Hardened\Path {}

        /**
         * Checks if this path starts with the given prefix path.
         *
         * @param mixed $path
         * @return bool `true` if this path starts with the given prefix.
         */
        public function startsWith(mixed $path): bool {}

        /**
         * Check if the path's extension is in the allowed list.
         *
         * @param array $allowed
         * @return bool - `bool` `true` if the file extension matches one of the allowed values.
         */
        public function validateExtension(array $allowed): bool {}

        /**
         * Check if the path's extension is a common audio type.
         *
         * @return bool - `bool` `true` if extension is one of `["mp3","wav","ogg","flac","aac"]`.
         */
        public function validateExtensionAudio(): bool {}

        /**
         * Check if the path's extension is a common document type.
         *
         * @return bool - `bool` `true` if extension is one of `["pdf","doc","docx","xls","xlsx","ppt","pptx"]`.
         */
        public function validateExtensionDocument(): bool {}

        /**
         * Check if the path's extension is a common image type.
         *
         * @return bool - `bool` `true` if extension is one of `["png","jpg","jpeg","gif","webp","bmp","tiff","svg"]`.
         */
        public function validateExtensionImage(): bool {}

        /**
         * Check if the path's extension is a common video type.
         *
         * @return bool - `bool` `true` if extension is one of `["mp4","mov","avi","mkv","webm","flv"]`.
         */
        public function validateExtensionVideo(): bool {}
    }

    /**
     * Open-redirect validator.
     *
     * Validates untrusted redirect targets (`?next=`, `?return_to=`, …) the way
     * a browser will actually interpret them (WHATWG URL parsing), which defeats
     * the classic bypasses: scheme-relative `//evil.com`, backslash tricks
     * `/\evil.com` and `\/\/evil.com`, missing-slash `https:/evil.com`, userinfo
     * `https://trusted@evil.com`, embedded whitespace/control bytes, and
     * percent- or unicode-encoded host variants.
     *
     * A URL is considered safe if it is a same-origin relative reference, or an
     * absolute `http(s)` URL whose host matches the allowlist.
     */
    class Redirect {
        /**
         * Constructs a redirect validator.
         *
         * @param array $allowed_hosts
         * @param bool|null $allow_subdomains
         */
        public function __construct(array $allowed_hosts, ?bool $allow_subdomains = null) {}

        /**
         * Checks whether a redirect target is safe.
         *
         * Safe means: a same-origin relative reference, or an absolute
         * `http(s)` URL without userinfo whose host matches the allowlist.
         *
         * @param string $url
         * @return bool - `bool`: `true` if the target is safe to redirect to.
         */
        public function isSafe(string $url): bool {}

        /**
         * Checks whether a redirect target is safe (static convenience).
         *
         * @param string $url
         * @param array $allowed_hosts
         * @param bool|null $allow_subdomains
         * @return bool - `bool`: `true` if the target is safe to redirect to.
         */
        public static function isSafeUrl(string $url, array $allowed_hosts, ?bool $allow_subdomains = null): bool {}

        /**
         * Returns the redirect target if it is safe, or the fallback otherwise.
         *
         * @param string $url
         * @param string|null $fallback
         * @return string - `string`: `url` if safe, `fallback` otherwise.
         */
        public function sanitize(string $url, ?string $fallback = null): string {}

        /**
         * Returns the redirect target if it is safe, or the fallback otherwise
         * (static convenience).
         *
         * @param string $url
         * @param array $allowed_hosts
         * @param string|null $fallback
         * @param bool|null $allow_subdomains
         * @return string - `string`: `url` if safe, `fallback` otherwise.
         */
        public static function sanitizeUrl(string $url, array $allowed_hosts, ?string $fallback = null, ?bool $allow_subdomains = null): string {}
    }

    class Rng {
        public function __construct() {}

        /**
         * Generate a random ASCII alphabetic string of the specified length.
         *
         * @param int $len
         * @return string - `String` containing random ASCII alphabetic characters.
         */
        public static function alphabetic(int $len): string {}

        /**
         * Generate a random ASCII alphanumeric string of the specified length.
         *
         * @param int $len
         * @return string - `String` containing random ASCII alphanumeric characters.
         */
        public static function alphanumeric(int $len): string {}

        /**
         * Generate a sequence of random bytes of the specified length.
         *
         * @param int $len
         * @return string - `string` containing `len` random bytes.
         */
        public static function bytes(int $len): string {}

        /**
         * Randomly selects one element from the given list.
         *
         * @param array $choices
         * @return mixed - `mixed|null`: A randomly chosen element, or `null` if `choices` is empty.
         */
        public static function choose(array $choices): mixed {}

        /**
         * Randomly selects exactly `amount` distinct elements without replacement.
         *
         * @param int $amount
         * @param array $choices
         * @return array - `mixed[]`: Array of selected values.
         */
        public static function chooseMultiple(int $amount, array $choices): array {}

        /**
         * Randomly selects `amount` elements from weighted choices without replacement.
         *
         * @param int $amount
         * @param array $choices
         * @return array - `mixed[]`: Array of selected values.
         */
        public static function chooseMultipleWeighted(int $amount, array $choices): array {}

        /**
         * Randomly selects one element from weighted choices.
         *
         * @param array $choices
         * @return array - `array{0: mixed, 1: int}` Two‐element array: the chosen value and its weight.
         */
        public static function chooseWeighted(array $choices): array {}

        /**
         * Sample random ASCII characters from the specified character set.
         *
         * @param int $len
         * @param string $chars
         * @return string - `String` of length `len`, or an empty string if `chars` is empty.
         */
        public static function customAscii(int $len, string $chars): string {}

        /**
         * Sample random Unicode characters (code points) from the given string.
         *
         * @param int $len
         * @param string $chars
         * @return string - `string` of length `len`, or an empty string if `chars` is empty.
         */
        public static function customUnicodeChars(int $len, string $chars): string {}

        /**
         * Sample random Unicode grapheme clusters from the given string.
         *
         * @param int $len
         * @param string $chars
         * @return string - `string` of length `len`, or an empty string if `chars` is empty.
         */
        public static function customUnicodeGraphemes(int $len, string $chars): string {}

        /**
         * Generate a single random integer in the inclusive range `[low, high]`.
         *
         * @param int $low
         * @param int $high
         * @return int - `int` — random value within bounds
         */
        public static function int(int $low, int $high): int {}

        /**
         * Generate a vector of random integers in the inclusive range `[low, high]`.
         *
         * @param int $n
         * @param int $low
         * @param int $high
         * @return array - `array[int; n]` — array of random values within bounds
         */
        public static function ints(int $n, int $low, int $high): array {}
    }

    /**
     * Safe subprocess launcher.
     *
     * Allows you to build up a command invocation with arguments, optionally configure
     * a timeout (seconds), and execute it without shell interpolation.
     * Returns exit codes or captures stdout/stderr.
     */
    class ShellCommand {
        /**
         * Constructs a new ShellCommand for the given program path.
         *
         * @param string $executable Path to the executable or command name.
         * @param array|null $arguments
         */
        public function __construct(string $executable, ?array $arguments = null) {}

        /**
         * Constructs a new ShellCommand for the given program path.
         *
         * @param string $executable Path to the executable or command name.
         * @return \Hardened\ShellCommand
         */
        public static function executable(string $executable): \Hardened\ShellCommand {}

        /**
         * Silently ignore both stdout and stderr.
         *
         * @return \Hardened\ShellCommand
         */
        public function ignoreBoth(): \Hardened\ShellCommand {}

        /**
         * Silently ignore stderr.
         *
         * @return \Hardened\ShellCommand
         */
        public function ignoreStderr(): \Hardened\ShellCommand {}

        /**
         * Silently ignore stdout.
         *
         * @return \Hardened\ShellCommand
         */
        public function ignoreStdout(): \Hardened\ShellCommand {}

        /**
         * Inherit _all_ parent environment variables.
         *
         * @return \Hardened\ShellCommand
         */
        public function inheritAllEnvs(): \Hardened\ShellCommand {}

        /**
         * Inherit only the specified environment variable names.
         *
         * @param array $envs
         * @return \Hardened\ShellCommand
         */
        public function inheritEnvs(array $envs): \Hardened\ShellCommand {}

        /**
         * Adds one argument to the command line.
         *
         * @param string $arg A single argument (will not be interpreted by a shell).
         * @return \Hardened\ShellCommand
         */
        public function passArg(string $arg): \Hardened\ShellCommand {}

        /**
         * Join numeric or flag-style arguments from a PHP table.
         *
         * Numeric keys => positional args; string keys => `--key value`.
         *
         * @param array $arguments
         * @return \Hardened\ShellCommand
         */
        public function passArgs(array $arguments): \Hardened\ShellCommand {}

        /**
         * Pass a single environment variable to the child.
         *
         * @param string $key
         * @param string $value
         * @return \Hardened\ShellCommand
         */
        public function passEnv(string $key, string $value): \Hardened\ShellCommand {}

        /**
         * Replace the child-process environment with exactly the given map.
         *
         * @param array $map
         * @return \Hardened\ShellCommand
         */
        public function passEnvOnly(array $map): \Hardened\ShellCommand {}

        /**
         * Merge in additional environment variables for the child process.
         *
         * Existing passed-env map is extended.
         *
         * @param array $map
         * @return \Hardened\ShellCommand
         */
        public function passEnvs(array $map): \Hardened\ShellCommand {}

        /**
         * Enable passthrough mode for both stdout and stderr:
         * PHP will receive all child-process output directly.
         *
         * @return \Hardened\ShellCommand
         */
        public function passthroughBoth(): \Hardened\ShellCommand {}

        /**
         * Enable passthrough mode for stderr only.
         *
         * @return \Hardened\ShellCommand
         */
        public function passthroughStderr(): \Hardened\ShellCommand {}

        /**
         * Enable passthrough mode for stdout only.
         *
         * @return \Hardened\ShellCommand
         */
        public function passthroughStdout(): \Hardened\ShellCommand {}

        /**
         * Pipe both stdout and stderr through a PHP callable.
         *
         * The callable will be invoked for each chunk of output.
         *
         * @param mixed $callable
         * @return \Hardened\ShellCommand
         */
        public function pipeCallbackBoth(mixed $callable): \Hardened\ShellCommand {}

        /**
         * Pipe stderr through a PHP callable.
         *
         * @param mixed $callable
         * @return \Hardened\ShellCommand
         */
        public function pipeCallbackStderr(mixed $callable): \Hardened\ShellCommand {}

        /**
         * Pipe stdout through a PHP callable.
         *
         * @param mixed $callable
         * @return \Hardened\ShellCommand
         */
        public function pipeCallbackStdout(mixed $callable): \Hardened\ShellCommand {}

        /**
         * Runs the command, streaming stdout/stderr live (according to configured pipe modes),
         * enforces the configured timeout, and optionally captures output into PHP variables.
         *
         * @param ?string $capture_stdout
         * @param ?string $capture_stderr
         * @return int - `int` The process's exit code (`0` on success, `-1` if killed by signal or timed out).
         */
        public function run(?string $capture_stdout = null, ?string $capture_stderr = null): int {}

        /**
         * @param string $command_line
         * @return \Hardened\ShellCommand - `ShellCommand`
         */
        public static function safeFromString(string $command_line): \Hardened\ShellCommand {}

        /**
         * Sets an execution timeout in seconds.
         *
         * @param int $seconds Maximum time to wait before killing the process.
         * @return \Hardened\ShellCommand
         */
        public function setTimeout(int $seconds): \Hardened\ShellCommand {}

        /**
         * Sets an execution timeout in milliseconds.
         *
         * @param int $milliseconds Maximum time to wait before killing the process.
         * @return \Hardened\ShellCommand
         */
        public function setTimeoutMs(int $milliseconds): \Hardened\ShellCommand {}

        /**
         * Constructs a new `ShellCommand` using the user's login shell.
         *
         * Looks up the `SHELL` environment variable, or falls back to `/bin/sh` if unset.
         *
         * @return \Hardened\ShellCommand - `ShellCommand`: with `executable` set to the shell path and no arguments.
         */
        public static function shell(): \Hardened\ShellCommand {}

        /**
         * Exactly like `shell_exec()`: pass the *raw* string to `/bin/sh -c`
         * and record the top-level command names.
         *
         * @param string $cmdline
         * @return \Hardened\ShellCommand - `ShellCommand`
         */
        public static function shellFromString(string $cmdline): \Hardened\ShellCommand {}

        /**
         * Returns the list of top-level command names parsed from the original shell line.
         *
         * @return array|null - `Option<Vec<String>>`: - `Some(vec)` when `shell_from_string()` was used and top-level commands were recorded; - `None` otherwise.
         */
        public function topLevelCommands(): ?array {}
    }

    /**
     * SSRF guard: outbound network policy for URLs built from untrusted input.
     *
     * Implements resolve-then-validate: the hostname is resolved once, every
     * resolved address is checked against the policy, and the validated
     * addresses are returned so the caller can *pin* the connection to them
     * (e.g. via curl's `CURLOPT_RESOLVE`). Re-resolving at connect time would
     * allow a DNS-rebinding TOCTOU; pinning closes it.
     *
     * By default only `http`/`https` on ports 80/443 are allowed, and loopback,
     * private (RFC 1918), link-local (incl. the 169.254.169.254 cloud metadata
     * endpoint), CGNAT, unique-local, multicast, broadcast and other reserved
     * ranges are denied — for both address families, including IPv4-mapped IPv6.
     *
     * When following redirects, disable automatic following and validate every
     * hop with this guard.
     */
    class SsrfGuard {
        /**
         * Constructs an SSRF guard with secure defaults: schemes `http`/`https`,
         * ports 80/443, and all reserved/private/metadata ranges denied.
         */
        public function __construct() {}

        /**
         * Adds an allowed CIDR range (or single IP), overriding the built-in
         * reserved-range denylist — but not explicit `denyCidr()` entries.
         *
         * Use this to deliberately permit, say, one internal service:
         * `$guard->allowCidr("10.0.5.20")`.
         *
         * @param string $cidr
         * @return void
         */
        public function allowCidr(string $cidr): void {}

        /**
         * Validates a URL and returns a ready-made `CURLOPT_RESOLVE` entry
         * (`"host:port:ip1,ip2"`) pinning curl to the validated addresses.
         *
         * ```php
         * $entry = $guard->curlResolve($url);
         * curl_setopt($ch, CURLOPT_RESOLVE, [$entry]);
         * curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // validate each hop!
         * ```
         *
         * @param string $url
         * @return string - `string`: A `CURLOPT_RESOLVE` entry for the validated addresses.
         */
        public function curlResolve(string $url): string {}

        /**
         * Adds a denied CIDR range (or single IP). Deny entries take precedence
         * over everything else.
         *
         * @param string $cidr
         * @return void
         */
        public function denyCidr(string $cidr): void {}

        /**
         * Checks a single IP address against the policy.
         *
         * @param string $ip
         * @return bool - `bool`: `true` if the address is allowed.
         */
        public function isIpAllowed(string $ip): bool {}

        /**
         * Replaces the set of allowed ports.
         *
         * @param array $ports
         * @return void
         */
        public function setAllowedPorts(array $ports): void {}

        /**
         * Replaces the set of allowed URL schemes.
         *
         * @param array $schemes
         * @return void
         */
        public function setAllowedSchemes(array $schemes): void {}

        /**
         * Enables or disables the built-in reserved-range denylist (loopback,
         * private, link-local/metadata, CGNAT, unique-local, multicast, …).
         * Enabled by default; disable only if you fully manage policy via
         * `allowCidr()`/`denyCidr()`.
         *
         * @param bool $block
         * @return void
         */
        public function setBlockReservedRanges(bool $block): void {}

        /**
         * Validates a URL against the policy: scheme, port, no userinfo, and
         * every address the host resolves to. Resolution happens exactly once.
         *
         * Connect to one of the returned addresses (e.g. via `curlResolve()`)
         * instead of re-resolving the hostname, otherwise a DNS-rebinding
         * attacker can serve a public address during validation and a private
         * one at connect time.
         *
         * @param string $url
         * @return array - `string[]`: The validated resolved IP addresses.
         */
        public function validateUrl(string $url): array {}
    }

    /**
     * Control-character and protocol-injection sanitizers.
     *
     * Untrusted strings carrying control bytes are a recurring injection vector:
     * CR/LF in HTTP/SMTP headers (response splitting, header injection), CR/LF in
     * log lines (log forging), null bytes in paths (truncation), and field
     * separators (`0x00`, `0x01`, …) in delimited backend protocols. These
     * helpers strip or reject such bytes. All methods are binary-safe.
     */
    class Text {
        public function __construct() {}

        /**
         * Asserts that a string contains no null bytes.
         *
         * Null bytes in filenames and paths cause truncation in C APIs and are
         * a classic path/filename bypass. Returns the input unchanged if clean.
         *
         * @param string $input
         * @return string - `string`: The input, unchanged.
         */
        public static function assertNoNullBytes(string $input): string {}

        /**
         * Checks whether a string contains control characters.
         *
         * Detects C0 controls (`0x00`–`0x1f`), DEL (`0x7f`), and UTF-8 encoded C1
         * controls (U+0080–U+009F), except the bytes listed in `keep`.
         *
         * @param string $input
         * @param string|null $keep
         * @return bool - `bool`: `true` if any control character is present.
         */
        public static function hasControls(string $input, ?string $keep = null): bool {}

        /**
         * Checks whether a string contains a null byte.
         *
         * @param string $input
         * @return bool - `bool`: `true` if a null byte is present.
         */
        public static function hasNullBytes(string $input): bool {}

        /**
         * Validates and sanitizes a string for use as an HTTP (or SMTP) header value.
         *
         * Throws if the value contains CR, LF or NUL (response splitting /
         * header injection); strips all other control characters except
         * horizontal tab, which is legal in header values per RFC 7230.
         *
         * @param string $input
         * @return string - `string`: The sanitized header value.
         */
        public static function sanitizeHeaderValue(string $input): string {}

        /**
         * Sanitizes a string for safe inclusion in a log line.
         *
         * Strips CR, LF and all other control characters (C0, DEL, UTF-8 C1)
         * except horizontal tab, preventing log forging via injected line breaks
         * or terminal escape sequences.
         *
         * @param string $input
         * @return string - `string`: The sanitized string, safe to embed in a single log line.
         */
        public static function sanitizeLogLine(string $input): string {}

        /**
         * Removes control characters from a string.
         *
         * Strips C0 controls (`0x00`–`0x1f`), DEL (`0x7f`), and UTF-8 encoded C1
         * controls (U+0080–U+009F), except the bytes listed in `keep`.
         *
         * @param string $input
         * @param string|null $keep
         * @return string - `string`: The sanitized string.
         */
        public static function stripControls(string $input, ?string $keep = null): string {}
    }

    /**
     * Execute a command directly (no shell), with arguments passed explicitly.
     *
     * Unlike `shell_exec()`, this function does NOT parse the executable string.
     * The executable is used as-is, and all arguments must be passed via the array.
     * This prevents any shell injection vulnerabilities.
     *
     * @param string $executable
     * @param array|null $arguments
     * @return mixed - `string|null`: On success, returns captured stdout as a string (or exit code as string if non-zero). Returns `null` only on error spawning the process.
     */
    function safe_exec(string $executable, ?array $arguments = null): mixed {}

    /**
     * Execute a shell command via the user's login shell, enforcing top-level command checks.
     *
     * @param string $command
     * @param array|null $expected_commands
     * @return mixed - `string|null`: On success, returns the command's stdout output as a string (or exit code as string if non-zero). Returns `null` only on error spawning the process.
     */
    function shell_exec(string $command, ?array $expected_commands = null): mixed {}
}

namespace Hardened\Sanitizers {
    /**
     * PHP class wrapping Ammonia's HTML sanitizer builder.
     * Allows customized sanitization through PHP method calls.
     */
    class HtmlSanitizer {
        /**
         * Constructs a sanitizer with default configuration.
         */
        public function __construct() {}

        /**
         * Adds allowed CSS classes for a specific tag.
         *
         * @param string $tag
         * @param array $classes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function addAllowedClasses(string $tag, array $classes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Add additional blacklisted clean-content tags without overwriting old ones.
         *
         * Does nothing if the tag is already there.
         *
         * @param array $tags
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function addCleanContentTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds prefixes for generic attributes.
         *
         * @param array $prefixes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function addGenericAttributePrefixes(array $prefixes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds generic attributes to all tags.
         *
         * @param array $attributes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function addGenericAttributes(array $attributes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds tag attribute values.
         *
         * @param string $tag
         * @param string $attr
         * @param array $values
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function addTagAttributeValues(string $tag, string $attr, array $values): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds allowed attributes to a specific tag.
         *
         * @param string $tag
         * @param array $attributes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function addTagAttributes(string $tag, array $attributes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Adds additional allowed tags to the existing whitelist.
         *
         * @param array $tags
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function addTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Sets the attribute filter callback.
         *
         * @param mixed $callable
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function attributeFilter(mixed $callable): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Sanitizes the given HTML string, applying any configured attribute filter.
         *
         * @param string $html
         * @return string - `String` The sanitized HTML.
         */
        public function clean(string $html): string {}

        /**
         * Sanitize and truncate the given HTML by extended grapheme clusters.
         *
         * This is a convenience wrapper that ensures no user-perceived character
         * (including complex emoji or combined sequences) is split in half.
         *
         * @param string $html
         * @param int $max
         * @param array $flags
         * @param string|null $etc
         * @return string
         */
        public function cleanAndTruncate(string $html, int $max, array $flags, ?string $etc = null): string {}

        /**
         * Sets the tags whose contents will be completely removed from the output.
         *
         * @param array $tags
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function cleanContentTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Gets all configured clean-content tags.
         *
         * @return array - `Vec<String>` The list of tags whose content is preserved.
         */
        public function cloneCleanContentTags(): array {}

        /**
         * Returns the configured tags as a vector of strings.
         *
         * @return array - `Vec<String>` The list of allowed tag names.
         */
        public function cloneTags(): array {}

        /**
         * @param array $props
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function filterStyleProperties(array $props): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Bulk overwrites generic attribute prefixes.
         *
         * @param array $prefixes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function genericAttributePrefixes(array $prefixes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Bulk overwrites generic attributes.
         *
         * @param array $attrs
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function genericAttributes(array $attrs): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Gets a single tag attribute value setting.
         *
         * @param string $tag
         * @param string $attr
         * @return string|null - `Option<String>` The configured value or `None` if unset.
         */
        public function getSetTagAttributeValue(string $tag, string $attr): ?string {}

        /**
         * Prefixes all `id` attributes with the given string.
         *
         * @param string|null $prefix
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function idPrefix(?string $prefix = null): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Checks if URL relative policy is custom (Rewrite).
         *
         * @return bool - `bool` `true` if a custom rewrite policy is set.
         */
        public function isUrlRelativeCustom(): bool {}

        /**
         * Checks if URL relative policy is Deny.
         *
         * @return bool - `bool` `true` if the policy is Deny.
         */
        public function isUrlRelativeDeny(): bool {}

        /**
         * Checks if URL relative policy is PassThrough.
         *
         * @return bool - `bool` `true` if the policy is PassThrough.
         */
        public function isUrlRelativePassThrough(): bool {}

        /**
         * Checks whether a URL is valid according to the sanitizer’s configured
         * URL scheme whitelist and relative-URL policy.
         *
         * @param string $url
         * @return bool - `bool`: `true` if the URL’s scheme is whitelisted, or if it is a relative URL and relative URLs are permitted; `false` otherwise.
         */
        public function isValidUrl(string $url): bool {}

        /**
         * Sets the `rel` attribute for generated `<a>` tags.
         *
         * @param string|null $value
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function linkRel(?string $value = null): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Constructs a sanitizer with default configuration.
         *
         * @return \Hardened\Sanitizers\HtmlSanitizer - HtmlSanitizer A new sanitizer instance.
         */
        public static function newDefault(): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Filters CSS style properties allowed in `style` attributes.
         *
         * @param array $props
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function newFilterStyleProperties(array $props): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes allowed CSS classes from a specific tag.
         *
         * @param string $tag
         * @param array $classes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function rmAllowedClasses(string $tag, array $classes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Remove already-blacklisted clean-content tags.
         *
         * Does nothing if the tags aren’t blacklisted.
         *
         * @param array $tags
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function rmCleanContentTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes prefixes for generic attributes.
         *
         * @param array $prefixes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function rmGenericAttributePrefixes(array $prefixes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes generic attributes from all tags.
         *
         * @param array $attributes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function rmGenericAttributes(array $attributes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes tag attribute values.
         *
         * @param string $tag
         * @param string $attr
         * @param array $values
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function rmTagAttributeValues(string $tag, string $attr, array $values): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes attributes from a specific tag.
         *
         * @param string $tag
         * @param array $classes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function rmTagAttributes(string $tag, array $classes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Removes tags from the whitelist.
         *
         * @param array $tags
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function rmTags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Sets a single tag attribute value.
         *
         * @param string $tag
         * @param string $attribute
         * @param string $value
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function setTagAttributeValue(string $tag, string $attribute, string $value): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Enables or disables HTML comment stripping.
         *
         * @param true $strip to strip comments; `false` to preserve them.
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function stripComments(bool $strip): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Overwrites the set of allowed tags.
         *
         * @param array $tags
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function tags(array $tags): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Denies all relative URLs in attributes.
         *
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function urlRelativeDeny(): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Passes through relative URLs unchanged.
         *
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function urlRelativePassthrough(): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Rewrites relative URLs using the given base URL.
         *
         * @param string $base_url
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function urlRelativeRewriteWithBase(string $base_url): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Rewrites relative URLs using a root URL and path prefix.
         *
         * @param string $root
         * @param string $path
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function urlRelativeRewriteWithRoot(string $root, string $path): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Whitelists URL schemes (e.g., "http", "https").
         *
         * @param array $schemes
         * @return \Hardened\Sanitizers\HtmlSanitizer
         */
        public function urlSchemes(array $schemes): \Hardened\Sanitizers\HtmlSanitizer {}

        /**
         * Returns whether HTML comments will be stripped.
         *
         * @return bool - `bool`: `true` if comments will be stripped; `false` otherwise.
         */
        public function willStripComments(): bool {}
    }

    enum HtmlSanitizerFlag: string {
      case ExtendedGraphemes = 'extended-graphemes';
      case Graphemes = 'graphemes';
      case Unicode = 'unicode';
      case Ascii = 'ascii';
      case PreserveWords = 'preserve-words';
    }

    class SvgSanitizer {
        const PRESET_PERMISSIVE = 'permissive';

        const PRESET_STANDARD = 'standard';

        const PRESET_STRICT = 'strict';

        public function __construct() {}

        /**
         * Add attributes to the allowlist
         *
         * @param array $attributes
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function addAllowedAttributes(array $attributes): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Add elements to the allowlist
         *
         * @param array $elements
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function addAllowedElements(array $elements): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Set allowed attributes (overwrites defaults)
         *
         * @param array $attributes
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function allowAttributes(array $attributes): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Set allowed SVG elements (overwrites defaults)
         *
         * @param array $elements
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function allowElements(array $elements): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Allow relative URLs
         *
         * @param bool $allow
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function allowRelativeUrls(bool $allow): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Enable/disable blocking of data: URIs
         *
         * @param bool $block
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function blockDataUris(bool $block): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Enable/disable blocking of external references (http/https URLs)
         *
         * @param bool $block
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function blockExternalReferences(bool $block): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Sanitize SVG content string
         *
         * @param string $svg
         * @return string
         */
        public function clean(string $svg): string {}

        /**
         * Sanitize SVG file and return cleaned content
         *
         * @param string $path
         * @return string
         */
        public function cleanFile(string $path): string {}

        /**
         * Static method for file-based bomb detection (throws on dangerous SVG)
         *
         * @param string $path
         * @param int|null $max_dimension
         * @return void
         */
        public static function defuse(string $path, ?int $max_dimension = null): void {}

        /**
         * Check if SVG content is safe without modification
         *
         * @param string $svg
         * @return bool
         */
        public function isSafe(string $svg): bool {}

        /**
         * Check if SVG file is safe without modification
         *
         * @param string $path
         * @return bool
         */
        public function isSafeFile(string $path): bool {}

        /**
         * Create a new SvgSanitizer with default (standard) settings
         *
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public static function newDefault(): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Remove attributes from the allowlist
         *
         * @param array $attributes
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function removeAttributes(array $attributes): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Remove elements from the allowlist
         *
         * @param array $elements
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function removeElements(array $elements): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Set maximum allowed dimension (width/height/viewBox)
         *
         * @param int $max
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function setMaxDimension(int $max): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Set maximum nesting depth
         *
         * @param int $max
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function setMaxNestingDepth(int $max): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Enable/disable XML comments removal
         *
         * @param bool $strip
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public function stripComments(bool $strip): \Hardened\Sanitizers\SvgSanitizer {}

        /**
         * Create a sanitizer with a named preset
         *
         * @param string $preset_name
         * @return \Hardened\Sanitizers\SvgSanitizer
         */
        public static function withPreset(string $preset_name): \Hardened\Sanitizers\SvgSanitizer {}
    }
}

namespace Hardened\Sanitizers\File {
    /**
     * Archive bomb detector for ZIP and RAR files.
     *
     * Provides two methods in PHP:
     *   - `scan_zip(string $path): bool`
     *   - `scan_rar(string $path, ?int $maxRatio = 1000): bool`
     */
    class ArchiveSanitizer {
        public function __construct() {}

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
         * @param string $path
         * @param int|null $max_ratio
         * @return void
         */
        public static function defuse(string $path, ?int $max_ratio = null): void {}
    }

    /**
     * Header-only image hardening: inspect untrusted image uploads without ever
     * invoking an image decoder.
     *
     * `getimagesize()` is header-based, but `imagecreatefromstring()` and friends
     * run the full C codec (libjpeg/libpng/libgd) on attacker bytes with no
     * sandbox. This class reads only headers and container structure, so
     * dimension checks (decompression-bomb guards), format/extension/MIME
     * verification, polyglot detection, and metadata stripping all happen
     * *before* any decoder sees the file.
     */
    class ImageSanitizer {
        /**
         * Constructs a sanitizer over raw image bytes.
         *
         * @param string $data
         */
        public function __construct(string $data) {}

        /**
         * Asserts that the header-declared dimensions do not exceed the limits.
         * Use before handing the bytes to any real decoder.
         *
         * @param int $max_width
         * @param int $max_height
         * @return void
         */
        public function assertDimensionsWithin(int $max_width, int $max_height): void {}

        /**
         * Asserts that the byte stream contains no active-content markers.
         *
         * @return void
         */
        public function assertNotPolyglot(): void {}

        /**
         * Asserts that the header-declared pixel count (width × height) does not
         * exceed the limit. Catches extreme aspect ratios (e.g. 1×1000000000)
         * that per-side limits miss.
         *
         * @param int $max_pixels
         * @return void
         */
        public function assertPixelsWithin(int $max_pixels): void {}

        /**
         * Reads the image dimensions from the header only — the pixel decoder is
         * never invoked, so decompression bombs cannot trigger.
         *
         * @return array - `array{0: int, 1: int}`: `[width, height]` in pixels.
         */
        public function dimensions(): array {}

        /**
         * Detects the image format from magic bytes (never trusts the extension
         * or a declared MIME type).
         *
         * @return string|null - `string|null`: One of `"jpeg"`, `"png"`, `"gif"`, `"webp"`, `"bmp"`, `"tiff"`, `"ico"`, `"avif"`, `"heif"`, `"jxl"`, `"psd"`, `"qoi"`, `"tga"`, or `null` if not a recognized image.
         */
        public function format(): ?string {}

        /**
         * Constructs a sanitizer over raw image bytes (alias for the constructor).
         *
         * @param string $data
         * @return \Hardened\Sanitizers\File\ImageSanitizer
         */
        public static function fromBytes(string $data): \Hardened\Sanitizers\File\ImageSanitizer {}

        /**
         * Constructs a sanitizer by reading a file.
         *
         * @param string $path
         * @return \Hardened\Sanitizers\File\ImageSanitizer
         */
        public static function fromFile(string $path): \Hardened\Sanitizers\File\ImageSanitizer {}

        /**
         * Scans the entire byte stream for active-content markers (`<?php`,
         * `<script`, `<html`, `<svg`, …) that turn a valid image into a
         * polyglot — content-sniffing XSS or upload-RCE when the file is ever
         * served inline or executed.
         *
         * @return bool - `bool`: `true` if a marker is present.
         */
        public function isPolyglot(): bool {}

        /**
         * Checks whether the magic-byte format matches the file extension.
         * Catches `shell.php` uploaded as `image/png`, double extensions whose
         * final extension lies, and renamed files.
         *
         * @param string $filename
         * @return bool - `bool`: `true` if the extension belongs to the detected format.
         */
        public function matchesExtension(string $filename): bool {}

        /**
         * Checks whether the magic-byte format matches a declared MIME type
         * (e.g. the `Content-Type` of an upload — which is attacker-controlled).
         *
         * @param string $mime
         * @return bool - `bool`: `true` if the declared type matches the detected format.
         */
        public function matchesMime(string $mime): bool {}

        /**
         * Returns the canonical MIME type for the detected format.
         *
         * @return string|null - `string|null`: e.g. `"image/jpeg"`, or `null` if the format is unrecognized.
         */
        public function mime(): ?string {}

        /**
         * Returns a copy of the image with metadata stripped, without decoding
         * pixel data:
         * - **JPEG**: drops APP1–APP15 (EXIF incl. GPS, XMP, IPTC) and COM
         *   comments; keeps JFIF, Adobe and ICC-profile segments.
         * - **PNG**: drops `eXIf`, `tEXt`, `zTXt`, `iTXt` chunks.
         * - **WebP**: drops `EXIF` and `XMP` chunks, fixing the RIFF size and
         *   VP8X feature flags.
         *
         * @return string - `string`: The sanitized image bytes.
         */
        public function stripMetadata(): string {}
    }

    /**
     * Engine for detecting "PNG bombs" (images with unreasonable dimensions).
     */
    class PngSanitizer {
        public function __construct() {}

        /**
         * Scan a file at the given path and detect PNG bombs.
         *
         * @param string $path Filesystem path to the PNG file.
         * @return void - `bool` `true` if the file is a PNG *and* has width or height > 10000, or if it's invalid PNG with missing IHDR. Returns `false` if it's not a PNG or has acceptable dimensions.
         */
        public static function defuse(string $path): void {}
    }
}

namespace Hardened\SecurityHeaders {
    /**
     * Your application's CSP config.
     */
    class ContentSecurityPolicy {
        /**
         * Constructs a new `ContentSecurityPolicy` builder with no directives set.
         */
        public function __construct() {}

        /**
         * Builds the `Content-Security-Policy` header value from the configured directives.
         *
         * @return string - `String` The full header value, for example: `"default-src 'self'; script-src 'self' 'nonce-ABCD1234' example.com; …"`.
         */
        public function build(): string {}

        /**
         * Returns the most recently generated nonce, if any.
         *
         * @return string|null - `Option<&str>` The raw nonce string (without the `'nonce-'` prefix), or `None` if `build()` has not yet generated one.
         */
        public function getNonce(): ?string {}

        /**
         * Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.
         *
         * @return void
         */
        public function resetNonce(): void {}

        /**
         * Send the `Content-Security-Policy` header via PHP `header()`.
         *
         * @return void
         */
        public function send(): void {}

        /**
         * Sets or replaces a CSP directive with the given keywords and host sources.
         *
         * @param \Hardened\SecurityHeaders\CspRule $rule
         * @param array $keywords
         * @param array|null $sources
         * @return void
         */
        public function setRule(\Hardened\SecurityHeaders\CspRule $rule, array $keywords, ?array $sources = null): void {}
    }

    /**
     * Values for the `X-Permitted-Cross-Domain-Policies` header.
     */
    enum CrossDomainPolicy: string {
      case None = 'none';
      case MasterOnly = 'master-only';
      case ByContentType = 'by-content-type';
      case All = 'all';
    }

    /**
     * All valid source keywords for CSP directives.
     *
     * These include host-independent keywords, nonce placeholders, resource-type tokens,
     * and sandbox flags that can appear after a directive name.
     */
    enum CspKeyword: string {
    /**
     * The `'self'` keyword, allowing the same origin.
     */
      case SelfOrigin = 'self';
    /**
     * The `'unsafe-inline'` keyword, allowing inline scripts or styles.
     */
      case UnsafeInline = 'unsafe-inline';
    /**
     * The `'unsafe-eval'` keyword, allowing `eval()` and similar.
     */
      case UnsafeEval = 'unsafe-eval';
    /**
     * The `'unsafe-hashes'` keyword, allowing hash-based inline resources.
     */
      case UnsafeHashes = 'unsafe-hashes';
    /**
     * The `'strict-dynamic'` keyword, enabling strict dynamic loading.
     */
      case StrictDynamic = 'strict-dynamic';
    /**
     * The `'nonce-…'` placeholder for single-use nonces.
     */
      case Nonce = 'nonce';
    /**
     * The `script` token for SRI or Trusted Types policies.
     */
      case Script = 'script';
    /**
     * The `style` token for SRI or Trusted Types policies.
     */
      case Style = 'style';
    /**
     * Allows form submission in a sandboxed context.
     */
      case AllowForms = 'allow-forms';
    /**
     * Allows modal dialogs in a sandboxed context.
     */
      case AllowModals = 'allow-modals';
    /**
     * Allows orientation lock in a sandboxed context.
     */
      case AllowOrientationLock = 'allow-orientation-lock';
    /**
     * Allows pointer lock in a sandboxed context.
     */
      case AllowPointerLock = 'allow-pointer-lock';
    /**
     * Allows presentation mode in a sandboxed context.
     */
      case AllowPresentation = 'allow-presentation';
    /**
     * Allows pop-ups in a sandboxed context.
     */
      case AllowPopups = 'allow-popups';
    /**
     * Allows pop-ups to escape sandbox restrictions.
     */
      case AllowPopupsToEscapeSandbox = 'allow-popups-to-escape-sandbox';
    /**
     * Allows same-origin access in a sandboxed context.
     */
      case AllowSameOrigin = 'allow-same-origin';
    /**
     * Allows script execution in a sandboxed context.
     */
      case AllowScripts = 'allow-scripts';
    /**
     * Allows storage access via user activation in a sandbox.
     */
      case AllowStorageAccessByUserActivation = 'allow-storage-access-by-user-activation';
    /**
     * Allows top-level navigation via user activation.
     */
      case AllowTopNavigationByUserActivation = 'allow-top-navigation-by-user-activation';
    /**
     * Allows duplicate directives.
     */
      case AllowDuplicates = 'allow-duplicates';
    /**
     * Allows WebAssembly to use `eval()`.
     */
      case WasmUnsafeEval = 'wasm-unsafe-eval';
    /**
     * Enables inline speculation rules.
     */
      case InlineSpeculationRules = 'inline-speculation-rules';
    /**
     * Includes sample reports in violation reports.
     */
      case ReportSample = 'report-sample';
    }

    /**
     * All the CSP directives you want to support.
     * Supported Content Security Policy (CSP) directives.
     *
     * These correspond to the various directives you can set in a
     * Content-Security-Policy header.
     */
    enum CspRule: string {
    /**
     * Fallback for other fetch directives.
     */
      case DefaultSrc = 'default-src';
    /**
     * Controls allowed sources for scripts.
     */
      case ScriptSrc = 'script-src';
    /**
     * Controls allowed sources for stylesheets.
     */
      case StyleSrc = 'style-src';
    /**
     * Controls allowed sources for images.
     */
      case ImgSrc = 'img-src';
    /**
     * Restricts which parent origins can embed this resource.
     */
      case FrameAncestors = 'frame-ancestors';
    /**
     * Controls allowed endpoints for fetch, XHR, WebSocket, etc.
     */
      case ConnectSrc = 'connect-src';
    /**
     * Controls allowed sources for font resources.
     */
      case FontSrc = 'font-src';
    /**
     * Alias for controlling allowed embedding contexts.
     */
      case ChildSrc = 'child-src';
    /**
     * Controls allowed sources for web app manifests.
     */
      case ManifestSrc = 'manifest-src';
    /**
     * Controls allowed sources for media elements.
     */
      case MediaSrc = 'media-src';
    /**
     * Controls allowed sources for plugin content.
     */
      case ObjectSrc = 'object-src';
    /**
     * Controls allowed sources for prefetch operations.
     */
      case PrefetchSrc = 'prefetch-src';
    /**
     * Controls allowed sources for script elements.
     */
      case ScriptSrcElem = 'script-src-elem';
    /**
     * Controls allowed sources for inline event handlers.
     */
      case ScriptSrcAttr = 'script-src-attr';
    /**
     * Controls allowed sources for style elements.
     */
      case StyleSrcElem = 'style-src-elem';
    /**
     * Controls allowed sources for inline style attributes.
     */
      case StyleSrcAttr = 'style-src-attr';
    /**
     * Controls allowed sources for worker scripts.
     */
      case WorkerSrc = 'worker-src';
    /**
     * Restricts the set of URLs usable in the document's base element.
     */
      case BaseUri = 'base-uri';
    /**
     * Restricts the URLs that forms can submit to.
     */
      case FormAction = 'form-action';
    /**
     * Applies sandboxing rules to the document.
     */
      case Sandbox = 'sandbox';
    /**
     * Restricts the types of plugins that may be loaded.
     */
      case PluginTypes = 'plugin-types';
    /**
     * Disallows all mixed HTTP content on secure pages.
     */
      case BlockAllMixedContent = 'block-all-mixed-content';
    /**
     * Instructs browsers to upgrade insecure requests to HTTPS.
     */
      case UpgradeInsecureRequests = 'upgrade-insecure-requests';
    /**
     * Specifies a URI to which policy violation reports are sent.
     */
      case ReportUri = 'report-uri';
    /**
     * Specifies a reporting group for violation reports.
     */
      case ReportTo = 'report-to';
    /**
     * Requires Subresource Integrity checks for specified resource types.
     */
      case RequireSriFor = 'require-sri-for';
    /**
     * Restricts creation of DOM sinks to a trusted-types policy.
     */
      case TrustedTypes = 'trusted-types';
    /**
     * Enforces Trusted Types for specified sinks.
     */
      case RequireTrustedTypesFor = 'require-trusted-types-for';
    }

    /**
     * Possible values for the `X-Frame-Options` header.
     */
    enum FrameOptions: string {
      case Deny = 'DENY';
      case SameOrigin = 'SAMEORIGIN';
      case AllowFrom = 'ALLOW-FROM';
    }

    /**
     * Permissions-Policy header builder.
     */
    class PermissionsPolicy {
        const ORIGIN_ANY = '*';

        const ORIGIN_SELF = 'self';

        const ORIGIN_SRC = 'src';

        /**
         * Constructs a new Permissions-Policy builder with no features allowed.
         */
        public function __construct() {}

        /**
         * Allow a feature for the given list of origins.
         *
         * @param \Hardened\SecurityHeaders\PermissionsPolicyFeature $feature
         * @param array $origins
         * @return void
         * @throws \Exception - if `feature` is not recognized.
         */
        public function allow(\Hardened\SecurityHeaders\PermissionsPolicyFeature $feature, array $origins): void {}

        /**
         * Builds the Permissions-Policy header value.
         *
         * @return string - `String`, e.g.: `geolocation=(self "https://api.example.com"), camera=()`
         */
        public function build(): string {}

        /**
         * Deny a feature entirely (empty allowlist).
         *
         * @param \Hardened\SecurityHeaders\PermissionsPolicyFeature $feature
         * @return void
         * @throws \Exception - if `feature` is not recognized.
         */
        public function deny(\Hardened\SecurityHeaders\PermissionsPolicyFeature $feature): void {}

        /**
         * Sends the Permissions-Policy header via PHP `header()` function.
         *
         * @return void
         * @throws \Exception - Returns an error if PHP `header()` cannot be invoked.
         */
        public function send(): void {}
    }

    /**
     * Supported Permissions-Policy features.
     *
     * Each variant corresponds to a feature name in the Permissions-Policy header
     * (kebab-case). See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
     */
    enum PermissionsPolicyFeature: string {
    /**
     * Controls whether the current document is allowed to gather information
     * about the acceleration of the device through the Accelerometer interface.
     */
      case Accelerometer = 'accelerometer';
    /**
     * Controls whether the current document is allowed to gather information
     * about the amount of light in the environment around the device through
     * the AmbientLightSensor interface.
     */
      case AmbientLightSensor = 'ambient-light-sensor';
    /**
     * Controls whether the current document is allowed to use the
     * Attribution Reporting API.
     */
      case AttributionReporting = 'attribution-reporting';
    /**
     * Controls whether the current document is allowed to autoplay media
     * requested through the HTMLMediaElement interface. When disabled without
     * user gesture, play() will reject with NotAllowedError.
     */
      case Autoplay = 'autoplay';
    /**
     * Controls whether the use of the Web Bluetooth API is allowed.
     * When disabled, Bluetooth methods will either return false or reject.
     */
      case Bluetooth = 'bluetooth';
    /**
     * Controls access to the Topics API. Disallowed calls to browsingTopics()
     * or Sec-Browsing-Topics header will fail with NotAllowedError.
     */
      case BrowsingTopics = 'browsing-topics';
    /**
     * Controls whether the current document is allowed to use video input devices.
     * When disabled, getUserMedia() will reject with NotAllowedError.
     */
      case Camera = 'camera';
    /**
     * Controls access to the Compute Pressure API.
     */
      case ComputePressure = 'compute-pressure';
    /**
     * Controls whether the current document can be treated as cross-origin isolated.
     */
      case CrossOriginIsolated = 'cross-origin-isolated';
    /**
     * Controls the allocation of the top-level origin's fetchLater() quota.
     */
      case DeferredFetch = 'deferred-fetch';
    /**
     * Controls the allocation of the shared cross-origin subframe fetchLater() quota.
     */
      case DeferredFetchMinimal = 'deferred-fetch-minimal';
    /**
     * Controls whether the current document may capture display media via getDisplayMedia().
     * When disabled, getDisplayMedia() will reject with NotAllowedError.
     */
      case DisplayCapture = 'display-capture';
    /**
     * Controls whether the current document is allowed to use the Encrypted Media
     * Extensions API (EME). When disabled, requestMediaKeySystemAccess() will reject.
     */
      case EncryptedMedia = 'encrypted-media';
    /**
     * Controls whether the current document is allowed to use Element.requestFullscreen().
     * When disabled, requestFullscreen() will reject with TypeError.
     */
      case Fullscreen = 'fullscreen';
    /**
     * Controls whether the current document is allowed to use the Gamepad API.
     * When disabled, getGamepads() will throw SecurityError and events won't fire.
     */
      case Gamepad = 'gamepad';
    /**
     * Controls whether the current document is allowed to use the Geolocation Interface.
     * When disabled, geolocation callbacks will error with PERMISSION_DENIED.
     */
      case Geolocation = 'geolocation';
    /**
     * Controls whether the current document is allowed to gather information
     * about device orientation through the Gyroscope interface.
     */
      case Gyroscope = 'gyroscope';
    /**
     * Controls whether the current document is allowed to use the WebHID API.
     * Allows communication with HID devices like gamepads or keyboards.
     */
      case Hid = 'hid';
    /**
     * Controls whether the document may use the Federated Credential Management API
     * (FedCM) via navigator.credentials.get({identity:…}).
     */
      case IdentityCredentialsGet = 'identity-credentials-get';
    /**
     * Controls whether the document may use the Idle Detection API to detect user idle/active state.
     */
      case IdleDetection = 'idle-detection';
    /**
     * Controls access to the language detection functionality of Translator & Language Detector APIs.
     */
      case LanguageDetector = 'language-detector';
    /**
     * Controls whether the document may gather data on locally-installed fonts via queryLocalFonts().
     */
      case LocalFonts = 'local-fonts';
    /**
     * Controls whether the document may gather device orientation via the Magnetometer interface.
     */
      case Magnetometer = 'magnetometer';
    /**
     * Controls whether the document is allowed to use audio input devices.
     * When disabled, getUserMedia() will reject with NotAllowedError.
     */
      case Microphone = 'microphone';
    /**
     * Controls whether the document may use the Web MIDI API.
     * When disabled, requestMIDIAccess() will reject with SecurityError.
     */
      case Midi = 'midi';
    /**
     * Controls whether the document may use the WebOTP API to retrieve one-time passwords.
     */
      case OtpCredentials = 'otp-credentials';
    /**
     * Controls whether the document may use the Payment Request API.
     * When disabled, PaymentRequest() will throw SecurityError.
     */
      case Payment = 'payment';
    /**
     * Controls whether the document may enter Picture-in-Picture mode via the API.
     */
      case PictureInPicture = 'picture-in-picture';
    /**
     * Controls whether the document may use Web Authentication API to create new credentials.
     */
      case PublickeyCredentialsCreate = 'publickey-credentials-create';
    /**
     * Controls whether the document may use Web Authentication API to retrieve stored credentials.
     */
      case PublickeyCredentialsGet = 'publickey-credentials-get';
    /**
     * Controls whether the document may use the Screen Wake Lock API to keep the screen on.
     */
      case ScreenWakeLock = 'screen-wake-lock';
    /**
     * Controls whether the document may use the Web Serial API to communicate with serial devices.
     */
      case Serial = 'serial';
    /**
     * Controls whether the document may list and select speakers via the Output Devices API.
     */
      case SpeakerSelection = 'speaker-selection';
    /**
     * Controls whether an embedded document may use the Storage Access API for third-party cookies.
     */
      case StorageAccess = 'storage-access';
    /**
     * Controls access to the translation functionality of Translator & Language Detector APIs.
     */
      case Translator = 'translator';
    /**
     * Controls access to the Summarizer API.
     */
      case Summarizer = 'summarizer';
    /**
     * Controls whether the document may use the WebUSB API to connect to USB devices.
     */
      case Usb = 'usb';
    /**
     * Controls whether the document may use the Web Share API (navigator.share()).
     */
      case WebShare = 'web-share';
    /**
     * Controls whether the document may use the Window Management API to manage windows.
     */
      case WindowManagement = 'window-management';
    /**
     * Controls whether the document may use the WebXR Device API to interact with XR sessions.
     */
      case XrSpatialTracking = 'xr-spatial-tracking';
    }

    /**
     * Referrer-Policy header builder.
     */
    class ReferrerPolicy {
        /**
         * Create a new Referrer-Policy builder for PHP.
         *
         * By default, the referrer policy is set to `no-referrer`, which prevents
         * the `Referer` header from being sent with any requests.
         *
         * @param string|null $policy
         */
        public function __construct(?string $policy = null) {}

        /**
         * Build the `Referrer-Policy` header value.
         *
         * @return string - `string` the configured policy value suitable for sending as a header.
         */
        public function build(): string {}

        /**
         * Get the current Referrer-Policy value.
         *
         * @return string - `string` the active policy token.
         */
        public function get(): string {}

        /**
         * Send the `Referrer-Policy` header via PHP `header()` function.
         *
         * @return void
         */
        public function send(): void {}

        /**
         * Update the active Referrer-Policy directive.
         *
         * @param string $policy
         * @return void
         */
        public function set(string $policy): void {}
    }

    /**
     * HTTP Strict Transport Security (HSTS) header builder.
     */
    class StrictTransportSecurity {
        /**
         * Constructs a new HSTS builder with default settings.
         */
        public function __construct() {}

        /**
         * Builds the `Strict-Transport-Security` header value.
         *
         * @return string - `string` e.g. `"max-age=31536000; includeSubDomains; preload"`.
         */
        public function build(): string {}

        /**
         * Enable or disable the `includeSubDomains` flag.
         *
         * @param bool $enable `true` to include subdomains, `false` to omit.
         * @return void - `void`
         */
        public function includeSubDomains(bool $enable): void {}

        /**
         * Sets the `max-age` directive (in seconds).
         *
         * @param int $max_age
         * @return void - `void`
         */
        public function maxAge(int $max_age): void {}

        /**
         * Enable or disable the `preload` flag.
         *
         * @param bool $enable `true` to add `preload`, `false` to omit.
         * @return void - `void`
         */
        public function preload(bool $enable): void {}

        /**
         * Sends the `Strict-Transport-Security` header via PHP `header()` function.
         *
         * @return void
         */
        public function send(): void {}
    }

    /**
     * Builder for miscellaneous HTTP security headers:
     * `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`,
     * `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,
     * and `Integrity-Policy-Report-Only`.
     */
    class Whatnot {
        /**
         * Constructs a new builder with all headers disabled.
         */
        public function __construct() {}

        /**
         * Build an associative array of header names → values.
         *
         * @return array
         */
        public function build(): array {}

        /**
         * Emit all configured headers via PHP `header()` calls.
         *
         * @return void
         */
        public function send(): void {}

        /**
         * Set `X-Frame-Options` header.
         *
         * @param FrameOptions::Deny $mode , `FrameOptions::SameOrigin`, or `FrameOptions::AllowFrom`.
         * @param string|null $uri
         * @return void
         */
        public function setFrameOptions(\Hardened\SecurityHeaders\FrameOptions $mode, ?string $uri = null): void {}

        /**
         * Set a structured `Integrity-Policy` header.
         *
         * @param mixed $blocked_destinations
         * @param array|null $sources
         * @param array|null $endpoints
         * @return void
         */
        public function setIntegrityPolicy(mixed $blocked_destinations, ?array $sources = null, ?array $endpoints = null): void {}

        /**
         * Set a structured `Integrity-Policy-Report-Only` header.
         *
         * @param mixed $blocked_destinations
         * @param array|null $sources
         * @param array|null $endpoints
         * @return void
         */
        public function setIntegrityPolicyReportOnly(mixed $blocked_destinations, ?array $sources = null, ?array $endpoints = null): void {}

        /**
         * Enable or disable `X-Content-Type-Options: nosniff`.
         *
         * @param bool $enable
         * @return void
         */
        public function setNosniff(bool $enable): void {}

        /**
         * Set `X-Permitted-Cross-Domain-Policies` header.
         *
         * @param CrossDomainPolicy::None $policy , `MasterOnly`, `ByContentType`, or `All`.
         * @return void
         */
        public function setPermittedCrossDomainPolicies(\Hardened\SecurityHeaders\CrossDomainPolicy $policy): void {}

        /**
         * Configure the `Report-To` header from structured arguments.
         *
         * @param string $group
         * @param int $max_age
         * @param bool $include_subdomains
         * @param array $endpoints
         * @return void
         */
        public function setReportTo(string $group, int $max_age, bool $include_subdomains, array $endpoints): void {}

        /**
         * Set `X-XSS-Protection` header.
         *
         * @param XssProtection::Off $mode , `XssProtection::On`, or `XssProtection::Block`.
         * @param string|null $report_uri
         * @return void
         */
        public function setXssProtection(\Hardened\SecurityHeaders\XssProtection $mode, ?string $report_uri = null): void {}
    }

    /**
     * Possible values for the `X-XSS-Protection` header.
     */
    enum XssProtection: string {
      case Off = 'off';
      case On = 'on';
      case Block = 'block';
    }
}

namespace Hardened\SecurityHeaders\CrossOrigin {
    /**
     * Builder for `Cross-Origin-Embedder-Policy` header.
     */
    class EmbedderPolicy {
        /**
         * Create a new Cross-Origin-Embedder-Policy (COEP) builder for PHP.
         *
         * By default, this sets the policy to `"unsafe-none"`, allowing all embedders.
         *
         * @param \Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicyValue|null $policy
         */
        public function __construct(?\Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicyValue $policy = null) {}

        /**
         * Render the header value.
         *
         * @return string - `string`: the currently configured policy token.
         */
        public function build(): string {}

        /**
         * Get the current Embedder-Policy value.
         *
         * @return string - `string` the active policy token.
         */
        public function get(): string {}

        /**
         * Send the `Cross-Origin-Embedder-Policy` header via PHP `header()`.
         *
         * @return void
         * @throws \Exception - Throws `Exception` if the PHP `header()` function cannot be invoked.
         */
        public function send(): void {}

        /**
         * Update the COEP directive.
         *
         * @param \Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicyValue $policy
         * @return void
         */
        public function set(\Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicyValue $policy): void {}
    }

    /**
     * Allowed values for the `Cross-Origin-Embedder-Policy` header.
     */
    enum EmbedderPolicyValue: string {
    /**
     * Allows the document to load cross-origin resources without giving explicit permission
     * through CORS or `Cross-Origin-Resource-Policy`. This is the default.
     */
      case UnsafeNone = 'unsafe-none';
    /**
     * Only same-origin or resources explicitly marked via `Cross-Origin-Resource-Policy`
     * or CORS may be loaded.
     */
      case RequireCorp = 'require-corp';
    /**
     * Similar to `require-corp`, but drops credentials on no-CORS requests.
     */
      case Credentialless = 'credentialless';
    }

    /**
     * Builder for `Cross-Origin-Opener-Policy` header.
     */
    class OpenerPolicy {
        /**
         * Create a new Cross-Origin-Opener-Policy builder.
         *
         * By default, this sets the policy to `"unsafe-none"`, which imposes
         * no special opener isolation. PHP users can call this without arguments
         * to get the default behavior.
         *
         * @param string|null $policy
         */
        public function __construct(?string $policy = null) {}

        /**
         * Build the header value.
         *
         * @return string - `string` the configured policy, e.g. `"same-origin"`.
         */
        public function build(): string {}

        /**
         * Send the `Cross-Origin-Opener-Policy` header via PHP `header()`.
         *
         * @return void
         */
        public function send(): void {}

        /**
         * Use this if you need to change the policy after construction.
         * Calling this method will override any previous setting.
         *
         * @param string $policy
         * @return void
         */
        public function set(string $policy): void {}
    }

    /**
     * Builder for the `Cross-Origin-Resource-Policy` header.
     */
    class ResourcePolicy {
        /**
         * Create a new Cross-Origin-Resource-Policy builder.
         *
         * By default, the policy is set to `same-origin`, which restricts
         * resource sharing to the same origin that served the document.
         *
         * @param string|null $policy
         */
        public function __construct(?string $policy = null) {}

        /**
         * Build the header value.
         *
         * @return string - `string` the configured directive token.
         */
        public function build(): string {}

        /**
         * Get the current Resource-Policy value.
         *
         * @return string - `string` the active policy token.
         */
        public function get(): string {}

        /**
         * Send the `Cross-Origin-Resource-Policy` header via PHP `header()`.
         *
         * @return void
         */
        public function send(): void {}

        /**
         * Change the active Cross-Origin-Resource-Policy directive.
         *
         * This will override any previous setting or the default.
         *
         * @param string $policy
         * @return void
         */
        public function set(string $policy): void {}
    }

    /**
     * CORS policy builder for HTTP responses.
     */
    class ResourceSharing {
        const ORIGIN_SELF = 'self';

        /**
         * Constructs a new CORS policy with default settings (no restrictions).
         */
        public function __construct() {}

        /**
         * Control whether cookies or HTTP authentication information are
         * included in cross-origin requests.
         *
         * @param true $enable to send credentials (cookies, HTTP auth), `false`
         * @return void - `void`
         */
        public function allowCredentials(bool $enable): void {}

        /**
         * Specify which custom headers the client may include in the request.
         *
         * Browsers enforce that only simple headers are sent by default; to
         * allow additional headers (e.g. `Content-Type`, `X-Custom-Header`),
         * they must be listed here.
         *
         * @param array $headers
         * @return void - `void`
         */
        public function allowHeaders(array $headers): void {}

        /**
         * Specify which HTTP methods may be used in cross-origin requests.
         *
         * During a CORS preflight (`OPTIONS`) request, the browser checks
         * this list to determine whether to allow the actual request method.
         *
         * @param array $methods
         * @return void - `void`
         */
        public function allowMethods(array $methods): void {}

        /**
         * Specify which origins are allowed to access the resource.
         *
         * Browsers will only allow cross-origin requests if the request's
         * `Origin` header matches one of these values. Use `["*"]` to allow
         * any origin (note: this will disable credentials).
         *
         * @param array $origins
         * @return void - `void`
         */
        public function allowOrigins(array $origins): void {}

        /**
         * Build an associative array of CORS headers and their values.
         *
         * @return array - `array<string,string>` Map of header names to header values.
         */
        public function build(): array {}

        /**
         * Specify which response headers can be accessed by client-side scripts.
         *
         * By default, browsers only expose a limited set of safe headers.
         * To expose additional headers (e.g. `X-RateLimit-Remaining`),
         * list them here.
         *
         * @param array $headers
         * @return void - `void`
         */
        public function exposeHeaders(array $headers): void {}

        /**
         * Set how long (in seconds) the results of a preflight request can
         * be cached by the browser.
         *
         * A higher value reduces the number of CORS preflight requests,
         * improving performance. A value of `0` forces the browser to
         * perform a preflight check on every request.
         *
         * @param int $seconds
         * @return void - `void`
         */
        public function maxAge(int $seconds): void {}

        /**
         * Send all configured CORS headers via PHP's `header()` function.
         *
         * @return void - `void`
         */
        public function send(): void {}
    }
}
