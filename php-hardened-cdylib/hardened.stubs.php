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
     * Hardened `Set-Cookie` builder.
     *
     * Secure defaults (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`) that you
     * must explicitly opt out of, RFC 6265 validation of names and values (no
     * header-splitting bytes can reach the wire), enforced `__Host-`/`__Secure-`
     * prefix invariants, and `SameSite=None` refusing to build without `Secure`.
     */
    class Cookie {
        /**
         * Constructs a cookie with hardened defaults: `Secure`, `HttpOnly`,
         * `SameSite=Lax`, `Path=/`.
         *
         * @param string $name
         * @param string $value
         */
        public function __construct(string $name, string $value) {}

        /**
         * Builds the `Set-Cookie` header value, validating all invariants:
         * `__Host-` (Secure, no Domain, Path=/), `__Secure-` (Secure),
         * `SameSite=None` and `Partitioned` (Secure).
         *
         * @return string - `string`: e.g. `session=abc; Path=/; Secure; HttpOnly; SameSite=Lax`.
         */
        public function build(): string {}

        /**
         * Builds and sends the cookie via PHP's `header()` (without replacing
         * previously sent cookies).
         *
         * @return void
         */
        public function send(): void {}

        /**
         * Sets the `Domain` attribute. Not allowed on `__Host-` cookies.
         *
         * @param string $domain
         * @return void
         */
        public function setDomain(string $domain): void {}

        /**
         * Sets the `Expires` attribute from a unix timestamp.
         *
         * @param int $unix_timestamp
         * @return void
         */
        public function setExpires(int $unix_timestamp): void {}

        /**
         * Enables or disables the `HttpOnly` attribute (default: enabled).
         *
         * @param bool $http_only
         * @return void
         */
        public function setHttpOnly(bool $http_only): void {}

        /**
         * Sets the `Max-Age` attribute in seconds. `0` (or negative) tells the
         * browser to delete the cookie.
         *
         * @param int $seconds
         * @return void
         */
        public function setMaxAge(int $seconds): void {}

        /**
         * Enables the `Partitioned` attribute (CHIPS). Requires `Secure`.
         *
         * @param bool $partitioned
         * @return void
         */
        public function setPartitioned(bool $partitioned): void {}

        /**
         * Sets the `Path` attribute (defaults to `/`).
         *
         * @param string $path
         * @return void
         */
        public function setPath(string $path): void {}

        /**
         * Sets the `SameSite` attribute (defaults to `Lax`). `None` requires
         * `Secure`, which is enforced at build time.
         *
         * @param "Strict" $same_site , `"Lax"`, or `"None"` (case-insensitive).
         * @return void
         */
        public function setSameSite(string $same_site): void {}

        /**
         * Enables or disables the `Secure` attribute (default: enabled).
         * Disabling it on a `__Host-`/`__Secure-` cookie or with
         * `SameSite=None` makes `build()` throw.
         *
         * @param bool $secure
         * @return void
         */
        public function setSecure(bool $secure): void {}

        /**
         * Replaces the cookie value.
         *
         * @param string $value
         * @return void
         */
        public function setValue(string $value): void {}
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
     * Safe filenames for downloads and uploads.
     *
     * Client-supplied filenames are attacker input: path separators climb
     * directories, control bytes and Unicode bidi overrides spoof what the user
     * sees (`U+202E` makes `…cod.exe` display as `…exe.doc`), reserved Windows
     * device names (`CON`, `NUL`, `COM1`) break file handling, trailing
     * dots/spaces round-trip differently on Windows, and double extensions
     * (`invoice.pdf.php`) turn an upload into code execution.
     */
    class Filename {
        public function __construct() {}

        /**
         * Builds a safe `Content-Disposition` header value for a download:
         * the filename is sanitized, an ASCII fallback goes into `filename=`,
         * and non-ASCII names additionally get an RFC 5987 `filename*=` form.
         *
         * ```php
         * header("Content-Disposition: " . Filename::contentDisposition($name));
         * ```
         *
         * @param string $filename
         * @param bool|null $inline
         * @return string - `string`: The header value, e.g. `attachment; filename="report.pdf"`.
         */
        public static function contentDisposition(string $filename, ?bool $inline = null): string {}

        /**
         * Checks whether any extension in the chain (not just the last) is an
         * executable/server-interpreted type: `invoice.pdf.php`, `shell.php.jpg`
         * and `run.exe` all return `true`.
         *
         * @param string $filename
         * @return bool - `bool`: `true` if a dangerous extension is present.
         */
        public static function hasDangerousExtension(string $filename): bool {}

        /**
         * Checks whether the filename has more than one extension
         * (`invoice.pdf.exe`), a common social-engineering pattern.
         *
         * @param string $filename
         * @return bool - `bool`: `true` if multiple extensions are present.
         */
        public static function hasDoubleExtension(string $filename): bool {}

        /**
         * Checks whether a filename is already safe: it survives `sanitize()`
         * unchanged and carries no dangerous extension anywhere in its chain.
         *
         * @param string $filename
         * @return bool - `bool`: `true` if the filename is safe as-is.
         */
        public static function isSafe(string $filename): bool {}

        /**
         * Sanitizes a client-supplied filename for safe storage and display.
         *
         * Keeps only the last path component; removes control bytes and
         * invisible/bidi-override characters; replaces Windows-forbidden
         * punctuation; strips leading/trailing dots and spaces; neutralizes
         * reserved Windows device names; caps the length at 255 bytes. Returns
         * `"file"` if nothing survives.
         *
         * @param string $filename
         * @param string|null $replacement
         * @return string - `string`: The sanitized filename.
         */
        public static function sanitize(string $filename, ?string $replacement = null): string {}
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

    /**
     * Hardened JWT verification.
     *
     * Most JWT vulnerabilities are verification bugs, and this API makes them
     * unrepresentable:
     * - **`alg: none` is always rejected** — there is no way to allow it.
     * - **No HS/RS algorithm confusion**: the key type is bound to an algorithm
     *   family at construction (`forHmac()` accepts only HS*, `forRsa()` only
     *   RS*/PS*, …), so an attacker cannot have an RSA public key interpreted
     *   as an HMAC secret.
     * - **`exp` is mandatory** and validated (with configurable leeway); `nbf`
     *   is validated when present; a future `iat` is rejected.
     * - The token's `alg` header must be in the explicit allowlist.
     */
    class JwtVerifier {
        public function __construct() {}

        /**
         * Constructs a verifier for ECDSA tokens from a PEM public key.
         *
         * @param string $public_key_pem
         * @param array|null $algorithms
         * @return \Hardened\JwtVerifier
         */
        public static function forEcdsa(string $public_key_pem, ?array $algorithms = null): \Hardened\JwtVerifier {}

        /**
         * Constructs a verifier for Ed25519 (`EdDSA`) tokens from a PEM public key.
         *
         * @param string $public_key_pem
         * @return \Hardened\JwtVerifier
         */
        public static function forEd25519(string $public_key_pem): \Hardened\JwtVerifier {}

        /**
         * Constructs a verifier for HMAC (shared-secret) tokens.
         *
         * @param string $secret
         * @param array|null $algorithms
         * @return \Hardened\JwtVerifier
         */
        public static function forHmac(string $secret, ?array $algorithms = null): \Hardened\JwtVerifier {}

        /**
         * Constructs a verifier for RSA tokens from a PEM public key.
         *
         * @param string $public_key_pem
         * @param array|null $algorithms
         * @return \Hardened\JwtVerifier
         */
        public static function forRsa(string $public_key_pem, ?array $algorithms = null): \Hardened\JwtVerifier {}

        /**
         * Requires the `aud` claim to contain one of the given values.
         *
         * @param array $audiences
         * @return void
         */
        public function requireAudience(array $audiences): void {}

        /**
         * Requires the listed claims to be present (any value).
         *
         * @param array $claims
         * @return void
         */
        public function requireClaims(array $claims): void {}

        /**
         * Requires the `iss` claim to equal one of the given values.
         *
         * @param array $issuers
         * @return void
         */
        public function requireIssuer(array $issuers): void {}

        /**
         * Rejects tokens whose `iat` is older than the given age. Makes `iat`
         * mandatory.
         *
         * @param int $seconds
         * @return void
         */
        public function requireMaxAge(int $seconds): void {}

        /**
         * Requires the `sub` claim to equal the given value.
         *
         * @param string $subject
         * @return void
         */
        public function requireSubject(string $subject): void {}

        /**
         * Sets the clock-skew leeway applied to `exp`/`nbf`/`iat` checks
         * (defaults to 60 seconds).
         *
         * @param int $seconds
         * @return void
         */
        public function setLeeway(int $seconds): void {}

        /**
         * Verifies a token and returns its claims.
         *
         * Checks performed: signature with an allowlisted algorithm (never
         * `none`), mandatory `exp`, `nbf` if present, `iat` not in the future,
         * plus any configured issuer/audience/subject/required-claim/max-age
         * constraints.
         *
         * @param string $token
         * @return mixed - `array`: The token claims as an associative array.
         */
        public function verify(string $token): mixed {}
    }

    /**
     * Password hashing with safe algorithms and safe defaults.
     *
     * `hash()` produces Argon2id (the current OWASP recommendation) PHC strings;
     * `verify()` accepts Argon2 and bcrypt hashes, so existing `password_hash()`
     * databases can be migrated gradually: verify with the old hash, then
     * re-hash when `needsRehash()` says so. Verification is timing-safe.
     */
    class Password {
        public function __construct() {}

        /**
         * Hashes a password with Argon2id.
         *
         * Defaults follow the OWASP Password Storage Cheat Sheet: 19 MiB memory,
         * 2 iterations, parallelism 1. A random salt is generated per call.
         *
         * @param string $password
         * @param int|null $memory_kib
         * @param int|null $iterations
         * @param int|null $parallelism
         * @return string - `string`: A PHC-format hash string (`$argon2id$...`).
         */
        public static function hash(string $password, ?int $memory_kib = null, ?int $iterations = null, ?int $parallelism = null): string {}

        /**
         * Hashes a password with bcrypt, for systems that must stay
         * bcrypt-compatible. Prefer `hash()` (Argon2id) for new code.
         *
         * Note: bcrypt only uses the first 72 bytes of the password.
         *
         * @param string $password
         * @param int|null $cost
         * @return string - `string`: A bcrypt hash string (`$2b$...`).
         */
        public static function hashBcrypt(string $password, ?int $cost = null): string {}

        /**
         * Checks whether a stored hash should be re-hashed: it is not Argon2id,
         * uses an outdated Argon2 version, or its cost parameters differ from
         * the given (or default) ones. Call after a successful `verify()` and
         * re-hash while you still have the plaintext.
         *
         * @param string $hash
         * @param int|null $memory_kib
         * @param int|null $iterations
         * @param int|null $parallelism
         * @return bool - `bool`: `true` if the hash should be regenerated.
         */
        public static function needsRehash(string $hash, ?int $memory_kib = null, ?int $iterations = null, ?int $parallelism = null): bool {}

        /**
         * Checks whether a bcrypt hash uses a cost lower than the given (or
         * default) one.
         *
         * @param string $hash
         * @param int|null $cost
         * @return bool - `bool`: `true` if the hash should be regenerated.
         */
        public static function needsRehashBcrypt(string $hash, ?int $cost = null): bool {}

        /**
         * Verifies a password against a stored hash, in constant time with
         * respect to the hash contents.
         *
         * Accepts Argon2 (`$argon2id$`, `$argon2i$`) and bcrypt (`$2a$`, `$2b$`,
         * `$2y$`) hashes, so databases written by PHP's `password_hash()` keep
         * verifying during a migration.
         *
         * @param string $password
         * @param string $hash
         * @return bool - `bool`: `true` if the password matches.
         */
        public static function verify(string $password, string $hash): bool {}
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
     * Token-bucket rate limiter.
     *
     * A bucket holds up to `capacity` tokens and refills at `refillTokens` per
     * `refillIntervalMs`. Each attempt consumes tokens; an empty bucket means
     * the action is rate-limited. This shape allows short bursts up to
     * `capacity` while capping the sustained rate.
     *
     * Three storage modes:
     * - **Process-local** (`attempt()`, keyed by string): zero setup. Note that
     *   under php-fpm each worker process keeps its own counters, so the
     *   effective limit is multiplied by the number of workers.
     * - **External** (`attemptStateful()`): the limiter is stateless; you keep
     *   the opaque state string anywhere shared — APCu, Redis, a session — and
     *   pass it back on the next attempt. Use your store's locking/CAS if
     *   strict accounting under concurrency is required.
     * - **`CL.THROTTLE`** (`attemptClThrottle()` / `clThrottleCommand()`): the
     *   strongest backend — atomic server-side GCRA in DragonflyDB (built in)
     *   or Redis with the redis-cell module. One round-trip, shared across all
     *   workers and hosts, no read-modify-write race.
     */
    class RateLimiter {
        /**
         * Constructs a token-bucket rate limiter.
         *
         * Example: `new RateLimiter(100, 10, 1000)` allows bursts of 100 and a
         * sustained 10 requests per second.
         *
         * @param int $capacity
         * @param int $refill_tokens
         * @param int $refill_interval_ms
         */
        public function __construct(int $capacity, int $refill_tokens, int $refill_interval_ms) {}

        /**
         * Attempts to consume tokens for `key` from the process-local store.
         *
         * @param string $key
         * @param int|null $cost
         * @return bool - `bool`: `true` if allowed, `false` if rate-limited.
         */
        public function attempt(string $key, ?int $cost = null): bool {}

        /**
         * One-call `CL.THROTTLE` attempt through any PHP Redis client: the
         * command is passed to `raw_command` as variadic string arguments, and
         * the reply is parsed into a decision object.
         *
         * ```php
         * $result = $limiter->attemptClThrottle(
         *     "login:$ip",
         *     fn (...$cmd) => $redis->rawCommand(...$cmd), // phpredis
         * );
         * if (!$result->allowed) {
         *     header("Retry-After: " . $result->retryAfterSec);
         *     http_response_code(429);
         * }
         * ```
         *
         * @param string $key
         * @param callable $raw_command
         * @param int|null $cost
         * @return \Hardened\ThrottleDecision - `ThrottleDecision`: readonly object with `allowed`, `limit`, `remaining`, `retryAfterSec` and `resetAfterSec` properties.
         */
        public function attemptClThrottle(string $key, callable $raw_command, ?int $cost = null): \Hardened\ThrottleDecision {}

        /**
         * Attempts to consume tokens against an externally-stored state string,
         * for shared backends (APCu, Redis, database, session).
         *
         * ```php
         * $state = apcu_fetch("rl:$ip") ?: null;
         * [$allowed, $state, $retryAfterMs] = $limiter->attemptStateful($state);
         * apcu_store("rl:$ip", $state, 3600);
         * if (!$allowed) { http_response_code(429); }
         * ```
         *
         * @param string|null $state
         * @param int|null $cost
         * @return array - `array{0: bool, 1: string, 2: int}`: whether the attempt is allowed, the new state string to store, and the retry-after hint in milliseconds (`0` when allowed).
         */
        public function attemptStateful(?string $state = null, ?int $cost = null): array {}

        /**
         * Builds the `CL.THROTTLE` command equivalent to this limiter's
         * configuration, for atomic server-side rate limiting on DragonflyDB
         * (built in) or Redis with the redis-cell module. This is the strongest
         * backend: one round-trip, GCRA, no read-modify-write race.
         *
         * ```php
         * $reply = $redis->rawCommand(...$limiter->clThrottleCommand("login:$ip"));
         * $result = RateLimiter::clThrottleParse($reply);
         * ```
         *
         * @param string $key
         * @param int|null $cost
         * @return array - `string[]`: The full command, e.g. `["CL.THROTTLE", "login:1.2.3.4", "9", "1", "12", "1"]`.
         */
        public function clThrottleCommand(string $key, ?int $cost = null): array {}

        /**
         * Parses a `CL.THROTTLE` reply (five integers) into a decision object.
         *
         * @param array $response
         * @return \Hardened\ThrottleDecision - `ThrottleDecision`: readonly object with `allowed`, `limit`, `remaining`, `retryAfterSec` (`0` when allowed) and `resetAfterSec` properties.
         */
        public static function clThrottleParse(array $response): \Hardened\ThrottleDecision {}

        /**
         * Returns the number of whole tokens currently available for `key`.
         *
         * @param string $key
         * @return int - `int`: Available tokens, after refill, without consuming any.
         */
        public function remaining(string $key): int {}

        /**
         * Removes the process-local bucket for `key`, restoring it to full.
         *
         * @param string $key
         * @return void
         */
        public function reset(string $key): void {}

        /**
         * Returns how long to wait (in milliseconds) until an attempt for `key`
         * with the given cost could succeed. Does not consume tokens.
         *
         * @param string $key
         * @param int|null $cost
         * @return int - `int`: `0` if an attempt would currently succeed, otherwise the wait time in milliseconds (suitable for a `Retry-After` header).
         */
        public function retryAfterMs(string $key, ?int $cost = null): int {}
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

    /**
     * Request-level cross-site request forgery guard built on browser-provided
     * metadata: `Sec-Fetch-Site`, `Origin`, and `Referer`.
     *
     * Many real CSRF bypasses come from a hand-rolled Origin check with a hole
     * in it (a forgotten dev domain, a prefix match, a null-origin pass).
     * This guard implements the OWASP-recommended order: safe methods pass;
     * `Sec-Fetch-Site` is honored when the browser sends it; otherwise the
     * `Origin` (then `Referer`) must match the allowlist exactly — scheme,
     * host, and port; a request with no usable headers is rejected by default.
     *
     * Defense in depth: combine with `Hardened\CsrfProtection` tokens rather
     * than replacing them.
     */
    class RequestGuard {
        /**
         * Constructs a request guard.
         *
         * @param array $allowed_origins
         */
        public function __construct(array $allowed_origins) {}

        /**
         * Accepts state-changing requests that carry none of the checked
         * headers. Off by default (strict); enable only if you must support
         * non-browser clients on cookie-authenticated endpoints — better, give
         * those clients token auth and keep this strict.
         *
         * @param bool $allow
         * @return void
         */
        public function allowMissingHeaders(bool $allow): void {}

        /**
         * Accepts `Sec-Fetch-Site: same-site` requests (subdomains of your
         * registrable domain). Off by default: a compromised or
         * attacker-registered subdomain is a classic CSRF hole.
         *
         * @param bool $allow
         * @return void
         */
        public function allowSameSite(bool $allow): void {}

        /**
         * Like `check()`, but throws a descriptive exception on rejection.
         *
         * @param string $method
         * @param string|null $origin
         * @param string|null $referer
         * @param string|null $sec_fetch_site
         * @return void
         */
        public function assert(string $method, ?string $origin = null, ?string $referer = null, ?string $sec_fetch_site = null): void {}

        /**
         * Like `checkServer()`, but throws a descriptive exception on rejection.
         *
         * @return void
         */
        public function assertServer(): void {}

        /**
         * Checks a request described by explicit values.
         *
         * @param string $method
         * @param string|null $origin
         * @param string|null $referer
         * @param string|null $sec_fetch_site
         * @return bool - `bool`: `true` if the request passes the policy.
         */
        public function check(string $method, ?string $origin = null, ?string $referer = null, ?string $sec_fetch_site = null): bool {}

        /**
         * Checks the current request using `$_SERVER` (`REQUEST_METHOD`,
         * `HTTP_ORIGIN`, `HTTP_REFERER`, `HTTP_SEC_FETCH_SITE`).
         *
         * @return bool - `bool`: `true` if the request passes the policy.
         */
        public function checkServer(): bool {}

        /**
         * Replaces the set of methods that always pass (defaults to
         * `GET`/`HEAD`/`OPTIONS`). Keep your safe methods side-effect free.
         *
         * @param array $methods
         * @return void
         */
        public function setSafeMethods(array $methods): void {}
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
     * Secret redactor for logs, error reports, and support dumps.
     *
     * Masks `Authorization`/`Cookie` header values, PEM private keys, JWTs,
     * well-known provider tokens (AWS, GitHub, Slack, Stripe, Google), generic
     * `password=`/`"api_key":` assignments, and Luhn-valid payment card numbers
     * (PCI) — keeping the last four digits for correlation. Patterns are
     * pluggable via `addPattern()`.
     */
    class SecretRedactor {
        /**
         * Constructs a redactor.
         *
         * @param bool|null $defaults
         */
        public function __construct(?bool $defaults = null) {}

        /**
         * Adds a custom redaction pattern, applied after the existing ones.
         *
         * @param string $pattern
         * @param string|null $replacement
         * @return void
         */
        public function addPattern(string $pattern, ?string $replacement = null): void {}

        /**
         * Redacts secrets from the given text.
         *
         * @param string $input
         * @return string - `string`: The text with secrets masked.
         */
        public function redact(string $input): string {}

        /**
         * Enables or disables Luhn-aware card number masking (default: enabled).
         *
         * @param bool $redact
         * @return void
         */
        public function setRedactCardNumbers(bool $redact): void {}
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
     * The outcome of a `CL.THROTTLE` attempt, as an immutable value object:
     * the properties are getter-backed and have no setters, so PHP code cannot
     * alter a decision after the fact.
     */
    class ThrottleDecision {
        /**
         * Whether the action is allowed.
         *
         * @var bool
         */
        public readonly bool $allowed;

        /**
         * The total limit of the key (`max_burst` + 1).
         *
         * @var int
         */
        public readonly int $limit;

        /**
         * The remaining limit of the key.
         *
         * @var int
         */
        public readonly int $remaining;

        /**
         * Seconds until the bucket refills to capacity.
         *
         * @var int
         */
        public readonly int $resetAfterSec;

        /**
         * Seconds until the action could succeed (`0` when allowed).
         *
         * @var int
         */
        public readonly int $retryAfterSec;

        public function __construct() {}
    }

    /**
     * Unicode hardening for identifiers people read: usernames, display names,
     * email local-parts, organization names.
     *
     * Homoglyph attacks register `pаypal` (Cyrillic `а`) next to `paypal`;
     * zero-width characters make two distinct usernames render identically;
     * mixed-script strings smuggle look-alikes past exact-match checks. These
     * helpers implement UTS #39 (confusable skeletons, restriction levels,
     * identifier profile) and NFKC/NFC normalization.
     */
    class Unicode {
        public function __construct() {}

        /**
         * Checks whether two strings are visually confusable per UTS #39
         * (equal skeletons). Case matters; lowercase both first for
         * case-insensitive identifier checks.
         *
         * @param string $a
         * @param string $b
         * @return bool - `bool`: `true` if the strings look alike.
         */
        public static function confusable(string $a, string $b): bool {}

        /**
         * Checks whether the string contains invisible or reordering
         * characters: zero-widths (U+200B–U+200F), bidi embedding/override
         * (U+202A–U+202E) and isolate (U+2066–U+2069) controls, word joiner,
         * BOM.
         *
         * @param string $input
         * @return bool - `bool`: `true` if invisible characters are present.
         */
        public static function hasInvisibleCharacters(string $input): bool {}

        /**
         * Checks whether every character is allowed in identifiers by the
         * UTS #39 General Security Profile (excludes deprecated, private-use,
         * and purely-decorative characters).
         *
         * @param string $input
         * @return bool - `bool`: `true` if all characters are identifier-safe.
         */
        public static function isIdentifierSafe(string $input): bool {}

        /**
         * Checks whether the string is written in a single Unicode script.
         * Mixed-script identifiers (`раyраl` mixing Cyrillic and Latin) are the
         * classic homoglyph-attack shape.
         *
         * @param string $input
         * @return bool - `bool`: `true` if all characters resolve to one script.
         */
        public static function isSingleScript(string $input): bool {}

        /**
         * Applies NFC (canonical) normalization — the form to use for general
         * text where compatibility folding would lose meaning.
         *
         * @param string $input
         * @return string - `string`: The NFC-normalized string.
         */
        public static function nfc(string $input): string {}

        /**
         * Applies NFKC (compatibility) normalization. This is the right
         * normalization before storing or comparing identifiers: it folds
         * full-width letters, ligatures and font variants into their plain
         * forms (`ｐａｙｐａｌ` → `paypal`, `ﬁ` → `fi`).
         *
         * @param string $input
         * @return string - `string`: The NFKC-normalized string.
         */
        public static function nfkc(string $input): string {}

        /**
         * Returns the UTS #39 restriction level of the string, from strictest
         * to loosest: `ascii-only`, `single-script`, `highly-restrictive`,
         * `moderately-restrictive`, `minimally-restrictive`, `unrestricted`.
         * A sane policy for usernames is to require at least
         * `highly-restrictive`.
         *
         * @param string $input
         * @return string - `string`: The restriction level name.
         */
        public static function restrictionLevel(string $input): string {}

        /**
         * Computes the UTS #39 confusable skeleton. Two strings whose skeletons
         * are equal look alike to a human (`pаypal` with a Cyrillic `а` has the
         * skeleton `paypal`). Store the skeleton of each username and enforce
         * uniqueness on it, not on the raw string.
         *
         * @param string $input
         * @return string - `string`: The confusable skeleton.
         */
        public static function skeleton(string $input): string {}

        /**
         * Removes invisible and reordering characters (see
         * `hasInvisibleCharacters()`).
         *
         * @param string $input
         * @return string - `string`: The string without invisible characters.
         */
        public static function stripInvisibleCharacters(string $input): string {}
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
