# php-hardened-rs

A PHP extension powered by **Rust** 🦀 and [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), delivering
essential security utilities for PHP applications. It provides following core classes:

1. **Hardened\Hostname** — secure hostname parsing, normalization, and comparison.
2. **Hardened\Path** — safe, purely-lexical filesystem path handling to prevent directory traversal.
3. **Hardened\Sanitizers\HtmlSanitizer** — configurable HTML sanitization via [Ammonia](https://github.com/rust-ammonia/ammonia),
   with fine-grained tag, attribute, and URL policy controls.
4. **Hardened\Rng** — stateless random-data generator: alphanumeric, alphabetic, byte sequences, integer ranges, and
   custom Unicode or ASCII sampling.
5. **Hardened\CsrfProtection** — synchronized CSRF token–cookie protection using AES-GCM, with a PHP-friendly API for
   token/cookie generation, verification, and cookie management.

## Security Headers

Currently, we provide builders for several HTTP security headers (namespace `Hardened\SecurityHeaders`):

- **ContentSecurityPolicy** — configure `Content-Security-Policy` directives, keyword sources, hosts, automatic nonces.
- **Hsts** — configure `Strict-Transport-Security: max-age`, `includeSubDomains`, `preload`.
- **CorsPolicy** — configure CORS: allowed origins, methods, headers, credentials, exposed headers, preflight cache.
- **ReferrerPolicy** — set any valid `Referrer-Policy` token and emit header.
- **PermissionsPolicy** — configure `Permissions-Policy` features, allow or deny per‐feature with allowlists (`*`,
  `self`, `'src'`, specific origins), build header, or send it.
- **ContentSecurityPolicy** — builder for HTTP Content-Security-Policy headers; configure
  directives, keyword sources, hosts, and automatic nonce generation.
- **Hsts** — builder for HTTP Strict-Transport-Security (HSTS); configure `max-age`,
  `includeSubDomains`, and `preload`, then emit the header.
- **CorsPolicy** — CORS policy builder; configure allowed origins, methods, headers,
  credentials flag, exposed headers, and preflight cache duration, then emit the necessary headers.
- **ReferrerPolicy** — Referrer-Policy header builder; initialize with or set any valid policy
  token, build the header value, or send it directly.
- **Hardened\Rng** — stateless random-data generator: alphanumeric, alphabetic, byte sequences, integer ranges, and
  custom Unicode or ASCII sampling.
- **Hardened\CsrfProtection** — synchronized CSRF token–cookie protection using AES-GCM, with a PHP-friendly API for
  token/cookie generation, verification, and cookie management.
- **MiscHeaders** — builder for miscellaneous HTTP security headers (`X-Frame-Options`,
  `X-XSS-Protection`, `X-Content-Type-Options`, `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,
  and `Integrity-Policy-Report-Only`); configure via `set…()` methods, build a header map with `build()`, or emit all
  via `send()`.

**Supported Platforms:** Linux, macOS, Windows (where `ext-php-rs` is available)

---

## Features

### Hardened\Hostname

- Parse or wrap existing `Hostname` objects.
- Methods accept mixed inputs (`string` or `Hostname` instances).
- Compare hosts, wildcard allowlists, and subdomain checks.
- API Highlights:
    - `Hostname::from(mixed $hostname): Hostname` — parse or wrap a hostname value.
    - `Hostname::fromStr(string $hostname): Hostname` — parse raw string only.
    - `Hostname::fromUrl(mixed $url): Hostname` — extract and wrap hostname from URL or Hostname.
    - `$host->equals(mixed $hostname): bool` — exact match against string or instance.
    - `$host->equalsStr(string $hostname): bool` — exact string comparison.
    - `$host->equalsAny(mixed $hostnames): bool` — match any from list of strings or instances.
    - `$host->equalsUrl(mixed $url): bool` — match against URL or Hostname.
    - `$host->equalsAnyUrl(mixed $urls): bool` — any URL or Hostname in list.
    - `$host->subdomainOf(mixed $hostname): bool` — subdomain check against string or instance.
    - `$host->subdomainOfStr(string $hostname): bool` — subdomain string only.
    - `$host->subdomainOfAny(mixed $hostnames): bool` — any in mixed list.
    - `$host->subdomainOfUrl(string $url): bool` — URL or Hostname subdomain check.
    - `$host->subdomainOfAnyUrl(array $urls): bool` — any URL or Hostname array.

#### Example

```php
use Hardened\Hostname;

var_dump(Hostname::fromUrl("https://example.com/php")->equals("eXaMple.com.")); 
// bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("eXaMple.com."));
// bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("example.co.uk"));
// bool(false)
```

### Hardened\Path

- Lexical canonicalization: remove `.` and `..`, collapse separators.
- No filesystem I/O or symlink resolution.
- Validate that a path stays within a given base.
- API Highlights:
    - `Path::from(mixed $path): Path` — parse Zval, string, or Path.
    - `$path->startsWith(mixed $prefix): bool` — prefix string or Path.
    - `$path->join(mixed $segment): Path` — append string or Path.
    - `$path->joinWithin(mixed $segment): Path` — append, canonicalize, and enforce subpath constraint.
    - `(string)$path` — string representation.

#### Example

```php
use Hardened\Path;

$path = Path::from("/foo/bar/data/");

var_dump($path->join("zzz")->startsWith($path));
// bool(true)

var_dump($path->join("zzz")->path());
// string(17) "/foo/bar/data/zzz"

var_dump($path->join("../zzz")->path());
// string(12) "/foo/bar/zzz"

var_dump($path->join("../zzz")->startsWith($path));
// bool(false)

try {
    var_dump($path->joinWithin("../zzz")); // throws
} catch (Throwable $e) {
    echo ";-)" . PHP_EOL;
}


// Create a Path instance
$path = new Path('/var/www/uploads/photo.JPG');

// Check against a custom list
var_dump(
    $path->validateExtension(['png','jpg','jpeg']),  // true
    $path->validateExtension(['gif','bmp'])          // false
);

// Built-in helpers
var_dump(
    $path->validateExtensionImage(),    // true (jpg)
    $path->validateExtensionVideo(),    // false
    $path->validateExtensionAudio(),    // false
    $path->validateExtensionDocument()  // false
);

// Another example: a document path
$doc = new Path('/home/user/report.PDF');
var_dump($doc->validateExtensionDocument()); // true
```

### Hardened\Sanitizers\HtmlSanitizer

- Wraps Ammonia `Builder` for fine-grained HTML sanitization.
- Configuration methods for URL policies, tags, attributes, and filters.
- Attribute filter callback support.

See [example](examples/sanitizers/html-sanitizer.php).

### Hardened\Rng

- Stateless random-data generator.
- Static methods to create random alphanumeric or alphabetic strings (`alphanumeric()`, `alphabetic()`).
- Byte sequences (`bytes()`), integer arrays (`ints()`), and single integers (`int()`) with inclusive ranges.
- Custom sampling from arbitrary Unicode code points (`customUnicodeChars()`), grapheme clusters (
  `customUnicodeGraphemes()`), or ASCII sets (`customAscii()`).

See [example](examples/rng.php).

### Hardened\CsrfProtection

- Synchronized token–cookie CSRF protection using AES-GCM.
- Constructor: `__construct($key, $ttl, $previousTokenValue = null)`.
- Token & cookie getters: `token()`, `cookie()`.
- Validation: `verifyToken($token, $cookie = null)` (auto-fetches cookie if omitted).
- Cookie management: `setCookieName()`, `cookieName()`,
  `setCookie($expires = null, $path = null, $domain = null, $secure = null, $httponly = null)`.

See [example](examples/csrf-protection.php).

### Hardened\SecurityHeaders\ContentSecurityPolicy

- Builder for HTTP Content-Security-Policy headers.
- Configure directives (`default-src`, `script-src`, etc.) with keyword tokens and host sources via `setRule()`.
- Automatically generates nonces for `'nonce-…'` directives.
- Produces a valid header string with `build()`, and convenience method `send()` to emit it.
- Retrieve the last-generated nonce with `getNonce()`.

See [example](examples/security-headers/csp.php).

### Hardened\SecurityHeaders\Hsts

- HTTP Strict Transport Security (HSTS) header builder.
- Configure `max-age`, `includeSubDomains`, and `preload` flags for best‐practice transport security.
- Build the header string with `build()`, or emit it directly with `send()` (uses PHP `header()`).

See [example](examples/security-headers/hsts.php).

### Hardened\SecurityHeaders\CorsPolicy

- CORS policy builder for HTTP responses.
- Configure allowed origins, methods, headers, credentials flag, exposed headers, and preflight cache duration.
- Build a map of header names → values with `build()`, or emit them directly with `send()`.

See [example](examples/security-headers/cors.php).

### Hardened\SecurityHeaders\ReferrerPolicy

- Referrer-Policy header builder for HTTP responses.
- Initialize with an optional policy token or configure via `setPolicy()`; enforces only valid CSP values.
- Build the header value with `build()`, or emit it directly with `send()`.

See [example](examples/security-headers/csp.php).

### Hardened\SecurityHeaders\MiscHeaders

- Builder for miscellaneous HTTP security headers:  
  `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`,  
  `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,  
  and `Integrity-Policy-Report-Only`.
- Strongly-typed enums for frame & XSS modes, with optional URIs for “ALLOW-FROM” and reporting.
- Configure each header with `set…()` methods, then gather with `build()` or emit via `send()`.

See [example](examples/security-headers/misc.php).

### Hardened\SecurityHeaders\PermissionsPolicy

- Builder for the `Permissions-Policy` header.
- Use `allow(feature, origins)` to enable a feature for a list of origins, or `deny(feature)` for an empty allowlist.

See [example](examples/security-headers/misc.php).

---

## Installation

Install with [`cargo-php`](https://github.com/davidcole1340/ext-php-rs):

```bash
# Install cargo-php if you haven't already
# (ensures you have the latest cargo-php installer)
cargo install cargo-php --locked

# Build and install the PHP extension
cd php-hardened-rs-cdylib
cargo php install --release --yes
```

On **macOS**, you may need to set the deployment target and link flags first:

```bash
export MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | tr -d '
')
export RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup"
```

Enable the extension by adding to your `php.ini`:

```ini
extension=php_hardened_rs
```

---

## API Reference

### Class `Hardened\Hostname`

| Method                                   | Signature | Description                                           |
|------------------------------------------|-----------|-------------------------------------------------------|
| `from(mixed $hostname): Hostname`        | `static`  | Parse or wrap string/Hostname.                        |
| `fromStr(string $hostname): Hostname`    | `static`  | Parse raw string only.                                |
| `fromUrl(mixed $url): Hostname`          | `static`  | Extract or wrap Hostname from URL/Hostname.           |
| `equals(mixed $hostname): bool`          | Instance  | Exact match against string or Hostname.               |
| `equalsStr(string $hostname): bool`      | Instance  | Exact string match only.                              |
| `equalsAny(mixed $hostnames): bool`      | Instance  | Any match from list of strings or Hostname instances. |
| `equalsUrl(mixed $url): bool`            | Instance  | Match against URL or Hostname.                        |
| `equalsAnyUrl(mixed $urls): bool`        | Instance  | Any match from list of URLs or Hostname instances.    |
| `subdomainOf(mixed $hostname): bool`     | Instance  | Subdomain check against string or Hostname.           |
| `subdomainOfStr(string $hostname): bool` | Instance  | Subdomain string check only.                          |
| `subdomainOfAny(mixed $hostnames): bool` | Instance  | Any subdomain match from mixed list.                  |
| `subdomainOfUrl(string $url): bool`      | Instance  | Subdomain check from URL.                             |
| `subdomainOfAnyUrl(array $urls): bool`   | Instance  | Any subdomain from URL or Hostname array.             |

### Class `Hardened\Path`

| Method                                    | Signature | Description                                                                                  |
|-------------------------------------------|-----------|----------------------------------------------------------------------------------------------|
| `from(mixed $path): Path`                 | static    | Parse or wrap a string/Zval/Path and canonicalize it.                                        |
| `__construct(mixed $path)`                | Instance  | Alias for `from()`.                                                                          |
| `fileName(): ?string`                     | Instance  | Get the final path component, or `null` if none.                                             |
| `path(): string`                          | Instance  | Get the full canonicalized path as a string.                                                 |
| `__toString(): string`                    | Instance  | Alias for `path()`.                                                                          |
| `startsWith(mixed $prefix): bool`         | Instance  | Check if this path begins with the given prefix.                                             |
| `join(mixed $segment): Path`              | Instance  | Append a segment (string/Zval/Path), then canonicalize.                                      |
| `joinWithin(mixed $segment): Path`        | Instance  | Append a segment and enforce that result stays within base.                                  |
| `setFileName(mixed $file_name): Path`     | Instance  | Replace the file name component.                                                             |
| `setExtension(mixed $extension): Path`    | Instance  | Replace the file extension (without leading dot).                                            |
| `validateExtension(array $allowed): bool` | Instance  | Check if the file extension is in a custom allowed list.                                     |
| `validateExtensionImage(): bool`          | Instance  | Returns `true` if extension is a common image (`png, jpg, jpeg, gif, webp, bmp, tiff, svg`). |
| `validateExtensionVideo(): bool`          | Instance  | Returns `true` if extension is a common video (`mp4, mov, avi, mkv, webm, flv`).             |
| `validateExtensionAudio(): bool`          | Instance  | Returns `true` if extension is a common audio (`mp3, wav, ogg, flac, aac`).                  |
| `validateExtensionDocument(): bool`       | Instance  | Returns `true` if extension is a common document (`pdf, doc, docx, xls, xlsx, ppt, pptx`).   |

### Class `Hardened\Sanitizers\HtmlSanitizer`

| Method                                                                      | Signature | Description                                                                                                           |
|-----------------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------------------------------|
| `default(): HtmlSanitizer`                                                  | static    | Construct a sanitizer with default configuration.                                                                     |
| `urlRelativeDeny(): void`                                                   | Instance  | Deny all relative URLs in attributes.                                                                                 |
| `urlRelativePassthrough(): void`                                            | Instance  | Pass through relative URLs unchanged.                                                                                 |
| `urlRelativeRewriteWithBase(string $base_url): void`                        | Instance  | Rewrite relative URLs using the given base URL.                                                                       |
| `urlRelativeRewriteWithRoot(string $root, string $path): void`              | Instance  | Rewrite relative URLs using a root URL and path prefix.                                                               |
| `linkRel(?string $value): void`                                             | Instance  | Set the `rel` attribute for generated `<a>` tags.                                                                     |
| `tags(array $tags): void`                                                   | Instance  | Overwrite the set of allowed tags.                                                                                    |
| `addTags(array $tags): void`                                                | Instance  | Add additional allowed tags to the existing whitelist.                                                                |
| `rmTags(array $tags): void`                                                 | Instance  | Remove tags from the whitelist.                                                                                       |
| `addAllowedClasses(string $tag, array $classes): void`                      | Instance  | Add allowed CSS classes for a specific tag.                                                                           |
| `rmAllowedClasses(string $tag, array $classes): void`                       | Instance  | Remove allowed CSS classes from a specific tag.                                                                       |
| `addTagAttributes(string $tag, array $attributes): void`                    | Instance  | Add allowed attributes to a specific tag.                                                                             |
| `rmTagAttributes(string $tag, array $attributes): void`                     | Instance  | Remove attributes from a specific tag.                                                                                |
| `addGenericAttributes(array $attributes): void`                             | Instance  | Add generic attributes to all tags.                                                                                   |
| `rmGenericAttributes(array $attributes): void`                              | Instance  | Remove generic attributes from all tags.                                                                              |
| `addGenericAttributePrefixes(array $prefixes): void`                        | Instance  | Add prefixes for generic attributes.                                                                                  |
| `rmGenericAttributePrefixes(array $prefixes): void`                         | Instance  | Remove prefixes for generic attributes.                                                                               |
| `clean(string $html): string`                                               | Instance  | Sanitize the given HTML string.                                                                                       |
| `urlSchemes(array $schemes): void`                                          | Instance  | Whitelist URL schemes (e.g., "http", "https").                                                                        |
| `stripComments(bool $strip): void`                                          | Instance  | Enable or disable HTML comment stripping.                                                                             |
| `willStripComments(): bool`                                                 | Instance  | Return whether HTML comments will be stripped.                                                                        |
| `idPrefix(?string $prefix): void`                                           | Instance  | Prefix all `id` attributes with the given string.                                                                     |
| `filterStyleProperties(array $props): void`                                 | Instance  | Filter CSS style properties allowed in `style` attributes.                                                            |
| `setTagAttributeValue(string $tag, string $attribute, string $value): void` | Instance  | Set single tag attribute value.                                                                                       |
| `cloneTags(): array`                                                        | Instance  | Return configured tags as a vector of strings.                                                                        |
| `cloneCleanContentTags(): array`                                            | Instance  | Get all configured clean-content tags.                                                                                |
| `genericAttributes(array $attrs): void`                                     | Instance  | Bulk overwrite generic attributes.                                                                                    |
| `genericAttributePrefixes(array $prefixes): void`                           | Instance  | Bulk overwrite generic attribute prefixes.                                                                            |
| `addTagAttributeValues(string $tag, string $attr, array $values): void`     | Instance  | Add tag attribute values.                                                                                             |
| `rmTagAttributeValues(string $tag, string $attr, array $values): void`      | Instance  | Remove tag attribute values.                                                                                          |
| `getSetTagAttributeValue(string $tag, string $attr): ?string`               | Instance  | Get a single set_tag_attribute_value.                                                                                 |
| `isUrlRelativeDeny(): bool`                                                 | Instance  | Check URL relative policy: Deny.                                                                                      |
| `isUrlRelativePassThrough(): bool`                                          | Instance  | Check URL relative policy: PassThrough.                                                                               |
| `isUrlRelativeCustom(): bool`                                               | Instance  | Check URL relative policy: custom (Rewrite).                                                                          |
| `attributeFilter(callable $fn): void`                                       | Instance  | Set attribute filter callback: `(string $element, string $attribute, string $value) -> string \|null`.                |
| **`cleanContentTags(array $tags): void`**                                   | Instance  | Sets the tags whose contents will be completely removed from the output.                                              |
| **`addCleanContentTags(array $tags): void`**                                | Instance  | Add additional blacklisted clean-content tags without overwriting old ones.                                           |
| **`rmCleanContentTags(array $tags): void`**                                 | Instance  | Remove already-blacklisted clean-content tags.                                                                        |
| `isValidUrl(string $url): bool`                                             | Instance  | Checks whether a URL is allowed by the configured scheme whitelist or, for relative URLs, by the relative-URL policy. |

### Class `Hardened\Rng`

| Method                                                       | Signature | Description                                                                                                      |
|--------------------------------------------------------------|-----------|------------------------------------------------------------------------------------------------------------------|
| `alphanumeric(int $len): string`                             | static    | Generate a random ASCII alphanumeric string of length `$len`.                                                    |
| `alphabetic(int $len): string`                               | static    | Generate a random ASCII alphabetic string of length `$len`.                                                      |
| `bytes(int $len): string`                                    | static    | Generate `$len` random bytes and return them as a binary string.                                                 |
| `ints(int $len, int $low, int $high): array`                 | static    | Generate an array of `$len` random integers in the inclusive range `[$low, $high]`.                              |
| `int(int $low, int $high): int`                              | static    | Generate a single random integer in the inclusive range `[$low, $high]`.                                         |
| `customUnicodeChars(int $len, string $chars): string`        | static    | Generate a string of `$len` random Unicode **code points** sampled from the characters in `$chars`.              |
| `customUnicodeGraphemes(int $len, string $chars): string`    | static    | Generate a string of `$len` random Unicode **grapheme clusters** sampled from the substrings in `$chars`.        |
| `customAscii(int $len, string $chars): string`               | static    | Generate a string of `$len` random ASCII characters sampled from the bytes in `$chars`.                          |
| `chooseMultiple(int $amount, array $choices): array`         | static    | Randomly select exactly `$amount` distinct elements from `$choices`; throws if `$amount` exceeds available.      |
| `chooseWeighted(array $choices): array`                      | static    | Randomly select one `[value, weight]` pair from `$choices` where `weight` is integer; returns `[value, weight]`. |
| `chooseMultipleWeighted(int $amount, array $choices): array` | static    | Randomly select `$amount` elements from weighted `[value, weight]` pairs (float weight) without replacement.     |

### Class `Hardened\CsrfProtection`

| Method                                                                                                                              | Signature | Description                                                                        |
|-------------------------------------------------------------------------------------------------------------------------------------|-----------|------------------------------------------------------------------------------------|
| `__construct(string $key, int $ttl, ?string $previousTokenValue = null): void`                                                      | static    | Initialize a CSRF protection instance.                                             |
| `verifyToken(string $token, ?string $cookie = null): void`                                                                          | Instance  | Validate the given token & cookie pair.                                            |
| `cookie(): string`                                                                                                                  | Instance  | Return the Base64URL-encoded CSRF cookie value to send via `Set-Cookie`.           |
| `token(): string`                                                                                                                   | Instance  | Return the Base64URL-encoded CSRF token value to embed in forms or headers.        |
| `setCookieName(string $name): void`                                                                                                 | Instance  | Override the name used for the CSRF cookie.                                        |
| `cookieName(): string`                                                                                                              | Instance  | Get the current CSRF cookie name (default is `csrf`).                              |
| `setCookie(?int $expires = null, ?string $path = null, ?string $domain = null, ?bool $secure = null, ?bool $httponly = null): void` | Instance  | Send the CSRF cookie via PHP’s `setcookie()` function using native argument order. |

### Class `Hardened\SecurityHeaders\ContentSecurityPolicy`

| Method                                                           | Signature | Description                                                                                                     |
|------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------------------------|
| `__construct()`                                                  | Instance  | Alias for `new()`, initializes an empty CSP builder.                                                            |
| `new(): ContentSecurityPolicy`                                   | static    | Construct a new CSP builder with no directives set.                                                             |
| `setRule(string $rule, array $keywords, ?array $sources): mixed` | Instance  | Set or replace a CSP directive with the given keywords (`'self'`, `'nonce'`, etc.) and host sources.            |
| `build(): string`                                                | Instance  | Build the `Content-Security-Policy` header value from the configured directives.                                |
| `send(): mixed`                                                  | Instance  | Send the constructed CSP header to the client (via PHP SAPI).                                                   |
| `getNonce(): ?string`                                            | Instance  | Return the most recently generated nonce (without the `'nonce-'` prefix), or `null` if none has been generated. |
| `resetNonce(): void`                                             | Instance  | Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.                     |

### Class `Hardened\SecurityHeaders\Hsts`

| Method                                  | Signature | Description                                                                                                 |
|-----------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------|
| `__construct()`                         | static    | Initialize with `max-age=0`, no subdomains, no preload.                                                     |
| `maxAge(int $maxAge): void`             | Instance  | Set the `max-age` directive (in seconds).                                                                   |
| `includeSubDomains(bool $enable): void` | Instance  | Enable or disable the `includeSubDomains` flag.                                                             |
| `preload(bool $enable): void`           | Instance  | Enable or disable the `preload` flag.                                                                       |
| `build(): string`                       | Instance  | Return the `Strict-Transport-Security` header value, e.g. `"max-age=31536000; includeSubDomains; preload"`. |
| `send(): void`                          | Instance  | Emit the header via PHP `header()` function.                                                                |

### Class `Hardened\SecurityHeaders\CorsPolicy`

| Method                                 | Signature                         | Description                                                                   |
|----------------------------------------|-----------------------------------|-------------------------------------------------------------------------------|
| `__construct()`                        | `static`                          | Initialize with no restrictions (empty lists, credentials=false, max\_age=0). |
| `allowOrigins(array $origins): void`   | Instance                          | Set `Access-Control-Allow-Origin` values (e.g. `['*']` or specific domains).  |
| `allowMethods(array $methods): void`   | Instance                          | Set `Access-Control-Allow-Methods` values (e.g. `['GET','POST']`).            |
| `allowHeaders(array $headers): void`   | Instance                          | Set `Access-Control-Allow-Headers` values (e.g. `['Content-Type']`).          |
| `allowCredentials(bool $enable): void` | Instance                          | Enable `Access-Control-Allow-Credentials: true` when `$enable` is `true`.     |
| `exposeHeaders(array $headers): void`  | Instance                          | Set `Access-Control-Expose-Headers` values for response exposure to client.   |
| `maxAge(int $seconds): void`           | Instance                          | Set `Access-Control-Max-Age` (in seconds) for caching preflight responses.    |
| `build(): array`                       | Instance → `array<string,string>` | Return an associative array of header names → values to send.                 |
| `send(): void`                         | Instance                          | Emit all configured CORS headers via PHP `header()` calls.                    |

### Class `Hardened\SecurityHeaders\RefererPolicy`

| Method                                | Signature                | Description                                                  |
|---------------------------------------|--------------------------|--------------------------------------------------------------|
| `__construct(?string $policy = null)` | static                   | Create builder with default `no-referrer` or given token.    |
| `setPolicy(string $policy): void`     | Instance                 | Set a new policy token; throws on invalid value.             |
| `policy(): string`                    | Instance, returns string | Get the current policy token.                                |
| `build(): string`                     | Instance, returns string | Build the header value to pass to `header()`.                |
| `send(): void`                        | Instance                 | Emit `Referrer-Policy: <value>` via PHP `header()` function. |

### Class `Hardened\SecurityHeaders\MiscHeaders`

| Method                                                                                     | Signature                                              | Description                                                                                                      |
|--------------------------------------------------------------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `__construct(): void`                                                                      | `static`                                               | Initialize builder with all headers disabled.                                                                    |
| `setFrameOptions(string $mode, ?string $uri): void`                                        | Instance                                               | Set `X-Frame-Options`: `"DENY"`, `"SAMEORIGIN"`, or `"ALLOW-FROM"` (URI required for `ALLOW-FROM`).              |
| `setXssProtection(string $mode, ?string $reportUri): void`                                 | Instance                                               | Set `X-XSS-Protection`: `"0"`/`"off"`, `"1"`/`"on"`, or `"1; mode=block"`; optional report URI when mode=`"1"`.  |
| `setNosniff(bool $enable): void`                                                           | Instance                                               | Enable or disable `X-Content-Type-Options: nosniff`.                                                             |
| `setPermittedCrossDomainPolicies(string $value): void`                                     | Instance                                               | Set `X-Permitted-Cross-Domain-Policies`: `"none"`, `"master-only"`, `"by-content-type"`, or `"all"`.             |
| `setReportTo(string $group, int $maxAge, bool $includeSubdomains, array $endpoints): void` | Instance                                               | Configure `Report-To` header with group name, retention (`max_age`), subdomain flag, and list of endpoint names. |
| `setIntegrityPolicy(string $policy): void`                                                 | Instance                                               | Set `Integrity-Policy` header value.                                                                             |
| `setIntegrityPolicyReportOnly(string $policy): void`                                       | Instance                                               | Set `Integrity-Policy-Report-Only` header value.                                                                 |
| `build(): array<string,string>`                                                            | Instance → associative array of header names to values | Return all configured headers & values.                                                                          |
| `send(): void`                                                                             | Instance                                               | Emit each header via PHP `header()` calls.                                                                       |

---

## Running Tests

```bash
cargo test
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.


