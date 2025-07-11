# php-hardened-rs

A PHP extension powered by **Rust** 🦀 and [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), delivering
essential security utilities for PHP applications. It provides following core classes:

- **Hardened\Hostname** — secure hostname parsing, normalization, and comparison.
- **Hardened\Path** — safe, purely-lexical filesystem path handling to prevent directory traversal.
  with fine-grained tag, attribute, and URL policy controls.
- **Hardened\Rng** — stateless random-data generator: alphanumeric, alphabetic, byte sequences, integer ranges, and
  custom Unicode or ASCII sampling. Using [rand](https://crates.io/crates/rand) crate.
- **Hardened\CsrfProtection** — synchronized [CSRF](https://owasp.org/www-community/attacks/csrf) token–cookie
  protection using AES-GCM, with a PHP-friendly API for
  token/cookie generation, verification, and cookie management. Using [csrf](https://crates.io/crates/csrf) crate.

As well as blazingly fast sanitizers, ergonomic builders of HTTP security headers (including cross-origin policies).

## Sanitizers (`Hardened\Sanitizers`)

- **Hardened\Sanitizers\HtmlSanitizer** — configurable HTML sanitization
  via [Ammonia](https://github.com/rust-ammonia/ammonia). There's also `truncateAndClean()`

## Security Headers (`Hardened\SecurityHeaders`)

Currently, we provide builders for several HTTP security headers (namespace `Hardened\SecurityHeaders`):

- **StrictTransportPolicy** — builder for HTTP Strict-Transport-Security (HSTS); configure `max-age`,
  `includeSubDomains`, and `preload`, then emit the header.
- **ReferrerPolicy** — Referrer-Policy header builder; initialize with or set any valid policy
  token, build the header value, or send it directly.
- **Whatnot** — builder for miscellaneous HTTP security headers (`X-Frame-Options`,
  `X-XSS-Protection`, `X-Content-Type-Options`, `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,
  and `Integrity-Policy-Report-Only`); configure via `set…()` methods, build a header map with `build()`, or emit all
  via `send()`.

### Cross Origin policies (`Hardened\SecurityHeaders\CrossOrigin`)

- **ResourceSharing** — configure CORS: allowed origins, methods, headers, credentials, exposed headers,
  preflight cache.
- **EmbedderPolicy** — configure `Cross-Origin-Embedder-Policy`: choose between `unsafe-none`,
  `require-corp`, or `credentialless`.
- **OpenerPolicy** — configure `Cross-Origin-Opener-Policy`: e.g. `same-origin`,
  `same-origin-allow-popups`, or `unsafe-none`.
- **ResourcePolicy** — configure `Cross-Origin-Resource-Policy`: choose `same-origin`, `same-site`, or
  `cross-origin`.
- -**ContentSecurityPolicy** — configure `Content-Security-Policy` directives, keyword sources, hosts, automatic
  nonces.
- **ReferrerPolicy** — set any valid `Referrer-Policy` token and emit header.
- **PermissionsPolicy** — configure `Permissions-Policy` features, allow or deny per‐feature with allowlists (`*`,
  `self`, `'src'`, specific origins), build header, or send it.
  directives, keyword sources, hosts, and automatic nonce generation.

**Supported Platforms:** Linux, macOS, Windows (where `ext-php-rs` is available)

---

## Classes

### `Hardened\Hostname`

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

See [example](examples/hostname.php).

| Method                                   | Description                                           |
|------------------------------------------|-------------------------------------------------------|
| `from(mixed $hostname): Hostname`        | Parse or wrap string/Hostname.                        |
| `fromStr(string $hostname): Hostname`    | Parse raw string only.                                |
| `fromUrl(mixed $url): Hostname`          | Extract or wrap Hostname from URL/Hostname.           |
| `equals(mixed $hostname): bool`          | Exact match against string or Hostname.               |
| `equalsStr(string $hostname): bool`      | Exact string match only.                              |
| `equalsAny(mixed $hostnames): bool`      | Any match from list of strings or Hostname instances. |
| `equalsUrl(mixed $url): bool`            | Match against URL or Hostname.                        |
| `equalsAnyUrl(mixed $urls): bool`        | Any match from list of URLs or Hostname instances.    |
| `subdomainOf(mixed $hostname): bool`     | Subdomain check against string or Hostname.           |
| `subdomainOfStr(string $hostname): bool` | Subdomain string check only.                          |
| `subdomainOfAny(mixed $hostnames): bool` | Any subdomain match from mixed list.                  |
| `subdomainOfUrl(string $url): bool`      | Subdomain check from URL.                             |
| `subdomainOfAnyUrl(array $urls): bool`   | Any subdomain from URL or Hostname array.             |

### `Hardened\Path`

- Lexical canonicalization: remove `.` and `..`, collapse separators.
- No filesystem I/O or symlink resolution.
- Validate that a path stays within a given base.
- API Highlights:
    - `Path::from(string|Path $path): Path` — parse path from string.
    - `$path->startsWith(string|Path $prefix): bool` — check if the path string or Path.
    - `$path->append(string|Path $segment): Path` — appends the argument to the path and returns a new Path
    - `$path->appendWithin(string|Path $segment): Path` — append, canonicalize, and enforce subpath constraint.
    - `(string)$path` — string representation.

Note that `Path` is immutable.

See [example](examples/path.php).

| Method                                    | Description                                                                                  |
|-------------------------------------------|----------------------------------------------------------------------------------------------|
| `from(string\|Path $path): Path`          | Parse path from string                                                                       |
| `__construct(string\|Path  $path)`        | Alias for `from()`.                                                                          |
| `fileName(): ?string`                     | Get the final path component, or `null` if none.                                             |
| `path(): string`                          | Get the full canonicalized path as a string.                                                 |
| `__toString(): string`                    | Alias for `path()`.                                                                          |
| `startsWith(string\|Path $prefix): bool`  | Check if this path begins with the given prefix.                                             |
| `append(mixed $segment): Path`            | Append a segment (string/Path), then canonicalize.                                           |
| `appendWithin(mixed $segment): Path`      | Append a segment and enforce that result stays within base.                                  |
| `setFileName(mixed $file_name): Path`     | Replace the file name component.                                                             |
| `setExtension(mixed $extension): Path`    | Replace the file extension (without leading dot).                                            |
| `validateExtension(array $allowed): bool` | Check if the file extension is in a custom allowed list.                                     |
| `validateExtensionImage(): bool`          | Returns `true` if extension is a common image (`png, jpg, jpeg, gif, webp, bmp, tiff, svg`). |
| `validateExtensionVideo(): bool`          | Returns `true` if extension is a common video (`mp4, mov, avi, mkv, webm, flv`).             |
| `validateExtensionAudio(): bool`          | Returns `true` if extension is a common audio (`mp3, wav, ogg, flac, aac`).                  |
| `validateExtensionDocument(): bool`       | Returns `true` if extension is a common document (`pdf, doc, docx, xls, xlsx, ppt, pptx`).   |

### `Hardened\Sanitizers\HtmlSanitizer`

- Provides a powerful fine-grained HTML sanitization using [Ammonia](https://github.com/rust-ammonia/ammonia).
- Configuration methods for URL policies, tags, attributes, and filters.
- Attribute filter callback support
- *A built-in truncator:*
  cleanAndTruncate($html, $max, $flags = ['e'], $etc = '…') is useful when you need to get a snippet of a dynamic HTML
  content. Length of `$etc` is included in the limit. Supported flags:
    - `extended-graphemes` (or `e`) — units of `$max` will be Unicode extended grapheme clusters.
    - `graphemes` (or `g`) — units of `$max` will be Unicode grapheme clusters.
    - __default__` unicode` (or `u`) — units of  `$max` will be Unicode code points.
    - `ascii` (or `a`) — units of  `$max` will be bytes. Even this mode doesn't chop Unicode code points in half.

> Open HTML tags will automatically close at all times, but beware that added closing tags may cause the result to
> flow over `$max` if you are truncating.

See [example](examples/sanitizers/html.php).

| Method                                                                                      | Description                                                                                                           |
|---------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `default(): HtmlSanitizer`                                                                  | Construct a sanitizer with default configuration.                                                                     |
| `clean(string $html): string`                                                               | Sanitize the given HTML string.                                                                                       |
| `cleanAndTruncate(string $html, int $max, array[string] $flags, string $etc = '…'): string` | Sanitize HTML and truncate appending `$etc` if truncated.                                                             |
| `urlRelativeDeny(): void`                                                                   | Deny all relative URLs in attributes.                                                                                 |
| `urlRelativePassthrough(): void`                                                            | Pass through relative URLs unchanged.                                                                                 |
| `urlRelativeRewriteWithBase(string $base_url): void`                                        | Rewrite relative URLs using the given base URL.                                                                       |
| `urlRelativeRewriteWithRoot(string $root, string $path): void`                              | Rewrite relative URLs using a root URL and path prefix.                                                               |
| `linkRel(?string $value): void`                                                             | Set the `rel` attribute for generated `<a>` tags.                                                                     |
| `tags(array $tags): void`                                                                   | Overwrite the set of allowed tags.                                                                                    |
| `addTags(array $tags): void`                                                                | Add additional allowed tags to the existing whitelist.                                                                |
| `rmTags(array $tags): void`                                                                 | Remove tags from the whitelist.                                                                                       |
| `addAllowedClasses(string $tag, array $classes): void`                                      | Add allowed CSS classes for a specific tag.                                                                           |
| `rmAllowedClasses(string $tag, array $classes): void`                                       | Remove allowed CSS classes from a specific tag.                                                                       |
| `addTagAttributes(string $tag, array $attributes): void`                                    | Add allowed attributes to a specific tag.                                                                             |
| `rmTagAttributes(string $tag, array $attributes): void`                                     | Remove attributes from a specific tag.                                                                                |
| `addGenericAttributes(array $attributes): void`                                             | Add generic attributes to all tags.                                                                                   |
| `rmGenericAttributes(array $attributes): void`                                              | Remove generic attributes from all tags.                                                                              |
| `addGenericAttributePrefixes(array $prefixes): void`                                        | Add prefixes for generic attributes.                                                                                  |
| `rmGenericAttributePrefixes(array $prefixes): void`                                         | Remove prefixes for generic attributes.                                                                               |
| `urlSchemes(array $schemes): void`                                                          | Whitelist URL schemes (e.g., "http", "https").                                                                        |
| `stripComments(bool $strip): void`                                                          | Enable or disable HTML comment stripping.                                                                             |
| `willStripComments(): bool`                                                                 | Return whether HTML comments will be stripped.                                                                        |
| `idPrefix(?string $prefix): void`                                                           | Prefix all `id` attributes with the given string.                                                                     |
| `filterStyleProperties(array $props): void`                                                 | Filter CSS style properties allowed in `style` attributes.                                                            |
| `setTagAttributeValue(string $tag, string $attribute, string $value): void`                 | Set single tag attribute value.                                                                                       |
| `cloneTags(): array`                                                                        | Return configured tags as a vector of strings.                                                                        |
| `cloneCleanContentTags(): array`                                                            | Get all configured clean-content tags.                                                                                |
| `genericAttributes(array $attrs): void`                                                     | Bulk overwrite generic attributes.                                                                                    |
| `genericAttributePrefixes(array $prefixes): void`                                           | Bulk overwrite generic attribute prefixes.                                                                            |
| `addTagAttributeValues(string $tag, string $attr, array $values): void`                     | Add tag attribute values.                                                                                             |
| `rmTagAttributeValues(string $tag, string $attr, array $values): void`                      | Remove tag attribute values.                                                                                          |
| `getSetTagAttributeValue(string $tag, string $attr): ?string`                               | Get a single set_tag_attribute_value.                                                                                 |
| `isUrlRelativeDeny(): bool`                                                                 | Check URL relative policy: Deny.                                                                                      |
| `isUrlRelativePassThrough(): bool`                                                          | Check URL relative policy: PassThrough.                                                                               |
| `isUrlRelativeCustom(): bool`                                                               | Check URL relative policy: custom (Rewrite).                                                                          |
| `attributeFilter(callable $fn): void`                                                       | Set attribute filter callback: `(string $element, string $attribute, string $value) -> string \|null`.                |
| **`cleanContentTags(array $tags): void`**                                                   | Sets the tags whose contents will be completely removed from the output.                                              |
| **`addCleanContentTags(array $tags): void`**                                                | Add additional blacklisted clean-content tags without overwriting old ones.                                           |
| **`rmCleanContentTags(array $tags): void`**                                                 | Remove already-blacklisted clean-content tags.                                                                        |
| `isValidUrl(string $url): bool`                                                             | Checks whether a URL is allowed by the configured scheme whitelist or, for relative URLs, by the relative-URL policy. |

### `Hardened\Rng`

- Stateless random-data generator.
- Static methods to create random alphanumeric or alphabetic strings (`alphanumeric()`, `alphabetic()`).
- Byte sequences (`bytes()`), integer arrays (`ints()`), and single integers (`int()`) with inclusive ranges.
- Custom sampling from arbitrary Unicode code points (`customUnicodeChars()`), grapheme clusters (
  `customUnicodeGraphemes()`), or ASCII sets (`customAscii()`).

See [example](examples/rng.php).

| Method                                                       | Description                                                                                                        |
|--------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `alphanumeric(int $len): string`                             | Generate a random ASCII alphanumeric string of length `$len`.                                                      |
| `alphabetic(int $len): string`                               | Generate a random ASCII alphabetic string of length `$len`.                                                        |
| `bytes(int $len): string`                                    | Generate `$len` random bytes and return them as a binary string.                                                   |
| `ints(int $len, int $low, int $high): array`                 | Generate an array of `$len` random integers in the inclusive range `[$low, $high]`.                                |
| `int(int $low, int $high): int`                              | Generate a single random integer in the inclusive range `[$low, $high]`.                                           |
| `customUnicodeChars(int $len, string $chars): string`        | Generate a string of `$len` random Unicode **code points** sampled from the characters in `$chars`.                |
| `customUnicodeGraphemes(int $len, string $chars): string`    | Generate a string of `$len` random Unicode **extended grapheme clusters** sampled from the substrings in `$chars`. |
| `customAscii(int $len, string $chars): string`               | Generate a string of `$len` random ASCII characters sampled from the bytes in `$chars`.                            |
| `chooseMultiple(int $amount, array $choices): array`         | Randomly select exactly `$amount` distinct elements from `$choices`; throws if `$amount` exceeds available.        |
| `chooseWeighted(array $choices): array`                      | Randomly select one `[value, weight]` pair from `$choices` where `weight` is integer; returns `[value, weight]`.   |
| `chooseMultipleWeighted(int $amount, array $choices): array` | Randomly select `$amount` elements from weighted `[value, weight]` pairs (float weight) without replacement.       |

### `Hardened\CsrfProtection`

- Synchronized token–cookie [CSRF](https://owasp.org/www-community/attacks/csrf) protection using AES-GCM.
- Constructor: `__construct($key, $ttl, $previousTokenValue = null)`.
- Token & cookie getters: `token()`, `cookie()`.
- Validation: `verifyToken($token, $cookie = null)` (auto-fetches cookie if omitted).
- Cookie management: `setCookieName()`, `cookieName()`,
  `setCookie($expires = null, $path = null, $domain = null, $secure = null, $httponly = null)`.

See [example](examples/csrf-protection.php).

| Method                                                                                                                              | Description                                                                        |
|-------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| `__construct(string $key, int $ttl, ?string $previousTokenValue = null): void`                                                      | Initialize a CSRF protection instance.                                             |
| `verifyToken(string $token, ?string $cookie = null): void`                                                                          | Validate the given token & cookie pair.                                            |
| `cookie(): string`                                                                                                                  | Return the Base64URL-encoded CSRF cookie value to send via `Set-Cookie`.           |
| `token(): string`                                                                                                                   | Return the Base64URL-encoded CSRF token value to embed in forms or headers.        |
| `setCookieName(string $name): void`                                                                                                 | Override the name used for the CSRF cookie.                                        |
| `cookieName(): string`                                                                                                              | Get the current CSRF cookie name (default is `csrf`).                              |
| `setCookie(?int $expires = null, ?string $path = null, ?string $domain = null, ?bool $secure = null, ?bool $httponly = null): void` | Send the CSRF cookie via PHP’s `setcookie()` function using native argument order. |

### `Hardened\SecurityHeaders\ContentSecurityPolicy`

- Builder for HTTP Content-Security-Policy headers.
- Configure directives (`default-src`, `script-src`, etc.) with keyword tokens and host sources via `setRule()`.
- Automatically generates nonces for `'nonce-…'` directives.
- Produces a valid header string with `build()`, and convenience method `send()` to emit it.
- Retrieve the last-generated nonce with `getNonce()`.

See [example](examples/security-headers/content-security-policy.php).

| Method                                                           | Description                                                                                                     |
|------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `__construct()`                                                  | Alias for `new()`, initializes an empty CSP builder.                                                            |
| `new(): ContentSecurityPolicy`                                   | Construct a new CSP builder with no directives set.                                                             |
| `setRule(string $rule, array $keywords, ?array $sources): mixed` | Set or replace a CSP directive with the given keywords (`'self'`, `'nonce'`, etc.) and host sources.            |
| `build(): string`                                                | Build the `Content-Security-Policy` header value from the configured directives.                                |
| `send(): mixed`                                                  | Send the constructed CSP header to the client (via PHP SAPI).                                                   |
| `getNonce(): ?string`                                            | Return the most recently generated nonce (without the `'nonce-'` prefix), or `null` if none has been generated. |
| `resetNonce(): void`                                             | Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.                     |

### `Hardened\SecurityHeaders\StrictTransportSecurity`

- HTTP Strict Transport Security (HSTS) header builder.
- Configure `max-age`, `includeSubDomains`, and `preload` flags for best‐practice transport security.
- Build the header string with `build()`, or emit it directly with `send()` (uses PHP `header()`).

See [example](examples/security-headers/strict-transport-security.php).

| Method                                  | Description                                                                                                 |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------|
| `__construct()`                         | Initialize with `max-age=0`, no subdomains, no preload.                                                     |
| `maxAge(int $maxAge): void`             | Set the `max-age` directive (in seconds).                                                                   |
| `includeSubDomains(bool $enable): void` | Enable or disable the `includeSubDomains` flag.                                                             |
| `preload(bool $enable): void`           | Enable or disable the `preload` flag.                                                                       |
| `build(): string`                       | Return the `Strict-Transport-Security` header value, e.g. `"max-age=31536000; includeSubDomains; preload"`. |
| `send(): void`                          | Emit the header via PHP `header()` function.                                                                |

### `Hardened\SecurityHeaders\CrossOrigin\ResourceSharing`

- CORS policy builder for HTTP responses.
- Configure allowed origins, methods, headers, credentials flag, exposed headers, and preflight cache duration.
- Build a map of header names → values with `build()`, or emit them directly with `send()`.

See [example](examples/security-headers/cross-origin/resource-sharing.php).

| Method                                  | Description                                                                   |
|-----------------------------------------|-------------------------------------------------------------------------------|
| `__construct()`                         | Initialize with no restrictions (empty lists, credentials=false, max\_age=0). |
| `allowOrigins(array $origins): void`    | Set `Access-Control-Allow-Origin` values (e.g. `['*']` or specific domains).  |
| `allowMethods(array $methods): void`    | Set `Access-Control-Allow-Methods` values (e.g. `['GET','POST']`).            |
| `allowHeaders(array $headers): void`    | Set `Access-Control-Allow-Headers` values (e.g. `['Content-Type']`).          |
| `allowCredentials(bool $enable): void`  | Enable `Access-Control-Allow-Credentials: true` when `$enable` is `true`.     |
| `exposeHeaders(array $headers): void`   | Set `Access-Control-Expose-Headers` values for response exposure to client.   |
| `maxAge(int $seconds): void`            | Set `Access-Control-Max-Age` (in seconds) for caching preflight responses.    |
| `build(): array`                      ` | Return an associative array of header names → values to send.                 |
| `send(): void`                          | Emit all configured CORS headers via PHP `header()` calls.                    |

### Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicy

- **Cross-Origin-Embedder-Policy** header builder.
- Supported policies:
    - `unsafe-none` (default)
    - `require-corp`
    - `credentialless`
- `__construct(?string $policy = null)` initialize with optional policy.
- `set_policy(string $policy)` change policy; throws on invalid tokens.
- `build(): string` returns the header value.
- `send(): void` emits `header("Cross-Origin-Embedder-Policy: …")`.

See [example](examples/security-headers/cross-origin/embedder-policy.php).

| Method                                      | Description                                                                                                                       |
|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `__construct(?string $policy = null): self` | Create a new COEP builder, defaults to `"unsafe-none"` if no policy is provided.                                                  |
| `set(string $policy): void`                 | Set the Cross-Origin-Embedder-Policy to one of `"unsafe-none"`, `"require-corp"`, or `"credentialless"`. Throws on invalid token. |
| `build(): string`                           | Return the header value, e.g. `"require-corp"`.                                                                                   |
| `send(): void`                              | Emit `Cross-Origin-Embedder-Policy: <value>` via PHP `header()`; errors if `header()` cannot be called.                           |

See [example](examples/security-headers/cross-origin/embedder-policy.php).

### Hardened\SecurityHeaders\CrossOrigin\OpenerPolicy

- Builder for the `Cross-Origin-Opener-Policy` response header.
- Supported values:
    - `unsafe-none` (default)
    - `same-origin`
    - `same-origin-allow-popups`
- Methods:
    - `__construct(?string $policy = null)` – initialize with an optional policy.
    - `set(string $policy): void` – change policy at any time.
    - `build(): string` – returns the policy token (e.g. `"same-origin"`).
    - `send(): void` – emits `Cross-Origin-Opener-Policy: <value>` via PHP `header()`.

See [example](examples/security-headers/cross-origin/opener-policy.php).

### Hardened\SecurityHeaders\CrossOrigin\ResourcePolicy

* Builder for the `Cross-Origin-Resource-Policy` (CORP) header.
* Configure one of the standard CORP directives (`same-origin`, `same-site`, `cross-origin`) via constructor or
  `setPolicy()`.
* Generate the header value with `build()`, or emit it directly with `send()`.

```php
// PHP example
use Hardened\SecurityHeaders\CrossOrigin\ResourcePolicy;

$rp = new ResourcePolicy();              // defaults to "same-origin"
$rp->setPolicy('cross-origin');          // switch to "cross-origin"
header('Cross-Origin-Resource-Policy: ' . $rp->build());
```

See [example](examples/security-headers/cross-origin/resource-policy.php).

#### API Reference

| Method                                | Description                                                  |
|---------------------------------------|--------------------------------------------------------------|
| `__construct(?string $policy = null)` | Instantiate builder; defaults to `"same-origin"` if `null`.  |
| `setPolicy(string $policy): void`     | Set a new CORP token; throws on invalid value.               |
| `build(): string`                     | Return the configured policy token.                          |
| `send(): void`                        | Emit `Cross-Origin-Resource-Policy: <value>` via `header()`. |

### Hardened\SecurityHeaders\ReferrerPolicy

- Referrer-Policy header builder for HTTP responses.
- Initialize with an optional policy token or configure via `set()`; enforces only valid CSP values.
- Build the header value with `build()`, or emit it directly with `send()`.

See [example](examples/security-headers/referrer-policy.php).

| Method                                | Description                                                  |
|---------------------------------------|--------------------------------------------------------------|
| `__construct(?string $policy = null)` | Create builder with default `no-referrer` or given token.    |
| `set(string $policy): void`           | Set a new policy token; throws on invalid value.             |
| `policy(): string`                    | Get the current policy token.                                |
| `build(): string`                     | Build the header value to pass to `header()`.                |
| `send(): void`                        | Emit `Referrer-Policy: <value>` via PHP `header()` function. |

### Hardened\SecurityHeaders\Whatnot

- Builder for miscellaneous HTTP security headers:  
  `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`,  
  `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,  
  and `Integrity-Policy-Report-Only`.
- Strongly-typed enums for frame & XSS modes, with optional URIs for “ALLOW-FROM” and reporting.
- Configure each header with `set…()` methods, then gather with `build()` or emit via `send()`.

See [example](examples/security-headers/whatnot.php).

| Method                                                                                     | Description                                                                                                     |
|--------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `__construct(): void`                                                                      | Initialize builder with all headers disabled.                                                                   |
| `setFrameOptions(string $mode, ?string $uri): void`                                        | Set `X-Frame-Options`: `"DENY"`, `"SAMEORIGIN"`, or `"ALLOW-FROM"` (URI required for `ALLOW-FROM`).             |
| `setXssProtection(string $mode, ?string $reportUri): void`                                 | Set `X-XSS-Protection`: `"0"`/`"off"`, `"1"`/`"on"`, or `"1; mode=block"`; optional report URI when mode=`"1"`. |
| `setNosniff(bool $enable): void`                                                           | Enable or disable `X-Content-Type-Options: nosniff`.                                                            |
| `setPermittedCrossDomainPolicies(string $value): void`                                     | Set `X-Permitted-Cross-Domain-Policies`: `"none"`, `"master-only"`, `"by-content-type"`, or `"all"`.            |
| `setReportTo(string $group, int $maxAge, bool $includeSubdomains, array $endpoints): void` | Configure `Report-To` header with group name, retention (`max_age`), subdomain flag, and list of endpoint URLs. |
| `setIntegrityPolicy(string $policy): void`                                                 | Set `Integrity-Policy` header value.                                                                            |
| `setIntegrityPolicyReportOnly(string $policy): void`                                       | Set `Integrity-Policy-Report-Only` header value.                                                                |
| `build(): array<string,string>`                                                            | Return all configured headers & values as an associative array of header names to values.                       |
| `send(): void`                                                                             | Emit each header via PHP `header()` calls.                                                                      |

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

## Running Tests

```bash
cargo test
```

PHP examples in `examples` directory are getting smoke tested automatically with `cargo test` (provided that you have
PHP installed).

---

## License

MIT License — see [LICENSE](LICENSE) for details.


