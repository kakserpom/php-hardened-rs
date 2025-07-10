# php-hardened-rs

A PHP extension powered by **Rust** 🦀 and [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), delivering
essential security utilities for PHP applications. It provides five core classes:

1. **Hardened\Hostname** — secure hostname parsing, normalization, and comparison.
2. **Hardened\Path** — safe, purely-lexical filesystem path handling to prevent directory traversal.
3. **Hardened\HtmlSanitizer** — configurable HTML sanitization via [Ammonia](https://github.com/rust-ammonia/ammonia),
   with fine-grained tag, attribute, and URL policy controls.
4. **Hardened\ContentSecurityPolicy** — builder for HTTP Content-Security-Policy headers; configure directives, keyword
   sources, hosts, and automatic nonce generation.
5. **Hardened\Rng** — stateless random-data generator: alphanumeric, alphabetic, byte sequences, integer ranges, and
   custom Unicode or ASCII sampling.

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

### Hardened\HtmlSanitizer

- Wraps Ammonia `Builder` for fine-grained HTML sanitization.
- Configuration methods for URL policies, tags, attributes, and filters.
- Thread-safe attribute filter callback support.

### Hardened\ContentSecurityPolicy

- Builder for HTTP Content-Security-Policy headers.
- Configure directives (`default-src`, `script-src`, etc.) with keyword tokens and host sources via `setRule()`.
- Automatically generates nonces for `'nonce-…'` directives.
- Produces a valid header string with `build()`, and convenience method `send()` to emit it.
- Retrieve the last-generated nonce with `getNonce()`.

### Hardened\Rng

- Stateless random-data generator.
- Static methods to create random alphanumeric or alphabetic strings (`alphanumeric()`, `alphabetic()`).
- Byte sequences (`bytes()`), integer arrays (`ints()`), and single integers (`int()`) with inclusive ranges.
- Custom sampling from arbitrary Unicode code points (`customUnicodeChars()`), grapheme clusters (
  `customUnicodeGraphemes()`), or ASCII sets (`customAscii()`).

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

## Usage

### Hardened\Hostname

```php
<?php
use Hardened\Hostname;

var_dump(Hostname::fromUrl("https://example.com/php")->equals("eXaMple.com.")); 
// bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("eXaMple.com."));
// bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("example.co.uk"));
// bool(false)
```

### Hardened\Path

```php
<?php
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
```

### Hardened\HtmlSanitizer

```php
<?php
use Hardened\HtmlSanitizer;

$sanitizer = HtmlSanitizer::default();
$sanitizer->urlRelativeDeny();
$sanitizer->tags(["a", "p"]);
$sanitizer->filterStyleProperties(["color", "font-size"]);

var_dump($sanitizer->clean("<a href='../evil'>Click</a><p>"));
// "<a rel="noopener noreferrer">Click</a><p></p>"

var_dump($sanitizer->clean(
  "<a href='https://github.com/' style='font-size: 12px; color: red; font-weight: bold;'>Click</a>"
));
// "<a href="https://github.com/" style="font-size:12px;color:red" rel="noopener noreferrer">Click</a>"

var_dump($sanitizer->isValidUrl("https://github.com"));
// bool(true)

var_dump($sanitizer->isValidUrl("javascript:alert(1)"));
// bool(false)

var_dump($sanitizer->isValidUrl("foo"));
// bool(false)
```

### Hardened\ContentSecurityPolicy

```php
<?php
use Hardened\ContentSecurityPolicy;

// Create a new CSP builder
$policy = new ContentSecurityPolicy();

// default-src 'self' *.site.tld blob:
$policy->setRule(
    ContentSecurityPolicy::DEFAULT_SRC,
    [ContentSecurityPolicy::SELF],
    ['*.site.tld', 'blob:']
);

// script-src 'self' 'nonce-…' https://cdn.site.tld/js
$policy->setRule(
    ContentSecurityPolicy::SCRIPT_SRC,
    [ContentSecurityPolicy::SELF, ContentSecurityPolicy::NONCE],
    ['https://cdn.site.tld/js']
);

// style-src 'self' 'nonce-…' https://fonts.googleapis.com
$policy->setRule(
    ContentSecurityPolicy::STYLE_SRC,
    [ContentSecurityPolicy::SELF, ContentSecurityPolicy::NONCE],
    ['https://fonts.googleapis.com']
);

// img-src 'self' data: *.images.site.tld
$policy->setRule(
    ContentSecurityPolicy::IMG_SRC,
    [ContentSecurityPolicy::SELF],
    ['data:', '*.images.site.tld']
);

// connect-src 'self' https://api.site.tld
$policy->setRule(
    ContentSecurityPolicy::CONNECT_SRC,
    [ContentSecurityPolicy::SELF],
    ['https://api.site.tld']
);

// frame-ancestors 'none'
$policy->setRule(
    ContentSecurityPolicy::FRAME_ANCESTORS,
    [],        // no keywords
    []         // empty list => effectively 'none'
);

// Build and display the value
var_dump($policy->build());

// Get and display the nonce
var_dump($policy->getNonce());

// Build and send the header
$policy->send();
```

### Hardened\Rng

```php
<?php
use Hardened\Rng;

// Random alphanumeric string of length 10
var_dump(Rng::alphanumeric(10));
// Example: string(10) "A1b2C3d4E5"

// 32 random bytes (binary data)
var_dump(Rng::bytes(32));
// Example: string(32) "\x8F\xA3\xC1\x7E\x09…"

// 3 random integers between 0 and 100
var_dump(Rng::ints(3, 0, 100));
// Example: array(3) { [0]=> int(42) [1]=> int(7) [2]=> int(89) }

// A single random integer between 0 and 100
var_dump(Rng::int(0, 100));
// Example: int(84)

// 10 random Unicode code‐points sampled from "Абвгд"
var_dump(Rng::customUnicodeChars(10, "Абвгд"));
// Example: string(20) "гдбАвдгАбвгд"

// 10 random ASCII characters sampled from "AbcDef"
var_dump(Rng::customAscii(10, "AbcDef"));
// Example: string(10) "cDfDefAbcD"

// 4 random Unicode grapheme clusters from the emoji set
var_dump(Rng::customUnicodeGraphemes(4, "🙈🙉🙊"));
// Example: string(16) "🙊🙈🙉🙊"

// Randomly pick one element
$choice = Rng::choose(['apple', 'banana', 'cherry']);
var_dump($choice);
// Example: string(6) "banana"

// Pick 2 distinct elements
$multiple = Rng::chooseMultiple(2, ['red','green','blue','yellow']);
var_dump($multiple);
// Example: array(2) { [0]=> string(5) "green" [1]=> string(4) "blue" }

// Weighted pick (integer weights)
$weighted = Rng::chooseWeighted([
    ['gold',  5],
    ['silver', 3],
    ['bronze',1],
]);
var_dump($weighted);
// Example: array(2) { [0]=> string(4) "gold" [1]=> int(5) }

// Pick 2 elements from weighted set (float weights)
$multiWeighted = Rng::chooseMultipleWeighted(2, [
    ['A', 0.1],
    ['B', 0.7],
    ['C', 0.2],
]);
var_dump($multiWeighted);
// Example: array(2) { [0]=> string(1) "B" [1]=> string(1) "C" }
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

| Method                                 | Signature | Description                                                 |
|----------------------------------------|-----------|-------------------------------------------------------------|
| `from(mixed $path): Path`              | static    | Parse or wrap a string/Zval/Path and canonicalize it.       |
| `__construct(mixed $path)`             | Instance  | Alias for `from()`.                                         |
| `startsWith(mixed $prefix): bool`      | Instance  | Check if this path begins with the given prefix.            |
| `join(mixed $segment): Path`           | Instance  | Append a segment (string/Zval/Path), then canonicalize.     |
| `joinWithin(mixed $segment): Path`     | Instance  | Append a segment and enforce that result stays within base. |
| `setFileName(mixed $file_name): Path`  | Instance  | Replace the file name component.                            |
| `setExtension(mixed $extension): Path` | Instance  | Replace the file extension (without leading dot).           |
| `fileName(): ?string`                  | Instance  | Get the final path component, or `null` if none.            |
| `path(): string`                       | Instance  | Get the full canonicalized path as a string.                |
| `__toString(): string`                 | Instance  | Alias for `path()`.                                         |

### Class `Hardened\HtmlSanitizer`

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

### Class `Hardened\ContentSecurityPolicy`

| Method                                                           | Signature | Description                                                                                                     |
|------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------------------------|
| `__construct()`                                                  | Instance  | Alias for `new()`, initializes an empty CSP builder.                                                            |
| `new(): ContentSecurityPolicy`                                   | static    | Construct a new CSP builder with no directives set.                                                             |
| `setRule(string $rule, array $keywords, ?array $sources): mixed` | Instance  | Set or replace a CSP directive with the given keywords (`'self'`, `'nonce'`, etc.) and host sources.            |
| `build(): string`                                                | Instance  | Build the `Content-Security-Policy` header value from the configured directives.                                |
| `send(): mixed`                                                  | Instance  | Send the constructed CSP header to the client (via PHP SAPI).                                                   |
| `getNonce(): ?string`                                            | Instance  | Return the most recently generated nonce (without the `'nonce-'` prefix), or `null` if none has been generated. |
| `resetNonce(): void`                                             | Instance  | Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.                     |

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

---

## Running Tests

```bash
cargo test
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.


