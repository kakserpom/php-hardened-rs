# php-hardened-rs

A PHP extension powered by **Rust** 🦀 and [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), delivering
essential security utilities for PHP applications. It provides three core classes:

1. **Hardened\Hostname** — secure hostname parsing, normalization, and comparison.
2. **Hardened\Path** — safe, purely lexical filesystem path handling to prevent directory traversal.
3. **Hardened\HtmlSanitizer** — configurable HTML sanitization via [Ammonia](https://github.com/rust-ammonia/ammonia).

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

On **macOS**, you may need to set the deployment target and link flags:

```bash
export MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | tr -d '
')
export RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup"

cargo install cargo-php --locked
cd php-hardened-rs-cdylib
cargo php install --release --yes
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

var_dump($sanitizer->clean("<a href='../evil'>Click</a>"));
// string(38) "<a rel="noopener noreferrer">Click</a>"

var_dump($sanitizer->clean("<a href='https://github.com/' style=\"font-size: 12px; color: red; font-weight: bold;\">Click</a>"));
// string(98) "<a href="https://github.com/" style="font-size:12px;color:red" rel="noopener noreferrer">Click</a>"

var_dump($sanitizer->isValidUrl("https://github.com"));
// bool(true)

var_dump($sanitizer->isValidUrl("javascript:alert(1)"));
// bool(false)

var_dump($sanitizer->isValidUrl("foo"));
// bool(false)
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

---

## Running Tests

```bash
cargo test
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.


