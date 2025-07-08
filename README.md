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
    var_dump($path->joinWithin("../zzz")); // nope
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

| Method                                                                    | Signature | Description                                                               |
|---------------------------------------------------------------------------|-----------|---------------------------------------------------------------------------|
| `default(): HtmlSanitizer`                                                | static    | Construct with default configuration.                                     |
| `urlRelativeDeny(): void`                                                 | instance  | Deny all relative URLs. Throws PhpException if invalid state.             |
| `urlRelativePassthrough(): void`                                          | instance  | Pass through relative URLs. Throws PhpException if invalid state.         |
| `urlRelativeRewriteWithBase(string $url): void`                           | instance  | Rewrite with base URL. Throws PhpException or Exception on parse errors.  |
| `urlRelativeRewriteWithRoot(string $root, string $path): void`            | instance  | Rewrite with root and prefix. Throws PhpException or Exception on errors. |
| `linkRel(?string $value): void`                                           | instance  | Set `<a>` rel attribute. Throws PhpException if invalid state.            |
| `tags(mixed $tags): void`                                                 | instance  | Overwrite allowed tags. Throws PhpException or Exception if not array.    |
| `addTags(mixed $tags): void`                                              | instance  | Add to allowed tags. Throws PhpException or Exception if not array.       |
| `rmTags(mixed $tags): void`                                               | instance  | Remove from allowed tags. Throws PhpException.                            |
| `addAllowedClasses(mixed $tag, mixed $classes): void`                     | instance  | Add CSS classes. Throws PhpException or Exception if invalid types.       |
| `rmAllowedClasses(mixed $tag, mixed $classes): void`                      | instance  | Remove CSS classes. Throws PhpException or Exception if invalid types.    |
| `addTagAttributes(mixed $tag, mixed $attributes): void`                   | instance  | Add tag attributes. Throws PhpException or Exception if invalid types.    |
| `rmTagAttributes(mixed $tag, mixed $attributes): void`                    | instance  | Remove tag attributes. Throws PhpException or Exception if invalid types. |
| `addGenericAttributes(mixed $attributes): void`                           | instance  | Add generic attributes. Throws PhpException or Exception if not array.    |
| `rmGenericAttributes(mixed $attributes): void`                            | instance  | Remove generic attributes. Throws PhpException.                           |
| `addGenericAttributePrefixes(mixed $prefixes): void`                      | instance  | Add generic prefixes. Throws PhpException or Exception.                   |
| `rmGenericAttributePrefixes(mixed $prefixes): void`                       | instance  | Remove generic prefixes. Throws PhpException or Exception.                |
| `clean(string $html): string`                                             | instance  | Sanitize HTML. Applies optional attribute filter.                         |
| `urlSchemes(mixed $schemes): void`                                        | instance  | Whitelist URL schemes. Throws PhpException or Exception if not array.     |
| `stripComments(bool $strip): void`                                        | instance  | Enable/disable comment stripping. Throws PhpException.                    |
| `willStripComments(): bool`                                               | instance  | Returns comment stripping policy. Throws PhpException.                    |
| `idPrefix(?string $prefix): void`                                         | instance  | Prefix `id` attributes. Throws PhpException.                              |
| `filterStyleProperties(mixed $props): void`                               | instance  | Filter CSS properties. Throws PhpException or Exception if not array.     |
| `setTagAttributeValue(mixed $tag, mixed $attribute, string $value): void` | instance  | Set attribute value. Throws PhpException or Exception if invalid types.   |
| `cloneTags(): array`                                                      | instance  | Get configured tags. Throws PhpException.                                 |
| `cloneCleanContentTags(): array`                                          | instance  | Get clean-content tags. Throws PhpException.                              |
| `genericAttributes(mixed $attrs): void`                                   | instance  | Overwrite generic attributes. Throws PhpException or Exception.           |
| `genericAttributePrefixes(mixed $prefixes): void`                         | instance  | Overwrite generic prefixes. Throws PhpException or Exception.             |
| `addTagAttributeValues(mixed $tag, mixed $attr, mixed $values): void`     | instance  | Add attribute values. Throws PhpException or Exception.                   |
| `rmTagAttributeValues(mixed $tag, mixed $attr, mixed $values): void`      | instance  | Remove attribute values. Throws PhpException or Exception.                |
| `getSetTagAttributeValue(mixed $tag, mixed $attr): ?string`               | instance  | Get single attribute value. Throws PhpException.                          |
| `isUrlRelativeDeny(): bool`                                               | instance  | Check Deny policy. Throws PhpException.                                   |
| `isUrlRelativePassThrough(): bool`                                        | instance  | Check PassThrough policy. Throws PhpException.                            |
| `isUrlRelativeCustom(): bool`                                             | instance  | Check custom rewrite policy. Throws PhpException.                         |
| `attributeFilter(mixed $callable): void`                                  | instance  | Set attribute filter callback.                                            |

---

## Running Tests

```bash
cargo test
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.


