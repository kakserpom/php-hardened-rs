# php-hardened-rs

A PHP extension powered by **Rust** 🦀 and [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), delivering
essential security utilities for PHP applications. It provides two core classes:

1. **Hardened\Hostname** — secure hostname parsing, normalization, and comparison.
2. **Hardened\Path** — safe, purely lexical filesystem path handling to prevent directory traversal.

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
- AP​I Highlights:
    - `Path::from(mixed $path): Path` — parse Zval, string, or Path.
    - `$path->startsWith(mixed $prefix): bool` — prefix string or Path.
    - `$path->join(mixed $segment): Path` — append string or Path.
    - `$path->joinWithin(mixed $segment): Path` — append, canonicalize, and enforce subpath constraint.
    - `(string)$path` — string representation.

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

| Method                                    | Signature | Description                                           |
|-------------------------------------------|-----------|-------------------------------------------------------|
| `from(mixed $path): Path`                 | `static`  | Parse or wrap string/Zval/Path.                       |
| `startsWith(mixed $prefix): bool`         | Instance  | Check prefix against string or Path.                  |
| `join(mixed $segment): Path`              | Instance  | Append string or Path, then canonicalize.             |
| `joinWithin(mixed $segment): Path`        | Instance  | Append, canonicalize, enforce within-base constraint. |
| `path(): string` / `__toString(): string` | Instance  | Convert to string.                                    |

---

## Running Tests

```bash
cargo test
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

