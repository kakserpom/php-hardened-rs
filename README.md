# php-hardened-rs

A PHP extension powered by **Rust** 🦀 and [ext-php-rs](https://github.com/davidcole1340/ext-php-rs), delivering
essential security utilities for PHP applications. It features the following core classes:

- **Hardened\Hostname** — secure hostname parsing, normalization, and comparison.
- **Hardened\Path** — safe, purely-lexical filesystem path handling to prevent directory traversal.
  with fine-grained tag, attribute, and URL policy controls.
- **Hardened\ShellCommand** — secure subprocess launcher: build up a command with arguments, configure timeouts,
  environment inheritance or overrides, live or captured I/O modes, and execute without shell interpolation.
- **Hardened\Rng** — stateless random-data generator: alphanumeric, alphabetic, byte sequences, integer ranges, and
  custom Unicode or ASCII sampling. Using [rand](https://crates.io/crates/rand) crate.
- **Hardened\CsrfProtection** — synchronized [CSRF](https://owasp.org/www-community/attacks/csrf) token–cookie
  protection using AES-GCM, with a PHP-friendly API for
  token/cookie generation, verification, and cookie management. Using [csrf](https://crates.io/crates/csrf) crate.

As well as blazingly fast sanitizers:

- **Hardened\Sanitizers\HtmlSanitizer** — configurable HTML sanitization
  via [Ammonia](https://github.com/rust-ammonia/ammonia). There's also `truncateAndClean()` for safe HTML truncation.
- **Hardened\Sanitizers\File\ArchiveSanitizer** — sanitization against ZIP/RAR bombs.
- **Hardened\Sanitizers\File\PngSanitizer** — sanitization against PNG bombs.

Ergonomic builders of HTTP security headers:

- **Hardened\SecurityHeaders\StrictTransportPolicy** — builder for HTTP Strict-Transport-Security (HSTS); configure
  `max-age`,
  `includeSubDomains`, and `preload`, then emit the header.
- **Hardened\SecurityHeaders\ReferrerPolicy** — Referrer-Policy header builder; initialize with or set any valid policy
  token, build the header value, or send it directly.
- **Hardened\SecurityHeaders\Whatnot** — builder for miscellaneous HTTP security headers (`X-Frame-Options`,
  `X-XSS-Protection`, `X-Content-Type-Options`, `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,
  and `Integrity-Policy-Report-Only`); configure via `set…()` methods, build a header map with `build()`, or emit all
  via `send()`.

Cross-Origin policy builders:

- **Hardened\SecurityHeaders\CrossOrigin\ResourceSharing** — configure CORS: allowed origins, methods, headers,
  credentials, exposed headers,
  preflight cache.
- **Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicy** — configure `Cross-Origin-Embedder-Policy`: choose between
  `unsafe-none`,
  `require-corp`, or `credentialless`.
- **Hardened\SecurityHeaders\CrossOrigin\OpenerPolicy** — configure `Cross-Origin-Opener-Policy`: e.g. `same-origin`,
  `same-origin-allow-popups`, or `unsafe-none`.
- **Hardened\SecurityHeaders\CrossOrigin\ResourcePolicy** — configure `Cross-Origin-Resource-Policy`: choose
  `same-origin`, `same-site`, or
  `cross-origin`.
- **ContentSecurityPolicy** — configure `Content-Security-Policy` directives, keyword sources, hosts, automatic
  nonces.
- **Hardened\SecurityHeaders\CrossOrigin\ReferrerPolicy** — set any valid `Referrer-Policy` token and emit header.
- **Hardened\SecurityHeaders\CrossOrigin\PermissionsPolicy** — configure `Permissions-Policy` features, allow or deny
  per‐feature with allowlists (`*`,
  `self`, `'src'`, specific origins), build header, or send it.
  directives, keyword sources, hosts, and automatic nonce generation.

## Installation

**Supported Platforms:** Linux, macOS, Windows (where `ext-php-rs` is available)

Install with [`cargo-php`](https://github.com/davidcole1340/ext-php-rs):

```bash
# Install cargo-php if you haven't already
# (ensures you have the latest cargo-php installer)
cargo install cargo-php --locked

# Build and install the PHP extension
cd php-hardened-rs-cdylib
cargo php install --release --yes
```

All features are enabled by default.

If you want to choose what features to include in the build, use `--features`.
For example, `cargo php install --release --yes --features rng, `

| Feature              | Enables                                                                                                                                                                            |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **default**          | `mimalloc`, `shell_command`, `html_sanitizer`, `hostname` `path`, `rng`, `csrf`, `headers`                                                                                         |
| **mimalloc**         | Use [mimalloc](https://docs.rs/mimalloc/latest/mimalloc/index.html) allocator.                                                                                                     |
| **shell\_command**   | Safe subprocess API & `Hardened\ShellCommand`                                                                                                                                      |
| **html\_sanitizer**  | The `Hardened\Sanitizers\HtmlSanitizer` wrapper around [Ammonia](https://github.com/rust-ammonia/ammonia)                                                                          |
| **file\_sanitizers** | File sanitizers. `Hardened\Sanitizers\File\Archive` and `Hardened\Sanitizers\File\Png`                                                                                             |
| **hostname**         | The `Hardened\Hostname` utility                                                                                                                                                    |
| **path**             | The `Hardened\Path` utility                                                                                                                                                        |
| **rng**              | The `Hardened\Rng` random-data generator                                                                                                                                           |
| **csrf**             | The `Hardened\CsrfProtection` module (requires [`csrf`](https://docs.rs/csrf/latest/mimalloc/index.html), [`data-encoding`](https://docs.rs/csrf/latest/data-encoding/index.html)) |
| **headers**          | All security headers (`CSP`, `HSTS`, `CORS`, etc.) (requires `trim-in-place`, `serde_json`)                                                                                        |

> On **macOS**, you may need to set the deployment target and link flags first:
> ```bash
> export MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | tr -d '')
> export RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup"
> ```

## API

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

<details><summary>Example</summary>

```php

var_dump(Hostname::fromUrl("https://example.com/php")->equals("eXaMple.com."));
// bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("eXaMple.com."));
// bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("example.co.uk"));
// bool(false)

```

</details>

<details><summary>API Reference</summary>

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

</details>

### `Hardened\Path`

- Lexical canonicalization: remove `.` and `..`, collapse separators.
- No filesystem I/O or symlink resolution.
- Validate that a path stays within a given base.
- API Highlights:
    - `Path::from(string|Path $path): Path` — parse path from string.
    - `$path->startsWith(string|Path $prefix): bool` — check if the path string or Path.
    - `$path->join(string|Path $path): Path` — joins the argument to the path and returns a new Path
    - `$path->joinSubpath(string|Path $subpath): Path` — join, normalize, and enforce subpath constraint.
    - `(string) $path` — string representation.

Note that `Path` is immutable.

<details><summary>Example</summary>

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
    var_dump($path->joinSubpath("../zzz")); // throws
} catch (Throwable $e) {
    echo $e->getMessage() . PHP_EOL;
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

</details>
<details><summary>API Reference</summary>

| Method                                    | Description                                                                                  |
|-------------------------------------------|----------------------------------------------------------------------------------------------|
| `from(string\|Path $path): Path`          | Parse path from string                                                                       |
| `__construct(string\|Path  $path)`        | Alias for `from()`.                                                                          |
| `fileName(): ?string`                     | Get the final path component, or `null` if none.                                             |
| `path(): string`                          | Get the full normalized path as a string.                                                    |
| `parent(): string`                        | Parent directory path.                                                                       |
| `__toString(): string`                    | Alias for `path()`.                                                                          |
| `startsWith(string\|Path $prefix): bool`  | Check if this path begins with the given prefix.                                             |
| `join(mixed $segment): Path`              | join a segment (string/Path), then normalize.                                                |
| `joinWithin(mixed $segment): Path`        | join a segment and enforce that result stays within base.                                    |
| `setFileName(mixed $file_name): Path`     | Replace the file name component.                                                             |
| `setExtension(mixed $extension): Path`    | Replace the file extension (without leading dot).                                            |
| `validateExtension(array $allowed): bool` | Check if the file extension is in a custom allowed list.                                     |
| `validateExtensionImage(): bool`          | Returns `true` if extension is a common image (`png, jpg, jpeg, gif, webp, bmp, tiff, svg`). |
| `validateExtensionVideo(): bool`          | Returns `true` if extension is a common video (`mp4, mov, avi, mkv, webm, flv`).             |
| `validateExtensionAudio(): bool`          | Returns `true` if extension is a common audio (`mp3, wav, ogg, flac, aac`).                  |
| `validateExtensionDocument(): bool`       | Returns `true` if extension is a common document (`pdf, doc, docx, xls, xlsx, ppt, pptx`).   |

</details>

### `Hardened\ShellCommand`

- Secure subprocess launcher without shell interpolation.
- Build a command with explicit executable and arguments.
- Configure timeouts (seconds or milliseconds) and environment inheritance/overrides.
- Choose I/O modes: ignore, passthrough (print to PHP), or callback per chunk.
- Entry-points:
    - `executable()` – start from a specific binary.
    - `shell()` – use your login shell (`$SHELL` or `/bin/sh`).

<details><summary>Example</summary>

```php
use Hardened\ShellCommand;

// 1) Basic builder:
$cmd = new ShellCommand('ls');
$cmd->passArg('-la');
$cmd->setTimeout(5);                // seconds
$cmd->inheritEnvs(['PATH', 'HOME']);
$cmd->passEnv('FOO', 'bar');
$cmd->passthroughStdout();          // print live
$cmd->pipeCallbackStderr(function($chunk) { /* handle stderr chunks */ });

// 2) Run and capture both streams internally:
$code = $cmd->run($stdoutVar, $stderrVar);
// $stdoutVar and $stderrVar now contain full output, $code is exit code.

// 3) One-line helpers:
$result = Hardened\shell_exec('echo hello', ['echo']);
// Enforces top-level command 'echo' only, returns output or exit code.

$args = ['status', '--short'];
$result2 = Hardened\safe_exec('git', $args);
// Spawns `git status --short` without any shell interpretation.
```

</details>

<details><summary>API Reference</summary>

| Method                                                 | Description                                                                                                                                                                    |
|--------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `executable(string $exe): Self`                        | Create a new instance targeting the given executable path (no arguments).                                                                                                      |
| `__construct(string $exe, array $args = []): Self`     | Same as `executable()` plus initial argument list.                                                                                                                             |
| `shell(): Self`                                        | Shortcut to `executable(env('SHELL') ?? '/bin/sh')`.                                                                                                                           |
| `safeFromString(string $cmd): Self`                    | Shell-split safely (handles quotes/escapes, disallows NUL), then configure the command.                                                                                        |
| `unsafeFromString(string $cmd): Self`                  | Like `shell_exec()`: runs via `/bin/sh -c`, but records top-level commands to detect injection.                                                                                |
| `arg(string $arg): Self`                               | join a single argument (no shell interpretation).                                                                                                                              |
| `passArgs(array $args): Self`                          | join multiple positional or `--key value` arguments.                                                                                                                           |
| `setTimeout(int $secs): Self`                          | Set an execution timeout in seconds (process is killed on expiry).                                                                                                             |
| `setTimeoutMs(int $ms): Self`                          | Set an execution timeout in milliseconds.                                                                                                                                      |
| `inheritAllEnvs(): Self`                               | Inherit all of the parent process’s environment variables.                                                                                                                     |
| `inheritEnvs(array $names): Self`                      | Restrict inherited environment variables to this set.                                                                                                                          |
| `passEnv(string $key, string $val): Self`              | Add or override a single environment variable for the child.                                                                                                                   |
| `passEnvOnly(array $map): Self`                        | Clear all inherited vars and set only these environment variables.                                                                                                             |
| `passthroughBoth(): Self`                              | Stream both `stdout` and `stderr` live into PHP output.                                                                                                                        |
| `passthroughStdout(): Self`                            | Stream `stdout` live into PHP output.                                                                                                                                          |
| `passthroughStderr(): Self`                            | Stream `stderr` live into PHP output.                                                                                                                                          |
| `ignoreBoth(): Self`                                   | Discard both `stdout` and `stderr`.                                                                                                                                            |
| `ignoreStdout(): Self`                                 | Discard `stdout` only.                                                                                                                                                         |
| `ignoreStderr(): Self`                                 | Discard `stderr` only.                                                                                                                                                         |
| `pipeCallbackBoth(callable $cb): Self`                 | Invoke the PHP callable for each chunk on both `stdout` and `stderr`.                                                                                                          |
| `pipeCallbackStdout(callable $cb): Self`               | Invoke the PHP callable for each chunk on `stdout`.                                                                                                                            |
| `pipeCallbackStderr(callable $cb): Self`               | Invoke the PHP callable for each chunk on `stderr`.                                                                                                                            |
| `run(?string &$out = null, ?string &$err = null): int` | Execute the command, stream according to configured modes, optionally capture `stdout`/`stderr` into the provided variables, and return exit code (`-1` on timeout or signal). |
| `topLevelCommands(): ?array`                           | Get the list of top-level command names parsed by `unsafeFromString()`, or `null` if not in unsafe mode.                                                                       |

| Function                                                                                   | Description                                                                                                                                                                                                                                                                     |
|--------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Hardened\shell_exec(string $command, array<string>? $expectedCommands = null): ?string`   | Drop-in replacement for PHP’s `shell_exec()`.  Runs `/bin/sh -c $command`, records the top-level command names, and if you pass an `$expectedCommands` list it will throw on any deviation (to catch injection). Returns the captured stdout (or exit-code string on non-zero). |
| `Hardened\safe_exec(string $commandLine, array<string,mixed>? $arguments = null): ?string` | Safe alternative that never invokes a shell.  Splits `$commandLine` into tokens, disallows NUL, joins `$arguments`, then spawns directly. Captures stdout into the return string (or exit-code string on non-zero).                                                             |

</details>

### `Hardened\Sanitizers\HtmlSanitizer`

- Provides a powerful fine-grained HTML sanitization using [Ammonia](https://github.com/rust-ammonia/ammonia).
- Configuration methods for URL policies, tags, attributes, and filters.
- Attribute filter callback support
- *A built-in truncator:*
  `cleanAndTruncate($html, $max, $flags = ['e'], $etc = '…')` is useful when you need to get a snippet of a dynamic HTML
  content. Length of `$etc` is included in the limit. Supported flags:
    - `extended-graphemes` (or `e`) — units of `$max` will be Unicode extended grapheme clusters.
    - `graphemes` (or `g`) — units of `$max` will be Unicode grapheme clusters.
    - __default__` unicode` (or `u`) — units of  `$max` will be Unicode code points.
    - `ascii` (or `a`) — units of  `$max` will be bytes. Even this mode doesn't chop Unicode code points in half.

> Open HTML tags will automatically close at all times, but beware that added closing tags may cause the result length
> to flow over `$max` if you are truncating.
> The current `cleanAndTruncate()` implementation is NOT safe to use if you allow dangerous block tags like `<script>`
> and `<style>`, so an exception will be thrown.

<details>
<summary>Example</summary>

```php
use Hardened\Sanitizers\HtmlSanitizer;

$sanitizer = HtmlSanitizer::default();
var_dump($sanitizer->urlRelativeDeny()
    ->filterStyleProperties(["color", "font-size"])
    ->setTagAttributeValue('a', 'target', '_blank')
    ->clean("<a href='../evil'>Click</a><p>"));
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

// Truncate by extended grapheme clusters (default ellipsis)
var_dump($sanitizer->cleanAndTruncate("<p>你好世界！</p>", 7, 'e'));
// string(19) "<p>你好世…</p>"

// Truncate by simple graphemes with custom suffix
var_dump($sanitizer->cleanAndTruncate("<p>Курва<p>!!</p>!</p>", 20, 'g', ' (more)'));
// Outputs: <p>abcdefghij (more)</p>

// Truncate by characters
var_dump($sanitizer->cleanAndTruncate("<p>Hello, world!</p>", 10, 'a'));
// Outputs: <p>12345…</p>

// Truncate by bytes (valid UTF-8 boundary)
var_dump($sanitizer->cleanAndTruncate("<p>доброеутро</p>", 20, 'u'));
// Outputs may vary but will not break UTF-8 sequences, e.g.: <p>доброеут…</p>
```

</details>

<details><summary>API Reference</summary>

| Method                                                                                      | Description                                                                                                           |
|---------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `default(): HtmlSanitizer`                                                                  | Construct a sanitizer with default configuration.                                                                     |
| `clean(string $html): string`                                                               | Sanitize the given HTML string.                                                                                       |
| `cleanAndTruncate(string $html, int $max, array[string] $flags, string $etc = '…'): string` | Sanitize HTML and truncate joining `$etc` if truncated.                                                               |
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

</details>

### `Hardened\Sanitizers\File\Archive`

* Detects “decompression bombs” in ZIP and RAR archives.
* **ZIP**: sums all central‑directory uncompressed sizes and compares against the first local‑header uncompressed size.
* **RAR**: checks the first entry’s unpacked size versus total compressed size (default 1000× ratio).
* On detection or any file/format error, throws an exception; otherwise returns normally.

<details>
<summary>Example</summary>

```php
<?php
use Hardened\Sanitizers\File\Archive;

try {
    // If neither a ZIP nor RAR bomb is found, this returns void
    Archive::defuse('/path/to/archive.zip');
    echo "Archive looks safe\n";
} catch (Exception $e) {
    // On bomb detection or parse error
    echo "Bomb detected or error: ", $e->getMessage(), "\n";
}

try {
    // You can equally defuse a RAR file
    Archive::defuse('/path/to/archive.rar');
    echo "RAR safe\n";
} catch (Exception $e) {
    echo "RAR bomb or error: ", $e->getMessage(), "\n";
}
```

</details>

<details><summary>API Reference</summary>

| Method                       | Description                                                                                                |
|------------------------------|------------------------------------------------------------------------------------------------------------|
| `defuse(string $path): void` | Inspect the given file at `$path` as ZIP or RAR. Throws if a “bomb” is detected or on any I/O/parse error. |

</details>

### `Hardened\Sanitizers\File\PngSanitizer`

* Detects “PNG bombs”—images whose IHDR dimensions are unreasonably large (>10000 px).
* Reads only the PNG signature and IHDR chunk; no full decode.
* On detection or any I/O/format error, throws an exception; otherwise returns normally.

<details>
<summary>Example</summary>

```php
<?php
use Hardened\Sanitizers\File\PngSanitizer;

try {
    // Throws if width or height > 10000 or IHDR missing/invalid
    PngSanitizer::defuse('/tmp/huge.png');
    echo "PNG is safe\n";
} catch (Exception $e) {
    echo "PNG bomb or error: ", $e->getMessage(), "\n";
}
```

</details>

<details><summary>API Reference</summary>

| Method                       | Description                                                                                                                  |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `defuse(string $path): void` | Inspect the file at `$path`. Throws if it’s a valid PNG with width>10000 or height>10000, or if the IHDR chunk is malformed. |

</details>

### `Hardened\Rng`

- Stateless random-data generator.
- Static methods to create random alphanumeric or alphabetic strings (`alphanumeric()`, `alphabetic()`).
- Byte sequences (`bytes()`), integer arrays (`ints()`), and single integers (`int()`) with inclusive ranges.
- Custom sampling from arbitrary Unicode code points (`customUnicodeChars()`), grapheme clusters (
  `customUnicodeGraphemes()`), or ASCII sets (`customAscii()`).

<details>
<summary>Example</summary>

```php
use Hardened\Rng;

// Random alphanumeric string of length 10
var_dump(Rng::alphanumeric(10));
// Example: string(10) "sR571dnuYv"

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
// Example: string(20) "ддббАгАбдб"

// 10 random ASCII characters sampled from "AbcDef"
var_dump(Rng::customAscii(10, "AbcDef"));
// Example: string(10) "AbAAefDDfc"

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

</details>

<details><summary>API Reference</summary>

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

</details>

### `Hardened\CsrfProtection`

- Synchronized token–cookie [CSRF](https://owasp.org/www-community/attacks/csrf) protection using AES-GCM.
- Constructor: `__construct($key, $ttl, $previousTokenValue = null)`.
- Token & cookie getters: `token()`, `cookie()`.
- Validation: `verifyToken($token, $cookie = null)` (auto-fetches cookie if omitted).
- Cookie management: `setCookieName()`, `cookieName()`,
  `sendCookie($expires = null, $path = null, $domain = null, $secure = null, $httponly = null)`.

<details>
<summary>Example</summary>

```php
use Hardened\CsrfProtection;

//
// 1) Initialization
//
$key = '7sVldqnZoPUIY7wWp1We-mbaZ5SAoe04QXUFiNnwJFE=';  // must decode to 32 bytes
$ttl = 3600;                              // token lifetime in seconds

// If you have a previous token (for rotation), pass it as third argument:
// $previous = $_COOKIE['csrf'] ?? null;
// $csrf = new CsrfProtection($key, $ttl, $previous);

$csrf = new CsrfProtection($key, $ttl);

//
// 2) Send the cookie to the client
//
$csrf->sendCookie(
    expires:  time() + $ttl,
    path:     '/',
    domain:   '',      // default: current host
    secure:   true,    // only over HTTPS
    httponly: true     // inaccessible to JavaScript
);

//
// 3) Embed the CSRF token in your form or AJAX request
//
$token = $csrf->token();  // Base64URL-encoded token string
?>
<!doctype html>
<html>
  <body>
    <form method="POST" action="submit.php">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token, \ENT_QUOTES) ?>">
      <!-- other form fields… -->
      <button type="submit">Submit Securely</button>
    </form>
  </body>
</html>
<?php

return;
//
// 4) On form submission (submit.php):
//

try {
    // Reconstruct with same key/ttl and pass previous cookie if rotating:
    $csrf = new CsrfProtection($key, $ttl, $_COOKIE['csrf'] ?? null);

    // Verify the token against the cookie
    $csrf->verifyToken(
        /* token value from form: */ $_POST['csrf_token'] ?? '',
        /* cookie value: */         $_COOKIE['csrf']     ?? null
    );

    // If we get here, CSRF check passed
    echo "CSRF validated — proceed with action.";
} catch (\Exception $e) {
    // Invalid or expired token
    http_response_code(403);
    echo "CSRF validation failed: " . htmlspecialchars($e->getMessage());
}
```

</details>

<details><summary>API Reference</summary>

| Method                                                                                                                               | Description                                                                        |
|--------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| `__construct(string $key, int $ttl, ?string $previousTokenValue = null): void`                                                       | Initialize a CSRF protection instance.                                             |
| `verifyToken(string $token, ?string $cookie = null): void`                                                                           | Validate the given token & cookie pair.                                            |
| `cookie(): string`                                                                                                                   | Return the Base64URL-encoded CSRF cookie value to send via `Set-Cookie`.           |
| `token(): string`                                                                                                                    | Return the Base64URL-encoded CSRF token value to embed in forms or headers.        |
| `setCookieName(string $name): void`                                                                                                  | Override the name used for the CSRF cookie.                                        |
| `cookieName(): string`                                                                                                               | Get the current CSRF cookie name (default is `csrf`).                              |
| `sendCookie(?int $expires = null, ?string $path = null, ?string $domain = null, ?bool $secure = null, ?bool $httponly = null): void` | Send the CSRF cookie via PHP’s `setcookie()` function using native argument order. |

</details>

### `Hardened\SecurityHeaders\ContentSecurityPolicy`

- Builder for HTTP Content-Security-Policy headers.
- Configure directives (`default-src`, `script-src`, etc.) with keyword tokens and host sources via `setRule()`.
- Automatically generates nonces for `'nonce-…'` directives.
- Produces a valid header string with `build()`, and convenience method `send()` to emit it.
- Retrieve the last-generated nonce with `getNonce()`.

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\ContentSecurityPolicy;

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

</details>

<details><summary>API Reference</summary>

| Method                                                           | Description                                                                                                     |
|------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `__construct()`                                                  | Alias for `new()`, initializes an empty CSP builder.                                                            |
| `new(): ContentSecurityPolicy`                                   | Construct a new CSP builder with no directives set.                                                             |
| `setRule(string $rule, array $keywords, ?array $sources): mixed` | Set or replace a CSP directive with the given keywords (`'self'`, `'nonce'`, etc.) and host sources.            |
| `build(): string`                                                | Build the `Content-Security-Policy` header value from the configured directives.                                |
| `send(): mixed`                                                  | Send the constructed CSP header to the client (via PHP SAPI).                                                   |
| `getNonce(): ?string`                                            | Return the most recently generated nonce (without the `'nonce-'` prefix), or `null` if none has been generated. |
| `resetNonce(): void`                                             | Clears the generated nonce. The next call of `build()` or `send()` will generate a new one.                     |

</details>

### `Hardened\SecurityHeaders\StrictTransportSecurity`

- HTTP Strict Transport Security (HSTS) header builder.
- Configure `max-age`, `includeSubDomains`, and `preload` flags for best‐practice transport security.
- Build the header string with `build()`, or emit it directly with `send()` (uses PHP `header()`).

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\StrictTransportSecurity;

// Create and configure HSTS
$hsts = new StrictTransportSecurity();
$hsts->maxAge(31536000);            // one year
$hsts->includeSubDomains(true);     // apply to all subdomains
$hsts->preload(true);               // request inclusion in browser preload lists

// Get header value
$value = $hsts->build();
// e.g. "max-age=31536000; includeSubDomains; preload"

// Send header to client
header('Strict-Transport-Security: ' . $value);

// Or simply:
$hsts->send();
```

</details>

<details><summary>API Reference</summary>

| Method                                  | Description                                                                                                 |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------|
| `__construct()`                         | Initialize with `max-age=0`, no subdomains, no preload.                                                     |
| `maxAge(int $maxAge): void`             | Set the `max-age` directive (in seconds).                                                                   |
| `includeSubDomains(bool $enable): void` | Enable or disable the `includeSubDomains` flag.                                                             |
| `preload(bool $enable): void`           | Enable or disable the `preload` flag.                                                                       |
| `build(): string`                       | Return the `Strict-Transport-Security` header value, e.g. `"max-age=31536000; includeSubDomains; preload"`. |
| `send(): void`                          | Emit the header via PHP `header()` function.                                                                |

</details>

### `Hardened\SecurityHeaders\CrossOrigin\ResourceSharing`

- CORS policy builder for HTTP responses.
- Configure allowed origins, methods, headers, credentials flag, exposed headers, and preflight cache duration.
- Build a map of header names → values with `build()`, or emit them directly with `send()`.

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\CrossOrigin\ResourceSharing;

$policy = new ResourceSharing();

// Allow specific origins or use ['*'] for wildcard
$policy->allowOrigins(['https://example.com', 'https://api.example.com', ResourceSharing::SELF]);

// Permit HTTP methods
$policy->allowMethods(['GET', 'POST', 'OPTIONS']);

// Permit request headers
$policy->allowHeaders(['Content-Type', 'Authorization']);

// Allow cookies/auth credentials
$policy->allowCredentials(true);

// Expose custom response headers to the browser
$policy->exposeHeaders(['X-Custom-Header']);

// Cache preflight response for 3600 seconds
$policy->maxAge(3600);

// Apply headers manually
foreach ($policy->build() as $name => $value) {
header("$name: $value");
}

// Or simply:
$policy->send();

```

</details>

<details><summary>API Reference</summary>

| Method                                 | Description                                                                   |
|----------------------------------------|-------------------------------------------------------------------------------|
| `__construct()`                        | Initialize with no restrictions (empty lists, credentials=false, max\_age=0). |
| `allowOrigins(array $origins): void`   | Set `Access-Control-Allow-Origin` values (e.g. `['*']` or specific domains).  |
| `allowMethods(array $methods): void`   | Set `Access-Control-Allow-Methods` values (e.g. `['GET','POST']`).            |
| `allowHeaders(array $headers): void`   | Set `Access-Control-Allow-Headers` values (e.g. `['Content-Type']`).          |
| `allowCredentials(bool $enable): void` | Enable `Access-Control-Allow-Credentials: true` when `$enable` is `true`.     |
| `exposeHeaders(array $headers): void`  | Set `Access-Control-Expose-Headers` values for response exposure to client.   |
| `maxAge(int $seconds): void`           | Set `Access-Control-Max-Age` (in seconds) for caching preflight responses.    |
| `build(): array`                       | Return an associative array of header names → values to send.                 |
| `send(): void`                         | Emit all configured CORS headers via PHP `header()` calls.                    |

</details>

### Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicy

- **Cross-Origin-Embedder-Policy** header builder.

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicy;

$policy = new EmbedderPolicy(); // defaults to "unsafe-none"
echo $policy->build(); // outputs "unsafe-none"

$policy = new EmbedderPolicy("require-corp");
$policy->set(EmbedderPolicy::CREDENTIALLESS);
echo $policy->build(); // "credentialless"

$policy->send(); // sends header

```

</details>

<details>
<summary>API Reference</summary>

| Method                                      | Description                                                                                                                       |
|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `__construct(?string $policy = null): self` | Create a new COEP builder, defaults to `"unsafe-none"` if no policy is provided.                                                  |
| `set(string $policy): void`                 | Set the Cross-Origin-Embedder-Policy to one of `"unsafe-none"`, `"require-corp"`, or `"credentialless"`. Throws on invalid token. |
| `build(): string`                           | Return the header value, e.g. `"require-corp"`.                                                                                   |
| `send(): void`                              | Emit `Cross-Origin-Embedder-Policy: <value>` via PHP `header()`; errors if `header()` cannot be called.                           |

</details>

### `Hardened\SecurityHeaders\CrossOrigin\OpenerPolicy`

- **Cross-Origin-Opener-Policy** header builder.

<details>
<summary>API Reference</summary>

| Method                                | Returns  | Description                                                                              |
|---------------------------------------|----------|------------------------------------------------------------------------------------------|
| `__construct(?string $policy = null)` | `self`   | Initialize builder with optional policy (defaults to `unsafe-none`).                     |
| `set(string $policy): void`           | `void`   | Change the policy to one of `unsafe-none`, `same-origin`, or `same-origin-allow-popups`. |
| `build(): string`                     | `string` | Get the current policy token (e.g. `"same-origin"`).                                     |
| `send(): void`                        | `void`   | Emit the header `Cross-Origin-Opener-Policy: <value>` via PHP `header()`.                |

</details>

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\CrossOrigin\OpenerPolicy;

// 2) Opener policy: isolate this window from cross-origin windows
$policy = new OpenerPolicy('same-origin'); // initialize directly to "same-origin"
$policy->send(); // emits header internally

// 3) Or build() yourself:
echo $policy->build(); // "require-corp"
```

</details>

### Hardened\SecurityHeaders\CrossOrigin\ResourcePolicy

* Builder for the `Cross-Origin-Resource-Policy` (CORP) header.
* Configure one of the standard CORP directives (`same-origin`, `same-site`, `cross-origin`) via constructor or
  `setPolicy()`.
* Generate the header value with `build()`, or emit it directly with `send()`.

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\CrossOrigin\ResourcePolicy;

$policy = new ResourcePolicy();                   // default "same-origin"
echo $policy->build();                            // "same-origin"

$policy->set('cross-origin');
header('Cross-Origin-Resource-Policy: ' . $policy->build());
// or
$policy->send();
```

</details>

<details>
<summary>API Reference</summary>

| Method                                | Description                                                  |
|---------------------------------------|--------------------------------------------------------------|
| `__construct(?string $policy = null)` | Instantiate builder; defaults to `"same-origin"` if `null`.  |
| `setPolicy(string $policy): void`     | Set a new CORP token; throws on invalid value.               |
| `build(): string`                     | Return the configured policy token.                          |
| `send(): void`                        | Emit `Cross-Origin-Resource-Policy: <value>` via `header()`. |

</details>

### Hardened\SecurityHeaders\ReferrerPolicy

- Referrer-Policy header builder for HTTP responses.
- Initialize with an optional policy token or configure via `set()`; enforces only valid CSP values.
- Build the header value with `build()`, or emit it directly with `send()`.

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\ReferrerPolicy;

// Default policy (no-referrer)
$rp = new ReferrerPolicy();

// Specify initial policy
$rp = new ReferrerPolicy('origin-when-cross-origin');

// Override later
$rp->set('strict-origin');

// Get the header value
$value = $rp->build();
// e.g. "strict-origin"

// Send the header
header('Referrer-Policy: ' . $value);

// Or simply:
$rp->send();
```

</details>

<details>
<summary>API Reference</summary>

| Method                                | Description                                                  |
|---------------------------------------|--------------------------------------------------------------|
| `__construct(?string $policy = null)` | Create builder with default `no-referrer` or given token.    |
| `set(string $policy): void`           | Set a new policy token; throws on invalid value.             |
| `policy(): string`                    | Get the current policy token.                                |
| `build(): string`                     | Build the header value to pass to `header()`.                |
| `send(): void`                        | Emit `Referrer-Policy: <value>` via PHP `header()` function. |

</details>

### Hardened\SecurityHeaders\Whatnot

- Builder for miscellaneous HTTP security headers:  
  `X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`,  
  `X-Permitted-Cross-Domain-Policies`, `Report-To`, `Integrity-Policy`,  
  and `Integrity-Policy-Report-Only`.
- Strongly-typed enums for frame & XSS modes, with optional URIs for `ALLOW-FROM` and reporting.
- Configure each header with `set…()` methods, then gather with `build()` or emit via `send()`.

<details>

<summary>Example</summary>

```php
use Hardened\SecurityHeaders\Whatnot;

$policy = new Whatnot();

// Frame options
$policy->setFrameOptions('DENY');
$policy->setFrameOptions('ALLOW-FROM', 'https://example.com');

// XSS protection
$policy->setXssProtection('on');
$policy->setXssProtection('block');
$policy->setXssProtection('block', 'https://report.example.com'); // Block with a report URI

// No-sniff
$policy->setNosniff(true);

// Cross-domain policies
$policy->setPermittedCrossDomainPolicies('none');

$policy->setReportTo(
    'csp-endpoint',          // group
    10886400,                // max_age
    true,                    // include_subdomains
    ['primary', 'backup']    // endpoints
);

// Structured Integrity-Policy
$policy->setIntegrityPolicy(
    ['script'],                    // blocked-destinations
    ['inline'],                    // sources (optional, defaults to ['inline'])
    ['csp-endpoint','backup']      // endpoints (optional)
);

// Apply headers
foreach ($policy->build() as $name => $value) {
    header("$name: $value");
}

// Or simply:
$policy->send();
```

</details>

<details>
<summary>API Reference</summary>

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

</details>

### Hardened\SecurityHeaders\PermissionsPolicy

- Builder for the `Permissions-Policy` header.
- Use `allow(feature, origins)` to enable a feature for a list of origins, or `deny(feature)` for an empty allowlist.

<details>
<summary>Example</summary>

```php
use Hardened\SecurityHeaders\PermissionsPolicy;

// 1) Instantiate the builder
$policy = new PermissionsPolicy();

// 2) Allow features with specific allowlists:
//    - geolocation: only same-origin and https://api.example.com
$policy->allow(
    PermissionsPolicy::GEOLOCATION,
    [ PermissionsPolicy::ORIGIN_SELF, 'https://api.example.com' ]
);

//    - sync-xhr: only the “src” allowlist token
$policy->allow(
    PermissionsPolicy::BLUETOOTH,
    [ PermissionsPolicy::ORIGIN_SRC ]
);

// 3) Deny features entirely (empty allowlist):
//    - camera
$policy->deny(PermissionsPolicy::CAMERA);

//    - microphone
$policy->deny(PermissionsPolicy::MICROPHONE);

// 4) Build the header value and emit it
header('Permissions-Policy: ' . $policy->build());

//—or— use the convenience send() method
// $policy->send();
```

</details>

<details>
<summary>API Reference</summary>

| Method                                         | Description                                                                                                                                                                  |
|------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `__construct(?array $features = null)`         | Initialize the builder, optionally pre‑populating a map of feature ⇒ allowlist entries (each allowlist is `string[]`).                                                       |
| `set(string $feature, array $allowlist): void` | Define or override the allowlist for a given feature. Valid allowlist entries are: `'*'`, `''` (empty), `'self'`, `'src'`, or specific origins like `'https://example.com'`. |
| `unset(string $feature): void`                 | Remove a feature so that it will not appear in the final header.                                                                                                             |
| `build(): string`                              | Render the header value, e.g. `geolocation=(self "https://maps.example.com"), fullscreen=(*)`.                                                                               |
| `send(): void`                                 | Emit `Permissions-Policy: <value>` via PHP `header()` calls.                                                                                                                 |

</details>

---

## Performance

Only `Hardened\Sanitizers\HtmlSanitizer` is covered with benchmarks as of this moment.
`HtmlSanitizer::cleanAndTruncate()` may call `clean()` an extra time to deal with unenclosed tags.

### Rust benchmark suite

Command:

```shell
cargo bench --features test
```

M1 Max results:

```
html_sanitizer_10kb     time:   [188.64 µs 189.33 µs 190.09 µs]
Found 6 outliers among 100 measurements (6.00%)
  4 (4.00%) high mild
  2 (2.00%) high severe
  
html_sanitizer_truncate_10k_to_5kb_in_ascii_mode
                        time:   [294.66 µs 298.40 µs 303.62 µs]
Found 8 outliers among 100 measurements (8.00%)
  3 (3.00%) high mild
  5 (5.00%) high severe
```

### PHP benchmarks

Run:

```shell
cd benches
curl -s https://raw.githubusercontent.com/composer/getcomposer.org/f3108f64b4e1c1ce6eb462b159956461592b3e3e/web/installer | php -- --quiet
./composer.phar require phpbench/phpbench ezyang/htmlpurifier --dev
./vendor/bin/phpbench run benchmark.php
```

M1 Max results:

```
    \HtmlSanitizerBenchmark

    benchHtmlSanitizer10kb..................I0 - Mo193.671μs (±0.00%)
    benchEzyangHtmlPurifier10kb.............I0 - Mo2.605ms (±0.00%)
    benchTidy10kb...........................I0 - Mo544.090μs (±0.00%)
```

As you can see, `Hardened\Sanitizers\HtmlSanitizer` (effectively [Ammonia](https://github.com/rust-ammonia/ammonia))
runs 13.7 times faster than the widely used [htmlpurifier](https://github.com/ezyang/htmlpurifier) written in PHP and
2.8 times faster than [tidy](https://www.php.net/manual/en/book.tidy.php) (a library written in C).

## Running Tests

```bash
cargo test
```

PHP examples in `examples` directory are getting smoke tested automatically with `cargo test` (provided that you have
PHP installed).

---

## License

MIT License — see [LICENSE](LICENSE) for details.


