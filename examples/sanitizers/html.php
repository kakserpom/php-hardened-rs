<?php
use Hardened\Sanitizers\HtmlSanitizer;
use Hardened\Sanitizers\HtmlSanitizerFlag;

$sanitizer = new HtmlSanitizer();
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
var_dump($sanitizer->cleanAndTruncate("<p>你好世界！</p>", 7, [HtmlSanitizerFlag::ExtendedGraphemes]));
// string(19) "<p>你好世…</p>"

// Truncate by simple graphemes with custom suffix
var_dump($sanitizer->cleanAndTruncate("<p>Курва<p>!!</p>!</p>", 20, [HtmlSanitizerFlag::Graphemes], ' (more)'));
// Outputs: <p>abcdefghij (more)</p>

// Truncate by characters
var_dump($sanitizer->cleanAndTruncate("<p>Hello, world!</p>", 10, [HtmlSanitizerFlag::Ascii]));
// Outputs: <p>12345…</p>

// Truncate by bytes (valid UTF-8 boundary)
var_dump($sanitizer->cleanAndTruncate("<p>доброеутро</p>", 20, [HtmlSanitizerFlag::Unicode]));
// Outputs may vary but will not break UTF-8 sequences, e.g.: <p>доброеут…</p>
