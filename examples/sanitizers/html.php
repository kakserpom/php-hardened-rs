<?php
use Hardened\Sanitizers\HtmlSanitizer;

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
