<?php
use Hardened\HtmlSanitizer;

$sanitizer = HtmlSanitizer::default();
$sanitizer->urlRelativeDeny();
$sanitizer->tags(["a", "p"]);
$sanitizer->addTagAttributes("a", ["style"]);
$sanitizer->filterStyleProperties(["color", "font-size"]);
var_dump($sanitizer->clean("<a href='../evil'>Click</a><p>"));
var_dump($sanitizer->clean("<a href='https://github.com/' \
style='font-size: 12px; color: red; font-weight: bold;'>Click</a>"));
var_dump($sanitizer->isValidUrl("https://github.com"));
// bool(true)
var_dump($sanitizer->isValidUrl("javascript:alert(1)"));
// bool(false)
var_dump($sanitizer->isValidUrl("foo"));
// bool(false)

return;


use Hardened\Hostname;

var_dump(Hostname::fromUrl("https://example.com/php")->equals("eXaMple.com.")); // bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("eXaMple.com.")); // bool(true)
var_dump(Hostname::from("zzz.example.com")->subdomainOf("example.co.uk")); // bool(false)

$path = Hardened\Path::from("/foo/bar/data/");
var_dump($path->join("zzz")->startsWith($path)); // bool(true)
var_dump($path->join("zzz")->path()); // string(17) "/foo/bar/data/zzz"
var_dump($path->join("../zzz")->path()); // string(12) "/foo/bar/zzz"
var_dump($path->join("../zzz")->startsWith($path)); // bool(false)
try {
    var_dump($path->joinWithin("../zzz")); // nope
} catch (Throwable) {
    echo ";-)" . PHP_EOL;
}
