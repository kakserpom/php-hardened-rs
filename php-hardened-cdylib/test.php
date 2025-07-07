<?php
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