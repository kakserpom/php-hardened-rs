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
