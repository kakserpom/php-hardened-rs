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
