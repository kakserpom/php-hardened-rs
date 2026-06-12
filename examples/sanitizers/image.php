<?php
use Hardened\Sanitizers\File\ImageSanitizer;

// A minimal GIF, the way an upload body arrives: raw bytes
$gif = "GIF89a" . pack("vv", 640, 480) . "\x00\x00\x00;";
$img = new ImageSanitizer($gif);

var_dump($img->format());
// string(3) "gif"
var_dump($img->mime());
// string(9) "image/gif"
var_dump($img->dimensions());
// array(2) { [0]=> int(640) [1]=> int(480) } — header-only, no decoder ran

$img->assertDimensionsWithin(10000, 10000);
$img->assertPixelsWithin(50_000_000);
try {
    (new ImageSanitizer("GIF89a" . pack("vv", 60000, 60000) . "\x00\x00\x00;"))
        ->assertPixelsWithin(50_000_000);
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(1611) — decompression bomb rejected without decoding
}

// Magic bytes vs claimed extension / MIME
var_dump($img->matchesExtension("kitten.gif"));
// bool(true)
var_dump($img->matchesExtension("kitten.gif.php"));
// bool(false) — double extension lie
var_dump($img->matchesMime("image/gif"));
// bool(true)

// Polyglot detection: valid image that is also active content
$polyglot = new ImageSanitizer($gif . "<?php system(\$_GET['c']);");
var_dump($polyglot->isPolyglot());
// bool(true)
try {
    $polyglot->assertNotPolyglot();
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(1612)
}

// Metadata stripping (JPEG/PNG/WebP), shown here on a PNG with a tEXt chunk
$png = "\x89PNG\r\n\x1a\n"
    . pack("N", 13) . "IHDR" . pack("NN", 10, 20) . "\x08\x00\x00\x00\x00" . "\x00\x00\x00\x00"
    . pack("N", 18) . "tEXt" . "Author\x00Big Brother" . "\x00\x00\x00\x00"
    . pack("N", 0) . "IEND" . "\x00\x00\x00\x00";
$clean = (new ImageSanitizer($png))->stripMetadata();
var_dump(str_contains($clean, "Big Brother"));
// bool(false)
var_dump((new ImageSanitizer($clean))->dimensions());
// array(2) { [0]=> int(10) [1]=> int(20) } — image intact, metadata gone
