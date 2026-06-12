<?php
use Hardened\Unicode;

// NFKC folds full-width and compatibility forms
var_dump(Unicode::nfkc("ｐａｙｐａｌ"));
// string(6) "paypal"
var_dump(Unicode::nfkc("ﬁle"));
// string(4) "file"

// Homoglyph detection: Cyrillic "а" looks exactly like Latin "a"
$real = "paypal";
$spoof = "pаypаl";
var_dump($real === $spoof);
// bool(false) — different bytes...
var_dump(Unicode::confusable($real, $spoof));
// bool(true) — ...same glyphs to a human
var_dump(Unicode::skeleton($spoof));
// string(6) "paypal" — store skeletons, enforce uniqueness on them

var_dump(Unicode::isSingleScript("пароль"));
// bool(true)
var_dump(Unicode::isSingleScript($spoof));
// bool(false) — Latin + Cyrillic mix

var_dump(Unicode::restrictionLevel("admin42"));
// string(10) "ascii-only"
var_dump(Unicode::restrictionLevel("пароль"));
// string(13) "single-script"

// Zero-width characters make distinct usernames render identically
var_dump(Unicode::hasInvisibleCharacters("ad\u{200B}min"));
// bool(true)
var_dump(Unicode::stripInvisibleCharacters("ad\u{200B}min"));
// string(5) "admin"
var_dump(Unicode::isIdentifierSafe("admin"));
// bool(true)
