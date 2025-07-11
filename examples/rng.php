<?php
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

