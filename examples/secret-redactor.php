<?php
use Hardened\SecretRedactor;

$redactor = new SecretRedactor();

var_dump($redactor->redact("Authorization: Bearer eyXtoken.secret.value"));
// string(33) "Authorization: Bearer [REDACTED]"
var_dump($redactor->redact("Cookie: session=abc; theme=dark"));
// string(18) "Cookie: [REDACTED]"
var_dump($redactor->redact("password=hunter2 user=bob"));
// string(25) "password=[REDACTED] user=bob"
var_dump($redactor->redact('{"api_key": "sk-abc123", "name": "x"}'));
// {"api_key": "[REDACTED]", "name": "x"}
var_dump($redactor->redact("aws AKIAIOSFODNN7EXAMPLE"));
// string(14) "aws [REDACTED]"

// Luhn-aware PAN masking keeps the last four digits (PCI)
var_dump($redactor->redact("card 4111 1111 1111 1111 charged"));
// string(32) "card **** **** **** 1111 charged"
var_dump($redactor->redact("ref 4111111111111112"));
// string(20) "ref 4111111111111112" — fails Luhn: not a card, untouched

// Pluggable patterns
$redactor->addPattern('\binternal-[a-z0-9]+\b');
var_dump($redactor->redact("ticket internal-abc123"));
// string(17) "ticket [REDACTED]"
