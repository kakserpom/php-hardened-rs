<?php
use Hardened\Password;

// Argon2id with OWASP defaults (19 MiB, t=2, p=1), random salt per call
$hash = Password::hash("correct horse battery staple");
var_dump(str_starts_with($hash, '$argon2id$v=19$'));
// bool(true)

var_dump(Password::verify("correct horse battery staple", $hash));
// bool(true)
var_dump(Password::verify("Tr0ub4dor&3", $hash));
// bool(false)

// Up-to-date hash: no rehash needed
var_dump(Password::needsRehash($hash));
// bool(false)
// Policy bumped to 64 MiB: rehash on next successful login
var_dump(Password::needsRehash($hash, 65536));
// bool(true)

// Legacy bcrypt hashes (e.g. from password_hash()) keep verifying...
$bcrypt = Password::hashBcrypt("legacy password", 10);
var_dump(str_starts_with($bcrypt, '$2b$10$'));
// bool(true)
var_dump(Password::verify("legacy password", $bcrypt));
// bool(true)
// ...and are flagged for migration to Argon2id
var_dump(Password::needsRehash($bcrypt));
// bool(true)
var_dump(Password::needsRehashBcrypt($bcrypt, 12));
// bool(true) — cost 10 < target 12
