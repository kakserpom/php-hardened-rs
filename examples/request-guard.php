<?php
use Hardened\RequestGuard;

$guard = new RequestGuard(["https://app.example"]);

// Safe methods always pass
var_dump($guard->check("GET", null, null, null));
// bool(true)

// Modern browsers send Sec-Fetch-Site — it can't be forged cross-origin
var_dump($guard->check("POST", null, null, "same-origin"));
// bool(true)
var_dump($guard->check("POST", null, null, "cross-site"));
// bool(false)
var_dump($guard->check("POST", null, null, "same-site"));
// bool(false) — subdomains rejected by default (see allowSameSite)

// Fallback for older clients: exact Origin match — scheme, host, and port
var_dump($guard->check("POST", "https://app.example", null, null));
// bool(true)
var_dump($guard->check("POST", "http://app.example", null, null));
// bool(false) — scheme downgrade
var_dump($guard->check("POST", "https://app.example.evil.com", null, null));
// bool(false) — the classic dev-domain/prefix hole
var_dump($guard->check("POST", "null", null, null));
// bool(false) — opaque origin never passes

// Referer is the last resort
var_dump($guard->check("POST", null, "https://app.example/checkout", null));
// bool(true)

// No usable headers on a state-changing request: rejected by default
try {
    $guard->assert("POST", null, null, null);
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(3004)
}

// One-call form reading $_SERVER (REQUEST_METHOD, HTTP_ORIGIN, ...):
// $guard->assertServer();
var_dump($guard->checkServer());
// bool(true) — CLI has no REQUEST_METHOD, treated as GET
