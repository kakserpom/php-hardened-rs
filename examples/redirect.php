<?php
use Hardened\Redirect;

$redirect = new Redirect(["trusted.example"], true); // allow subdomains

// Same-origin relative targets are safe
var_dump($redirect->isSafe("/dashboard?tab=1"));
// bool(true)

// Allowlisted host (and subdomains, as configured)
var_dump($redirect->isSafe("https://trusted.example/account"));
// bool(true)
var_dump($redirect->isSafe("https://login.trusted.example/"));
// bool(true)

// Classic open-redirect bypasses are rejected
var_dump($redirect->isSafe("//evil.com"));
// bool(false)
var_dump($redirect->isSafe("/\\evil.com"));
// bool(false)
var_dump($redirect->isSafe("https:/evil.com"));
// bool(false)
var_dump($redirect->isSafe("https://trusted.example@evil.com/"));
// bool(false)
var_dump($redirect->isSafe("javascript:alert(1)"));
// bool(false)
var_dump($redirect->isSafe("https://trusted.example.evil.com/"));
// bool(false)

var_dump($redirect->sanitize("https://evil.com/phish", "/home"));
// string(5) "/home"

// Static one-shot helpers
var_dump(Redirect::isSafeUrl("https://app.example/cb", ["app.example"]));
// bool(true)
var_dump(Redirect::sanitizeUrl("//evil.com", ["app.example"]));
// string(1) "/"
