<?php
use Hardened\SecurityHeaders\Hsts;

// Create and configure HSTS
$hsts = new Hsts();
$hsts->maxAge(31536000);            // one year
$hsts->includeSubDomains(true);     // apply to all subdomains
$hsts->preload(true);               // request inclusion in browser preload lists

// Get header value
$value = $hsts->build();
// e.g. "max-age=31536000; includeSubDomains; preload"

// Send header to client
header('Strict-Transport-Security: ' . $value);

// Or simply:
// $hsts->send();
