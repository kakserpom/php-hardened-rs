<?php
use Hardened\SecurityHeaders\CorsPolicy;

$cors = new CorsPolicy();

// Allow specific origins or use ['*'] for wildcard
$cors->allowOrigins(['https://example.com', 'https://api.example.com']);

// Permit HTTP methods
$cors->allowMethods(['GET', 'POST', 'OPTIONS']);

// Permit request headers
$cors->allowHeaders(['Content-Type', 'Authorization']);

// Allow cookies/auth credentials
$cors->allowCredentials(true);

// Expose custom response headers to the browser
$cors->exposeHeaders(['X-Custom-Header']);

// Cache preflight response for 3600 seconds
$cors->maxAge(3600);

// Apply headers manually
foreach ($cors->build() as $name => $value) {
    header("$name: $value");
}

// Or simply:
$cors->send();
