<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\CrossOrigin\ResourceSharing;

$policy = new ResourceSharing();

// Allow specific origins or use ['*'] for wildcard
$policy->allowOrigins(['https://example.com', 'https://api.example.com', ResourceSharing::SELF]);

// Permit HTTP methods
$policy->allowMethods(['GET', 'POST', 'OPTIONS']);

// Permit request headers
$policy->allowHeaders(['Content-Type', 'Authorization']);

// Allow cookies/auth credentials
$policy->allowCredentials(true);

// Expose custom response headers to the browser
$policy->exposeHeaders(['X-Custom-Header']);

// Cache preflight response for 3600 seconds
$policy->maxAge(3600);

// Apply headers manually
foreach ($policy->build() as $name => $value) {
    header("$name: $value");
}

// Or simply:
$policy->send();
