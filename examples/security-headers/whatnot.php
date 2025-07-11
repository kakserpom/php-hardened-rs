<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\Whatnot;

$policy = new Whatnot();

// Frame options
$policy->setFrameOptions('DENY');
$policy->setFrameOptions('ALLOW-FROM', 'https://example.com');

// XSS protection
$policy->setXssProtection('on');
$policy->setXssProtection('block');
$policy->setXssProtection('block', 'https://report.example.com'); // Block with a report URI

// No-sniff
$policy->setNosniff(true);

// Cross-domain policies
$policy->setPermittedCrossDomainPolicies('none');

$policy->setReportTo(
    'csp-endpoint',          // group
    10886400,                // max_age
    true,                    // include_subdomains
    ['primary', 'backup']    // endpoints
);

// Structured Integrity-Policy
$policy->setIntegrityPolicy(
    ['script'],                    // blocked-destinations
    ['inline'],                    // sources (optional, defaults to ['inline'])
    ['csp-endpoint','backup']      // endpoints (optional)
);

// Apply headers
foreach ($policy->build() as $name => $value) {
    header("$name: $value");
}

// Or simply:
$policy->send();
