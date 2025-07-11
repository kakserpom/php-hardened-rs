<?php
use Hardened\SecurityHeaders\MiscHeaders;

$misc = new MiscHeaders();

// Frame options
$misc->setFrameOptions('DENY');
$misc->setFrameOptions('ALLOW-FROM', 'https://example.com');

// XSS protection
$misc->setXssProtection('on');
$misc->setXssProtection('block');
$misc->setXssProtection('block', 'https://report.example.com'); // Block with a report URI

// No-sniff
$misc->setNosniff(true);

// Cross-domain policies
$misc->setPermittedCrossDomainPolicies('none');

$misc->setReportTo(
    'csp-endpoint',          // group
    10886400,                // max_age
    true,                    // include_subdomains
    ['primary', 'backup']    // endpoints
);

// Structured Integrity-Policy
$misc->setIntegrityPolicy(
    ['script'],                    // blocked-destinations
    ['inline'],                    // sources (optional, defaults to ['inline'])
    ['csp-endpoint','backup']      // endpoints (optional)
);

// Apply headers
foreach ($misc->build() as $name => $value) {
    header("$name: $value");
}

// Or simply:
$misc->send();
