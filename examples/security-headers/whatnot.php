<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\Whatnot;
use Hardened\SecurityHeaders\FrameOptions;
use Hardened\SecurityHeaders\XssProtection;
use Hardened\SecurityHeaders\CrossDomainPolicy;

$policy = new Whatnot();

// Frame options
$policy->setFrameOptions(FrameOptions::Deny);
$policy->setFrameOptions(FrameOptions::AllowFrom, 'https://example.com');

// XSS protection
$policy->setXssProtection(XssProtection::On);
$policy->setXssProtection(XssProtection::Block);
$policy->setXssProtection(XssProtection::Block, 'https://report.example.com'); // Block with a report URI

// No-sniff
$policy->setNosniff(true);

// Cross-domain policies
$policy->setPermittedCrossDomainPolicies(CrossDomainPolicy::None);

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

// Structured Integrity-Policy-Report-Only (same arguments as setIntegrityPolicy)
$policy->setIntegrityPolicyReportOnly(
    ['script'],                    // blocked-destinations
    ['inline'],                    // sources (optional)
    ['report-endpoint']            // endpoints (optional)
);

// Apply headers
foreach ($policy->build() as $name => $value) {
    header("$name: $value");
}

// Or simply:
$policy->send();
