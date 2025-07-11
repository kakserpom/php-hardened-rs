<?php
use Hardened\SecurityHeaders\ContentSecurityPolicy;

// Create a new CSP builder
$policy = new ContentSecurityPolicy();

// default-src 'self' *.site.tld blob:
$policy->setRule(
    ContentSecurityPolicy::DEFAULT_SRC,
    [ContentSecurityPolicy::SELF],
    ['*.site.tld', 'blob:']
);

// script-src 'self' 'nonce-…' https://cdn.site.tld/js
$policy->setRule(
    ContentSecurityPolicy::SCRIPT_SRC,
    [ContentSecurityPolicy::SELF, ContentSecurityPolicy::NONCE],
    ['https://cdn.site.tld/js']
);

// style-src 'self' 'nonce-…' https://fonts.googleapis.com
$policy->setRule(
    ContentSecurityPolicy::STYLE_SRC,
    [ContentSecurityPolicy::SELF, ContentSecurityPolicy::NONCE],
    ['https://fonts.googleapis.com']
);

// img-src 'self' data: *.images.site.tld
$policy->setRule(
    ContentSecurityPolicy::IMG_SRC,
    [ContentSecurityPolicy::SELF],
    ['data:', '*.images.site.tld']
);

// connect-src 'self' https://api.site.tld
$policy->setRule(
    ContentSecurityPolicy::CONNECT_SRC,
    [ContentSecurityPolicy::SELF],
    ['https://api.site.tld']
);

// frame-ancestors 'none'
$policy->setRule(
    ContentSecurityPolicy::FRAME_ANCESTORS,
    [],        // no keywords
    []         // empty list => effectively 'none'
);

// Build and display the value
var_dump($policy->build());

// Get and display the nonce
var_dump($policy->getNonce());

// Build and send the header
$policy->send();
