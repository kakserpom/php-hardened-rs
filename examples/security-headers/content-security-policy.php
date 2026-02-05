<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\ContentSecurityPolicy;
use Hardened\SecurityHeaders\CspRule;
use Hardened\SecurityHeaders\CspKeyword;

// Create a new CSP builder
$policy = new ContentSecurityPolicy();

// default-src 'self' *.site.tld blob:
$policy->setRule(
    CspRule::DefaultSrc,
    [CspKeyword::SelfOrigin],
    ['*.site.tld', 'blob:']
);

// script-src 'self' 'nonce-…' https://cdn.site.tld/js
$policy->setRule(
    CspRule::ScriptSrc,
    [CspKeyword::SelfOrigin, CspKeyword::Nonce],
    ['https://cdn.site.tld/js']
);

// style-src 'self' 'nonce-…' https://fonts.googleapis.com
$policy->setRule(
    CspRule::StyleSrc,
    [CspKeyword::SelfOrigin, CspKeyword::Nonce],
    ['https://fonts.googleapis.com']
);

// img-src 'self' data: *.images.site.tld
$policy->setRule(
    CspRule::ImgSrc,
    [CspKeyword::SelfOrigin],
    ['data:', '*.images.site.tld']
);

// connect-src 'self' https://api.site.tld
$policy->setRule(
    CspRule::ConnectSrc,
    [CspKeyword::SelfOrigin],
    ['https://api.site.tld']
);

// frame-ancestors 'none'
$policy->setRule(
    CspRule::FrameAncestors,
    [],        // no keywords
    []         // empty list => effectively 'none'
);

// Build and display the value
var_dump($policy->build());

// Get and display the nonce
var_dump($policy->getNonce());

// Build and send the header
$policy->send();
