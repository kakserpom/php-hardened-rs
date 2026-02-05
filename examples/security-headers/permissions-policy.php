<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\PermissionsPolicy;
use Hardened\SecurityHeaders\PermissionsPolicyFeature;

// 1) Instantiate the builder
$policy = new PermissionsPolicy();

// 2) Allow features with specific allowlists:
//    - geolocation: only same-origin and https://api.example.com
$policy->allow(
    PermissionsPolicyFeature::Geolocation,
    [ PermissionsPolicy::ORIGIN_SELF, 'https://api.example.com' ]
);

//    - bluetooth: only the "src" allowlist token
$policy->allow(
    PermissionsPolicyFeature::Bluetooth,
    [ PermissionsPolicy::ORIGIN_SRC ]
);

// 3) Deny features entirely (empty allowlist):
//    - camera
$policy->deny(PermissionsPolicyFeature::Camera);

//    - microphone
$policy->deny(PermissionsPolicyFeature::Microphone);

// 4) Build the header value and emit it
header('Permissions-Policy: ' . $policy->build());

//—or— use the convenience send() method
// $policy->send();
