<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\PermissionsPolicy;

// 1) Instantiate the builder
$policy = new PermissionsPolicy();

// 2) Allow features with specific allowlists:
//    - geolocation: only same-origin and https://api.example.com
$policy->allow(
    PermissionsPolicy::GEOLOCATION,
    [ PermissionsPolicy::ORIGIN_SELF, 'https://api.example.com' ]
);

//    - sync-xhr: only the “src” allowlist token
$policy->allow(
    PermissionsPolicy::BLUETOOTH,
    [ PermissionsPolicy::ORIGIN_SRC ]
);

// 3) Deny features entirely (empty allowlist):
//    - camera
$policy->deny(PermissionsPolicy::CAMERA);

//    - microphone
$policy->deny(PermissionsPolicy::MICROPHONE);

// 4) Build the header value and emit it
header('Permissions-Policy: ' . $policy->build());

//—or— use the convenience send() method
// $policy->send();
