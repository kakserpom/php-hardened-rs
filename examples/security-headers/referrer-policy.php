<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\ReferrerPolicy;

// Default policy (no-referrer)
$rp = new ReferrerPolicy();

// Specify initial policy
$rp = new ReferrerPolicy('origin-when-cross-origin');

// Override later
$rp->setPolicy('strict-origin');

// Get the header value
$value = $rp->build();
// e.g. "strict-origin"

// Send the header
header('Referrer-Policy: ' . $value);

// Or simply:
$rp->send();