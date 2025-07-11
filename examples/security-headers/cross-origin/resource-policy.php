<?php
use Hardened\SecurityHeaders\CrossOrigin\ResourcePolicy;

$policy = new ResourcePolicy();                   // default "same-origin"
echo $policy->build();                            // "same-origin"

$policy->set('cross-origin');
header('Cross-Origin-Resource-Policy: ' . $policy->build());
// or
$policy->send();
