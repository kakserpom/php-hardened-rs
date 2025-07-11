<?php
use Hardened\SecurityHeaders\CrossOrigin\ResourcePolicy;

$policy = new ResourcePolicy();                   // default "same-origin"
echo $policy->build();                            // "same-origin"

$policy->set('cross-origin');
$policy('Cross-Origin-Resource-Policy: ' . $rp->build());
// or
$policy->send();
