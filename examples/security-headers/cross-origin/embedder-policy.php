<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicy;
use Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicyValue;

$policy = new EmbedderPolicy();                    // defaults to "unsafe-none"
echo $policy->build();                   // outputs "unsafe-none"

$policy = new EmbedderPolicy(EmbedderPolicyValue::RequireCorp);
$policy->set(EmbedderPolicyValue::Credentialless);
echo $policy->build();                   // "credentialless"

$policy->send();                         // sends header
