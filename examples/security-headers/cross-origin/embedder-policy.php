<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\CrossOrigin\EmbedderPolicy;

$policy = new EmbedderPolicy();                    // defaults to "unsafe-none"
echo $policy->build();                   // outputs "unsafe-none"

$policy = new EmbedderPolicy("require-corp");
$policy->set(EmbedderPolicy::CREDENTIALLESS);
echo $policy->build();                   // "credentialless"

$policy->send();                         // sends header
