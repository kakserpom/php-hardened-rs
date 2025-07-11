<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\CrossOrigin\Coep;

$coep = new Coep();                    // defaults to "unsafe-none"
echo $coep->build();                   // outputs "unsafe-none"

$coep = new Coep("require-corp");
$coep->setPolicy("credentialless");
echo $coep->build();                   // "credentialless"

$coep->send();                         // sends header