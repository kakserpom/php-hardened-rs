<?php
declare(strict_types=1);

use Hardened\SecurityHeaders\CrossOrigin\OpenerPolicy;

// 2) Opener policy: isolate this window from cross-origin windows
$policy = new OpenerPolicy('same-origin');  // initialize directly to "same-origin"
$policy->send();                     // emits header internally

// 3) Or build() yourself:
echo $policy->build(); // "require-corp"
