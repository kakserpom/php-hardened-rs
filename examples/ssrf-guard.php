<?php
use Hardened\SsrfGuard;

$guard = new SsrfGuard(); // http/https, ports 80/443, reserved ranges denied

// Pure policy checks (no network access)
var_dump($guard->isIpAllowed("93.184.216.34"));
// bool(true)
var_dump($guard->isIpAllowed("127.0.0.1"));
// bool(false)
var_dump($guard->isIpAllowed("169.254.169.254"));
// bool(false) — cloud metadata endpoint
var_dump($guard->isIpAllowed("::ffff:10.0.0.1"));
// bool(false) — IPv4-mapped IPv6 is not a bypass

// URL validation: scheme, port, userinfo, and every resolved address
try {
    $guard->validateUrl("http://169.254.169.254/latest/meta-data/");
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2206) — forbidden IP
}
try {
    $guard->validateUrl("http://localhost/admin");
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2206) — resolves to loopback
}
try {
    $guard->validateUrl("ftp://example.com/");
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2201) — forbidden scheme
}

// Deliberately allow one internal service
$guard->allowCidr("10.0.5.20");
var_dump($guard->isIpAllowed("10.0.5.20"));
// bool(true)
var_dump($guard->isIpAllowed("10.0.5.21"));
// bool(false)

// DNS-rebinding-safe fetch: resolve once, validate, pin the connection.
$pinned = $guard->validateUrl("http://1.1.1.1/");
var_dump($pinned);
// array(1) { [0]=> string(7) "1.1.1.1" }
var_dump($guard->curlResolve("http://1.1.1.1/"));
// string(18) "1.1.1.1:80:1.1.1.1"
//
// $ch = curl_init($url);
// curl_setopt($ch, CURLOPT_RESOLVE, [$guard->curlResolve($url)]);
// curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // validate every hop instead
