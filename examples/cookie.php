<?php
use Hardened\Cookie;

// Hardened defaults: Secure, HttpOnly, SameSite=Lax, Path=/
$cookie = new Cookie("session", "abc123");
var_dump($cookie->build());
// string(53) "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
// $cookie->send(); // emits the Set-Cookie header without replacing others

$pref = new Cookie("pref", "dark");
$pref->setPath("/app");
$pref->setDomain("example.com");
$pref->setMaxAge(3600);
$pref->setSameSite("Strict");
$pref->setHttpOnly(false);
var_dump($pref->build());
// string(74) "pref=dark; Path=/app; Domain=example.com; Max-Age=3600; Secure; SameSite=Strict"

// Header splitting is unrepresentable: bad bytes never reach the wire
try {
    new Cookie("evil", "v\r\nSet-Cookie: hijack=1");
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2701)
}

// __Host- prefix invariants are enforced at build time
$host = new Cookie("__Host-session", "v");
var_dump($host->build());
// string(60) "__Host-session=v; Path=/; Secure; HttpOnly; SameSite=Lax"
try {
    $broken = new Cookie("__Host-session", "v");
    $broken->setDomain("example.com");
    $broken->build();
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2703)
}

// SameSite=None without Secure refuses to build
try {
    $tracker = new Cookie("tracker", "v");
    $tracker->setSameSite("None");
    $tracker->setSecure(false);
    $tracker->build();
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2704)
}
