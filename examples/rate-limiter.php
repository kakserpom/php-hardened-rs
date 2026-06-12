<?php
use Hardened\RateLimiter;

// Burst of 3, refilling 1 token per minute
$limiter = new RateLimiter(3, 1, 60_000);
$key = "login:203.0.113.7";

var_dump($limiter->attempt($key));
// bool(true)
var_dump($limiter->attempt($key));
// bool(true)
var_dump($limiter->attempt($key));
// bool(true)
var_dump($limiter->attempt($key));
// bool(false) — burst exhausted
var_dump($limiter->retryAfterMs($key) > 0);
// bool(true) — suitable for a Retry-After header
var_dump($limiter->remaining($key));
// int(0)

$limiter->reset($key);
var_dump($limiter->attempt($key));
// bool(true)

// Shared-store mode: the limiter is stateless, the opaque state string
// lives wherever you want (APCu, Redis, database, session).
$state = null; // e.g. apcu_fetch("rl:$ip") ?: null
[$allowed, $state, $retryAfterMs] = $limiter->attemptStateful($state);
var_dump($allowed, $retryAfterMs);
// bool(true)
// int(0)
[$allowed, $state] = $limiter->attemptStateful($state, 2);
var_dump($allowed);
// bool(true)
[$allowed, $state, $retryAfterMs] = $limiter->attemptStateful($state);
var_dump($allowed, $retryAfterMs > 0);
// bool(false) — 3 tokens consumed
// bool(true)
// then: apcu_store("rl:$ip", $state, 3600);
