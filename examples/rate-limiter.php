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

// CL.THROTTLE mode: atomic server-side GCRA on DragonflyDB (built in) or
// Redis + redis-cell — the strongest backend: one round-trip, shared across
// all workers and hosts. The limiter maps its config onto the command:
var_dump($limiter->clThrottleCommand("login:203.0.113.7"));
// array(6) { "CL.THROTTLE", "login:203.0.113.7", "2", "1", "60", "1" }
// — burst 3 (max_burst 2 + 1), 1 token per 60s

// With a real client: $reply = $redis->rawCommand(...$limiter->clThrottleCommand($key));
// Here the server reply is simulated:
$result = $limiter->attemptClThrottle(
    "login:203.0.113.7",
    fn (...$cmd) => [0, 3, 2, -1, 60], // e.g. fn (...$cmd) => $redis->rawCommand(...$cmd)
);
var_dump($result['allowed'], $result['remaining'], $result['retryAfterSec']);
// bool(true)
// int(2)
// int(0)
var_dump(RateLimiter::clThrottleParse([1, 3, 0, 42, 180]));
// array(5) { ["allowed"]=> bool(false), ["limit"]=> int(3), ["remaining"]=> int(0),
//            ["retryAfterSec"]=> int(42), ["resetAfterSec"]=> int(180) }
