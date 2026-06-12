use ext_php_rs::convert::{FromZval, IntoZval, IntoZvalDyn};
use ext_php_rs::exception::PhpException;
use ext_php_rs::types::{ZendCallable, ZendHashTable, Zval};
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// Error codes for rate limiter errors: 2400-2499
pub mod error_codes {
    pub const INVALID_CONFIG: i32 = 2400;
    pub const INVALID_STATE: i32 = 2401;
    pub const CONVERSION: i32 = 2402;
    pub const INVALID_THROTTLE_RESPONSE: i32 = 2403;
    pub const CALLBACK_FAILED: i32 = 2404;
}

/// Errors that can occur during rate limiting operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid rate limiter configuration: {0}")]
    InvalidConfig(String),

    #[error("Invalid rate limiter state string")]
    InvalidState,

    #[error("Invalid CL.THROTTLE response: {0}")]
    InvalidThrottleResponse(String),

    #[error("CL.THROTTLE callback failed: {0}")]
    CallbackFailed(String),

    #[error("Failed to convert value: {0}")]
    Conversion(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidConfig(_) => error_codes::INVALID_CONFIG,
            Error::InvalidState => error_codes::INVALID_STATE,
            Error::InvalidThrottleResponse(_) => error_codes::INVALID_THROTTLE_RESPONSE,
            Error::CallbackFailed(_) => error_codes::CALLBACK_FAILED,
            Error::Conversion(_) => error_codes::CONVERSION,
        }
    }
}

impl From<Error> for PhpException {
    fn from(err: Error) -> Self {
        let code = err.code();
        let message = err.to_string();
        PhpException::new(message, code, ce::exception())
    }
}

/// Result type alias for rate limiter operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Tokens are tracked in thousandths so refill math stays in integers.
const MILLI: u64 = 1000;

/// Soft cap on the process-local store; an opportunistic sweep evicts
/// fully-refilled buckets (identical to absent ones) when it is exceeded.
const STORE_SOFT_CAP: usize = 100_000;

#[derive(Clone, Copy)]
struct Bucket {
    tokens_milli: u64,
    updated_ms: u64,
}

static STORE: LazyLock<Mutex<HashMap<String, Bucket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Token-bucket rate limiter.
///
/// A bucket holds up to `capacity` tokens and refills at `refillTokens` per
/// `refillIntervalMs`. Each attempt consumes tokens; an empty bucket means
/// the action is rate-limited. This shape allows short bursts up to
/// `capacity` while capping the sustained rate.
///
/// Three storage modes:
/// - **Process-local** (`attempt()`, keyed by string): zero setup. Note that
///   under php-fpm each worker process keeps its own counters, so the
///   effective limit is multiplied by the number of workers.
/// - **External** (`attemptStateful()`): the limiter is stateless; you keep
///   the opaque state string anywhere shared — APCu, Redis, a session — and
///   pass it back on the next attempt. Use your store's locking/CAS if
///   strict accounting under concurrency is required.
/// - **`CL.THROTTLE`** (`attemptClThrottle()` / `clThrottleCommand()`): the
///   strongest backend — atomic server-side GCRA in DragonflyDB (built in)
///   or Redis with the redis-cell module. One round-trip, shared across all
///   workers and hosts, no read-modify-write race.
#[php_class]
#[php(name = "Hardened\\RateLimiter")]
pub struct RateLimiter {
    capacity_milli: u64,
    refill_tokens_milli: u64,
    refill_interval_ms: u64,
}

impl RateLimiter {
    /// Refills `bucket` according to the time elapsed since its last update.
    fn _refill(&self, bucket: &mut Bucket, now: u64) {
        let elapsed = now.saturating_sub(bucket.updated_ms);
        if elapsed == 0 {
            return;
        }
        let refilled = u128::from(elapsed) * u128::from(self.refill_tokens_milli)
            / u128::from(self.refill_interval_ms);
        let refilled = u64::try_from(refilled).unwrap_or(u64::MAX);
        bucket.tokens_milli = bucket
            .tokens_milli
            .saturating_add(refilled)
            .min(self.capacity_milli);
        bucket.updated_ms = now;
    }

    /// Core token-bucket step: refill, then try to consume `cost` tokens.
    /// Returns `(allowed, retry_after_ms)`.
    fn _attempt_bucket(&self, bucket: &mut Bucket, cost: u64, now: u64) -> (bool, u64) {
        self._refill(bucket, now);
        let cost_milli = cost.saturating_mul(MILLI);
        if bucket.tokens_milli >= cost_milli {
            bucket.tokens_milli -= cost_milli;
            return (true, 0);
        }
        let missing = u128::from(cost_milli - bucket.tokens_milli);
        let retry_after = missing * u128::from(self.refill_interval_ms)
            / u128::from(self.refill_tokens_milli)
            + 1;
        (false, u64::try_from(retry_after).unwrap_or(u64::MAX))
    }

    fn _full_bucket(&self, now: u64) -> Bucket {
        Bucket {
            tokens_milli: self.capacity_milli,
            updated_ms: now,
        }
    }

    /// Namespaces a caller key with the limiter configuration so that two
    /// limiters with different rates never share a bucket by accident.
    fn _store_key(&self, key: &str) -> String {
        format!(
            "{}:{}:{}:{key}",
            self.capacity_milli, self.refill_tokens_milli, self.refill_interval_ms
        )
    }

    fn _attempt_local(&self, key: &str, cost: u64, now: u64) -> (bool, u64) {
        let mut store = STORE.lock().expect("rate limiter store poisoned");
        if store.len() > STORE_SOFT_CAP {
            store.retain(|_, bucket| {
                bucket.tokens_milli < self.capacity_milli
                    && now.saturating_sub(bucket.updated_ms) < self.refill_interval_ms * 100
            });
        }
        let bucket = store
            .entry(self._store_key(key))
            .or_insert_with(|| self._full_bucket(now));
        self._attempt_bucket(bucket, cost, now)
    }

    fn _serialize(bucket: &Bucket) -> String {
        format!("v1:{}:{}", bucket.tokens_milli, bucket.updated_ms)
    }

    fn _deserialize(&self, state: &str, now: u64) -> Result<Bucket> {
        let mut parts = state.split(':');
        let (Some("v1"), Some(tokens), Some(updated), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::InvalidState);
        };
        let tokens_milli: u64 = tokens.parse().map_err(|_| Error::InvalidState)?;
        let updated_ms: u64 = updated.parse().map_err(|_| Error::InvalidState)?;
        Ok(Bucket {
            // Never trust a state string into granting more than capacity.
            tokens_milli: tokens_milli.min(self.capacity_milli),
            updated_ms: updated_ms.min(now),
        })
    }

    /// Maps this limiter's configuration onto `CL.THROTTLE` arguments:
    /// `(max_burst, count_per_period, period_seconds)`.
    ///
    /// `CL.THROTTLE` allows `max_burst + 1` in a burst, so `max_burst` is
    /// `capacity - 1`. Its refill rate is `count / period` with the period in
    /// whole seconds, so the configured `refill_tokens / refill_interval_ms`
    /// rate is expressed as the exactly-equal reduced fraction
    /// `refill_tokens * 1000 / refill_interval_ms` per second.
    fn _cl_throttle_args(&self) -> (u64, u64, u64) {
        fn gcd(mut a: u64, mut b: u64) -> u64 {
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a
        }
        let max_burst = self.capacity_milli / MILLI - 1;
        // refill_tokens_milli == refill_tokens * 1000
        let divisor = gcd(self.refill_tokens_milli, self.refill_interval_ms);
        (
            max_burst,
            self.refill_tokens_milli / divisor,
            self.refill_interval_ms / divisor,
        )
    }

    fn _cl_throttle_command(&self, key: &str, cost: u64) -> Vec<String> {
        let (max_burst, count, period) = self._cl_throttle_args();
        vec![
            "CL.THROTTLE".to_string(),
            key.to_string(),
            max_burst.to_string(),
            count.to_string(),
            period.to_string(),
            cost.to_string(),
        ]
    }

    /// Interprets the five-integer `CL.THROTTLE` reply:
    /// `[limited, limit, remaining, retry_after_s, reset_after_s]`.
    fn _cl_throttle_decision(response: &[i64]) -> Result<ThrottleDecision> {
        let &[limited, limit, remaining, retry_after, reset_after] = response else {
            return Err(Error::InvalidThrottleResponse(format!(
                "expected 5 integers, got {}",
                response.len()
            )));
        };
        Ok(ThrottleDecision {
            allowed: limited == 0,
            limit,
            remaining,
            // -1 means "not limited"
            retry_after_sec: retry_after.max(0),
            reset_after_sec: reset_after.max(0),
        })
    }
}

struct ThrottleDecision {
    allowed: bool,
    limit: i64,
    remaining: i64,
    retry_after_sec: i64,
    reset_after_sec: i64,
}

impl ThrottleDecision {
    fn into_zval(self) -> Result<Zval> {
        let into = |err: ext_php_rs::error::Error| Error::Conversion(err.to_string());
        let mut table = ZendHashTable::new();
        let mut insert = |key, value: Zval| {
            table
                .insert(key, value)
                .map_err(|e| Error::Conversion(e.to_string()))
        };
        insert("allowed", self.allowed.into_zval(false).map_err(into)?)?;
        insert("limit", self.limit.into_zval(false).map_err(into)?)?;
        insert("remaining", self.remaining.into_zval(false).map_err(into)?)?;
        insert(
            "retryAfterSec",
            self.retry_after_sec.into_zval(false).map_err(into)?,
        )?;
        insert(
            "resetAfterSec",
            self.reset_after_sec.into_zval(false).map_err(into)?,
        )?;
        table.into_zval(false).map_err(into)
    }
}

#[php_impl]
impl RateLimiter {
    /// Constructs a token-bucket rate limiter.
    ///
    /// Example: `new RateLimiter(100, 10, 1000)` allows bursts of 100 and a
    /// sustained 10 requests per second.
    ///
    /// # Parameters
    /// - `capacity`: Maximum tokens the bucket holds (burst size), > 0.
    /// - `refill_tokens`: Tokens added per interval, > 0.
    /// - `refill_interval_ms`: Refill interval in milliseconds, > 0.
    ///
    /// # Exceptions
    /// - Throws an exception if any parameter is zero.
    fn __construct(capacity: u64, refill_tokens: u64, refill_interval_ms: u64) -> Result<Self> {
        if capacity == 0 || refill_tokens == 0 || refill_interval_ms == 0 {
            return Err(Error::InvalidConfig(
                "capacity, refill_tokens and refill_interval_ms must be > 0".to_string(),
            ));
        }
        let capacity_milli = capacity
            .checked_mul(MILLI)
            .ok_or_else(|| Error::InvalidConfig("capacity too large".to_string()))?;
        let refill_tokens_milli = refill_tokens
            .checked_mul(MILLI)
            .ok_or_else(|| Error::InvalidConfig("refill_tokens too large".to_string()))?;
        Ok(Self {
            capacity_milli,
            refill_tokens_milli,
            refill_interval_ms,
        })
    }

    /// Attempts to consume tokens for `key` from the process-local store.
    ///
    /// # Parameters
    /// - `key`: Identifier to limit on, e.g. `"login:" . $ip`.
    /// - `cost`: Tokens this attempt consumes (defaults to 1).
    ///
    /// # Returns
    /// - `bool`: `true` if allowed, `false` if rate-limited.
    fn attempt(&self, key: &str, cost: Option<u64>) -> bool {
        self._attempt_local(key, cost.unwrap_or(1), now_ms()).0
    }

    /// Returns how long to wait (in milliseconds) until an attempt for `key`
    /// with the given cost could succeed. Does not consume tokens.
    ///
    /// # Parameters
    /// - `key`: Identifier to limit on.
    /// - `cost`: Tokens the attempt would consume (defaults to 1).
    ///
    /// # Returns
    /// - `int`: `0` if an attempt would currently succeed, otherwise the
    ///   wait time in milliseconds (suitable for a `Retry-After` header).
    fn retry_after_ms(&self, key: &str, cost: Option<u64>) -> u64 {
        let now = now_ms();
        let store = STORE.lock().expect("rate limiter store poisoned");
        let mut bucket = store
            .get(&self._store_key(key))
            .copied()
            .unwrap_or_else(|| self._full_bucket(now));
        drop(store);
        // Work on a copy: peeking must not consume.
        self._attempt_bucket(&mut bucket, cost.unwrap_or(1), now).1
    }

    /// Returns the number of whole tokens currently available for `key`.
    ///
    /// # Parameters
    /// - `key`: Identifier to limit on.
    ///
    /// # Returns
    /// - `int`: Available tokens, after refill, without consuming any.
    fn remaining(&self, key: &str) -> u64 {
        let now = now_ms();
        let store = STORE.lock().expect("rate limiter store poisoned");
        let mut bucket = store
            .get(&self._store_key(key))
            .copied()
            .unwrap_or_else(|| self._full_bucket(now));
        self._refill(&mut bucket, now);
        bucket.tokens_milli / MILLI
    }

    /// Removes the process-local bucket for `key`, restoring it to full.
    ///
    /// # Parameters
    /// - `key`: Identifier to reset.
    fn reset(&self, key: &str) {
        STORE
            .lock()
            .expect("rate limiter store poisoned")
            .remove(&self._store_key(key));
    }

    /// Attempts to consume tokens against an externally-stored state string,
    /// for shared backends (APCu, Redis, database, session).
    ///
    /// ```php
    /// $state = apcu_fetch("rl:$ip") ?: null;
    /// [$allowed, $state, $retryAfterMs] = $limiter->attemptStateful($state);
    /// apcu_store("rl:$ip", $state, 3600);
    /// if (!$allowed) { http_response_code(429); }
    /// ```
    ///
    /// # Parameters
    /// - `state`: The state string from the previous call, or `null` for a
    ///   fresh (full) bucket.
    /// - `cost`: Tokens this attempt consumes (defaults to 1).
    ///
    /// # Returns
    /// - `array{0: bool, 1: string, 2: int}`: whether the attempt is allowed,
    ///   the new state string to store, and the retry-after hint in
    ///   milliseconds (`0` when allowed).
    ///
    /// # Exceptions
    /// - Throws an exception if `state` is not a valid state string.
    fn attempt_stateful(&self, state: Option<String>, cost: Option<u64>) -> Result<Vec<Zval>> {
        let now = now_ms();
        let mut bucket = match state {
            Some(state) => self._deserialize(&state, now)?,
            None => self._full_bucket(now),
        };
        let (allowed, retry_after) = self._attempt_bucket(&mut bucket, cost.unwrap_or(1), now);
        let into = |err: ext_php_rs::error::Error| Error::Conversion(err.to_string());
        Ok(vec![
            allowed.into_zval(false).map_err(into)?,
            Self::_serialize(&bucket).into_zval(false).map_err(into)?,
            i64::try_from(retry_after)
                .unwrap_or(i64::MAX)
                .into_zval(false)
                .map_err(into)?,
        ])
    }

    /// Builds the `CL.THROTTLE` command equivalent to this limiter's
    /// configuration, for atomic server-side rate limiting on DragonflyDB
    /// (built in) or Redis with the redis-cell module. This is the strongest
    /// backend: one round-trip, GCRA, no read-modify-write race.
    ///
    /// ```php
    /// $reply = $redis->rawCommand(...$limiter->clThrottleCommand("login:$ip"));
    /// $result = RateLimiter::clThrottleParse($reply);
    /// ```
    ///
    /// # Parameters
    /// - `key`: The key to limit on (used verbatim — add your own prefix).
    /// - `cost`: Tokens this attempt consumes (defaults to 1).
    ///
    /// # Returns
    /// - `string[]`: The full command, e.g.
    ///   `["CL.THROTTLE", "login:1.2.3.4", "9", "1", "12", "1"]`.
    fn cl_throttle_command(&self, key: &str, cost: Option<u64>) -> Vec<String> {
        self._cl_throttle_command(key, cost.unwrap_or(1))
    }

    /// Parses a `CL.THROTTLE` reply (five integers) into a decision array.
    ///
    /// # Parameters
    /// - `response`: The raw reply array from the server.
    ///
    /// # Returns
    /// - `array{allowed: bool, limit: int, remaining: int, retryAfterSec: int,
    ///   resetAfterSec: int}`: `retryAfterSec` is `0` when allowed.
    ///
    /// # Exceptions
    /// - Throws an exception if the reply is not five integers.
    fn cl_throttle_parse(response: Vec<i64>) -> Result<Zval> {
        Self::_cl_throttle_decision(&response)?.into_zval()
    }

    /// One-call `CL.THROTTLE` attempt through any PHP Redis client: the
    /// command is passed to `raw_command` as variadic string arguments, and
    /// the reply is parsed into a decision array.
    ///
    /// ```php
    /// $result = $limiter->attemptClThrottle(
    ///     "login:$ip",
    ///     fn (...$cmd) => $redis->rawCommand(...$cmd), // phpredis
    /// );
    /// if (!$result['allowed']) {
    ///     header("Retry-After: " . $result['retryAfterSec']);
    ///     http_response_code(429);
    /// }
    /// ```
    ///
    /// # Parameters
    /// - `key`: The key to limit on (used verbatim — add your own prefix).
    /// - `raw_command`: Callable receiving the command as variadic strings
    ///   and returning the server reply array.
    /// - `cost`: Tokens this attempt consumes (defaults to 1).
    ///
    /// # Returns
    /// - `array{allowed: bool, limit: int, remaining: int, retryAfterSec: int,
    ///   resetAfterSec: int}`.
    ///
    /// # Exceptions
    /// - Throws an exception if the callable fails or the reply is not five
    ///   integers.
    fn attempt_cl_throttle(
        &self,
        key: &str,
        raw_command: ZendCallable,
        cost: Option<u64>,
    ) -> Result<Zval> {
        let command = self._cl_throttle_command(key, cost.unwrap_or(1));
        let params: Vec<&dyn IntoZvalDyn> = command
            .iter()
            .map(|part| part as &dyn IntoZvalDyn)
            .collect();
        let reply = raw_command
            .try_call(params)
            .map_err(|e| Error::CallbackFailed(e.to_string()))?;
        let response = Vec::<i64>::from_zval(&reply).ok_or_else(|| {
            Error::InvalidThrottleResponse("reply is not an array of integers".to_string())
        })?;
        Self::_cl_throttle_decision(&response)?.into_zval()
    }
}

#[cfg(test)]
mod tests {
    use super::{Bucket, RateLimiter};
    use crate::run_php_example;

    fn limiter(capacity: u64, refill_tokens: u64, interval_ms: u64) -> RateLimiter {
        RateLimiter::__construct(capacity, refill_tokens, interval_ms).unwrap()
    }

    #[test]
    fn test_burst_then_limited() {
        let rl = limiter(3, 1, 1000);
        let mut bucket = rl._full_bucket(1_000_000);
        for _ in 0..3 {
            assert!(rl._attempt_bucket(&mut bucket, 1, 1_000_000).0);
        }
        let (allowed, retry_after) = rl._attempt_bucket(&mut bucket, 1, 1_000_000);
        assert!(!allowed);
        // One token refills in 1000ms
        assert!((1000..=1001).contains(&retry_after), "{retry_after}");
    }

    #[test]
    fn test_refill_over_time() {
        let rl = limiter(10, 5, 1000);
        let mut bucket = rl._full_bucket(0);
        for _ in 0..10 {
            assert!(rl._attempt_bucket(&mut bucket, 1, 0).0);
        }
        assert!(!rl._attempt_bucket(&mut bucket, 1, 0).0);
        // 400ms later: 2 tokens refilled
        assert!(rl._attempt_bucket(&mut bucket, 2, 400).0);
        assert!(!rl._attempt_bucket(&mut bucket, 1, 400).0);
        // Refill never exceeds capacity
        let mut bucket = rl._full_bucket(0);
        rl._refill(&mut bucket, 1_000_000_000);
        assert_eq!(bucket.tokens_milli, rl.capacity_milli);
    }

    #[test]
    fn test_cost_and_clock_skew() {
        let rl = limiter(10, 1, 1000);
        let mut bucket = rl._full_bucket(5000);
        assert!(rl._attempt_bucket(&mut bucket, 10, 5000).0);
        // Clock going backwards must not panic or refill
        let (allowed, _) = rl._attempt_bucket(&mut bucket, 1, 4000);
        assert!(!allowed);
    }

    #[test]
    fn test_state_roundtrip() {
        let rl = limiter(5, 1, 1000);
        let mut bucket = rl._full_bucket(123_456);
        rl._attempt_bucket(&mut bucket, 2, 123_456);
        let state = RateLimiter::_serialize(&bucket);
        let restored = rl._deserialize(&state, 123_456).unwrap();
        assert_eq!(restored.tokens_milli, bucket.tokens_milli);
        assert_eq!(restored.updated_ms, bucket.updated_ms);
    }

    #[test]
    fn test_state_tampering_clamped() {
        let rl = limiter(5, 1, 1000);
        // Claiming a million tokens gets clamped to capacity
        let bucket = rl._deserialize("v1:1000000000:0", 1000).unwrap();
        assert_eq!(bucket.tokens_milli, rl.capacity_milli);
        // A future timestamp gets clamped to now (no refill credit from it)
        let bucket = rl._deserialize("v1:0:99999999999", 1000).unwrap();
        assert_eq!(bucket.updated_ms, 1000);
        // Garbage is rejected
        assert!(rl._deserialize("v2:1:2", 1000).is_err());
        assert!(rl._deserialize("junk", 1000).is_err());
        assert!(rl._deserialize("v1:x:0", 1000).is_err());
        assert!(rl._deserialize("v1:1:2:3", 1000).is_err());
    }

    #[test]
    fn test_local_store_isolated_by_config() {
        let a = limiter(1, 1, 60_000);
        let b = limiter(100, 100, 1000);
        let key = "test_local_store_isolated_by_config";
        assert!(a._attempt_local(key, 1, super::now_ms()).0);
        assert!(!a._attempt_local(key, 1, super::now_ms()).0);
        // Different limiter config: separate bucket, still allowed
        assert!(b._attempt_local(key, 1, super::now_ms()).0);
        a.reset(key);
        assert!(a._attempt_local(key, 1, super::now_ms()).0);
    }

    #[test]
    fn test_invalid_config() {
        assert!(RateLimiter::__construct(0, 1, 1).is_err());
        assert!(RateLimiter::__construct(1, 0, 1).is_err());
        assert!(RateLimiter::__construct(1, 1, 0).is_err());
    }

    #[test]
    fn test_full_bucket_definition() {
        let rl = limiter(2, 1, 1000);
        let bucket: Bucket = rl._full_bucket(7);
        assert_eq!(bucket.tokens_milli, 2000);
        assert_eq!(bucket.updated_ms, 7);
    }

    #[test]
    fn test_cl_throttle_args_mapping() {
        // 10 burst, 5 tokens per minute → max_burst 9, rate 1 per 12s
        assert_eq!(limiter(10, 5, 60_000)._cl_throttle_args(), (9, 1, 12));
        // 100 burst, 10 per second → max_burst 99, rate 10 per 1s
        assert_eq!(limiter(100, 10, 1000)._cl_throttle_args(), (99, 10, 1));
        // 1 burst, 1 per 500ms → exactly 2 per 1s (rate preserved, not rounded)
        assert_eq!(limiter(1, 1, 500)._cl_throttle_args(), (0, 2, 1));
        // 3 per 700ms → reduced fraction 30/7
        assert_eq!(limiter(5, 3, 700)._cl_throttle_args(), (4, 30, 7));
    }

    #[test]
    fn test_cl_throttle_command() {
        assert_eq!(
            limiter(10, 5, 60_000)._cl_throttle_command("login:1.2.3.4", 2),
            ["CL.THROTTLE", "login:1.2.3.4", "9", "1", "12", "2"],
        );
    }

    #[test]
    fn test_cl_throttle_decision() {
        let allowed = RateLimiter::_cl_throttle_decision(&[0, 10, 9, -1, 30]).unwrap();
        assert!(allowed.allowed);
        assert_eq!(allowed.limit, 10);
        assert_eq!(allowed.remaining, 9);
        assert_eq!(allowed.retry_after_sec, 0);
        assert_eq!(allowed.reset_after_sec, 30);

        let limited = RateLimiter::_cl_throttle_decision(&[1, 10, 0, 3, 60]).unwrap();
        assert!(!limited.allowed);
        assert_eq!(limited.retry_after_sec, 3);

        assert!(RateLimiter::_cl_throttle_decision(&[0, 1]).is_err());
        assert!(RateLimiter::_cl_throttle_decision(&[]).is_err());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("rate-limiter")?;
        Ok(())
    }
}
