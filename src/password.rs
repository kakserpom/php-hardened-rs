use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use ext_php_rs::binary_slice::BinarySlice;
use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use thiserror::Error;

// Error codes for password hashing errors: 2300-2399
pub mod error_codes {
    pub const HASH_FAILED: i32 = 2300;
    pub const INVALID_HASH: i32 = 2301;
    pub const INVALID_PARAMS: i32 = 2302;
    pub const BCRYPT_FAILED: i32 = 2303;
}

/// Errors that can occur during password hashing operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Password hashing failed: {0}")]
    HashFailed(String),

    #[error("Invalid password hash: {0}")]
    InvalidHash(String),

    #[error("Invalid hashing parameters: {0}")]
    InvalidParams(String),

    #[error("bcrypt operation failed: {0}")]
    BcryptFailed(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::HashFailed(_) => error_codes::HASH_FAILED,
            Error::InvalidHash(_) => error_codes::INVALID_HASH,
            Error::InvalidParams(_) => error_codes::INVALID_PARAMS,
            Error::BcryptFailed(_) => error_codes::BCRYPT_FAILED,
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

/// Result type alias for password hashing operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Default Argon2id parameters per the OWASP Password Storage Cheat Sheet:
/// 19 MiB of memory, 2 iterations, 1 lane.
const DEFAULT_MEMORY_KIB: u32 = 19_456;
const DEFAULT_ITERATIONS: u32 = 2;
const DEFAULT_PARALLELISM: u32 = 1;
const DEFAULT_BCRYPT_COST: u32 = 12;

/// Password hashing with safe algorithms and safe defaults.
///
/// `hash()` produces Argon2id (the current OWASP recommendation) PHC strings;
/// `verify()` accepts Argon2 and bcrypt hashes, so existing `password_hash()`
/// databases can be migrated gradually: verify with the old hash, then
/// re-hash when `needsRehash()` says so. Verification is timing-safe.
#[php_class]
#[php(name = "Hardened\\Password")]
pub struct Password {}

impl Password {
    fn _argon2(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Argon2<'static>> {
        let params = Params::new(memory_kib, iterations, parallelism, None)
            .map_err(|e| Error::InvalidParams(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    fn _hash(
        password: &[u8],
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(Self::_argon2(memory_kib, iterations, parallelism)?
            .hash_password(password, &salt)
            .map_err(|e| Error::HashFailed(e.to_string()))?
            .to_string())
    }

    fn _verify(password: &[u8], hash: &str) -> Result<bool> {
        if hash.starts_with("$2") {
            return bcrypt::verify(password, hash).map_err(|e| Error::InvalidHash(e.to_string()));
        }
        let parsed = PasswordHash::new(hash).map_err(|e| Error::InvalidHash(e.to_string()))?;
        Ok(Argon2::default().verify_password(password, &parsed).is_ok())
    }

    fn _needs_rehash(
        hash: &str,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<bool> {
        // Anything that is not Argon2id (bcrypt, argon2i, …) should migrate.
        if hash.starts_with("$2") {
            return Ok(true);
        }
        let parsed = PasswordHash::new(hash).map_err(|e| Error::InvalidHash(e.to_string()))?;
        if parsed.algorithm != Algorithm::Argon2id.ident() {
            return Ok(true);
        }
        if parsed.version != Some(Version::V0x13.into()) {
            return Ok(true);
        }
        let params = Params::try_from(&parsed).map_err(|e| Error::InvalidHash(e.to_string()))?;
        Ok(params.m_cost() != memory_kib
            || params.t_cost() != iterations
            || params.p_cost() != parallelism)
    }

    fn _bcrypt_cost(hash: &str) -> Result<u32> {
        // $2b$12$... — the cost is the second dollar-delimited field.
        let mut parts = hash.split('$');
        let (Some(""), Some(version), Some(cost)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::InvalidHash("not a bcrypt hash".to_string()));
        };
        if !matches!(version, "2a" | "2b" | "2x" | "2y") {
            return Err(Error::InvalidHash("not a bcrypt hash".to_string()));
        }
        cost.parse()
            .map_err(|_| Error::InvalidHash("invalid bcrypt cost".to_string()))
    }
}

#[php_impl]
impl Password {
    /// Hashes a password with Argon2id.
    ///
    /// Defaults follow the OWASP Password Storage Cheat Sheet: 19 MiB memory,
    /// 2 iterations, parallelism 1. A random salt is generated per call.
    ///
    /// # Parameters
    /// - `password`: The password (binary-safe).
    /// - `memory_kib`: Memory cost in KiB (defaults to 19456).
    /// - `iterations`: Time cost (defaults to 2).
    /// - `parallelism`: Number of lanes (defaults to 1).
    ///
    /// # Returns
    /// - `string`: A PHC-format hash string (`$argon2id$...`).
    ///
    /// # Exceptions
    /// - Throws an exception if the parameters are invalid or hashing fails.
    #[allow(clippy::needless_pass_by_value)]
    fn hash(
        password: BinarySlice<u8>,
        memory_kib: Option<u32>,
        iterations: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<String> {
        Self::_hash(
            &password,
            memory_kib.unwrap_or(DEFAULT_MEMORY_KIB),
            iterations.unwrap_or(DEFAULT_ITERATIONS),
            parallelism.unwrap_or(DEFAULT_PARALLELISM),
        )
    }

    /// Verifies a password against a stored hash, in constant time with
    /// respect to the hash contents.
    ///
    /// Accepts Argon2 (`$argon2id$`, `$argon2i$`) and bcrypt (`$2a$`, `$2b$`,
    /// `$2y$`) hashes, so databases written by PHP's `password_hash()` keep
    /// verifying during a migration.
    ///
    /// # Parameters
    /// - `password`: The password to check (binary-safe).
    /// - `hash`: The stored hash string.
    ///
    /// # Returns
    /// - `bool`: `true` if the password matches.
    ///
    /// # Exceptions
    /// - Throws an exception if the hash string is malformed.
    #[allow(clippy::needless_pass_by_value)]
    fn verify(password: BinarySlice<u8>, hash: &str) -> Result<bool> {
        Self::_verify(&password, hash)
    }

    /// Checks whether a stored hash should be re-hashed: it is not Argon2id,
    /// uses an outdated Argon2 version, or its cost parameters differ from
    /// the given (or default) ones. Call after a successful `verify()` and
    /// re-hash while you still have the plaintext.
    ///
    /// # Parameters
    /// - `hash`: The stored hash string.
    /// - `memory_kib`: Target memory cost in KiB (defaults to 19456).
    /// - `iterations`: Target time cost (defaults to 2).
    /// - `parallelism`: Target lane count (defaults to 1).
    ///
    /// # Returns
    /// - `bool`: `true` if the hash should be regenerated.
    ///
    /// # Exceptions
    /// - Throws an exception if the hash string is malformed.
    fn needs_rehash(
        hash: &str,
        memory_kib: Option<u32>,
        iterations: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<bool> {
        Self::_needs_rehash(
            hash,
            memory_kib.unwrap_or(DEFAULT_MEMORY_KIB),
            iterations.unwrap_or(DEFAULT_ITERATIONS),
            parallelism.unwrap_or(DEFAULT_PARALLELISM),
        )
    }

    /// Hashes a password with bcrypt, for systems that must stay
    /// bcrypt-compatible. Prefer `hash()` (Argon2id) for new code.
    ///
    /// Note: bcrypt only uses the first 72 bytes of the password.
    ///
    /// # Parameters
    /// - `password`: The password (binary-safe).
    /// - `cost`: The bcrypt cost factor (defaults to 12).
    ///
    /// # Returns
    /// - `string`: A bcrypt hash string (`$2b$...`).
    ///
    /// # Exceptions
    /// - Throws an exception if hashing fails.
    #[allow(clippy::needless_pass_by_value)]
    fn hash_bcrypt(password: BinarySlice<u8>, cost: Option<u32>) -> Result<String> {
        bcrypt::hash(*password, cost.unwrap_or(DEFAULT_BCRYPT_COST))
            .map_err(|e| Error::BcryptFailed(e.to_string()))
    }

    /// Checks whether a bcrypt hash uses a cost lower than the given (or
    /// default) one.
    ///
    /// # Parameters
    /// - `hash`: The stored bcrypt hash string.
    /// - `cost`: Target cost factor (defaults to 12).
    ///
    /// # Returns
    /// - `bool`: `true` if the hash should be regenerated.
    ///
    /// # Exceptions
    /// - Throws an exception if the hash is not a bcrypt hash.
    fn needs_rehash_bcrypt(hash: &str, cost: Option<u32>) -> Result<bool> {
        Ok(Self::_bcrypt_cost(hash)? < cost.unwrap_or(DEFAULT_BCRYPT_COST))
    }
}

#[cfg(test)]
mod tests {
    use super::Password;
    use crate::run_php_example;

    #[test]
    fn test_hash_and_verify_argon2id() {
        // Small params to keep the test fast
        let hash = Password::_hash(b"correct horse battery staple", 8, 1, 1).unwrap();
        assert!(hash.starts_with("$argon2id$v=19$"));
        assert!(Password::_verify(b"correct horse battery staple", &hash).unwrap());
        assert!(!Password::_verify(b"wrong password", &hash).unwrap());
    }

    #[test]
    fn test_binary_safe_password() {
        let hash = Password::_hash(b"pa\x00ss\xff", 8, 1, 1).unwrap();
        assert!(Password::_verify(b"pa\x00ss\xff", &hash).unwrap());
        assert!(!Password::_verify(b"pa", &hash).unwrap());
    }

    #[test]
    fn test_bcrypt_roundtrip_and_php_compat() {
        let hash = Password::hash_bcrypt(b"secret".as_slice().into(), Some(4)).unwrap();
        assert!(hash.starts_with("$2b$04$"));
        assert!(Password::_verify(b"secret", &hash).unwrap());
        assert!(!Password::_verify(b"other", &hash).unwrap());
        // A $2y$ hash as produced by PHP's password_hash(..., PASSWORD_BCRYPT)
        // ("rasmuslerdorf" / cost 10 — from the PHP manual)
        let php_hash = "$2y$10$.vGA1O9wmRjrwAVXD98HNOgsNpDczlqm3Jq7KnEd1rVAGv3Fykk1a";
        assert!(Password::_verify(b"rasmuslerdorf", php_hash).unwrap());
        assert!(!Password::_verify(b"notthepassword", php_hash).unwrap());
    }

    #[test]
    fn test_needs_rehash() {
        let hash = Password::_hash(b"pw", 8, 1, 1).unwrap();
        assert!(!Password::_needs_rehash(&hash, 8, 1, 1).unwrap());
        // Different target params
        assert!(Password::_needs_rehash(&hash, 16, 1, 1).unwrap());
        assert!(Password::_needs_rehash(&hash, 8, 2, 1).unwrap());
        // bcrypt always needs migration to argon2id
        let bcrypt_hash = Password::hash_bcrypt(b"pw".as_slice().into(), Some(4)).unwrap();
        assert!(Password::_needs_rehash(&bcrypt_hash, 8, 1, 1).unwrap());
        // Garbage is an error, not "false"
        assert!(Password::_needs_rehash("garbage", 8, 1, 1).is_err());
    }

    #[test]
    fn test_needs_rehash_bcrypt() {
        let hash = Password::hash_bcrypt(b"pw".as_slice().into(), Some(4)).unwrap();
        assert!(Password::needs_rehash_bcrypt(&hash, Some(10)).unwrap());
        assert!(!Password::needs_rehash_bcrypt(&hash, Some(4)).unwrap());
        assert!(Password::needs_rehash_bcrypt("$argon2id$junk", Some(10)).is_err());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("password")?;
        Ok(())
    }
}
