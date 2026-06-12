use ext_php_rs::binary_slice::BinarySlice;
use ext_php_rs::convert::IntoZval;
use ext_php_rs::exception::PhpException;
use ext_php_rs::types::{ZendHashTable, Zval};
use ext_php_rs::zend::ce;
use ext_php_rs::{php_class, php_impl};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// Error codes for JWT errors: 2500-2599
pub mod error_codes {
    pub const INVALID_KEY: i32 = 2500;
    pub const INVALID_ALGORITHM: i32 = 2501;
    pub const VERIFICATION_FAILED: i32 = 2502;
    pub const MISSING_CLAIM: i32 = 2503;
    pub const INVALID_CLAIM: i32 = 2504;
    pub const CONVERSION: i32 = 2505;
}

/// Errors that can occur during JWT verification.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid verification key: {0}")]
    InvalidKey(String),

    #[error("Invalid or disallowed algorithm: {0}")]
    InvalidAlgorithm(String),

    #[error("JWT verification failed: {0}")]
    VerificationFailed(String),

    #[error("Missing required claim {0:?}")]
    MissingClaim(String),

    #[error("Invalid claim {0}: {1}")]
    InvalidClaim(&'static str, String),

    #[error("Failed to convert claims: {0}")]
    Conversion(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidKey(_) => error_codes::INVALID_KEY,
            Error::InvalidAlgorithm(_) => error_codes::INVALID_ALGORITHM,
            Error::VerificationFailed(_) => error_codes::VERIFICATION_FAILED,
            Error::MissingClaim(_) => error_codes::MISSING_CLAIM,
            Error::InvalidClaim(_, _) => error_codes::INVALID_CLAIM,
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

/// Result type alias for JWT operations.
pub type Result<T> = std::result::Result<T, Error>;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Recursively converts a JSON value into a PHP value.
fn json_to_zval(value: &Value) -> Result<Zval> {
    let into = |err: ext_php_rs::error::Error| Error::Conversion(err.to_string());
    match value {
        Value::Null => ().into_zval(false).map_err(into),
        Value::Bool(b) => b.into_zval(false).map_err(into),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_zval(false).map_err(into)
            } else {
                n.as_f64()
                    .unwrap_or(f64::NAN)
                    .into_zval(false)
                    .map_err(into)
            }
        }
        Value::String(s) => s.as_str().into_zval(false).map_err(into),
        Value::Array(items) => {
            let mut table = ZendHashTable::new();
            for item in items {
                table
                    .push(json_to_zval(item)?)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
            }
            table.into_zval(false).map_err(into)
        }
        Value::Object(map) => {
            let mut table = ZendHashTable::new();
            for (key, item) in map {
                table
                    .insert(key.as_str(), json_to_zval(item)?)
                    .map_err(|e| Error::Conversion(e.to_string()))?;
            }
            table.into_zval(false).map_err(into)
        }
    }
}

/// Hardened JWT verification.
///
/// Most JWT vulnerabilities are verification bugs, and this API makes them
/// unrepresentable:
/// - **`alg: none` is always rejected** — there is no way to allow it.
/// - **No HS/RS algorithm confusion**: the key type is bound to an algorithm
///   family at construction (`forHmac()` accepts only HS*, `forRsa()` only
///   RS*/PS*, …), so an attacker cannot have an RSA public key interpreted
///   as an HMAC secret.
/// - **`exp` is mandatory** and validated (with configurable leeway); `nbf`
///   is validated when present; a future `iat` is rejected.
/// - The token's `alg` header must be in the explicit allowlist.
#[php_class]
#[php(name = "Hardened\\JwtVerifier")]
pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
    required_claims: Vec<String>,
    max_age_secs: Option<i64>,
    leeway_secs: i64,
}

impl JwtVerifier {
    fn _new(
        key: DecodingKey,
        algorithms: &[String],
        family: &[Algorithm],
        family_name: &str,
    ) -> Result<Self> {
        if algorithms.is_empty() {
            return Err(Error::InvalidAlgorithm(
                "algorithm allowlist must not be empty".to_string(),
            ));
        }
        let mut parsed = Vec::with_capacity(algorithms.len());
        for name in algorithms {
            let alg: Algorithm = name
                .parse()
                .map_err(|_| Error::InvalidAlgorithm(name.clone()))?;
            if !family.contains(&alg) {
                return Err(Error::InvalidAlgorithm(format!(
                    "{name} is not a {family_name} algorithm"
                )));
            }
            parsed.push(alg);
        }
        let mut validation = Validation::new(parsed[0]);
        validation.algorithms = parsed;
        validation.set_required_spec_claims(&["exp"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 60;
        Ok(Self {
            key,
            validation,
            required_claims: Vec::new(),
            max_age_secs: None,
            leeway_secs: 60,
        })
    }

    fn _verify(&self, token: &str) -> Result<Value> {
        let data = decode::<Value>(token, &self.key, &self.validation)
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;
        let claims = data.claims;
        let now = now_secs();

        // `iat` must not be in the future (clock skew aside).
        let iat = claims.get("iat").and_then(Value::as_i64);
        if let Some(iat) = iat
            && iat > now + self.leeway_secs
        {
            return Err(Error::InvalidClaim("iat", "issued in the future".into()));
        }
        if let Some(max_age) = self.max_age_secs {
            let Some(iat) = iat else {
                return Err(Error::MissingClaim("iat".to_string()));
            };
            if now - iat > max_age + self.leeway_secs {
                return Err(Error::InvalidClaim(
                    "iat",
                    format!("token is older than {max_age} seconds"),
                ));
            }
        }
        for name in &self.required_claims {
            if claims.get(name).is_none() {
                return Err(Error::MissingClaim(name.clone()));
            }
        }
        Ok(claims)
    }
}

#[php_impl]
impl JwtVerifier {
    /// Constructs a verifier for HMAC (shared-secret) tokens.
    ///
    /// # Parameters
    /// - `secret`: The shared secret (binary-safe).
    /// - `algorithms`: Allowlist of `HS256`/`HS384`/`HS512` (defaults to
    ///   `["HS256"]`).
    ///
    /// # Exceptions
    /// - Throws an exception if the allowlist is empty or contains a
    ///   non-HMAC algorithm.
    #[allow(clippy::needless_pass_by_value)]
    fn for_hmac(secret: BinarySlice<u8>, algorithms: Option<Vec<String>>) -> Result<Self> {
        Self::_new(
            DecodingKey::from_secret(&secret),
            &algorithms.unwrap_or_else(|| vec!["HS256".to_string()]),
            &[Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
            "HMAC",
        )
    }

    /// Constructs a verifier for RSA tokens from a PEM public key.
    ///
    /// # Parameters
    /// - `public_key_pem`: The RSA public key in PEM format.
    /// - `algorithms`: Allowlist of `RS256`/`RS384`/`RS512`/`PS256`/`PS384`/
    ///   `PS512` (defaults to `["RS256"]`).
    ///
    /// # Exceptions
    /// - Throws an exception if the key cannot be parsed, or the allowlist is
    ///   empty or contains a non-RSA algorithm.
    fn for_rsa(public_key_pem: &str, algorithms: Option<Vec<String>>) -> Result<Self> {
        Self::_new(
            DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
                .map_err(|e| Error::InvalidKey(e.to_string()))?,
            &algorithms.unwrap_or_else(|| vec!["RS256".to_string()]),
            &[
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::RS512,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::PS512,
            ],
            "RSA",
        )
    }

    /// Constructs a verifier for ECDSA tokens from a PEM public key.
    ///
    /// # Parameters
    /// - `public_key_pem`: The EC public key in PEM format.
    /// - `algorithms`: Allowlist of `ES256`/`ES384` (defaults to `["ES256"]`).
    ///
    /// # Exceptions
    /// - Throws an exception if the key cannot be parsed, or the allowlist is
    ///   empty or contains a non-ECDSA algorithm.
    fn for_ecdsa(public_key_pem: &str, algorithms: Option<Vec<String>>) -> Result<Self> {
        Self::_new(
            DecodingKey::from_ec_pem(public_key_pem.as_bytes())
                .map_err(|e| Error::InvalidKey(e.to_string()))?,
            &algorithms.unwrap_or_else(|| vec!["ES256".to_string()]),
            &[Algorithm::ES256, Algorithm::ES384],
            "ECDSA",
        )
    }

    /// Constructs a verifier for Ed25519 (`EdDSA`) tokens from a PEM public key.
    ///
    /// # Parameters
    /// - `public_key_pem`: The Ed25519 public key in PEM format.
    ///
    /// # Exceptions
    /// - Throws an exception if the key cannot be parsed.
    fn for_ed25519(public_key_pem: &str) -> Result<Self> {
        Self::_new(
            DecodingKey::from_ed_pem(public_key_pem.as_bytes())
                .map_err(|e| Error::InvalidKey(e.to_string()))?,
            &["EdDSA".to_string()],
            &[Algorithm::EdDSA],
            "EdDSA",
        )
    }

    /// Requires the `iss` claim to equal one of the given values.
    ///
    /// # Parameters
    /// - `issuers`: Acceptable issuer values.
    fn require_issuer(&mut self, issuers: Vec<String>) {
        self.validation.set_issuer(&issuers);
    }

    /// Requires the `aud` claim to contain one of the given values.
    ///
    /// # Parameters
    /// - `audiences`: Acceptable audience values.
    fn require_audience(&mut self, audiences: Vec<String>) {
        self.validation.set_audience(&audiences);
    }

    /// Requires the `sub` claim to equal the given value.
    ///
    /// # Parameters
    /// - `subject`: The exact expected subject.
    fn require_subject(&mut self, subject: String) {
        self.validation.sub = Some(subject);
    }

    /// Requires the listed claims to be present (any value).
    ///
    /// # Parameters
    /// - `claims`: Claim names that must exist, e.g. `["sub", "jti"]`.
    fn require_claims(&mut self, claims: Vec<String>) {
        self.required_claims = claims;
    }

    /// Rejects tokens whose `iat` is older than the given age. Makes `iat`
    /// mandatory.
    ///
    /// # Parameters
    /// - `seconds`: Maximum token age in seconds.
    fn require_max_age(&mut self, seconds: i64) {
        self.max_age_secs = Some(seconds);
    }

    /// Sets the clock-skew leeway applied to `exp`/`nbf`/`iat` checks
    /// (defaults to 60 seconds).
    ///
    /// # Parameters
    /// - `seconds`: Leeway in seconds.
    fn set_leeway(&mut self, seconds: u64) {
        self.validation.leeway = seconds;
        self.leeway_secs = i64::try_from(seconds).unwrap_or(i64::MAX);
    }

    /// Verifies a token and returns its claims.
    ///
    /// Checks performed: signature with an allowlisted algorithm (never
    /// `none`), mandatory `exp`, `nbf` if present, `iat` not in the future,
    /// plus any configured issuer/audience/subject/required-claim/max-age
    /// constraints.
    ///
    /// # Parameters
    /// - `token`: The JWT string.
    ///
    /// # Returns
    /// - `array`: The token claims as an associative array.
    ///
    /// # Exceptions
    /// - Throws an exception describing the first failed check.
    fn verify(&self, token: &str) -> Result<Zval> {
        json_to_zval(&self._verify(token)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, JwtVerifier, now_secs};
    use crate::run_php_example;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};

    const SECRET: &[u8] = b"test-secret-key";

    fn hmac_verifier(algs: &[&str]) -> JwtVerifier {
        JwtVerifier::for_hmac(
            SECRET.into(),
            Some(algs.iter().map(ToString::to_string).collect()),
        )
        .unwrap()
    }

    fn token(claims: &Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap()
    }

    #[test]
    fn test_valid_token_roundtrip() {
        let verifier = hmac_verifier(&["HS256"]);
        let claims = json!({"exp": now_secs() + 600, "sub": "user-1", "role": "admin"});
        let verified = verifier._verify(&token(&claims)).unwrap();
        assert_eq!(verified["sub"], "user-1");
        assert_eq!(verified["role"], "admin");
    }

    #[test]
    fn test_alg_none_rejected() {
        // {"alg":"none","typ":"JWT"} . {"exp": far future} . empty signature
        let none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjk5OTk5OTk5OTl9.";
        let verifier = hmac_verifier(&["HS256"]);
        assert!(verifier._verify(none_token).is_err());
    }

    #[test]
    fn test_alg_allowlist_enforced() {
        let verifier = hmac_verifier(&["HS384"]);
        // Token signed with HS256, allowlist only has HS384
        let claims = json!({"exp": now_secs() + 600});
        assert!(verifier._verify(&token(&claims)).is_err());
    }

    #[test]
    fn test_family_binding_prevents_confusion() {
        // An HMAC verifier cannot be configured for RSA algorithms and
        // vice versa, so "verify RS256 token with public key as HMAC
        // secret" is unrepresentable.
        assert!(JwtVerifier::for_hmac(SECRET.into(), Some(vec!["RS256".to_string()])).is_err());
        assert!(JwtVerifier::for_hmac(SECRET.into(), Some(vec!["none".to_string()])).is_err());
        assert!(JwtVerifier::for_hmac(SECRET.into(), Some(vec![])).is_err());
    }

    #[test]
    fn test_tampered_token_rejected() {
        let verifier = hmac_verifier(&["HS256"]);
        let user = token(&json!({"exp": now_secs() + 600, "role": "user"}));
        let admin = token(&json!({"exp": now_secs() + 600, "role": "admin"}));
        let user_parts: Vec<&str> = user.split('.').collect();
        let admin_parts: Vec<&str> = admin.split('.').collect();
        // Splice the privileged payload onto the original signature
        let forged = format!("{}.{}.{}", user_parts[0], admin_parts[1], user_parts[2]);
        assert!(verifier._verify(&forged).is_err());
    }

    #[test]
    fn test_exp_mandatory_and_enforced() {
        let verifier = hmac_verifier(&["HS256"]);
        // No exp at all
        assert!(verifier._verify(&token(&json!({"sub": "x"}))).is_err());
        // Expired beyond leeway
        let expired = json!({"exp": now_secs() - 3600});
        assert!(verifier._verify(&token(&expired)).is_err());
    }

    #[test]
    fn test_nbf_and_future_iat_rejected() {
        let verifier = hmac_verifier(&["HS256"]);
        let not_yet = json!({"exp": now_secs() + 600, "nbf": now_secs() + 300});
        assert!(verifier._verify(&token(&not_yet)).is_err());
        let from_future = json!({"exp": now_secs() + 600, "iat": now_secs() + 300});
        assert!(matches!(
            verifier._verify(&token(&from_future)),
            Err(Error::InvalidClaim("iat", _))
        ));
    }

    #[test]
    fn test_max_age() {
        let mut verifier = hmac_verifier(&["HS256"]);
        verifier.require_max_age(300);
        let fresh = json!({"exp": now_secs() + 600, "iat": now_secs() - 10});
        assert!(verifier._verify(&token(&fresh)).is_ok());
        let stale = json!({"exp": now_secs() + 600, "iat": now_secs() - 3600});
        assert!(verifier._verify(&token(&stale)).is_err());
        // max-age makes iat mandatory
        let missing_iat = json!({"exp": now_secs() + 600});
        assert!(matches!(
            verifier._verify(&token(&missing_iat)),
            Err(Error::MissingClaim(_))
        ));
    }

    #[test]
    fn test_issuer_audience_required_claims() {
        let mut verifier = hmac_verifier(&["HS256"]);
        verifier.require_issuer(vec!["https://idp.example".to_string()]);
        verifier.require_audience(vec!["api".to_string()]);
        verifier.require_claims(vec!["jti".to_string()]);

        let good = json!({
            "exp": now_secs() + 600,
            "iss": "https://idp.example",
            "aud": "api",
            "jti": "token-1",
        });
        assert!(verifier._verify(&token(&good)).is_ok());

        let wrong_issuer = json!({
            "exp": now_secs() + 600, "iss": "https://evil.example", "aud": "api", "jti": "x",
        });
        assert!(verifier._verify(&token(&wrong_issuer)).is_err());

        let wrong_audience = json!({
            "exp": now_secs() + 600, "iss": "https://idp.example", "aud": "other", "jti": "x",
        });
        assert!(verifier._verify(&token(&wrong_audience)).is_err());

        let missing_jti = json!({
            "exp": now_secs() + 600, "iss": "https://idp.example", "aud": "api",
        });
        assert!(matches!(
            verifier._verify(&token(&missing_jti)),
            Err(Error::MissingClaim(_))
        ));
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("jwt-verifier")?;
        Ok(())
    }
}
