use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use thiserror::Error;

pub mod cross_origin;
pub mod csp;
pub mod hsts;
pub mod whatnot;
pub mod permissions;
pub mod referrer_policy;

// Error codes for security header errors: 1700-1799
pub mod error_codes {
    pub const INVALID_VALUE: i32 = 1700;
    pub const INVALID_FEATURE: i32 = 1701;
    pub const INVALID_KEYWORD: i32 = 1702;
    pub const INVALID_RULE: i32 = 1703;
    pub const QUOTES_IN_SOURCE: i32 = 1704;
    pub const ALLOW_FROM_REQUIRES_URI: i32 = 1705;
    pub const REPORT_URI_INCOMPATIBLE: i32 = 1706;
    pub const EMPTY_BLOCKED_DESTINATIONS: i32 = 1707;
    pub const INVALID_BLOCKED_DESTINATION: i32 = 1708;
    pub const INVALID_SOURCE: i32 = 1709;
    pub const HEADER_UNAVAILABLE: i32 = 1710;
    pub const HEADER_CALL_FAILED: i32 = 1711;
    pub const FORMAT_ERROR: i32 = 1712;
}

/// Errors that can occur during security header operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid {header_type} value: {value}")]
    InvalidValue { header_type: String, value: String },

    #[error("Invalid feature: {0}")]
    InvalidFeature(String),

    #[error("Invalid keyword: {0}")]
    InvalidKeyword(String),

    #[error("Invalid rule name: {0}")]
    InvalidRule(String),

    #[error("Source may not contain quotes: {0}")]
    QuotesInSource(String),

    #[error("ALLOW-FROM requires a URI")]
    AllowFromRequiresUri,

    #[error("report_uri is incompatible with mode being 'off'")]
    ReportUriIncompatible,

    #[error("blocked_destinations must be a non-empty array")]
    EmptyBlockedDestinations,

    #[error("Each blocked_destination must be a string")]
    InvalidBlockedDestination,

    #[error("Invalid source: {0}")]
    InvalidSource(String),

    #[error("Could not call header()")]
    HeaderUnavailable,

    #[error("header() call failed: {0}")]
    HeaderCallFailed(String),

    #[error("Format error: {0}")]
    FormatError(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidValue { .. } => error_codes::INVALID_VALUE,
            Error::InvalidFeature(_) => error_codes::INVALID_FEATURE,
            Error::InvalidKeyword(_) => error_codes::INVALID_KEYWORD,
            Error::InvalidRule(_) => error_codes::INVALID_RULE,
            Error::QuotesInSource(_) => error_codes::QUOTES_IN_SOURCE,
            Error::AllowFromRequiresUri => error_codes::ALLOW_FROM_REQUIRES_URI,
            Error::ReportUriIncompatible => error_codes::REPORT_URI_INCOMPATIBLE,
            Error::EmptyBlockedDestinations => error_codes::EMPTY_BLOCKED_DESTINATIONS,
            Error::InvalidBlockedDestination => error_codes::INVALID_BLOCKED_DESTINATION,
            Error::InvalidSource(_) => error_codes::INVALID_SOURCE,
            Error::HeaderUnavailable => error_codes::HEADER_UNAVAILABLE,
            Error::HeaderCallFailed(_) => error_codes::HEADER_CALL_FAILED,
            Error::FormatError(_) => error_codes::FORMAT_ERROR,
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

/// Result type alias for security header operations.
pub type Result<T> = std::result::Result<T, Error>;
