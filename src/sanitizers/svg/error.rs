use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use thiserror::Error;

pub mod error_codes {
    pub const INVALID_STATE: i32 = 1900;
    pub const PARSE_ERROR: i32 = 1901;
    pub const FILE_OPEN_ERROR: i32 = 1902;
    pub const FILE_READ_ERROR: i32 = 1903;
    pub const SVG_BOMB_DIMENSIONS: i32 = 1904;
    pub const SVG_BOMB_DEPTH: i32 = 1905;
    pub const EXTERNAL_REFERENCE: i32 = 1906;
    pub const DANGEROUS_ELEMENT: i32 = 1907;
    pub const DANGEROUS_ATTRIBUTE: i32 = 1908;
    pub const INVALID_VIEWBOX: i32 = 1909;
    pub const JAVASCRIPT_URL: i32 = 1910;
    pub const DATA_URI: i32 = 1911;
    pub const STYLE_PARSE_ERROR: i32 = 1912;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Sanitizer is not in a valid state")]
    InvalidState,

    #[error("Failed to parse SVG: {0}")]
    ParseError(String),

    #[error("Failed to open file '{path}': {reason}")]
    FileOpenError { path: String, reason: String },

    #[error("Failed to read file '{path}': {reason}")]
    FileReadError { path: String, reason: String },

    #[error("SVG dimensions too large (width: {width}, height: {height}, max: {max})")]
    SvgBombDimensions { width: u32, height: u32, max: u32 },

    #[error("SVG nesting depth ({depth}) exceeds maximum ({max})")]
    SvgBombDepth { depth: u32, max: u32 },

    #[error("External reference detected: {0}")]
    ExternalReference(String),

    #[error("Dangerous element detected: <{0}>")]
    DangerousElement(String),

    #[error("Dangerous attribute detected: {attribute} on <{element}>")]
    DangerousAttribute { element: String, attribute: String },

    #[error("Invalid viewBox: {0}")]
    InvalidViewBox(String),

    #[error("JavaScript URL detected: {0}")]
    JavaScriptUrl(String),

    #[error("Data URI not allowed: {0}")]
    DataUri(String),

    #[error("Failed to parse style: {0}")]
    StyleParseError(String),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidState => error_codes::INVALID_STATE,
            Error::ParseError(_) => error_codes::PARSE_ERROR,
            Error::FileOpenError { .. } => error_codes::FILE_OPEN_ERROR,
            Error::FileReadError { .. } => error_codes::FILE_READ_ERROR,
            Error::SvgBombDimensions { .. } => error_codes::SVG_BOMB_DIMENSIONS,
            Error::SvgBombDepth { .. } => error_codes::SVG_BOMB_DEPTH,
            Error::ExternalReference(_) => error_codes::EXTERNAL_REFERENCE,
            Error::DangerousElement(_) => error_codes::DANGEROUS_ELEMENT,
            Error::DangerousAttribute { .. } => error_codes::DANGEROUS_ATTRIBUTE,
            Error::InvalidViewBox(_) => error_codes::INVALID_VIEWBOX,
            Error::JavaScriptUrl(_) => error_codes::JAVASCRIPT_URL,
            Error::DataUri(_) => error_codes::DATA_URI,
            Error::StyleParseError(_) => error_codes::STYLE_PARSE_ERROR,
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

pub type Result<T> = std::result::Result<T, Error>;
