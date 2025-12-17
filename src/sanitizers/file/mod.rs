use ext_php_rs::exception::PhpException;
use ext_php_rs::zend::ce;
use thiserror::Error;

pub mod archive;
pub mod png;

// Error codes for file sanitizer errors: 1600-1699
pub mod error_codes {
    pub const FILE_OPEN_ERROR: i32 = 1600;
    pub const PNG_SIGNATURE: i32 = 1601;
    pub const SEEK: i32 = 1602;
    pub const IHDR_LENGTH: i32 = 1603;
    pub const CHUNK_TYPE: i32 = 1604;
    pub const MISSING_IHDR: i32 = 1605;
    pub const DIMENSION_READ: i32 = 1606;
    pub const PNG_BOMB: i32 = 1607;
    pub const ZIP_BOMB: i32 = 1608;
    pub const RAR_BOMB: i32 = 1609;
}

/// Errors that can occur during file sanitization operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to open file '{path}': {reason}")]
    FileOpenError { path: String, reason: String },

    #[error("Failed to read PNG signature: {0}")]
    PngSignatureError(String),

    #[error("Seek failed: {0}")]
    SeekError(String),

    #[error("Failed to read IHDR length: {0}")]
    IhdrLengthError(String),

    #[error("Failed to read chunk type: {0}")]
    ChunkTypeError(String),

    #[error("Missing IHDR chunk; invalid PNG")]
    MissingIhdr,

    #[error("Failed to read dimensions: {0}")]
    DimensionReadError(String),

    #[error("PNG dimensions are too large (width: {width}, height: {height})")]
    PngBomb { width: u32, height: u32 },

    #[error("ZIP archive looks like a bomb")]
    ZipBomb,

    #[error("RAR archive looks like a bomb")]
    RarBomb,
}

impl Error {
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Error::FileOpenError { .. } => error_codes::FILE_OPEN_ERROR,
            Error::PngSignatureError(_) => error_codes::PNG_SIGNATURE,
            Error::SeekError(_) => error_codes::SEEK,
            Error::IhdrLengthError(_) => error_codes::IHDR_LENGTH,
            Error::ChunkTypeError(_) => error_codes::CHUNK_TYPE,
            Error::MissingIhdr => error_codes::MISSING_IHDR,
            Error::DimensionReadError(_) => error_codes::DIMENSION_READ,
            Error::PngBomb { .. } => error_codes::PNG_BOMB,
            Error::ZipBomb => error_codes::ZIP_BOMB,
            Error::RarBomb => error_codes::RAR_BOMB,
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

/// Result type alias for file sanitizer operations.
pub type Result<T> = std::result::Result<T, Error>;
