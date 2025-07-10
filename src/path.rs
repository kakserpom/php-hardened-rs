use crate::to_str;
use ext_php_rs::prelude::{PhpException, PhpResult};
use ext_php_rs::types::Zval;
use ext_php_rs::{php_class, php_impl};
use std::ffi::OsStr;
use std::path::Component;
use std::path::{Path, PathBuf};

#[php_class]
#[php(name = "Hardened\\Path")]
pub struct PathObj {
    inner: PathBuf,
}

#[php_impl]
impl PathObj {
    /// Creates a new PathObj by lexically canonicalizing a given PHP value.
    ///
    /// # Parameters
    /// - `path`: The PHP value to convert to a filesystem path.
    ///
    /// # Errors
    /// Throws an exception if conversion from Zval to string fails.
    #[inline]
    pub fn from(path: &Zval) -> PhpResult<Self> {
        Ok(Self {
            inner: lexical_canonicalize(Path::new(&to_str(path)?)),
        })
    }

    /// Constructs a new PathObj instance (alias for `from`).
    ///
    /// # Parameters
    /// - `path`: The PHP value to convert to a filesystem path.
    ///
    /// # Errors
    /// Throws an exception if conversion from Zval to string fails.
    pub fn __construct(path: &Zval) -> PhpResult<Self> {
        Self::from(path)
    }

    /// Checks if this path starts with the given prefix path.
    ///
    /// # Parameters
    /// - `path`: The PHP value to compare against.
    ///
    /// # Returns
    /// `true` if this path starts with the given prefix.
    ///
    /// # Errors
    /// Throws an exception if conversion from Zval to string fails.
    pub fn starts_with(&self, path: &Zval) -> PhpResult<bool> {
        Ok(self.inner.starts_with(to_str(path)?))
    }

    /// Joins the given path onto this path and canonicalizes it.
    ///
    /// # Parameters
    /// - `path`: The PHP value to join.
    ///
    /// # Returns
    /// A new PathObj representing the joined path.
    ///
    /// # Errors
    /// Throws an exception if conversion from Zval to string fails.
    pub fn join(&self, path: &Zval) -> PhpResult<Self> {
        Ok(Self {
            inner: lexical_canonicalize(self.inner.join(to_str(path)?)),
        })
    }

    /// Joins the given path onto this path, canonicalizes it, and ensures it's a subpath.
    ///
    /// # Parameters
    /// - `path`: The PHP value to join.
    ///
    /// # Errors
    /// Throws an exception if conversion from Zval to string fails or if the resulting path is not a subpath.
    pub fn join_within(&self, path: &Zval) -> PhpResult<Self> {
        let inner = lexical_canonicalize(self.inner.join(to_str(path)?));
        if inner.starts_with(&self.inner) {
            Ok(Self { inner })
        } else {
            Err(PhpException::from("Not a sub path"))
        }
    }

    pub fn set_file_name(&mut self, file_name: &Zval) -> PhpResult<Self> {
        let mut inner = self.inner.clone();
        inner.set_file_name(to_str(file_name)?);
        Ok(Self { inner })
    }

    pub fn set_extension(&mut self, file_name: &Zval) -> PhpResult<Self> {
        let mut inner = self.inner.clone();
        inner.set_extension(to_str(file_name)?);
        Ok(Self { inner })
    }

    pub fn file_name(&self) -> Option<String> {
        self.inner
            .file_name()
            .and_then(OsStr::to_str)
            .map(str::to_string)
    }

    /// Converts the path to its string representation.
    ///
    /// # Returns
    /// The string representation of the path.
    ///
    /// # Errors
    /// Throws an exception if the path cannot be converted to a string.
    pub fn __to_string(&self) -> PhpResult<String> {
        Ok(self
            .inner
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("Could not convert path to string"))?)
    }

    pub fn path(&self) -> PhpResult<String> {
        Ok(self
            .inner
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("Could not convert path to string"))?)
    }

    /// Check if the path’s extension is in the allowed list.
    ///
    /// # Parameters
    /// - `allowed`: PHP array of allowed extensions (strings, without leading dot), case-insensitive.
    ///
    /// # Returns
    /// - `bool` `true` if the file extension matches one of the allowed values.
    fn validate_extension(&self, allowed: Vec<&str>) -> bool {
        self.inner
            .extension()
            .and_then(OsStr::to_str)
            .map_or(false, |ext| {
                allowed.iter().any(|a| a.eq_ignore_ascii_case(ext))
            })
    }

    /// Check if the path’s extension is a common image type.
    ///
    /// # Returns
    /// - `bool` `true` if extension is one of `["png","jpg","jpeg","gif","webp","bmp","tiff","svg"]`.
    fn validate_extension_image(&self) -> bool {
        self.validate_extension(vec![
            "png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "svg",
        ])
    }

    /// Check if the path’s extension is a common video type.
    ///
    /// # Returns
    /// - `bool` `true` if extension is one of `["mp4","mov","avi","mkv","webm","flv"]`.
    fn validate_extension_video(&self) -> bool {
        self.validate_extension(vec!["mp4", "mov", "avi", "mkv", "webm", "flv"])
    }

    /// Check if the path’s extension is a common audio type.
    ///
    /// # Returns
    /// - `bool` `true` if extension is one of `["mp3","wav","ogg","flac","aac"]`.
    fn validate_extension_audio(&self) -> bool {
        self.validate_extension(vec!["mp3", "wav", "ogg", "flac", "aac"])
    }

    /// Check if the path’s extension is a common document type.
    ///
    /// # Returns
    /// - `bool` `true` if extension is one of `["pdf","doc","docx","xls","xlsx","ppt","pptx"]`.
    fn validate_extension_document(&self) -> bool {
        self.validate_extension(vec!["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"])
    }
}

/// Performs a purely lexical normalization of a path:
/// - Removes `.` segments
/// - Resolves `..` by removing the previous segment when possible
/// - Preserves absolute paths (root or prefix remain)
/// - Does NOT resolve symlinks or consult the filesystem
///
/// # Parameters
/// - `path`: The path to normalize.
///
/// # Returns
/// A lexically canonicalized PathBuf.
pub fn lexical_canonicalize<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    let mut stack: Vec<Component> = Vec::new();

    for component in path.components() {
        match component {
            Component::CurDir => {
                // Skip current directory marker `.`
            }
            Component::ParentDir => {
                // Attempt to pop the last normal segment
                if let Some(last) = stack.last() {
                    match last {
                        Component::Normal(_) => {
                            stack.pop();
                        }
                        // If at root or prefix, ignore `..`
                        Component::RootDir | Component::Prefix(_) => {}
                        // Otherwise (relative excess `..`), preserve it
                        _ => stack.push(component),
                    }
                } else {
                    // No previous segment, keep `..`
                    stack.push(component);
                }
            }
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                // Retain normal segments, root, and prefix
                stack.push(component);
            }
        }
    }

    // Reconstruct the resulting PathBuf
    let mut result = PathBuf::new();
    for comp in stack {
        result.push(comp.as_os_str());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::lexical_canonicalize;

    fn canon(s: &str) -> String {
        lexical_canonicalize(s).to_str().unwrap().to_owned()
    }

    #[test]
    fn test_unix_relative() {
        assert_eq!(canon("a/b/./c"), "a/b/c");
        assert_eq!(canon("a/b/../c"), "a/c");
        assert_eq!(canon("../x/../y"), "../y");
        assert_eq!(canon("."), "");
        assert_eq!(canon("././."), "");
    }

    #[test]
    fn test_unix_absolute() {
        assert_eq!(canon("/usr//local/./bin"), "/usr/local/bin");
        assert_eq!(canon("/foo/../bar"), "/bar");
        // `..` at root should be ignored
        assert_eq!(canon("/../etc"), "/etc");
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_prefix() {
        // Drive-letter absolute path
        assert_eq!(canon(r"C:\\foo\\.\\bar"), r"C:\\foo\\bar");
        assert_eq!(canon(r"C:\\foo\\..\\bar"), r"C:\\bar");
        // UNC path
        assert_eq!(
            canon(r"\\\\server\\share\\dir\\..\\file"),
            "\\\\server\\share\\file\\\\"
        );
    }
}
