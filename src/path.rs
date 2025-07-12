use crate::to_str;
use anyhow::anyhow;
use ext_php_rs::types::Zval;
use ext_php_rs::{php_class, php_impl};
use std::ffi::OsStr;
use std::path::Component;
use std::path::{Path, PathBuf};

#[php_class]
#[php(name = "Hardened\\Path")]
#[derive(Debug)]
pub struct PathObj {
    inner: PathBuf,
}

impl PathObj {
    #[inline]
    fn _from<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            inner: lexical_canonicalize(path.into()),
        }
    }

    #[inline]
    fn _append(&self, path: &str) -> Self {
        Self::_from(self.inner.join(path))
    }

    #[inline]
    fn _append_within(&self, path: &str) -> anyhow::Result<Self> {
        let inner = lexical_canonicalize(self.inner.join(path));
        if inner.starts_with(&self.inner) {
            Ok(Self { inner })
        } else {
            Err(anyhow!("Not a sub path"))
        }
    }

    fn _starts_with(&self, path: &str) -> bool {
        self.inner.starts_with(path)
    }
}

impl PartialEq<Self> for PathObj {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<OsStr> for PathObj {
    fn eq(&self, other: &OsStr) -> bool {
        self.inner.eq(other)
    }
}

impl PartialEq<str> for PathObj {
    fn eq(&self, other: &str) -> bool {
        self.inner.eq(Path::new(other))
    }
}

#[php_impl]
impl PathObj {
    /// Creates a new PathObj by lexically canonicalizing a given PHP value.
    ///
    /// # Parameters
    /// - `path`: The PHP value to convert to a filesystem path.
    ///
    /// # Exceptions
    /// - Throws an exception if conversion of `$path` to string fails.
    #[inline]
    fn from(path: &Zval) -> anyhow::Result<Self> {
        Ok(Self {
            inner: lexical_canonicalize(Path::new(&to_str(path)?)),
        })
    }

    /// Constructs a new PathObj instance (alias for `from`).
    ///
    /// # Parameters
    /// - `path`: The PHP value to convert to a filesystem path.
    ///
    /// # Exceptions
    /// - Throws an exception if conversion from Zval to string fails.
    fn __construct(path: &Zval) -> anyhow::Result<Self> {
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
    /// # Exceptions
    /// - Throws an exception if conversion from Zval to string fails.
    fn starts_with(&self, path: &Zval) -> anyhow::Result<bool> {
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
    /// # Exceptions
    /// - Throws an exception if conversion from Zval to string fails.
    fn append(&self, path: &Zval) -> anyhow::Result<Self> {
        Ok(self._append(&to_str(path)?))
    }

    /// Joins the given path onto this path, canonicalizes it, and ensures it's a subpath.
    ///
    /// # Parameters
    /// - `path`: string|Path
    ///
    /// # Exceptions
    /// - Throws an exception if `$path` is not a string nor Path
    fn append_within_base(&self, path: &Zval) -> anyhow::Result<Self> {
        self._append_within(&to_str(path)?)
    }

    /// Set the file name component of the path.
    ///
    /// # Parameters
    /// - `fileName`: string
    fn set_file_name(&mut self, file_name: &str) -> Self {
        let mut inner = self.inner.clone();
        inner.set_file_name(file_name);
        Self { inner }
    }

    /// Set the file name component of the path.
    ///
    /// # Parameters
    /// - `extension`: string
    fn set_extension(&mut self, extension: &str) -> Self {
        let mut inner = self.inner.clone();
        inner.set_extension(extension);
        Self { inner }
    }

    /// Get the last component of the path.
    fn file_name(&self) -> Option<String> {
        self.inner
            .file_name()
            .and_then(OsStr::to_str)
            .map(str::to_string)
    }

    /// Get the directory name (similar to `dirname()`).
    fn parent(&self) -> Option<PathObj> {
        self.inner.parent().and_then(Path::to_str).map(|x| Self {
            inner: lexical_canonicalize(Path::new(x)),
        })
    }

    /// Converts the path to its string representation.
    ///
    /// # Returns
    /// The string representation of the path.
    ///
    /// # Errors
    /// Throws an exception if the path cannot be converted to a string.
    fn __to_string(&self) -> anyhow::Result<String> {
        self.inner
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("Could not convert path to string"))
    }

    fn path(&self) -> anyhow::Result<String> {
        self.inner
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("Could not convert path to string"))
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
            .is_some_and(|ext| allowed.iter().any(|a| a.eq_ignore_ascii_case(ext)))
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
fn lexical_canonicalize<P: AsRef<Path>>(path: P) -> PathBuf {
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
    use super::{PathObj, lexical_canonicalize};
    use crate::run_php_example;
    use std::ffi::OsStr;
    use std::path::PathBuf;

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

    // --- Tests for PathObj stringification and basic join/canonicalize ---

    #[test]
    fn test_pathobj_to_string() {
        let p = PathObj {
            inner: PathBuf::from("foo/bar"),
        };
        assert_eq!(p.__to_string().unwrap(), "foo/bar");
    }

    #[test]
    fn test_lexical_append_paths() {
        // join-like behavior via canonicalize
        assert_eq!(canon("base/inner/../leaf"), "base/leaf");
        assert_eq!(canon("/base//subdir//file.txt"), "/base/subdir/file.txt");
    }

    #[test]
    fn test_lexical_canonicalize_escape_prevention() {
        // attempting to escape beyond root yields root-relative
        assert_eq!(canon("base/sub/../../etc"), "etc");
    }

    // --- Tests for std::path PathBuf file-name and extension operations ---

    #[test]
    fn test_std_pathbuf_file_name_and_extension() {
        let mut path = PathBuf::from("dir/filename.txt");
        assert_eq!(path.file_name(), Some(OsStr::new("filename.txt")));
        assert_eq!(path.extension(), Some(OsStr::new("txt")));

        path.set_file_name("other.bin");
        assert_eq!(path.file_name(), Some(OsStr::new("other.bin")));
        assert_eq!(path.extension(), Some(OsStr::new("bin")));

        path.set_extension("md");
        assert_eq!(path.file_name(), Some(OsStr::new("other.md")));
        assert_eq!(path.extension(), Some(OsStr::new("md")));
    }

    // --- Tests for our PathObj extension helpers ---

    #[test]
    fn test_validate_extension_custom() {
        let p = PathObj {
            inner: PathBuf::from("photo.JPG"),
        };
        assert!(p.validate_extension(vec!["jpg", "png"]));
        assert!(!p.validate_extension(vec!["gif", "bmp"]));
    }

    #[test]
    fn test_validate_extension_image() {
        let p_img = PathObj {
            inner: PathBuf::from("image.PNG"),
        };
        let p_not = PathObj {
            inner: PathBuf::from("video.mp4"),
        };
        assert!(p_img.validate_extension_image());
        assert!(!p_not.validate_extension_image());
    }

    #[test]
    fn test_validate_extension_video() {
        let p_vid = PathObj {
            inner: PathBuf::from("clip.webm"),
        };
        let p_not = PathObj {
            inner: PathBuf::from("sound.mp3"),
        };
        assert!(p_vid.validate_extension_video());
        assert!(!p_not.validate_extension_video());
    }

    #[test]
    fn test_validate_extension_audio() {
        let p_audio = PathObj {
            inner: PathBuf::from("track.FlAc"),
        };
        let p_not = PathObj {
            inner: PathBuf::from("document.pdf"),
        };
        assert!(p_audio.validate_extension_audio());
        assert!(!p_not.validate_extension_audio());
    }

    #[test]
    fn test_validate_extension_document() {
        let p_doc = PathObj {
            inner: PathBuf::from("report.PdF"),
        };
        let p_not = PathObj {
            inner: PathBuf::from("archive.zip"),
        };
        assert!(p_doc.validate_extension_document());
        assert!(!p_not.validate_extension_document());
    }

    #[test]
    fn test_append_simple() {
        let base = PathBuf::from("base/dir");
        let joined = lexical_canonicalize(base.join("sub/file.txt"));
        assert_eq!(joined, PathBuf::from("base/dir/sub/file.txt"));
    }

    #[test]
    fn test_append_and_canonicalize() {
        let base = PathBuf::from("base/dir");
        let joined = lexical_canonicalize(base.join("../other/./leaf"));
        assert_eq!(joined, PathBuf::from("base/other/leaf"));
    }

    #[test]
    fn test_append_within_allowed() {
        let base = PathBuf::from("home/user");
        let candidate = lexical_canonicalize(base.join("docs/report.pdf"));
        assert!(candidate.starts_with("home/user"));
    }

    #[test]
    fn test_append_within_disallowed() {
        let base = PathBuf::from("home/user");
        let candidate = lexical_canonicalize(base.join("../../etc/passwd"));
        assert!(!candidate.starts_with("home/user"));
    }

    // --- Tests for PathObj methods that mirror PathBuf operations ---

    #[test]
    fn test_pathobj_to_string_and_starts_with() {
        let p = PathObj {
            inner: PathBuf::from("a/b/c"),
        };
        // __to_string
        assert_eq!(p.__to_string().unwrap(), "a/b/c");
        // starts_with
        assert!(p._starts_with("a/b"));
        assert!(!p._starts_with("a/x"));
    }

    #[test]
    fn test_pathobj_append_and_append_within() {
        let base = PathObj {
            inner: PathBuf::from("root/dir"),
        };
        // join
        assert!(base._append("sub/child").eq("root/dir/sub/child"));
        // join_within valid
        assert!(base._append_within("docs").unwrap().eq("root/dir/docs"));
        assert!(base._append_within("../dir").unwrap().eq("root/dir"));

        // join_within disallowed
        assert!(base._append_within("../outside").is_err());
        assert!(base._append_within("../dirzzz").is_err());
    }

    #[test]
    fn test_pathobj_file_name_and_extension_methods() {
        let mut p = PathBuf::from("folder/old.txt");
        // file_name change
        p.set_file_name("new.bin");
        assert_eq!(p.file_name(), Some(OsStr::new("new.bin")));
        // extension change
        p.set_extension("md");
        assert_eq!(p.extension(), Some(OsStr::new("md")));
    }

    #[test]
    fn test_set_file_name_and_get_file_name() {
        let mut original = PathObj::_from("dir/old.txt");
        let changed = original.set_file_name("new.bin");
        assert_eq!(changed.file_name(), Some("new.bin".to_string()));
    }

    #[test]
    fn test_set_extension_and_get_file_name() {
        let mut original = PathObj::_from("dir/file.txt");
        let changed = original.set_extension("md");
        assert_eq!(changed.file_name(), Some("file.md".to_string()));
    }

    #[test]
    fn test_file_name_not_none() {
        let p = PathObj::_from("foo/bar/");
        assert_eq!(p.file_name(), Some("bar".to_string()));
    }

    #[test]
    fn test_parent() {
        let p = PathObj::_from("foo/bar/baz.txt");
        let parent = p.parent().unwrap();
        assert_eq!(
            parent,
            PathObj {
                inner: lexical_canonicalize(PathBuf::from("foo/bar"))
            }
        );
    }

    #[test]
    fn test_parent_none() {
        let p = PathObj::_from("");
        assert!(p.parent().is_none());
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("path")?;
        Ok(())
    }
}
