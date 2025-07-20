use anyhow::{Result, anyhow, bail};
use ext_php_rs::{php_class, php_impl};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
use unrar::Archive as RarArchive;
use zip::ZipArchive;

/// Archive bomb detector for ZIP and RAR files.
///
/// Provides two methods in PHP:
///   - `scan_zip(string $path): bool`
///   - `scan_rar(string $path, ?int $maxRatio = 1000): bool`
#[php_class]
#[php(name = "Hardened\\Sanitizers\\File\\ArchiveSanitizer")]
pub struct ArchiveSanitizer {}

#[php_impl]
impl ArchiveSanitizer {
    /// Perform archive‐bomb detection on a file.
    ///
    /// This internal helper examines the file at `path` and returns an error if it
    /// appears to be a “bomb” (i.e. an archive whose reported uncompressed size
    /// far exceeds its on‐disk compressed size or mismatches the local header).
    ///
    /// **ZIP**:
    /// - Reads the central directory to sum the uncompressed sizes of all entries.
    /// - Reads the 4‐byte little‐endian uncompressed size from the local file header at offset 22.
    /// - Fails if those two values differ.
    ///
    /// **RAR**:
    /// - Computes the on‐disk file size.
    /// - Lists the first entry’s `unpacked_size` and divides by the compressed size.
    /// - Fails if that ratio ≥ `max_ratio` (default 1000).
    ///
    /// # Parameters
    /// - `path`: Filesystem path to the archive file to inspect.
    /// - `max_ratio`: Optional maximum unpacked/compressed ratio for RAR; Default is 1000
    ///
    /// # Exceptions
    /// - I/O errors opening, reading, or seeking the file.
    /// - ZIP archive mismatches (central-directory total vs. local-header size).
    /// - RAR archive exceeds the allowed unpacked/compressed ratio.
    fn defuse(path: &str, max_ratio: Option<u64>) -> Result<()> {
        let mut f = File::open(path).map_err(|e| anyhow!("Failed to open '{}': {}", path, e))?;
        let mut sig = [0u8; 4];
        f.read_exact(&mut sig)?;
        if &sig == b"PK\x03\x04" {
            // Central directory: sum uncompressed sizes
            f.seek(SeekFrom::Start(0))?;
            let mut zip = ZipArchive::new(f)?;
            let mut total_uncompressed = 0u64;
            for i in 0..zip.len() {
                let stat = zip.by_index(i)?;
                total_uncompressed = total_uncompressed.saturating_add(stat.size());
            }

            // Local file header at offset 22 holds a u32 LE uncompressed size
            let mut f2 = File::open(path)?;
            f2.seek(SeekFrom::Start(22))?;
            let mut buf = [0u8; 4];
            f2.read_exact(&mut buf)?;
            let header_uncompressed = u32::from_le_bytes(buf) as u64;

            if total_uncompressed != header_uncompressed {
                bail!("ZIP archive looks like a bomb");
            }
        } else if sig.starts_with(b"Rar") {
            let compressed_size = f.metadata()?.len() as f64;
            let max_ratio = max_ratio.unwrap_or(1000) as f64;

            if let Ok(archive) = RarArchive::new(path).open_for_listing() {
                return archive
                    .map(|entry| -> Result<_> {
                        let entry = entry?;
                        let unpacked = entry.unpacked_size as f64;
                        if compressed_size > 0.0 && (unpacked / compressed_size) >= max_ratio {
                            bail!("RAR archive looks like a bomb");
                        }
                        Ok(())
                    })
                    .collect();
            }
        }
        Ok(())
    }
}
