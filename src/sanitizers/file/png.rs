use anyhow::{Result, anyhow, bail};
use ext_php_rs::{php_class, php_impl};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

/// Engine for detecting “PNG bombs” (images with unreasonable dimensions).
#[php_class]
#[php(name = "Hardened\\Sanitizers\\File\\PngSanitizer")]
pub struct PngSanitizer {}

#[php_impl]
impl PngSanitizer {
    /// Scan a file at the given path and detect PNG bombs.
    ///
    /// # Parameters
    /// - `path`: `string` Filesystem path to the PNG file.
    ///
    /// # Returns
    /// - `bool` `true` if the file is a PNG *and* has width or height > 10000,
    ///   or if it’s invalid PNG with missing IHDR. Returns `false` if it’s not
    ///   a PNG or has acceptable dimensions.
    ///
    /// # Exceptions
    /// - Throws an exception if the file cannot be opened, read, or the format
    ///   is malformed (e.g. missing IHDR).
    ///
    /// ## Example
    /// ```php
    /// Hardened\Sanitizers\File\PngSanitizer::defuse('/tmp/image.png');
    /// ```
    fn defuse(path: &str) -> Result<()> {
        // Open the file
        let mut f = File::open(path).map_err(|e| anyhow!("Failed to open '{}': {}", path, e))?;

        // Read and verify the 8‑byte PNG signature
        let mut sig = [0u8; 8];
        f.read_exact(&mut sig)
            .map_err(|e| anyhow!("Failed to read PNG signature: {}", e))?;
        if sig != [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
            // Not a PNG → not a bomb
            return Ok(());
        }

        // Next comes a 4‑byte chunk length and 4‑byte chunk type
        // Seek to the chunk-length field (immediately after signature)
        f.seek(SeekFrom::Start(8))
            .map_err(|e| anyhow!("Seek failed: {}", e))?;
        let mut len_buf = [0u8; 4];
        f.read_exact(&mut len_buf)
            .map_err(|e| anyhow!("Failed to read IHDR length: {}", e))?;

        let mut chunk_type = [0u8; 4];
        f.read_exact(&mut chunk_type)
            .map_err(|e| anyhow!("Failed to read chunk type: {}", e))?;
        if &chunk_type != b"IHDR" {
            return Err(anyhow!("Missing IHDR chunk; invalid PNG"));
        }

        // IHDR payload starts immediately: width (4 bytes BE), height (4 bytes BE)
        let mut dim_buf = [0u8; 4];
        f.read_exact(&mut dim_buf)
            .map_err(|e| anyhow!("Failed to read width: {}", e))?;
        let width = u32::from_be_bytes(dim_buf);
        f.read_exact(&mut dim_buf)
            .map_err(|e| anyhow!("Failed to read height: {}", e))?;
        let height = u32::from_be_bytes(dim_buf);

        // Consider >10000 in either dimension a “bomb”
        if width > 10_000 || height > 10_000 {
            bail!("PNG dimensions are too large (width: {width}, height: {height})");
        }

        Ok(())
    }
}
