use super::{Error, Result};
use ext_php_rs::binary::Binary;
use ext_php_rs::binary_slice::BinarySlice;
use ext_php_rs::{php_class, php_impl};
use imagesize::{Compression, ImageType};

/// Active-content markers that make an "image" dangerous when a browser
/// content-sniffs it as HTML or a misconfigured server executes it as PHP.
/// All markers start with `<`, which the scanner exploits.
const POLYGLOT_MARKERS: &[&[u8]] = &[
    b"<?php",
    b"<?=",
    b"<script",
    b"<html",
    b"<!doctype",
    b"<svg",
    b"<iframe",
    b"<embed",
    b"<object",
];

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Header-only image hardening: inspect untrusted image uploads without ever
/// invoking an image decoder.
///
/// `getimagesize()` is header-based, but `imagecreatefromstring()` and friends
/// run the full C codec (libjpeg/libpng/libgd) on attacker bytes with no
/// sandbox. This class reads only headers and container structure, so
/// dimension checks (decompression-bomb guards), format/extension/MIME
/// verification, polyglot detection, and metadata stripping all happen
/// *before* any decoder sees the file.
#[php_class]
#[php(name = "Hardened\\Sanitizers\\File\\ImageSanitizer")]
pub struct ImageSanitizer {
    data: Vec<u8>,
}

impl ImageSanitizer {
    fn _image_type(&self) -> Option<ImageType> {
        imagesize::image_type(&self.data).ok()
    }

    fn _format(&self) -> Option<&'static str> {
        Some(match self._image_type()? {
            ImageType::Bmp => "bmp",
            ImageType::Gif => "gif",
            ImageType::Heif(Compression::Av1) => "avif",
            ImageType::Heif(_) => "heif",
            ImageType::Ico => "ico",
            ImageType::Jpeg => "jpeg",
            ImageType::Jxl => "jxl",
            ImageType::Png => "png",
            ImageType::Psd => "psd",
            ImageType::Qoi => "qoi",
            ImageType::Tga => "tga",
            ImageType::Tiff => "tiff",
            ImageType::Webp => "webp",
            _ => return None,
        })
    }

    fn _mime(&self) -> Option<&'static str> {
        Some(match self._format()? {
            "avif" => "image/avif",
            "bmp" => "image/bmp",
            "gif" => "image/gif",
            "heif" => "image/heif",
            "ico" => "image/x-icon",
            "jpeg" => "image/jpeg",
            "jxl" => "image/jxl",
            "png" => "image/png",
            "psd" => "image/vnd.adobe.photoshop",
            "qoi" => "image/qoi",
            "tga" => "image/x-tga",
            "tiff" => "image/tiff",
            "webp" => "image/webp",
            _ => return None,
        })
    }

    fn _extensions(&self) -> &'static [&'static str] {
        match self._format() {
            Some("avif") => &["avif"],
            Some("bmp") => &["bmp", "dib"],
            Some("gif") => &["gif"],
            Some("heif") => &["heif", "heic"],
            Some("ico") => &["ico"],
            Some("jpeg") => &["jpg", "jpeg", "jpe", "jfif"],
            Some("jxl") => &["jxl"],
            Some("png") => &["png"],
            Some("psd") => &["psd"],
            Some("qoi") => &["qoi"],
            Some("tga") => &["tga"],
            Some("tiff") => &["tif", "tiff"],
            Some("webp") => &["webp"],
            _ => &[],
        }
    }

    fn _dimensions(&self) -> Result<(usize, usize)> {
        let size = imagesize::blob_size(&self.data)
            .map_err(|e| Error::UnknownImageFormat(e.to_string()))?;
        Ok((size.width, size.height))
    }

    fn _find_polyglot_marker(&self) -> Option<&'static [u8]> {
        let data = &self.data;
        for (pos, _) in data.iter().enumerate().filter(|&(_, &b)| b == b'<') {
            for marker in POLYGLOT_MARKERS {
                if data[pos..]
                    .get(..marker.len())
                    .is_some_and(|window| window.eq_ignore_ascii_case(marker))
                {
                    return Some(marker);
                }
            }
        }
        None
    }

    /// Strips metadata segments from a JPEG stream: APP1–APP15 (EXIF, XMP,
    /// IPTC, …) and COM comments. APP0 (JFIF), APP14 (Adobe color transform)
    /// and APP2 carrying an ICC profile are kept, since removing them changes
    /// how the image renders.
    fn _strip_jpeg(data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
            return Err(Error::MalformedImage("missing JPEG SOI marker".into()));
        }
        let mut out = Vec::with_capacity(data.len());
        out.extend_from_slice(&data[..2]);
        let mut i = 2;
        loop {
            if i + 2 > data.len() {
                return Err(Error::MalformedImage("truncated JPEG segment".into()));
            }
            if data[i] != 0xFF {
                return Err(Error::MalformedImage("invalid JPEG marker".into()));
            }
            let marker = data[i + 1];
            match marker {
                // Fill byte before a marker
                0xFF => i += 1,
                // SOS: entropy-coded data follows — copy the rest verbatim
                0xDA => {
                    out.extend_from_slice(&data[i..]);
                    break;
                }
                // EOI
                0xD9 => {
                    out.extend_from_slice(&data[i..]);
                    break;
                }
                // Standalone markers without a length field
                0x01 | 0xD0..=0xD7 => {
                    out.extend_from_slice(&data[i..i + 2]);
                    i += 2;
                }
                _ => {
                    if i + 4 > data.len() {
                        return Err(Error::MalformedImage("truncated JPEG segment".into()));
                    }
                    let len = usize::from(u16::from_be_bytes([data[i + 2], data[i + 3]]));
                    if len < 2 || i + 2 + len > data.len() {
                        return Err(Error::MalformedImage("invalid JPEG segment length".into()));
                    }
                    let payload = &data[i + 4..i + 2 + len];
                    let drop = match marker {
                        0xE0 | 0xEE => false,
                        0xE2 => !payload.starts_with(b"ICC_PROFILE\0"),
                        0xE1..=0xEF | 0xFE => true,
                        _ => false,
                    };
                    if !drop {
                        out.extend_from_slice(&data[i..i + 2 + len]);
                    }
                    i += 2 + len;
                }
            }
        }
        Ok(out)
    }

    /// Strips metadata chunks from a PNG stream: `eXIf` and the textual
    /// chunks (`tEXt`, `zTXt`, `iTXt`) where XMP and other metadata live.
    fn _strip_png(data: &[u8]) -> Result<Vec<u8>> {
        if !data.starts_with(&PNG_SIGNATURE) {
            return Err(Error::MalformedImage("missing PNG signature".into()));
        }
        let mut out = Vec::with_capacity(data.len());
        out.extend_from_slice(&PNG_SIGNATURE);
        let mut i = PNG_SIGNATURE.len();
        while i < data.len() {
            if i + 8 > data.len() {
                return Err(Error::MalformedImage("truncated PNG chunk header".into()));
            }
            let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
            let chunk_type = &data[i + 4..i + 8];
            let total = 8usize
                .checked_add(len)
                .and_then(|n| n.checked_add(4))
                .ok_or_else(|| Error::MalformedImage("PNG chunk length overflow".into()))?;
            if i + total > data.len() {
                return Err(Error::MalformedImage("truncated PNG chunk".into()));
            }
            let drop = matches!(chunk_type, b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt");
            if !drop {
                out.extend_from_slice(&data[i..i + total]);
            }
            if chunk_type == b"IEND" {
                break;
            }
            i += total;
        }
        Ok(out)
    }

    /// Strips `EXIF` and `XMP ` chunks from a WebP (RIFF) stream, fixing up
    /// the RIFF size field and the VP8X feature flags.
    fn _strip_webp(data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
            return Err(Error::MalformedImage("missing RIFF/WEBP header".into()));
        }
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut i = 12;
        while i < data.len() {
            if i + 8 > data.len() {
                return Err(Error::MalformedImage("truncated WebP chunk header".into()));
            }
            let fourcc = &data[i..i + 4];
            let len =
                u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]) as usize;
            let padded = len + (len & 1);
            if i + 8 + padded > data.len() {
                return Err(Error::MalformedImage("truncated WebP chunk".into()));
            }
            if !matches!(fourcc, b"EXIF" | b"XMP ") {
                let mut chunk = data[i..i + 8 + len].to_vec();
                if len & 1 == 1 {
                    chunk.push(0);
                }
                chunks.push(chunk);
            }
            i += 8 + padded;
        }
        // Clear the EXIF (0x08) and XMP (0x04) feature bits in VP8X, if present.
        if let Some(first) = chunks.first_mut()
            && first.starts_with(b"VP8X")
            && first.len() > 8
        {
            first[8] &= !0x0C;
        }
        let payload_len: usize = chunks.iter().map(Vec::len).sum();
        let riff_size = u32::try_from(payload_len + 4)
            .map_err(|_| Error::MalformedImage("WebP too large".into()))?;
        let mut out = Vec::with_capacity(12 + payload_len);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&riff_size.to_le_bytes());
        out.extend_from_slice(b"WEBP");
        for chunk in &chunks {
            out.extend_from_slice(chunk);
        }
        Ok(out)
    }

    fn _strip_metadata(&self) -> Result<Vec<u8>> {
        match self._format() {
            Some("jpeg") => Self::_strip_jpeg(&self.data),
            Some("png") => Self::_strip_png(&self.data),
            Some("webp") => Self::_strip_webp(&self.data),
            Some(other) => Err(Error::MetadataStripUnsupported(other.to_string())),
            None => Err(Error::UnknownImageFormat(
                "could not detect image format".into(),
            )),
        }
    }
}

#[php_impl]
impl ImageSanitizer {
    /// Constructs a sanitizer over raw image bytes.
    ///
    /// # Parameters
    /// - `data`: The raw image bytes (e.g. an upload body).
    #[allow(clippy::needless_pass_by_value)]
    fn __construct(data: BinarySlice<u8>) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Constructs a sanitizer over raw image bytes (alias for the constructor).
    ///
    /// # Parameters
    /// - `data`: The raw image bytes.
    #[allow(clippy::needless_pass_by_value)]
    fn from_bytes(data: BinarySlice<u8>) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Constructs a sanitizer by reading a file.
    ///
    /// # Parameters
    /// - `path`: Filesystem path to the image (e.g. `$_FILES[...]['tmp_name']`).
    ///
    /// # Exceptions
    /// - Throws an exception if the file cannot be read.
    fn from_file(path: &str) -> Result<Self> {
        Ok(Self {
            data: std::fs::read(path).map_err(|e| Error::FileOpenError {
                path: path.to_string(),
                reason: e.to_string(),
            })?,
        })
    }

    /// Detects the image format from magic bytes (never trusts the extension
    /// or a declared MIME type).
    ///
    /// # Returns
    /// - `string|null`: One of `"jpeg"`, `"png"`, `"gif"`, `"webp"`, `"bmp"`,
    ///   `"tiff"`, `"ico"`, `"avif"`, `"heif"`, `"jxl"`, `"psd"`, `"qoi"`,
    ///   `"tga"`, or `null` if not a recognized image.
    fn format(&self) -> Option<&'static str> {
        self._format()
    }

    /// Returns the canonical MIME type for the detected format.
    ///
    /// # Returns
    /// - `string|null`: e.g. `"image/jpeg"`, or `null` if the format is
    ///   unrecognized.
    fn mime(&self) -> Option<&'static str> {
        self._mime()
    }

    /// Reads the image dimensions from the header only — the pixel decoder is
    /// never invoked, so decompression bombs cannot trigger.
    ///
    /// # Returns
    /// - `array{0: int, 1: int}`: `[width, height]` in pixels.
    ///
    /// # Exceptions
    /// - Throws an exception if the format is unrecognized or the header is
    ///   malformed.
    fn dimensions(&self) -> Result<Vec<usize>> {
        let (width, height) = self._dimensions()?;
        Ok(vec![width, height])
    }

    /// Asserts that the header-declared dimensions do not exceed the limits.
    /// Use before handing the bytes to any real decoder.
    ///
    /// # Parameters
    /// - `max_width`: Maximum allowed width in pixels.
    /// - `max_height`: Maximum allowed height in pixels.
    ///
    /// # Exceptions
    /// - Throws an exception if the image exceeds the limits, or if the
    ///   format/header cannot be parsed.
    fn assert_dimensions_within(&self, max_width: usize, max_height: usize) -> Result<()> {
        let (width, height) = self._dimensions()?;
        if width > max_width || height > max_height {
            return Err(Error::ImageBomb { width, height });
        }
        Ok(())
    }

    /// Asserts that the header-declared pixel count (width × height) does not
    /// exceed the limit. Catches extreme aspect ratios (e.g. 1×1000000000)
    /// that per-side limits miss.
    ///
    /// # Parameters
    /// - `max_pixels`: Maximum allowed number of pixels.
    ///
    /// # Exceptions
    /// - Throws an exception if the image exceeds the limit, or if the
    ///   format/header cannot be parsed.
    fn assert_pixels_within(&self, max_pixels: usize) -> Result<()> {
        let (width, height) = self._dimensions()?;
        if width.checked_mul(height).is_none_or(|px| px > max_pixels) {
            return Err(Error::ImageBomb { width, height });
        }
        Ok(())
    }

    /// Checks whether the magic-byte format matches the file extension.
    /// Catches `shell.php` uploaded as `image/png`, double extensions whose
    /// final extension lies, and renamed files.
    ///
    /// # Parameters
    /// - `filename`: The client-supplied filename.
    ///
    /// # Returns
    /// - `bool`: `true` if the extension belongs to the detected format.
    fn matches_extension(&self, filename: &str) -> bool {
        let Some((_, extension)) = filename.rsplit_once('.') else {
            return false;
        };
        let extension = extension.to_ascii_lowercase();
        self._extensions().contains(&extension.as_str())
    }

    /// Checks whether the magic-byte format matches a declared MIME type
    /// (e.g. the `Content-Type` of an upload — which is attacker-controlled).
    ///
    /// # Parameters
    /// - `mime`: The declared MIME type.
    ///
    /// # Returns
    /// - `bool`: `true` if the declared type matches the detected format.
    fn matches_mime(&self, mime: &str) -> bool {
        self._mime()
            .is_some_and(|detected| detected.eq_ignore_ascii_case(mime.trim()))
    }

    /// Scans the entire byte stream for active-content markers (`<?php`,
    /// `<script`, `<html`, `<svg`, …) that turn a valid image into a
    /// polyglot — content-sniffing XSS or upload-RCE when the file is ever
    /// served inline or executed.
    ///
    /// # Returns
    /// - `bool`: `true` if a marker is present.
    fn is_polyglot(&self) -> bool {
        self._find_polyglot_marker().is_some()
    }

    /// Asserts that the byte stream contains no active-content markers.
    ///
    /// # Exceptions
    /// - Throws an exception naming the marker if one is found.
    fn assert_not_polyglot(&self) -> Result<()> {
        if let Some(marker) = self._find_polyglot_marker() {
            return Err(Error::ImagePolyglot(
                String::from_utf8_lossy(marker).into_owned(),
            ));
        }
        Ok(())
    }

    /// Returns a copy of the image with metadata stripped, without decoding
    /// pixel data:
    /// - **JPEG**: drops APP1–APP15 (EXIF incl. GPS, XMP, IPTC) and COM
    ///   comments; keeps JFIF, Adobe and ICC-profile segments.
    /// - **PNG**: drops `eXIf`, `tEXt`, `zTXt`, `iTXt` chunks.
    /// - **WebP**: drops `EXIF` and `XMP` chunks, fixing the RIFF size and
    ///   VP8X feature flags.
    ///
    /// # Returns
    /// - `string`: The sanitized image bytes.
    ///
    /// # Exceptions
    /// - Throws an exception for other formats or malformed container data.
    fn strip_metadata(&self) -> Result<Binary<u8>> {
        Ok(Binary::from(self._strip_metadata()?))
    }
}

#[cfg(test)]
mod tests {
    use super::ImageSanitizer;
    use crate::run_php_example;

    fn sanitizer(data: &[u8]) -> ImageSanitizer {
        ImageSanitizer {
            data: data.to_vec(),
        }
    }

    /// Minimal GIF89a header with the given logical screen dimensions.
    fn gif(width: u16, height: u16) -> Vec<u8> {
        let mut data = b"GIF89a".to_vec();
        data.extend_from_slice(&width.to_le_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x3B]);
        data
    }

    /// Minimal JPEG: SOI, APP1 Exif, COM, SOF0 with dimensions, SOS, EOI.
    fn jpeg_with_metadata(width: u16, height: u16) -> Vec<u8> {
        let mut data = vec![0xFF, 0xD8];
        // APP1 Exif segment
        let exif = b"Exif\0\0SECRET-GPS-DATA";
        data.extend_from_slice(&[0xFF, 0xE1]);
        data.extend_from_slice(&u16::try_from(exif.len() + 2).unwrap().to_be_bytes());
        data.extend_from_slice(exif);
        // COM segment
        let comment = b"a comment";
        data.extend_from_slice(&[0xFF, 0xFE]);
        data.extend_from_slice(&u16::try_from(comment.len() + 2).unwrap().to_be_bytes());
        data.extend_from_slice(comment);
        // SOF0: len 11, precision 8, height, width, 1 component
        data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08]);
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x01, 0x11, 0x00]);
        // SOS with token entropy data, then EOI
        data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        data.extend_from_slice(&[0xAB, 0xCD]);
        data.extend_from_slice(&[0xFF, 0xD9]);
        data
    }

    /// Minimal PNG with an IHDR, a tEXt metadata chunk, and IEND.
    /// CRCs are zeroed; nothing in the sanitizer validates them.
    fn png_with_text_chunk(width: u32, height: u32) -> Vec<u8> {
        let mut data = super::PNG_SIGNATURE.to_vec();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
        data.extend_from_slice(&u32::try_from(ihdr.len()).unwrap().to_be_bytes());
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&ihdr);
        data.extend_from_slice(&[0; 4]);
        let text = b"Author\0Big Brother";
        data.extend_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
        data.extend_from_slice(b"tEXt");
        data.extend_from_slice(text);
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&[0; 4]);
        data
    }

    /// Minimal extended WebP: VP8X with EXIF+XMP flags, EXIF and XMP chunks.
    fn webp_with_metadata(width: u32, height: u32) -> Vec<u8> {
        let mut chunks = Vec::new();
        // VP8X: flags (EXIF|XMP), 3 reserved bytes, canvas size minus one (24-bit LE)
        let mut vp8x = vec![0x0C, 0, 0, 0];
        vp8x.extend_from_slice(&(width - 1).to_le_bytes()[..3]);
        vp8x.extend_from_slice(&(height - 1).to_le_bytes()[..3]);
        for (fourcc, payload) in [
            (b"VP8X", vp8x.as_slice()),
            (b"EXIF", b"SECRET-GPS".as_slice()),
            (b"XMP ", b"<x:xmpmeta/>".as_slice()),
        ] {
            chunks.extend_from_slice(fourcc);
            chunks.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
            chunks.extend_from_slice(payload);
            if payload.len() & 1 == 1 {
                chunks.push(0);
            }
        }
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&u32::try_from(chunks.len() + 4).unwrap().to_le_bytes());
        data.extend_from_slice(b"WEBP");
        data.extend_from_slice(&chunks);
        data
    }

    #[test]
    fn test_format_and_mime() {
        assert_eq!(sanitizer(&gif(2, 3)).format(), Some("gif"));
        assert_eq!(sanitizer(&jpeg_with_metadata(4, 5)).format(), Some("jpeg"));
        assert_eq!(sanitizer(&png_with_text_chunk(1, 1)).format(), Some("png"));
        assert_eq!(sanitizer(&webp_with_metadata(8, 8)).format(), Some("webp"));
        assert_eq!(sanitizer(b"not an image at all").format(), None);
        assert_eq!(sanitizer(&gif(2, 3)).mime(), Some("image/gif"));
        assert_eq!(
            sanitizer(&jpeg_with_metadata(4, 5)).mime(),
            Some("image/jpeg")
        );
    }

    #[test]
    fn test_dimensions_header_only() {
        assert_eq!(sanitizer(&gif(640, 480))._dimensions().unwrap(), (640, 480));
        assert_eq!(
            sanitizer(&jpeg_with_metadata(123, 45))
                ._dimensions()
                .unwrap(),
            (123, 45)
        );
        assert_eq!(
            sanitizer(&png_with_text_chunk(10, 20))
                ._dimensions()
                .unwrap(),
            (10, 20)
        );
        assert_eq!(
            sanitizer(&webp_with_metadata(16, 9))._dimensions().unwrap(),
            (16, 9)
        );
        assert!(sanitizer(b"junk")._dimensions().is_err());
    }

    #[test]
    fn test_bomb_guards() {
        let ok = sanitizer(&gif(640, 480));
        assert!(ok.assert_dimensions_within(1000, 1000).is_ok());
        assert!(ok.assert_pixels_within(1_000_000).is_ok());

        let wide = sanitizer(&gif(60000, 2));
        assert!(wide.assert_dimensions_within(10000, 10000).is_err());
        // Per-side limits pass, pixel budget catches it
        let tall = sanitizer(&gif(5000, 5000));
        assert!(tall.assert_dimensions_within(10000, 10000).is_ok());
        assert!(tall.assert_pixels_within(1_000_000).is_err());
    }

    #[test]
    fn test_matches_extension_and_mime() {
        let png = sanitizer(&png_with_text_chunk(1, 1));
        assert!(png.matches_extension("photo.png"));
        assert!(png.matches_extension("PHOTO.PNG"));
        assert!(!png.matches_extension("photo.jpg"));
        assert!(!png.matches_extension("shell.php"));
        assert!(!png.matches_extension("no-extension"));
        // The double-extension lie: bytes are PNG, final extension is php
        assert!(!png.matches_extension("invoice.png.php"));
        assert!(png.matches_mime("image/png"));
        assert!(png.matches_mime("IMAGE/PNG"));
        assert!(!png.matches_mime("image/jpeg"));

        let jpeg = sanitizer(&jpeg_with_metadata(1, 1));
        assert!(jpeg.matches_extension("a.jpg"));
        assert!(jpeg.matches_extension("a.jpeg"));
        assert!(!sanitizer(b"junk").matches_extension("a.jpg"));
        assert!(!sanitizer(b"junk").matches_mime("image/jpeg"));
    }

    #[test]
    fn test_polyglot_detection() {
        let mut evil = gif(2, 2);
        evil.extend_from_slice(b"<?php system($_GET['c']); ?>");
        assert!(sanitizer(&evil).is_polyglot());
        assert!(sanitizer(&evil).assert_not_polyglot().is_err());

        let mut sneaky = gif(2, 2);
        sneaky.extend_from_slice(b"<ScRiPt>alert(1)</script>");
        assert!(sanitizer(&sneaky).is_polyglot());

        assert!(!sanitizer(&gif(2, 2)).is_polyglot());
        assert!(!sanitizer(&jpeg_with_metadata(4, 4)).is_polyglot());
        // A lone '<' is not a marker
        let mut angles = gif(2, 2);
        angles.extend_from_slice(b"a < b > c");
        assert!(!sanitizer(&angles).is_polyglot());
    }

    #[test]
    fn test_strip_jpeg_metadata() {
        let original = jpeg_with_metadata(123, 45);
        let stripped = sanitizer(&original)._strip_metadata().unwrap();
        assert!(stripped.len() < original.len());
        let stripped_img = sanitizer(&stripped);
        // Still a valid JPEG with the same dimensions...
        assert_eq!(stripped_img.format(), Some("jpeg"));
        assert_eq!(stripped_img._dimensions().unwrap(), (123, 45));
        // ...but the metadata is gone
        assert!(!stripped.windows(6).any(|w| w == b"SECRET"));
        assert!(!stripped.windows(9).any(|w| w == b"a comment"));
    }

    #[test]
    fn test_strip_png_metadata() {
        let original = png_with_text_chunk(10, 20);
        let stripped = sanitizer(&original)._strip_metadata().unwrap();
        let stripped_img = sanitizer(&stripped);
        assert_eq!(stripped_img.format(), Some("png"));
        assert_eq!(stripped_img._dimensions().unwrap(), (10, 20));
        assert!(!stripped.windows(11).any(|w| w == b"Big Brother"));
        assert!(stripped.windows(4).any(|w| w == b"IEND"));
    }

    #[test]
    fn test_strip_webp_metadata() {
        let original = webp_with_metadata(16, 9);
        let stripped = sanitizer(&original)._strip_metadata().unwrap();
        let stripped_img = sanitizer(&stripped);
        assert_eq!(stripped_img.format(), Some("webp"));
        assert_eq!(stripped_img._dimensions().unwrap(), (16, 9));
        assert!(!stripped.windows(6).any(|w| w == b"SECRET"));
        assert!(!stripped.windows(4).any(|w| w == b"XMP "));
        // VP8X EXIF/XMP feature bits cleared
        assert_eq!(stripped[20] & 0x0C, 0);
    }

    #[test]
    fn test_strip_unsupported_format() {
        assert!(sanitizer(&gif(2, 2))._strip_metadata().is_err());
        assert!(sanitizer(b"junk")._strip_metadata().is_err());
    }

    #[test]
    fn test_strip_malformed_input() {
        // Truncated JPEG segment must error, not panic
        let truncated = vec![0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF];
        assert!(ImageSanitizer::_strip_jpeg(&truncated).is_err());
        // PNG chunk length pointing past the end
        let mut bad_png = super::PNG_SIGNATURE.to_vec();
        bad_png.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        bad_png.extend_from_slice(b"IHDR");
        assert!(ImageSanitizer::_strip_png(&bad_png).is_err());
        // WebP chunk overrunning the buffer
        let mut bad_webp = b"RIFF\x20\x00\x00\x00WEBP".to_vec();
        bad_webp.extend_from_slice(b"VP8X\xFF\x00\x00\x00");
        assert!(ImageSanitizer::_strip_webp(&bad_webp).is_err());
    }

    #[test]
    fn php_example() -> crate::TestResult {
        run_php_example("sanitizers/image")?;
        Ok(())
    }
}
