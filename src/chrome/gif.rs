//! GIF encoder for browser screenshot capture sequences.
//!
//! Receives PNG screenshot bytes from the Chrome extension, decodes them,
//! quantizes to 256-color palette, and assembles an animated GIF.
//! Frames are processed as a stream — no full-sequence accumulation in memory.
//!
//! Design decision #23: GIF encoding in Rust, not JS.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use image::codecs::gif::{GifEncoder as ImageGifEncoder, Repeat};
use image::{DynamicImage, Frame, RgbaImage};
use thiserror::Error;

/// Default frame delay in milliseconds.
pub const DEFAULT_FRAME_DELAY_MS: u16 = 100;

/// Maximum frames per GIF to prevent runaway memory usage.
pub const MAX_FRAMES: usize = 500;

/// Maximum dimension (width or height) before resize.
pub const MAX_DIMENSION: u32 = 1280;

/// Budget: GIF creation < 5s for 10 frames.
pub const BUDGET_10_FRAMES_MS: u64 = 5000;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum GifError {
    #[error("no frames provided")]
    NoFrames,

    #[error("frame limit exceeded: {0} > {MAX_FRAMES}")]
    TooManyFrames(usize),

    #[error("failed to decode PNG frame {index}: {source}")]
    DecodePng {
        index: usize,
        source: image::ImageError,
    },

    #[error("failed to encode GIF: {0}")]
    EncodeGif(String),

    #[error("I/O error writing GIF: {0}")]
    Io(#[from] io::Error),
}

// ---------------------------------------------------------------------------
// GIF builder (streaming)
// ---------------------------------------------------------------------------

/// Configuration for GIF creation.
#[derive(Debug, Clone)]
pub struct GifConfig {
    /// Frame delay in milliseconds.
    pub frame_delay_ms: u16,
    /// Maximum width/height — frames exceeding this are scaled down.
    pub max_dimension: u32,
    /// Whether the GIF loops infinitely.
    pub repeat: bool,
}

impl Default for GifConfig {
    fn default() -> Self {
        Self {
            frame_delay_ms: DEFAULT_FRAME_DELAY_MS,
            max_dimension: MAX_DIMENSION,
            repeat: true,
        }
    }
}

/// Result of a successful GIF encoding.
#[derive(Debug, Clone)]
pub struct GifResult {
    pub path: PathBuf,
    pub frame_count: usize,
    pub file_size_bytes: u64,
    pub elapsed_ms: u64,
}

/// Encode a sequence of PNG screenshot bytes into an animated GIF file.
///
/// Frames are decoded and processed one at a time to minimize peak memory.
pub fn encode_gif(
    png_frames: &[Vec<u8>],
    output_path: &Path,
    config: &GifConfig,
) -> Result<GifResult, GifError> {
    if png_frames.is_empty() {
        return Err(GifError::NoFrames);
    }
    if png_frames.len() > MAX_FRAMES {
        return Err(GifError::TooManyFrames(png_frames.len()));
    }

    let start = Instant::now();

    let file = std::fs::File::create(output_path)?;
    let writer = io::BufWriter::new(file);

    let mut encoder = ImageGifEncoder::new_with_speed(writer, 10);
    if config.repeat {
        encoder
            .set_repeat(Repeat::Infinite)
            .map_err(|e| GifError::EncodeGif(e.to_string()))?;
    }

    let delay = image::Delay::from_numer_denom_ms(u32::from(config.frame_delay_ms), 1);

    for (i, png_bytes) in png_frames.iter().enumerate() {
        let img = decode_png(png_bytes, i)?;
        let rgba = maybe_resize(img, config.max_dimension);
        let frame = Frame::from_parts(rgba, 0, 0, delay);
        encoder
            .encode_frame(frame)
            .map_err(|e| GifError::EncodeGif(e.to_string()))?;
    }

    // Drop encoder to flush and close the writer
    drop(encoder);

    let metadata = std::fs::metadata(output_path)?;
    let elapsed = start.elapsed();

    Ok(GifResult {
        path: output_path.to_path_buf(),
        frame_count: png_frames.len(),
        file_size_bytes: metadata.len(),
        elapsed_ms: elapsed.as_millis() as u64,
    })
}

/// Encode a single PNG frame into a (non-animated) GIF file.
pub fn encode_single_frame(
    png_bytes: &[u8],
    output_path: &Path,
    max_dimension: u32,
) -> Result<GifResult, GifError> {
    let start = Instant::now();

    let img = decode_png(png_bytes, 0)?;
    let rgba = maybe_resize(img, max_dimension);

    let file = std::fs::File::create(output_path)?;
    let writer = io::BufWriter::new(file);
    let mut encoder = ImageGifEncoder::new_with_speed(writer, 10);
    let delay = image::Delay::from_numer_denom_ms(0, 1);
    let frame = Frame::from_parts(rgba, 0, 0, delay);
    encoder
        .encode_frame(frame)
        .map_err(|e| GifError::EncodeGif(e.to_string()))?;
    drop(encoder);

    let metadata = std::fs::metadata(output_path)?;
    let elapsed = start.elapsed();

    Ok(GifResult {
        path: output_path.to_path_buf(),
        frame_count: 1,
        file_size_bytes: metadata.len(),
        elapsed_ms: elapsed.as_millis() as u64,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn decode_png(png_bytes: &[u8], index: usize) -> Result<DynamicImage, GifError> {
    image::load_from_memory_with_format(png_bytes, image::ImageFormat::Png)
        .map_err(|source| GifError::DecodePng { index, source })
}

fn maybe_resize(img: DynamicImage, max_dim: u32) -> RgbaImage {
    let (w, h) = (img.width(), img.height());
    if w <= max_dim && h <= max_dim {
        return img.into_rgba8();
    }
    // Preserve aspect ratio
    let scale = f64::from(max_dim) / f64::from(w.max(h));
    let new_w = ((f64::from(w) * scale) as u32).max(1);
    let new_h = ((f64::from(h) * scale) as u32).max(1);
    img.resize_exact(new_w, new_h, image::imageops::FilterType::Triangle)
        .into_rgba8()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageEncoder;

    /// Create a minimal valid PNG in memory.
    fn tiny_png(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
        let mut img = RgbaImage::new(width, height);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgba(color);
        }
        let mut buf = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut buf);
        encoder
            .write_image(img.as_raw(), width, height, image::ExtendedColorType::Rgba8)
            .expect("encode test PNG");
        buf
    }

    #[test]
    fn test_encode_single_frame() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("single.gif");
        let png = tiny_png(10, 10, [255, 0, 0, 255]);

        let result = encode_single_frame(&png, &out, MAX_DIMENSION).expect("encode single frame");

        assert_eq!(result.frame_count, 1);
        assert!(result.file_size_bytes > 0);
        assert!(out.exists());
    }

    #[test]
    fn test_encode_multi_frame() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("multi.gif");
        let frames: Vec<Vec<u8>> = (0..5)
            .map(|i| {
                let c = (i * 50) as u8;
                tiny_png(20, 20, [c, 255 - c, 128, 255])
            })
            .collect();

        let config = GifConfig::default();
        let result = encode_gif(&frames, &out, &config).expect("encode multi frame");

        assert_eq!(result.frame_count, 5);
        assert!(result.file_size_bytes > 0);
        assert!(out.exists());
    }

    #[test]
    fn test_no_frames_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("empty.gif");

        let result = encode_gif(&[], &out, &GifConfig::default());
        assert!(matches!(result, Err(GifError::NoFrames)));
    }

    #[test]
    fn test_too_many_frames_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("too_many.gif");
        let frames: Vec<Vec<u8>> = (0..MAX_FRAMES + 1).map(|_| vec![0u8; 0]).collect();

        let result = encode_gif(&frames, &out, &GifConfig::default());
        assert!(matches!(result, Err(GifError::TooManyFrames(_))));
    }

    #[test]
    fn test_invalid_png_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("bad.gif");
        let bad_png = vec![0u8, 1, 2, 3]; // not valid PNG

        let result = encode_single_frame(&bad_png, &out, MAX_DIMENSION);
        assert!(matches!(result, Err(GifError::DecodePng { index: 0, .. })));
    }

    #[test]
    fn test_resize_large_frame() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("resized.gif");
        // 2000x2000 > MAX_DIMENSION(1280), should resize
        let png = tiny_png(2000, 2000, [0, 255, 0, 255]);

        let result = encode_single_frame(&png, &out, MAX_DIMENSION).expect("encode resized");
        assert_eq!(result.frame_count, 1);
        assert!(result.file_size_bytes > 0);
    }

    #[test]
    fn test_config_defaults() {
        let config = GifConfig::default();
        assert_eq!(config.frame_delay_ms, DEFAULT_FRAME_DELAY_MS);
        assert_eq!(config.max_dimension, MAX_DIMENSION);
        assert!(config.repeat);
    }

    #[test]
    fn test_custom_config() {
        let config = GifConfig {
            frame_delay_ms: 200,
            max_dimension: 640,
            repeat: false,
        };
        assert_eq!(config.frame_delay_ms, 200);
        assert_eq!(config.max_dimension, 640);
        assert!(!config.repeat);
    }

    #[test]
    fn test_error_display_messages() {
        let err = GifError::NoFrames;
        assert!(format!("{err}").contains("no frames"));

        let err = GifError::TooManyFrames(999);
        let msg = format!("{err}");
        assert!(msg.contains("999") && msg.contains("limit"));

        let err = GifError::EncodeGif("codec failure".to_string());
        assert!(format!("{err}").contains("codec failure"));
    }

    #[test]
    fn test_constants_are_sane() {
        assert!(DEFAULT_FRAME_DELAY_MS > 0, "frame delay must be positive");
        assert!(MAX_FRAMES > 10, "must allow at least 10 frames");
        assert!(MAX_DIMENSION >= 640, "must allow at least 640px");
        assert!(BUDGET_10_FRAMES_MS >= 1000, "budget must be at least 1s");
    }

    #[test]
    fn test_maybe_resize_preserves_small_images() {
        let small = DynamicImage::new_rgba8(100, 100);
        let result = maybe_resize(small, 1280);
        assert_eq!(result.width(), 100);
        assert_eq!(result.height(), 100);
    }

    #[test]
    fn test_maybe_resize_scales_large_images() {
        let large = DynamicImage::new_rgba8(2560, 1440);
        let result = maybe_resize(large, 1280);
        // Should scale to fit within 1280x1280 preserving aspect
        assert!(result.width() <= 1280);
        assert!(result.height() <= 1280);
        assert!(result.width() > 0 && result.height() > 0);
    }

    #[test]
    fn test_gif_output_is_valid_gif_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("header_check.gif");
        let png = tiny_png(4, 4, [128, 128, 128, 255]);

        encode_single_frame(&png, &out, MAX_DIMENSION).expect("encode");

        let bytes = std::fs::read(&out).expect("read gif");
        // GIF files start with "GIF89a" or "GIF87a"
        assert!(
            bytes.starts_with(b"GIF89a") || bytes.starts_with(b"GIF87a"),
            "output must be a valid GIF file"
        );
    }

    #[test]
    fn test_encode_10_frames_within_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("budget.gif");
        let frames: Vec<Vec<u8>> = (0..10)
            .map(|i| {
                let c = (i * 25) as u8;
                tiny_png(100, 100, [c, c, c, 255])
            })
            .collect();

        let config = GifConfig::default();
        let result = encode_gif(&frames, &out, &config).expect("encode 10 frames");

        assert_eq!(result.frame_count, 10);
        assert!(
            result.elapsed_ms < BUDGET_10_FRAMES_MS,
            "10-frame GIF must encode in < {}ms, took {}ms",
            BUDGET_10_FRAMES_MS,
            result.elapsed_ms
        );
    }

    #[test]
    fn test_non_repeating_gif() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("no_repeat.gif");
        let frames = vec![
            tiny_png(10, 10, [255, 0, 0, 255]),
            tiny_png(10, 10, [0, 255, 0, 255]),
        ];

        let config = GifConfig {
            repeat: false,
            ..GifConfig::default()
        };
        let result = encode_gif(&frames, &out, &config).expect("encode non-repeating");
        assert_eq!(result.frame_count, 2);
    }
}
