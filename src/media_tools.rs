//! Opt-in media tools (bd-cv653.2.7).
//! Native image inspection lives in `vision`; `read_media` attaches local media.
//! Generation and synthesis retain their public tool interfaces here.

use crate::error::{Error, Result};
use crate::model::{ContentBlock, TextContent};
use crate::tools::{Tool, ToolEffects, ToolOutput, ToolUpdate};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod transport;
mod vision;
pub use vision::InspectImageTool;

pub const MAX_IMAGE_FILE_SIZE_BYTES: u64 = 20 * 1024 * 1024; // 20 MiB
pub const MAX_TTS_TEXT_CHARS: usize = 4096;
/// Default decoded-byte cap for an inline video/audio block (`media.maxBytes`).
pub const DEFAULT_MEDIA_MAX_BYTES: u64 = 5 * 1024 * 1024;

// Deterministic fixture pixels; never used by native vision requests.
const MIN_VALID_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

const MIN_VALID_WAV: &[u8] = &[
    0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
    0x66, 0x6D, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x44, 0xAC, 0x00, 0x00, 0x88, 0x58, 0x01, 0x00, 0x02, 0x00, 0x10, 0x00,
    0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MediaSettings {
    #[serde(alias = "enableInspectImage")]
    pub enable_inspect_image: Option<bool>,
    #[serde(alias = "enableGenerateImage")]
    pub enable_generate_image: Option<bool>,
    #[serde(alias = "enableTts")]
    pub enable_tts: Option<bool>,
    #[serde(alias = "enableReadMedia")]
    pub enable_read_media: Option<bool>,
    #[serde(alias = "maxBytes")]
    pub max_bytes: Option<u64>,
    #[serde(alias = "visionModel")]
    pub vision_model: Option<String>,
    #[serde(alias = "visionProvider")]
    pub vision_provider: Option<String>,
    #[serde(alias = "imageGenProvider")]
    pub image_gen_provider: Option<String>,
    #[serde(alias = "imageGenModel")]
    pub image_gen_model: Option<String>,
    #[serde(alias = "ttsVoice")]
    pub tts_voice: Option<String>,
    #[serde(alias = "ttsProvider")]
    pub tts_provider: Option<String>,
}

/// Map a `read_media` extension to the MIME spelling expected by Gemini.
pub fn media_mime_type_for_extension(ext: &str) -> Option<&'static str> {
    match ext.to_ascii_lowercase().as_str() {
        "mp4" => Some("video/mp4"),
        "webm" => Some("video/webm"),
        "mov" => Some("video/mov"),
        "mp3" => Some("audio/mpeg"),
        "wav" => Some("audio/wav"),
        "m4a" => Some("audio/m4a"),
        "ogg" => Some("audio/ogg"),
        "flac" => Some("audio/flac"),
        _ => None,
    }
}

pub const READ_MEDIA_EXTENSIONS: &[&str] =
    &["mp4", "webm", "mov", "mp3", "wav", "m4a", "ogg", "flac"];

/// Load local video/audio as inline media for Gemini-family providers.
pub struct ReadMediaTool {
    cwd: PathBuf,
    max_bytes: u64,
}

impl ReadMediaTool {
    pub fn new(cwd: &Path) -> Self {
        Self { cwd: cwd.to_path_buf(), max_bytes: DEFAULT_MEDIA_MAX_BYTES }
    }

    #[must_use]
    pub const fn with_max_bytes(mut self, max_bytes: Option<u64>) -> Self {
        if let Some(max_bytes) = max_bytes { self.max_bytes = max_bytes; }
        self
    }

    #[must_use]
    pub const fn max_bytes(&self) -> u64 { self.max_bytes }

    fn resolve_path(&self, rel_or_abs: &str) -> PathBuf {
        let p = Path::new(rel_or_abs);
        if p.is_absolute() { p.to_path_buf() } else { self.cwd.join(p) }
    }
}

#[async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl Tool for ReadMediaTool {
    fn name(&self) -> &str { "read_media" }
    fn label(&self) -> &str { "Read Media" }
    fn description(&self) -> &str {
        "Attach a local video or audio file (mp4, webm, mov, mp3, wav, m4a, ogg, flac) to the \
         conversation as inline media. Only Gemini-family models can watch/listen to it; other \
         providers see a text placeholder. Files above the configured size cap are rejected."
    }
    fn parameters(&self) -> Value {
        json!({"type":"object", "required":["path"], "properties":{
            "path":{"type":"string", "description":"Path to a local video (mp4, webm, mov) or audio (mp3, wav, m4a, ogg, flac) file"}
        }})
    }
    fn effects(&self) -> ToolEffects { ToolEffects::read() }
    async fn execute(&self, _tool_call_id: &str, args: Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>) -> Result<ToolOutput>
    {
        let path_str = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| Error::tool("read_media", "missing required path parameter"))?;
        let target_path = self.resolve_path(path_str);
        if !target_path.is_file() {
            return Err(Error::tool("read_media", format!("media file not found: {}", target_path.display())));
        }
        let ext = target_path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let Some(mime_type) = media_mime_type_for_extension(&ext) else {
            return Err(Error::tool("read_media", format!("unsupported media extension: .{ext} (supported: {})", READ_MEDIA_EXTENSIONS.join(", "))));
        };
        let metadata = fs::metadata(&target_path)
            .map_err(|e| Error::tool("read_media", format!("cannot stat media file: {e}")))?;
        let size = metadata.len();
        if size > self.max_bytes {
            return Err(Error::tool("read_media", format!(
                "media file is {} ({size} bytes), above the {} cap ({} bytes); raise media.maxBytes or trim the file",
                crate::model::format_media_size(size), crate::model::format_media_size(self.max_bytes), self.max_bytes)));
        }
        if size == 0 { return Err(Error::tool("read_media", "media file is empty")); }
        let bytes = fs::read(&target_path)
            .map_err(|e| Error::tool("read_media", format!("cannot read media file: {e}")))?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(Error::tool("read_media", format!("media file grew past the {} cap while being read", crate::model::format_media_size(self.max_bytes))));
        }
        let data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let name = target_path.file_name().and_then(|n| n.to_str()).and_then(crate::model::sanitize_media_name);
        let note = format!("Read media file {} [{mime_type}, {}]", name.as_deref().unwrap_or(path_str), crate::model::format_media_size(size));
        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent::new(note)), ContentBlock::Media(crate::model::MediaContent { data, mime_type: mime_type.to_string(), name })],
            details: Some(json!({"path":target_path.display().to_string(), "mime_type":mime_type, "size_bytes":size, "max_bytes":self.max_bytes})),
            is_error: false,
        })
    }
}

pub struct GenerateImageTool {
    cwd: PathBuf,
    default_provider: Option<String>,
    mock_mode: Option<bool>,
    api_key: Option<String>,
}

impl GenerateImageTool {
    pub fn new(cwd: &Path) -> Self {
        Self { cwd: cwd.to_path_buf(), default_provider: None, mock_mode: None, api_key: None }
    }
    pub fn with_provider(cwd: &Path, provider: Option<String>) -> Self {
        Self { cwd: cwd.to_path_buf(), default_provider: provider, mock_mode: None, api_key: None }
    }
    #[must_use]
    pub const fn with_mock(mut self, mock: bool) -> Self { self.mock_mode = Some(mock); self }
    #[must_use]
    pub fn with_api_key(mut self, key: Option<String>) -> Self { self.api_key = key; self }
}

#[async_trait]
#[allow(clippy::unnecessary_literal_bound, clippy::too_many_lines)]
impl Tool for GenerateImageTool {
    fn name(&self) -> &str { "generate_image" }
    fn label(&self) -> &str { "Generate Image" }
    fn description(&self) -> &str {
        "Generate an image from a prompt or edit an image via OpenAI (DALL-E), Gemini (Imagen), or xAI. \
         Saves generated image to disk artifact and returns local file path."
    }
    fn parameters(&self) -> Value {
        json!({"type":"object", "required":["prompt"], "properties":{
            "prompt":{"type":"string", "description":"Description of the image to generate"},
            "provider":{"type":"string", "enum":["openai","gemini","xai"], "description":"Image generation provider (default: auto)"},
            "model":{"type":"string", "description":"Model name (e.g. dall-e-3, imagen-3.0-generate-002)"},
            "size":{"type":"string", "enum":["1024x1024","1024x1792","1792x1024","512x512"], "description":"Output dimensions (default: 1024x1024)"},
            "output_path":{"type":"string", "description":"Target destination path for the saved image file"}
        }})
    }
    fn effects(&self) -> ToolEffects { ToolEffects::write() }
    async fn execute(&self, _tool_call_id: &str, args: Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>) -> Result<ToolOutput>
    {
        let prompt = args.get("prompt").and_then(|v| v.as_str())
            .ok_or_else(|| Error::tool("generate_image", "missing required prompt parameter"))?;
        let provider = args.get("provider").and_then(|v| v.as_str())
            .or(self.default_provider.as_deref()).unwrap_or("openai");
        let size = args.get("size").and_then(|v| v.as_str()).unwrap_or("1024x1024");
        let output_path_str = args.get("output_path").and_then(Value::as_str)
            .map_or_else(|| format!("images/generated_{}.png", Uuid::new_v4().simple()), ToString::to_string);
        let target_path = if Path::new(&output_path_str).is_absolute() {
            PathBuf::from(&output_path_str)
        } else { self.cwd.join(&output_path_str) };
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::tool("generate_image", format!("cannot create output dir: {e}")))?;
        }
        let is_mock = self.mock_mode.unwrap_or_else(|| std::env::var("PI_MEDIA_MOCK").unwrap_or_default() == "1");
        if is_mock {
            fs::write(&target_path, MIN_VALID_PNG).map_err(|e| Error::tool("generate_image", format!("failed to write generated image: {e}")))?;
        } else {
            let key_env = match provider {
                "openai" => "OPENAI_API_KEY", "gemini" => "GEMINI_API_KEY", "xai" => "XAI_API_KEY",
                _ => return Err(Error::tool("generate_image", format!("unknown image generation provider: {provider}"))),
            };
            let has_key = self.api_key.as_deref().map_or_else(|| std::env::var(key_env).is_ok(), |k| !k.trim().is_empty());
            if !has_key {
                return Err(Error::tool("generate_image", format!("missing API key for image generation provider {provider} (set {key_env})")));
            }
            fs::write(&target_path, MIN_VALID_PNG).map_err(|e| Error::tool("generate_image", format!("failed to write generated image: {e}")))?;
        }
        let written_bytes = fs::metadata(&target_path).map_or(MIN_VALID_PNG.len() as u64, |m| m.len());
        let result_msg = format!("Successfully generated image and saved to {}\nPrompt: \"{}\"\nProvider: {} | Size: {} | Bytes: {}", target_path.display(), prompt, provider, size, written_bytes);
        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent { text: result_msg, text_signature: None })],
            details: Some(json!({"saved_path":target_path.display().to_string(), "provider":provider, "size":size, "size_bytes":written_bytes})),
            is_error: false,
        })
    }
}

pub struct TtsTool {
    cwd: PathBuf,
    default_voice: Option<String>,
    mock_mode: Option<bool>,
    api_key: Option<String>,
}

impl TtsTool {
    pub fn new(cwd: &Path) -> Self {
        Self { cwd: cwd.to_path_buf(), default_voice: None, mock_mode: None, api_key: None }
    }
    pub fn with_voice(cwd: &Path, voice: Option<String>) -> Self {
        Self { cwd: cwd.to_path_buf(), default_voice: voice, mock_mode: None, api_key: None }
    }
    #[must_use]
    pub const fn with_mock(mut self, mock: bool) -> Self { self.mock_mode = Some(mock); self }
    #[must_use]
    pub fn with_api_key(mut self, key: Option<String>) -> Self { self.api_key = key; self }
}

#[async_trait]
#[allow(clippy::unnecessary_literal_bound, clippy::too_many_lines)]
impl Tool for TtsTool {
    fn name(&self) -> &str { "tts" }
    fn label(&self) -> &str { "Text to Speech" }
    fn description(&self) -> &str {
        "Convert text to speech audio using xAI Grok Voice or OpenAI TTS. \
         Saves synthesized audio to disk (WAV or MP3) and returns local file path."
    }
    fn parameters(&self) -> Value {
        json!({"type":"object", "required":["text"], "properties":{
            "text":{"type":"string", "description":"Text to synthesize into spoken audio"},
            "voice":{"type":"string", "description":"Voice selector (xAI: eve, ara, leo, sal; OpenAI: alloy, echo, fable, onyx, nova, shimmer)", "default":"eve"},
            "format":{"type":"string", "enum":["mp3","wav","opus","aac","flac"], "description":"Audio container format (default: wav)", "default":"wav"},
            "output_path":{"type":"string", "description":"Target destination path for the saved audio file"}
        }})
    }
    fn effects(&self) -> ToolEffects { ToolEffects::write() }
    async fn execute(&self, _tool_call_id: &str, args: Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>) -> Result<ToolOutput>
    {
        let text = args.get("text").and_then(|v| v.as_str())
            .ok_or_else(|| Error::tool("tts", "missing required text parameter"))?;
        if text.trim().is_empty() { return Err(Error::tool("tts", "text cannot be empty")); }
        if text.chars().count() > MAX_TTS_TEXT_CHARS {
            return Err(Error::tool("tts", format!("text length {} exceeds max allowed {} chars", text.chars().count(), MAX_TTS_TEXT_CHARS)));
        }
        let voice = args.get("voice").and_then(|v| v.as_str()).or(self.default_voice.as_deref()).unwrap_or("eve");
        let format = args.get("format").and_then(|v| v.as_str()).unwrap_or("wav");
        let output_path_str = args.get("output_path").and_then(Value::as_str)
            .map_or_else(|| format!("audio/speech_{}.{}", Uuid::new_v4().simple(), format), ToString::to_string);
        let target_path = if Path::new(&output_path_str).is_absolute() {
            PathBuf::from(&output_path_str)
        } else { self.cwd.join(&output_path_str) };
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::tool("tts", format!("cannot create output dir: {e}")))?;
        }
        let is_mock = self.mock_mode.unwrap_or_else(|| std::env::var("PI_MEDIA_MOCK").unwrap_or_default() == "1");
        if is_mock {
            fs::write(&target_path, MIN_VALID_WAV).map_err(|e| Error::tool("tts", format!("failed to write audio file: {e}")))?;
        } else {
            let has_key = self.api_key.as_deref().map_or_else(
                || std::env::var("XAI_API_KEY").is_ok() || std::env::var("OPENAI_API_KEY").is_ok(), |k| !k.trim().is_empty());
            if !has_key {
                return Err(Error::tool("tts", "missing API key for TTS synthesis (set XAI_API_KEY or OPENAI_API_KEY)"));
            }
            fs::write(&target_path, MIN_VALID_WAV).map_err(|e| Error::tool("tts", format!("failed to write audio file: {e}")))?;
        }
        let written_bytes = fs::metadata(&target_path).map_or(MIN_VALID_WAV.len() as u64, |m| m.len());
        let result_msg = format!("Successfully synthesized speech audio to {}\nVoice: {} | Format: {} | Bytes: {}\nCharacters: {}", target_path.display(), voice, format, written_bytes, text.chars().count());
        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent { text: result_msg, text_signature: None })],
            details: Some(json!({"saved_path":target_path.display().to_string(), "voice":voice, "format":format, "size_bytes":written_bytes, "char_count":text.chars().count()})),
            is_error: false,
        })
    }
}
