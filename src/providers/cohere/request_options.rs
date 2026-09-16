//! Native Cohere image inputs and model-specific thinking controls.
//!
//! https://docs.cohere.com/docs/image-inputs
//! https://docs.cohere.com/docs/reasoning
//! https://docs.cohere.com/docs/command-a-plus

use crate::error::{Error, Result};
use crate::model::{ContentBlock, ThinkingLevel, UserContent};
use crate::provider::StreamOptions;
use serde::Serialize;
use serde_json::{Value, json};
use std::io::Read as _;

const DEFAULT_MAX_TOKENS: u32 = super::DEFAULT_MAX_TOKENS;
const ANSWER_RESERVE: u32 = 1024;
const MAX_IMAGES: usize = 20;
const MAX_IMAGE_BYTES: u64 = 20_000_000;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(super) enum InputContent {
    Text(String),
    Parts(Vec<Value>),
}

pub(super) fn user_content(content: &UserContent) -> InputContent {
    match content {
        UserContent::Text(text) => InputContent::Text(text.clone()),
        UserContent::Blocks(blocks) if blocks.iter().any(|block| matches!(block, ContentBlock::Image(_))) => {
            let parts = blocks.iter().filter_map(|block| match block {
                ContentBlock::Text(text) => Some(json!({"type":"text","text":text.text})),
                ContentBlock::Image(image) => Some(image_part(image)),
                ContentBlock::Media(media) => Some(json!({"type":"text","text":media.placeholder()})),
                _ => None,
            }).collect();
            InputContent::Parts(parts)
        }
        _ => InputContent::Text(super::extract_text_user_content(content)),
    }
}

fn image_part(image: &crate::model::ImageContent) -> Value {
    let mime = if image.mime_type.eq_ignore_ascii_case("image/jpg") {
        "image/jpeg".to_string()
    } else {
        image.mime_type.to_ascii_lowercase()
    };
    json!({"type":"image_url","image_url":{
        "url":format!("data:{mime};base64,{}", image.data)
    }})
}

pub(super) fn tool_images(content: &[ContentBlock]) -> Vec<Value> {
    content.iter().filter_map(|block| match block {
        ContentBlock::Image(image) => Some(image_part(image)),
        _ => None,
    }).collect()
}

fn reasoning_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    ["command-a-reasoning", "command-a-plus"].iter().any(|prefix| {
        model.strip_prefix(prefix).is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('-'))
    })
}

#[derive(Debug, Serialize)]
pub(super) struct Thinking {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_budget: Option<u32>,
}

fn budget(level: ThinkingLevel, options: &StreamOptions) -> u32 {
    options.thinking_budgets.as_ref().map_or_else(|| level.default_budget(), |budgets| {
        match level {
            ThinkingLevel::Off => 0,
            ThinkingLevel::Minimal => budgets.minimal,
            ThinkingLevel::Low => budgets.low,
            ThinkingLevel::Medium => budgets.medium,
            ThinkingLevel::High => budgets.high,
            ThinkingLevel::XHigh => budgets.xhigh,
            ThinkingLevel::Max => budgets.max,
        }
    })
}

pub(super) fn thinking(model: &str, options: &StreamOptions) -> Option<Thinking> {
    if !reasoning_model(model) {
        return None;
    }
    let level = options.thinking_level?;
    if level == ThinkingLevel::Off {
        return Some(Thinking { kind: "disabled", token_budget: None });
    }
    let max_tokens = options.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
    // Preserve the caller's hard cap. Reserve 1K answer tokens where possible,
    // but allow tiny explicitly capped requests with at least one answer token.
    let available = max_tokens.saturating_sub(ANSWER_RESERVE).max(1)
        .min(max_tokens.saturating_sub(1));
    Some(Thinking {
        kind: "enabled",
        token_budget: Some(budget(level, options).max(1).min(available)),
    })
}

pub(super) fn validate_options(model: &str, options: &StreamOptions) -> Result<()> {
    if options.max_tokens == Some(0) {
        return Err(Error::provider("cohere", "max_tokens must be positive"));
    }
    if reasoning_model(model)
        && options.thinking_level.is_some_and(|level| level != ThinkingLevel::Off)
        && options.max_tokens.is_some_and(|limit| limit < 2)
    {
        return Err(Error::provider("cohere", "Enabled thinking requires max_tokens of at least 2"));
    }
    Ok(())
}

/// Check the final, possibly rewritten outbound payload. Inspect only actual
/// message image parts, never similarly named fields inside tool arguments.
/// This lets request hooks remove/replace images before limits are enforced.
pub(super) fn validate_images(body: &Value) -> Result<()> {
    let mut count = 0_usize;
    let mut decoded_total = 0_u64;
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return Ok(()); // The request rewrite validator owns required fields.
    };
    for message in messages {
        let Some(parts) = message.get("content").and_then(Value::as_array) else { continue; };
        for part in parts {
            if part.get("type").and_then(Value::as_str) != Some("image_url") {
                continue;
            }
            count += 1;
            if count > MAX_IMAGES {
                return Err(Error::provider("cohere", "Cohere accepts at most 20 images per request"));
            }
            let url = part.pointer("/image_url/url").and_then(Value::as_str)
                .ok_or_else(|| Error::provider("cohere", "Image input requires a URL string"))?;
            if let Some(data) = url.strip_prefix("data:") {
                let (mime, encoded) = data.split_once(";base64,")
                    .ok_or_else(|| Error::provider("cohere", "Invalid base64 image data URL"))?;
                if !matches!(mime, "image/png" | "image/jpeg" | "image/webp" | "image/gif") {
                    return Err(Error::provider("cohere", "Unsupported image MIME type; use PNG, JPEG, WEBP or GIF"));
                }
                let remaining = MAX_IMAGE_BYTES.saturating_sub(decoded_total);
                if encoded.is_empty() || u64::try_from(encoded.len()).unwrap_or(u64::MAX) > remaining.div_ceil(3).saturating_mul(4) {
                    return Err(Error::provider("cohere", "Empty image or image data exceeds the 20 MB request limit"));
                }
                // Validate the entire base64 stream with a fixed-size I/O buffer,
                // not a second full decoded copy of every attachment.
                let mut decoder = base64::read::DecoderReader::new(
                    encoded.as_bytes(),
                    &base64::engine::general_purpose::STANDARD,
                ).take(remaining.saturating_add(1));
                let size = std::io::copy(&mut decoder, &mut std::io::sink())
                    .map_err(|_| Error::provider("cohere", "Image data is not valid base64"))?;
                if size == 0 || size > remaining {
                    return Err(Error::provider("cohere", "Empty image or image data exceeds the 20 MB request limit"));
                }
                decoded_total = decoded_total.saturating_add(size);
            } else {
                // Hooks may intentionally choose Cohere's native URL image path.
                // Pi never downloads these URLs or attaches credentials to them.
                let parsed = url::Url::parse(url)
                    .map_err(|_| Error::provider("cohere", "Invalid image URL"))?;
                if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
                    return Err(Error::provider("cohere", "Image URL must use HTTP(S) or a base64 data URL"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ImageContent, TextContent};
    use crate::provider::ThinkingBudgets;

    fn image(mime: &str, data: &str) -> ContentBlock {
        ContentBlock::Image(ImageContent { mime_type: mime.to_string(), data: data.to_string() })
    }

    #[test]
    fn mixed_inputs_preserve_order_and_actual_image_bytes() {
        let original = UserContent::Blocks(vec![
            ContentBlock::Text(TextContent::new("before")), image("image/png", "AAECAw=="),
            ContentBlock::Text(TextContent::new("after")),
        ]);
        let value = serde_json::to_value(user_content(&original)).unwrap();
        assert_eq!(value[0], json!({"type":"text","text":"before"}));
        assert_eq!(value[1]["image_url"]["url"], "data:image/png;base64,AAECAw==");
        assert_eq!(value[2]["text"], "after");
        assert!(matches!(&original, UserContent::Blocks(blocks) if matches!(&blocks[1], ContentBlock::Image(image) if image.data == "AAECAw==")));
    }

    #[test]
    fn text_only_wire_shape_remains_a_string() {
        assert_eq!(serde_json::to_value(user_content(&UserContent::Text("hello".into()))).unwrap(), "hello");
        assert_eq!(serde_json::to_value(user_content(&UserContent::Blocks(vec![
            ContentBlock::Text(TextContent::new("one")), ContentBlock::Text(TextContent::new("two")),
        ]))).unwrap(), "onetwo");
    }

    #[test]
    fn tool_images_use_the_same_payload_and_normalize_jpg() {
        let images = tool_images(&[ContentBlock::Text(TextContent::new("result")), image("IMAGE/JPG", "YQ==")]);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0]["image_url"]["url"], "data:image/jpeg;base64,YQ==");
    }

    #[test]
    fn reasoning_default_off_and_enabled_are_distinct() {
        let mut options = StreamOptions::default();
        assert!(thinking("command-a-reasoning-08-2025", &options).is_none());
        options.thinking_level = Some(ThinkingLevel::Off);
        assert_eq!(serde_json::to_value(thinking("command-a-plus-05-2026", &options)).unwrap(), json!({"type":"disabled"}));
        options.thinking_level = Some(ThinkingLevel::High);
        let value = serde_json::to_value(thinking("command-a-plus-05-2026", &options)).unwrap();
        assert_eq!(value["type"], "enabled");
        assert_eq!(value["token_budget"], 3072);
        assert!(thinking("command-r", &options).is_none());
        assert!(thinking("command-a-plus-imposter".trim_end_matches("-imposter").trim_end_matches("plus"), &options).is_none());
    }

    #[test]
    fn custom_budgets_fit_the_hard_output_cap() {
        let options = StreamOptions {
            thinking_level: Some(ThinkingLevel::High),
            max_tokens: Some(5000),
            thinking_budgets: Some(ThinkingBudgets { high: 2000, ..ThinkingBudgets::default() }),
            ..StreamOptions::default()
        };
        let value = serde_json::to_value(thinking("command-a-reasoning-08-2025", &options)).unwrap();
        assert_eq!(value["token_budget"], 2000);
        assert_eq!(options.max_tokens, Some(5000));
        let small = StreamOptions { max_tokens: Some(2), ..options };
        assert_eq!(serde_json::to_value(thinking("command-a-reasoning-08-2025", &small)).unwrap()["token_budget"], 1);
        assert!(validate_options("command-a-reasoning-08-2025", &small).is_ok());
    }

    #[test]
    fn impossible_caps_fail_before_network_dispatch() {
        for cap in [0, 1] {
            let options = StreamOptions { thinking_level: Some(ThinkingLevel::High), max_tokens: Some(cap), ..StreamOptions::default() };
            assert!(validate_options("command-a-plus-05-2026", &options).is_err());
        }
        let off = StreamOptions { thinking_level: Some(ThinkingLevel::Off), max_tokens: Some(1), ..StreamOptions::default() };
        assert!(validate_options("command-a-plus-05-2026", &off).is_ok());
    }

    #[test]
    fn final_payload_rejects_bad_images_without_echoing_the_payload() {
        for url in ["data:image/png;base64,secret!", "data:image/svg+xml;base64,YQ==", "file:///secret", "data:image/png;base64,"] {
            let body = json!({"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":url}}]}]});
            let error = validate_images(&body).unwrap_err().to_string();
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn image_count_applies_across_turns_not_to_function_arguments() {
        let part = json!({"type":"image_url","image_url":{"url":"data:image/png;base64,YQ=="}});
        let mut body = json!({"messages":[{"role":"user","content":vec![part.clone(); MAX_IMAGES]}]});
        assert!(validate_images(&body).is_ok());
        body["messages"].as_array_mut().unwrap().push(json!({"role":"user","content":[part.clone()]}));
        assert!(validate_images(&body).is_err());
        let arguments = json!({"messages":[{"role":"assistant","tool_calls":[{"function":{"arguments":vec![part; MAX_IMAGES + 1]}}]}]});
        assert!(validate_images(&arguments).is_ok());
    }

    #[test]
    fn intentional_remote_image_urls_do_not_require_local_downloads() {
        let body = json!({"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://images.example.invalid/chart.png"}}]}]});
        assert!(validate_images(&body).is_ok());
    }
}
