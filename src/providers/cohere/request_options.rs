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
        UserContent::Blocks(blocks)
            if blocks.iter().any(|block| matches!(block, ContentBlock::Image(_))) =>
        {
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
        model.strip_prefix(*prefix)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('-'))
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

fn decoded_image_size(encoded: &str, remaining: u64) -> Result<u64> {
    if encoded.is_empty()
        || u64::try_from(encoded.len()).unwrap_or(u64::MAX) > remaining.div_ceil(3).saturating_mul(4)
    {
        return Err(Error::provider("cohere", "Empty image or image data exceeds the 20 MB request limit"));
    }
    // Validate all base64 with a fixed-size I/O buffer, not a second full
    // decoded copy of every attachment. Read one extra byte to enforce limits.
    let mut decoder = base64::read::DecoderReader::new(
        encoded.as_bytes(), &base64::engine::general_purpose::STANDARD,
    ).take(remaining.saturating_add(1));
    let size = std::io::copy(&mut decoder, &mut std::io::sink())
        .map_err(|_| Error::provider("cohere", "Image data is not valid base64"))?;
    if size == 0 || size > remaining {
        return Err(Error::provider("cohere", "Empty image or image data exceeds the 20 MB request limit"));
    }
    Ok(size)
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
                decoded_total = decoded_total.saturating_add(decoded_image_size(encoded, remaining)?);
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
        assert!(thinking("command-a-reasoningish", &options).is_none());
    }

    #[test]
    fn custom_budgets_fit_the_hard_output_cap() {
        let options = StreamOptions {
            thinking_level: Some(ThinkingLevel::High), max_tokens: Some(5000),
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

    #[test]
    fn decoded_byte_limit_checks_padding_and_one_byte_overflow() {
        assert_eq!(decoded_image_size("AAEC", 3).unwrap(), 3);
        assert!(decoded_image_size("AAEC", 2).is_err());
        assert_eq!(decoded_image_size("AAE=", 2).unwrap(), 2);
        assert_eq!(decoded_image_size("AA==", 1).unwrap(), 1);
        assert!(decoded_image_size("AA==", 0).is_err());
        assert!(decoded_image_size("AA=!", 3).is_err());
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::model::{ImageContent, Message, StopReason, StreamEvent, TextContent, ToolResultMessage, UserMessage};
    use crate::provider::{BeforeProviderRequestHook, Context, Provider, ToolDef};
    use crate::providers::cohere::CohereProvider;
    use futures::StreamExt as _;
    use std::collections::HashMap;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, mpsc};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jf9sAAAAASUVORK5CYII=";

    struct Reply {
        status: u16,
        content_type: &'static str,
        chunks: Vec<String>,
        after_first: Option<mpsc::Receiver<()>>,
    }

    impl Reply {
        fn events(events: &[Value]) -> Self {
            Self { status: 200, content_type: "text/event-stream", chunks: vec![sse(events)], after_first: None }
        }
    }

    #[derive(Debug)]
    struct Request {
        headers: HashMap<String, String>,
        body: Value,
    }

    fn read_request(socket: &mut TcpStream) -> Request {
        socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut bytes = Vec::new();
        let boundary = loop {
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(bytes.len() < 64 * 1024);
            let mut chunk = [0; 4096];
            let count = socket.read(&mut chunk).expect("request headers");
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
        };
        let text = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
        let headers: HashMap<String, String> = text.lines().skip(1).filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.to_ascii_lowercase(), value.trim().to_string()))
        }).collect();
        let length = headers.get("content-length").map_or(0, |value| value.parse::<usize>().unwrap());
        assert!(length < 1024 * 1024);
        while bytes.len() - boundary < length {
            let mut chunk = [0; 4096];
            let count = socket.read(&mut chunk).expect("request body");
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        Request { headers, body: serde_json::from_slice(&bytes[boundary..boundary + length]).unwrap() }
    }

    struct Server {
        url: String,
        stop: Arc<AtomicBool>,
        requests: mpsc::Receiver<Request>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Server {
        fn new(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}/v2/chat", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = Arc::clone(&stop);
            let (tx, requests) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                for reply in replies {
                    let deadline = Instant::now() + Duration::from_secs(15);
                    let mut socket = loop {
                        if stopping.load(Ordering::Relaxed) || Instant::now() >= deadline { return; }
                        match listener.accept() {
                            Ok((socket, _)) => break socket,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
                            Err(error) => panic!("accept: {error}"),
                        }
                    };
                    tx.send(read_request(&mut socket)).unwrap();
                    let length: usize = reply.chunks.iter().map(String::len).sum();
                    write!(socket, "HTTP/1.1 {} Fixture\r\nContent-Type: {}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n", reply.status, reply.content_type).unwrap();
                    for (index, chunk) in reply.chunks.iter().enumerate() {
                        socket.write_all(chunk.as_bytes()).unwrap();
                        socket.flush().unwrap();
                        if index == 0 && let Some(gate) = &reply.after_first {
                            gate.recv_timeout(Duration::from_secs(10)).expect("client must see a delta before the server sends completion");
                        }
                    }
                }
            });
            Self { url, stop, requests, thread: Some(thread) }
        }

        fn finish(mut self) -> Vec<Request> {
            self.stop.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().expect("server completed");
            self.requests.try_iter().collect()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        }
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 8).build().expect("runtime").block_on(future)
    }

    fn sse(events: &[Value]) -> String {
        events.iter().map(|event| format!("data: {event}\n\n")).collect()
    }

    fn start() -> Value { json!({"type":"message-start"}) }
    fn done(reason: &str) -> Value {
        json!({"type":"message-end","delta":{"finish_reason":reason,"usage":{"tokens":{"input_tokens":12,"output_tokens":4}}}})
    }
    fn open_text() -> Value {
        json!({"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}})
    }
    fn text_delta() -> Value {
        json!({"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"first"}}}})
    }
    fn close_text() -> Value { json!({"type":"content-end","index":0}) }
    fn call_start(index: u32, id: &str) -> Value {
        json!({"type":"tool-call-start","index":index,"delta":{"message":{"tool_calls":{"id":id,"function":{"name":"read","arguments":"{\"path\":"}}}}})
    }
    fn call_delta(index: u32, value: &str) -> Value {
        json!({"type":"tool-call-delta","index":index,"delta":{"message":{"tool_calls":{"function":{"arguments":value}}}}})
    }
    fn image() -> ContentBlock {
        ContentBlock::Image(ImageContent { data: PNG.to_string(), mime_type: "image/png".to_string() })
    }
    fn context() -> Context<'static> {
        Context::owned(None, vec![Message::User(UserMessage {
            content: UserContent::Blocks(vec![ContentBlock::Text(TextContent::new("Inspect")), image()]), timestamp: 0,
        })], vec![ToolDef { name: "read".to_string(), description: "read a file".to_string(), parameters: json!({"type":"object","properties":{"path":{"type":"string"}}}) }])
    }
    fn options() -> StreamOptions {
        StreamOptions { api_key: Some("cohere-http-test-key".to_string()), ..StreamOptions::default() }
    }

    #[test]
    fn public_provider_sends_images_thinking_and_the_accepted_hook_rewrite() {
        let server = Server::new(vec![Reply::events(&[start(), done("COMPLETE")])]);
        let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
        let context = context();
        let original = serde_json::to_value(context.messages.as_ref()).unwrap();
        let mut options = options();
        options.max_tokens = Some(8192);
        options.thinking_level = Some(ThinkingLevel::High);
        options.before_provider_request = Some(BeforeProviderRequestHook::new(|mut event| {
            assert_eq!(event.payload["thinking"]["type"], "enabled");
            assert!(event.payload["messages"][0]["content"][1]["image_url"]["url"].as_str().unwrap().starts_with("data:image/png;base64,"));
            event.payload["thinking"]["token_budget"] = json!(100);
            Box::pin(futures::future::ready(Some(event.payload)))
        }));
        let events = run(async { provider.stream(&context, &options).await.unwrap().take(32).collect::<Vec<_>>().await });
        assert!(events.iter().all(Result::is_ok));
        assert!(matches!(events.last(), Some(Ok(StreamEvent::Done { .. }))));
        assert_eq!(serde_json::to_value(context.messages.as_ref()).unwrap(), original);
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].headers["authorization"], "Bearer cohere-http-test-key");
        assert_eq!(requests[0].body["thinking"]["token_budget"], 100);
        assert_eq!(requests[0].body["max_tokens"], 8192);
        assert_eq!(requests[0].body["messages"][0]["content"][1]["image_url"]["url"], format!("data:image/png;base64,{PNG}"));
    }

    #[test]
    fn request_hook_can_remove_invalid_images_before_final_payload_validation() {
        let server = Server::new(vec![Reply::events(&[start(), done("COMPLETE")])]);
        let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
        let context = Context::owned(None, vec![Message::User(UserMessage {
            content: UserContent::Blocks(vec![ContentBlock::Image(ImageContent { data: "not-base64!".into(), mime_type: "image/png".into() })]), timestamp: 0,
        })], Vec::new());
        let options = StreamOptions {
            before_provider_request: Some(BeforeProviderRequestHook::new(|mut event| {
                event.payload["messages"][0]["content"] = json!("image intentionally removed");
                Box::pin(futures::future::ready(Some(event.payload)))
            })), ..options()
        };
        run(async { provider.stream(&context, &options).await.unwrap().take(32).collect::<Vec<_>>().await });
        assert_eq!(server.finish()[0].body["messages"][0]["content"], "image intentionally removed");
    }

    #[test]
    fn rejected_hook_keeps_native_images_and_thinking_disabled() {
        let server = Server::new(vec![Reply::events(&[start(), done("COMPLETE")])]);
        let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
        let context = context();
        let options = StreamOptions {
            thinking_level: Some(ThinkingLevel::Off),
            before_provider_request: Some(BeforeProviderRequestHook::new(|_| Box::pin(futures::future::ready(Some(json!({"invalid":true})))))),
            ..options()
        };
        run(async { provider.stream(&context, &options).await.unwrap().take(32).collect::<Vec<_>>().await });
        let requests = server.finish();
        assert_eq!(requests[0].body["thinking"], json!({"type":"disabled"}));
        assert!(requests[0].body["messages"][0]["content"][1]["image_url"].is_object());
    }

    #[test]
    fn first_text_delta_arrives_before_the_server_releases_completion() {
        let (resume, gate) = mpsc::channel();
        let server = Server::new(vec![Reply {
            status: 200, content_type: "text/event-stream; charset=utf-8",
            chunks: vec![sse(&[start(), open_text(), text_delta()]), sse(&[close_text(), done("COMPLETE")])],
            after_first: Some(gate),
        }]);
        let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
        let context = context();
        let options = options();
        run(async {
            let mut stream = provider.stream(&context, &options).await.unwrap();
            let mut saw_delta = false;
            for _ in 0..16 {
                let Some(event) = stream.next().await else { break; };
                match event.unwrap() {
                    StreamEvent::TextDelta { delta, .. } => {
                        assert_eq!(delta, "first");
                        saw_delta = true;
                        resume.send(()).unwrap();
                    }
                    StreamEvent::Done { .. } => { assert!(saw_delta); break; }
                    _ => {}
                }
            }
            assert!(saw_delta);
            assert!(stream.next().await.is_none());
            assert!(stream.next().await.is_none());
        });
        assert_eq!(server.finish().len(), 1);
    }

    #[test]
    fn interleaved_tool_calls_survive_session_roundtrip_and_image_results() {
        let server = Server::new(vec![
            Reply::events(&[
                start(), call_start(2, "a"), call_start(19, "b"),
                call_delta(19, "\"b.png\"}"), json!({"type":"tool-call-end","index":19}),
                call_delta(2, "\"a.png\"}"), json!({"type":"tool-call-end","index":2}), done("TOOL_CALL"),
            ]),
            Reply::events(&[start(), open_text(), text_delta(), close_text(), done("COMPLETE")]),
        ]);
        let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
        let mut context = context();
        let options = options();
        run(async {
            let events = provider.stream(&context, &options).await.unwrap().take(32).collect::<Vec<_>>().await;
            assert!(events.iter().all(Result::is_ok));
            let Some(Ok(StreamEvent::Done { reason, message })) = events.last() else { panic!("tool completion"); };
            assert_eq!(*reason, StopReason::ToolUse);
            let stored = serde_json::to_string(&Message::assistant(message.clone())).unwrap();
            let replay: Message = serde_json::from_str(&stored).unwrap();
            let mut history = context.messages.into_owned();
            history.push(replay);
            for block in &message.content {
                if let ContentBlock::ToolCall(call) = block {
                    history.push(Message::tool_result(ToolResultMessage {
                        tool_call_id: call.id.clone(), tool_name: call.name.clone(),
                        content: vec![ContentBlock::Text(TextContent::new("screenshot")), image()],
                        details: None, is_error: false, timestamp: 1,
                    }));
                }
            }
            context = Context::owned(None, history, Vec::new());
            let final_events = provider.stream(&context, &options).await.unwrap().take(32).collect::<Vec<_>>().await;
            assert!(matches!(final_events.last(), Some(Ok(StreamEvent::Done { reason: StopReason::Stop, .. }))));
        });
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        let messages = requests[1].body["messages"].as_array().unwrap();
        assert_eq!(messages.iter().map(|m| m["role"].as_str().unwrap()).collect::<Vec<_>>(), vec!["user", "assistant", "tool", "tool", "user"]);
        let calls = messages[1]["tool_calls"].as_array().unwrap();
        assert_eq!(calls[0]["id"], "a");
        assert_eq!(calls[1]["id"], "b");
        assert_eq!(serde_json::from_str::<Value>(calls[0]["function"]["arguments"].as_str().unwrap()).unwrap()["path"], "a.png");
        assert_eq!(serde_json::from_str::<Value>(calls[1]["function"]["arguments"].as_str().unwrap()).unwrap()["path"], "b.png");
        assert_eq!(messages[2]["tool_call_id"], "a");
        assert_eq!(messages[3]["tool_call_id"], "b");
        let images = messages[4]["content"].as_array().unwrap().iter().filter(|p| p["type"] == "image_url").collect::<Vec<_>>();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0]["image_url"]["url"], format!("data:image/png;base64,{PNG}"));
    }

    #[test]
    fn truncated_and_invalid_tool_streams_emit_one_error_without_done() {
        for events in [
            vec![start(), open_text(), text_delta()],
            vec![start(), call_start(0, "a"), json!({"type":"tool-call-end","index":0}), done("TOOL_CALL")],
        ] {
            let server = Server::new(vec![Reply::events(&events)]);
            let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
            let context = context();
            let options = options();
            let events = run(async { provider.stream(&context, &options).await.unwrap().take(32).collect::<Vec<_>>().await });
            assert_eq!(events.iter().filter(|event| event.is_err()).count(), 1);
            assert!(events.last().unwrap().is_err());
            assert!(!events.iter().any(|event| matches!(event, Ok(StreamEvent::Done { .. }))));
            assert_eq!(server.finish().len(), 1);
        }
    }

    #[test]
    fn terminal_failure_and_length_are_not_successful_tool_turns() {
        for (finish, expected) in [("ERROR", StopReason::Error), ("MAX_TOKENS", StopReason::Length)] {
            let server = Server::new(vec![Reply::events(&[start(), done(finish)])]);
            let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
            let context = context();
            let options = options();
            let events = run(async { provider.stream(&context, &options).await.unwrap().take(32).collect::<Vec<_>>().await });
            let Some(Ok(StreamEvent::Done { reason, message })) = events.last() else { panic!("terminal event"); };
            assert_eq!(*reason, expected);
            assert_eq!(message.stop_reason, expected);
            assert_eq!(server.finish().len(), 1);
        }
    }

    #[test]
    fn http_failures_redact_credentials_and_json_success_is_not_an_sse_stream() {
        for reply in [
            Reply { status: 500, content_type: "text/plain", chunks: vec!["echo cohere-http-test-key".to_string()], after_first: None },
            Reply { status: 200, content_type: "application/json", chunks: vec!["{}".to_string()], after_first: None },
        ] {
            let server = Server::new(vec![reply]);
            let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url(&server.url);
            let context = context();
            let options = options();
            let error = run(async { provider.stream(&context, &options).await.err().expect("request rejected") }).to_string();
            assert!(!error.contains("cohere-http-test-key"));
            assert!(error.contains("HTTP 500") || error.contains("text/event-stream"));
            assert_eq!(server.finish().len(), 1);
        }
    }

    #[test]
    fn impossible_thinking_budget_fails_before_the_request_hook_or_endpoint() {
        let provider = CohereProvider::new("command-a-plus-05-2026").with_base_url("not a URL");
        let context = context();
        let options = StreamOptions {
            max_tokens: Some(1), thinking_level: Some(ThinkingLevel::High),
            before_provider_request: Some(BeforeProviderRequestHook::new(|_| panic!("must fail before request hook"))),
            ..options()
        };
        let error = run(async { provider.stream(&context, &options).await.err().expect("invalid budget") }).to_string();
        assert!(error.contains("max_tokens"));
    }
}
