//! Wire-level Bedrock tests: use the public provider and real loopback HTTP.
#![recursion_limit = "256"]

use asupersync::runtime::RuntimeBuilder;
use futures::StreamExt as _;
use pi::model::{
    AssistantMessage, ContentBlock, Message, RedactedThinkingContent, StopReason,
    StreamEvent, TextContent, ThinkingContent, ToolResultMessage, UserContent, UserMessage,
};
use pi::provider::{BeforeProviderRequestHook, Context, Provider, StreamOptions, ToolDef};
use pi::providers::bedrock::BedrockProvider;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const EVENT_STREAM: &str = "application/vnd.amazon.eventstream";
const TOKEN: &str = "bedrock-wire-credential-canary";

// Independent bitwise encoder, rather than calling the production CRC routine.
fn fixture_crc(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 { crc >> 1 } else { (crc >> 1) ^ 0xedb8_8320 };
        }
    }
    !crc
}

fn frame(headers: &[(&str, &str)], payload: &Value) -> Vec<u8> {
    let mut encoded_headers = Vec::new();
    for (name, value) in headers {
        encoded_headers.push(u8::try_from(name.len()).unwrap());
        encoded_headers.extend_from_slice(name.as_bytes());
        encoded_headers.push(7);
        encoded_headers.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        encoded_headers.extend_from_slice(value.as_bytes());
    }
    let payload = serde_json::to_vec(payload).unwrap();
    let mut output = Vec::new();
    output.extend_from_slice(
        &u32::try_from(16 + encoded_headers.len() + payload.len()).unwrap().to_be_bytes(),
    );
    output.extend_from_slice(&u32::try_from(encoded_headers.len()).unwrap().to_be_bytes());
    output.extend_from_slice(&fixture_crc(&output).to_be_bytes());
    output.extend_from_slice(&encoded_headers);
    output.extend_from_slice(&payload);
    output.extend_from_slice(&fixture_crc(&output).to_be_bytes());
    output
}

fn event(kind: &str, payload: Value) -> Vec<u8> {
    frame(
        &[(":message-type", "event"), (":event-type", kind), (":content-type", "application/json")],
        &payload,
    )
}

fn start() -> Vec<u8> {
    event("messageStart", json!({"role": "assistant"}))
}

fn text(index: u64, value: &str) -> Vec<u8> {
    event("contentBlockDelta", json!({"contentBlockIndex": index, "delta": {"text": value}}))
}

fn block_stop(index: u64) -> Vec<u8> {
    event("contentBlockStop", json!({"contentBlockIndex": index}))
}

fn message_stop(reason: &str) -> Vec<u8> {
    event("messageStop", json!({"stopReason": reason}))
}

fn complete_text() -> Vec<u8> {
    [start(), text(0, "ok"), block_stop(0), message_stop("end_turn")].concat()
}

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

fn read_request(socket: &mut TcpStream) -> CapturedRequest {
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut data = Vec::new();
    let header_end = loop {
        if let Some(index) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break index + 4;
        }
        assert!(data.len() < 64 * 1024, "bounded fixture headers");
        let mut buffer = [0; 4096];
        let count = socket.read(&mut buffer).expect("request header bytes");
        assert!(count > 0, "request closed before headers");
        data.extend_from_slice(&buffer[..count]);
    };
    let head = String::from_utf8(data[..header_end].to_vec()).unwrap();
    let mut lines = head.lines();
    let mut request_line = lines.next().unwrap().split_whitespace();
    let method = request_line.next().unwrap().to_string();
    let path = request_line.next().unwrap().to_string();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length = headers["content-length"].parse::<usize>().unwrap();
    assert!(length <= 1024 * 1024, "bounded fixture request body");
    while data.len() - header_end < length {
        let mut buffer = [0; 4096];
        let count = socket.read(&mut buffer).expect("request body bytes");
        assert!(count > 0, "request closed before body");
        data.extend_from_slice(&buffer[..count]);
    }
    CapturedRequest {
        method, path, headers,
        body: serde_json::from_slice(&data[header_end..header_end + length]).unwrap(),
    }
}

struct Server {
    base: String,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<CapturedRequest>>,
}

impl Server {
    fn new(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self::start(status, content_type, body, Vec::new(), None)
    }

    fn gated(prefix: Vec<u8>, tail: Vec<u8>) -> (Self, mpsc::Sender<()>) {
        let (tx, rx) = mpsc::channel();
        (
            Self::start(200, "Application/Vnd.Amazon.Eventstream; charset=binary", prefix, tail, Some(rx)),
            tx,
        )
    }

    fn start(
        status: u16,
        content_type: &'static str,
        prefix: Vec<u8>,
        tail: Vec<u8>,
        release: Option<mpsc::Receiver<()>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut socket = loop {
                assert!(!thread_stop.load(Ordering::Relaxed), "fixture cancelled before request");
                assert!(Instant::now() < deadline, "fixture request did not arrive");
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            let captured = read_request(&mut socket);
            write!(
                socket,
                "HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                prefix.len() + tail.len(),
            ).unwrap();
            socket.write_all(&prefix).unwrap();
            socket.flush().unwrap();
            if let Some(release) = release {
                // The client must observe an early delta before the server
                // sends the completion. This proves streaming without a
                // fragile elapsed-time performance assertion.
                release.recv_timeout(Duration::from_secs(10)).expect("client observed early delta");
            }
            socket.write_all(&tail).unwrap();
            captured
        });
        Self { base, stop, join: Some(join) }
    }

    fn finish(mut self) -> CapturedRequest {
        self.stop.store(true, Ordering::Relaxed);
        self.join.take().unwrap().join().expect("fixture completed")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    // This integration test is its own process. Let bounded OS socket/channel
    // guards police the fixtures instead of racing a virtual HTTP timer with
    // the native server thread. No timeout behavior is claimed by these tests.
    pi::http::client::set_request_timeout_override(0);
    RuntimeBuilder::current_thread().build().expect("runtime").block_on(future)
}

fn context() -> Context<'static> {
    Context::owned(
        Some("Be concise.".to_string()),
        vec![Message::User(UserMessage {
            content: UserContent::Text("Read a.txt".to_string()), timestamp: 0,
        })],
        vec![ToolDef {
            name: "read".to_string(), description: "Read a file".to_string(),
            parameters: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        }],
    )
}

fn options() -> StreamOptions {
    StreamOptions { api_key: Some(TOKEN.to_string()), ..StreamOptions::default() }
}

fn collect(server: &Server) -> Vec<pi::error::Result<StreamEvent>> {
    run(async {
        BedrockProvider::new("model-a")
            .with_base_url(&server.base)
            .stream(&context(), &options())
            .await.expect("stream opened")
            .collect().await
    })
}

#[test]
fn public_provider_delivers_text_before_server_sends_completion() {
    assert_eq!(fixture_crc(b"123456789"), 0xcbf4_3926);
    let prefix = [start(), text(0, "Hello ")].concat();
    let tail = [
        text(0, "world"), block_stop(0), message_stop("end_turn"),
        event("metadata", json!({"usage": {
            "inputTokens": 7, "outputTokens": 3, "totalTokens": 10,
            "cacheReadInputTokens": 2, "cacheWriteInputTokens": 1
        }})),
    ].concat();
    let (server, release) = Server::gated(prefix, tail);
    let events = run(async {
        let provider = BedrockProvider::new("model-a")
            .with_base_url(format!("{}/", server.base))
            .with_provider_name("custom-bedrock");
        let mut output = provider.stream(&context(), &options()).await.expect("stream opened");
        let mut result = Vec::new();
        let mut released = false;
        while let Some(item) = output.next().await {
            let item = item.expect("valid wire event");
            if matches!(&item, StreamEvent::TextDelta { delta, .. } if delta == "Hello ") {
                release.send(()).unwrap();
                released = true;
            }
            result.push(item);
        }
        assert!(released, "early delta must be observed");
        result
    });
    assert!(matches!(&events[0], StreamEvent::Start { partial } if partial.content.is_empty()));
    let Some(StreamEvent::Done { reason, message }) = events.last() else { panic!("{events:?}") };
    assert_eq!(*reason, StopReason::Stop);
    assert_eq!(message.provider, "custom-bedrock");
    assert_eq!(message.model, "model-a");
    let ContentBlock::Text(text) = &message.content[0] else { panic!() };
    assert_eq!(text.text, "Hello world");
    assert_eq!(message.usage.total_tokens, 10);
    assert_eq!(message.usage.cache_read, 2);
    assert_eq!(message.usage.cache_write, 1);
    let request = server.finish();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/model/model-a/converse-stream");
    assert_eq!(request.headers["accept"], EVENT_STREAM);
    assert_eq!(request.headers["authorization"], format!("Bearer {TOKEN}"));
    assert_eq!(request.body["messages"][0]["content"][0]["text"], "Read a.txt");
    assert_eq!(request.body["toolConfig"]["tools"][0]["toolSpec"]["name"], "read");
}

#[test]
fn signed_reasoning_and_tool_calls_survive_stream_session_and_replay() {
    let body = [
        start(),
        event("contentBlockDelta", json!({"contentBlockIndex": 0, "delta": {"reasoningContent": {"text": "  Plan.\n"}}})),
        event("contentBlockDelta", json!({"contentBlockIndex": 0, "delta": {"reasoningContent": {"signature": "opaque-signature"}}})),
        block_stop(0),
        event("contentBlockDelta", json!({"contentBlockIndex": 1, "delta": {"reasoningContent": {"redactedContent": "AA=="}}})),
        event("contentBlockDelta", json!({"contentBlockIndex": 1, "delta": {"reasoningContent": {"redactedContent": "AQ=="}}})),
        block_stop(1),
        event("contentBlockStart", json!({"contentBlockIndex": 2, "start": {"toolUse": {"toolUseId": "tool-a", "name": "read"}}})),
        event("contentBlockDelta", json!({"contentBlockIndex": 2, "delta": {"toolUse": {"input": "{\"path\":"}}})),
        event("contentBlockDelta", json!({"contentBlockIndex": 2, "delta": {"toolUse": {"input": "\"a.txt\"}"}}})),
        block_stop(2), message_stop("tool_use"),
    ].concat();
    let server = Server::new(200, EVENT_STREAM, body);
    let events = collect(&server);
    assert!(events.iter().all(Result::is_ok), "{events:?}");
    let Some(Ok(StreamEvent::Done { reason, message })) = events.last() else { panic!("{events:?}") };
    assert_eq!(*reason, StopReason::ToolUse);
    assert!(!events.iter().any(|event| matches!(event, Ok(StreamEvent::TextDelta { .. }))));
    let saved = serde_json::to_string(&Message::assistant(message.clone())).unwrap();
    let restored: Message = serde_json::from_str(&saved).unwrap();
    let mut replay = context();
    replay.messages.to_mut().push(restored);
    replay.messages.to_mut().push(Message::tool_result(ToolResultMessage {
        tool_call_id: "tool-a".to_string(), tool_name: "read".to_string(),
        content: vec![ContentBlock::Text(TextContent::new("file contents"))],
        details: None, is_error: false, timestamp: 1,
    }));
    let request = serde_json::to_value(BedrockProvider::build_request(&replay, &options())).unwrap();
    let blocks = request["messages"][1]["content"].as_array().unwrap();
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0], json!({"reasoningContent": {"reasoningText": {
        "text": "  Plan.\n", "signature": "opaque-signature"
    }}}));
    assert_eq!(blocks[1], json!({"reasoningContent": {"redactedContent": "AAE="}}));
    assert_eq!(blocks[2], json!({"toolUse": {"toolUseId": "tool-a", "name": "read", "input": {"path": "a.txt"}}}));
    assert_eq!(request["messages"][2]["content"][0]["toolResult"]["toolUseId"], "tool-a");
    server.finish();
}

#[test]
fn explicit_converse_endpoint_retains_json_and_reasoning_support() {
    let server = Server::new(200, "application/json", serde_json::to_vec(&json!({
        "output": {"message": {"role": "assistant", "content": [
            {"reasoningContent": {"reasoningText": {"text": "Think.", "signature": "signed"}}},
            {"reasoningContent": {"redactedContent": "AAE="}},
            {"text": "ok"}
        ]}},
        "stopReason": "end_turn", "usage": {"inputTokens": 1, "outputTokens": 2, "totalTokens": 3}
    })).unwrap());
    let events: Vec<_> = run(async {
        BedrockProvider::new("ignored")
            .with_base_url(format!("{}/model/custom/converse?route=test", server.base))
            .stream(&context(), &options()).await.unwrap().collect().await
    });
    assert!(events.iter().all(Result::is_ok));
    let Some(Ok(StreamEvent::Done { message, .. })) = events.last() else { panic!("{events:?}") };
    let ContentBlock::Thinking(thinking) = &message.content[0] else { panic!() };
    assert_eq!(thinking.thinking_signature.as_deref(), Some("signed"));
    assert!(matches!(&message.content[1], ContentBlock::RedactedThinking(redacted) if redacted.data == "AAE="));
    assert!(events.iter().any(|event| matches!(event, Ok(StreamEvent::ThinkingDelta { delta, .. }) if delta == "Think.")));
    let request = server.finish();
    assert_eq!(request.path, "/model/custom/converse?route=test");
    assert_eq!(request.headers["accept"], "application/json");
}

#[test]
fn truncated_and_corrupt_http_streams_never_emit_done() {
    let mut corrupt = text(0, "partial");
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    for body in [
        [start(), text(0, "partial")].concat(),
        [complete_text(), vec![0, 0, 0]].concat(),
        [start(), corrupt, message_stop("end_turn")].concat(),
    ] {
        let server = Server::new(200, EVENT_STREAM, body);
        let events = collect(&server);
        assert!(events.last().unwrap().is_err(), "{events:?}");
        assert!(!events.iter().any(|event| matches!(event, Ok(StreamEvent::Done { .. }))));
        server.finish();
    }
}

#[test]
fn streamed_exceptions_and_http_failures_redact_bearer_credentials() {
    let exception = frame(
        &[(":message-type", "exception"), (":exception-type", "throttlingException")],
        &json!({"message": format!("rate limited; echoed {TOKEN}")}),
    );
    let server = Server::new(200, EVENT_STREAM, [start(), exception].concat());
    let events = collect(&server);
    let error = events.last().unwrap().as_ref().unwrap_err().to_string();
    assert!(error.contains("HTTP 429"), "{error}");
    assert!(!error.contains(TOKEN), "{error}");
    assert!(!events.iter().any(|event| matches!(event, Ok(StreamEvent::Done { .. }))));
    server.finish();

    let server = Server::new(403, "application/json", serde_json::to_vec(&json!({"message": TOKEN})).unwrap());
    let error = run(async {
        BedrockProvider::new("m").with_base_url(&server.base)
            .stream(&context(), &options()).await.err().expect("HTTP failure")
    }).to_string();
    assert!(error.contains("HTTP 403"), "{error}");
    assert!(!error.contains(TOKEN), "{error}");
    server.finish();
}

#[test]
fn malformed_tool_json_never_reaches_tool_end() {
    let body = [
        start(),
        event("contentBlockStart", json!({"contentBlockIndex": 0, "start": {"toolUse": {"toolUseId": "bad", "name": "read"}}})),
        event("contentBlockDelta", json!({"contentBlockIndex": 0, "delta": {"toolUse": {"input": "{"}}})),
        block_stop(0), message_stop("tool_use"),
    ].concat();
    let server = Server::new(200, EVENT_STREAM, body);
    let events = collect(&server);
    assert!(events.last().unwrap().is_err());
    assert!(!events.iter().any(|event| matches!(event,
        Ok(StreamEvent::ToolCallEnd { .. } | StreamEvent::Done { .. })
    )));
    server.finish();
}

#[test]
fn incomplete_json_response_is_not_a_successful_turn() {
    for value in [json!({}), json!({"output": {"message": {"role": "assistant", "content": []}}})] {
        let server = Server::new(200, "application/json", serde_json::to_vec(&value).unwrap());
        let error = run(async {
            BedrockProvider::new("m").with_base_url(&server.base)
                .stream(&context(), &options()).await.err().expect("incomplete JSON rejected")
        }).to_string();
        assert!(error.contains("missing output or stopReason"), "{error}");
        server.finish();
    }
}

#[test]
fn other_provider_reasoning_is_not_replayed_as_bedrock_state() {
    let mut replay = context();
    replay.messages.to_mut().push(Message::assistant(AssistantMessage {
        api: "another-provider-api".to_string(),
        content: vec![
            ContentBlock::Thinking(ThinkingContent {
                thinking: "private provider state".to_string(), thinking_signature: Some("foreign".to_string()),
            }),
            ContentBlock::RedactedThinking(RedactedThinkingContent { data: "foreign".to_string() }),
            ContentBlock::Text(TextContent::new("visible answer")),
        ],
        ..AssistantMessage::default()
    }));
    let request = serde_json::to_value(BedrockProvider::build_request(&replay, &options())).unwrap();
    assert_eq!(request["messages"][1]["content"], json!([{"text": "visible answer"}]));
}

#[test]
fn inference_profile_arn_remains_one_encoded_path_segment() {
    let server = Server::new(200, EVENT_STREAM, complete_text());
    let events: Vec<_> = run(async {
        BedrockProvider::new("arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.model")
            .with_base_url(&server.base)
            .stream(&context(), &options()).await.unwrap().collect().await
    });
    assert!(events.iter().all(Result::is_ok));
    let request = server.finish();
    assert_eq!(request.path, "/model/arn:aws:bedrock:us-east-1:123456789012:inference-profile%2Fus.model/converse-stream");
}

#[test]
fn request_rewrite_receives_the_streaming_route_and_reaches_the_wire() {
    let server = Server::new(200, EVENT_STREAM, complete_text());
    let mut options = options();
    options.before_provider_request = Some(BeforeProviderRequestHook::new(|mut event| {
        assert!(event.base_url.ends_with("/converse-stream"));
        assert_eq!(event.api, "bedrock-converse-stream");
        assert!(!event.payload.to_string().contains(TOKEN));
        event.payload["messages"][0]["content"][0]["text"] = json!("rewritten prompt");
        event.payload["additionalModelRequestFields"] = json!({"thinking": {"type": "enabled", "budget_tokens": 1024}});
        Box::pin(async move { Some(event.payload) })
    }));
    let events: Vec<_> = run(async {
        BedrockProvider::new("model-a").with_base_url(&server.base)
            .stream(&context(), &options).await.unwrap().collect().await
    });
    assert!(events.iter().all(Result::is_ok));
    let request = server.finish();
    assert_eq!(request.body["messages"][0]["content"][0]["text"], "rewritten prompt");
    assert_eq!(request.body["additionalModelRequestFields"]["thinking"]["budget_tokens"], 1024);
}
