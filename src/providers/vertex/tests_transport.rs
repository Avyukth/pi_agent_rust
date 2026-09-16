//! Exercise Vertex's public Provider path with real loopback HTTP and SSE.

use super::*;
use crate::model::{Message, ThinkingLevel, UserContent, UserMessage};
use crate::provider::{BeforeProviderRequestHook, CacheRetention, ToolDef};
use asupersync::runtime::RuntimeBuilder;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct CapturedRequest {
    target: String,
    headers: HashMap<String, String>,
    body: Value,
}

struct WireServer {
    url: String,
    requests: mpsc::Receiver<CapturedRequest>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl WireServer {
    fn new(replies: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "http://{}/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-6:streamRawPredict",
            listener.local_addr().unwrap()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let (tx, requests) = mpsc::channel();
        let join = std::thread::spawn(move || {
            for (status, response_body) in replies {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut socket = loop {
                    if server_stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                        return;
                    }
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let header_end = loop {
                    if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        break index + 4;
                    }
                    assert!(bytes.len() < 64 * 1024, "bounded headers");
                    let count = socket.read(&mut chunk).expect("read headers");
                    assert!(count > 0, "EOF before headers");
                    bytes.extend_from_slice(&chunk[..count]);
                };
                let head = std::str::from_utf8(&bytes[..header_end]).unwrap();
                let target = head.lines().next().unwrap().to_string();
                let headers: HashMap<String, String> = head
                    .lines()
                    .skip(1)
                    .filter_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        Some((key.to_ascii_lowercase(), value.trim().to_string()))
                    })
                    .collect();
                let length: usize = headers["content-length"].parse().unwrap();
                assert!(length < 1024 * 1024, "bounded fixture body");
                while bytes.len() - header_end < length {
                    let count = socket.read(&mut chunk).expect("read body");
                    assert!(count > 0, "EOF before body");
                    bytes.extend_from_slice(&chunk[..count]);
                }
                tx.send(CapturedRequest {
                    target,
                    headers,
                    body: serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap(),
                })
                .expect("capture request");
                write!(
                    socket,
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                    response_body.len()
                )
                .expect("write response");
            }
        });
        Self {
            url,
            requests,
            stop,
            join: Some(join),
        }
    }

    fn captured(&self) -> CapturedRequest {
        self.requests
            .recv_timeout(Duration::from_secs(3))
            .expect("request captured")
    }
}

impl Drop for WireServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let result = join.join();
            if !std::thread::panicking() {
                result.expect("fixture thread completed");
            }
        }
    }
}

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    RuntimeBuilder::current_thread()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn provider(server: &WireServer) -> VertexProvider {
    VertexProvider::new("claude-sonnet-4-6")
        .with_project("p")
        .with_location("us-east5")
        .with_publisher("anthropic")
        .with_endpoint_url(&server.url)
}

fn context() -> Context<'static> {
    Context::owned(
        Some("Use the read tool.".to_string()),
        vec![Message::User(UserMessage {
            content: UserContent::Text("Read a.txt".to_string()),
            timestamp: 0,
        })],
        vec![ToolDef {
            name: "read".to_string(),
            description: "Read a file".to_string(),
            parameters: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        }],
    )
}

fn options() -> StreamOptions {
    StreamOptions {
        api_key: Some("google-test-token".to_string()),
        ..Default::default()
    }
}

fn frames(events: &[Value]) -> String {
    events
        .iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect()
}

fn success() -> String {
    frames(&[
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 3}}}),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text"}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "done"}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
        json!({"type": "message_stop"}),
    ])
}

async fn collect(
    provider: &VertexProvider,
    context: &Context<'_>,
    options: &StreamOptions,
) -> Vec<Result<StreamEvent>> {
    provider
        .stream(context, options)
        .await
        .expect("start stream")
        .collect()
        .await
}

#[test]
fn vertex_anthropic_request_and_stream_use_anthropic_not_gemini_shapes() {
    let server = WireServer::new(vec![(200, success())]);
    let provider = provider(&server);
    let opts = StreamOptions {
        thinking_level: Some(ThinkingLevel::High),
        cache_retention: CacheRetention::Short,
        ..options()
    };
    let events = run(collect(&provider, &context(), &opts));
    assert!(events.iter().all(Result::is_ok), "{events:?}");
    let Some(Ok(StreamEvent::Done { reason, message })) = events.last() else {
        panic!("missing Done: {events:?}");
    };
    assert_eq!(*reason, StopReason::Stop);
    assert_eq!(message.provider, "google-vertex");
    assert_eq!(message.api, "google-vertex");
    assert_eq!(message.model, "claude-sonnet-4-6");
    assert_eq!(message.usage.input, 3);
    assert_eq!(message.usage.output, 2);
    assert!(events.iter().any(|event| matches!(
        event,
        Ok(StreamEvent::TextDelta { delta, .. }) if delta == "done"
    )));
    let request = server.captured();
    assert!(request.target.ends_with(":streamRawPredict HTTP/1.1"));
    assert_eq!(request.headers["authorization"], "Bearer google-test-token");
    assert!(!request.headers.contains_key("x-api-key"));
    assert!(!request.headers.contains_key("anthropic-version"));
    assert!(!request.headers.contains_key("anthropic-beta"));
    assert!(!request.headers.contains_key("anthropic-dangerous-direct-browser-access"));
    let body = request.body;
    assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
    assert_eq!(body["stream"], true);
    assert!(body.get("model").is_none());
    assert!(body.get("contents").is_none());
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["system"][0]["text"], "Use the read tool.");
    assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
    assert_eq!(body["thinking"]["type"], "adaptive");
    assert_eq!(body["output_config"]["effort"], "high");
    assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
}

#[test]
fn vertex_tool_round_trip_preserves_thinking_signature_arguments_and_cache_usage() {
    let turn = frames(&[
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 3, "cache_read_input_tokens": 5, "cache_creation_input_tokens": 2}}}),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking"}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Use the file tool."}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "c2lnbmVk"}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "tool-1", "name": "read", "input": {}}}),
        json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":"}}),
        json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "\"a.txt\"}"}}),
        json!({"type": "content_block_stop", "index": 1}),
        json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 7}}),
        json!({"type": "message_stop"}),
    ]);
    let server = WireServer::new(vec![(200, turn), (200, success())]);
    let provider = provider(&server);
    run(async {
        let initial = context();
        let opts = options();
        let events = collect(&provider, &initial, &opts).await;
        assert!(events.iter().all(Result::is_ok), "{events:?}");
        assert!(events.iter().any(|event| matches!(
            event,
            Ok(StreamEvent::ThinkingDelta { delta, .. }) if delta == "Use the file tool."
        )));
        let Some(Ok(StreamEvent::Done { reason, message })) = events.last() else {
            panic!("missing Done");
        };
        assert_eq!(*reason, StopReason::ToolUse);
        assert_eq!(message.usage.cache_read, 5);
        assert_eq!(message.usage.cache_write, 2);
        assert_eq!(message.usage.total_tokens, 17);
        let ContentBlock::ToolCall(call) = &message.content[1] else {
            panic!("missing tool call");
        };
        assert_eq!(call.id, "tool-1");
        assert_eq!(call.arguments, json!({"path": "a.txt"}));
        // Use the actual session message encoding before making the next request.
        let encoded = serde_json::to_vec(&Message::assistant(message.clone())).unwrap();
        let replay: Message = serde_json::from_slice(&encoded).unwrap();
        let mut messages = initial.messages.to_vec();
        messages.push(replay);
        messages.push(Message::tool_result(crate::model::ToolResultMessage {
            tool_call_id: call.id.clone(),
            tool_name: call.name.clone(),
            content: vec![ContentBlock::Text(TextContent::new("file contents"))],
            details: None,
            is_error: false,
            timestamp: 1,
        }));
        let next = Context::owned(None, messages, initial.tools.to_vec());
        let events = collect(&provider, &next, &opts).await;
        assert!(events.iter().all(Result::is_ok));
        assert_eq!(
            events.iter().filter(|event| matches!(event, Ok(StreamEvent::Done { .. }))).count(),
            1
        );
    });
    let _first = server.captured();
    let body = server.captured().body;
    assert_eq!(body["messages"][1]["content"][0]["signature"], "c2lnbmVk");
    assert_eq!(body["messages"][1]["content"][1]["type"], "tool_use");
    assert_eq!(body["messages"][1]["content"][1]["input"], json!({"path": "a.txt"}));
    assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], "tool-1");
    assert_eq!(body["messages"][2]["content"][0]["content"][0]["text"], "file contents");
}

#[test]
fn vertex_rewrite_sees_native_shape_and_cannot_change_transport_fields() {
    let server = WireServer::new(vec![(200, success())]);
    let provider = provider(&server);
    let opts = StreamOptions {
        before_provider_request: Some(BeforeProviderRequestHook::new(|event| {
            Box::pin(async move {
                assert_eq!(event.provider, "google-vertex");
                assert_eq!(event.api, "google-vertex");
                assert_eq!(event.model, "claude-sonnet-4-6");
                assert_eq!(event.payload["anthropic_version"], "vertex-2023-10-16");
                assert!(event.payload.get("model").is_none());
                let mut body = event.payload;
                body["metadata"] = json!({"user_id": "rewrite-marker"});
                body["model"] = json!("must-not-change-route");
                body["anthropic_version"] = json!("wrong");
                body["stream"] = json!(false);
                Some(body)
            })
        })),
        ..options()
    };
    let events = run(collect(&provider, &context(), &opts));
    assert!(events.iter().all(Result::is_ok));
    let body = server.captured().body;
    assert_eq!(body["metadata"]["user_id"], "rewrite-marker");
    assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
    assert_eq!(body["stream"], true);
    assert!(body.get("model").is_none());
}

#[test]
fn invalid_vertex_rewrite_falls_back_to_original_anthropic_body() {
    let server = WireServer::new(vec![(200, success())]);
    let opts = StreamOptions {
        before_provider_request: Some(BeforeProviderRequestHook::new(|_| {
            Box::pin(async {
                Some(json!({"messages": "not-an-array", "max_tokens": 10}))
            })
        })),
        ..options()
    };
    let events = run(collect(&provider(&server), &context(), &opts));
    assert!(events.iter().all(Result::is_ok));
    let body = server.captured().body;
    assert_eq!(body["messages"][0]["content"][0]["text"], "Read a.txt");
    assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
}

#[test]
fn vertex_authorization_override_precedence_is_google_scoped() {
    let compat = CompatConfig {
        custom_headers: Some(HashMap::from([
            ("Authorization".to_string(), "Bearer compat".to_string()),
        ])),
        ..Default::default()
    };
    let mut opts = options();
    opts.headers.insert("aUtHoRiZaTiOn".to_string(), "Bearer request".to_string());
    let no_env = |_: &str| -> Option<String> {
        panic!("explicit authorization must not consult environment");
    };
    assert_eq!(vertex_authorization(&opts, Some(&compat), no_env).unwrap(), "Bearer request");
    opts.headers.insert("aUtHoRiZaTiOn".to_string(), "  ".to_string());
    assert_eq!(vertex_authorization(&opts, Some(&compat), no_env).unwrap(), "Bearer compat");
    assert_eq!(vertex_authorization(&opts, None, no_env).unwrap(), "Bearer google-test-token");
    opts.api_key = Some(" ".to_string());
    let env = |name: &str| match name {
        "GOOGLE_CLOUD_API_KEY" => Some(" ".to_string()),
        "VERTEX_API_KEY" => Some("vertex-env".to_string()),
        _ => panic!("must not load another provider's credentials"),
    };
    assert_eq!(vertex_authorization(&opts, None, env).unwrap(), "Bearer vertex-env");
    assert!(vertex_authorization(&opts, None, |_| None).is_err());
}

#[test]
fn header_only_vertex_auth_works_without_api_key_and_blank_override_cannot_erase_it() {
    for publisher in ["anthropic", "google"] {
        let response = if publisher == "anthropic" {
            success()
        } else {
            frames(&[json!({"candidates": [{"content": {"parts": [{"text": "done"}]}, "finishReason": "STOP"}]})])
        };
        let server = WireServer::new(vec![(200, response)]);
        let provider = provider(&server)
            .with_publisher(publisher)
            .with_compat(Some(CompatConfig {
                custom_headers: Some(HashMap::from([
                    ("Authorization".to_string(), "Bearer google-header".to_string()),
                    ("x-goog-user-project".to_string(), "quota-project".to_string()),
                ])),
                ..Default::default()
            }));
        let opts = StreamOptions {
            headers: HashMap::from([("authorization".to_string(), " ".to_string())]),
            ..Default::default()
        };
        let events = run(collect(&provider, &context(), &opts));
        assert!(events.iter().all(Result::is_ok), "{publisher}: {events:?}");
        let request = server.captured();
        assert_eq!(request.headers["authorization"], "Bearer google-header");
        assert_eq!(request.headers["x-goog-user-project"], "quota-project");
        assert_eq!(request.body.get("messages").is_some(), publisher == "anthropic");
        assert_eq!(request.body.get("contents").is_some(), publisher == "google");
    }
}

#[test]
fn vertex_anthropic_http_failure_preserves_status_and_provider() {
    let server = WireServer::new(vec![
        (403, json!({"error": {"message": "permission denied"}}).to_string()),
    ]);
    let provider = provider(&server);
    let error = run(async {
        provider.stream(&context(), &options()).await.err().expect("HTTP error")
    });
    assert!(error.to_string().contains("google-vertex"));
    assert!(error.to_string().contains("HTTP 403"));
    assert!(error.to_string().contains("permission denied"));
}

#[test]
fn vertex_anthropic_truncation_and_parse_errors_never_report_success() {
    for malformed in [false, true] {
        let mut body = frames(&[
            json!({"type": "message_start", "message": {"usage": {"input_tokens": 1}}}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text"}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "partial"}}),
        ]);
        if malformed {
            body.push_str("data: {invalid-json}\n\n");
        }
        let server = WireServer::new(vec![(200, body)]);
        let events = run(collect(&provider(&server), &context(), &options()));
        assert!(events.iter().any(|event| matches!(
            event,
            Ok(StreamEvent::TextDelta { delta, .. }) if delta == "partial"
        )));
        assert!(!events.iter().any(|event| matches!(event, Ok(StreamEvent::Done { .. }))));
        let error = events.last().unwrap().as_ref().expect_err("terminal error").to_string();
        if malformed {
            assert!(error.contains("JSON parse error"), "{error}");
        } else {
            assert!(error.contains("message_stop"), "{error}");
            assert!(crate::error::is_retryable_error(&error, None, None));
        }
    }
}

#[test]
fn vertex_anthropic_error_event_terminates_before_a_later_message_stop() {
    let server = WireServer::new(vec![(200, frames(&[
        json!({"type": "error", "error": {"message": "overloaded"}}),
        json!({"type": "message_stop"}),
    ]))]);
    let events = run(collect(&provider(&server), &context(), &options()));
    assert_eq!(events.len(), 1);
    let Ok(StreamEvent::Error { error, .. }) = &events[0] else {
        panic!("expected Error");
    };
    assert_eq!(error.provider, "google-vertex");
    assert_eq!(error.error_message.as_deref(), Some("overloaded"));
}

#[test]
fn unknown_vertex_publisher_is_rejected_before_network_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let provider = VertexProvider::new("unknown")
        .with_project("p")
        .with_publisher("unimplemented")
        .with_endpoint_url(format!("http://{}", listener.local_addr().unwrap()));
    let error = run(async {
        provider.stream(&context(), &options()).await.err().expect("unsupported")
    });
    assert!(error.to_string().contains("Unsupported Vertex AI publisher"));
    assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn global_vertex_routes_use_the_global_host_for_both_publishers() {
    for (publisher, method) in [
        ("google", "streamGenerateContent?alt=sse"),
        ("anthropic", "streamRawPredict"),
    ] {
        let provider = VertexProvider::new("test-model").with_publisher(publisher);
        assert_eq!(provider.streaming_url("p", "global"), format!(
            "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/{publisher}/models/test-model:{method}"
        ));
        assert!(provider.streaming_url("p", "us-east5").starts_with("https://us-east5-aiplatform.googleapis.com/"));
    }
}

#[test]
fn vertex_endpoint_parsing_keeps_complete_regions_and_explicit_path_precedence() {
    for (url, expected) in [
        ("https://us-east5-aiplatform.googleapis.com/v1/projects/p", Some("us-east5")),
        ("https://europe-west1-aiplatform.googleapis.com/v1/projects/p", Some("europe-west1")),
        ("https://aiplatform.googleapis.com/v1/projects/p", Some("global")),
        ("https://us-east5-aiplatform.googleapis.com/v1/projects/p/locations/global", Some("global")),
        ("https://proxy.example/v1/projects/p", None),
    ] {
        let (_, location, _) = parse_vertex_base_url(url);
        assert_eq!(location.as_deref(), expected, "{url}");
    }
}

#[test]
fn custom_vertex_endpoints_are_not_rewritten_by_transport_selection() {
    let endpoint = "http://127.0.0.1:8080/custom?region=test";
    for publisher in ["google", "anthropic"] {
        let provider = VertexProvider::new("test-model")
            .with_publisher(publisher)
            .with_endpoint_url(endpoint);
        assert_eq!(provider.streaming_url("ignored", "global"), endpoint);
    }
}
