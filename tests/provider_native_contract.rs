//! Native adapter contract tests (bd-3uqg.8.2).
//!
//! For each native provider integration, these tests validate:
//! 1. **Request payload shape**: correct URL path, Content-Type, body structure
//! 2. **Auth header construction**: Bearer vs X-API-Key vs provider-specific
//! 3. **Tool-schema translation**: internal `ToolDef` → provider-specific wire format
//! 4. **Response event decoding**: provider SSE → internal `StreamEvent` variants
//!
//! All tests run with mock HTTP transports so failures isolate adapter logic
//! rather than network behavior.

mod common;

use common::harness::MockHttpRequest;
use common::{MockHttpResponse, TestHarness};
use futures::StreamExt;
use pi::model::{Message, StreamEvent, UserContent, UserMessage};
use pi::models::ModelEntry;
use pi::provider::{Context, InputType, Model, ModelCost, StreamOptions, ToolDef};
use pi::providers::create_provider;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// Helpers
// ============================================================================

fn make_model_entry(provider: &str, model_id: &str, base_url: &str) -> ModelEntry {
    ModelEntry {
        model: Model {
            id: model_id.to_string(),
            name: format!("{provider} {model_id}"),
            api: String::new(), // let factory infer
            provider: provider.to_string(),
            base_url: base_url.to_string(),
            reasoning: false,
            input: vec![InputType::Text],
            cost: ModelCost {
                input: 0.0,
                output: 0.0,
                cache_read: 0.0,
                cache_write: 0.0,
            },
            context_window: 8192,
            max_tokens: 4096,
            headers: HashMap::new(),
        },
        api_key: None,
        headers: HashMap::new(),
        auth_header: false,
        compat: None,
        oauth_config: None,
    }
}

fn make_model_entry_with_api(
    provider: &str,
    model_id: &str,
    base_url: &str,
    api: &str,
) -> ModelEntry {
    let mut entry = make_model_entry(provider, model_id, base_url);
    entry.model.api = api.to_string();
    entry
}

fn text_event_stream_response(body: String) -> MockHttpResponse {
    MockHttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
        body: body.into_bytes(),
    }
}

fn request_header(headers: &[(String, String)], key: &str) -> Option<String> {
    headers
        .iter()
        .rev()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.clone())
}

fn request_body_json(request: &MockHttpRequest) -> serde_json::Value {
    serde_json::from_slice(&request.body).unwrap_or(serde_json::Value::Null)
}

fn simple_context() -> Context {
    Context {
        system_prompt: Some("You are a test assistant.".to_string()),
        messages: vec![Message::User(UserMessage {
            content: UserContent::Text("Hello".to_string()),
            timestamp: 0,
        })],
        tools: Vec::new(),
    }
}

fn context_with_tools() -> Context {
    Context {
        system_prompt: Some("You are a test assistant.".to_string()),
        messages: vec![Message::User(UserMessage {
            content: UserContent::Text("Use the echo tool".to_string()),
            timestamp: 0,
        })],
        tools: vec![
            ToolDef {
                name: "echo".to_string(),
                description: "Echoes text back".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The text to echo"
                        }
                    },
                    "required": ["text"]
                }),
            },
            ToolDef {
                name: "calculate".to_string(),
                description: "Performs arithmetic".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "expression": {
                            "type": "string",
                            "description": "Math expression to evaluate"
                        }
                    },
                    "required": ["expression"]
                }),
            },
        ],
    }
}

fn options_with_key(key: &str) -> StreamOptions {
    StreamOptions {
        api_key: Some(key.to_string()),
        max_tokens: Some(64),
        ..Default::default()
    }
}

/// Drive a provider stream to Done and collect all events.
fn collect_stream_events(
    provider: Arc<dyn pi::provider::Provider>,
    context: Context,
    options: StreamOptions,
) -> Vec<StreamEvent> {
    common::run_async(async move {
        let mut stream = provider
            .stream(&context, &options)
            .await
            .expect("provider stream should start");
        let mut events = Vec::new();
        while let Some(event) = stream.next().await {
            let event = event.expect("stream event");
            let is_done = matches!(event, StreamEvent::Done { .. });
            events.push(event);
            if is_done {
                break;
            }
        }
        events
    })
}

// ============================================================================
// SSE body generators for each provider API
// ============================================================================

fn anthropic_simple_sse() -> String {
    [
        r"event: message_start",
        r#"data: {"type":"message_start","message":{"id":"msg_ct_001","type":"message","role":"assistant","content":[],"model":"claude-test","stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}"#,
        "",
        r"event: content_block_start",
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        "",
        r"event: content_block_delta",
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello there!"}}"#,
        "",
        r"event: content_block_stop",
        r#"data: {"type":"content_block_stop","index":0}"#,
        "",
        r"event: message_delta",
        r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}"#,
        "",
        r"event: message_stop",
        r#"data: {"type":"message_stop"}"#,
        "",
    ]
    .join("\n")
}

fn anthropic_tool_call_sse() -> String {
    [
        r"event: message_start",
        r#"data: {"type":"message_start","message":{"id":"msg_ct_002","type":"message","role":"assistant","content":[],"model":"claude-test","stop_reason":null,"usage":{"input_tokens":15,"output_tokens":0}}}"#,
        "",
        r"event: content_block_start",
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_ct_001","name":"echo","input":{}}}"#,
        "",
        r"event: content_block_delta",
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"text\":\"contract test\"}"}}"#,
        "",
        r"event: content_block_stop",
        r#"data: {"type":"content_block_stop","index":0}"#,
        "",
        r"event: message_delta",
        r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":12}}"#,
        "",
        r"event: message_stop",
        r#"data: {"type":"message_stop"}"#,
        "",
    ]
    .join("\n")
}

fn openai_simple_sse() -> String {
    [
        r#"data: {"id":"chatcmpl-ct001","object":"chat.completion.chunk","created":1700000000,"model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}"#,
        "",
        r#"data: {"id":"chatcmpl-ct001","object":"chat.completion.chunk","created":1700000000,"model":"gpt-test","choices":[{"index":0,"delta":{"content":" there!"},"finish_reason":null}]}"#,
        "",
        r#"data: {"id":"chatcmpl-ct001","object":"chat.completion.chunk","created":1700000000,"model":"gpt-test","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#,
        "",
        "data: [DONE]",
        "",
    ]
    .join("\n")
}

fn openai_tool_call_sse() -> String {
    [
        r#"data: {"id":"chatcmpl-ct002","object":"chat.completion.chunk","created":1700000000,"model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"id":"call_ct_001","index":0,"type":"function","function":{"name":"echo","arguments":""}}]},"finish_reason":null}]}"#,
        "",
        r#"data: {"id":"chatcmpl-ct002","object":"chat.completion.chunk","created":1700000000,"model":"gpt-test","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"text\":\"contract test\"}"}}]},"finish_reason":null}]}"#,
        "",
        r#"data: {"id":"chatcmpl-ct002","object":"chat.completion.chunk","created":1700000000,"model":"gpt-test","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":15,"completion_tokens":12,"total_tokens":27}}"#,
        "",
        "data: [DONE]",
        "",
    ]
    .join("\n")
}

fn cohere_simple_sse() -> String {
    [
        r"event: message-start",
        r#"data: {"id":"ct-cohere-001","type":"message-start","delta":{"message":{"role":"assistant","content":[]}}}"#,
        "",
        r"event: content-start",
        r#"data: {"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}"#,
        "",
        r"event: content-delta",
        r#"data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Hello there!"}}}}"#,
        "",
        r"event: content-end",
        r#"data: {"type":"content-end","index":0}"#,
        "",
        r"event: message-end",
        r#"data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":10,"output_tokens":5},"tokens":{"input_tokens":10,"output_tokens":5}}}}"#,
        "",
    ]
    .join("\n")
}

fn gemini_simple_sse() -> String {
    // Gemini uses JSON streaming with generateContent endpoint
    [
        r#"data: {"candidates":[{"content":{"parts":[{"text":"Hello there!"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}"#,
        "",
    ]
    .join("\n")
}

// ============================================================================
// ANTHROPIC CONTRACT TESTS
// ============================================================================

mod anthropic_contract {
    use super::*;

    #[test]
    fn request_payload_shape() {
        let harness = TestHarness::new("anthropic_contract_request_payload_shape");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/messages";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(anthropic_simple_sse()),
        );

        let entry = make_model_entry(
            "anthropic",
            "claude-test",
            &format!("{}{endpoint}", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create anthropic");

        let context = simple_context();
        let options = options_with_key("sk-ant-test-key");
        collect_stream_events(provider, context, options);

        let requests = server.requests();
        assert_eq!(requests.len(), 1, "expected exactly one request");
        let req = &requests[0];

        // Path correctness
        assert_eq!(req.path, endpoint);
        assert_eq!(req.method, "POST");

        // Content-Type
        assert_eq!(
            request_header(&req.headers, "content-type").as_deref(),
            Some("application/json")
        );

        // Body structure
        let body = request_body_json(req);
        assert!(body.get("model").is_some(), "body must contain 'model'");
        assert_eq!(body["model"], "claude-test");
        assert!(
            body.get("messages").is_some(),
            "body must contain 'messages'"
        );
        assert!(body["messages"].is_array(), "messages must be an array");
        assert!(
            body.get("max_tokens").is_some(),
            "body must contain 'max_tokens'"
        );
        assert!(body.get("stream").is_some(), "body must contain 'stream'");
        assert_eq!(body["stream"], true, "stream must be true");

        // System prompt handling (Anthropic uses top-level 'system' field)
        assert!(
            body.get("system").is_some(),
            "body must contain 'system' for system prompt"
        );

        harness
            .log()
            .info_ctx("contract", "anthropic request payload validated", |ctx| {
                ctx.push(("model".to_string(), body["model"].to_string()));
                ctx.push((
                    "messages_count".to_string(),
                    body["messages"].as_array().map_or(0, Vec::len).to_string(),
                ));
            });
    }

    #[test]
    fn auth_header_x_api_key() {
        let harness = TestHarness::new("anthropic_contract_auth_header");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/messages";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(anthropic_simple_sse()),
        );

        let entry = make_model_entry(
            "anthropic",
            "claude-test",
            &format!("{}{endpoint}", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create anthropic");

        let context = simple_context();
        let options = options_with_key("sk-ant-contract-test");
        collect_stream_events(provider, context, options);

        let req = &server.requests()[0];

        // Anthropic uses x-api-key header, NOT Bearer auth
        assert_eq!(
            request_header(&req.headers, "x-api-key").as_deref(),
            Some("sk-ant-contract-test"),
            "Anthropic must use x-api-key header"
        );

        // Anthropic-specific headers
        assert!(
            request_header(&req.headers, "anthropic-version").is_some(),
            "Anthropic must send anthropic-version header"
        );

        harness
            .log()
            .info("contract", "anthropic auth headers validated");
    }

    #[test]
    fn tool_schema_translation() {
        let harness = TestHarness::new("anthropic_contract_tool_schema");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/messages";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(anthropic_tool_call_sse()),
        );

        let entry = make_model_entry(
            "anthropic",
            "claude-test",
            &format!("{}{endpoint}", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create anthropic");

        let context = context_with_tools();
        let options = options_with_key("sk-ant-tool-test");
        collect_stream_events(provider, context, options);

        let req = &server.requests()[0];
        let body = request_body_json(req);

        // Anthropic tool format: { "name", "description", "input_schema" }
        let tools = body["tools"].as_array().expect("tools must be an array");
        assert_eq!(tools.len(), 2, "expected 2 tools");

        let echo_tool = &tools[0];
        assert_eq!(echo_tool["name"], "echo");
        assert_eq!(echo_tool["description"], "Echoes text back");
        // Anthropic uses "input_schema" (not "parameters")
        assert!(
            echo_tool.get("input_schema").is_some(),
            "Anthropic tools must use 'input_schema' key"
        );
        let schema = &echo_tool["input_schema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["text"].is_object());

        harness
            .log()
            .info_ctx("contract", "anthropic tool schema validated", |ctx| {
                ctx.push(("tool_count".to_string(), tools.len().to_string()));
            });
    }

    #[test]
    fn response_event_decoding_text() {
        let harness = TestHarness::new("anthropic_contract_response_decoding_text");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/messages";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(anthropic_simple_sse()),
        );

        let entry = make_model_entry(
            "anthropic",
            "claude-test",
            &format!("{}{endpoint}", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create anthropic");

        let events = collect_stream_events(provider, simple_context(), options_with_key("test"));

        // Must contain text delta and Done events
        let has_text = events
            .iter()
            .any(|e| matches!(e, StreamEvent::TextDelta { .. }));
        let has_done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));

        assert!(
            has_text,
            "Anthropic text stream must produce TextDelta events"
        );
        assert!(has_done, "Anthropic text stream must end with Done event");

        harness
            .log()
            .info_ctx("contract", "anthropic response decoding validated", |ctx| {
                ctx.push(("event_count".to_string(), events.len().to_string()));
            });
    }

    #[test]
    fn response_event_decoding_tool_call() {
        let harness = TestHarness::new("anthropic_contract_response_decoding_tool_call");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/messages";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(anthropic_tool_call_sse()),
        );

        let entry = make_model_entry(
            "anthropic",
            "claude-test",
            &format!("{}{endpoint}", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create anthropic");

        let events =
            collect_stream_events(provider, context_with_tools(), options_with_key("test"));

        let has_tool_call = events
            .iter()
            .any(|e| matches!(e, StreamEvent::ToolCallStart { .. }));
        let has_done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));

        assert!(
            has_tool_call,
            "Anthropic tool stream must produce ToolCallStart events"
        );
        assert!(has_done, "Anthropic tool stream must end with Done event");

        harness.log().info_ctx(
            "contract",
            "anthropic tool call decoding validated",
            |ctx| {
                ctx.push(("event_count".to_string(), events.len().to_string()));
            },
        );
    }
}

// ============================================================================
// OPENAI (Chat Completions) CONTRACT TESTS
// ============================================================================

mod openai_contract {
    use super::*;

    #[test]
    fn request_payload_shape() {
        let harness = TestHarness::new("openai_contract_request_payload_shape");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/chat/completions";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(openai_simple_sse()),
        );

        let entry = make_model_entry_with_api(
            "openai",
            "gpt-test",
            &format!("{}{endpoint}", server.base_url()),
            "openai-completions",
        );
        let provider = create_provider(&entry, None).expect("create openai");

        let context = simple_context();
        let options = options_with_key("sk-openai-test-key");
        collect_stream_events(provider, context, options);

        let requests = server.requests();
        assert_eq!(requests.len(), 1, "expected exactly one request");
        let req = &requests[0];

        assert_eq!(req.path, endpoint);
        assert_eq!(req.method, "POST");

        let body = request_body_json(req);
        assert_eq!(body["model"], "gpt-test");
        assert!(body["messages"].is_array());
        assert_eq!(body["stream"], true);

        // OpenAI uses messages array with role/content objects
        let messages = body["messages"].as_array().unwrap();
        // System prompt should be in messages (OpenAI style)
        let has_system = messages.iter().any(|m| m["role"] == "system");
        let has_user = messages.iter().any(|m| m["role"] == "user");
        assert!(
            has_system,
            "OpenAI must include system message in messages array"
        );
        assert!(has_user, "OpenAI must include user message");

        harness
            .log()
            .info("contract", "openai request payload validated");
    }

    #[test]
    fn auth_header_bearer() {
        let harness = TestHarness::new("openai_contract_auth_header");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/chat/completions";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(openai_simple_sse()),
        );

        let entry = make_model_entry_with_api(
            "openai",
            "gpt-test",
            &format!("{}{endpoint}", server.base_url()),
            "openai-completions",
        );
        let provider = create_provider(&entry, None).expect("create openai");

        collect_stream_events(
            provider,
            simple_context(),
            options_with_key("sk-openai-contract"),
        );

        let req = &server.requests()[0];

        // OpenAI uses Bearer token
        assert_eq!(
            request_header(&req.headers, "authorization").as_deref(),
            Some("Bearer sk-openai-contract"),
            "OpenAI must use Bearer auth"
        );

        harness
            .log()
            .info("contract", "openai auth header validated");
    }

    #[test]
    fn tool_schema_translation() {
        let harness = TestHarness::new("openai_contract_tool_schema");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/chat/completions";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(openai_tool_call_sse()),
        );

        let entry = make_model_entry_with_api(
            "openai",
            "gpt-test",
            &format!("{}{endpoint}", server.base_url()),
            "openai-completions",
        );
        let provider = create_provider(&entry, None).expect("create openai");

        collect_stream_events(provider, context_with_tools(), options_with_key("test"));

        let req = &server.requests()[0];
        let body = request_body_json(req);

        // OpenAI tool format: { "type": "function", "function": { "name", "description", "parameters" } }
        let tools = body["tools"].as_array().expect("tools must be an array");
        assert_eq!(tools.len(), 2, "expected 2 tools");

        let echo_tool = &tools[0];
        assert_eq!(echo_tool["type"], "function");
        assert_eq!(echo_tool["function"]["name"], "echo");
        assert_eq!(echo_tool["function"]["description"], "Echoes text back");
        // OpenAI uses "parameters" (not "input_schema")
        assert!(
            echo_tool["function"].get("parameters").is_some(),
            "OpenAI tools must use 'parameters' key inside 'function'"
        );

        harness
            .log()
            .info("contract", "openai tool schema validated");
    }

    #[test]
    fn response_event_decoding_text() {
        let harness = TestHarness::new("openai_contract_response_decoding_text");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/chat/completions";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(openai_simple_sse()),
        );

        let entry = make_model_entry_with_api(
            "openai",
            "gpt-test",
            &format!("{}{endpoint}", server.base_url()),
            "openai-completions",
        );
        let provider = create_provider(&entry, None).expect("create openai");

        let events = collect_stream_events(provider, simple_context(), options_with_key("test"));

        let has_text = events
            .iter()
            .any(|e| matches!(e, StreamEvent::TextDelta { .. }));
        let has_done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));

        assert!(has_text, "OpenAI text stream must produce Text events");
        assert!(has_done, "OpenAI text stream must end with Done event");

        harness
            .log()
            .info("contract", "openai response decoding validated");
    }

    #[test]
    fn response_event_decoding_tool_call() {
        let harness = TestHarness::new("openai_contract_response_decoding_tool_call");
        let server = harness.start_mock_http_server();
        let endpoint = "/v1/chat/completions";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(openai_tool_call_sse()),
        );

        let entry = make_model_entry_with_api(
            "openai",
            "gpt-test",
            &format!("{}{endpoint}", server.base_url()),
            "openai-completions",
        );
        let provider = create_provider(&entry, None).expect("create openai");

        let events =
            collect_stream_events(provider, context_with_tools(), options_with_key("test"));

        let has_tool_call = events
            .iter()
            .any(|e| matches!(e, StreamEvent::ToolCallStart { .. }));
        let has_done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));

        assert!(
            has_tool_call,
            "OpenAI tool stream must produce ToolCallStart events"
        );
        assert!(has_done, "OpenAI tool stream must end with Done event");

        harness
            .log()
            .info("contract", "openai tool call decoding validated");
    }
}

// ============================================================================
// GEMINI CONTRACT TESTS
// ============================================================================

mod gemini_contract {
    use super::*;

    /// Gemini appends `?alt=sse&key={key}` to the path.  The mock server
    /// matches on the full request-line path (including query string), so we
    /// must register routes with the expected query params.
    fn gemini_route(key: &str) -> String {
        format!("/v1beta/models/gemini-test:streamGenerateContent?alt=sse&key={key}")
    }

    #[test]
    fn request_payload_shape() {
        let harness = TestHarness::new("gemini_contract_request_payload_shape");
        let server = harness.start_mock_http_server();
        let api_key = "gemini-test-key";
        let endpoint = gemini_route(api_key);

        server.add_route(
            "POST",
            &endpoint,
            text_event_stream_response(gemini_simple_sse()),
        );

        let entry = make_model_entry(
            "google",
            "gemini-test",
            &format!("{}/v1beta", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create gemini");

        let context = simple_context();
        let options = options_with_key(api_key);
        collect_stream_events(provider, context, options);

        let requests = server.requests();
        assert_eq!(requests.len(), 1, "expected exactly one request");
        let req = &requests[0];

        assert_eq!(req.method, "POST");
        // Gemini endpoint should include model name in path
        assert!(
            req.path.contains("gemini-test"),
            "Gemini request path must contain model name"
        );

        let body = request_body_json(req);
        // Gemini uses 'contents' instead of 'messages'
        assert!(
            body.get("contents").is_some(),
            "Gemini body must contain 'contents'"
        );

        harness
            .log()
            .info("contract", "gemini request payload validated");
    }

    #[test]
    fn auth_via_query_param() {
        let harness = TestHarness::new("gemini_contract_auth_query_param");
        let server = harness.start_mock_http_server();
        let api_key = "gemini-key-test";
        let endpoint = gemini_route(api_key);

        server.add_route(
            "POST",
            &endpoint,
            text_event_stream_response(gemini_simple_sse()),
        );

        let entry = make_model_entry(
            "google",
            "gemini-test",
            &format!("{}/v1beta", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create gemini");

        collect_stream_events(provider, simple_context(), options_with_key(api_key));

        let req = &server.requests()[0];

        // Gemini uses key as query parameter
        assert!(
            req.path.contains("key=gemini-key-test"),
            "Gemini must pass API key as query parameter"
        );

        harness.log().info("contract", "gemini auth validated");
    }

    #[test]
    fn tool_schema_translation() {
        let harness = TestHarness::new("gemini_contract_tool_schema");
        let server = harness.start_mock_http_server();
        let api_key = "gemini-tool-test";
        let endpoint = gemini_route(api_key);

        server.add_route(
            "POST",
            &endpoint,
            text_event_stream_response(gemini_simple_sse()),
        );

        let entry = make_model_entry(
            "google",
            "gemini-test",
            &format!("{}/v1beta", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create gemini");

        collect_stream_events(provider, context_with_tools(), options_with_key(api_key));

        let req = &server.requests()[0];
        let body = request_body_json(req);

        // Gemini uses 'tools' array with 'function_declarations'
        assert!(
            body.get("tools").is_some(),
            "Gemini body must contain 'tools'"
        );
        let tools = body["tools"].as_array().expect("tools must be an array");
        assert!(!tools.is_empty(), "tools must not be empty");

        // Gemini wraps functions in functionDeclarations
        let first_tool = &tools[0];
        assert!(
            first_tool.get("function_declarations").is_some()
                || first_tool.get("functionDeclarations").is_some(),
            "Gemini tools must contain function_declarations or functionDeclarations"
        );

        harness
            .log()
            .info("contract", "gemini tool schema validated");
    }

    #[test]
    fn response_event_decoding_text() {
        let harness = TestHarness::new("gemini_contract_response_decoding_text");
        let server = harness.start_mock_http_server();
        let api_key = "gemini-decode-test";
        let endpoint = gemini_route(api_key);

        server.add_route(
            "POST",
            &endpoint,
            text_event_stream_response(gemini_simple_sse()),
        );

        let entry = make_model_entry(
            "google",
            "gemini-test",
            &format!("{}/v1beta", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create gemini");

        let events = collect_stream_events(provider, simple_context(), options_with_key(api_key));

        let has_text = events
            .iter()
            .any(|e| matches!(e, StreamEvent::TextDelta { .. }));
        let has_done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));

        assert!(has_text, "Gemini text stream must produce Text events");
        assert!(has_done, "Gemini text stream must end with Done event");

        harness
            .log()
            .info("contract", "gemini response decoding validated");
    }
}

// ============================================================================
// COHERE CONTRACT TESTS
// ============================================================================

mod cohere_contract {
    use super::*;

    #[test]
    fn request_payload_shape() {
        let harness = TestHarness::new("cohere_contract_request_payload_shape");
        let server = harness.start_mock_http_server();
        let endpoint = "/v2/chat";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(cohere_simple_sse()),
        );

        let entry = make_model_entry(
            "cohere",
            "command-r-test",
            &format!("{}/v2", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create cohere");

        let context = simple_context();
        let options = options_with_key("cohere-test-key");
        collect_stream_events(provider, context, options);

        let requests = server.requests();
        assert_eq!(requests.len(), 1, "expected exactly one request");
        let req = &requests[0];

        assert_eq!(req.method, "POST");

        let body = request_body_json(req);
        assert_eq!(body["model"], "command-r-test");
        assert_eq!(body["stream"], true);
        // Cohere uses 'messages' array
        assert!(
            body.get("messages").is_some(),
            "Cohere body must contain 'messages'"
        );

        harness
            .log()
            .info("contract", "cohere request payload validated");
    }

    #[test]
    fn auth_header_bearer() {
        let harness = TestHarness::new("cohere_contract_auth_header");
        let server = harness.start_mock_http_server();
        let endpoint = "/v2/chat";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(cohere_simple_sse()),
        );

        let entry = make_model_entry(
            "cohere",
            "command-r-test",
            &format!("{}/v2", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create cohere");

        collect_stream_events(
            provider,
            simple_context(),
            options_with_key("cohere-bearer-test"),
        );

        let req = &server.requests()[0];

        // Cohere uses Bearer token
        assert_eq!(
            request_header(&req.headers, "authorization").as_deref(),
            Some("Bearer cohere-bearer-test"),
            "Cohere must use Bearer auth"
        );

        harness
            .log()
            .info("contract", "cohere auth header validated");
    }

    #[test]
    fn response_event_decoding_text() {
        let harness = TestHarness::new("cohere_contract_response_decoding_text");
        let server = harness.start_mock_http_server();
        let endpoint = "/v2/chat";

        server.add_route(
            "POST",
            endpoint,
            text_event_stream_response(cohere_simple_sse()),
        );

        let entry = make_model_entry(
            "cohere",
            "command-r-test",
            &format!("{}/v2", server.base_url()),
        );
        let provider = create_provider(&entry, None).expect("create cohere");

        let events = collect_stream_events(provider, simple_context(), options_with_key("test"));

        let has_text = events
            .iter()
            .any(|e| matches!(e, StreamEvent::TextDelta { .. }));
        let has_done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));

        assert!(has_text, "Cohere text stream must produce Text events");
        assert!(has_done, "Cohere text stream must end with Done event");

        harness
            .log()
            .info("contract", "cohere response decoding validated");
    }
}

// ============================================================================
// OPENAI-COMPATIBLE PRESET CONTRACT TESTS
// ============================================================================
//
// These tests verify that OpenAI-compatible presets (groq, deepseek, etc.)
// correctly route through the OpenAI chat completions adapter.

mod openai_compat_preset_contract {
    use super::*;

    const PRESET_PROVIDERS: [&str; 5] = ["groq", "deepseek", "xai", "perplexity", "fireworks"];

    #[test]
    fn preset_providers_use_bearer_auth_and_chat_completions() {
        let harness = TestHarness::new("preset_contract_bearer_and_chat_completions");

        for &provider_id in &PRESET_PROVIDERS {
            let server = harness.start_mock_http_server();
            let endpoint = "/v1/chat/completions";
            server.add_route(
                "POST",
                endpoint,
                text_event_stream_response(openai_simple_sse()),
            );

            let entry = make_model_entry_with_api(
                provider_id,
                "preset-model",
                &format!("{}/v1", server.base_url()),
                "openai-completions",
            );
            let provider = create_provider(&entry, None)
                .unwrap_or_else(|e| panic!("create_provider should work for {provider_id}: {e}"));

            let api_key = format!("{provider_id}-contract-key");
            collect_stream_events(provider, simple_context(), options_with_key(&api_key));

            let req = &server.requests()[0];

            // All OAI-compat presets use Bearer auth
            let expected_auth = format!("Bearer {api_key}");
            assert_eq!(
                request_header(&req.headers, "authorization").as_deref(),
                Some(expected_auth.as_str()),
                "{provider_id} must use Bearer auth"
            );

            // All route to /chat/completions
            assert_eq!(
                req.path, endpoint,
                "{provider_id} must route to /v1/chat/completions"
            );

            // Body must contain standard OpenAI fields
            let body = request_body_json(req);
            assert_eq!(body["model"], "preset-model");
            assert_eq!(body["stream"], true);
            assert!(body["messages"].is_array());

            harness
                .log()
                .info_ctx("contract", "preset validated", |ctx| {
                    ctx.push(("provider".to_string(), provider_id.to_string()));
                });
        }
    }
}

// ============================================================================
// CROSS-PROVIDER INVARIANTS
// ============================================================================

mod cross_provider_invariants {
    use super::*;

    /// All native providers must produce at least one Text or `ToolCallStart` event
    /// followed by a Done event when given a valid simple SSE stream.
    #[test]
    fn all_native_providers_produce_done_event() {
        let harness = TestHarness::new("cross_provider_done_event");

        let cases: Vec<(&str, &str, &str, String)> = vec![
            (
                "anthropic",
                "claude-test",
                "/v1/messages",
                anthropic_simple_sse(),
            ),
            (
                "openai",
                "gpt-test",
                "/v1/chat/completions",
                openai_simple_sse(),
            ),
            ("cohere", "command-r-test", "/v2/chat", cohere_simple_sse()),
        ];

        for (provider_id, model_id, endpoint, sse_body) in cases {
            let server = harness.start_mock_http_server();
            server.add_route("POST", endpoint, text_event_stream_response(sse_body));

            let mut entry = make_model_entry(
                provider_id,
                model_id,
                &format!("{}{endpoint}", server.base_url()),
            );
            if provider_id == "openai" {
                entry.model.api = "openai-completions".to_string();
            }
            let provider = create_provider(&entry, None)
                .unwrap_or_else(|e| panic!("create_provider for {provider_id}: {e}"));

            let events =
                collect_stream_events(provider, simple_context(), options_with_key("test"));

            let has_done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));
            assert!(
                has_done,
                "{provider_id} must produce a Done event from a valid stream"
            );

            harness
                .log()
                .info_ctx("invariant", "done event confirmed", |ctx| {
                    ctx.push(("provider".to_string(), provider_id.to_string()));
                    ctx.push(("event_count".to_string(), events.len().to_string()));
                });
        }
    }

    /// All native providers must set Content-Type: application/json on requests.
    #[test]
    fn all_native_providers_send_json_content_type() {
        let harness = TestHarness::new("cross_provider_json_content_type");

        let cases: Vec<(&str, &str, &str, String)> = vec![
            (
                "anthropic",
                "claude-test",
                "/v1/messages",
                anthropic_simple_sse(),
            ),
            (
                "openai",
                "gpt-test",
                "/v1/chat/completions",
                openai_simple_sse(),
            ),
            ("cohere", "command-r-test", "/v2/chat", cohere_simple_sse()),
        ];

        for (provider_id, model_id, endpoint, sse_body) in cases {
            let server = harness.start_mock_http_server();
            server.add_route("POST", endpoint, text_event_stream_response(sse_body));

            let mut entry = make_model_entry(
                provider_id,
                model_id,
                &format!("{}{endpoint}", server.base_url()),
            );
            if provider_id == "openai" {
                entry.model.api = "openai-completions".to_string();
            }
            let provider = create_provider(&entry, None)
                .unwrap_or_else(|e| panic!("create_provider for {provider_id}: {e}"));

            collect_stream_events(provider, simple_context(), options_with_key("test"));

            let req = &server.requests()[0];
            assert_eq!(
                request_header(&req.headers, "content-type").as_deref(),
                Some("application/json"),
                "{provider_id} must send Content-Type: application/json"
            );
        }
    }
}
