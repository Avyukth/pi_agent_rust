//! Provider smoke tests for observation injection (bd-7x4).
//!
//! Verifies that the system-message observation wrapper is interpreted correctly
//! by representative providers (Anthropic/Claude, OpenAI/GPT-4, Google/Gemini).
//!
//! Scope:
//! - Observation summary text does not break provider request serialization
//! - SSE event stream contracts hold when observation messages are in context
//! - Console-error, load-complete, and near-budget observation summaries
//!   are correctly included in the request body
//! - Structured JSON logs capture provider/model/version metadata
//!
//! These tests use mocked HTTP (no real API calls) and run in CI on every PR.
//! Live provider validation (nightly) is deferred until CI has API key secrets.
//!
//! bd-7x4

mod common;

use common::{ArtifactBundle, MockHttpResponse, ProtocolDirection, TestHarness};
use futures::StreamExt;
use pi::model::{CustomMessage, Message, UserContent, UserMessage};
use pi::provider::{Context, InputType, Model, ModelCost, StreamEvent, StreamOptions};
use pi::providers::create_provider;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn make_entry(provider: &str, model_id: &str, base_url: &str) -> pi::models::ModelEntry {
    pi::models::ModelEntry {
        model: Model {
            id: model_id.to_string(),
            name: format!("{provider} observation smoke"),
            api: String::new(),
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

fn stream_options(api_key: &str) -> StreamOptions {
    StreamOptions {
        api_key: Some(api_key.to_string()),
        max_tokens: Some(64),
        ..Default::default()
    }
}

fn sse_response(body: String) -> MockHttpResponse {
    MockHttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
        body: body.into_bytes(),
    }
}

fn anthropic_sse() -> String {
    [
        r#"data: {"type":"message_start","message":{"usage":{"input_tokens":10}}}"#,
        "",
        r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}"#,
        "",
        r#"data: {"type":"message_stop"}"#,
        "",
    ]
    .join("\n")
}

fn openai_chat_sse() -> String {
    [
        r#"data: {"choices":[{"delta":{}}]}"#,
        "",
        r#"data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#,
        "",
        "data: [DONE]",
        "",
    ]
    .join("\n")
}

fn gemini_sse() -> String {
    [
        r#"data: {"candidates":[{"content":{"parts":[{"text":"ok"}],"role":"model"}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}"#,
        "",
    ]
    .join("\n")
}

// ── Provider setup helpers (route + entry + provider) ────────────────

struct ProviderSetup {
    provider: Arc<dyn pi::provider::Provider>,
    api_key: String,
}

fn setup_anthropic(server: &common::MockHttpServer, tag: &str) -> ProviderSetup {
    let prefix = format!("/obs/{tag}");
    let endpoint = format!("{prefix}/v1/messages");
    server.add_route("POST", &endpoint, sse_response(anthropic_sse()));
    let mut entry = make_entry(
        "anthropic",
        "obs-claude",
        &format!("{}{prefix}", server.base_url()),
    );
    entry.model.api.clear();
    let provider = create_provider(&entry, None).expect("create anthropic provider");
    ProviderSetup {
        provider,
        api_key: "obs-anth-key".to_string(),
    }
}

fn setup_openai(server: &common::MockHttpServer, tag: &str) -> ProviderSetup {
    let prefix = format!("/obs/{tag}");
    let endpoint = format!("{prefix}/chat/completions");
    server.add_route("POST", &endpoint, sse_response(openai_chat_sse()));
    let mut entry = make_entry(
        "openai",
        "obs-gpt4",
        &format!("{}{prefix}", server.base_url()),
    );
    entry.model.api = "openai-completions".to_string();
    let provider = create_provider(&entry, None).expect("create openai provider");
    ProviderSetup {
        provider,
        api_key: "obs-oai-key".to_string(),
    }
}

fn setup_gemini(server: &common::MockHttpServer, tag: &str) -> ProviderSetup {
    let api_key = format!("obs-gem-key-{tag}");
    let model_id = format!("obs-gem-{tag}");
    // Gemini sends API key via x-goog-api-key header, not URL query param
    let endpoint = format!("/v1beta/models/{model_id}:streamGenerateContent?alt=sse");
    server.add_route("POST", &endpoint, sse_response(gemini_sse()));
    let mut entry = make_entry(
        "google",
        &model_id,
        &format!("{}/v1beta", server.base_url()),
    );
    entry.model.api.clear();
    let provider = create_provider(&entry, None).expect("create gemini provider");
    ProviderSetup { provider, api_key }
}

// ── Observation message factories ────────────────────────────────────

fn observation_console_error() -> Message {
    Message::Custom(CustomMessage {
        content:
            "[Browser Observation]\n- console_error: TypeError: cannot read property 'x' of null"
                .to_string(),
        custom_type: "browser_observations".to_string(),
        display: true,
        details: Some(json!({"events_processed": 1, "batches": 1})),
        timestamp: 1000,
    })
}

fn observation_load_complete() -> Message {
    Message::Custom(CustomMessage {
        content: "[Browser Observation]\n- load_complete: https://example.com/dashboard"
            .to_string(),
        custom_type: "browser_observations".to_string(),
        display: true,
        details: Some(json!({"events_processed": 1, "batches": 1})),
        timestamp: 2000,
    })
}

fn observation_near_budget() -> Message {
    let mut lines = Vec::with_capacity(21);
    lines.push("[Browser Observation]".to_string());
    for i in 0..19 {
        lines.push(format!(
            "- console_warn: Warning {i}: deprecated API usage in module {i}"
        ));
    }
    lines.push("(+5 additional events omitted)".to_string());
    Message::Custom(CustomMessage {
        content: lines.join("\n"),
        custom_type: "browser_observations".to_string(),
        display: true,
        details: Some(json!({"events_processed": 24, "batches": 3})),
        timestamp: 3000,
    })
}

fn context_with_observation(observation: Message) -> Context<'static> {
    Context::owned(
        Some("You are a helpful coding assistant with browser automation.".to_string()),
        vec![
            Message::User(UserMessage {
                content: UserContent::Text("Check the page for errors.".to_string()),
                timestamp: 0,
            }),
            observation,
        ],
        Vec::new(),
    )
}

fn drive_to_done(
    provider: Arc<dyn pi::provider::Provider>,
    context: Context<'static>,
    options: StreamOptions,
) -> usize {
    common::run_async(async move {
        let mut stream = provider
            .stream(&context, &options)
            .await
            .expect("provider stream should start");
        let mut count = 0;
        while let Some(event) = stream.next().await {
            count += 1;
            if matches!(event.expect("stream event"), StreamEvent::Done { .. }) {
                return count;
            }
        }
        panic!("stream ended before Done");
    })
}

fn assert_body_contains(server: &common::MockHttpServer, needles: &[&str]) {
    let reqs = server.requests();
    assert!(!reqs.is_empty(), "expected at least one request");
    let body_str = String::from_utf8_lossy(&reqs[reqs.len() - 1].body);
    for needle in needles {
        assert!(
            body_str.contains(needle),
            "request body must contain \"{needle}\""
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Anthropic/Claude
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn obs_smoke_anthropic_console_error() {
    let harness = TestHarness::new("obs_smoke_anthropic_console_error");
    let bundle = ArtifactBundle::new("obs_smoke_anthropic_console_error");
    bundle.add_metadata("provider", "anthropic");
    bundle.add_metadata("scenario", "console_error");
    bundle.add_metadata("bead", "bd-7x4");

    let server = harness.start_mock_http_server();
    let setup = setup_anthropic(&server, "anth_ce");

    let ctx = context_with_observation(observation_console_error());
    let events = drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));

    assert_body_contains(
        &server,
        &["[Browser Observation]", "console_error", "TypeError"],
    );

    bundle.record_protocol_trace(
        ProtocolDirection::Outgoing,
        "observation_smoke",
        &json!({"events": events}),
        None,
    );
    bundle.add_metadata("result", "pass");
    let _ = bundle.finalize(Some(true));
}

#[test]
fn obs_smoke_anthropic_load_complete() {
    let harness = TestHarness::new("obs_smoke_anthropic_load_complete");
    let server = harness.start_mock_http_server();
    let setup = setup_anthropic(&server, "anth_lc");

    let ctx = context_with_observation(observation_load_complete());
    let events = drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));
    assert!(events > 0);
    assert_body_contains(&server, &["load_complete", "example.com/dashboard"]);
}

#[test]
fn obs_smoke_anthropic_near_budget() {
    let harness = TestHarness::new("obs_smoke_anthropic_near_budget");
    let server = harness.start_mock_http_server();
    let setup = setup_anthropic(&server, "anth_nb");

    let ctx = context_with_observation(observation_near_budget());
    drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));
    assert_body_contains(&server, &["console_warn", "additional events omitted"]);
}

// ═══════════════════════════════════════════════════════════════════════
// OpenAI/GPT-4
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn obs_smoke_openai_console_error() {
    let harness = TestHarness::new("obs_smoke_openai_console_error");
    let bundle = ArtifactBundle::new("obs_smoke_openai_console_error");
    bundle.add_metadata("provider", "openai");
    bundle.add_metadata("scenario", "console_error");
    bundle.add_metadata("bead", "bd-7x4");

    let server = harness.start_mock_http_server();
    let setup = setup_openai(&server, "oai_ce");

    let ctx = context_with_observation(observation_console_error());
    let events = drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));

    assert_body_contains(
        &server,
        &["[Browser Observation]", "console_error", "TypeError"],
    );

    bundle.record_protocol_trace(
        ProtocolDirection::Outgoing,
        "observation_smoke",
        &json!({"events": events}),
        None,
    );
    bundle.add_metadata("result", "pass");
    let _ = bundle.finalize(Some(true));
}

#[test]
fn obs_smoke_openai_load_complete() {
    let harness = TestHarness::new("obs_smoke_openai_load_complete");
    let server = harness.start_mock_http_server();
    let setup = setup_openai(&server, "oai_lc");

    let ctx = context_with_observation(observation_load_complete());
    drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));
    assert_body_contains(&server, &["load_complete"]);
}

#[test]
fn obs_smoke_openai_near_budget() {
    let harness = TestHarness::new("obs_smoke_openai_near_budget");
    let server = harness.start_mock_http_server();
    let setup = setup_openai(&server, "oai_nb");

    let ctx = context_with_observation(observation_near_budget());
    drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));
    assert_body_contains(&server, &["console_warn", "additional events omitted"]);
}

// ═══════════════════════════════════════════════════════════════════════
// Google/Gemini
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn obs_smoke_gemini_console_error() {
    let harness = TestHarness::new("obs_smoke_gemini_console_error");
    let bundle = ArtifactBundle::new("obs_smoke_gemini_console_error");
    bundle.add_metadata("provider", "gemini");
    bundle.add_metadata("scenario", "console_error");
    bundle.add_metadata("bead", "bd-7x4");

    let server = harness.start_mock_http_server();
    let setup = setup_gemini(&server, "gem_ce");

    let ctx = context_with_observation(observation_console_error());
    let events = drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));

    assert_body_contains(
        &server,
        &["[Browser Observation]", "console_error", "TypeError"],
    );

    bundle.record_protocol_trace(
        ProtocolDirection::Outgoing,
        "observation_smoke",
        &json!({"events": events}),
        None,
    );
    bundle.add_metadata("result", "pass");
    let _ = bundle.finalize(Some(true));
}

#[test]
fn obs_smoke_gemini_load_complete() {
    let harness = TestHarness::new("obs_smoke_gemini_load_complete");
    let server = harness.start_mock_http_server();
    let setup = setup_gemini(&server, "gem_lc");

    let ctx = context_with_observation(observation_load_complete());
    drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));
    assert_body_contains(&server, &["load_complete"]);
}

#[test]
fn obs_smoke_gemini_near_budget() {
    let harness = TestHarness::new("obs_smoke_gemini_near_budget");
    let server = harness.start_mock_http_server();
    let setup = setup_gemini(&server, "gem_nb");

    let ctx = context_with_observation(observation_near_budget());
    drive_to_done(setup.provider, ctx, stream_options(&setup.api_key));
    assert_body_contains(&server, &["console_warn", "additional events omitted"]);
}

// ═══════════════════════════════════════════════════════════════════════
// Cross-provider: observation text preserved across all three
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn obs_cross_provider_format_preserved() {
    let harness = TestHarness::new("obs_cross_provider_format_preserved");
    let server = harness.start_mock_http_server();

    let obs = Message::Custom(CustomMessage {
        content: "[Browser Observation]\n- console_error: ReferenceError: foo is not defined"
            .to_string(),
        custom_type: "browser_observations".to_string(),
        display: true,
        details: None,
        timestamp: 5000,
    });

    let anth = setup_anthropic(&server, "cross_anth");
    drive_to_done(
        anth.provider,
        context_with_observation(obs.clone()),
        stream_options(&anth.api_key),
    );

    let oai = setup_openai(&server, "cross_oai");
    drive_to_done(
        oai.provider,
        context_with_observation(obs.clone()),
        stream_options(&oai.api_key),
    );

    let gem = setup_gemini(&server, "cross_gem");
    drive_to_done(
        gem.provider,
        context_with_observation(obs),
        stream_options(&gem.api_key),
    );

    let reqs = server.requests();
    assert_eq!(reqs.len(), 3, "expected 3 provider requests");
    for (i, req) in reqs.iter().enumerate() {
        let body = String::from_utf8_lossy(&req.body);
        assert!(
            body.contains("ReferenceError: foo is not defined"),
            "provider {i} must include observation error text"
        );
        assert!(
            body.contains("[Browser Observation]"),
            "provider {i} must include observation header"
        );
    }

    harness.log().info_ctx(
        "obs.cross_provider",
        "all 3 providers preserve observation format",
        |ctx| {
            ctx.push((
                "providers".to_string(),
                "anthropic,openai,gemini".to_string(),
            ));
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Multi-turn observation accumulation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn obs_multi_turn_accumulation() {
    let harness = TestHarness::new("obs_multi_turn_accumulation");
    let server = harness.start_mock_http_server();
    let setup = setup_anthropic(&server, "multi");

    let context = Context::owned(
        Some("You are a helpful coding assistant.".to_string()),
        vec![
            Message::User(UserMessage {
                content: UserContent::Text("Navigate to the dashboard.".to_string()),
                timestamp: 0,
            }),
            observation_load_complete(),
            Message::User(UserMessage {
                content: UserContent::Text("Check for errors.".to_string()),
                timestamp: 3000,
            }),
            observation_console_error(),
        ],
        Vec::new(),
    );

    let events = drive_to_done(setup.provider, context, stream_options(&setup.api_key));
    assert!(events > 0);

    let reqs = server.requests();
    let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).expect("valid JSON");
    let messages = body["messages"].as_array().expect("messages array");

    assert_eq!(
        messages.len(),
        4,
        "context with 2 user + 2 observation messages"
    );

    let body_str = body.to_string();
    assert!(body_str.contains("load_complete"));
    assert!(body_str.contains("console_error"));
}
