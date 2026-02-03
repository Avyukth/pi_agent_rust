#![allow(clippy::similar_names)]
#![allow(clippy::unnecessary_literal_bound)]
#![allow(clippy::too_many_lines)]

use pi::agent::{Agent, AgentConfig, AgentSession};
use pi::auth::AuthStorage;
use pi::config::Config;
use pi::model::{AssistantMessage, ContentBlock, StopReason, TextContent, ToolCall, Usage};
use pi::provider::{Context, Provider, StreamOptions};
use pi::resources::ResourceLoader;
use pi::rpc::{RpcOptions, run};
use pi::session::{Session, SessionMessage};
use pi::tools::ToolRegistry;
use std::pin::Pin;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct MockProvider;

#[async_trait::async_trait]
impl Provider for MockProvider {
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "mock"
    }

    #[allow(clippy::unnecessary_literal_bound)]
    fn api(&self) -> &str {
        "mock"
    }

    #[allow(clippy::unnecessary_literal_bound)]
    fn model_id(&self) -> &str {
        "mock-model"
    }

    async fn stream(
        &self,
        _context: &Context,
        _options: &StreamOptions,
    ) -> pi::error::Result<
        Pin<Box<dyn futures::Stream<Item = pi::error::Result<pi::model::StreamEvent>> + Send>>,
    > {
        let now = chrono::Utc::now().timestamp_millis();
        let message = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("hello"))],
            api: "mock".to_string(),
            provider: "mock".to_string(),
            model: "mock-model".to_string(),
            usage: Usage {
                input: 10,
                output: 5,
                total_tokens: 15,
                ..Usage::default()
            },
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: now,
        };

        let events = vec![Ok(pi::model::StreamEvent::Done {
            reason: StopReason::Stop,
            message,
        })];

        Ok(Box::pin(futures::stream::iter(events)))
    }
}

async fn recv_line(rx: &Arc<Mutex<Receiver<String>>>, label: &str) -> String {
    let start = Instant::now();
    loop {
        let recv_result = {
            let rx = rx.lock().expect("lock rpc output receiver");
            rx.try_recv()
        };

        match recv_result {
            Ok(line) => return line,
            Err(TryRecvError::Disconnected) => panic!("{label}: output channel disconnected"),
            Err(TryRecvError::Empty) => {}
        }

        assert!(
            start.elapsed() <= Duration::from_secs(2),
            "{label}: timed out waiting for output"
        );

        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn rpc_get_state_and_prompt() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("build test runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let tools = ToolRegistry::new(&[], &std::env::current_dir().unwrap(), None);
        let mut config = AgentConfig::default();
        config.stream_options.api_key = Some("test-key".to_string());
        let agent = Agent::new(provider, tools, config);

        let mut session = Session::in_memory();
        session.header.provider = Some("mock".to_string());
        session.header.model_id = Some("mock-model".to_string());
        session.header.thinking_level = Some("off".to_string());

        let agent_session = AgentSession::new(agent, session, false);

        let auth_dir = tempfile::tempdir().unwrap();
        let auth = AuthStorage::load(auth_dir.path().join("auth.json")).unwrap();

        let options = RpcOptions {
            config: Config::default(),
            resources: ResourceLoader::empty(false),
            available_models: Vec::new(),
            scoped_models: Vec::new(),
            auth,
            runtime_handle: handle.clone(),
        };

        let (in_tx, in_rx) = asupersync::channel::mpsc::channel::<String>(16);
        let (out_tx, out_rx) = std::sync::mpsc::channel::<String>();
        let out_rx = Arc::new(Mutex::new(out_rx));

        let server = handle.spawn(async move { run(agent_session, options, in_rx, out_tx).await });

        // get_state
        let cx = asupersync::Cx::for_testing();
        in_tx
            .send(&cx, r#"{"id":"1","type":"get_state"}"#.to_string())
            .await
            .expect("send get_state");

        let line = recv_line(&out_rx, "get_state response").await;
        let get_state_response: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(get_state_response["type"], "response");
        assert_eq!(get_state_response["command"], "get_state");
        assert_eq!(get_state_response["success"], true);
        let get_state_data = get_state_response["data"].as_object().unwrap();
        assert!(get_state_data.get("sessionFile").is_some());
        assert!(get_state_response["data"]["sessionFile"].is_null());
        assert!(get_state_data.get("sessionName").is_some());
        assert!(get_state_response["data"]["sessionName"].is_null());
        assert!(get_state_data.get("model").is_some());
        assert!(get_state_response["data"]["model"].is_null());

        // prompt
        in_tx
            .send(
                &cx,
                r#"{"id":"2","type":"prompt","message":"hi"}"#.to_string(),
            )
            .await
            .expect("send prompt");

        let line = recv_line(&out_rx, "prompt response").await;
        let prompt_resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(prompt_resp["type"], "response");
        assert_eq!(prompt_resp["command"], "prompt");
        assert_eq!(prompt_resp["success"], true);

        // Collect events until agent_end.
        let mut saw_agent_end = false;
        let mut message_end_count = 0usize;
        for _ in 0..10 {
            let line = recv_line(&out_rx, "event stream").await;
            let event: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            if event["type"] == "message_end" {
                message_end_count += 1;
            }
            if event["type"] == "agent_end" {
                saw_agent_end = true;
                break;
            }
        }
        assert!(saw_agent_end, "did not receive agent_end event");
        assert!(
            message_end_count >= 2,
            "expected at least user+assistant message_end events"
        );

        // get_session_stats
        in_tx
            .send(&cx, r#"{"id":"3","type":"get_session_stats"}"#.to_string())
            .await
            .expect("send get_session_stats");

        let line = recv_line(&out_rx, "get_session_stats response").await;
        let get_stats_response: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(get_stats_response["type"], "response");
        assert_eq!(get_stats_response["command"], "get_session_stats");
        assert_eq!(get_stats_response["success"], true);
        let get_stats_data = get_stats_response["data"].as_object().unwrap();
        assert!(get_stats_data.get("sessionFile").is_some());
        assert!(get_stats_response["data"]["sessionFile"].is_null());
        assert_eq!(get_stats_response["data"]["userMessages"], 1);
        assert_eq!(get_stats_response["data"]["assistantMessages"], 1);
        assert_eq!(get_stats_response["data"]["toolCalls"], 0);
        assert_eq!(get_stats_response["data"]["toolResults"], 0);
        assert_eq!(get_stats_response["data"]["totalMessages"], 2);
        assert_eq!(get_stats_response["data"]["tokens"]["input"], 10);
        assert_eq!(get_stats_response["data"]["tokens"]["output"], 5);
        assert_eq!(get_stats_response["data"]["tokens"]["total"], 15);

        drop(in_tx);

        let result = server.await;
        assert!(result.is_ok(), "rpc server returned error: {result:?}");
    });
}

#[test]
fn rpc_session_stats_counts_tool_calls_and_results() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("build test runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let tools = ToolRegistry::new(&[], &std::env::current_dir().unwrap(), None);
        let mut config = AgentConfig::default();
        config.stream_options.api_key = Some("test-key".to_string());
        let agent = Agent::new(provider, tools, config);

        let now = chrono::Utc::now().timestamp_millis();
        let mut session = Session::in_memory();
        session.header.provider = Some("mock".to_string());
        session.header.model_id = Some("mock-model".to_string());
        session.header.thinking_level = Some("off".to_string());
        session.append_message(SessionMessage::User {
            content: pi::model::UserContent::Text("hi".to_string()),
            timestamp: Some(now),
        });
        session.append_message(SessionMessage::Assistant {
            message: AssistantMessage {
                content: vec![ContentBlock::ToolCall(ToolCall {
                    id: "tc1".to_string(),
                    name: "read".to_string(),
                    arguments: serde_json::json!({ "path": "test.txt" }),
                    thought_signature: None,
                })],
                api: "mock".to_string(),
                provider: "mock".to_string(),
                model: "mock-model".to_string(),
                usage: Usage {
                    input: 2,
                    output: 3,
                    total_tokens: 5,
                    ..Usage::default()
                },
                stop_reason: StopReason::ToolUse,
                error_message: None,
                timestamp: now,
            },
        });
        session.append_message(SessionMessage::ToolResult {
            tool_call_id: "tc1".to_string(),
            tool_name: "read".to_string(),
            content: vec![ContentBlock::Text(TextContent::new("ok"))],
            details: None,
            is_error: false,
            timestamp: Some(now),
        });

        let agent_session = AgentSession::new(agent, session, false);

        let auth_dir = tempfile::tempdir().unwrap();
        let auth = AuthStorage::load(auth_dir.path().join("auth.json")).unwrap();

        let options = RpcOptions {
            config: Config::default(),
            resources: ResourceLoader::empty(false),
            available_models: Vec::new(),
            scoped_models: Vec::new(),
            auth,
            runtime_handle: handle.clone(),
        };

        let (in_tx, in_rx) = asupersync::channel::mpsc::channel::<String>(16);
        let (out_tx, out_rx) = std::sync::mpsc::channel::<String>();
        let out_rx = Arc::new(Mutex::new(out_rx));

        let server = handle.spawn(async move { run(agent_session, options, in_rx, out_tx).await });

        let cx = asupersync::Cx::for_testing();
        in_tx
            .send(&cx, r#"{"id":"1","type":"get_session_stats"}"#.to_string())
            .await
            .expect("send get_session_stats");

        let line = recv_line(&out_rx, "get_session_stats response").await;
        let stats_resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(stats_resp["type"], "response");
        assert_eq!(stats_resp["command"], "get_session_stats");
        assert_eq!(stats_resp["success"], true);
        let stats_data = stats_resp["data"].as_object().unwrap();
        assert!(stats_data.get("sessionFile").is_some());
        assert!(stats_resp["data"]["sessionFile"].is_null());
        assert_eq!(stats_resp["data"]["userMessages"], 1);
        assert_eq!(stats_resp["data"]["assistantMessages"], 1);
        assert_eq!(stats_resp["data"]["toolCalls"], 1);
        assert_eq!(stats_resp["data"]["toolResults"], 1);
        assert_eq!(stats_resp["data"]["totalMessages"], 3);
        assert_eq!(stats_resp["data"]["tokens"]["total"], 5);

        drop(in_tx);
        let result = server.await;
        assert!(result.is_ok(), "rpc server returned error: {result:?}");
    });
}
