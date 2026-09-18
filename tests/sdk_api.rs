use pi::sdk;
use serde_json::json;
use std::path::PathBuf;

const fn assert_clone_debug_send_sync<T: Clone + std::fmt::Debug + Send + Sync>() {}

#[test]
fn sdk_surface_exports_core_types() {
    let _: Option<sdk::ModelRegistry> = None;
    let _: Option<sdk::Config> = None;
    let _: Option<sdk::Session> = None;
    let _: Option<sdk::Agent> = None;
    let _: Option<sdk::AgentSession> = None;
    let _: sdk::ProviderContext = sdk::ProviderContext::default();
    let _: sdk::StreamOptions = sdk::StreamOptions::default();

    let _: sdk::ToolDefinition = sdk::ToolDef {
        name: "read".to_string(),
        description: "Read file".to_string(),
        parameters: json!({"type": "object"}),
    };
}

#[test]
fn sdk_public_types_have_expected_traits() {
    assert_clone_debug_send_sync::<sdk::Message>();
    assert_clone_debug_send_sync::<sdk::ContentBlock>();
    assert_clone_debug_send_sync::<sdk::ToolCall>();
    assert_clone_debug_send_sync::<sdk::ToolDefinition>();
    assert_clone_debug_send_sync::<sdk::AgentEvent>();
    assert_clone_debug_send_sync::<sdk::RpcModelInfo>();
    assert_clone_debug_send_sync::<sdk::RpcSessionState>();
    assert_clone_debug_send_sync::<sdk::RpcSessionStats>();
    assert_clone_debug_send_sync::<sdk::RpcCommandInfo>();
    assert_clone_debug_send_sync::<sdk::RpcExtensionUiResponse>();
}

#[test]
fn sdk_message_round_trips_via_serde() {
    let message = sdk::Message::User(sdk::UserMessage {
        content: sdk::UserContent::Text("hello".to_string()),
        timestamp: 1234,
    });

    let encoded = serde_json::to_value(&message).expect("serialize sdk::Message");
    let decoded: sdk::Message = serde_json::from_value(encoded.clone()).expect("deserialize");
    let reencoded = serde_json::to_value(decoded).expect("re-serialize");

    assert_eq!(reencoded, encoded);
}

#[test]
fn sdk_rpc_state_round_trips_via_serde() {
    let value = json!({
        "model": {
            "id": "claude-sonnet-4-20250514",
            "name": "Claude Sonnet 4",
            "api": "anthropic-messages",
            "provider": "anthropic",
            "baseUrl": "https://api.anthropic.com",
            "reasoning": true,
            "input": ["text", "image"],
            "contextWindow": 200_000,
            "maxTokens": 8192,
            "cost": {
                "input": 3.0,
                "output": 15.0,
                "cacheRead": 0.3,
                "cacheWrite": 3.75
            }
        },
        "thinkingLevel": "low",
        "isStreaming": false,
        "isCompacting": false,
        "steeringMode": "all",
        "followUpMode": "one-at-a-time",
        "sessionFile": null,
        "sessionId": "session-123",
        "sessionName": "demo",
        "autoCompactionEnabled": true,
        "autoRetryEnabled": false,
        "messageCount": 2,
        "pendingMessageCount": 0,
        "durabilityMode": "balanced"
    });

    let state: sdk::RpcSessionState =
        serde_json::from_value(value.clone()).expect("deserialize RpcSessionState");
    let reencoded = serde_json::to_value(state).expect("serialize RpcSessionState");
    assert_eq!(reencoded, value);
}

#[test]
fn sdk_extension_ui_response_round_trips_via_serde() {
    let value = json!({
        "kind": "confirmed",
        "confirmed": true
    });
    let decoded: sdk::RpcExtensionUiResponse =
        serde_json::from_value(value.clone()).expect("deserialize RpcExtensionUiResponse");
    let reencoded = serde_json::to_value(decoded).expect("serialize RpcExtensionUiResponse");
    assert_eq!(reencoded, value);
}

#[test]
fn sdk_rpc_transport_client_typed_methods_work_with_subprocess_bridge() {
    if !cfg!(unix) {
        return;
    }

    let script = r#"
while IFS= read -r line; do
  id=$(printf '%s\n' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  cmd=$(printf '%s\n' "$line" | sed -n 's/.*"type":"\([^"]*\)".*/\1/p')
  case "$cmd" in
    get_state)
      printf '{"type":"response","id":"%s","command":"get_state","success":true,"data":{"model":null,"thinkingLevel":"off","isStreaming":false,"isCompacting":false,"steeringMode":"all","followUpMode":"all","sessionFile":null,"sessionId":"sess-1","sessionName":null,"autoCompactionEnabled":true,"autoRetryEnabled":true,"messageCount":0,"pendingMessageCount":0,"durabilityMode":"balanced"}}\n' "$id"
      ;;
    get_available_models)
      printf '{"type":"response","id":"%s","command":"get_available_models","success":true,"data":{"models":[{"id":"m1","name":"Model 1","api":"anthropic-messages","provider":"anthropic","baseUrl":"https://api.example.com","reasoning":false,"input":["text"],"contextWindow":8192,"maxTokens":1024,"cost":{"input":1.0,"output":2.0,"cacheRead":0.0,"cacheWrite":0.0}}]}}\n' "$id"
      ;;
    set_model)
      printf '{"type":"response","id":"%s","command":"set_model","success":true,"data":{"id":"m1","name":"Model 1","api":"anthropic-messages","provider":"anthropic","baseUrl":"https://api.example.com","reasoning":false,"input":["text"],"contextWindow":8192,"maxTokens":1024,"cost":{"input":1.0,"output":2.0,"cacheRead":0.0,"cacheWrite":0.0}}}\n' "$id"
      ;;
    prompt)
      printf '{"type":"response","id":"%s","command":"prompt","success":true}\n' "$id"
      printf '{"type":"agent_start","sessionId":"sess-1"}\n'
      printf '{"type":"agent_end","sessionId":"sess-1","messages":[]}\n'
      ;;
    extension_ui_response)
      printf '{"type":"response","id":"%s","command":"extension_ui_response","success":true,"data":{"resolved":true}}\n' "$id"
      ;;
    *)
      printf '{"type":"response","id":"%s","command":"%s","success":true}\n' "$id" "$cmd"
      ;;
  esac
done
"#;

    let options = sdk::RpcTransportOptions {
        binary_path: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_string(), script.to_string()],
        cwd: None,
    };
    let mut client = sdk::RpcTransportClient::connect(options).expect("connect rpc subprocess");

    futures::executor::block_on(async {
        let state = client.get_state().await.expect("get_state");
        assert_eq!(state.session_id, "sess-1");
        assert_eq!(state.thinking_level, "off");
        assert!(state.auto_retry_enabled);
        assert_eq!(state.durability_mode, "balanced");

        let models = client
            .get_available_models()
            .await
            .expect("get_available_models");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "m1");

        let model = client
            .set_model("anthropic", "m1")
            .await
            .expect("set_model");
        assert_eq!(model.provider, "anthropic");
        assert_eq!(model.id, "m1");

        let events = client
            .prompt_with_options("hello", None, Some("steer"))
            .await
            .expect("prompt_with_options");
        assert!(
            events.iter().any(
                |event| event.get("type").and_then(serde_json::Value::as_str) == Some("agent_end")
            ),
            "expected prompt event stream to terminate with agent_end"
        );

        let resolved = client
            .extension_ui_response(
                "req-1",
                1,
                sdk::RpcExtensionUiResponse::Confirmed { confirmed: true },
            )
            .await
            .expect("extension_ui_response");
        assert!(resolved);
    });
}

#[cfg(unix)]
#[test]
fn sdk_rpc_prompt_streams_live_and_preserves_pre_ack_events() {
    let script = r#"
IFS= read -r line
id=$(printf '%s\n' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
printf '{"type":"agent_start","sessionId":"early"}\n'
printf '{"type":"response","id":"%s","command":"prompt","success":true}\n' "$id"
printf '{"type":"message_update","delta":"first"}\n'
sleep 1
printf '{"type":"agent_end","sessionId":"early","messages":[]}\n'
"#;
    let options = sdk::RpcTransportOptions {
        binary_path: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), script.into()],
        cwd: None,
    };
    let mut client = sdk::RpcTransportClient::connect(options).expect("connect");
    let started = std::time::Instant::now();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let times = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_cb = std::sync::Arc::clone(&seen);
    let times_cb = std::sync::Arc::clone(&times);
    let events = futures::executor::block_on(client.prompt_with_options_streaming(
        "hello",
        None,
        None,
        move |event| {
            seen_cb
                .lock()
                .unwrap()
                .push(event["type"].as_str().unwrap().to_string());
            times_cb.lock().unwrap().push(started.elapsed());
        },
    ))
    .expect("streaming prompt");
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["agent_start", "message_update", "agent_end"]
    );
    assert_eq!(events.len(), 3);
    assert!(
        times.lock().unwrap()[1] < std::time::Duration::from_millis(700),
        "message_update must be delivered before the delayed agent_end"
    );
}

#[cfg(unix)]
#[test]
fn sdk_rpc_prompt_rejects_wrong_ack_and_reserved_request_fields() {
    let script = r#"
while IFS= read -r line; do
  id=$(printf '%s\n' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  printf '{"type":"response","id":"%s","command":"wrong","success":true}\n' "$id"
done
"#;
    let options = sdk::RpcTransportOptions {
        binary_path: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), script.into()],
        cwd: None,
    };
    let mut client = sdk::RpcTransportClient::connect(options).expect("connect");
    let error = futures::executor::block_on(client.prompt("hello")).expect_err("wrong command");
    assert!(error.to_string().contains("wrong command"), "{error}");

    let options = sdk::RpcTransportOptions {
        binary_path: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), "sleep 5".into()],
        cwd: None,
    };
    let mut client = sdk::RpcTransportClient::connect(options).expect("connect");
    let mut payload = serde_json::Map::new();
    payload.insert("id".into(), json!("caller-controlled"));
    let error = futures::executor::block_on(client.request("get_state", payload))
        .expect_err("reserved id must be rejected before write");
    assert!(error.to_string().contains("reserved type/id"), "{error}");
}

#[cfg(unix)]
#[test]
fn sdk_rpc_control_handle_can_abort_during_a_live_prompt() {
    let script = r#"
IFS= read -r prompt
prompt_id=$(printf '%s\n' "$prompt" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
printf '{"type":"response","id":"%s","command":"prompt","success":true}\n' "$prompt_id"
printf '{"type":"agent_start","sessionId":"sess-control"}\n'
IFS= read -r control
control_id=$(printf '%s\n' "$control" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
control_type=$(printf '%s\n' "$control" | sed -n 's/.*"type":"\([^"]*\)".*/\1/p')
printf '{"type":"response","id":"%s","command":"%s","success":true}\n' "$control_id" "$control_type"
printf '{"type":"agent_end","sessionId":"sess-control","control":"%s","messages":[]}\n' "$control_type"
"#;
    let options = sdk::RpcTransportOptions {
        binary_path: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), script.into()],
        cwd: None,
    };
    let mut client = sdk::RpcTransportClient::connect(options).expect("connect");
    let control = client.control_handle();
    let control_id = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let stored = std::sync::Arc::clone(&control_id);
    let events = futures::executor::block_on(client.prompt_with_options_streaming(
        "hello",
        None,
        None,
        move |event| {
            if event["type"] == "agent_start" {
                let id = control
                    .abort()
                    .expect("dispatch abort while prompt owns stdout");
                *stored.lock().unwrap() = Some(id);
            }
        },
    ))
    .expect("prompt completes after abort acknowledgement");
    assert_eq!(events.last().unwrap()["control"], "abort");
    assert!(
        control_id
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|id| id.starts_with("rpc-")),
        "control command must receive an SDK-owned unique request id"
    );
}

#[cfg(unix)]
#[test]
fn sdk_rpc_control_handle_ids_share_the_client_sequence() {
    let options = sdk::RpcTransportOptions {
        binary_path: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), "cat >/dev/null".into()],
        cwd: None,
    };
    let client = sdk::RpcTransportClient::connect(options).expect("connect");
    let control = client.control_handle();
    let first = control.steer("one").expect("steer dispatch");
    let second = control.follow_up("two").expect("follow-up dispatch");
    let third = control.abort().expect("abort dispatch");
    assert_eq!(
        [first.as_str(), second.as_str(), third.as_str()],
        ["rpc-1", "rpc-2", "rpc-3"]
    );
}
