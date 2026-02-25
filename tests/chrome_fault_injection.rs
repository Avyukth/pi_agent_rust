//! Deterministic fault-injection harness for `ChromeBridge` + Native Host tests (bd-1xz.3).
//!
//! Provides a configurable mock host that injects specific faults at precise
//! points in the handshake lifecycle. Fault scenarios are deterministic — given
//! the same [`FaultScript`], the mock produces identical behavior every run,
//! enabling reproducible CI regression detection.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐       Unix Socket       ┌──────────────────┐
//! │ ChromeBridge  │ ─────────────────────── │ FaultMockHost    │
//! │ (under test)  │                         │ (this harness)   │
//! └──────────────┘                         └──────────────────┘
//!                                           FaultScript decides
//!                                           what to send (or not)
//! ```
//!
//! # Safety Invariants Verified
//!
//! - **S5**: Auth rejection faults produce correct error variants
//! - **S6**: Connection drop faults produce IO errors, not panics
//! - **S7**: Frame codec faults produce Frame errors, not panics
//! - **S8**: Failure streak policy disables after N consecutive failures
//! - **S9**: Happy-path through fault harness matches direct mock behavior

use asupersync::runtime::RuntimeBuilder;
use pi::chrome::protocol;
use pi::chrome::{ChromeBridge, ChromeBridgeConfig, ChromeBridgeError, ConnectionState};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::Path;
use std::thread::JoinHandle;

// ═══════════════════════════════════════════════════════════════════════════
// Fault Harness Types
// ═══════════════════════════════════════════════════════════════════════════

/// A single fault action the mock host can take at a specific lifecycle point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum FaultKind {
    /// Send a valid `AuthOk` response (no fault — happy path).
    AuthOk,
    /// Send an `AuthBusy` response, rejecting the claim.
    AuthBusy {
        claimed_by_session: String,
        claimed_by_client: String,
    },
    /// Send a protocol mismatch error response.
    ProtocolMismatch { message: String },
    /// Send a malformed (invalid JSON) frame.
    MalformedFrame { garbage: Vec<u8> },
    /// Close the socket immediately after accept (before reading auth).
    DropBeforeAuth,
    /// Read the auth claim, then close without responding.
    DropAfterAuth,
    /// Send an unexpected message type as the auth response.
    UnexpectedMessageType,
    /// Send an `AuthOk` with a protocol version outside supported range.
    AuthOkBadProtocol { protocol_version: u16 },
}

/// An ordered sequence of fault actions. The mock host executes the first
/// action on the first connection, the second on the next, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FaultScript {
    actions: Vec<FaultKind>,
}

impl FaultScript {
    fn single(action: FaultKind) -> Self {
        Self {
            actions: vec![action],
        }
    }

    const fn sequence(actions: Vec<FaultKind>) -> Self {
        Self { actions }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// JSONL Outcome Recording
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome of a single fault-injection test scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestOutcome {
    scenario: String,
    script: FaultScript,
    passed: bool,
    assertion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    timestamp: String,
}

impl TestOutcome {
    fn pass(
        scenario: impl Into<String>,
        script: FaultScript,
        assertion: impl Into<String>,
    ) -> Self {
        Self {
            scenario: scenario.into(),
            script,
            passed: true,
            assertion: assertion.into(),
            error: None,
            timestamp: now_epoch_str(),
        }
    }

    fn fail(
        scenario: impl Into<String>,
        script: FaultScript,
        assertion: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            scenario: scenario.into(),
            script,
            passed: false,
            assertion: assertion.into(),
            error: Some(error.into()),
            timestamp: now_epoch_str(),
        }
    }
}

/// Append a test outcome as a JSONL line to the given file.
fn write_outcome_jsonl(path: &Path, outcome: &TestOutcome) -> std::io::Result<()> {
    let line = serde_json::to_string(outcome)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn now_epoch_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", d.as_secs())
}

// ═══════════════════════════════════════════════════════════════════════════
// Fault Mock Host
// ═══════════════════════════════════════════════════════════════════════════

/// Event logged by the fault mock host for each connection attempt.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FaultHostEvent {
    connection_index: usize,
    action: FaultKind,
    outcome: String,
}

/// Spawn a configurable mock host that follows a [`FaultScript`].
///
/// Binds a Unix socket and spawns a thread that accepts connections according
/// to the script. The thread terminates after all script actions are exhausted.
fn spawn_fault_host(socket_path: &Path, script: FaultScript) -> JoinHandle<Vec<FaultHostEvent>> {
    let listener = StdUnixListener::bind(socket_path).expect("bind fault mock unix listener");
    std::thread::spawn(move || {
        let mut events = Vec::new();
        for (idx, action) in script.actions.iter().enumerate() {
            let Ok((stream, _)) = listener.accept() else {
                events.push(FaultHostEvent {
                    connection_index: idx,
                    action: action.clone(),
                    outcome: "accept_failed".to_string(),
                });
                break;
            };

            let outcome = execute_fault_action(stream, action);
            events.push(FaultHostEvent {
                connection_index: idx,
                action: action.clone(),
                outcome,
            });
        }
        events
    })
}

/// Build an `AuthOk` message from a claim, optionally overriding the negotiated protocol version.
fn build_auth_ok(claim: protocol::AuthClaim, negotiated_protocol: u16) -> protocol::MessageType {
    let host_epoch = format!("{}-epoch", claim.host_id);
    protocol::MessageType::AuthOk(protocol::AuthOk {
        version: protocol::PROTOCOL_VERSION_V1,
        host_id: claim.host_id,
        claimed_by: protocol::ClaimedBy {
            pi_session_id: claim.pi_session_id,
            client_instance_id: claim.client_instance_id,
        },
        host_epoch,
        protocol: negotiated_protocol,
        capabilities: claim.want_capabilities,
        lease_ttl_ms: 30_000,
    })
}

fn execute_fault_action(stream: std::os::unix::net::UnixStream, action: &FaultKind) -> String {
    match action {
        FaultKind::DropBeforeAuth => {
            drop(stream);
            "dropped_before_auth".to_string()
        }
        FaultKind::DropAfterAuth => {
            let result = read_auth_claim(&stream);
            drop(stream);
            match result {
                Ok(_) => "dropped_after_auth".to_string(),
                Err(e) => format!("read_error:{e}"),
            }
        }
        FaultKind::AuthOk => {
            let claim = match read_auth_claim(&stream) {
                Ok(c) => c,
                Err(e) => return format!("read_error:{e}"),
            };
            let response = build_auth_ok(claim, protocol::PROTOCOL_VERSION_V1);
            write_response(&stream, &response)
        }
        FaultKind::AuthBusy {
            claimed_by_session,
            claimed_by_client,
        } => {
            let claim = match read_auth_claim(&stream) {
                Ok(c) => c,
                Err(e) => return format!("read_error:{e}"),
            };
            let response = protocol::MessageType::AuthBusy(protocol::AuthBusy {
                version: protocol::PROTOCOL_VERSION_V1,
                host_id: claim.host_id,
                claimed_by: protocol::ClaimedBy {
                    pi_session_id: claimed_by_session.clone(),
                    client_instance_id: claimed_by_client.clone(),
                },
            });
            write_response(&stream, &response)
        }
        FaultKind::ProtocolMismatch { message } => {
            let _claim = match read_auth_claim(&stream) {
                Ok(c) => c,
                Err(e) => return format!("read_error:{e}"),
            };
            let response = protocol::MessageType::Response(protocol::ResponseEnvelope::Error(
                protocol::ErrorResponse {
                    version: protocol::PROTOCOL_VERSION_V1,
                    id: "handshake".to_string(),
                    ok: false,
                    error: protocol::ProtocolErrorDetail {
                        code: protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                        message: message.clone(),
                        retryable: false,
                    },
                },
            ));
            write_response(&stream, &response)
        }
        FaultKind::MalformedFrame { garbage } => {
            let _claim = match read_auth_claim(&stream) {
                Ok(c) => c,
                Err(e) => return format!("read_error:{e}"),
            };
            let mut writer = &stream;
            let mut payload = garbage.clone();
            payload.push(b'\n');
            match writer.write_all(&payload) {
                Ok(()) => "sent_malformed".to_string(),
                Err(e) => format!("write_error:{e}"),
            }
        }
        FaultKind::UnexpectedMessageType => {
            let _claim = match read_auth_claim(&stream) {
                Ok(c) => c,
                Err(e) => return format!("read_error:{e}"),
            };
            let response = protocol::MessageType::Request(protocol::Request {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "unexpected".to_string(),
                op: "navigate".to_string(),
                payload: serde_json::json!({}),
            });
            write_response(&stream, &response)
        }
        FaultKind::AuthOkBadProtocol { protocol_version } => {
            let claim = match read_auth_claim(&stream) {
                Ok(c) => c,
                Err(e) => return format!("read_error:{e}"),
            };
            let response = build_auth_ok(claim, *protocol_version);
            write_response(&stream, &response)
        }
    }
}

fn read_auth_claim(stream: &std::os::unix::net::UnixStream) -> Result<protocol::AuthClaim, String> {
    let mut reader = std::io::BufReader::new(stream);
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .map_err(|e| format!("read: {e}"))?;

    let (message, _) = protocol::decode_frame::<protocol::MessageType>(&line)
        .map_err(|e| format!("decode: {e}"))?
        .ok_or_else(|| "incomplete frame".to_string())?;

    match message {
        protocol::MessageType::AuthClaim(claim) => Ok(claim),
        other => Err(format!("expected AuthClaim, got {other:?}")),
    }
}

fn write_response(
    stream: &std::os::unix::net::UnixStream,
    message: &protocol::MessageType,
) -> String {
    let frame = match protocol::encode_frame(message) {
        Ok(f) => f,
        Err(e) => return format!("encode_error:{e}"),
    };
    let mut writer = stream;
    match writer.write_all(&frame) {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("write_error:{e}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build");
    runtime.block_on(future)
}

fn test_bridge_config(discovery_dir: &Path) -> ChromeBridgeConfig {
    ChromeBridgeConfig {
        pi_session_id: "fault-test-session".to_string(),
        client_instance_id: "fault-test-client".to_string(),
        discovery_dir: discovery_dir.to_path_buf(),
        want_capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
        max_reconnect_attempts: 3,
        reconnect_backoff_ms: 1, // fast for tests
    }
}

fn make_test_record(socket_path: &Path, host_id: &str) -> pi::chrome::DiscoveryRecord {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX);

    pi::chrome::DiscoveryRecord {
        host_id: host_id.to_string(),
        host_epoch: format!("{host_id}-epoch"),
        socket_path: socket_path.to_path_buf(),
        token: "secret-token".to_string(),
        protocol_min: protocol::PROTOCOL_MIN_SUPPORTED,
        protocol_max: protocol::PROTOCOL_MAX_SUPPORTED,
        capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
        claimed_by: None,
        lease_expires_at_ms: None,
        expires_at_ms: Some(now_ms + 60_000),
    }
}

fn write_test_discovery(dir: &Path, record: &pi::chrome::DiscoveryRecord) {
    let filename = format!("pi-chrome-host-{}.discovery.json", record.host_id);
    std::fs::write(
        dir.join(filename),
        serde_json::to_vec(record).expect("serialize discovery record"),
    )
    .expect("write discovery record");
}

// ═══════════════════════════════════════════════════════════════════════════
// S5: Auth Rejection Faults
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fault_auth_busy_returns_auth_busy_error() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("busy.sock");
        let record = make_test_record(&socket_path, "host-busy");

        let script = FaultScript::single(FaultKind::AuthBusy {
            claimed_by_session: "other-session".to_string(),
            claimed_by_client: "other-client".to_string(),
        });
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("auth_busy must reject");

        assert!(
            matches!(err, ChromeBridgeError::AuthBusy { .. }),
            "expected AuthBusy, got {err:?}"
        );
        assert_eq!(bridge.status().state, ConnectionState::Disconnected);

        let events = server.join().expect("server join");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "ok");
    });
}

#[test]
fn fault_protocol_mismatch_returns_mismatch_error() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("mismatch.sock");
        let record = make_test_record(&socket_path, "host-mismatch");

        let script = FaultScript::single(FaultKind::ProtocolMismatch {
            message: "unsupported v99".to_string(),
        });
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("protocol mismatch must fail");

        assert!(
            matches!(err, ChromeBridgeError::ProtocolMismatch(_)),
            "expected ProtocolMismatch, got {err:?}"
        );

        server.join().expect("server join");
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// S6: Connection Drop Faults
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fault_drop_before_auth_causes_io_error() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("drop-before.sock");
        let record = make_test_record(&socket_path, "host-drop-before");

        let script = FaultScript::single(FaultKind::DropBeforeAuth);
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("drop before auth must fail");

        assert!(
            matches!(err, ChromeBridgeError::Io(_)),
            "expected Io error from early drop, got {err:?}"
        );
        assert_eq!(bridge.status().state, ConnectionState::Disconnected);

        server.join().expect("server join");
    });
}

#[test]
fn fault_drop_after_auth_causes_io_error() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("drop-after.sock");
        let record = make_test_record(&socket_path, "host-drop-after");

        let script = FaultScript::single(FaultKind::DropAfterAuth);
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("drop after auth must fail");

        assert!(
            matches!(err, ChromeBridgeError::Io(_)),
            "expected Io error from post-auth drop, got {err:?}"
        );

        server.join().expect("server join");
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// S7: Frame Codec Faults
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fault_malformed_frame_causes_codec_error() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("malformed.sock");
        let record = make_test_record(&socket_path, "host-malformed");

        let script = FaultScript::single(FaultKind::MalformedFrame {
            garbage: b"{{not json at all".to_vec(),
        });
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("malformed frame must fail");

        assert!(
            matches!(err, ChromeBridgeError::Frame(_)),
            "expected Frame codec error, got {err:?}"
        );

        server.join().expect("server join");
    });
}

#[test]
fn fault_unexpected_message_type_causes_handshake_error() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("unexpected.sock");
        let record = make_test_record(&socket_path, "host-unexpected");

        let script = FaultScript::single(FaultKind::UnexpectedMessageType);
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("unexpected message type must fail");

        assert!(
            matches!(err, ChromeBridgeError::UnexpectedHandshakeMessage(_)),
            "expected UnexpectedHandshakeMessage, got {err:?}"
        );

        server.join().expect("server join");
    });
}

#[test]
fn fault_auth_ok_bad_protocol_causes_protocol_mismatch() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("badproto.sock");
        let record = make_test_record(&socket_path, "host-badproto");

        let script = FaultScript::single(FaultKind::AuthOkBadProtocol {
            protocol_version: 99,
        });
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("bad protocol in AuthOk must fail");

        assert!(
            matches!(err, ChromeBridgeError::ProtocolMismatch(_)),
            "expected ProtocolMismatch, got {err:?}"
        );

        server.join().expect("server join");
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// S8: Failure Streak / Disable Policy
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fault_three_consecutive_failures_disable_browser_tools() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");

        // Create 3 sockets, each will drop before auth.
        // spawn_fault_host binds the socket, making it exist for discovery.
        let mut servers = Vec::new();
        for i in 0..3 {
            let host_id = format!("host-fail-{i}");
            let socket_path = tempdir.path().join(format!("fail-{i}.sock"));
            let record = make_test_record(&socket_path, &host_id);
            write_test_discovery(tempdir.path(), &record);

            let script = FaultScript::single(FaultKind::DropBeforeAuth);
            servers.push(spawn_fault_host(&socket_path, script));
        }

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));

        // Three failing connect() calls should trip the disable policy.
        for i in 0..3u8 {
            let _ = bridge.connect().await;
            let status = bridge.status();
            if i < 2 {
                assert!(
                    !status.browser_tools_disabled,
                    "should not be disabled after {} failures",
                    i + 1
                );
            }
        }

        let status = bridge.status();
        assert!(
            status.browser_tools_disabled,
            "browser tools must be disabled after 3 consecutive failures"
        );
        assert_eq!(status.state, ConnectionState::Disabled);

        // Further connect attempts should immediately return BrowserToolsDisabled.
        let err = bridge
            .connect()
            .await
            .expect_err("disabled bridge must fail");
        assert!(
            matches!(err, ChromeBridgeError::BrowserToolsDisabled),
            "expected BrowserToolsDisabled, got {err:?}"
        );

        for server in servers {
            let _ = server.join();
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// S9: Happy Path Through Fault Harness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fault_auth_ok_connects_successfully() {
    run_async(async {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("ok.sock");
        let record = make_test_record(&socket_path, "host-ok");

        let script = FaultScript::single(FaultKind::AuthOk);
        let server = spawn_fault_host(&socket_path, script);

        let bridge = ChromeBridge::new(test_bridge_config(tempdir.path()));
        bridge
            .connect_to_record(&record)
            .await
            .expect("AuthOk should succeed");

        let status = bridge.status();
        assert_eq!(status.state, ConnectionState::Connected);
        assert_eq!(status.pinned_host_id.as_deref(), Some("host-ok"));
        assert_eq!(status.consecutive_failures, 0);
        assert!(!status.browser_tools_disabled);

        bridge.disconnect().expect("disconnect");

        let events = server.join().expect("server join");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "ok");
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// JSONL Outcome Recording
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn outcome_jsonl_roundtrip() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let jsonl_path = tempdir.path().join("outcomes.jsonl");

    let script = FaultScript::single(FaultKind::AuthOk);
    let outcome1 = TestOutcome::pass("happy_path", script, "connection succeeded");
    let outcome2 = TestOutcome::fail(
        "auth_busy",
        FaultScript::single(FaultKind::AuthBusy {
            claimed_by_session: "s".to_string(),
            claimed_by_client: "c".to_string(),
        }),
        "auth rejected",
        "unexpected: got Ok",
    );

    write_outcome_jsonl(&jsonl_path, &outcome1).expect("write outcome 1");
    write_outcome_jsonl(&jsonl_path, &outcome2).expect("write outcome 2");

    let content = std::fs::read_to_string(&jsonl_path).expect("read jsonl");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2, "should have 2 JSONL lines");

    let parsed1: TestOutcome = serde_json::from_str(lines[0]).expect("parse line 1");
    assert!(parsed1.passed);
    assert_eq!(parsed1.scenario, "happy_path");

    let parsed2: TestOutcome = serde_json::from_str(lines[1]).expect("parse line 2");
    assert!(!parsed2.passed);
    assert_eq!(parsed2.scenario, "auth_busy");
    assert!(parsed2.error.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// FaultScript / FaultKind Serialization
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fault_script_serde_roundtrip() {
    let script = FaultScript::sequence(vec![
        FaultKind::DropBeforeAuth,
        FaultKind::AuthBusy {
            claimed_by_session: "s".to_string(),
            claimed_by_client: "c".to_string(),
        },
        FaultKind::AuthOk,
    ]);
    let json = serde_json::to_string(&script).expect("serialize");
    let parsed: FaultScript = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.actions.len(), 3);
    assert_eq!(parsed.actions[0], FaultKind::DropBeforeAuth);
    assert_eq!(parsed.actions[2], FaultKind::AuthOk);
}

#[test]
fn fault_kind_all_variants_serialize() {
    let variants = vec![
        FaultKind::AuthOk,
        FaultKind::AuthBusy {
            claimed_by_session: "s".to_string(),
            claimed_by_client: "c".to_string(),
        },
        FaultKind::ProtocolMismatch {
            message: "v99".to_string(),
        },
        FaultKind::MalformedFrame {
            garbage: vec![0xFF, 0xFE],
        },
        FaultKind::DropBeforeAuth,
        FaultKind::DropAfterAuth,
        FaultKind::UnexpectedMessageType,
        FaultKind::AuthOkBadProtocol {
            protocol_version: 42,
        },
    ];

    for variant in &variants {
        let json =
            serde_json::to_string(variant).unwrap_or_else(|e| panic!("serialize {variant:?}: {e}"));
        let parsed: FaultKind =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialize {variant:?}: {e}"));
        assert_eq!(
            &parsed, variant,
            "roundtrip must preserve variant: {variant:?}"
        );
    }
}
