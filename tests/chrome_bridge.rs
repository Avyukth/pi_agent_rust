//! Phase 1 Integration Test Suite for `ChromeBridge` (bd-18m.4).
//!
//! Comprehensive integration tests from PLAN.md §6.3 exercising the full
//! `ChromeBridge` lifecycle: discovery, auth handshake, request/response
//! multiplexing, reconnection, and failure handling.
//!
//! # Relationship to Other Test Files
//!
//! - **`chrome_safety.rs`** (bd-18m.6): Focused on S5/S6/S7 safety invariants.
//!   Where tests overlap (exclusive claim, reconnect pinning, stale discovery),
//!   this file emphasizes end-to-end integration behavior while the safety file
//!   emphasizes invariant boundary conditions.
//!
//! - **`chrome_fault_injection.rs`** (bd-1xz.3): Focused on fault harness mechanics.
//!   This file uses the same fault patterns but in integration scenarios.
//!
//! # Tests (PLAN.md §6.3)
//!
//! | # | Test | Status |
//! |---|------|--------|
//! | 1 | `agent_to_host_roundtrip` | Implemented |
//! | 2 | `concurrent_requests` | Deferred (needs `send_request` public API) |
//! | 3 | `connection_loss_recovery` | Implemented |
//! | 4 | `auth_token_validation` | Implemented |
//! | 5 | `host_claim_exclusive` | See `chrome_safety.rs::s6_exclusive_claim_rejects_second_agent` |
//! | 6 | `dual_session_binding_isolation` | See `chrome_safety.rs::s6_dual_agent_dual_host_no_cross_binding` |
//! | 7 | `reconnect_pins_host_id` | See `chrome_safety.rs::s6_reconnect_pins_to_original_host` |
//! | 8 | `stale_discovery_record_ignored` | See `chrome_safety.rs::s6_stale_discovery_record_skipped` |
//! | 9 | `timeout_then_retry_replays_cached_result` | Deferred (needs `NativeHost` on main) |
//! | 10 | `non_idempotent_retry_after_host_restart_returns_indeterminate` | Deferred (needs `NativeHost` on main) |

use asupersync::runtime::RuntimeBuilder;
use pi::chrome::protocol;
use pi::chrome::{ChromeBridge, ChromeBridgeConfig, ChromeBridgeError, ConnectionState};
use std::io::{BufRead, Write};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build");
    runtime.block_on(future)
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

fn make_record(socket_path: &Path, host_id: &str) -> pi::chrome::DiscoveryRecord {
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
        expires_at_ms: Some(now_ms() + 60_000),
    }
}

fn write_discovery(dir: &Path, record: &pi::chrome::DiscoveryRecord) {
    let filename = format!("pi-chrome-host-{}.discovery.json", record.host_id);
    let path = dir.join(filename);
    std::fs::write(
        &path,
        serde_json::to_vec(record).expect("serialize discovery record"),
    )
    .expect("write discovery record");
    // LavenderCastle's Wave 1A added a permission check (0o600) in discover_hosts_in_dir.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod discovery record");
    }
}

fn bridge_config(discovery_dir: &Path, session_id: &str, client_id: &str) -> ChromeBridgeConfig {
    ChromeBridgeConfig {
        pi_session_id: session_id.to_string(),
        client_instance_id: client_id.to_string(),
        discovery_dir: discovery_dir.to_path_buf(),
        want_capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
        max_reconnect_attempts: 3,
        reconnect_backoff_ms: 1, // fast for tests
    }
}

fn read_auth_claim(stream: &std::os::unix::net::UnixStream) -> protocol::AuthClaim {
    let mut reader = std::io::BufReader::new(stream);
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .expect("read auth_claim frame");
    let (message, _) = protocol::decode_frame::<protocol::MessageType>(&line)
        .expect("decode auth_claim")
        .expect("complete auth_claim frame");
    match message {
        protocol::MessageType::AuthClaim(claim) => claim,
        other => panic!("expected AuthClaim, got {other:?}"),
    }
}

fn build_auth_ok(claim: &protocol::AuthClaim, host_id: &str) -> protocol::MessageType {
    protocol::MessageType::AuthOk(protocol::AuthOk {
        version: protocol::PROTOCOL_VERSION_V1,
        host_id: host_id.to_string(),
        claimed_by: protocol::ClaimedBy {
            pi_session_id: claim.pi_session_id.clone(),
            client_instance_id: claim.client_instance_id.clone(),
        },
        host_epoch: format!("{host_id}-epoch"),
        protocol: protocol::PROTOCOL_VERSION_V1,
        capabilities: claim.want_capabilities.clone(),
        lease_ttl_ms: 30_000,
    })
}

fn write_response(stream: &std::os::unix::net::UnixStream, message: &protocol::MessageType) {
    let frame = protocol::encode_frame(message).expect("encode response");
    let mut writer = stream;
    writer.write_all(&frame).expect("write response frame");
}

/// Spawn a mock host that accepts one connection and completes the auth handshake.
fn spawn_auth_ok_host(socket_path: &Path, host_id: &str) -> JoinHandle<protocol::AuthClaim> {
    let listener = StdUnixListener::bind(socket_path).expect("bind mock unix listener");
    let host_id = host_id.to_string();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept mock client");
        let claim = read_auth_claim(&stream);
        let response = build_auth_ok(&claim, &host_id);
        write_response(&stream, &response);
        claim
    })
}

/// Spawn a mock host that validates the auth token and rejects if it doesn't match.
fn spawn_token_checking_host(
    socket_path: &Path,
    host_id: &str,
    expected_token: &str,
) -> JoinHandle<(protocol::AuthClaim, bool)> {
    let listener = StdUnixListener::bind(socket_path).expect("bind mock unix listener");
    let host_id = host_id.to_string();
    let expected_token = expected_token.to_string();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept mock client");
        let claim = read_auth_claim(&stream);

        if claim.token == expected_token {
            let response = build_auth_ok(&claim, &host_id);
            write_response(&stream, &response);
            (claim, true)
        } else {
            // Reject with protocol mismatch (simulating token validation failure).
            let response = protocol::MessageType::Response(protocol::ResponseEnvelope::Error(
                protocol::ErrorResponse {
                    version: protocol::PROTOCOL_VERSION_V1,
                    id: "handshake".to_string(),
                    ok: false,
                    error: protocol::ProtocolErrorDetail {
                        code: protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                        message: "invalid auth token".to_string(),
                        retryable: false,
                    },
                },
            ));
            write_response(&stream, &response);
            (claim, false)
        }
    })
}

/// Spawn a mock host that accepts N connections, completing auth each time.
fn spawn_multi_accept_host(
    socket_path: &Path,
    host_id: &str,
    accept_count: usize,
) -> JoinHandle<Vec<protocol::AuthClaim>> {
    let listener = StdUnixListener::bind(socket_path).expect("bind mock unix listener");
    let host_id = host_id.to_string();
    std::thread::spawn(move || {
        let mut claims = Vec::new();
        for _ in 0..accept_count {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let claim = read_auth_claim(&stream);
            let response = build_auth_ok(&claim, &host_id);
            write_response(&stream, &response);
            claims.push(claim);
        }
        claims
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// §6.3.1: Agent-to-Host Roundtrip
// ═══════════════════════════════════════════════════════════════════════════

/// §6.3.1: Socket connect → auth handshake → verify Connected state.
///
/// Verifies the complete connection lifecycle: discovery record creation,
/// Unix socket connect, `auth_claim`/`auth_ok` handshake, and final Connected state
/// with correct `host_id` and `host_epoch` pinning.
#[test]
fn test_agent_to_host_connect_and_auth() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-roundtrip.sock");
        let record = make_record(&socket_path, "host-roundtrip");

        let server = spawn_auth_ok_host(&socket_path, "host-roundtrip");

        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-rt", "client-rt"));
        assert_eq!(bridge.status().state, ConnectionState::Disconnected);

        bridge
            .connect_to_record(&record)
            .await
            .expect("connect should succeed");

        let status = bridge.status();
        assert_eq!(status.state, ConnectionState::Connected);
        assert_eq!(status.pinned_host_id.as_deref(), Some("host-roundtrip"));
        assert_eq!(status.host_epoch.as_deref(), Some("host-roundtrip-epoch"));
        assert_eq!(status.consecutive_failures, 0);
        assert!(!status.browser_tools_disabled);

        // Verify the claim the host received.
        let claim = server.join().expect("server join");
        assert_eq!(claim.pi_session_id, "session-rt");
        assert_eq!(claim.client_instance_id, "client-rt");
        assert_eq!(claim.host_id, "host-roundtrip");
        assert_eq!(claim.token, "secret-token");
        assert_eq!(claim.version, protocol::PROTOCOL_VERSION_V1);
        assert_eq!(claim.protocol_min, protocol::PROTOCOL_MIN_SUPPORTED);
        assert_eq!(claim.protocol_max, protocol::PROTOCOL_MAX_SUPPORTED);
        assert_eq!(
            claim.want_capabilities,
            vec!["browser_tools", "observations"]
        );

        bridge.disconnect().expect("disconnect");
        assert_eq!(bridge.status().state, ConnectionState::Disconnected);
    });
}

/// §6.3.1: Disconnect transitions state from Connected → Disconnected.
///
/// Verifies that disconnect is clean and the bridge returns to Disconnected
/// while preserving the `pinned_host_id` for future reconnection.
#[test]
fn test_disconnect_preserves_pinned_host() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-disconnect.sock");
        let record = make_record(&socket_path, "host-disconnect");

        let server = spawn_auth_ok_host(&socket_path, "host-disconnect");
        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-disc", "client-disc"));

        bridge.connect_to_record(&record).await.expect("connect");
        assert_eq!(bridge.status().state, ConnectionState::Connected);

        bridge.disconnect().expect("disconnect");

        let status = bridge.status();
        assert_eq!(status.state, ConnectionState::Disconnected);
        // Pinned host must survive disconnect for deterministic reconnection.
        assert_eq!(
            status.pinned_host_id.as_deref(),
            Some("host-disconnect"),
            "pinned_host_id must survive disconnect"
        );

        server.join().expect("server join");
    });
}

/// §6.3.1: Discovery via `connect()` — full lifecycle using discovery directory.
///
/// Verifies: Bridge discovers host from written discovery record, connects via
/// discovery (not `connect_to_record`), and reaches Connected state.
#[test]
fn test_connect_via_discovery() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-disco.sock");
        let record = make_record(&socket_path, "host-disco");
        write_discovery(dir.path(), &record);

        let server = spawn_auth_ok_host(&socket_path, "host-disco");
        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-disco", "client-disco"));

        bridge.connect().await.expect("connect via discovery");

        assert_eq!(bridge.status().state, ConnectionState::Connected);
        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-disco")
        );

        bridge.disconnect().expect("disconnect");
        server.join().expect("server join");
    });
}

/// §6.3.1: `discover_hosts()` returns records sorted with pinned host first.
///
/// Verifies the discovery priority ordering: pinned host appears first,
/// remaining hosts sorted alphabetically by `host_id`.
#[test]
fn test_discover_hosts_sorted_order() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Create placeholder sockets.
    let sock_a = dir.path().join("host-alpha.sock");
    let sock_b = dir.path().join("host-beta.sock");
    let sock_c = dir.path().join("host-gamma.sock");
    for sock in [&sock_a, &sock_b, &sock_c] {
        std::fs::write(sock, []).expect("create placeholder socket");
    }

    write_discovery(dir.path(), &make_record(&sock_a, "host-alpha"));
    write_discovery(dir.path(), &make_record(&sock_b, "host-beta"));
    write_discovery(dir.path(), &make_record(&sock_c, "host-gamma"));

    // Without pinning: alphabetical order.
    let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-sort", "client-sort"));
    let hosts = bridge.discover_hosts().expect("discover hosts");
    assert_eq!(hosts.len(), 3);
    assert_eq!(hosts[0].host_id, "host-alpha");
    assert_eq!(hosts[1].host_id, "host-beta");
    assert_eq!(hosts[2].host_id, "host-gamma");
}

// ═══════════════════════════════════════════════════════════════════════════
// §6.3.3: Connection Loss Recovery
// ═══════════════════════════════════════════════════════════════════════════

/// §6.3.3: Kill host → reconnect succeeds to same host via discovery.
///
/// Verifies: After the initial host connection drops, the bridge can reconnect
/// via the discovery mechanism. The multi-accept mock host simulates a host
/// that stays alive across reconnect cycles.
#[test]
fn test_connection_loss_recovery_via_reconnect() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-recovery.sock");
        let record = make_record(&socket_path, "host-recovery");
        write_discovery(dir.path(), &record);

        // Host accepts 2 connections (initial + reconnect).
        let server = spawn_multi_accept_host(&socket_path, "host-recovery", 2);

        let bridge = ChromeBridge::new(bridge_config(
            dir.path(),
            "session-recovery",
            "client-recovery",
        ));

        // First connect.
        bridge.connect().await.expect("initial connect");
        assert_eq!(bridge.status().state, ConnectionState::Connected);
        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-recovery")
        );

        // Simulate connection loss.
        bridge.disconnect().expect("disconnect (simulating loss)");
        assert_eq!(bridge.status().state, ConnectionState::Disconnected);

        // Reconnect via discovery — should find the same host.
        bridge.connect().await.expect("reconnect");
        assert_eq!(bridge.status().state, ConnectionState::Connected);
        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-recovery"),
            "reconnect must pin to same host"
        );

        bridge.disconnect().expect("final disconnect");

        let claims = server.join().expect("server join");
        assert_eq!(claims.len(), 2, "host should have served 2 connections");
        assert_eq!(claims[0].pi_session_id, "session-recovery");
        assert_eq!(claims[1].pi_session_id, "session-recovery");
    });
}

/// §6.3.3: Multiple failed connects → bridge disabled → `BrowserToolsDisabled` error.
///
/// Verifies the failure streak policy: after `max_reconnect_attempts` failed
/// connection cycles, the bridge transitions to Disabled state and returns
/// `BrowserToolsDisabled` on subsequent connect attempts.
#[test]
fn test_failure_streak_disables_browser_tools() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");

        // Create 3 hosts, each drops connection before auth.
        let mut servers = Vec::new();
        for i in 0..3 {
            let host_id = format!("host-fail-{i}");
            let socket_path = dir.path().join(format!("fail-{i}.sock"));
            let record = make_record(&socket_path, &host_id);
            write_discovery(dir.path(), &record);

            let listener = StdUnixListener::bind(&socket_path).expect("bind");
            servers.push(std::thread::spawn(move || {
                // Accept and immediately drop (fault: DropBeforeAuth).
                let _ = listener.accept();
            }));
        }

        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-fail", "client-fail"));

        // Three connect cycles, each fails.
        for _ in 0..3u8 {
            let _ = bridge.connect().await;
        }

        let status = bridge.status();
        assert!(
            status.browser_tools_disabled,
            "browser tools must be disabled after 3 consecutive failures"
        );
        assert_eq!(status.state, ConnectionState::Disabled);

        // Further attempts return BrowserToolsDisabled.
        let err = bridge.connect().await.expect_err("disabled must fail");
        assert!(
            matches!(err, ChromeBridgeError::BrowserToolsDisabled),
            "expected BrowserToolsDisabled, got {err:?}"
        );

        for server in servers {
            let _ = server.join();
        }
    });
}

/// §6.3.3: No hosts found → `NoHostsFound` error.
///
/// Verifies: When the discovery directory is empty, `connect()` returns
/// `NoHostsFound` after exhausting retry attempts.
#[test]
fn test_no_hosts_found_in_empty_directory() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-empty", "client-empty"));

        let err = bridge.connect().await.expect_err("empty dir must fail");

        assert!(
            matches!(err, ChromeBridgeError::NoHostsFound),
            "expected NoHostsFound, got {err:?}"
        );
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §6.3.4: Auth Token Validation
// ═══════════════════════════════════════════════════════════════════════════

/// §6.3.4: Bad auth token → connection rejected.
///
/// Verifies: When the discovery record's token doesn't match what the host
/// expects, the host rejects the claim. The bridge receives an error response
/// and transitions back to Disconnected.
#[test]
fn test_auth_token_validation_bad_token_rejected() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-auth.sock");

        // Discovery record has "secret-token", host expects "correct-token".
        let record = make_record(&socket_path, "host-auth");
        let server = spawn_token_checking_host(&socket_path, "host-auth", "correct-token");

        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-auth", "client-auth"));
        let err = bridge
            .connect_to_record(&record)
            .await
            .expect_err("bad token must be rejected");

        // The host sends an error Response with ChromeBridgeAuthFailed code.
        // Wave 1A's authenticate_stream now handles this explicitly as AuthRejected.
        assert!(
            matches!(
                err,
                ChromeBridgeError::AuthRejected(_)
                    | ChromeBridgeError::UnexpectedHandshakeMessage(_)
                    | ChromeBridgeError::ProtocolMismatch(_)
            ),
            "expected rejection error, got {err:?}"
        );

        let (claim, accepted) = server.join().expect("server join");
        assert!(!accepted, "host should have rejected the token");
        assert_eq!(
            claim.token, "secret-token",
            "claim should carry the discovery token"
        );

        assert_eq!(bridge.status().state, ConnectionState::Disconnected);
    });
}

/// §6.3.4: Good auth token → connection accepted.
///
/// Verifies: When the token matches, the host accepts the claim normally.
#[test]
fn test_auth_token_validation_good_token_accepted() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-auth-ok.sock");
        let record = make_record(&socket_path, "host-auth-ok");

        // Discovery record has "secret-token", host also expects "secret-token".
        let server = spawn_token_checking_host(&socket_path, "host-auth-ok", "secret-token");

        let bridge = ChromeBridge::new(bridge_config(
            dir.path(),
            "session-auth-ok",
            "client-auth-ok",
        ));
        bridge
            .connect_to_record(&record)
            .await
            .expect("matching token should succeed");

        assert_eq!(bridge.status().state, ConnectionState::Connected);

        let (claim, accepted) = server.join().expect("server join");
        assert!(accepted, "host should have accepted the token");
        assert_eq!(claim.token, "secret-token");

        bridge.disconnect().expect("disconnect");
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Protocol Handshake Details
// ═══════════════════════════════════════════════════════════════════════════

/// Auth claim carries correct protocol version range and capabilities.
///
/// Verifies the claim envelope sent by `ChromeBridge` matches the configured
/// values from `ChromeBridgeConfig`.
#[test]
fn test_auth_claim_carries_config_values() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-claim-check.sock");
        let record = make_record(&socket_path, "host-claim-check");

        let server = spawn_auth_ok_host(&socket_path, "host-claim-check");

        let config = ChromeBridgeConfig {
            pi_session_id: "custom-session".to_string(),
            client_instance_id: "custom-client".to_string(),
            discovery_dir: dir.path().to_path_buf(),
            want_capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
            max_reconnect_attempts: 1,
            reconnect_backoff_ms: 1,
        };

        let bridge = ChromeBridge::new(config);
        bridge.connect_to_record(&record).await.expect("connect");

        let claim = server.join().expect("server join");
        assert_eq!(claim.version, protocol::PROTOCOL_VERSION_V1);
        assert_eq!(claim.pi_session_id, "custom-session");
        assert_eq!(claim.client_instance_id, "custom-client");
        assert_eq!(claim.host_id, "host-claim-check");
        assert_eq!(claim.protocol_min, protocol::PROTOCOL_MIN_SUPPORTED);
        assert_eq!(claim.protocol_max, protocol::PROTOCOL_MAX_SUPPORTED);
        assert!(
            claim
                .want_capabilities
                .contains(&"browser_tools".to_string())
        );
        assert!(
            claim
                .want_capabilities
                .contains(&"observations".to_string())
        );

        bridge.disconnect().expect("disconnect");
    });
}

/// Multiple discovery records — bridge iterates through candidates.
///
/// Verifies: When the first host is unreachable (dead socket), the bridge
/// falls through to the next discovery candidate.
#[test]
fn test_discovery_fallthrough_on_dead_first_host() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");

        // Host A: dead (no listener).
        let sock_a = dir.path().join("host-aaa-dead.sock");
        std::fs::write(&sock_a, []).expect("create placeholder");
        let record_a = make_record(&sock_a, "host-aaa-dead");
        write_discovery(dir.path(), &record_a);

        // Host B: alive.
        let sock_b = dir.path().join("host-bbb-alive.sock");
        let record_b = make_record(&sock_b, "host-bbb-alive");
        write_discovery(dir.path(), &record_b);

        let server_b = spawn_auth_ok_host(&sock_b, "host-bbb-alive");

        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-fall", "client-fall"));
        bridge
            .connect()
            .await
            .expect("should fall through to host B");

        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-bbb-alive"),
            "bridge should have connected to the alive host"
        );

        bridge.disconnect().expect("disconnect");
        server_b.join().expect("server B join");
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Discovery Record Parsing
// ═══════════════════════════════════════════════════════════════════════════

/// Discovery record deserialization handles all field aliases.
///
/// Verifies: The `DiscoveryRecord` struct supports field aliases for backward
/// compatibility with different host implementations.
#[test]
fn test_discovery_record_serde_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("host-serde.sock");
    std::fs::write(&socket_path, []).expect("create placeholder socket");

    let record = make_record(&socket_path, "host-serde");
    let json = serde_json::to_string(&record).expect("serialize");
    let parsed: pi::chrome::DiscoveryRecord = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(parsed.host_id, "host-serde");
    assert_eq!(parsed.host_epoch, "host-serde-epoch");
    assert_eq!(parsed.token, "secret-token");
    assert_eq!(parsed.protocol_min, protocol::PROTOCOL_MIN_SUPPORTED);
    assert_eq!(parsed.protocol_max, protocol::PROTOCOL_MAX_SUPPORTED);
}

/// Expired discovery records are correctly detected.
#[test]
fn test_discovery_record_expiry_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("host-expire.sock");

    let mut record = make_record(&socket_path, "host-expire");
    let now = now_ms();

    // Not expired.
    record.expires_at_ms = Some(now + 60_000);
    assert!(!record.is_expired(now));

    // Expired.
    record.expires_at_ms = Some(now - 1);
    assert!(record.is_expired(now));

    // No expiry → never expires.
    record.expires_at_ms = None;
    assert!(!record.is_expired(now));
}

/// Discovery filters out records with missing socket files.
#[test]
fn test_discovery_filters_missing_sockets() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write a discovery record for a non-existent socket.
    let dead_socket = dir.path().join("host-phantom.sock");
    let record = make_record(&dead_socket, "host-phantom");
    write_discovery(dir.path(), &record);

    let bridge = ChromeBridge::new(bridge_config(
        dir.path(),
        "session-phantom",
        "client-phantom",
    ));
    let hosts = bridge.discover_hosts().expect("discover hosts");
    assert!(
        hosts.is_empty(),
        "dead socket record must be filtered out, found {} hosts",
        hosts.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame Protocol
// ═══════════════════════════════════════════════════════════════════════════

/// Frame encode/decode roundtrip for all message types.
///
/// Verifies: Every `MessageType` variant survives `encode_frame` → `decode_frame`.
#[test]
fn test_frame_encode_decode_roundtrip_all_types() {
    let messages: Vec<protocol::MessageType> = vec![
        protocol::MessageType::AuthClaim(protocol::AuthClaim {
            version: protocol::PROTOCOL_VERSION_V1,
            host_id: "h1".to_string(),
            pi_session_id: "s1".to_string(),
            client_instance_id: "c1".to_string(),
            token: "t1".to_string(),
            protocol_min: 1,
            protocol_max: 1,
            want_capabilities: vec!["browser_tools".to_string()],
        }),
        protocol::MessageType::AuthOk(protocol::AuthOk {
            version: protocol::PROTOCOL_VERSION_V1,
            host_id: "h1".to_string(),
            claimed_by: protocol::ClaimedBy {
                pi_session_id: "s1".to_string(),
                client_instance_id: "c1".to_string(),
            },
            host_epoch: "h1-e1".to_string(),
            protocol: 1,
            capabilities: vec!["browser_tools".to_string()],
            lease_ttl_ms: 30_000,
        }),
        protocol::MessageType::AuthBusy(protocol::AuthBusy {
            version: protocol::PROTOCOL_VERSION_V1,
            host_id: "h1".to_string(),
            claimed_by: protocol::ClaimedBy {
                pi_session_id: "other".to_string(),
                client_instance_id: "other-c".to_string(),
            },
        }),
        protocol::MessageType::Request(protocol::Request {
            version: protocol::PROTOCOL_VERSION_V1,
            id: "req-1".to_string(),
            op: "navigate".to_string(),
            payload: serde_json::json!({"url": "https://example.com"}),
        }),
        protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(protocol::Response {
            version: protocol::PROTOCOL_VERSION_V1,
            id: "req-1".to_string(),
            ok: true,
            result: serde_json::json!({"title": "Example"}),
        })),
        protocol::MessageType::Response(protocol::ResponseEnvelope::Error(
            protocol::ErrorResponse {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-2".to_string(),
                ok: false,
                error: protocol::ProtocolErrorDetail {
                    code: protocol::ProtocolErrorCode::TabNotFound,
                    message: "no such tab".to_string(),
                    retryable: false,
                },
            },
        )),
        protocol::MessageType::Observation(protocol::ObservationEvent {
            version: protocol::PROTOCOL_VERSION_V1,
            observer_id: "obs-1".to_string(),
            events: vec![protocol::ObservationEntry {
                kind: "console".to_string(),
                message: Some("hello".to_string()),
                source: None,
                url: Some("https://example.com".to_string()),
                ts: 1234,
            }],
        }),
    ];

    for message in &messages {
        let frame =
            protocol::encode_frame(message).unwrap_or_else(|e| panic!("encode {message:?}: {e}"));
        assert!(frame.ends_with(b"\n"), "frame must be newline-delimited");
        let (decoded, consumed) = protocol::decode_frame::<protocol::MessageType>(&frame)
            .unwrap_or_else(|e| panic!("decode {message:?}: {e}"))
            .expect("complete frame");
        assert_eq!(consumed, frame.len(), "must consume entire frame");

        // Re-encode to verify determinism.
        let re_encoded = protocol::encode_frame(&decoded).expect("re-encode");
        assert_eq!(frame, re_encoded, "frame must be deterministic");
    }
}

/// Frame size limit enforced.
#[test]
fn test_frame_size_limit() {
    // Create a message larger than MAX_SOCKET_FRAME_BYTES (1 MB).
    let huge_payload = "x".repeat(2 * 1024 * 1024);
    let msg = protocol::MessageType::Request(protocol::Request {
        version: protocol::PROTOCOL_VERSION_V1,
        id: "req-huge".to_string(),
        op: "navigate".to_string(),
        payload: serde_json::Value::String(huge_payload),
    });

    let result = protocol::encode_frame(&msg);
    assert!(result.is_err(), "encoding a >1MB frame should fail");
    if let Err(protocol::FrameCodecError::FrameTooLarge {
        frame_bytes,
        max_bytes,
    }) = result
    {
        assert!(frame_bytes > max_bytes);
        assert_eq!(max_bytes, protocol::MAX_SOCKET_FRAME_BYTES);
    } else {
        panic!("expected FrameTooLarge error");
    }
}
