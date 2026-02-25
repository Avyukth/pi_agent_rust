//! Safety invariant integration tests for `ChromeBridge` (bd-18m.6).
//!
//! Dedicated stop-ship test suite verifying invariants S5, S6, and S7 using
//! deterministic fault-injection hooks. Each test documents the exact invariant
//! and failure mode it proves.
//!
//! # Safety Invariants
//!
//! - **S5 (Session Isolation)**: No data leaks between Pi sessions via shared
//!   browser state. Separate `ChromeBridge` instances must have fully independent
//!   observation buffers, connection state, and request sequences.
//!
//! - **S6 (Host Binding Determinism)**: Agent must NEVER bind to wrong native
//!   host. Reconnect always pins to originally-claimed `host_id`. Stale/expired
//!   discovery records are filtered. Second claim to a busy host is rejected.
//!
//! - **S7 (ESL At-Most-Once)**: Non-idempotent operations never silently executed
//!   twice. The protocol-level tests verify that `EXECUTION_INDETERMINATE` errors
//!   are surfaced correctly and that request IDs enable replay detection.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────┐     Unix Socket     ┌──────────────────────┐
//! │ ChromeBridge(s) │ ──────────────────► │ SafetyMockHost(s)    │
//! │ (under test)    │                     │ (configurable faults) │
//! └────────────────┘                     └──────────────────────┘
//! ```

use asupersync::runtime::RuntimeBuilder;
use pi::chrome::protocol;
use pi::chrome::{ChromeBridge, ChromeBridgeConfig, ChromeBridgeError, ConnectionState};
use serde_json::json;
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
    std::fs::write(
        dir.join(filename),
        serde_json::to_vec(record).expect("serialize discovery record"),
    )
    .expect("write discovery record");
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

/// Spawn a mock host that accepts one connection, reads `AuthClaim`, and responds
/// with a valid `AuthOk`. Returns the join handle so the caller can verify completion.
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

/// Spawn a mock host that accepts one connection, reads `AuthClaim`, and responds
/// with `AuthBusy` indicating the host is already claimed.
fn spawn_auth_busy_host(
    socket_path: &Path,
    claimed_session: &str,
    claimed_client: &str,
) -> JoinHandle<()> {
    let listener = StdUnixListener::bind(socket_path).expect("bind mock unix listener");
    let claimed_session = claimed_session.to_string();
    let claimed_client = claimed_client.to_string();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept mock client");
        let claim = read_auth_claim(&stream);
        let response = protocol::MessageType::AuthBusy(protocol::AuthBusy {
            version: protocol::PROTOCOL_VERSION_V1,
            host_id: claim.host_id,
            claimed_by: protocol::ClaimedBy {
                pi_session_id: claimed_session,
                client_instance_id: claimed_client,
            },
        });
        write_response(&stream, &response);
    })
}

/// Spawn a mock host that accepts N connections, responding with `AuthOk` each time.
/// Used for reconnect tests — the host stays alive across multiple connection cycles.
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

// ═══════════════════════════════════════════════════════════════════════════
// S5: Session Isolation
// ═══════════════════════════════════════════════════════════════════════════
//
// S5 invariant: No data leaks between Pi sessions via shared browser state.
// ChromeBridge instances with different session IDs must be fully independent.

/// **S5**: Two independent `ChromeBridge` instances have isolated observation buffers.
///
/// Verifies: Each bridge has its own observation buffer; draining one does not affect the other.
/// Failure mode: Shared static/global observation storage would leak between sessions.
#[test]
fn s5_observation_buffers_isolated_between_sessions() {
    run_async(async {
        let dir_a = tempfile::tempdir().expect("tempdir A");
        let dir_b = tempfile::tempdir().expect("tempdir B");
        let sock_a = dir_a.path().join("host-a.sock");
        let sock_b = dir_b.path().join("host-b.sock");

        let record_a = make_record(&sock_a, "host-a");
        let record_b = make_record(&sock_b, "host-b");

        let server_a = spawn_auth_ok_host(&sock_a, "host-a");
        let server_b = spawn_auth_ok_host(&sock_b, "host-b");

        let bridge_a = ChromeBridge::new(bridge_config(dir_a.path(), "session-A", "client-A"));
        let bridge_b = ChromeBridge::new(bridge_config(dir_b.path(), "session-B", "client-B"));

        bridge_a
            .connect_to_record(&record_a)
            .await
            .expect("bridge A connect");
        bridge_b
            .connect_to_record(&record_b)
            .await
            .expect("bridge B connect");

        // Both buffers start empty — no cross-contamination from construction.
        assert_eq!(
            bridge_a.observation_buffer_len(),
            0,
            "S5: bridge A should start with empty observation buffer"
        );
        assert_eq!(
            bridge_b.observation_buffer_len(),
            0,
            "S5: bridge B should start with empty observation buffer"
        );

        // Drain A — must not affect B.
        let obs_a = bridge_a.take_observations();
        assert!(obs_a.is_empty(), "S5: bridge A drain returns empty");
        assert_eq!(
            bridge_b.observation_buffer_len(),
            0,
            "S5 VIOLATION: draining bridge A must not affect bridge B's buffer"
        );

        // Drain B — must not affect A.
        let obs_b = bridge_b.take_observations();
        assert!(obs_b.is_empty(), "S5: bridge B drain returns empty");
        assert_eq!(
            bridge_a.observation_buffer_len(),
            0,
            "S5 VIOLATION: draining bridge B must not affect bridge A's buffer"
        );

        bridge_a.disconnect().expect("disconnect A");
        bridge_b.disconnect().expect("disconnect B");

        server_a.join().expect("server A");
        server_b.join().expect("server B");
    });
}

/// **S5**: Two `ChromeBridge` instances have independent connection state.
///
/// Verifies: Disabling bridge A does not affect bridge B's ability to connect.
/// Failure mode: Shared global connection state would cascade failures across sessions.
#[test]
fn s5_connection_state_independent_between_sessions() {
    run_async(async {
        let dir_a = tempfile::tempdir().expect("tempdir A");
        let dir_b = tempfile::tempdir().expect("tempdir B");
        let sock_b = dir_b.path().join("host-b.sock");
        let record_b = make_record(&sock_b, "host-b");

        let server_b = spawn_auth_ok_host(&sock_b, "host-b");

        // Bridge A: Configure with empty dir so it fails repeatedly and gets disabled.
        let bridge_a = ChromeBridge::new(bridge_config(dir_a.path(), "session-A", "client-A"));
        // Three failed connect attempts → disabled.
        for _ in 0..3u8 {
            let _ = bridge_a.connect().await;
        }
        assert_eq!(
            bridge_a.status().state,
            ConnectionState::Disabled,
            "precondition: bridge A should be disabled"
        );

        // Bridge B: Must still connect successfully.
        let bridge_b = ChromeBridge::new(bridge_config(dir_b.path(), "session-B", "client-B"));
        bridge_b
            .connect_to_record(&record_b)
            .await
            .expect("S5 VIOLATION: bridge B must connect despite bridge A being disabled");

        assert_eq!(bridge_b.status().state, ConnectionState::Connected);
        assert_eq!(bridge_a.status().state, ConnectionState::Disabled);

        bridge_b.disconnect().expect("disconnect B");
        server_b.join().expect("server B");
    });
}

/// **S5**: Request ID sequences are independent across sessions.
///
/// Verifies: Two bridges generate their own monotonic sequences without interference.
/// Failure mode: Shared atomic counter would create non-deterministic ID collisions.
#[test]
#[allow(clippy::similar_names)]
fn s5_request_id_sequences_independent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bridge_a = ChromeBridge::new(bridge_config(dir.path(), "session-A", "client-A"));
    let bridge_b = ChromeBridge::new(bridge_config(dir.path(), "session-B", "client-B"));

    let id_a_first = bridge_a.next_request_id();
    let id_a_second = bridge_a.next_request_id();
    let id_b_first = bridge_b.next_request_id();
    let id_b_second = bridge_b.next_request_id();

    // Each bridge starts from 1 independently.
    assert_eq!(id_a_first, "chrome-1", "S5: bridge A first ID");
    assert_eq!(id_a_second, "chrome-2", "S5: bridge A second ID");
    assert_eq!(
        id_b_first, "chrome-1",
        "S5: bridge B first ID (independent)"
    );
    assert_eq!(
        id_b_second, "chrome-2",
        "S5: bridge B second ID (independent)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// S6: Host Binding Determinism
// ═══════════════════════════════════════════════════════════════════════════
//
// S6 invariant: Agent must NEVER bind to wrong native host.
// - Exclusive claim: second agent gets AuthBusy rejection
// - Reconnect pins to originally-claimed host_id
// - Host crash → agent does NOT accidentally connect to different host
// - Stale discovery records (expired, dead socket) are filtered

/// **S6**: Exclusive claim — second agent claiming same host receives `AuthBusy`.
///
/// Verifies: When host is already claimed by session A, session B's claim is rejected.
/// Failure mode: Missing exclusive claim enforcement would allow dual-binding.
#[test]
fn s6_exclusive_claim_rejects_second_agent() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("host-exclusive.sock");
        let record = make_record(&socket_path, "host-exclusive");

        // First connection: session A claims the host.
        let server = spawn_auth_ok_host(&socket_path, "host-exclusive");
        let bridge_a = ChromeBridge::new(bridge_config(dir.path(), "session-A", "client-A"));
        bridge_a
            .connect_to_record(&record)
            .await
            .expect("session A should claim host");
        assert_eq!(bridge_a.status().state, ConnectionState::Connected);
        let claim_a = server.join().expect("server A join");
        assert_eq!(claim_a.pi_session_id, "session-A");

        bridge_a.disconnect().expect("disconnect A");

        // Remove the old socket so we can re-bind for the second mock host.
        let _ = std::fs::remove_file(&socket_path);

        // Second connection: session B tries to claim same host — gets AuthBusy.
        let server_b = spawn_auth_busy_host(
            &socket_path,
            "session-A", // claimed by A
            "client-A",
        );
        let bridge_b = ChromeBridge::new(bridge_config(dir.path(), "session-B", "client-B"));
        let err = bridge_b
            .connect_to_record(&record)
            .await
            .expect_err("S6 VIOLATION: session B must be rejected");

        assert!(
            matches!(err, ChromeBridgeError::AuthBusy { .. }),
            "S6: expected AuthBusy, got {err:?}"
        );

        server_b.join().expect("server B join");
    });
}

/// **S6**: Reconnect always pins to originally-claimed `host_id`.
///
/// Verifies: After disconnect, the bridge reconnects to the same host (not a random one).
/// Failure mode: Missing `pinned_host_id` would cause random host selection on reconnect.
#[test]
fn s6_reconnect_pins_to_original_host() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_a = dir.path().join("host-alpha.sock");
        let sock_b = dir.path().join("host-beta.sock");

        let record_a = make_record(&sock_a, "host-alpha");
        let record_b = make_record(&sock_b, "host-beta");

        // Write both discovery records so connect() could choose either.
        write_discovery(dir.path(), &record_a);
        write_discovery(dir.path(), &record_b);

        // First connection cycle: spawn both hosts, connect (should bind to one).
        // The multi-accept host for alpha will serve 2 connections (initial + reconnect).
        let server_alpha = spawn_multi_accept_host(&sock_a, "host-alpha", 2);
        // Beta host: if the bridge tries to connect here, it's a violation.
        // We make it accept once to detect the violation.
        let server_beta = spawn_auth_ok_host(&sock_b, "host-beta");

        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-pin", "client-pin"));
        bridge
            .connect_to_record(&record_a)
            .await
            .expect("initial connect to host-alpha");

        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-alpha"),
            "S6: pinned_host_id should be host-alpha after first connect"
        );

        // Disconnect and reconnect via discovery.
        bridge.disconnect().expect("disconnect");
        assert_eq!(bridge.status().state, ConnectionState::Disconnected);
        // pinned_host_id should persist after disconnect.
        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-alpha"),
            "S6: pinned_host_id must survive disconnect"
        );

        bridge.connect().await.expect("reconnect via discovery");

        assert_eq!(
            bridge.status().state,
            ConnectionState::Connected,
            "S6: should reconnect successfully"
        );
        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-alpha"),
            "S6 VIOLATION: reconnect must pin to original host-alpha, not host-beta"
        );

        bridge.disconnect().expect("final disconnect");

        // Verify alpha served both connections.
        let claims = server_alpha.join().expect("alpha join");
        assert_eq!(
            claims.len(),
            2,
            "S6: host-alpha should have received 2 connection attempts"
        );
        for claim in &claims {
            assert_eq!(claim.pi_session_id, "session-pin");
        }

        // Beta host: drop it. If it accepted a connection, that's a violation
        // (but we can't easily assert on that without timeout, so we verify via
        // the pinned_host_id assertions above).
        drop(server_beta);
    });
}

/// **S6**: Stale (expired) discovery records are skipped during host selection.
///
/// Verifies: Expired records don't participate in discovery, even if socket exists.
/// Failure mode: Missing expiry check would connect to stale/abandoned hosts.
#[test]
fn s6_stale_discovery_record_skipped() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_stale = dir.path().join("host-stale.sock");
        let sock_fresh = dir.path().join("host-fresh.sock");

        // Create stale record (expired 10 seconds ago).
        let mut record_stale = make_record(&sock_stale, "host-stale");
        record_stale.expires_at_ms = Some(now_ms() - 10_000);
        write_discovery(dir.path(), &record_stale);

        // Create fresh record.
        let record_fresh = make_record(&sock_fresh, "host-fresh");
        write_discovery(dir.path(), &record_fresh);

        // Create a placeholder for stale socket (to pass exists() check if expiry is ignored).
        std::fs::write(&sock_stale, []).expect("create stale socket placeholder");

        let server_fresh = spawn_auth_ok_host(&sock_fresh, "host-fresh");

        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-stale", "client-stale"));
        bridge
            .connect()
            .await
            .expect("should connect to fresh host");

        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-fresh"),
            "S6 VIOLATION: bridge must skip stale record and connect to host-fresh"
        );

        bridge.disconnect().expect("disconnect");
        server_fresh.join().expect("server join");
    });
}

/// **S6**: Discovery record with dead socket (file doesn't exist) is skipped.
///
/// Verifies: Records pointing to non-existent sockets are filtered out.
/// Failure mode: Attempting to connect to dead socket would waste retry budget.
#[test]
fn s6_dead_socket_discovery_record_skipped() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_dead = dir.path().join("host-dead.sock");
        let sock_alive = dir.path().join("host-alive.sock");

        // Write discovery for dead socket (don't create the socket file).
        let record_dead = make_record(&sock_dead, "host-dead");
        write_discovery(dir.path(), &record_dead);

        // Write discovery for alive socket.
        let record_alive = make_record(&sock_alive, "host-alive");
        write_discovery(dir.path(), &record_alive);

        let server_alive = spawn_auth_ok_host(&sock_alive, "host-alive");

        let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-dead", "client-dead"));
        bridge
            .connect()
            .await
            .expect("should connect to alive host");

        assert_eq!(
            bridge.status().pinned_host_id.as_deref(),
            Some("host-alive"),
            "S6: bridge must skip dead socket and connect to host-alive"
        );

        bridge.disconnect().expect("disconnect");
        server_alive.join().expect("server join");
    });
}

/// **S6**: Two agents bind to separate hosts without cross-contamination.
///
/// Verifies: Agent A claims host-1, agent B claims host-2. Neither crosses.
/// Failure mode: Incorrect discovery sorting or pinning would allow cross-binding.
#[test]
fn s6_dual_agent_dual_host_no_cross_binding() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_1 = dir.path().join("host-1.sock");
        let sock_2 = dir.path().join("host-2.sock");

        let record_1 = make_record(&sock_1, "host-1");
        let record_2 = make_record(&sock_2, "host-2");

        let server_1 = spawn_auth_ok_host(&sock_1, "host-1");
        let server_2 = spawn_auth_ok_host(&sock_2, "host-2");

        let bridge_a = ChromeBridge::new(bridge_config(dir.path(), "session-A", "client-A"));
        let bridge_b = ChromeBridge::new(bridge_config(dir.path(), "session-B", "client-B"));

        // Agent A → host-1 (direct).
        bridge_a
            .connect_to_record(&record_1)
            .await
            .expect("agent A connect to host-1");
        // Agent B → host-2 (direct).
        bridge_b
            .connect_to_record(&record_2)
            .await
            .expect("agent B connect to host-2");

        assert_eq!(
            bridge_a.status().pinned_host_id.as_deref(),
            Some("host-1"),
            "S6: agent A must be bound to host-1"
        );
        assert_eq!(
            bridge_b.status().pinned_host_id.as_deref(),
            Some("host-2"),
            "S6: agent B must be bound to host-2"
        );

        // Verify each server received the correct session ID.
        let claim_1 = server_1.join().expect("server 1 join");
        let claim_2 = server_2.join().expect("server 2 join");
        assert_eq!(claim_1.pi_session_id, "session-A");
        assert_eq!(claim_2.pi_session_id, "session-B");

        bridge_a.disconnect().expect("disconnect A");
        bridge_b.disconnect().expect("disconnect B");
    });
}

/// **S6**: Discovery prefers pinned host first in sorted order.
///
/// Verifies: `discover_hosts()` returns the pinned host before other candidates.
/// Failure mode: Without pinned-first sorting, reconnect would try random hosts first.
#[test]
fn s6_discovery_prefers_pinned_host_first() {
    run_async(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_a = dir.path().join("host-aaa.sock");
        let sock_b = dir.path().join("host-bbb.sock");
        let sock_c = dir.path().join("host-ccc.sock");

        // Create placeholder sockets for hosts we won't actually connect to.
        // Don't create sock_c — spawn_auth_ok_host will bind the real socket there.
        std::fs::write(&sock_a, []).expect("create sock_a");
        std::fs::write(&sock_b, []).expect("create sock_b");

        let record_a = make_record(&sock_a, "host-aaa");
        let record_b = make_record(&sock_b, "host-bbb");
        let record_c = make_record(&sock_c, "host-ccc");
        write_discovery(dir.path(), &record_a);
        write_discovery(dir.path(), &record_b);
        write_discovery(dir.path(), &record_c);

        // Create a bridge that has pinned to host-ccc.
        let mut config = bridge_config(dir.path(), "session-pin", "client-pin");
        config.max_reconnect_attempts = 1;
        let bridge = ChromeBridge::new(config);

        // First connect to host-ccc to pin it (spawns the real socket).
        let server = spawn_auth_ok_host(&sock_c, "host-ccc");
        bridge
            .connect_to_record(&record_c)
            .await
            .expect("pin to host-ccc");
        bridge.disconnect().expect("disconnect");
        server.join().expect("server join");

        // Now discover_hosts() should return host-ccc first.
        let hosts = bridge.discover_hosts().expect("discover hosts");
        assert!(!hosts.is_empty(), "should find at least one host");
        assert_eq!(
            hosts[0].host_id, "host-ccc",
            "S6 VIOLATION: pinned host-ccc must be first in discovery results, got {}",
            hosts[0].host_id
        );
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// S7: ESL At-Most-Once Semantics
// ═══════════════════════════════════════════════════════════════════════════
//
// S7 invariant: Non-idempotent operations never silently executed twice.
// Since NativeHost (with the ESL journal) is not yet on main, these tests
// verify the protocol-level contracts that S7 depends on:
// - Request IDs enable deduplication
// - EXECUTION_INDETERMINATE error code is correctly surfaced
// - RequestFingerprint determinism for canonical payload hashing

/// **S7**: `RequestFingerprint` is deterministic for same op+payload regardless of key order.
///
/// Verifies: JSON key ordering doesn't affect fingerprint. Same semantic request → same hash.
/// Failure mode: Non-canonical JSON would create different fingerprints for equivalent requests,
/// breaking ESL deduplication.
#[test]
fn s7_request_fingerprint_deterministic() {
    let fp1 = protocol::RequestFingerprint::new(
        "navigate",
        &json!({"url": "https://example.com", "timeout": 5000}),
    )
    .expect("fingerprint 1");

    let fp2 = protocol::RequestFingerprint::new(
        "navigate",
        &json!({"timeout": 5000, "url": "https://example.com"}),
    )
    .expect("fingerprint 2");

    assert_eq!(
        fp1.as_str(),
        fp2.as_str(),
        "S7 VIOLATION: same op+payload with different key order must produce same fingerprint"
    );

    // Different payload → different fingerprint.
    let fp3 = protocol::RequestFingerprint::new(
        "navigate",
        &json!({"url": "https://other.com", "timeout": 5000}),
    )
    .expect("fingerprint 3");
    assert_ne!(
        fp1.as_str(),
        fp3.as_str(),
        "S7: different payloads must produce different fingerprints"
    );
}

/// **S7**: `RequestFingerprint` differs when op changes (same payload).
///
/// Verifies: The operation name is part of the fingerprint.
/// Failure mode: Missing op in hash would conflate different operations with same payload.
#[test]
fn s7_request_fingerprint_includes_op_name() {
    let payload = json!({"url": "https://example.com"});
    let fp_navigate =
        protocol::RequestFingerprint::new("navigate", &payload).expect("navigate fingerprint");
    let fp_get_text = protocol::RequestFingerprint::new("get_page_text", &payload)
        .expect("get_page_text fingerprint");

    assert_ne!(
        fp_navigate.as_str(),
        fp_get_text.as_str(),
        "S7 VIOLATION: different ops with same payload must produce different fingerprints"
    );
}

/// **S7**: `EXECUTION_INDETERMINATE` error code is correctly represented in the protocol.
///
/// Verifies: The error code enum variant serializes and the `retryable=false` semantics
/// are preserved through encode/decode.
/// Failure mode: Missing or misnamed error code would prevent fail-closed handling.
#[test]
fn s7_execution_indeterminate_error_roundtrip() {
    let error_response = protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: "req-42".to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code: protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
            message: "host restarted during execution window".to_string(),
            retryable: false,
        },
    };

    let envelope = protocol::ResponseEnvelope::Error(error_response);
    let message = protocol::MessageType::Response(envelope);

    // Encode → decode roundtrip.
    let frame = protocol::encode_frame(&message).expect("encode");
    let (decoded, _) = protocol::decode_frame::<protocol::MessageType>(&frame)
        .expect("decode")
        .expect("complete frame");

    match decoded {
        protocol::MessageType::Response(protocol::ResponseEnvelope::Error(err)) => {
            assert_eq!(
                err.error.code,
                protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
                "S7: error code must survive roundtrip"
            );
            assert!(
                !err.error.retryable,
                "S7 VIOLATION: EXECUTION_INDETERMINATE must be non-retryable (fail-closed)"
            );
            assert_eq!(err.id, "req-42");
        }
        other => panic!("S7: expected Error response, got {other:?}"),
    }
}

/// **S7**: `EXECUTION_INDETERMINATE` serializes to correct `SCREAMING_SNAKE_CASE` wire format.
///
/// Verifies: The JSON representation matches the protocol spec.
/// Failure mode: Wrong serialization name would cause host/agent deserialization failures.
#[test]
fn s7_execution_indeterminate_wire_format() {
    let detail = protocol::ProtocolErrorDetail {
        code: protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
        message: "test".to_string(),
        retryable: false,
    };

    let json = serde_json::to_value(&detail).expect("serialize");
    assert_eq!(
        json["code"], "CHROME_BRIDGE_EXECUTION_INDETERMINATE",
        "S7: error code must serialize as SCREAMING_SNAKE_CASE"
    );
    assert_eq!(json["retryable"], false);
}

/// **S7**: Request ID monotonicity ensures no accidental reuse within a session.
///
/// Verifies: `next_request_id()` produces strictly increasing IDs.
/// Failure mode: ID reuse would cause ESL to incorrectly match different requests.
#[test]
fn s7_request_id_monotonic_no_reuse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bridge = ChromeBridge::new(bridge_config(dir.path(), "session-mono", "client-mono"));

    let mut ids = Vec::new();
    for _ in 0..100 {
        ids.push(bridge.next_request_id());
    }

    // No duplicates.
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "S7 VIOLATION: request IDs must be unique, found duplicates"
    );

    // Verify ordering: chrome-1, chrome-2, ..., chrome-100.
    for (i, id) in ids.iter().enumerate() {
        let expected = format!("chrome-{}", i + 1);
        assert_eq!(id, &expected, "S7: request ID sequence must be monotonic");
    }
}

/// **S7**: All `ProtocolErrorCode` variants that affect retry semantics encode correctly.
///
/// Verifies: Key error codes round-trip through JSON serialization.
/// Failure mode: Missing serde attributes would cause deserialization failures in the
/// error-handling path, potentially masking `EXECUTION_INDETERMINATE`.
#[test]
fn s7_all_retry_relevant_error_codes_roundtrip() {
    let codes = vec![
        (
            protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
            false,
        ),
        (protocol::ProtocolErrorCode::ChromeBridgeTimeout, true),
        (protocol::ProtocolErrorCode::ChromeBridgeDisconnected, true),
        (protocol::ProtocolErrorCode::ChromeBridgeBusy, true),
    ];

    for (code, retryable) in codes {
        let detail = protocol::ProtocolErrorDetail {
            code,
            message: format!("test {code:?}"),
            retryable,
        };

        let json = serde_json::to_string(&detail).expect("serialize");
        let parsed: protocol::ProtocolErrorDetail =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            parsed.code, code,
            "S7: error code {code:?} must survive JSON roundtrip"
        );
        assert_eq!(
            parsed.retryable, retryable,
            "S7: retryable flag for {code:?} must survive roundtrip"
        );
    }
}
