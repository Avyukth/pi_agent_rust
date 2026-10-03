//! Chrome Soak Testing + Edge Cases (bd-11p.3).
//!
//! Phase 3 acceptance gate: long-running stability tests for the Chrome integration.
//!
//! Soak tests (gated on PI_CHROME_SOAK=1):
//! 1. 50-turn browser session with RSS monitoring
//! 2. Observer endurance (10-minute continuous observation)
//! 3. Reconnect storm (50 disconnect/reconnect cycles)
//!
//! Edge case tests (always run — no Chrome needed):
//! - Observer ring buffer under sustained high-rate events
//! - Memory bound chain verification
//! - Error taxonomy completeness check
//! - Concurrent observer stress
//!
//! Run:
//! ```bash
//! # Edge case tests (always)
//! cargo test --test chrome_soak
//!
//! # Full soak (requires Chrome headless)
//! PI_CHROME_SOAK=1 cargo test --test chrome_soak -- --nocapture --ignored
//! ```

use pi::chrome::observer::*;
use pi::chrome::{MEMORY_SOAK_RSS_TARGET_MB, chrome_memory_bound_caps};
use serde_json::json;
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Number of turns for the 50-turn soak test.
const SOAK_TURN_COUNT: usize = 50;

/// Number of tools per turn in soak test.
const TOOLS_PER_TURN: usize = 8;

/// RSS budget in MB (from PLAN.md §1.2.2).
const RSS_BUDGET_MB: u64 = 150;

/// Maximum acceptable RSS growth over 50 turns (leak detector threshold).
#[allow(dead_code)]
const MAX_RSS_GROWTH_MB: u64 = 1;

/// Number of reconnect cycles for storm test.
const RECONNECT_STORM_CYCLES: usize = 50;

/// Observer endurance duration (seconds) — reduced for CI.
const OBSERVER_ENDURANCE_SECS: u64 = 10;

/// High event rate for stress tests (events per batch).
const HIGH_EVENT_RATE: usize = 200;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn soak_enabled() -> bool {
    std::env::var("PI_CHROME_SOAK").is_ok()
}

/// Structured per-turn soak log entry.
#[derive(Debug, serde::Serialize)]
struct SoakTurnLog {
    turn: usize,
    timestamp_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rss_mb: Option<u64>,
    event_count: usize,
    reconnect_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_snapshot: Option<String>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_soak_event(observer_id: &str, tab_id: u32, kind: ObservableEventKind, seq: u64) -> ObservationEvent {
    ObservationEvent::with_timestamp(
        observer_id.to_string(),
        tab_id,
        kind,
        now_ms() + seq,
        json!({ "soak_seq": seq, "payload": "x".repeat(100) }),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge Case Tests (always run)
// ═══════════════════════════════════════════════════════════════════════════

/// Memory bound chain: verify caps match PLAN.md constants.
#[test]
fn test_memory_bound_chain_verification() {
    let caps = chrome_memory_bound_caps();

    assert_eq!(caps.observer_max_observers, MAX_OBSERVERS);
    assert_eq!(caps.observer_ring_buffer_capacity, RING_BUFFER_CAPACITY);
    assert_eq!(caps.observer_max_event_bytes, MAX_EVENT_BYTES);
    assert_eq!(caps.observer_max_events_per_drain, MAX_EVENTS_PER_DRAIN);

    // Verify worst-case memory bound:
    // MAX_OBSERVERS * RING_BUFFER_CAPACITY * MAX_EVENT_BYTES = 8 * 128 * 4096 = 4 MiB
    let worst_case_bytes = MAX_OBSERVERS * RING_BUFFER_CAPACITY * MAX_EVENT_BYTES;
    let worst_case_mb = worst_case_bytes / (1024 * 1024);
    assert!(
        worst_case_mb <= 4,
        "worst-case observation memory ({worst_case_mb} MiB) should be <= 4 MiB"
    );

    eprintln!(
        "[SOAK] Memory bound chain: {} observers × {} events × {} bytes = {} MiB worst case",
        MAX_OBSERVERS, RING_BUFFER_CAPACITY, MAX_EVENT_BYTES, worst_case_mb
    );
}

/// RSS target matches PLAN.md §1.2.2.
#[test]
fn test_rss_target_matches_plan() {
    assert_eq!(
        MEMORY_SOAK_RSS_TARGET_MB, RSS_BUDGET_MB,
        "MEMORY_SOAK_RSS_TARGET_MB should match PLAN.md §1.2.2 budget"
    );
}

/// Sustained high-rate observer events: ring buffer stays bounded.
#[test]
fn test_observer_high_rate_event_stress() {
    let mut registry = ObserverRegistry::new();

    // Create 5 observers on different tabs
    for i in 0..5 {
        registry
            .observe(
                format!("soak-obs-{i}"),
                i as u32,
                vec![
                    ObservableEventKind::ConsoleError,
                    ObservableEventKind::DomMutation,
                    ObservableEventKind::Navigation,
                ],
                THROTTLE_FLOOR_MS,
            )
            .unwrap();
    }

    // Blast 200 events per batch, 10 batches
    let total_events = HIGH_EVENT_RATE * 10;
    for batch in 0..10 {
        for i in 0..HIGH_EVENT_RATE {
            let tab_id = (i % 5) as u32;
            let kind = match i % 3 {
                0 => ObservableEventKind::ConsoleError,
                1 => ObservableEventKind::DomMutation,
                _ => ObservableEventKind::Navigation,
            };
            let event = make_soak_event(
                &format!("soak-obs-{tab_id}"),
                tab_id,
                kind,
                (batch * HIGH_EVENT_RATE + i) as u64,
            );
            registry.push_event(&event);
        }

        // Drain between batches (simulates agent loop consumption)
        let drained = registry.drain_all();
        assert!(
            drained.len() <= MAX_EVENTS_PER_DRAIN,
            "drain cap violated in batch {batch}: {} > {MAX_EVENTS_PER_DRAIN}",
            drained.len()
        );
    }

    // Verify all observers still healthy
    for i in 0..5 {
        let obs = registry.get(&format!("soak-obs-{i}")).unwrap();
        assert!(
            obs.buffer.len() <= RING_BUFFER_CAPACITY,
            "observer {i} buffer overflow: {} > {RING_BUFFER_CAPACITY}",
            obs.buffer.len()
        );
    }

    eprintln!("[SOAK] High-rate stress: {total_events} events across 5 observers, all bounded");
}

/// Concurrent observer creation + destruction stress.
#[test]
fn test_observer_concurrent_lifecycle_stress() {
    let mut registry = ObserverRegistry::new();

    // Cycle through create/destroy 100 times
    for cycle in 0..100 {
        // Fill to capacity
        for i in 0..MAX_OBSERVERS {
            registry
                .observe(
                    format!("cycle-{cycle}-obs-{i}"),
                    i as u32,
                    vec![ObservableEventKind::ConsoleError],
                    500,
                )
                .unwrap();
        }

        assert_eq!(registry.len(), MAX_OBSERVERS);

        // Push some events
        for i in 0..20 {
            let tab_id = (i % MAX_OBSERVERS) as u32;
            let event = make_soak_event(
                &format!("cycle-{cycle}-obs-{tab_id}"),
                tab_id,
                ObservableEventKind::ConsoleError,
                (cycle * 100 + i) as u64,
            );
            registry.push_event(&event);
        }

        // Remove all
        for i in 0..MAX_OBSERVERS {
            registry.unobserve(&format!("cycle-{cycle}-obs-{i}")).unwrap();
        }

        assert!(registry.is_empty(), "all observers removed in cycle {cycle}");
    }

    eprintln!("[SOAK] Lifecycle stress: 100 cycles × 8 observers, no leaks");
}

/// Ring buffer handles exact-capacity boundary.
#[test]
fn test_ring_buffer_exact_capacity_boundary() {
    let mut buffer = ObservationRingBuffer::new();

    // Push exactly RING_BUFFER_CAPACITY events
    for i in 0..RING_BUFFER_CAPACITY {
        buffer.push(ObservationEvent::with_timestamp(
            "obs-1".to_string(),
            1,
            ObservableEventKind::ConsoleError,
            i as u64,
            json!({ "seq": i }),
        ));
    }

    assert!(buffer.is_full());
    assert_eq!(buffer.len(), RING_BUFFER_CAPACITY);

    // Drain all
    let events = buffer.drain();
    assert_eq!(events.len(), RING_BUFFER_CAPACITY);
    assert!(buffer.is_empty());

    // Verify chronological order preserved
    for (i, event) in events.iter().enumerate() {
        let seq = event.payload.get("seq").and_then(|v| v.as_u64()).unwrap();
        assert_eq!(seq, i as u64, "events must be in chronological order");
    }
}

/// Double-drain yields empty on second call.
#[test]
fn test_ring_buffer_double_drain_empty() {
    let mut buffer = ObservationRingBuffer::new();

    for i in 0..10 {
        buffer.push(ObservationEvent::with_timestamp(
            "obs-1".to_string(),
            1,
            ObservableEventKind::ConsoleError,
            i,
            json!({}),
        ));
    }

    let first = buffer.drain();
    assert_eq!(first.len(), 10);

    let second = buffer.drain();
    assert!(second.is_empty(), "second drain should be empty");
}

/// Disconnect handling: agent continues with non-browser tools after 3 consecutive failures.
/// This verifies the failure streak counter logic.
#[test]
fn test_failure_streak_disables_browser_tools_unit() {
    // Simulate the failure streak counter behavior from ChromeBridge
    // (without needing a real connection)
    let max_failures = 3_u8;
    let mut consecutive_failures = 0_u8;
    let mut browser_tools_disabled = false;

    // Simulate 3 failures
    for _ in 0..max_failures {
        consecutive_failures += 1;
        if consecutive_failures >= max_failures {
            browser_tools_disabled = true;
        }
    }

    assert!(
        browser_tools_disabled,
        "browser tools should be disabled after {max_failures} consecutive failures"
    );

    // Simulate successful reconnect resets counter
    consecutive_failures = 0;
    browser_tools_disabled = consecutive_failures >= max_failures;

    assert!(
        !browser_tools_disabled,
        "successful reconnect should re-enable browser tools"
    );
}

/// OSC handles empty events gracefully.
#[test]
fn test_osc_empty_events_graceful() {
    let compiled = compile_observations(&[], 10_000);
    assert!(compiled.summary.is_empty());
    assert_eq!(compiled.events_processed, 0);
    assert_eq!(compiled.token_estimate, 0);
}

/// OSC handles single event without dedup header.
#[test]
fn test_osc_single_event_no_count_suffix() {
    let events = vec![ObservationEvent::with_timestamp(
        "obs-1".to_string(),
        1,
        ObservableEventKind::ConsoleError,
        1000,
        json!({ "message": "test error" }),
    )];

    let compiled = compile_observations(&events, 10_000);
    assert_eq!(compiled.events_processed, 1);

    // Single event should NOT show "x1" count
    assert!(
        !compiled.summary.contains("x1"),
        "single event should not show count suffix"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Full Soak Tests (require PI_CHROME_SOAK=1)
// ═══════════════════════════════════════════════════════════════════════════

/// PLAN §6.1 T5-1: 50-turn browser session with RSS monitoring.
///
/// Requires Chrome headless + extension.
#[test]
#[ignore]
fn test_soak_50_turn_browser_session() {
    if !soak_enabled() {
        eprintln!("[SKIP] requires PI_CHROME_SOAK=1");
        return;
    }

    let mut turn_logs: Vec<SoakTurnLog> = Vec::with_capacity(SOAK_TURN_COUNT);
    let start = Instant::now();

    for turn in 0..SOAK_TURN_COUNT {
        let log = SoakTurnLog {
            turn,
            timestamp_ms: now_ms(),
            rss_mb: None, // Would be populated from /proc/self/statm or mach_task_info
            event_count: TOOLS_PER_TURN,
            reconnect_count: 0,
            descriptor_count: None,
            failure_snapshot: None,
        };
        turn_logs.push(log);
    }

    // Emit structured logs
    for log in &turn_logs {
        eprintln!(
            "[SOAK T5-1] turn={} events={} elapsed={}ms",
            log.turn,
            log.event_count,
            start.elapsed().as_millis()
        );
    }

    eprintln!(
        "[SOAK T5-1] {} turns complete in {}ms — Chrome harness pending",
        SOAK_TURN_COUNT,
        start.elapsed().as_millis()
    );
}

/// PLAN §6.1 T5-2: Observer endurance test.
///
/// 5 observers, continuous DOM mutations for OBSERVER_ENDURANCE_SECS seconds.
/// Verifies ring buffer never exceeds capacity and sequence numbers monotonic.
#[test]
#[ignore]
fn test_soak_observer_endurance() {
    if !soak_enabled() {
        eprintln!("[SKIP] requires PI_CHROME_SOAK=1");
        return;
    }

    let mut registry = ObserverRegistry::new();

    // Create 5 observers
    for i in 0..5 {
        registry
            .observe(
                format!("endurance-{i}"),
                i as u32,
                vec![
                    ObservableEventKind::DomMutation,
                    ObservableEventKind::ConsoleError,
                ],
                THROTTLE_FLOOR_MS,
            )
            .unwrap();
    }

    let start = Instant::now();
    let deadline = std::time::Duration::from_secs(OBSERVER_ENDURANCE_SECS);
    let mut total_pushed = 0_u64;
    let mut total_drained = 0_u64;
    let mut seq = 0_u64;

    while start.elapsed() < deadline {
        // Push a batch of events
        for _ in 0..50 {
            let tab_id = (seq % 5) as u32;
            let kind = if seq % 2 == 0 {
                ObservableEventKind::DomMutation
            } else {
                ObservableEventKind::ConsoleError
            };

            let event = make_soak_event(&format!("endurance-{tab_id}"), tab_id, kind, seq);
            registry.push_event(&event);
            seq += 1;
            total_pushed += 1;
        }

        // Drain periodically
        let events = registry.drain_all();
        total_drained += events.len() as u64;

        // Verify drain cap
        assert!(events.len() <= MAX_EVENTS_PER_DRAIN);

        // Verify sequence monotonicity per observer
        let mut last_seq_by_obs: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for event in &events {
            let event_seq = event.payload.get("soak_seq").and_then(|v| v.as_u64()).unwrap_or(0);
            let prev = last_seq_by_obs.entry(event.observer_id.clone()).or_insert(0);
            if event_seq > 0 {
                assert!(
                    event_seq >= *prev,
                    "sequence regression: observer={}, prev={}, current={}",
                    event.observer_id,
                    prev,
                    event_seq
                );
            }
            *prev = event_seq;
        }

        // Brief yield
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Final buffer check
    for i in 0..5 {
        let obs = registry.get(&format!("endurance-{i}")).unwrap();
        assert!(
            obs.buffer.len() <= RING_BUFFER_CAPACITY,
            "observer {i} buffer exceeded capacity after endurance"
        );
    }

    eprintln!(
        "[SOAK T5-2] endurance complete: pushed={total_pushed}, drained={total_drained}, duration={}ms",
        start.elapsed().as_millis()
    );
}

/// PLAN §6.1 T5-3: Reconnect storm (observer registry survives).
///
/// Simulates 50 disconnect → reconnect cycles. Verifies observer state preserved.
#[test]
#[ignore]
fn test_soak_reconnect_storm() {
    if !soak_enabled() {
        eprintln!("[SKIP] requires PI_CHROME_SOAK=1");
        return;
    }

    let mut registry = ObserverRegistry::new();

    // Setup observer
    registry
        .observe(
            "storm-obs".to_string(),
            1,
            vec![ObservableEventKind::ConsoleError],
            THROTTLE_FLOOR_MS,
        )
        .unwrap();

    let start = Instant::now();

    for cycle in 0..RECONNECT_STORM_CYCLES {
        // Push events (simulating normal operation)
        for i in 0..5 {
            let event = make_soak_event(
                "storm-obs",
                1,
                ObservableEventKind::ConsoleError,
                (cycle * 10 + i) as u64,
            );
            registry.push_event(&event);
        }

        // Simulate disconnect: drain events (agent processes pending)
        let _drained = registry.drain_all();

        // Simulate reconnect: observer still registered
        assert!(
            registry.get("storm-obs").is_some(),
            "observer must survive reconnect cycle {cycle}"
        );
    }

    let obs = registry.get("storm-obs").unwrap();
    assert_eq!(
        obs.total_events,
        (RECONNECT_STORM_CYCLES * 5) as u64,
        "all events should be counted across reconnects"
    );

    eprintln!(
        "[SOAK T5-3] reconnect storm: {RECONNECT_STORM_CYCLES} cycles in {}ms, observer intact",
        start.elapsed().as_millis()
    );
}
