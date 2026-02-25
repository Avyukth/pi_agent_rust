//! Chrome observer integration tests (bd-3mf.8).
//!
//! Tests the observer subsystem from the integration perspective:
//! - Throttle batching and floor clamping
//! - Observer limit enforcement
//! - Ring buffer overflow semantics
//! - Global drain cap
//! - Unobserve delivery cessation
//! - OSC compiled summary under token budget
//!
//! NOTE: `test_observation_survives_reconnect` requires ChromeBridge integration
//! and is gated on PI_CHROME_E2E=1 (see e2e_chrome.rs).
//!
//! Run:
//! ```bash
//! cargo test --test chrome_observer
//! ```

use pi::chrome::observer::*;
use serde_json::json;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn make_event(observer_id: &str, tab_id: u32, kind: ObservableEventKind, seq: u64) -> ObservationEvent {
    ObservationEvent::with_timestamp(
        observer_id.to_string(),
        tab_id,
        kind,
        1_000_000 + seq,
        json!({ "seq": seq }),
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

/// bd-3mf.8: Throttle floor clamps any value < 500ms to 500ms.
#[test]
fn test_observe_throttle_floor_clamp() {
    let mut registry = ObserverRegistry::new();

    // Request throttle well below floor (100ms)
    registry
        .observe(
            "obs-low".to_string(),
            1,
            vec![ObservableEventKind::ConsoleError],
            100,
        )
        .unwrap();

    let obs = registry.get("obs-low").unwrap();
    assert_eq!(
        obs.throttle_ms, THROTTLE_FLOOR_MS,
        "throttle below floor must be clamped to {THROTTLE_FLOOR_MS}ms"
    );

    // Request throttle at zero
    registry
        .observe(
            "obs-zero".to_string(),
            2,
            vec![ObservableEventKind::ConsoleError],
            0,
        )
        .unwrap();

    let obs = registry.get("obs-zero").unwrap();
    assert_eq!(obs.throttle_ms, THROTTLE_FLOOR_MS);

    // Request throttle above floor should pass through
    registry
        .observe(
            "obs-high".to_string(),
            3,
            vec![ObservableEventKind::ConsoleError],
            2000,
        )
        .unwrap();

    let obs = registry.get("obs-high").unwrap();
    assert_eq!(obs.throttle_ms, 2000, "throttle above floor should pass through");
}

/// bd-3mf.8: Batching — events for subscribed kinds accumulate in ring buffer.
#[test]
fn test_observe_throttle_batching() {
    let mut registry = ObserverRegistry::new();

    registry
        .observe(
            "obs-batch".to_string(),
            1,
            vec![
                ObservableEventKind::ConsoleError,
                ObservableEventKind::ConsoleWarn,
            ],
            500,
        )
        .unwrap();

    // Push 10 console errors
    for i in 0..10 {
        let event = make_event("obs-batch", 1, ObservableEventKind::ConsoleError, i);
        registry.push_event(&event);
    }

    // Push 5 console warns
    for i in 0..5 {
        let event = make_event("obs-batch", 1, ObservableEventKind::ConsoleWarn, 100 + i);
        registry.push_event(&event);
    }

    // Events should accumulate before drain
    let obs = registry.get("obs-batch").unwrap();
    assert_eq!(obs.buffer.len(), 15, "all 15 events should be buffered");
    assert_eq!(obs.total_events, 15);

    // Drain clears buffer
    let events = registry.drain_all();
    assert_eq!(events.len(), 15);

    let obs = registry.get("obs-batch").unwrap();
    assert!(obs.buffer.is_empty(), "buffer should be empty after drain");
}

/// bd-3mf.8: Observer limit enforced at MAX_OBSERVERS.
#[test]
fn test_observer_limit_enforced() {
    let mut registry = ObserverRegistry::new();

    // Fill to capacity
    for i in 0..MAX_OBSERVERS {
        registry
            .observe(
                format!("obs-{i}"),
                i as u32,
                vec![ObservableEventKind::ConsoleError],
                500,
            )
            .unwrap();
    }

    assert_eq!(registry.len(), MAX_OBSERVERS);

    // Next observer must fail
    let result = registry.observe(
        "obs-overflow".to_string(),
        99,
        vec![ObservableEventKind::ConsoleError],
        500,
    );
    assert!(
        matches!(result, Err(ObserverError::LimitReached { max }) if max == MAX_OBSERVERS),
        "observer over limit should produce LimitReached error"
    );

    // After removing one, should succeed
    registry.unobserve("obs-0").unwrap();
    let result = registry.observe(
        "obs-replacement".to_string(),
        100,
        vec![ObservableEventKind::ConsoleError],
        500,
    );
    assert!(result.is_ok(), "should accept observer after removal");
}

/// bd-3mf.8: Ring buffer overflow evicts oldest events (FIFO).
#[test]
fn test_observe_ring_buffer_overflow() {
    let mut registry = ObserverRegistry::new();

    registry
        .observe(
            "obs-ring".to_string(),
            1,
            vec![ObservableEventKind::ConsoleError],
            500,
        )
        .unwrap();

    // Push more than RING_BUFFER_CAPACITY events
    let overflow = 20;
    let total = RING_BUFFER_CAPACITY + overflow;
    for i in 0..total {
        let event = make_event("obs-ring", 1, ObservableEventKind::ConsoleError, i as u64);
        registry.push_event(&event);
    }

    // Buffer at capacity
    let obs = registry.get("obs-ring").unwrap();
    assert_eq!(
        obs.buffer.len(),
        RING_BUFFER_CAPACITY,
        "buffer must cap at RING_BUFFER_CAPACITY"
    );

    // Total events count should include evicted events
    assert_eq!(obs.total_events, total as u64);

    // Drain and verify oldest were evicted
    let events = registry.drain_all();
    assert_eq!(events.len(), RING_BUFFER_CAPACITY);

    // First event should be the one after the overflow count
    let first_seq = events[0].payload.get("seq").and_then(|v| v.as_u64());
    assert_eq!(
        first_seq,
        Some(overflow as u64),
        "first event after drain should be seq={overflow} (oldest {overflow} evicted)"
    );

    // Last event should be the most recent
    let last_seq = events.last().unwrap().payload.get("seq").and_then(|v| v.as_u64());
    assert_eq!(last_seq, Some((total - 1) as u64));
}

/// bd-3mf.8: Global drain cap at MAX_EVENTS_PER_DRAIN.
#[test]
fn test_observation_global_drain_cap() {
    let mut registry = ObserverRegistry::new();

    // Create multiple observers each with full buffers
    for i in 0..MAX_OBSERVERS {
        registry
            .observe(
                format!("obs-{i}"),
                i as u32,
                vec![ObservableEventKind::ConsoleError],
                500,
            )
            .unwrap();

        for j in 0..RING_BUFFER_CAPACITY {
            let event = make_event(
                &format!("obs-{i}"),
                i as u32,
                ObservableEventKind::ConsoleError,
                (i * RING_BUFFER_CAPACITY + j) as u64,
            );
            registry.push_event(&event);
        }
    }

    // Total buffered = MAX_OBSERVERS * RING_BUFFER_CAPACITY = 8 * 128 = 1024
    let total_buffered = MAX_OBSERVERS * RING_BUFFER_CAPACITY;
    assert!(
        total_buffered > MAX_EVENTS_PER_DRAIN,
        "test requires total ({total_buffered}) > drain cap ({MAX_EVENTS_PER_DRAIN})"
    );

    let drained = registry.drain_all();
    assert!(
        drained.len() <= MAX_EVENTS_PER_DRAIN,
        "drain_all must cap at MAX_EVENTS_PER_DRAIN ({MAX_EVENTS_PER_DRAIN}), got {}",
        drained.len()
    );
}

/// bd-3mf.8: Unobserve stops event delivery.
#[test]
fn test_unobserve_stops_delivery() {
    let mut registry = ObserverRegistry::new();

    registry
        .observe(
            "obs-remove".to_string(),
            1,
            vec![ObservableEventKind::ConsoleError],
            500,
        )
        .unwrap();

    // Push event — should buffer
    let event = make_event("obs-remove", 1, ObservableEventKind::ConsoleError, 1);
    registry.push_event(&event);
    assert_eq!(registry.get("obs-remove").unwrap().buffer.len(), 1);

    // Unobserve
    let removed = registry.unobserve("obs-remove").unwrap();
    assert_eq!(removed.buffer.len(), 1, "removed observer should carry its buffer");

    // Push more events — should not be buffered (observer gone)
    let event = make_event("obs-remove", 1, ObservableEventKind::ConsoleError, 2);
    registry.push_event(&event);

    // Drain should yield nothing
    let drained = registry.drain_all();
    assert!(drained.is_empty(), "no events after unobserve");
}

/// bd-3mf.8: OSC compiles events under token budget.
#[test]
fn test_observation_compiler_budgeted_summary() {
    let events: Vec<ObservationEvent> = (0..50)
        .map(|i| {
            let kind = if i % 3 == 0 {
                ObservableEventKind::ConsoleError
            } else if i % 3 == 1 {
                ObservableEventKind::NetworkError
            } else {
                ObservableEventKind::DomMutation
            };
            ObservationEvent::with_timestamp(
                "obs-osc".to_string(),
                1,
                kind,
                2_000_000 + i,
                json!({ "message": format!("event-{i}"), "url": format!("https://test/{i}") }),
            )
        })
        .collect();

    // Large budget — should include all event types
    let compiled = compile_observations(&events, 10_000);
    assert_eq!(compiled.events_processed, 50);
    assert!(compiled.summary.contains("[Browser Observation]"));
    assert!(compiled.summary.contains("console_error"));
    assert!(compiled.summary.contains("network_error"));
    assert!(compiled.summary.contains("dom_mutation"));

    // Small budget — should truncate
    let compiled_small = compile_observations(&events, 15);
    assert!(
        compiled_small.events_processed < 50,
        "small budget should truncate"
    );
    assert!(compiled_small.token_estimate <= 20); // Allow slight overhead
}

/// bd-3mf.8: Events only delivered to subscribed kinds.
#[test]
fn test_observe_event_subscription_filtering() {
    let mut registry = ObserverRegistry::new();

    // Observer subscribes ONLY to ConsoleError
    registry
        .observe(
            "obs-filter".to_string(),
            1,
            vec![ObservableEventKind::ConsoleError],
            500,
        )
        .unwrap();

    // Push various event kinds
    for kind in [
        ObservableEventKind::ConsoleError,
        ObservableEventKind::ConsoleWarn,
        ObservableEventKind::NetworkError,
        ObservableEventKind::DomMutation,
        ObservableEventKind::Navigation,
        ObservableEventKind::LoadComplete,
    ] {
        let event = make_event("obs-filter", 1, kind, 0);
        registry.push_event(&event);
    }

    // Only ConsoleError should be buffered
    let obs = registry.get("obs-filter").unwrap();
    assert_eq!(obs.buffer.len(), 1, "only subscribed kind should buffer");
    assert_eq!(obs.total_events, 1);
}

/// bd-3mf.8: Events only delivered to matching tab_id.
#[test]
fn test_observe_tab_id_filtering() {
    let mut registry = ObserverRegistry::new();

    // Observer on tab 1
    registry
        .observe(
            "obs-tab1".to_string(),
            1,
            vec![ObservableEventKind::ConsoleError],
            500,
        )
        .unwrap();

    // Push event for tab 1 — should buffer
    let event = make_event("obs-tab1", 1, ObservableEventKind::ConsoleError, 1);
    registry.push_event(&event);

    // Push event for tab 2 — should NOT buffer
    let event = make_event("obs-tab1", 2, ObservableEventKind::ConsoleError, 2);
    registry.push_event(&event);

    let obs = registry.get("obs-tab1").unwrap();
    assert_eq!(obs.buffer.len(), 1, "only matching tab events should buffer");
}

/// bd-3mf.8: Duplicate observer ID rejected.
#[test]
fn test_observe_duplicate_id_rejected() {
    let mut registry = ObserverRegistry::new();

    registry
        .observe(
            "obs-dup".to_string(),
            1,
            vec![ObservableEventKind::ConsoleError],
            500,
        )
        .unwrap();

    let result = registry.observe(
        "obs-dup".to_string(),
        2,
        vec![ObservableEventKind::ConsoleWarn],
        1000,
    );

    assert!(
        matches!(result, Err(ObserverError::AlreadyExists(ref id)) if id == "obs-dup"),
        "duplicate observer ID must be rejected"
    );
}

/// bd-3mf.8: OSC severity ordering (errors before warnings before info).
#[test]
fn test_observation_compiler_severity_ordering() {
    let events = vec![
        ObservationEvent::with_timestamp(
            "obs-1".to_string(), 1, ObservableEventKind::DomMutation, 1000, json!({}),
        ),
        ObservationEvent::with_timestamp(
            "obs-1".to_string(), 1, ObservableEventKind::ConsoleWarn, 1001,
            json!({ "message": "warning" }),
        ),
        ObservationEvent::with_timestamp(
            "obs-1".to_string(), 1, ObservableEventKind::ConsoleError, 1002,
            json!({ "message": "error" }),
        ),
        ObservationEvent::with_timestamp(
            "obs-1".to_string(), 1, ObservableEventKind::NetworkError, 1003,
            json!({ "url": "https://fail" }),
        ),
    ];

    let compiled = compile_observations(&events, 10_000);
    let summary = &compiled.summary;

    let error_pos = summary.find("console_error").expect("missing console_error");
    let network_pos = summary.find("network_error").expect("missing network_error");
    let warn_pos = summary.find("console_warn").expect("missing console_warn");
    let dom_pos = summary.find("dom_mutation").expect("missing dom_mutation");

    assert!(error_pos < network_pos, "errors before network errors");
    assert!(network_pos < warn_pos, "network errors before warnings");
    assert!(warn_pos < dom_pos, "warnings before dom mutations");
}

/// bd-3mf.8: Plan constant values match interview-locked PLAN.md specs.
#[test]
fn test_observer_plan_constants() {
    assert_eq!(MAX_OBSERVERS, 8, "PLAN.md §9: max 8 observers");
    assert_eq!(RING_BUFFER_CAPACITY, 128, "PLAN.md §9: 128 events/observer");
    assert_eq!(MAX_EVENTS_PER_DRAIN, 256, "PLAN.md §9: 256 global drain cap");
    assert_eq!(MAX_EVENT_BYTES, 4096, "PLAN.md §9: 4KB max event size");
    assert_eq!(THROTTLE_FLOOR_MS, 500, "PLAN.md §9: 500ms hard throttle floor");
}
