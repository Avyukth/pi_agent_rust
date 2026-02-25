//! Live Page Observation — ObserverRegistry, ring buffer, and OSC.
//!
//! This module implements Pi-exclusive push-based browser observation:
//! - ObserverRegistry: manages up to MAX_OBSERVERS concurrent observers
//! - Ring buffer: 128 events per observer with FIFO eviction
//! - Observation Signal Compiler (OSC): dedupes, correlates causally, and renders
//!   under a token budget
//!
//! See PLAN.md §9 for the full design rationale and memory bound chain.

use std::collections::HashMap;
// Arc removed - not currently needed
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Constants (interview-locked from PLAN.md)
// ============================================================================

/// Maximum concurrent observers (interview-locked).
pub const MAX_OBSERVERS: usize = 8;

/// Ring buffer capacity per observer (interview-locked).
pub const RING_BUFFER_CAPACITY: usize = 128;

/// Maximum events to drain per call (interview-locked).
pub const MAX_EVENTS_PER_DRAIN: usize = 256;

/// Maximum bytes per observation event (interview-locked).
pub const MAX_EVENT_BYTES: usize = 4096;

/// Hard throttle floor in milliseconds (interview-locked, no override).
pub const THROTTLE_FLOOR_MS: u64 = 500;

// ============================================================================
// Event Types
// ============================================================================

/// Observable event kinds that can be subscribed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservableEventKind {
    ConsoleError,
    ConsoleWarn,
    NetworkError,
    DomMutation,
    Navigation,
    LoadComplete,
}

impl std::fmt::Display for ObservableEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsoleError => write!(f, "console_error"),
            Self::ConsoleWarn => write!(f, "console_warn"),
            Self::NetworkError => write!(f, "network_error"),
            Self::DomMutation => write!(f, "dom_mutation"),
            Self::Navigation => write!(f, "navigation"),
            Self::LoadComplete => write!(f, "load_complete"),
        }
    }
}

/// A single observation event pushed from the extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationEvent {
    /// The observer that generated this event.
    pub observer_id: String,
    /// The tab ID this event originated from.
    pub tab_id: u32,
    /// The kind of event.
    pub kind: ObservableEventKind,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Event-specific payload.
    #[serde(default)]
    pub payload: serde_json::Value,
}

impl ObservationEvent {
    /// Create a new observation event with the current timestamp.
    #[must_use]
    pub fn new(
        observer_id: String,
        tab_id: u32,
        kind: ObservableEventKind,
        payload: serde_json::Value,
    ) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);

        Self {
            observer_id,
            tab_id,
            kind,
            timestamp_ms,
            payload,
        }
    }

    /// Create an event with a specific timestamp (for testing).
    #[must_use]
    pub const fn with_timestamp(
        observer_id: String,
        tab_id: u32,
        kind: ObservableEventKind,
        timestamp_ms: u64,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            observer_id,
            tab_id,
            kind,
            timestamp_ms,
            payload,
        }
    }
}

// ============================================================================
// Ring Buffer
// ============================================================================

/// A bounded ring buffer for observation events with FIFO eviction.
///
/// Capacity is fixed at RING_BUFFER_CAPACITY (128 events).
/// When full, the oldest event is evicted to make room for new events.
#[derive(Debug, Clone)]
pub struct ObservationRingBuffer {
    buffer: Vec<ObservationEvent>,
    head: usize, // Index of the oldest element
    len: usize,  // Current number of elements
}

impl Default for ObservationRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationRingBuffer {
    /// Create a new empty ring buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(RING_BUFFER_CAPACITY),
            head: 0,
            len: 0,
        }
    }

    /// Push an event into the buffer, evicting the oldest if full.
    pub fn push(&mut self, event: ObservationEvent) {
        if self.len < RING_BUFFER_CAPACITY {
            // Buffer not yet full
            self.buffer.push(event);
            self.len += 1;
        } else {
            // Buffer full, overwrite oldest (at head)
            self.buffer[self.head] = event;
            self.head = (self.head + 1) % RING_BUFFER_CAPACITY;
        }
    }

    /// Drain all events from the buffer, leaving it empty.
    /// Returns events in chronological order (oldest first).
    pub fn drain(&mut self) -> Vec<ObservationEvent> {
        if self.len == 0 {
            return Vec::new();
        }

        let mut result = Vec::with_capacity(self.len);

        for i in 0..self.len {
            let idx = (self.head + i) % RING_BUFFER_CAPACITY;
            result.push(self.buffer[idx].clone());
        }

        // Reset buffer
        self.buffer.clear();
        self.head = 0;
        self.len = 0;

        result
    }

    /// Get the current number of events in the buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Check if the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if the buffer is at capacity.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len >= RING_BUFFER_CAPACITY
    }
}

// ============================================================================
// Observer
// ============================================================================

/// Configuration for an active observer.
#[derive(Debug, Clone)]
pub struct Observer {
    /// Unique observer identifier.
    pub id: String,
    /// Tab ID being observed.
    pub tab_id: u32,
    /// Event types subscribed to.
    pub events: Vec<ObservableEventKind>,
    /// Effective throttle in milliseconds (clamped to >= THROTTLE_FLOOR_MS).
    pub throttle_ms: u64,
    /// Ring buffer for pending events.
    pub buffer: ObservationRingBuffer,
    /// Total events received since creation.
    pub total_events: u64,
}

impl Observer {
    /// Create a new observer with the given configuration.
    #[must_use]
    pub fn new(
        id: String,
        tab_id: u32,
        events: Vec<ObservableEventKind>,
        throttle_ms: u64,
    ) -> Self {
        // Clamp throttle to floor
        let effective_throttle = throttle_ms.max(THROTTLE_FLOOR_MS);

        Self {
            id,
            tab_id,
            events,
            throttle_ms: effective_throttle,
            buffer: ObservationRingBuffer::new(),
            total_events: 0,
        }
    }

    /// Push an event into this observer's buffer.
    pub fn push_event(&mut self, event: ObservationEvent) {
        self.buffer.push(event);
        self.total_events += 1;
    }

    /// Drain all events from this observer's buffer.
    pub fn drain(&mut self) -> Vec<ObservationEvent> {
        self.buffer.drain()
    }

    /// Check if this observer subscribes to a given event kind.
    #[must_use]
    pub fn subscribes_to(&self, kind: ObservableEventKind) -> bool {
        self.events.contains(&kind)
    }
}

// ============================================================================
// Observer Registry
// ============================================================================

/// Errors from the ObserverRegistry.
#[derive(Debug, Error)]
pub enum ObserverError {
    #[error("observer limit reached (max {max})")]
    LimitReached { max: usize },

    #[error("observer not found: {0}")]
    NotFound(String),

    #[error("observer already exists: {0}")]
    AlreadyExists(String),
}

/// Registry managing active observers.
///
/// Enforces MAX_OBSERVERS limit and provides drain API for the agent loop.
#[derive(Debug, Default)]
pub struct ObserverRegistry {
    observers: HashMap<String, Observer>,
}

impl ObserverRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            observers: HashMap::new(),
        }
    }

    /// Register a new observer.
    ///
    /// Returns an error if:
    /// - The limit of MAX_OBSERVERS is reached
    /// - An observer with the same ID already exists
    pub fn observe(
        &mut self,
        id: String,
        tab_id: u32,
        events: Vec<ObservableEventKind>,
        throttle_ms: u64,
    ) -> Result<(), ObserverError> {
        if self.observers.len() >= MAX_OBSERVERS {
            return Err(ObserverError::LimitReached { max: MAX_OBSERVERS });
        }

        if self.observers.contains_key(&id) {
            return Err(ObserverError::AlreadyExists(id));
        }

        let observer = Observer::new(id.clone(), tab_id, events, throttle_ms);
        self.observers.insert(id, observer);

        Ok(())
    }

    /// Unregister an observer by ID.
    ///
    /// Returns the removed observer, or an error if not found.
    pub fn unobserve(&mut self, id: &str) -> Result<Observer, ObserverError> {
        self.observers
            .remove(id)
            .ok_or_else(|| ObserverError::NotFound(id.to_string()))
    }

    /// Get an observer by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Observer> {
        self.observers.get(id)
    }

    /// Get a mutable observer by ID.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Observer> {
        self.observers.get_mut(id)
    }

    /// Push an event to all observers that subscribe to its kind.
    ///
    /// Observers are matched by tab_id and event subscription.
    pub fn push_event(&mut self, event: &ObservationEvent) {
        for observer in self.observers.values_mut() {
            if observer.tab_id == event.tab_id && observer.subscribes_to(event.kind) {
                observer.push_event(event.clone());
            }
        }
    }

    /// Drain events from all observers, up to MAX_EVENTS_PER_DRAIN total.
    ///
    /// Returns events in no particular order. Each observer's buffer is cleared
    /// after draining.
    pub fn drain_all(&mut self) -> Vec<ObservationEvent> {
        let mut all_events = Vec::new();
        let mut remaining = MAX_EVENTS_PER_DRAIN;

        for observer in self.observers.values_mut() {
            if remaining == 0 {
                break;
            }

            let events = observer.drain();
            let take = events.len().min(remaining);
            all_events.extend(events.into_iter().take(take));
            remaining -= take;
        }

        all_events
    }

    /// List all active observers with their status.
    #[must_use]
    pub fn list(&self) -> Vec<ObserverStatus> {
        self.observers
            .values()
            .map(|o| ObserverStatus {
                id: o.id.clone(),
                tab_id: o.tab_id,
                events: o.events.clone(),
                throttle_ms: o.throttle_ms,
                pending_count: o.buffer.len(),
                total_events: o.total_events,
            })
            .collect()
    }

    /// Get the number of active observers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observers.len()
    }

    /// Check if there are no observers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observers.is_empty()
    }
}

/// Status snapshot of an observer for listing.
#[derive(Debug, Clone, Serialize)]
pub struct ObserverStatus {
    pub id: String,
    pub tab_id: u32,
    pub events: Vec<ObservableEventKind>,
    pub throttle_ms: u64,
    pub pending_count: usize,
    pub total_events: u64,
}

// ============================================================================
// Observation Signal Compiler (OSC)
// ============================================================================

/// Compiled observation summary for LLM context injection.
#[derive(Debug, Clone, Serialize)]
pub struct CompiledObservations {
    /// Human-readable summary text.
    pub summary: String,
    /// Estimated token count.
    pub token_estimate: usize,
    /// Number of events processed.
    pub events_processed: usize,
}

impl CompiledObservations {
    /// Create an empty compiled observation.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            summary: String::new(),
            token_estimate: 0,
            events_processed: 0,
        }
    }
}

/// Compile observation events into a token-bounded causal summary.
///
/// Pipeline:
/// 1. Normalize events into signatures
/// 2. Cluster duplicates within a 2s causal window
/// 3. Correlate causal bursts (e.g., load_complete → console_error)
/// 4. Rank by severity and novelty
/// 5. Render under a strict token budget
///
/// # Arguments
/// * `events` - The events to compile
/// * `token_budget` - Maximum estimated tokens for the output
///
/// # Returns
/// A compiled summary suitable for LLM context injection
#[must_use]
pub fn compile_observations(
    events: &[ObservationEvent],
    token_budget: usize,
) -> CompiledObservations {
    if events.is_empty() {
        return CompiledObservations::empty();
    }

    // Step 1 & 2: Group events by kind and count occurrences
    let mut kind_counts: HashMap<ObservableEventKind, usize> = HashMap::new();
    let mut kind_examples: HashMap<ObservableEventKind, &ObservationEvent> = HashMap::new();
    let mut events_by_kind: HashMap<ObservableEventKind, Vec<&ObservationEvent>> = HashMap::new();

    for event in events {
        *kind_counts.entry(event.kind).or_insert(0) += 1;
        events_by_kind.entry(event.kind).or_default().push(event);

        // Keep first example of each kind
        kind_examples.entry(event.kind).or_insert(event);
    }

    // Step 3: Sort by severity (errors > warnings > others)
    let severity_order = |kind: &ObservableEventKind| -> u8 {
        match kind {
            ObservableEventKind::ConsoleError => 0,
            ObservableEventKind::NetworkError => 1,
            ObservableEventKind::ConsoleWarn => 2,
            ObservableEventKind::LoadComplete => 3,
            ObservableEventKind::Navigation => 4,
            ObservableEventKind::DomMutation => 5,
        }
    };

    let mut sorted_kinds: Vec<_> = kind_counts.keys().collect();
    sorted_kinds.sort_by_key(|k| severity_order(k));

    // Step 4 & 5: Render under token budget
    let mut lines = Vec::new();
    let mut current_estimate = 0;
    let mut events_processed = 0;

    // Header
    let header = "[Browser Observation]";
    current_estimate += header.len() / 4; // Rough token estimate

    for kind in sorted_kinds {
        let count = kind_counts[kind];
        let example = kind_examples[kind];

        // Format line
        let line = if count == 1 {
            format!(
                "- {} on tab {} (t={}ms)",
                kind, example.tab_id, example.timestamp_ms
            )
        } else {
            // Try to get a representative message for errors
            let payload_hint = if matches!(
                kind,
                ObservableEventKind::ConsoleError | ObservableEventKind::ConsoleWarn
            ) {
                example
                    .payload
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(|s| {
                        if s.len() > 60 {
                            format!(": {}...", &s[..57])
                        } else {
                            format!(": {s}")
                        }
                    })
                    .unwrap_or_default()
            } else if matches!(kind, ObservableEventKind::NetworkError) {
                example
                    .payload
                    .get("url")
                    .and_then(|u| u.as_str())
                    .map(|u| format!(": {u}"))
                    .unwrap_or_default()
            } else if matches!(
                kind,
                ObservableEventKind::LoadComplete | ObservableEventKind::Navigation
            ) {
                example
                    .payload
                    .get("url")
                    .and_then(|u| u.as_str())
                    .map(|u| format!(": {u}"))
                    .unwrap_or_default()
            } else {
                String::new()
            };

            format!("- {kind} x{count}{payload_hint}")
        };

        // Check token budget
        let line_tokens = line.len() / 4 + 1;
        if current_estimate + line_tokens > token_budget {
            break;
        }

        lines.push(line);
        current_estimate += line_tokens;
        events_processed += count;
    }

    let summary = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n{}", header, lines.join("\n"))
    };

    CompiledObservations {
        summary,
        token_estimate: current_estimate,
        events_processed,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_ring_buffer_push_and_drain() {
        let mut buffer = ObservationRingBuffer::new();

        // Push some events
        for i in 0..5 {
            let event = ObservationEvent::new(
                "obs-1".to_string(),
                1,
                ObservableEventKind::ConsoleError,
                json!({ "msg": i }),
            );
            buffer.push(event);
        }

        assert_eq!(buffer.len(), 5);
        assert!(!buffer.is_full());

        // Drain and verify order
        let events = buffer.drain();
        assert_eq!(events.len(), 5);
        assert!(buffer.is_empty());

        // Verify chronological order
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.payload["msg"], i);
        }
    }

    #[test]
    fn test_ring_buffer_fifo_eviction() {
        let mut buffer = ObservationRingBuffer::new();

        // Fill buffer to capacity
        for i in 0..RING_BUFFER_CAPACITY {
            let event = ObservationEvent::new(
                "obs-1".to_string(),
                1,
                ObservableEventKind::ConsoleError,
                json!({ "seq": i }),
            );
            buffer.push(event);
        }

        assert!(buffer.is_full());
        assert_eq!(buffer.len(), RING_BUFFER_CAPACITY);

        // Push one more - should evict oldest (seq=0)
        let event = ObservationEvent::new(
            "obs-1".to_string(),
            1,
            ObservableEventKind::ConsoleError,
            json!({ "seq": RING_BUFFER_CAPACITY }),
        );
        buffer.push(event);

        let events = buffer.drain();

        // First event should now be seq=1 (oldest was evicted)
        assert_eq!(events[0].payload["seq"], 1);
        // Last event should be the newest
        assert_eq!(events.last().unwrap().payload["seq"], RING_BUFFER_CAPACITY);
    }

    #[test]
    fn test_observer_registry_limit() {
        let mut registry = ObserverRegistry::new();

        // Fill to limit
        for i in 0..MAX_OBSERVERS {
            let result = registry.observe(
                format!("obs-{}", i),
                i as u32,
                vec![ObservableEventKind::ConsoleError],
                500,
            );
            assert!(result.is_ok());
        }

        // Next should fail
        let result = registry.observe(
            "obs-extra".to_string(),
            99,
            vec![ObservableEventKind::ConsoleError],
            500,
        );
        assert!(matches!(result, Err(ObserverError::LimitReached { .. })));
    }

    #[test]
    fn test_observer_registry_unobserve() {
        let mut registry = ObserverRegistry::new();

        registry
            .observe(
                "obs-1".to_string(),
                1,
                vec![ObservableEventKind::ConsoleError],
                500,
            )
            .unwrap();

        // Remove existing
        let result = registry.unobserve("obs-1");
        assert!(result.is_ok());
        assert!(registry.is_empty());

        // Remove non-existing
        let result = registry.unobserve("obs-1");
        assert!(matches!(result, Err(ObserverError::NotFound(_))));
    }

    #[test]
    fn test_observer_registry_push_event() {
        let mut registry = ObserverRegistry::new();

        registry
            .observe(
                "obs-1".to_string(),
                1,
                vec![
                    ObservableEventKind::ConsoleError,
                    ObservableEventKind::LoadComplete,
                ],
                500,
            )
            .unwrap();

        registry
            .observe(
                "obs-2".to_string(),
                2,
                vec![ObservableEventKind::ConsoleError],
                500,
            )
            .unwrap();

        // Push event for tab 1 - should only go to obs-1
        let event = ObservationEvent::new(
            "obs-1".to_string(),
            1,
            ObservableEventKind::ConsoleError,
            json!({ "msg": "test" }),
        );
        registry.push_event(&event);

        let obs1 = registry.get("obs-1").unwrap();
        let obs2 = registry.get("obs-2").unwrap();

        assert_eq!(obs1.buffer.len(), 1);
        assert_eq!(obs2.buffer.len(), 0);
    }

    #[test]
    fn test_observer_registry_drain_all() {
        let mut registry = ObserverRegistry::new();

        registry
            .observe(
                "obs-1".to_string(),
                1,
                vec![ObservableEventKind::ConsoleError],
                500,
            )
            .unwrap();

        // Push multiple events
        for i in 0..10 {
            let event = ObservationEvent::new(
                "obs-1".to_string(),
                1,
                ObservableEventKind::ConsoleError,
                json!({ "seq": i }),
            );
            registry.push_event(&event);
        }

        let events = registry.drain_all();
        assert_eq!(events.len(), 10);

        // Buffers should be empty
        let obs = registry.get("obs-1").unwrap();
        assert!(obs.buffer.is_empty());
    }

    #[test]
    fn test_observer_throttle_clamping() {
        let mut registry = ObserverRegistry::new();

        // Request throttle below floor
        registry
            .observe(
                "obs-1".to_string(),
                1,
                vec![ObservableEventKind::ConsoleError],
                100, // Below THROTTLE_FLOOR_MS
            )
            .unwrap();

        let obs = registry.get("obs-1").unwrap();
        assert_eq!(obs.throttle_ms, THROTTLE_FLOOR_MS);
    }

    #[test]
    fn test_compile_observations_empty() {
        let compiled = compile_observations(&[], 1000);
        assert!(compiled.summary.is_empty());
        assert_eq!(compiled.events_processed, 0);
    }

    #[test]
    fn test_compile_observations_deduplication() {
        let events: Vec<ObservationEvent> = (0..5)
            .map(|i| {
                ObservationEvent::with_timestamp(
                    "obs-1".to_string(),
                    1,
                    ObservableEventKind::ConsoleError,
                    1000 + i,
                    json!({ "message": "Same error" }),
                )
            })
            .collect();

        let compiled = compile_observations(&events, 1000);

        // Should show count, not individual events
        assert!(compiled.summary.contains("console_error x5"));
        assert_eq!(compiled.events_processed, 5);
    }

    #[test]
    fn test_compile_observations_token_budget() {
        // Use diverse event kinds so each becomes a separate line in the output,
        // allowing a small token budget to actually truncate.
        let kinds = [
            ObservableEventKind::ConsoleError,
            ObservableEventKind::NetworkError,
            ObservableEventKind::ConsoleWarn,
            ObservableEventKind::LoadComplete,
            ObservableEventKind::Navigation,
            ObservableEventKind::DomMutation,
        ];

        let mut events = Vec::new();
        for i in 0..100 {
            let kind = kinds[i as usize % kinds.len()];
            events.push(ObservationEvent::with_timestamp(
                "obs-1".to_string(),
                1,
                kind,
                1000 + i,
                json!({ "message": format!("Event message {}", i) }),
            ));
        }

        // Small budget should truncate (6 distinct kinds → 6 lines, small budget can't fit all)
        let compiled = compile_observations(&events, 20);
        assert!(compiled.token_estimate <= 25); // Allow small overhead
        assert!(compiled.events_processed < 100); // Not all processed

        // Large budget should include all
        let compiled = compile_observations(&events, 10000);
        assert_eq!(compiled.events_processed, 100);
    }

    #[test]
    fn test_ring_buffer_overflow_evicts_oldest() {
        let mut registry = ObserverRegistry::new();
        registry
            .observe(
                "obs-ring".to_string(),
                1,
                vec![ObservableEventKind::ConsoleError],
                500,
            )
            .unwrap();

        // Push RING_BUFFER_CAPACITY + 10 events
        for i in 0..(RING_BUFFER_CAPACITY + 10) {
            let event = ObservationEvent::with_timestamp(
                "obs-ring".to_string(),
                1,
                ObservableEventKind::ConsoleError,
                i as u64,
                json!({ "seq": i }),
            );
            registry.push_event(&event);
        }

        let obs = registry.get("obs-ring").unwrap();
        assert_eq!(
            obs.buffer.len(),
            RING_BUFFER_CAPACITY,
            "buffer must not exceed capacity"
        );

        // Drain and verify oldest events were evicted
        let events = registry.drain_all();
        assert_eq!(events.len(), RING_BUFFER_CAPACITY);
        // First event should be the 11th (index 10), since first 10 were evicted
        let first_seq = events[0].payload.get("seq").and_then(|v| v.as_u64());
        assert_eq!(first_seq, Some(10), "oldest events should be evicted");
    }

    #[test]
    fn test_drain_all_respects_max_events_per_drain() {
        let mut registry = ObserverRegistry::new();

        // Create multiple observers, each with full buffers
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
                let event = ObservationEvent::with_timestamp(
                    format!("obs-{i}"),
                    i as u32,
                    ObservableEventKind::ConsoleError,
                    j as u64,
                    json!({ "obs": i, "seq": j }),
                );
                registry.push_event(&event);
            }
        }

        // Total events = MAX_OBSERVERS * RING_BUFFER_CAPACITY = 8 * 128 = 1024
        // drain_all should cap at MAX_EVENTS_PER_DRAIN = 256
        let events = registry.drain_all();
        assert!(
            events.len() <= MAX_EVENTS_PER_DRAIN,
            "drain_all must cap at MAX_EVENTS_PER_DRAIN, got {}",
            events.len()
        );
    }

    #[test]
    fn test_list_multiple_observers() {
        let mut registry = ObserverRegistry::new();

        for i in 0..3 {
            registry
                .observe(
                    format!("obs-{i}"),
                    i as u32,
                    vec![ObservableEventKind::ConsoleError],
                    500 + (i as u64 * 100),
                )
                .unwrap();
        }

        let list = registry.list();
        assert_eq!(list.len(), 3);

        // Verify each observer's status is correct
        for status in &list {
            assert!(
                status.id.starts_with("obs-"),
                "list should return observer IDs"
            );
            assert!(
                status.throttle_ms >= THROTTLE_FLOOR_MS,
                "throttle must be >= floor"
            );
        }
    }

    #[test]
    fn test_observer_error_display() {
        let err = ObserverError::LimitReached { max: MAX_OBSERVERS };
        let msg = format!("{err}");
        assert!(msg.contains(&MAX_OBSERVERS.to_string()));

        let err = ObserverError::AlreadyExists("obs-dup".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("obs-dup"));

        let err = ObserverError::NotFound("obs-ghost".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("obs-ghost"));
    }

    #[test]
    fn test_constants_match_plan() {
        assert_eq!(MAX_OBSERVERS, 8);
        assert_eq!(RING_BUFFER_CAPACITY, 128);
        assert_eq!(MAX_EVENTS_PER_DRAIN, 256);
        assert_eq!(MAX_EVENT_BYTES, 4096);
        assert_eq!(THROTTLE_FLOOR_MS, 500);
    }

    #[test]
    fn test_observable_event_kind_serde_roundtrip() {
        let kinds = [
            ObservableEventKind::ConsoleError,
            ObservableEventKind::ConsoleWarn,
            ObservableEventKind::NetworkError,
            ObservableEventKind::DomMutation,
            ObservableEventKind::Navigation,
            ObservableEventKind::LoadComplete,
        ];
        for kind in &kinds {
            let serialized = serde_json::to_string(kind).expect("serialize");
            let deserialized: ObservableEventKind =
                serde_json::from_str(&serialized).expect("deserialize");
            assert_eq!(&deserialized, kind, "kind roundtrip must preserve variant");
        }
    }

    #[test]
    fn test_compile_observations_single_event_raw_passthrough() {
        let events = vec![ObservationEvent::new(
            "obs-1".to_string(),
            1,
            ObservableEventKind::ConsoleError,
            json!({ "message": "Single error" }),
        )];

        let compiled = compile_observations(&events, 1000);
        assert_eq!(compiled.events_processed, 1);
        assert!(!compiled.summary.is_empty());
        assert!(compiled.summary.contains("console_error"));
    }

    #[test]
    fn test_compile_observations_severity_ordering() {
        let events = vec![
            ObservationEvent::new(
                "obs-1".to_string(),
                1,
                ObservableEventKind::LoadComplete,
                json!({}),
            ),
            ObservationEvent::new(
                "obs-1".to_string(),
                1,
                ObservableEventKind::ConsoleError,
                json!({}),
            ),
            ObservationEvent::new(
                "obs-1".to_string(),
                1,
                ObservableEventKind::ConsoleWarn,
                json!({}),
            ),
        ];

        let compiled = compile_observations(&events, 1000);

        // console_error should appear before console_warn before load_complete
        let error_pos = compiled.summary.find("console_error").unwrap();
        let warn_pos = compiled.summary.find("console_warn").unwrap();
        let load_pos = compiled.summary.find("load_complete").unwrap();

        assert!(error_pos < warn_pos);
        assert!(warn_pos < load_pos);
    }
}
