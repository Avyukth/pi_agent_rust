//! AMAC-style interleaved hostcall batch executor with stall-aware toggling.
//!
//! AMAC (Asynchronous Memory Access Chaining) interleaves multiple independent
//! hostcall state machines per scheduler tick to hide memory-access latency.
//! When the working set exceeds the LLC, sequential dispatch stalls on cache
//! misses; interleaving lets one request's computation overlap another's
//! memory fetch, improving throughput by up to the memory-level parallelism
//! ratio.
//!
//! The executor dynamically toggles between batched-interleaved and sequential
//! dispatch based on observed per-call timing telemetry as a proxy for LLC miss
//! rates and stall cycles.

use crate::extensions_js::HostcallKind;
use crate::extensions_js::HostcallRequest;
use crate::scheduler::HostcallOutcome;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── Configuration constants ──────────────────────────────────────────────

/// Minimum batch size to consider AMAC interleaving (below this, sequential
/// dispatch has less overhead).
const AMAC_MIN_BATCH_SIZE: usize = 4;

/// Maximum number of in-flight state machines per interleave round.
const AMAC_MAX_INTERLEAVE_WIDTH: usize = 16;

/// Stall-detection threshold: if a request takes longer than this many
/// nanoseconds, it's treated as a "stall" (likely LLC miss or IO wait).
const AMAC_STALL_THRESHOLD_NS: u64 = 100_000; // 100us

/// Exponential moving average decay factor (fixed-point, 0..256 maps to 0..1).
/// EMA_ALPHA=51 ≈ 0.2, giving 80% weight to history.
const EMA_ALPHA: u64 = 51;
const EMA_SCALE: u64 = 256;

/// Minimum stall ratio (fixed-point, 0..1000) to enable AMAC interleaving.
/// 200 = 20% stall rate.
const AMAC_STALL_RATIO_THRESHOLD: u64 = 200;

/// Maximum ratio (fixed-point, 0..1000) above which we assume all calls are
/// memory-bound and interleaving provides maximum benefit.
const AMAC_STALL_RATIO_SATURATED: u64 = 800;

/// How many recent timing samples to retain for decision-making.
const TELEMETRY_WINDOW_SIZE: usize = 64;

// ── Core types ───────────────────────────────────────────────────────────

/// Grouping key for batching compatible hostcall requests together.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AmacGroupKey {
    /// Session read operations (get_state, get_messages, etc.) - highly batchable.
    SessionRead,
    /// Session write operations (set_model, set_name, etc.) - must preserve order.
    SessionWrite,
    /// Event queries (get_model, get_flag, list_flags) - batchable.
    EventRead,
    /// Event mutations (set_model, register_*) - preserve order.
    EventWrite,
    /// Tool invocations - independent, can interleave.
    Tool,
    /// Exec invocations - independent but may have side effects.
    Exec,
    /// HTTP requests - independent, high latency → good AMAC candidates.
    Http,
    /// UI operations - typically sequential.
    Ui,
    /// Log operations - fire-and-forget, trivially batchable.
    Log,
}

impl AmacGroupKey {
    /// Classify a hostcall request into its batch group.
    #[must_use]
    pub fn from_request(request: &HostcallRequest) -> Self {
        match &request.kind {
            HostcallKind::Session { op } => {
                if is_session_read_op(op) {
                    Self::SessionRead
                } else {
                    Self::SessionWrite
                }
            }
            HostcallKind::Events { op } => {
                if is_event_read_op(op) {
                    Self::EventRead
                } else {
                    Self::EventWrite
                }
            }
            HostcallKind::Tool { .. } => Self::Tool,
            HostcallKind::Exec { .. } => Self::Exec,
            HostcallKind::Http => Self::Http,
            HostcallKind::Ui { .. } => Self::Ui,
            HostcallKind::Log => Self::Log,
        }
    }

    /// Whether requests in this group are safe to interleave (no ordering
    /// dependencies within the group).
    #[must_use]
    pub const fn interleave_safe(&self) -> bool {
        matches!(
            self,
            Self::SessionRead | Self::EventRead | Self::Tool | Self::Http | Self::Log
        )
    }

    /// Estimated memory-boundedness weight for this group (0..100).
    /// Higher means more likely to benefit from interleaving.
    #[must_use]
    pub const fn memory_weight(&self) -> u32 {
        match self {
            Self::Http => 90,                  // Network IO = high stall
            Self::Tool | Self::Exec => 70,     // File IO or subprocess
            Self::SessionRead => 50,           // In-memory but large working set
            Self::EventRead => 40,             // Small working set, fast
            Self::SessionWrite => 30,
            Self::EventWrite => 20,
            Self::Ui => 10,
            Self::Log => 5,
        }
    }
}

/// A group of hostcall requests that share a batch key and can be
/// dispatched together.
#[derive(Debug)]
pub struct AmacBatchGroup {
    /// The batch key for this group.
    pub key: AmacGroupKey,
    /// Requests in this group, in original drain order.
    pub requests: Vec<HostcallRequest>,
}

impl AmacBatchGroup {
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
}

/// The decision of whether to use AMAC interleaving or sequential dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AmacToggleDecision {
    /// Use interleaved dispatch for this batch.
    Interleave {
        /// Number of concurrent state machines per round.
        width: usize,
    },
    /// Use sequential dispatch (AMAC overhead not justified).
    Sequential {
        /// Reason for falling back.
        reason: &'static str,
    },
}

impl AmacToggleDecision {
    #[must_use]
    pub const fn is_interleave(&self) -> bool {
        matches!(self, Self::Interleave { .. })
    }
}

/// Per-call timing observation for stall detection.
#[derive(Debug, Clone, Copy)]
struct TimingSample {
    /// Wall-clock nanoseconds for this dispatch.
    elapsed_ns: u64,
    /// Whether this was classified as a stall.
    stalled: bool,
}

/// Stall telemetry tracker using exponential moving averages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmacStallTelemetry {
    /// EMA of per-call dispatch time (nanoseconds, fixed-point ×256).
    ema_elapsed_scaled: u64,
    /// EMA of stall ratio (fixed-point, 0..1000 ×256).
    ema_stall_ratio_scaled: u64,
    /// Total calls observed.
    total_calls: u64,
    /// Total stalls observed.
    total_stalls: u64,
    /// Recent timing window for variance estimation.
    #[serde(skip)]
    recent_samples: Vec<TimingSample>,
    /// Stall threshold in nanoseconds.
    stall_threshold_ns: u64,
    /// Number of AMAC toggle decisions made.
    pub toggle_decisions: u64,
    /// Number of times AMAC was selected over sequential.
    pub interleave_selections: u64,
}

impl Default for AmacStallTelemetry {
    fn default() -> Self {
        Self::new(AMAC_STALL_THRESHOLD_NS)
    }
}

impl AmacStallTelemetry {
    #[must_use]
    pub fn new(stall_threshold_ns: u64) -> Self {
        Self {
            ema_elapsed_scaled: 0,
            ema_stall_ratio_scaled: 0,
            total_calls: 0,
            total_stalls: 0,
            recent_samples: Vec::with_capacity(TELEMETRY_WINDOW_SIZE),
            stall_threshold_ns,
            toggle_decisions: 0,
            interleave_selections: 0,
        }
    }

    /// Record a timing observation.
    pub fn record(&mut self, elapsed_ns: u64) {
        let stalled = elapsed_ns > self.stall_threshold_ns;
        self.total_calls = self.total_calls.saturating_add(1);
        if stalled {
            self.total_stalls = self.total_stalls.saturating_add(1);
        }

        // Update EMA for elapsed time.
        let scaled_elapsed = elapsed_ns.saturating_mul(EMA_SCALE);
        self.ema_elapsed_scaled = if self.total_calls == 1 {
            scaled_elapsed
        } else {
            // EMA = alpha * new + (1 - alpha) * old
            let alpha_new = scaled_elapsed.saturating_mul(EMA_ALPHA) / EMA_SCALE;
            let alpha_old = self
                .ema_elapsed_scaled
                .saturating_mul(EMA_SCALE.saturating_sub(EMA_ALPHA))
                / EMA_SCALE;
            alpha_new.saturating_add(alpha_old)
        };

        // Update EMA for stall ratio.
        let stall_point = if stalled { 1000 * EMA_SCALE } else { 0 };
        self.ema_stall_ratio_scaled = if self.total_calls == 1 {
            stall_point
        } else {
            let alpha_new = stall_point.saturating_mul(EMA_ALPHA) / EMA_SCALE;
            let alpha_old = self
                .ema_stall_ratio_scaled
                .saturating_mul(EMA_SCALE.saturating_sub(EMA_ALPHA))
                / EMA_SCALE;
            alpha_new.saturating_add(alpha_old)
        };

        // Maintain sliding window.
        let sample = TimingSample {
            elapsed_ns,
            stalled,
        };
        if self.recent_samples.len() >= TELEMETRY_WINDOW_SIZE {
            self.recent_samples.remove(0);
        }
        self.recent_samples.push(sample);
    }

    /// Current smoothed stall ratio (0..1000).
    #[must_use]
    pub fn stall_ratio(&self) -> u64 {
        self.ema_stall_ratio_scaled / EMA_SCALE.max(1)
    }

    /// Current smoothed average elapsed nanoseconds.
    #[must_use]
    pub fn avg_elapsed_ns(&self) -> u64 {
        self.ema_elapsed_scaled / EMA_SCALE.max(1)
    }

    /// Variance of recent timing samples (nanoseconds squared).
    #[must_use]
    pub fn recent_variance(&self) -> u64 {
        if self.recent_samples.len() < 2 {
            return 0;
        }
        let n = self.recent_samples.len() as u64;
        let sum: u64 = self
            .recent_samples
            .iter()
            .map(|sample| sample.elapsed_ns)
            .sum();
        let mean = sum / n;
        let variance: u64 = self
            .recent_samples
            .iter()
            .map(|sample| {
                let diff = sample.elapsed_ns.abs_diff(mean);
                diff.saturating_mul(diff)
            })
            .sum::<u64>()
            / n;
        variance
    }

    /// Snapshot of current telemetry state.
    #[must_use]
    pub fn snapshot(&self) -> AmacStallTelemetrySnapshot {
        AmacStallTelemetrySnapshot {
            stall_ratio: self.stall_ratio(),
            avg_elapsed_ns: self.avg_elapsed_ns(),
            recent_variance: self.recent_variance(),
            total_calls: self.total_calls,
            total_stalls: self.total_stalls,
            toggle_decisions: self.toggle_decisions,
            interleave_selections: self.interleave_selections,
            recent_window_size: self.recent_samples.len(),
        }
    }
}

/// Immutable snapshot of stall telemetry for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmacStallTelemetrySnapshot {
    pub stall_ratio: u64,
    pub avg_elapsed_ns: u64,
    pub recent_variance: u64,
    pub total_calls: u64,
    pub total_stalls: u64,
    pub toggle_decisions: u64,
    pub interleave_selections: u64,
    pub recent_window_size: usize,
}

// ── Batch plan ───────────────────────────────────────────────────────────

/// Execution plan for a batch of hostcall requests.
#[derive(Debug)]
pub struct AmacBatchPlan {
    /// Groups to dispatch, in priority order.
    pub groups: Vec<AmacBatchGroup>,
    /// Per-group toggle decisions.
    pub decisions: Vec<AmacToggleDecision>,
    /// Total requests in the batch.
    pub total_requests: usize,
    /// How many groups will use interleaving.
    pub interleaved_groups: usize,
    /// How many groups will use sequential dispatch.
    pub sequential_groups: usize,
}

/// Result of executing a batch plan.
#[derive(Debug)]
pub struct AmacBatchResult {
    /// Completed hostcall outcomes, in call_id order for deterministic
    /// scheduler enqueuing.
    pub completions: Vec<(String, HostcallOutcome)>,
    /// Telemetry from this batch execution.
    pub batch_telemetry: AmacBatchTelemetry,
}

/// Per-batch execution telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmacBatchTelemetry {
    pub total_requests: usize,
    pub groups_dispatched: usize,
    pub interleaved_groups: usize,
    pub sequential_groups: usize,
    pub total_elapsed_ns: u64,
}

// ── Executor ─────────────────────────────────────────────────────────────

/// AMAC batch executor configuration.
#[derive(Debug, Clone)]
pub struct AmacBatchExecutorConfig {
    /// Minimum batch size to consider interleaving.
    pub min_batch_size: usize,
    /// Maximum interleave width (concurrent state machines).
    pub max_interleave_width: usize,
    /// Enable/disable AMAC globally.
    pub enabled: bool,
}

impl Default for AmacBatchExecutorConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl AmacBatchExecutorConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let enabled = std::env::var("PI_HOSTCALL_AMAC")
            .ok()
            .as_deref()
            .is_none_or(|value| {
                !matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "off" | "disabled"
                )
            });
        let min_batch_size = std::env::var("PI_HOSTCALL_AMAC_MIN_BATCH")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(AMAC_MIN_BATCH_SIZE)
            .max(2);
        let max_interleave_width = std::env::var("PI_HOSTCALL_AMAC_MAX_WIDTH")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(AMAC_MAX_INTERLEAVE_WIDTH)
            .max(2);
        Self {
            min_batch_size,
            max_interleave_width,
            enabled,
        }
    }

    #[must_use]
    pub const fn new(enabled: bool, min_batch_size: usize, max_interleave_width: usize) -> Self {
        Self {
            min_batch_size,
            max_interleave_width,
            enabled,
        }
    }
}

/// The AMAC batch executor.
///
/// Groups incoming hostcall requests by kind, decides per-group whether
/// interleaving or sequential dispatch is optimal based on stall telemetry,
/// and produces an execution plan.
#[derive(Debug, Clone)]
pub struct AmacBatchExecutor {
    config: AmacBatchExecutorConfig,
    telemetry: AmacStallTelemetry,
}

impl AmacBatchExecutor {
    #[must_use]
    pub fn new(config: AmacBatchExecutorConfig) -> Self {
        Self {
            config,
            telemetry: AmacStallTelemetry::default(),
        }
    }

    #[must_use]
    pub const fn with_telemetry(
        config: AmacBatchExecutorConfig,
        telemetry: AmacStallTelemetry,
    ) -> Self {
        Self { config, telemetry }
    }

    /// Access the current stall telemetry.
    #[must_use]
    pub const fn telemetry(&self) -> &AmacStallTelemetry {
        &self.telemetry
    }

    /// Mutable access to telemetry for recording observations.
    pub const fn telemetry_mut(&mut self) -> &mut AmacStallTelemetry {
        &mut self.telemetry
    }

    /// Whether AMAC is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Group a batch of drained hostcall requests and produce an execution plan.
    ///
    /// The plan preserves original request ordering within each group and
    /// chooses interleave vs. sequential per group based on telemetry.
    #[must_use]
    pub fn plan_batch(&mut self, requests: Vec<HostcallRequest>) -> AmacBatchPlan {
        let total_requests = requests.len();

        if !self.config.enabled || total_requests == 0 {
            return AmacBatchPlan {
                groups: Vec::new(),
                decisions: Vec::new(),
                total_requests,
                interleaved_groups: 0,
                sequential_groups: 0,
            };
        }

        // Group by batch key, preserving intra-group order.
        let mut group_map: BTreeMap<AmacGroupKey, Vec<HostcallRequest>> = BTreeMap::new();
        for request in requests {
            let key = AmacGroupKey::from_request(&request);
            group_map.entry(key).or_default().push(request);
        }

        let mut groups = Vec::with_capacity(group_map.len());
        let mut decisions = Vec::with_capacity(group_map.len());
        let mut interleaved_groups = 0_usize;
        let mut sequential_groups = 0_usize;

        for (key, group_requests) in group_map {
            let decision = self.decide_toggle(&key, group_requests.len());
            if decision.is_interleave() {
                interleaved_groups += 1;
            } else {
                sequential_groups += 1;
            }
            groups.push(AmacBatchGroup {
                key,
                requests: group_requests,
            });
            decisions.push(decision);
        }

        self.telemetry.toggle_decisions = self
            .telemetry
            .toggle_decisions
            .saturating_add(groups.len() as u64);
        self.telemetry.interleave_selections = self
            .telemetry
            .interleave_selections
            .saturating_add(interleaved_groups as u64);

        AmacBatchPlan {
            groups,
            decisions,
            total_requests,
            interleaved_groups,
            sequential_groups,
        }
    }

    /// Decide whether a group should use interleaved or sequential dispatch.
    fn decide_toggle(&self, key: &AmacGroupKey, group_size: usize) -> AmacToggleDecision {
        // Rule 1: Too small to benefit from interleaving.
        if group_size < self.config.min_batch_size {
            return AmacToggleDecision::Sequential {
                reason: "batch_too_small",
            };
        }

        // Rule 2: Group is not safe to interleave (ordering dependencies).
        if !key.interleave_safe() {
            return AmacToggleDecision::Sequential {
                reason: "ordering_dependency",
            };
        }

        // Rule 3: Insufficient telemetry history → conservative sequential.
        if self.telemetry.total_calls < TELEMETRY_WINDOW_SIZE as u64 {
            return AmacToggleDecision::Sequential {
                reason: "insufficient_telemetry",
            };
        }

        // Rule 4: Stall ratio below threshold → sequential is fine.
        let stall_ratio = self.telemetry.stall_ratio();
        if stall_ratio < AMAC_STALL_RATIO_THRESHOLD {
            return AmacToggleDecision::Sequential {
                reason: "low_stall_ratio",
            };
        }

        // Rule 5: Compute interleave width based on stall severity.
        let width = compute_interleave_width(
            stall_ratio,
            key.memory_weight(),
            group_size,
            self.config.max_interleave_width,
        );

        if width < 2 {
            return AmacToggleDecision::Sequential {
                reason: "computed_width_too_low",
            };
        }

        AmacToggleDecision::Interleave { width }
    }

    /// Record a per-call timing observation for stall detection.
    pub fn observe_call(&mut self, elapsed_ns: u64) {
        self.telemetry.record(elapsed_ns);
    }
}

impl Default for AmacBatchExecutor {
    fn default() -> Self {
        Self::new(AmacBatchExecutorConfig::default())
    }
}

// ── Helper functions ─────────────────────────────────────────────────────

/// Compute optimal interleave width from stall ratio and group characteristics.
fn compute_interleave_width(
    stall_ratio: u64,
    memory_weight: u32,
    group_size: usize,
    max_width: usize,
) -> usize {
    // Scale width proportionally to stall severity × memory weight.
    // At AMAC_STALL_RATIO_SATURATED, we use max_width.
    let effective_ratio = stall_ratio
        .saturating_sub(AMAC_STALL_RATIO_THRESHOLD)
        .min(AMAC_STALL_RATIO_SATURATED - AMAC_STALL_RATIO_THRESHOLD);
    let ratio_range = AMAC_STALL_RATIO_SATURATED.saturating_sub(AMAC_STALL_RATIO_THRESHOLD);

    // Avoid division by zero.
    if ratio_range == 0 {
        return 2;
    }

    let base_width = 2_u64
        + (effective_ratio * u64::from(memory_weight) * (max_width as u64 - 2))
            / (ratio_range * 100);

    // Safe: base_width is bounded by max_width (which fits in usize).
    let width = usize::try_from(base_width).unwrap_or(max_width);
    width.min(max_width).min(group_size).max(2)
}

/// Check if a session operation is read-only.
fn is_session_read_op(op: &str) -> bool {
    let normalized = op.trim().to_ascii_lowercase();
    let normalized = normalized.replace('_', "");
    matches!(
        normalized.as_str(),
        "getstate"
            | "getmessages"
            | "getentries"
            | "getname"
            | "getmodel"
            | "getlabel"
            | "getlabels"
            | "getallsessions"
    )
}

/// Check if an event operation is read-only.
fn is_event_read_op(op: &str) -> bool {
    let normalized = op.trim().to_ascii_lowercase();
    let normalized = normalized.replace('_', "");
    matches!(
        normalized.as_str(),
        "getactivetools"
            | "getalltools"
            | "getmodel"
            | "getthinkinglevel"
            | "getflag"
            | "listflags"
    )
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(kind: HostcallKind) -> HostcallRequest {
        HostcallRequest {
            call_id: format!("test-{}", rand_id()),
            kind,
            payload: json!({}),
            trace_id: 0,
            extension_id: None,
        }
    }

    fn rand_id() -> u64 {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn session_read_request() -> HostcallRequest {
        make_request(HostcallKind::Session {
            op: "get_state".to_string(),
        })
    }

    fn session_write_request() -> HostcallRequest {
        make_request(HostcallKind::Session {
            op: "set_model".to_string(),
        })
    }

    fn event_read_request() -> HostcallRequest {
        make_request(HostcallKind::Events {
            op: "get_model".to_string(),
        })
    }

    fn tool_request() -> HostcallRequest {
        make_request(HostcallKind::Tool {
            name: "read".to_string(),
        })
    }

    fn http_request() -> HostcallRequest {
        make_request(HostcallKind::Http)
    }

    fn log_request() -> HostcallRequest {
        make_request(HostcallKind::Log)
    }

    // ── AmacGroupKey tests ───────────────────────────────────────────

    #[test]
    fn group_key_classifies_session_reads_correctly() {
        let req = session_read_request();
        assert_eq!(AmacGroupKey::from_request(&req), AmacGroupKey::SessionRead);
    }

    #[test]
    fn group_key_classifies_session_writes_correctly() {
        let req = session_write_request();
        assert_eq!(AmacGroupKey::from_request(&req), AmacGroupKey::SessionWrite);
    }

    #[test]
    fn group_key_classifies_event_reads_correctly() {
        let req = event_read_request();
        assert_eq!(AmacGroupKey::from_request(&req), AmacGroupKey::EventRead);
    }

    #[test]
    fn group_key_classifies_tools_correctly() {
        let req = tool_request();
        assert_eq!(AmacGroupKey::from_request(&req), AmacGroupKey::Tool);
    }

    #[test]
    fn group_key_classifies_http_correctly() {
        let req = http_request();
        assert_eq!(AmacGroupKey::from_request(&req), AmacGroupKey::Http);
    }

    #[test]
    fn group_key_classifies_log_correctly() {
        let req = log_request();
        assert_eq!(AmacGroupKey::from_request(&req), AmacGroupKey::Log);
    }

    #[test]
    fn interleave_safe_for_read_and_independent_groups() {
        assert!(AmacGroupKey::SessionRead.interleave_safe());
        assert!(AmacGroupKey::EventRead.interleave_safe());
        assert!(AmacGroupKey::Tool.interleave_safe());
        assert!(AmacGroupKey::Http.interleave_safe());
        assert!(AmacGroupKey::Log.interleave_safe());
    }

    #[test]
    fn interleave_unsafe_for_write_and_ui_groups() {
        assert!(!AmacGroupKey::SessionWrite.interleave_safe());
        assert!(!AmacGroupKey::EventWrite.interleave_safe());
        assert!(!AmacGroupKey::Ui.interleave_safe());
        assert!(!AmacGroupKey::Exec.interleave_safe());
    }

    // ── Telemetry tests ──────────────────────────────────────────────

    #[test]
    fn telemetry_records_and_tracks_stall_ratio() {
        let mut telemetry = AmacStallTelemetry::new(100_000);

        // Record some fast calls (no stalls).
        for _ in 0..10 {
            telemetry.record(50_000);
        }
        assert_eq!(telemetry.total_calls, 10);
        assert_eq!(telemetry.total_stalls, 0);
        assert!(telemetry.stall_ratio() < AMAC_STALL_RATIO_THRESHOLD);

        // Record some slow calls (stalls).
        for _ in 0..20 {
            telemetry.record(200_000);
        }
        assert_eq!(telemetry.total_calls, 30);
        assert_eq!(telemetry.total_stalls, 20);
        assert!(telemetry.stall_ratio() > 0);
    }

    #[test]
    fn telemetry_ema_converges_to_steady_state() {
        let mut telemetry = AmacStallTelemetry::new(100_000);

        // All fast → stall ratio should converge near 0.
        for _ in 0..100 {
            telemetry.record(10_000);
        }
        assert!(telemetry.stall_ratio() < 50, "expected low stall ratio");

        // All slow → stall ratio should converge near 1000.
        for _ in 0..200 {
            telemetry.record(500_000);
        }
        assert!(
            telemetry.stall_ratio() > 900,
            "expected high stall ratio, got {}",
            telemetry.stall_ratio()
        );
    }

    #[test]
    fn telemetry_sliding_window_bounded() {
        let mut telemetry = AmacStallTelemetry::new(100_000);
        for i in 0..200 {
            telemetry.record(i * 1000);
        }
        assert_eq!(telemetry.recent_samples.len(), TELEMETRY_WINDOW_SIZE);
    }

    #[test]
    fn telemetry_variance_zero_for_constant_input() {
        let mut telemetry = AmacStallTelemetry::new(100_000);
        for _ in 0..10 {
            telemetry.record(50_000);
        }
        assert_eq!(telemetry.recent_variance(), 0);
    }

    #[test]
    fn telemetry_snapshot_captures_state() {
        let mut telemetry = AmacStallTelemetry::new(100_000);
        for _ in 0..5 {
            telemetry.record(50_000);
        }
        let snap = telemetry.snapshot();
        assert_eq!(snap.total_calls, 5);
        assert_eq!(snap.total_stalls, 0);
        assert_eq!(snap.recent_window_size, 5);
    }

    // ── Executor plan tests ──────────────────────────────────────────

    #[test]
    fn plan_empty_batch_returns_empty_plan() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 4, 16));
        let plan = executor.plan_batch(Vec::new());
        assert_eq!(plan.total_requests, 0);
        assert!(plan.groups.is_empty());
        assert!(plan.decisions.is_empty());
    }

    #[test]
    fn plan_disabled_executor_returns_empty_groups() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(false, 4, 16));
        let requests = vec![tool_request(), tool_request()];
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.total_requests, 2);
        assert!(plan.groups.is_empty());
    }

    #[test]
    fn plan_groups_requests_by_kind() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 2, 16));
        let requests = vec![
            session_read_request(),
            tool_request(),
            session_read_request(),
            http_request(),
            tool_request(),
        ];
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.total_requests, 5);
        assert_eq!(plan.groups.len(), 3); // SessionRead, Tool, Http
    }

    #[test]
    fn plan_preserves_intra_group_order() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 2, 16));
        let req1 = session_read_request();
        let req2 = session_read_request();
        let id1 = req1.call_id.clone();
        let id2 = req2.call_id.clone();

        let requests = vec![req1, req2];
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].requests[0].call_id, id1);
        assert_eq!(plan.groups[0].requests[1].call_id, id2);
    }

    #[test]
    fn plan_sequential_for_small_groups_without_telemetry() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 4, 16));
        let requests = vec![tool_request(), tool_request()]; // < min_batch_size=4
        let plan = executor.plan_batch(requests);
        assert!(plan.decisions.iter().all(|d| !d.is_interleave()));
    }

    #[test]
    fn plan_sequential_for_write_groups() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 2, 16));

        // Prime telemetry with high stall ratio.
        for _ in 0..100 {
            executor.observe_call(500_000);
        }

        let requests = vec![
            session_write_request(),
            session_write_request(),
            session_write_request(),
            session_write_request(),
        ];
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.groups.len(), 1);
        assert!(
            plan.decisions[0]
                == AmacToggleDecision::Sequential {
                    reason: "ordering_dependency"
                }
        );
    }

    #[test]
    fn plan_interleave_with_high_stall_ratio_and_sufficient_batch() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 4, 16));

        // Prime telemetry with high stall ratio.
        for _ in 0..100 {
            executor.observe_call(500_000);
        }

        let requests: Vec<HostcallRequest> = (0..8).map(|_| http_request()).collect();
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.groups.len(), 1);
        assert!(plan.decisions[0].is_interleave());
        if let AmacToggleDecision::Interleave { width } = plan.decisions[0] {
            assert!(width >= 2);
            assert!(width <= 16);
        }
    }

    #[test]
    fn plan_sequential_with_low_stall_ratio() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 4, 16));

        // Prime telemetry with low stall ratio.
        for _ in 0..100 {
            executor.observe_call(10_000);
        }

        let requests: Vec<HostcallRequest> = (0..8).map(|_| http_request()).collect();
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.groups.len(), 1);
        assert!(!plan.decisions[0].is_interleave());
    }

    // ── Toggle decision tests ────────────────────────────────────────

    #[test]
    fn toggle_interleave_width_scales_with_stall_severity() {
        // Higher stall ratio → wider interleave.
        let width_low = compute_interleave_width(300, 90, 16, 16);
        let width_high = compute_interleave_width(700, 90, 16, 16);
        assert!(
            width_high >= width_low,
            "higher stall ratio should give wider interleave: low={width_low}, high={width_high}"
        );
    }

    #[test]
    fn toggle_width_capped_by_group_size() {
        let width = compute_interleave_width(800, 90, 3, 16);
        assert!(width <= 3);
    }

    #[test]
    fn toggle_width_capped_by_max_width() {
        let width = compute_interleave_width(800, 90, 100, 8);
        assert!(width <= 8);
    }

    #[test]
    fn toggle_width_minimum_is_two() {
        let width = compute_interleave_width(201, 5, 100, 16);
        assert!(width >= 2);
    }

    // ── Session/event operation classification ───────────────────────

    #[test]
    fn session_read_ops_classified_correctly() {
        assert!(is_session_read_op("get_state"));
        assert!(is_session_read_op("getState"));
        assert!(is_session_read_op("get_messages"));
        assert!(is_session_read_op("getMessages"));
        assert!(is_session_read_op("get_entries"));
        assert!(is_session_read_op("getEntries"));
    }

    #[test]
    fn session_write_ops_classified_correctly() {
        assert!(!is_session_read_op("set_model"));
        assert!(!is_session_read_op("setModel"));
        assert!(!is_session_read_op("set_name"));
        assert!(!is_session_read_op("add_label"));
    }

    #[test]
    fn event_read_ops_classified_correctly() {
        assert!(is_event_read_op("get_active_tools"));
        assert!(is_event_read_op("getActiveTools"));
        assert!(is_event_read_op("get_all_tools"));
        assert!(is_event_read_op("get_model"));
        assert!(is_event_read_op("get_flag"));
        assert!(is_event_read_op("list_flags"));
    }

    #[test]
    fn event_write_ops_classified_correctly() {
        assert!(!is_event_read_op("set_active_tools"));
        assert!(!is_event_read_op("set_model"));
        assert!(!is_event_read_op("register_command"));
        assert!(!is_event_read_op("register_provider"));
    }

    // ── Serialization round-trip ─────────────────────────────────────

    #[test]
    fn telemetry_snapshot_serializes_deterministically() {
        let mut telemetry = AmacStallTelemetry::new(100_000);
        for i in 0..10 {
            telemetry.record(i * 10_000);
        }
        let snap = telemetry.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize snapshot");
        let deserialized: AmacStallTelemetrySnapshot =
            serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(deserialized.total_calls, snap.total_calls);
        assert_eq!(deserialized.total_stalls, snap.total_stalls);
        assert_eq!(deserialized.toggle_decisions, snap.toggle_decisions);
    }

    #[test]
    fn group_key_serializes_round_trip() {
        let keys = vec![
            AmacGroupKey::SessionRead,
            AmacGroupKey::SessionWrite,
            AmacGroupKey::EventRead,
            AmacGroupKey::EventWrite,
            AmacGroupKey::Tool,
            AmacGroupKey::Exec,
            AmacGroupKey::Http,
            AmacGroupKey::Ui,
            AmacGroupKey::Log,
        ];
        for key in keys {
            let json = serde_json::to_string(&key).expect("serialize key");
            let deserialized: AmacGroupKey = serde_json::from_str(&json).expect("deserialize key");
            assert_eq!(deserialized, key);
        }
    }

    #[test]
    fn toggle_decision_serializes_round_trip() {
        let interleave = AmacToggleDecision::Interleave { width: 8 };
        let json = serde_json::to_string(&interleave).expect("serialize");
        let json: &'static str = Box::leak(json.into_boxed_str());
        let deserialized: AmacToggleDecision = serde_json::from_str(json).expect("deserialize");
        assert_eq!(deserialized, interleave);

        let sequential = AmacToggleDecision::Sequential {
            reason: "batch_too_small",
        };
        let json = serde_json::to_string(&sequential).expect("serialize");
        let json: &'static str = Box::leak(json.into_boxed_str());
        let deserialized: AmacToggleDecision = serde_json::from_str(json).expect("deserialize");
        assert_eq!(deserialized, sequential);
    }

    // ── Mixed batch scenarios ────────────────────────────────────────

    #[test]
    fn mixed_batch_groups_independently() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 2, 16));
        let requests = vec![
            session_read_request(),
            tool_request(),
            http_request(),
            session_write_request(),
            log_request(),
            event_read_request(),
            session_read_request(),
            tool_request(),
        ];
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.total_requests, 8);

        // Should have groups for: SessionRead(2), SessionWrite(1), EventRead(1),
        // Tool(2), Http(1), Log(1)
        assert_eq!(plan.groups.len(), 6);

        // Verify group sizes.
        let session_read_group = plan
            .groups
            .iter()
            .find(|g| g.key == AmacGroupKey::SessionRead);
        assert!(session_read_group.is_some());
        assert_eq!(session_read_group.unwrap().len(), 2);

        let tool_group = plan.groups.iter().find(|g| g.key == AmacGroupKey::Tool);
        assert!(tool_group.is_some());
        assert_eq!(tool_group.unwrap().len(), 2);
    }

    #[test]
    fn executor_tracks_toggle_decision_counts() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 2, 16));

        // Prime with high stalls.
        for _ in 0..100 {
            executor.observe_call(500_000);
        }

        let requests: Vec<HostcallRequest> = (0..6).map(|_| http_request()).collect();
        let plan = executor.plan_batch(requests);

        let snap = executor.telemetry().snapshot();
        assert_eq!(snap.toggle_decisions, plan.groups.len() as u64);
        assert!(snap.interleave_selections > 0);
    }

    #[test]
    fn single_request_batch_always_sequential() {
        let mut executor = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 2, 16));

        // Even with high stalls.
        for _ in 0..100 {
            executor.observe_call(500_000);
        }

        let requests = vec![http_request()];
        let plan = executor.plan_batch(requests);
        assert_eq!(plan.groups.len(), 1);
        // Single item in group < min_batch_size=2 would be edge case,
        // but batch has 1 item total.
        assert!(plan.decisions.iter().all(|d| !d.is_interleave()));
    }

    // ── Clone semantics ─────────────────────────────────────────────

    #[test]
    fn executor_clone_preserves_telemetry_state() {
        let mut original = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 4, 16));
        for _ in 0..50 {
            original.observe_call(200_000);
        }
        let snap_before = original.telemetry().snapshot();
        assert_eq!(snap_before.total_calls, 50);

        let cloned = original.clone();
        let snap_cloned = cloned.telemetry().snapshot();
        assert_eq!(snap_cloned.total_calls, snap_before.total_calls);
        assert_eq!(snap_cloned.total_stalls, snap_before.total_stalls);
        assert_eq!(snap_cloned.stall_ratio, snap_before.stall_ratio);
    }

    #[test]
    fn executor_clone_is_independent() {
        let mut original = AmacBatchExecutor::new(AmacBatchExecutorConfig::new(true, 4, 16));
        for _ in 0..10 {
            original.observe_call(50_000);
        }

        let mut cloned = original.clone();
        // Mutate only the clone.
        for _ in 0..100 {
            cloned.observe_call(500_000);
        }

        // Original should be unaffected.
        assert_eq!(original.telemetry().snapshot().total_calls, 10);
        assert_eq!(cloned.telemetry().snapshot().total_calls, 110);
    }

    // ── Config from env ─────────────────────────────────────────────

    #[test]
    fn config_new_matches_parameters() {
        let config = AmacBatchExecutorConfig::new(false, 8, 32);
        assert!(!config.enabled);
        assert_eq!(config.min_batch_size, 8);
        assert_eq!(config.max_interleave_width, 32);
    }

    #[test]
    fn default_executor_is_enabled() {
        // Default from_env with no env vars set → enabled.
        let executor = AmacBatchExecutor::default();
        assert!(executor.enabled());
    }

    // ── Batch result types ──────────────────────────────────────────

    #[test]
    fn batch_telemetry_serializes() {
        let telem = AmacBatchTelemetry {
            total_requests: 10,
            groups_dispatched: 3,
            interleaved_groups: 1,
            sequential_groups: 2,
            total_elapsed_ns: 5_000_000,
        };
        let json = serde_json::to_string(&telem).expect("serialize");
        let deser: AmacBatchTelemetry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.total_requests, 10);
        assert_eq!(deser.interleaved_groups, 1);
    }
}
