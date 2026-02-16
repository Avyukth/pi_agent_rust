//! Deterministic replay trace bundle core for extension runtime forensics.
//!
//! This module provides a standalone schema + codec surface that records
//! extension runtime events in a stable order so race/tail anomalies can be
//! replayed and compared deterministically.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Canonical schema identifier for replay trace bundles.
pub const REPLAY_TRACE_SCHEMA_V1: &str = "pi.ext.replay.trace.v1";

/// Kind of extension runtime event captured for deterministic replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayEventKind {
    Scheduled,
    QueueAccepted,
    PolicyDecision,
    Cancelled,
    Retried,
    Completed,
    Failed,
}

impl ReplayEventKind {
    const fn canonical_rank(self) -> u8 {
        match self {
            Self::Scheduled => 0,
            Self::QueueAccepted => 1,
            Self::PolicyDecision => 2,
            Self::Cancelled => 3,
            Self::Retried => 4,
            Self::Completed => 5,
            Self::Failed => 6,
        }
    }
}

/// Single deterministic replay trace event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayTraceEvent {
    pub seq: u64,
    pub logical_clock: u64,
    pub extension_id: String,
    pub request_id: String,
    pub kind: ReplayEventKind,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// Builder input event before canonical ordering/sequence assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayEventDraft {
    pub logical_clock: u64,
    pub extension_id: String,
    pub request_id: String,
    pub kind: ReplayEventKind,
    pub attributes: BTreeMap<String, String>,
}

impl ReplayEventDraft {
    #[must_use]
    pub fn new(
        logical_clock: u64,
        extension_id: impl Into<String>,
        request_id: impl Into<String>,
        kind: ReplayEventKind,
    ) -> Self {
        Self {
            logical_clock,
            extension_id: extension_id.into(),
            request_id: request_id.into(),
            kind,
            attributes: BTreeMap::new(),
        }
    }
}

/// Deterministic replay trace bundle.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayTraceBundle {
    pub schema: String,
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    pub events: Vec<ReplayTraceEvent>,
}

/// First deterministic mismatch between two replay bundles.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayDivergence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub reason: ReplayDivergenceReason,
}

/// Machine-readable mismatch reason for replay comparisons.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDivergenceReason {
    SchemaMismatch {
        expected: String,
        observed: String,
    },
    TraceIdMismatch {
        expected: String,
        observed: String,
    },
    EventCountMismatch {
        expected: u64,
        observed: u64,
    },
    EventFieldMismatch {
        field: String,
        expected: String,
        observed: String,
    },
}

/// Configuration budget for deterministic replay trace capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayCaptureBudget {
    /// Global kill switch for replay capture in production.
    pub capture_enabled: bool,
    /// Maximum allowed overhead in per-mille (1/1000) units.
    pub max_overhead_per_mille: u32,
    /// Maximum allowed serialized trace bytes for a capture window.
    pub max_trace_bytes: u64,
}

/// Runtime observation used to evaluate replay capture budget gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayCaptureObservation {
    /// Baseline runtime cost without replay capture.
    pub baseline_micros: u64,
    /// Measured runtime cost with replay capture active.
    pub captured_micros: u64,
    /// Size of the collected replay trace payload in bytes.
    pub trace_bytes: u64,
}

/// Deterministic gate reason emitted by replay capture budget evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCaptureGateReason {
    Enabled,
    DisabledByConfig,
    DisabledByOverheadBudget,
    DisabledByTraceBudget,
    DisabledByInvalidBaseline,
}

/// Machine-readable report for replay capture gating decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayCaptureGateReport {
    pub capture_allowed: bool,
    pub reason: ReplayCaptureGateReason,
    pub observed_overhead_per_mille: u32,
    pub max_overhead_per_mille: u32,
    pub observed_trace_bytes: u64,
    pub max_trace_bytes: u64,
}

/// Deterministic hint categories for automated replay triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayRootCauseHint {
    TraceSchemaMismatch,
    TraceIdMismatch,
    EventCountDrift,
    EventPayloadDrift,
    LogicalClockDrift,
    PolicyGateDisabled,
    OverheadBudgetExceeded,
    TraceBudgetExceeded,
    InvalidBaselineTelemetry,
}

/// Structured replay diagnostic snapshot for log/event sinks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayDiagnosticSnapshot {
    pub trace_id: String,
    pub schema: String,
    pub event_count: u64,
    pub capture_gate: ReplayCaptureGateReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergence: Option<ReplayDivergence>,
    pub root_cause_hints: Vec<ReplayRootCauseHint>,
}

/// Evaluate replay capture against overhead and size budgets.
#[must_use]
pub fn evaluate_replay_capture_gate(
    budget: ReplayCaptureBudget,
    observation: ReplayCaptureObservation,
) -> ReplayCaptureGateReport {
    if !budget.capture_enabled {
        return ReplayCaptureGateReport {
            capture_allowed: false,
            reason: ReplayCaptureGateReason::DisabledByConfig,
            observed_overhead_per_mille: 0,
            max_overhead_per_mille: budget.max_overhead_per_mille,
            observed_trace_bytes: observation.trace_bytes,
            max_trace_bytes: budget.max_trace_bytes,
        };
    }

    let observed_overhead_per_mille =
        compute_overhead_per_mille(observation.baseline_micros, observation.captured_micros);

    if observed_overhead_per_mille == u32::MAX {
        return ReplayCaptureGateReport {
            capture_allowed: false,
            reason: ReplayCaptureGateReason::DisabledByInvalidBaseline,
            observed_overhead_per_mille,
            max_overhead_per_mille: budget.max_overhead_per_mille,
            observed_trace_bytes: observation.trace_bytes,
            max_trace_bytes: budget.max_trace_bytes,
        };
    }

    if observed_overhead_per_mille > budget.max_overhead_per_mille {
        return ReplayCaptureGateReport {
            capture_allowed: false,
            reason: ReplayCaptureGateReason::DisabledByOverheadBudget,
            observed_overhead_per_mille,
            max_overhead_per_mille: budget.max_overhead_per_mille,
            observed_trace_bytes: observation.trace_bytes,
            max_trace_bytes: budget.max_trace_bytes,
        };
    }

    if observation.trace_bytes > budget.max_trace_bytes {
        return ReplayCaptureGateReport {
            capture_allowed: false,
            reason: ReplayCaptureGateReason::DisabledByTraceBudget,
            observed_overhead_per_mille,
            max_overhead_per_mille: budget.max_overhead_per_mille,
            observed_trace_bytes: observation.trace_bytes,
            max_trace_bytes: budget.max_trace_bytes,
        };
    }

    ReplayCaptureGateReport {
        capture_allowed: true,
        reason: ReplayCaptureGateReason::Enabled,
        observed_overhead_per_mille,
        max_overhead_per_mille: budget.max_overhead_per_mille,
        observed_trace_bytes: observation.trace_bytes,
        max_trace_bytes: budget.max_trace_bytes,
    }
}

/// Build a machine-readable replay diagnostics snapshot.
///
/// # Errors
///
/// Returns an error when the replay bundle fails deterministic validation.
pub fn build_replay_diagnostic_snapshot(
    bundle: &ReplayTraceBundle,
    capture_gate: ReplayCaptureGateReport,
    divergence: Option<&ReplayDivergence>,
) -> Result<ReplayDiagnosticSnapshot, ReplayTraceValidationError> {
    bundle.validate()?;

    let event_count = u64::try_from(bundle.events.len())
        .map_err(|_| ReplayTraceValidationError::TooManyEvents)?;
    let root_cause_hints = derive_root_cause_hints(capture_gate.reason, divergence);

    Ok(ReplayDiagnosticSnapshot {
        trace_id: bundle.trace_id.clone(),
        schema: bundle.schema.clone(),
        event_count,
        capture_gate,
        divergence: divergence.cloned(),
        root_cause_hints,
    })
}

fn compute_overhead_per_mille(baseline_micros: u64, captured_micros: u64) -> u32 {
    if captured_micros <= baseline_micros {
        return 0;
    }
    if baseline_micros == 0 {
        return u32::MAX;
    }

    let overhead = u128::from(captured_micros - baseline_micros);
    let baseline = u128::from(baseline_micros);
    let scaled = overhead.saturating_mul(1_000);
    let rounded_up = scaled
        .saturating_add(baseline - 1)
        .checked_div(baseline)
        .unwrap_or(u128::MAX);
    u32::try_from(rounded_up).unwrap_or(u32::MAX)
}

fn derive_root_cause_hints(
    gate_reason: ReplayCaptureGateReason,
    divergence: Option<&ReplayDivergence>,
) -> Vec<ReplayRootCauseHint> {
    let mut hints = BTreeSet::new();

    match gate_reason {
        ReplayCaptureGateReason::Enabled => {}
        ReplayCaptureGateReason::DisabledByConfig => {
            hints.insert(ReplayRootCauseHint::PolicyGateDisabled);
        }
        ReplayCaptureGateReason::DisabledByOverheadBudget => {
            hints.insert(ReplayRootCauseHint::OverheadBudgetExceeded);
        }
        ReplayCaptureGateReason::DisabledByTraceBudget => {
            hints.insert(ReplayRootCauseHint::TraceBudgetExceeded);
        }
        ReplayCaptureGateReason::DisabledByInvalidBaseline => {
            hints.insert(ReplayRootCauseHint::InvalidBaselineTelemetry);
        }
    }

    if let Some(divergence) = divergence {
        match &divergence.reason {
            ReplayDivergenceReason::SchemaMismatch { .. } => {
                hints.insert(ReplayRootCauseHint::TraceSchemaMismatch);
            }
            ReplayDivergenceReason::TraceIdMismatch { .. } => {
                hints.insert(ReplayRootCauseHint::TraceIdMismatch);
            }
            ReplayDivergenceReason::EventCountMismatch { .. } => {
                hints.insert(ReplayRootCauseHint::EventCountDrift);
            }
            ReplayDivergenceReason::EventFieldMismatch { field, .. } => {
                if field == "logical_clock" {
                    hints.insert(ReplayRootCauseHint::LogicalClockDrift);
                } else {
                    hints.insert(ReplayRootCauseHint::EventPayloadDrift);
                }
            }
        }
    }

    hints.into_iter().collect()
}

impl ReplayTraceBundle {
    /// Encode bundle as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn encode_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Decode bundle from JSON and validate deterministic invariants.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails or bundle invariants are invalid.
    pub fn decode_json(input: &str) -> Result<Self, ReplayTraceCodecError> {
        let bundle: Self = serde_json::from_str(input)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Validate schema, sequence continuity, and cancellation/retry ordering.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle is malformed or violates replay
    /// ordering invariants.
    pub fn validate(&self) -> Result<(), ReplayTraceValidationError> {
        if self.schema != REPLAY_TRACE_SCHEMA_V1 {
            return Err(ReplayTraceValidationError::UnknownSchema(
                self.schema.clone(),
            ));
        }

        if self.trace_id.trim().is_empty() {
            return Err(ReplayTraceValidationError::EmptyTraceId);
        }

        for (idx, event) in self.events.iter().enumerate() {
            let seq_index = idx
                .checked_add(1)
                .ok_or(ReplayTraceValidationError::TooManyEvents)?;
            let expected_seq =
                u64::try_from(seq_index).map_err(|_| ReplayTraceValidationError::TooManyEvents)?;
            if event.seq != expected_seq {
                return Err(ReplayTraceValidationError::NonContiguousSequence {
                    expected: expected_seq,
                    observed: event.seq,
                });
            }

            if event.extension_id.trim().is_empty() {
                return Err(ReplayTraceValidationError::MissingExtensionId { seq: event.seq });
            }
            if event.request_id.trim().is_empty() {
                return Err(ReplayTraceValidationError::MissingRequestId { seq: event.seq });
            }
        }

        self.validate_retry_ordering()
    }

    fn validate_retry_ordering(&self) -> Result<(), ReplayTraceValidationError> {
        let mut pending_cancel: BTreeSet<(String, String)> = BTreeSet::new();
        for event in &self.events {
            let key = (event.extension_id.clone(), event.request_id.clone());
            match event.kind {
                ReplayEventKind::Cancelled => {
                    if !pending_cancel.insert(key) {
                        return Err(ReplayTraceValidationError::DuplicateCancelWithoutRetry {
                            seq: event.seq,
                            extension_id: event.extension_id.clone(),
                            request_id: event.request_id.clone(),
                        });
                    }
                }
                ReplayEventKind::Retried => {
                    if !pending_cancel.remove(&key) {
                        return Err(ReplayTraceValidationError::RetryWithoutCancel {
                            seq: event.seq,
                            extension_id: event.extension_id.clone(),
                            request_id: event.request_id.clone(),
                        });
                    }
                }
                ReplayEventKind::Completed | ReplayEventKind::Failed => {
                    pending_cancel.remove(&key);
                }
                ReplayEventKind::Scheduled
                | ReplayEventKind::QueueAccepted
                | ReplayEventKind::PolicyDecision => {}
            }
        }
        Ok(())
    }
}

/// Compare two bundles and return the first deterministic divergence.
///
/// Both bundles are validated before comparison.
///
/// # Errors
///
/// Returns an error if either bundle fails validation.
pub fn first_divergence(
    expected: &ReplayTraceBundle,
    observed: &ReplayTraceBundle,
) -> Result<Option<ReplayDivergence>, ReplayTraceValidationError> {
    expected.validate()?;
    observed.validate()?;

    if expected.schema != observed.schema {
        return Ok(Some(ReplayDivergence {
            seq: None,
            reason: ReplayDivergenceReason::SchemaMismatch {
                expected: expected.schema.clone(),
                observed: observed.schema.clone(),
            },
        }));
    }

    if expected.trace_id != observed.trace_id {
        return Ok(Some(ReplayDivergence {
            seq: None,
            reason: ReplayDivergenceReason::TraceIdMismatch {
                expected: expected.trace_id.clone(),
                observed: observed.trace_id.clone(),
            },
        }));
    }

    let max_shared = expected.events.len().min(observed.events.len());
    for idx in 0..max_shared {
        let left = &expected.events[idx];
        let right = &observed.events[idx];
        if left.logical_clock != right.logical_clock {
            return Ok(Some(field_mismatch(
                left.seq,
                "logical_clock",
                left.logical_clock.to_string(),
                right.logical_clock.to_string(),
            )));
        }
        if left.extension_id != right.extension_id {
            return Ok(Some(field_mismatch(
                left.seq,
                "extension_id",
                left.extension_id.clone(),
                right.extension_id.clone(),
            )));
        }
        if left.request_id != right.request_id {
            return Ok(Some(field_mismatch(
                left.seq,
                "request_id",
                left.request_id.clone(),
                right.request_id.clone(),
            )));
        }
        if left.kind != right.kind {
            return Ok(Some(field_mismatch(
                left.seq,
                "kind",
                format!("{:?}", left.kind),
                format!("{:?}", right.kind),
            )));
        }
        if left.attributes != right.attributes {
            return Ok(Some(field_mismatch(
                left.seq,
                "attributes",
                format!("{:?}", left.attributes),
                format!("{:?}", right.attributes),
            )));
        }
    }

    if expected.events.len() != observed.events.len() {
        let next_seq = max_shared
            .checked_add(1)
            .ok_or(ReplayTraceValidationError::TooManyEvents)?;
        let seq = u64::try_from(next_seq).map_err(|_| ReplayTraceValidationError::TooManyEvents)?;
        return Ok(Some(ReplayDivergence {
            seq: Some(seq),
            reason: ReplayDivergenceReason::EventCountMismatch {
                expected: u64::try_from(expected.events.len())
                    .map_err(|_| ReplayTraceValidationError::TooManyEvents)?,
                observed: u64::try_from(observed.events.len())
                    .map_err(|_| ReplayTraceValidationError::TooManyEvents)?,
            },
        }));
    }

    Ok(None)
}

fn field_mismatch(seq: u64, field: &str, expected: String, observed: String) -> ReplayDivergence {
    ReplayDivergence {
        seq: Some(seq),
        reason: ReplayDivergenceReason::EventFieldMismatch {
            field: field.to_string(),
            expected,
            observed,
        },
    }
}

/// Builder that canonicalizes event ordering and sequence assignment.
#[derive(Debug, Clone, Default)]
pub struct ReplayTraceBuilder {
    trace_id: String,
    metadata: BTreeMap<String, String>,
    drafts: Vec<ReplayEventDraft>,
}

impl ReplayTraceBuilder {
    #[must_use]
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            metadata: BTreeMap::new(),
            drafts: Vec::new(),
        }
    }

    pub fn insert_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    pub fn push(&mut self, draft: ReplayEventDraft) {
        self.drafts.push(draft);
    }

    /// Build a validated, deterministic trace bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if sequence assignment overflows or validation fails.
    pub fn build(self) -> Result<ReplayTraceBundle, ReplayTraceValidationError> {
        let mut indexed = self
            .drafts
            .into_iter()
            .enumerate()
            .map(|(insertion_index, draft)| IndexedDraft {
                insertion_index,
                draft,
            })
            .collect::<Vec<_>>();
        indexed.sort_by(compare_indexed_drafts);

        let events = indexed
            .into_iter()
            .enumerate()
            .map(|(idx, entry)| {
                let seq_index = idx
                    .checked_add(1)
                    .ok_or(ReplayTraceValidationError::TooManyEvents)?;
                let seq = u64::try_from(seq_index)
                    .map_err(|_| ReplayTraceValidationError::TooManyEvents)?;
                Ok(ReplayTraceEvent {
                    seq,
                    logical_clock: entry.draft.logical_clock,
                    extension_id: entry.draft.extension_id,
                    request_id: entry.draft.request_id,
                    kind: entry.draft.kind,
                    attributes: entry.draft.attributes,
                })
            })
            .collect::<Result<Vec<_>, ReplayTraceValidationError>>()?;

        let bundle = ReplayTraceBundle {
            schema: REPLAY_TRACE_SCHEMA_V1.to_string(),
            trace_id: self.trace_id,
            metadata: self.metadata,
            events,
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

#[derive(Debug, Clone)]
struct IndexedDraft {
    insertion_index: usize,
    draft: ReplayEventDraft,
}

fn compare_indexed_drafts(left: &IndexedDraft, right: &IndexedDraft) -> Ordering {
    left.draft
        .logical_clock
        .cmp(&right.draft.logical_clock)
        .then_with(|| left.draft.extension_id.cmp(&right.draft.extension_id))
        .then_with(|| left.draft.request_id.cmp(&right.draft.request_id))
        .then_with(|| {
            left.draft
                .kind
                .canonical_rank()
                .cmp(&right.draft.kind.canonical_rank())
        })
        .then_with(|| left.insertion_index.cmp(&right.insertion_index))
}

/// Validation failures for replay bundle semantics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplayTraceValidationError {
    #[error("unknown replay trace schema: {0}")]
    UnknownSchema(String),
    #[error("trace id must not be empty")]
    EmptyTraceId,
    #[error("replay bundle contains too many events to index")]
    TooManyEvents,
    #[error("non-contiguous sequence: expected {expected}, observed {observed}")]
    NonContiguousSequence { expected: u64, observed: u64 },
    #[error("event seq {seq} missing extension id")]
    MissingExtensionId { seq: u64 },
    #[error("event seq {seq} missing request id")]
    MissingRequestId { seq: u64 },
    #[error("retry without prior cancel at seq {seq} for {extension_id}/{request_id}")]
    RetryWithoutCancel {
        seq: u64,
        extension_id: String,
        request_id: String,
    },
    #[error("duplicate cancel without retry at seq {seq} for {extension_id}/{request_id}")]
    DuplicateCancelWithoutRetry {
        seq: u64,
        extension_id: String,
        request_id: String,
    },
}

/// Codec-level decode failures.
#[derive(Debug, Error)]
pub enum ReplayTraceCodecError {
    #[error("failed to parse replay trace JSON: {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("invalid replay trace bundle: {0}")]
    Validation(#[from] ReplayTraceValidationError),
}

#[cfg(test)]
mod tests {
    use super::{
        REPLAY_TRACE_SCHEMA_V1, ReplayCaptureBudget, ReplayCaptureGateReason,
        ReplayCaptureObservation, ReplayDivergenceReason, ReplayEventDraft, ReplayEventKind,
        ReplayRootCauseHint, ReplayTraceBuilder, ReplayTraceBundle, ReplayTraceCodecError,
        ReplayTraceValidationError, build_replay_diagnostic_snapshot, evaluate_replay_capture_gate,
        first_divergence,
    };
    use std::collections::BTreeMap;

    fn draft(
        logical_clock: u64,
        extension_id: &str,
        request_id: &str,
        kind: ReplayEventKind,
    ) -> ReplayEventDraft {
        ReplayEventDraft::new(
            logical_clock,
            extension_id.to_string(),
            request_id.to_string(),
            kind,
        )
    }

    const fn standard_capture_budget() -> ReplayCaptureBudget {
        ReplayCaptureBudget {
            capture_enabled: true,
            max_overhead_per_mille: 120,
            max_trace_bytes: 8_192,
        }
    }

    fn standard_bundle() -> ReplayTraceBundle {
        let mut builder = ReplayTraceBuilder::new("trace-diagnostic");
        builder.push(draft(1, "ext.a", "req-1", ReplayEventKind::Scheduled));
        builder.push(draft(2, "ext.a", "req-1", ReplayEventKind::PolicyDecision));
        builder.push(draft(3, "ext.a", "req-1", ReplayEventKind::Completed));
        builder.build().expect("bundle should build")
    }

    #[test]
    fn deterministic_build_is_order_stable_across_input_permutations() {
        let mut left = ReplayTraceBuilder::new("trace-a");
        left.push(draft(10, "ext.alpha", "req-1", ReplayEventKind::Retried));
        left.push(draft(10, "ext.alpha", "req-1", ReplayEventKind::Cancelled));
        left.push(draft(11, "ext.alpha", "req-1", ReplayEventKind::Scheduled));
        left.push(draft(11, "ext.beta", "req-2", ReplayEventKind::Scheduled));

        let mut right = ReplayTraceBuilder::new("trace-a");
        right.push(draft(11, "ext.beta", "req-2", ReplayEventKind::Scheduled));
        right.push(draft(10, "ext.alpha", "req-1", ReplayEventKind::Cancelled));
        right.push(draft(11, "ext.alpha", "req-1", ReplayEventKind::Scheduled));
        right.push(draft(10, "ext.alpha", "req-1", ReplayEventKind::Retried));

        let left_bundle = left.build().expect("left bundle should build");
        let right_bundle = right.build().expect("right bundle should build");

        assert_eq!(left_bundle, right_bundle);
        assert_eq!(left_bundle.events[0].kind, ReplayEventKind::Cancelled);
        assert_eq!(left_bundle.events[1].kind, ReplayEventKind::Retried);
    }

    #[test]
    fn json_roundtrip_preserves_replay_bundle() {
        let mut builder = ReplayTraceBuilder::new("trace-roundtrip");
        builder.insert_metadata("lane", "shadow");
        let mut event = draft(20, "ext.gamma", "req-7", ReplayEventKind::PolicyDecision);
        event
            .attributes
            .insert("decision".to_string(), "fast_lane".to_string());
        builder.push(draft(19, "ext.gamma", "req-7", ReplayEventKind::Scheduled));
        builder.push(event);
        builder.push(draft(21, "ext.gamma", "req-7", ReplayEventKind::Completed));

        let bundle = builder.build().expect("bundle should build");
        let encoded = bundle.encode_json().expect("bundle should encode");
        let decoded = ReplayTraceBundle::decode_json(&encoded).expect("bundle should decode");
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn decode_rejects_retry_without_prior_cancel() {
        let bundle = ReplayTraceBundle {
            schema: REPLAY_TRACE_SCHEMA_V1.to_string(),
            trace_id: "trace-invalid".to_string(),
            metadata: BTreeMap::new(),
            events: vec![super::ReplayTraceEvent {
                seq: 1,
                logical_clock: 1,
                extension_id: "ext.a".to_string(),
                request_id: "req".to_string(),
                kind: ReplayEventKind::Retried,
                attributes: BTreeMap::new(),
            }],
        };
        let encoded = bundle
            .encode_json()
            .expect("invalid bundle should serialize");

        let error = ReplayTraceBundle::decode_json(&encoded).expect_err("retry without cancel");
        match error {
            ReplayTraceCodecError::Validation(ReplayTraceValidationError::RetryWithoutCancel {
                ..
            }) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_non_contiguous_sequence() {
        let bundle = ReplayTraceBundle {
            schema: REPLAY_TRACE_SCHEMA_V1.to_string(),
            trace_id: "trace-seq".to_string(),
            metadata: BTreeMap::new(),
            events: vec![
                super::ReplayTraceEvent {
                    seq: 1,
                    logical_clock: 1,
                    extension_id: "ext.a".to_string(),
                    request_id: "req-1".to_string(),
                    kind: ReplayEventKind::Scheduled,
                    attributes: BTreeMap::new(),
                },
                super::ReplayTraceEvent {
                    seq: 3,
                    logical_clock: 2,
                    extension_id: "ext.a".to_string(),
                    request_id: "req-1".to_string(),
                    kind: ReplayEventKind::Completed,
                    attributes: BTreeMap::new(),
                },
            ],
        };
        let encoded = bundle
            .encode_json()
            .expect("invalid bundle should serialize");

        let error = ReplayTraceBundle::decode_json(&encoded).expect_err("non-contiguous seq");
        match error {
            ReplayTraceCodecError::Validation(
                ReplayTraceValidationError::NonContiguousSequence { expected, observed },
            ) => {
                assert_eq!(expected, 2);
                assert_eq!(observed, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn divergence_reports_kind_mismatch_with_seq() {
        let mut expected_builder = ReplayTraceBuilder::new("trace-divergence");
        expected_builder.push(draft(1, "ext.a", "req-1", ReplayEventKind::Scheduled));
        expected_builder.push(draft(2, "ext.a", "req-1", ReplayEventKind::Completed));
        let expected = expected_builder.build().expect("expected bundle");

        let mut observed_builder = ReplayTraceBuilder::new("trace-divergence");
        observed_builder.push(draft(1, "ext.a", "req-1", ReplayEventKind::Scheduled));
        observed_builder.push(draft(2, "ext.a", "req-1", ReplayEventKind::Failed));
        let observed = observed_builder.build().expect("observed bundle");

        let divergence = first_divergence(&expected, &observed)
            .expect("comparison should succeed")
            .expect("divergence expected");
        assert_eq!(divergence.seq, Some(2));
        match divergence.reason {
            ReplayDivergenceReason::EventFieldMismatch { field, .. } => {
                assert_eq!(field, "kind");
            }
            other => panic!("unexpected divergence reason: {other:?}"),
        }
    }

    #[test]
    fn divergence_reports_event_count_mismatch() {
        let mut expected_builder = ReplayTraceBuilder::new("trace-length");
        expected_builder.push(draft(1, "ext.a", "req-1", ReplayEventKind::Scheduled));
        expected_builder.push(draft(2, "ext.a", "req-1", ReplayEventKind::Completed));
        let expected = expected_builder.build().expect("expected bundle");

        let mut observed_builder = ReplayTraceBuilder::new("trace-length");
        observed_builder.push(draft(1, "ext.a", "req-1", ReplayEventKind::Scheduled));
        let observed = observed_builder.build().expect("observed bundle");

        let divergence = first_divergence(&expected, &observed)
            .expect("comparison should succeed")
            .expect("divergence expected");
        assert_eq!(divergence.seq, Some(2));
        match divergence.reason {
            ReplayDivergenceReason::EventCountMismatch { expected, observed } => {
                assert_eq!(expected, 2);
                assert_eq!(observed, 1);
            }
            other => panic!("unexpected divergence reason: {other:?}"),
        }
    }

    #[test]
    fn divergence_returns_none_for_identical_bundles() {
        let mut builder = ReplayTraceBuilder::new("trace-identical");
        builder.push(draft(1, "ext.a", "req-1", ReplayEventKind::Scheduled));
        builder.push(draft(2, "ext.a", "req-1", ReplayEventKind::Completed));
        let bundle = builder.build().expect("bundle");

        let divergence =
            first_divergence(&bundle, &bundle).expect("comparison should validate identical");
        assert!(divergence.is_none());
    }

    #[test]
    fn capture_gate_disables_when_config_switch_is_off() {
        let mut budget = standard_capture_budget();
        budget.capture_enabled = false;
        let observation = ReplayCaptureObservation {
            baseline_micros: 1_000,
            captured_micros: 1_010,
            trace_bytes: 128,
        };

        let report = evaluate_replay_capture_gate(budget, observation);
        assert!(!report.capture_allowed);
        assert_eq!(report.reason, ReplayCaptureGateReason::DisabledByConfig);
    }

    #[test]
    fn capture_gate_disables_when_overhead_exceeds_budget() {
        let budget = standard_capture_budget();
        let observation = ReplayCaptureObservation {
            baseline_micros: 1_000,
            captured_micros: 1_140,
            trace_bytes: 512,
        };

        let report = evaluate_replay_capture_gate(budget, observation);
        assert!(!report.capture_allowed);
        assert_eq!(
            report.reason,
            ReplayCaptureGateReason::DisabledByOverheadBudget
        );
        assert_eq!(report.observed_overhead_per_mille, 140);
    }

    #[test]
    fn capture_gate_disables_when_trace_budget_exceeded() {
        let budget = standard_capture_budget();
        let observation = ReplayCaptureObservation {
            baseline_micros: 1_000,
            captured_micros: 1_050,
            trace_bytes: 9_000,
        };

        let report = evaluate_replay_capture_gate(budget, observation);
        assert!(!report.capture_allowed);
        assert_eq!(
            report.reason,
            ReplayCaptureGateReason::DisabledByTraceBudget
        );
        assert_eq!(report.observed_overhead_per_mille, 50);
    }

    #[test]
    fn capture_gate_fails_closed_on_invalid_baseline() {
        let budget = standard_capture_budget();
        let observation = ReplayCaptureObservation {
            baseline_micros: 0,
            captured_micros: 1,
            trace_bytes: 64,
        };

        let report = evaluate_replay_capture_gate(budget, observation);
        assert!(!report.capture_allowed);
        assert_eq!(
            report.reason,
            ReplayCaptureGateReason::DisabledByInvalidBaseline
        );
        assert_eq!(report.observed_overhead_per_mille, u32::MAX);
    }

    #[test]
    fn capture_gate_reports_deterministic_within_budget_enablement() {
        let budget = standard_capture_budget();
        let observation = ReplayCaptureObservation {
            baseline_micros: 1_000,
            captured_micros: 1_080,
            trace_bytes: 4_096,
        };

        let first = evaluate_replay_capture_gate(budget, observation);
        let second = evaluate_replay_capture_gate(budget, observation);

        assert_eq!(first, second);
        assert!(first.capture_allowed);
        assert_eq!(first.reason, ReplayCaptureGateReason::Enabled);
        assert_eq!(first.observed_overhead_per_mille, 80);
    }

    #[test]
    fn diagnostic_snapshot_emits_hint_codes_for_gate_and_payload_drift() {
        let expected = standard_bundle();

        let mut observed_builder = ReplayTraceBuilder::new("trace-diagnostic");
        observed_builder.push(draft(1, "ext.a", "req-1", ReplayEventKind::Scheduled));
        observed_builder.push(draft(2, "ext.a", "req-1", ReplayEventKind::PolicyDecision));
        observed_builder.push(draft(3, "ext.a", "req-1", ReplayEventKind::Failed));
        let observed = observed_builder.build().expect("observed bundle");

        let divergence = first_divergence(&expected, &observed)
            .expect("comparison should succeed")
            .expect("divergence expected");
        let capture_gate = evaluate_replay_capture_gate(
            standard_capture_budget(),
            ReplayCaptureObservation {
                baseline_micros: 1_000,
                captured_micros: 1_150,
                trace_bytes: 64,
            },
        );

        let snapshot = build_replay_diagnostic_snapshot(&expected, capture_gate, Some(&divergence))
            .expect("snapshot should build");
        assert_eq!(snapshot.event_count, 3);
        assert_eq!(
            snapshot.root_cause_hints,
            vec![
                ReplayRootCauseHint::EventPayloadDrift,
                ReplayRootCauseHint::OverheadBudgetExceeded,
            ]
        );
    }

    #[test]
    fn diagnostic_snapshot_maps_logical_clock_drift_hint() {
        let expected = standard_bundle();
        let mut observed = expected.clone();
        observed.events[1].logical_clock = 77;

        let divergence = first_divergence(&expected, &observed)
            .expect("comparison should succeed")
            .expect("divergence expected");
        let capture_gate = evaluate_replay_capture_gate(
            standard_capture_budget(),
            ReplayCaptureObservation {
                baseline_micros: 1_000,
                captured_micros: 1_010,
                trace_bytes: 64,
            },
        );

        let snapshot = build_replay_diagnostic_snapshot(&expected, capture_gate, Some(&divergence))
            .expect("snapshot should build");
        assert_eq!(
            snapshot.root_cause_hints,
            vec![ReplayRootCauseHint::LogicalClockDrift]
        );
    }

    #[test]
    fn diagnostic_snapshot_is_deterministic_for_same_inputs() {
        let bundle = standard_bundle();
        let capture_gate = evaluate_replay_capture_gate(
            standard_capture_budget(),
            ReplayCaptureObservation {
                baseline_micros: 1_000,
                captured_micros: 1_020,
                trace_bytes: 256,
            },
        );

        let first =
            build_replay_diagnostic_snapshot(&bundle, capture_gate, None).expect("first snapshot");
        let second =
            build_replay_diagnostic_snapshot(&bundle, capture_gate, None).expect("second snapshot");
        assert_eq!(first, second);
    }

    #[test]
    fn diagnostic_snapshot_rejects_invalid_bundle() {
        let invalid = ReplayTraceBundle {
            schema: "invalid.schema".to_string(),
            trace_id: "trace-bad".to_string(),
            metadata: BTreeMap::new(),
            events: Vec::new(),
        };
        let capture_gate = evaluate_replay_capture_gate(
            standard_capture_budget(),
            ReplayCaptureObservation {
                baseline_micros: 1_000,
                captured_micros: 1_000,
                trace_bytes: 0,
            },
        );

        let error = build_replay_diagnostic_snapshot(&invalid, capture_gate, None)
            .expect_err("invalid schema should fail");
        assert!(matches!(
            error,
            ReplayTraceValidationError::UnknownSchema(_)
        ));
    }
}
