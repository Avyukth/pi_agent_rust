//! Exactly-once Semantic Layer (ESL) journal for request deduplication.
//!
//! The journal tracks in-flight and completed requests so that duplicate
//! request IDs can be detected and replayed without re-execution.

use std::collections::HashMap;

use super::native_host::NativeHostError;
use super::protocol;

// ── Constants ──────────────────────────────────────────────────────────

pub(crate) const DEFAULT_REQUEST_JOURNAL_TTL_MS: i64 = 60_000;
pub(crate) const MAX_JOURNAL_ENTRIES: usize = 256;
pub(crate) const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_AGENT_MAX_RECONNECT_ATTEMPTS: i64 = 3;
const DEFAULT_AGENT_SOCKET_TIMEOUT_MS: i64 = 5_000;
const JOURNAL_TTL_COUPLING_SAFETY_MARGIN_MS: i64 = 10_000;

// ── Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EslJournalKey {
    pub(super) pi_session_id: String,
    pub(super) request_id: String,
    pub(super) host_epoch: String,
}

#[derive(Debug, Clone)]
pub(super) struct EslJournalEntry {
    pub(super) fingerprint: protocol::RequestFingerprint,
    pub(super) state: EslJournalState,
    pub(super) created_at_ms: i64,
    pub(super) last_access_ms: i64,
    pub(super) approx_bytes: usize,
}

#[derive(Debug, Clone)]
pub(super) enum EslJournalState {
    InProgress,
    Terminal(protocol::ResponseEnvelope),
}

#[derive(Debug, Clone)]
pub(super) struct EslJournal {
    pub(super) ttl_ms: i64,
    pub(super) max_entries: usize,
    pub(super) max_bytes: usize,
    pub(super) current_bytes: usize,
    pub(super) entries: HashMap<EslJournalKey, EslJournalEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EslBeginOutcome {
    Dispatch,
    Replay(protocol::ResponseEnvelope),
    Reject(protocol::ResponseEnvelope),
}

// ── Implementation ─────────────────────────────────────────────────────

impl EslJournal {
    pub(super) fn new(lease_ttl_ms: u64) -> Result<Self, NativeHostError> {
        let min_ttl_ms = i64::try_from(lease_ttl_ms)
            .unwrap_or(i64::MAX)
            .saturating_add(
                (DEFAULT_AGENT_MAX_RECONNECT_ATTEMPTS + 1)
                    .saturating_mul(DEFAULT_AGENT_SOCKET_TIMEOUT_MS)
                    .saturating_add(JOURNAL_TTL_COUPLING_SAFETY_MARGIN_MS),
            );
        if DEFAULT_REQUEST_JOURNAL_TTL_MS < min_ttl_ms {
            return Err(NativeHostError::EslInvariant(format!(
                "request journal ttl {DEFAULT_REQUEST_JOURNAL_TTL_MS}ms violates coupling invariant (min {min_ttl_ms}ms)"
            )));
        }
        Ok(Self {
            ttl_ms: DEFAULT_REQUEST_JOURNAL_TTL_MS,
            max_entries: MAX_JOURNAL_ENTRIES,
            max_bytes: MAX_JOURNAL_BYTES,
            current_bytes: 0,
            entries: HashMap::new(),
        })
    }

    #[cfg(test)]
    pub(super) fn with_limits_for_test(ttl_ms: i64, max_entries: usize, max_bytes: usize) -> Self {
        Self {
            ttl_ms,
            max_entries,
            max_bytes,
            current_bytes: 0,
            entries: HashMap::new(),
        }
    }

    pub(super) fn begin_request(
        &mut self,
        pi_session_id: &str,
        host_epoch: &str,
        request: &protocol::Request,
        now_ms: i64,
    ) -> Result<EslBeginOutcome, NativeHostError> {
        self.prune_expired_terminal_entries(now_ms);

        let key = EslJournalKey {
            pi_session_id: pi_session_id.to_string(),
            request_id: request.id.clone(),
            host_epoch: host_epoch.to_string(),
        };
        let fingerprint = protocol::RequestFingerprint::new(&request.op, &request.payload)
            .map_err(NativeHostError::Fingerprint)?;

        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_access_ms = now_ms;
            if entry.fingerprint != fingerprint {
                return Ok(EslBeginOutcome::Reject(invalid_request_envelope(
                    &request.id,
                    "request_id reused with different op/payload",
                )));
            }
            return Ok(match &entry.state {
                EslJournalState::InProgress => EslBeginOutcome::Reject(in_progress_envelope(
                    &request.id,
                    "in_progress: request still executing",
                )),
                EslJournalState::Terminal(envelope) => EslBeginOutcome::Replay(envelope.clone()),
            });
        }

        let new_entry_bytes = approx_in_progress_entry_bytes(&key, &fingerprint);
        if !self.ensure_capacity_for_new_entry(new_entry_bytes, now_ms) {
            tracing::warn!(
                event = "pi.chrome.esl.reject_indeterminate_capacity",
                pi_session_id,
                request_id = %request.id,
                host_epoch,
                max_entries = self.max_entries,
                max_bytes = self.max_bytes,
                current_entries = self.entries.len(),
                current_bytes = self.current_bytes,
                "Rejecting request because ESL caps can only be satisfied by evicting in_progress entries"
            );
            return Ok(EslBeginOutcome::Reject(execution_indeterminate_envelope(
                &request.id,
                "esl journal capacity reached with only in_progress entries",
            )));
        }

        let entry = EslJournalEntry {
            fingerprint,
            state: EslJournalState::InProgress,
            created_at_ms: now_ms,
            last_access_ms: now_ms,
            approx_bytes: new_entry_bytes,
        };
        self.current_bytes = self.current_bytes.saturating_add(new_entry_bytes);
        self.entries.insert(key, entry);
        Ok(EslBeginOutcome::Dispatch)
    }

    pub(super) fn record_terminal_response(
        &mut self,
        pi_session_id: &str,
        host_epoch: &str,
        request: &protocol::Request,
        response: &protocol::ResponseEnvelope,
        now_ms: i64,
    ) -> Result<(), NativeHostError> {
        let key = EslJournalKey {
            pi_session_id: pi_session_id.to_string(),
            request_id: request.id.clone(),
            host_epoch: host_epoch.to_string(),
        };
        let Some(entry) = self.entries.get_mut(&key) else {
            return Ok(());
        };

        let fingerprint = protocol::RequestFingerprint::new(&request.op, &request.payload)
            .map_err(NativeHostError::Fingerprint)?;
        if entry.fingerprint != fingerprint {
            tracing::warn!(
                event = "pi.chrome.esl.record_terminal_fingerprint_mismatch",
                pi_session_id,
                request_id = %request.id,
                host_epoch,
                "Skipping terminal ESL update because request fingerprint mismatched existing entry"
            );
            return Ok(());
        }

        self.current_bytes = self.current_bytes.saturating_sub(entry.approx_bytes);
        entry.state = EslJournalState::Terminal(response.clone());
        entry.last_access_ms = now_ms;
        entry.approx_bytes = approx_terminal_entry_bytes(&key, &entry.fingerprint, response);
        self.current_bytes = self.current_bytes.saturating_add(entry.approx_bytes);

        let _ = self.ensure_capacity_for_new_entry(0, now_ms);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn contains_key(
        &self,
        pi_session_id: &str,
        request_id: &str,
        host_epoch: &str,
    ) -> bool {
        self.entries.contains_key(&EslJournalKey {
            pi_session_id: pi_session_id.to_string(),
            request_id: request_id.to_string(),
            host_epoch: host_epoch.to_string(),
        })
    }

    #[cfg(test)]
    pub(super) fn terminal_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| matches!(entry.state, EslJournalState::Terminal(_)))
            .count()
    }

    pub(super) fn prune_expired_terminal_entries(&mut self, now_ms: i64) {
        if self.ttl_ms <= 0 {
            return;
        }
        let mut expired = Vec::new();
        for (key, entry) in &self.entries {
            let is_terminal = matches!(entry.state, EslJournalState::Terminal(_));
            if is_terminal && now_ms.saturating_sub(entry.last_access_ms) >= self.ttl_ms {
                expired.push(key.clone());
            }
        }
        for key in expired {
            self.remove_entry(&key);
        }
    }

    pub(super) fn ensure_capacity_for_new_entry(
        &mut self,
        additional_bytes: usize,
        now_ms: i64,
    ) -> bool {
        self.prune_expired_terminal_entries(now_ms);
        while self
            .entries
            .len()
            .saturating_add(usize::from(additional_bytes > 0))
            > self.max_entries
            || self.current_bytes.saturating_add(additional_bytes) > self.max_bytes
        {
            let Some(evict_key) = self.oldest_terminal_key() else {
                return false;
            };
            tracing::debug!(
                event = "pi.chrome.esl.evict_terminal",
                request_id = %evict_key.request_id,
                host_epoch = %evict_key.host_epoch,
                "Evicting terminal ESL entry to satisfy caps"
            );
            self.remove_entry(&evict_key);
        }
        true
    }

    fn oldest_terminal_key(&self) -> Option<EslJournalKey> {
        self.entries
            .iter()
            .filter_map(|(key, entry)| {
                if matches!(entry.state, EslJournalState::Terminal(_)) {
                    Some((key, entry.last_access_ms))
                } else {
                    None
                }
            })
            .min_by(|(a_key, a_ts), (b_key, b_ts)| {
                a_ts.cmp(b_ts)
                    .then_with(|| a_key.request_id.cmp(&b_key.request_id))
            })
            .map(|(key, _)| key.clone())
    }

    fn remove_entry(&mut self, key: &EslJournalKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.current_bytes = self.current_bytes.saturating_sub(entry.approx_bytes);
        }
    }
}

// ── Helper functions ───────────────────────────────────────────────────

fn invalid_request_envelope(
    request_id: &str,
    message: impl Into<String>,
) -> protocol::ResponseEnvelope {
    protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: request_id.to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code: protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
            message: format!("invalid_request: {}", message.into()),
            retryable: false,
        },
    })
}

fn in_progress_envelope(
    request_id: &str,
    message: impl Into<String>,
) -> protocol::ResponseEnvelope {
    protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: request_id.to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code: protocol::ProtocolErrorCode::ChromeBridgeBusy,
            message: message.into(),
            retryable: true,
        },
    })
}

fn execution_indeterminate_envelope(
    request_id: &str,
    message: impl Into<String>,
) -> protocol::ResponseEnvelope {
    protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: request_id.to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code: protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
            message: message.into(),
            retryable: false,
        },
    })
}

fn approx_in_progress_entry_bytes(
    key: &EslJournalKey,
    fingerprint: &protocol::RequestFingerprint,
) -> usize {
    key.pi_session_id
        .len()
        .saturating_add(key.request_id.len())
        .saturating_add(key.host_epoch.len())
        .saturating_add(fingerprint.as_str().len())
        .saturating_add(128)
}

fn approx_terminal_entry_bytes(
    key: &EslJournalKey,
    fingerprint: &protocol::RequestFingerprint,
    response: &protocol::ResponseEnvelope,
) -> usize {
    let response_bytes = serde_json::to_vec(response).map_or(0, |bytes| bytes.len());
    key.pi_session_id
        .len()
        .saturating_add(key.request_id.len())
        .saturating_add(key.host_epoch.len())
        .saturating_add(fingerprint.as_str().len())
        .saturating_add(response_bytes)
        .saturating_add(160)
}
