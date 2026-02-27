//! Background compaction worker with basic quota controls.
//!
//! This keeps LLM compaction off the foreground turn path by running compaction
//! on a dedicated thread and applying results on subsequent turns.

use crate::compaction::{self, CompactionPreparation, CompactionResult};
use crate::error::{Error, Result};
use crate::provider::Provider;
use std::sync::{Arc, Mutex as StdMutex, mpsc};
use std::time::{Duration, Instant};

/// Quota controls that bound background compaction resource usage.
#[derive(Debug, Clone)]
pub struct CompactionQuota {
    /// Minimum elapsed time between compaction starts.
    pub cooldown: Duration,
    /// Maximum wall-clock time to wait for a background compaction result.
    pub timeout: Duration,
    /// Maximum compaction attempts allowed in a single session.
    pub max_attempts_per_session: u32,
}

impl Default for CompactionQuota {
    fn default() -> Self {
        Self {
            cooldown: Duration::from_secs(60),
            timeout: Duration::from_secs(120),
            max_attempts_per_session: 100,
        }
    }
}

type CompactionOutcome = Result<CompactionResult>;

struct PendingCompaction {
    rx: StdMutex<mpsc::Receiver<CompactionOutcome>>,
    started_at: Instant,
}

/// Per-session background compaction state.
pub(crate) struct CompactionWorkerState {
    pending: Option<PendingCompaction>,
    last_start: Option<Instant>,
    attempt_count: u32,
    quota: CompactionQuota,
}

impl CompactionWorkerState {
    pub const fn new(quota: CompactionQuota) -> Self {
        Self {
            pending: None,
            last_start: None,
            attempt_count: 0,
            quota,
        }
    }

    /// Whether a new background compaction is allowed to start now.
    pub fn can_start(&self) -> bool {
        if self.pending.is_some() {
            return false;
        }
        if self.attempt_count >= self.quota.max_attempts_per_session {
            return false;
        }
        if let Some(last) = self.last_start {
            if last.elapsed() < self.quota.cooldown {
                return false;
            }
        }
        true
    }

    /// Non-blocking check for a completed compaction result.
    pub fn try_recv(&mut self) -> Option<CompactionOutcome> {
        // Check timeout first (read-only borrow, then drop before mutation).
        let timed_out = self
            .pending
            .as_ref()
            .is_some_and(|p| p.started_at.elapsed() > self.quota.timeout);

        if timed_out {
            self.pending = None;
            return Some(Err(Error::session(
                "Background compaction timed out".to_string(),
            )));
        }

        // Try to receive — take() moves ownership so no outstanding borrow.
        let pending = self.pending.take()?;
        let recv_result = match pending.rx.lock() {
            Ok(rx) => rx.try_recv(),
            Err(_) => {
                return Some(Err(Error::session(
                    "Background compaction receiver mutex poisoned".to_string(),
                )));
            }
        };

        match recv_result {
            Ok(outcome) => Some(outcome),
            Err(mpsc::TryRecvError::Empty) => {
                // Not done yet — put it back.
                self.pending = Some(pending);
                None
            }
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(Error::session(
                "Background compaction worker disconnected".to_string(),
            ))),
        }
    }

    /// Spawn a background compaction in a dedicated thread.
    pub fn start(
        &mut self,
        preparation: CompactionPreparation,
        provider: Arc<dyn Provider>,
        api_key: String,
        custom_instructions: Option<String>,
    ) {
        debug_assert!(
            self.can_start(),
            "start() called while can_start() is false"
        );

        let (tx, rx) = mpsc::channel();
        let now = Instant::now();

        std::thread::Builder::new()
            .name("pi-compaction-bg".to_string())
            .spawn(move || {
                run_compaction_thread(preparation, provider, api_key, custom_instructions, tx);
            })
            .expect("spawn background compaction thread");

        self.pending = Some(PendingCompaction {
            rx: StdMutex::new(rx),
            started_at: now,
        });
        self.last_start = Some(now);
        self.attempt_count = self.attempt_count.saturating_add(1);
    }
}

#[allow(clippy::needless_pass_by_value)]
fn run_compaction_thread(
    preparation: CompactionPreparation,
    provider: Arc<dyn Provider>,
    api_key: String,
    custom_instructions: Option<String>,
    tx: mpsc::Sender<CompactionOutcome>,
) {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime for background compaction");

    let result = runtime.block_on(async {
        compaction::compact(
            preparation,
            provider,
            &api_key,
            custom_instructions.as_deref(),
        )
        .await
    });

    let _ = tx.send(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_worker(quota: CompactionQuota) -> CompactionWorkerState {
        CompactionWorkerState::new(quota)
    }

    fn default_worker() -> CompactionWorkerState {
        make_worker(CompactionQuota::default())
    }

    fn inject_pending(worker: &mut CompactionWorkerState, rx: mpsc::Receiver<CompactionOutcome>) {
        worker.pending = Some(PendingCompaction {
            rx: StdMutex::new(rx),
            started_at: Instant::now(),
        });
        worker.last_start = Some(Instant::now());
        worker.attempt_count += 1;
    }

    #[test]
    fn fresh_worker_can_start() {
        let w = default_worker();
        assert!(w.can_start());
    }

    #[test]
    fn cannot_start_while_pending() {
        let mut w = default_worker();
        let (_tx, rx) = mpsc::channel();
        inject_pending(&mut w, rx);
        assert!(!w.can_start());
    }

    #[test]
    fn cannot_start_during_cooldown() {
        let mut w = make_worker(CompactionQuota {
            cooldown: Duration::from_secs(3600),
            ..CompactionQuota::default()
        });
        w.last_start = Some(Instant::now());
        w.attempt_count = 1;
        assert!(!w.can_start());
    }

    #[test]
    fn can_start_after_cooldown() {
        let mut w = make_worker(CompactionQuota {
            cooldown: Duration::from_millis(0),
            ..CompactionQuota::default()
        });
        w.last_start = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        );
        w.attempt_count = 1;
        assert!(w.can_start());
    }

    #[test]
    fn max_attempts_blocks_start() {
        let mut w = make_worker(CompactionQuota {
            max_attempts_per_session: 2,
            cooldown: Duration::from_millis(0),
            ..CompactionQuota::default()
        });
        w.attempt_count = 2;
        assert!(!w.can_start());
    }

    #[test]
    fn try_recv_none_when_no_pending() {
        let mut w = default_worker();
        assert!(w.try_recv().is_none());
    }

    #[test]
    fn try_recv_none_when_not_ready() {
        let mut w = default_worker();
        let (_tx, rx) = mpsc::channel::<CompactionOutcome>();
        inject_pending(&mut w, rx);
        // Nothing sent yet.
        assert!(w.try_recv().is_none());
        // Pending should still be there.
        assert!(w.pending.is_some());
    }

    #[test]
    fn try_recv_returns_disconnected_when_sender_dropped() {
        let mut w = default_worker();
        let (tx, rx) = mpsc::channel::<CompactionOutcome>();
        inject_pending(&mut w, rx);
        drop(tx);
        let outcome = w.try_recv().expect("should return disconnected error");
        assert!(outcome.is_err());
        assert!(w.pending.is_none());
    }

    #[test]
    fn try_recv_timeout() {
        let mut w = make_worker(CompactionQuota {
            timeout: Duration::from_millis(0),
            ..CompactionQuota::default()
        });
        let (_tx, rx) = mpsc::channel::<CompactionOutcome>();
        w.pending = Some(PendingCompaction {
            rx: StdMutex::new(rx),
            started_at: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        });
        let outcome = w.try_recv().expect("should return timeout error");
        assert!(outcome.is_err());
        let err_msg = outcome.unwrap_err().to_string();
        assert!(err_msg.contains("timed out"), "got: {err_msg}");
    }

    #[test]
    fn try_recv_success() {
        let mut w = default_worker();
        let (tx, rx) = mpsc::channel::<CompactionOutcome>();
        inject_pending(&mut w, rx);

        // Simulate a successful compaction result.
        let result = CompactionResult {
            summary: "test summary".to_string(),
            first_kept_entry_id: "entry-1".to_string(),
            tokens_before: 1000,
            details: compaction::CompactionDetails {
                read_files: vec![],
                modified_files: vec![],
            },
        };
        tx.send(Ok(result)).unwrap();

        let outcome = w.try_recv().expect("should have result");
        let result = outcome.expect("should be Ok");
        assert_eq!(result.summary, "test summary");
        assert!(w.pending.is_none());
    }
}
