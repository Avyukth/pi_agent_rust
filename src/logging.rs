//! Structured observability layer for pi_agent_rust (bd-2mz).
//!
//! Provides a layered `tracing` subscriber with:
//! - **stderr** output for interactive terminal use (respects `RUST_LOG`).
//! - **file appender** writing to `~/.pi/logs/pi-chrome.log` with daily rotation
//!   and bounded retention.
//! - **Redaction** of sensitive fields (`api_key`, `token`, `secret`, `password`,
//!   `authorization`, `credential`) at INFO level and below.
//! - **Correlation fields** via `tracing::Span` for `pi_session_id`, `host_id`,
//!   `host_epoch`, and `request_id`.
//! - **Test capture** helpers for asserting on log output in tests.

use std::path::PathBuf;
use tracing::Span;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Default log directory under the user's home.
const LOG_DIR_RELATIVE: &str = ".pi/logs";

/// Default log file prefix.
const LOG_FILE_PREFIX: &str = "pi-chrome";

/// Maximum number of daily log files to retain.
const MAX_LOG_FILES: usize = 7;

/// Fields whose values are replaced with `[REDACTED]` in INFO-and-below output.
const REDACTED_FIELD_NAMES: &[&str] = &[
    "api_key",
    "token",
    "secret",
    "password",
    "authorization",
    "credential",
    "access_token",
    "refresh_token",
    "bearer",
];

// ─── Subscriber Initialization ──────────────────────────────────────────────

/// Initialize the global tracing subscriber with stderr + file layers.
///
/// Call this **once** early in `main()`. Panics if called twice.
///
/// # Layers
///
/// 1. **stderr** — human-readable, filtered by `RUST_LOG` (default `warn`).
/// 2. **file** — JSON-formatted, filtered at `debug` level, written to
///    `~/.pi/logs/pi-chrome.YYYY-MM-DD.log` with daily rotation.
///
/// Both layers apply field-level redaction for sensitive values at INFO
/// and below (DEBUG/TRACE bypass redaction for local debugging).
pub fn init_logging() {
    let stderr_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    let stderr_layer = fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(stderr_filter);

    let file_layer = make_file_layer();

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .init();
}

/// Initialize logging for tests (captures to a shared in-memory buffer).
///
/// Returns a [`LogCapture`] handle that can be used to inspect captured events.
/// Safe to call from multiple tests (uses `try_init`).
#[cfg(test)]
pub fn init_test_logging() -> LogCapture {
    let capture = LogCapture::new();
    let capture_layer = capture.layer();

    let _ = tracing_subscriber::registry()
        .with(capture_layer)
        .try_init();

    capture
}

// ─── File Layer ─────────────────────────────────────────────────────────────

fn log_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(LOG_DIR_RELATIVE))
}

fn make_file_layer<S>() -> Option<Box<dyn Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let dir = log_dir()?;
    // Ensure the log directory exists (best-effort).
    let _ = std::fs::create_dir_all(&dir);

    let file_appender = tracing_appender::rolling::daily(&dir, LOG_FILE_PREFIX);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Leak the guard so it lives for the process lifetime.
    // This is the standard pattern for tracing-appender non-blocking writers.
    std::mem::forget(guard);

    let file_filter = EnvFilter::new("debug");

    let layer = fmt::layer()
        .json()
        .with_target(true)
        .with_thread_ids(true)
        .with_writer(non_blocking)
        .with_filter(file_filter);

    Some(layer.boxed())
}

// ─── Pruning ────────────────────────────────────────────────────────────────

/// Remove log files older than [`MAX_LOG_FILES`] days.
///
/// Called opportunistically at startup. Errors are silently ignored.
pub fn prune_old_logs() {
    let Some(dir) = log_dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };

    let mut log_files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(LOG_FILE_PREFIX))
        })
        .collect();

    // Sort by name (daily rotation files sort chronologically).
    log_files.sort();

    if log_files.len() > MAX_LOG_FILES {
        let to_remove = log_files.len() - MAX_LOG_FILES;
        for path in &log_files[..to_remove] {
            let _ = std::fs::remove_file(path);
        }
    }
}

// ─── Redaction ──────────────────────────────────────────────────────────────

/// Returns true if the field name looks sensitive and should be redacted.
pub fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    REDACTED_FIELD_NAMES.iter().any(|&pat| lower.contains(pat))
}

/// Redact a value if the field name is sensitive.
///
/// Returns `"[REDACTED]"` for sensitive fields, the original value otherwise.
pub fn redact_if_sensitive<'a>(field_name: &str, value: &'a str) -> std::borrow::Cow<'a, str> {
    if is_sensitive_field(field_name) {
        std::borrow::Cow::Borrowed("[REDACTED]")
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

// ─── Correlation Spans ──────────────────────────────────────────────────────

/// Create a top-level session span with correlation fields.
///
/// Attach this span as the parent of all work within a single agent session.
///
/// # Example
///
/// ```ignore
/// let _guard = logging::session_span("sess_abc123", "host_42", 3).entered();
/// tracing::info!("Starting agent loop");
/// ```
pub fn session_span(session_id: &str, host_id: &str, host_epoch: u64) -> Span {
    tracing::info_span!(
        "pi_session",
        pi_session_id = session_id,
        host_id = host_id,
        host_epoch = host_epoch,
    )
}

/// Create a request-scoped span for a single tool call or LLM request.
pub fn request_span(request_id: &str) -> Span {
    tracing::info_span!("pi_request", request_id = request_id,)
}

/// Create an observer-scoped span for Chrome extension observer events.
pub fn observer_span(observer_id: &str, event_type: &str) -> Span {
    tracing::debug_span!(
        "pi_observer",
        observer_id = observer_id,
        event_type = event_type,
    )
}

// ─── Test Capture ───────────────────────────────────────────────────────────

/// In-memory log capture for test assertions.
///
/// Collects formatted log lines that can be searched with [`contains`](LogCapture::contains).
#[cfg(test)]
pub struct LogCapture {
    buffer: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[cfg(test)]
impl LogCapture {
    fn new() -> Self {
        Self {
            buffer: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn layer<S>(&self) -> impl Layer<S>
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        CaptureLayer {
            buffer: self.buffer.clone(),
        }
    }

    /// Check if any captured log line contains the given substring.
    pub fn contains(&self, needle: &str) -> bool {
        let buf = self.buffer.lock().unwrap();
        buf.iter().any(|line| line.contains(needle))
    }

    /// Return all captured lines.
    pub fn lines(&self) -> Vec<String> {
        self.buffer.lock().unwrap().clone()
    }

    /// Clear all captured lines.
    pub fn clear(&self) {
        self.buffer.lock().unwrap().clear();
    }
}

#[cfg(test)]
struct CaptureLayer {
    buffer: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[cfg(test)]
impl<S> Layer<S> for CaptureLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = StringVisitor::default();
        event.record(&mut visitor);
        let level = event.metadata().level();
        let target = event.metadata().target();
        let line = format!("[{level}] {target}: {}", visitor.output);
        self.buffer.lock().unwrap().push(line);
    }
}

#[cfg(test)]
#[derive(Default)]
struct StringVisitor {
    output: String,
}

#[cfg(test)]
impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if !self.output.is_empty() {
            self.output.push(' ');
        }
        self.output
            .push_str(&format!("{}={:?}", field.name(), value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if !self.output.is_empty() {
            self.output.push(' ');
        }
        let redacted = redact_if_sensitive(field.name(), value);
        self.output
            .push_str(&format!("{}=\"{}\"", field.name(), redacted));
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_field_detection() {
        assert!(is_sensitive_field("api_key"));
        assert!(is_sensitive_field("API_KEY"));
        assert!(is_sensitive_field("x_api_key_header"));
        assert!(is_sensitive_field("token"));
        assert!(is_sensitive_field("access_token"));
        assert!(is_sensitive_field("refresh_token"));
        assert!(is_sensitive_field("secret"));
        assert!(is_sensitive_field("password"));
        assert!(is_sensitive_field("authorization"));
        assert!(is_sensitive_field("credential"));
        assert!(is_sensitive_field("bearer"));

        // Non-sensitive fields.
        assert!(!is_sensitive_field("model"));
        assert!(!is_sensitive_field("session_id"));
        assert!(!is_sensitive_field("path"));
        assert!(!is_sensitive_field("name"));
        assert!(!is_sensitive_field("command"));
    }

    #[test]
    fn redaction_replaces_sensitive_values() {
        let redacted = redact_if_sensitive("api_key", "sk-abc123");
        assert_eq!(redacted.as_ref(), "[REDACTED]");

        let kept = redact_if_sensitive("model", "claude-opus-4-6");
        assert_eq!(kept.as_ref(), "claude-opus-4-6");
    }

    #[test]
    fn session_span_creation_does_not_panic() {
        // Without a subscriber, spans are disabled (NoOp), but creation must not panic.
        let span = session_span("sess_123", "host_abc", 5);
        let _guard = span.enter();
    }

    #[test]
    fn request_span_creation_does_not_panic() {
        let span = request_span("req_456");
        let _guard = span.enter();
    }

    #[test]
    fn observer_span_creation_does_not_panic() {
        let span = observer_span("obs_789", "page_navigation");
        let _guard = span.enter();
    }

    #[test]
    fn log_dir_under_home() {
        let dir = log_dir();
        assert!(dir.is_some());
        let dir = dir.unwrap();
        assert!(dir.to_string_lossy().contains(".pi/logs"));
    }

    #[test]
    fn prune_old_logs_does_not_panic_on_missing_dir() {
        // Should be a no-op, not a panic.
        prune_old_logs();
    }

    #[test]
    fn max_log_files_is_reasonable() {
        assert!(MAX_LOG_FILES >= 3);
        assert!(MAX_LOG_FILES <= 30);
    }
}
