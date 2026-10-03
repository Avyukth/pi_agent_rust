//! Structured test artifact bundles with correlated trace IDs (bd-1xz.2).
//!
//! Extends the existing `TestLogger` infrastructure with:
//! - **Artifact bundles**: groups logs, protocol traces, and files into a single
//!   directory with a standard layout for CI artifact retention.
//! - **Protocol trace recording**: structured capture of Chrome protocol messages
//!   (auth handshake, requests, responses, observations).
//! - **Cross-layer correlation**: bridges test `trace_id` to the runtime
//!   `logging::session_span` for end-to-end debugging.
//! - **Predictable storage**: `target/test-artifacts/{trace_id}/` convention
//!   for both CI and local runs.
//!
//! # Usage
//!
//! ```ignore
//! let bundle = ArtifactBundle::new("my_test_scenario");
//! bundle.record_protocol_trace(ProtocolDirection::Outgoing, "auth_claim", &claim_json);
//! bundle.record_protocol_trace(ProtocolDirection::Incoming, "auth_ok", &response_json);
//! bundle.logger().info("verify", "Connection established");
//! bundle.finalize().expect("write bundle");
//! ```

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use super::logging::{self, TestLogger};

// ═══════════════════════════════════════════════════════════════════════════
// Protocol Trace Types
// ═══════════════════════════════════════════════════════════════════════════

/// Direction of a protocol message relative to the agent (`ChromeBridge`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDirection {
    /// Message sent from the agent to the native host.
    Outgoing,
    /// Message received by the agent from the native host.
    Incoming,
}

/// A single Chrome protocol message captured during a test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTraceEntry {
    /// Schema identifier for JSONL validation.
    pub schema: String,
    /// Direction of the message.
    pub direction: ProtocolDirection,
    /// Protocol message type (e.g. `auth_claim`, `auth_ok`, `request`, `response`).
    pub message_type: String,
    /// Elapsed milliseconds from bundle creation.
    pub elapsed_ms: u64,
    /// Redacted payload summary (sensitive fields replaced with `[REDACTED]`).
    pub payload_summary: serde_json::Value,
    /// Optional request ID for correlating request/response pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Correlation trace ID linking to the parent bundle.
    pub trace_id: String,
}

/// Schema identifier for protocol trace JSONL records.
pub const PROTOCOL_TRACE_SCHEMA_V1: &str = "pi.test.protocol_trace.v1";

// ═══════════════════════════════════════════════════════════════════════════
// Bundle Manifest
// ═══════════════════════════════════════════════════════════════════════════

/// Manifest written as `bundle.json` at the root of each artifact bundle directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Schema identifier.
    pub schema: String,
    /// Unique trace ID for this bundle (same as the `TestLogger` trace ID).
    pub trace_id: String,
    /// Optional runtime session ID for cross-layer correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Test scenario name.
    pub scenario: String,
    /// ISO-8601 timestamp when the bundle was created.
    pub created_at: String,
    /// ISO-8601 timestamp when the bundle was finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_at: Option<String>,
    /// Whether the test passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<bool>,
    /// Files included in this bundle (relative paths).
    pub files: Vec<BundleFile>,
    /// Arbitrary metadata key-value pairs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Schema identifier for bundle manifest.
pub const BUNDLE_MANIFEST_SCHEMA_V1: &str = "pi.test.bundle_manifest.v1";

/// A file entry in the bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFile {
    /// Relative path within the bundle directory.
    pub path: String,
    /// MIME-like content type hint.
    pub content_type: String,
    /// File size in bytes (populated at finalization).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Artifact Bundle
// ═══════════════════════════════════════════════════════════════════════════

/// A structured artifact bundle that groups test logs, protocol traces,
/// and arbitrary files into a single directory with a standard layout.
///
/// The bundle is stored at `target/test-artifacts/{trace_id}/` with:
/// - `bundle.json` — manifest with metadata and file index
/// - `logs.jsonl` — structured test log records
/// - `protocol_traces.jsonl` — Chrome protocol message captures
/// - Additional files recorded via [`record_file`](Self::record_file)
pub struct ArtifactBundle {
    logger: TestLogger,
    scenario: String,
    session_id: Option<String>,
    protocol_traces: Mutex<Vec<ProtocolTraceEntry>>,
    extra_files: Mutex<Vec<BundleFile>>,
    metadata: Mutex<BTreeMap<String, String>>,
    start: Instant,
    start_wall: SystemTime,
    bundle_dir: PathBuf,
}

impl ArtifactBundle {
    /// Create a new artifact bundle for the given test scenario.
    ///
    /// The bundle directory is `target/test-artifacts/{trace_id}/`.
    pub fn new(scenario: impl Into<String>) -> Self {
        let logger = TestLogger::new();
        let trace_id = logger.trace_id().to_string();
        let bundle_dir = bundle_base_dir().join(&trace_id);

        let scenario = scenario.into();
        logger.set_test_name(&scenario);

        Self {
            logger,
            scenario,
            session_id: None,
            protocol_traces: Mutex::new(Vec::new()),
            extra_files: Mutex::new(Vec::new()),
            metadata: Mutex::new(BTreeMap::new()),
            start: Instant::now(),
            start_wall: SystemTime::now(),
            bundle_dir,
        }
    }

    /// Access the underlying `TestLogger` for log recording.
    pub const fn logger(&self) -> &TestLogger {
        &self.logger
    }

    /// Get the trace ID for this bundle.
    pub fn trace_id(&self) -> &str {
        self.logger.trace_id()
    }

    /// Get the bundle output directory path.
    pub fn bundle_dir(&self) -> &Path {
        &self.bundle_dir
    }

    /// Set the runtime session ID for cross-layer correlation.
    ///
    /// This links the test bundle to the runtime's `logging::session_span`
    /// so that file-appender logs can be correlated with test outcomes.
    pub fn set_session_id(&mut self, session_id: impl Into<String>) {
        self.session_id = Some(session_id.into());
    }

    /// Add an arbitrary metadata key-value pair to the bundle manifest.
    pub fn add_metadata(&self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata
            .lock()
            .unwrap()
            .insert(key.into(), value.into());
    }

    /// Record a Chrome protocol message exchange.
    ///
    /// The payload is automatically redacted for sensitive fields before storage.
    pub fn record_protocol_trace(
        &self,
        direction: ProtocolDirection,
        message_type: impl Into<String>,
        payload: &serde_json::Value,
        request_id: Option<String>,
    ) {
        let mut redacted_payload = payload.clone();
        logging::redact_json_value(&mut redacted_payload);

        let entry = ProtocolTraceEntry {
            schema: PROTOCOL_TRACE_SCHEMA_V1.to_string(),
            direction,
            message_type: message_type.into(),
            elapsed_ms: u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX),
            payload_summary: redacted_payload,
            request_id,
            trace_id: self.logger.trace_id().to_string(),
        };

        self.protocol_traces.lock().unwrap().push(entry);
    }

    /// Record an additional file in the bundle.
    ///
    /// The file is referenced by path and will be included in the manifest.
    /// The caller is responsible for writing the file to `self.bundle_dir()`.
    pub fn record_file(&self, relative_path: impl Into<String>, content_type: impl Into<String>) {
        self.extra_files.lock().unwrap().push(BundleFile {
            path: relative_path.into(),
            content_type: content_type.into(),
            size_bytes: None,
        });
    }

    /// Get the number of protocol trace entries recorded.
    pub fn protocol_trace_count(&self) -> usize {
        self.protocol_traces.lock().unwrap().len()
    }

    /// Get a copy of all protocol trace entries.
    pub fn protocol_traces(&self) -> Vec<ProtocolTraceEntry> {
        self.protocol_traces.lock().unwrap().clone()
    }

    /// Finalize the bundle: write all artifacts to the bundle directory.
    ///
    /// Creates the directory structure and writes:
    /// - `bundle.json` — manifest
    /// - `logs.jsonl` — test log records
    /// - `protocol_traces.jsonl` — protocol message captures
    ///
    /// Returns the bundle directory path on success.
    pub fn finalize(&self, passed: Option<bool>) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.bundle_dir)?;

        // Write logs.
        let logs_path = self.bundle_dir.join("logs.jsonl");
        self.logger.write_jsonl_to_path(&logs_path)?;

        // Write protocol traces.
        let traces_path = self.bundle_dir.join("protocol_traces.jsonl");
        let trace_content = {
            let traces = self.protocol_traces.lock().unwrap();
            let mut content = String::new();
            for entry in traces.iter() {
                if let Ok(line) = serde_json::to_string(entry) {
                    content.push_str(&line);
                    content.push('\n');
                }
            }
            drop(traces);
            content
        };
        std::fs::write(&traces_path, &trace_content)?;

        // Build manifest.
        let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
        let created: chrono::DateTime<chrono::Utc> = self.start_wall.into();

        let mut files = vec![
            BundleFile {
                path: "logs.jsonl".to_string(),
                content_type: "application/x-jsonl".to_string(),
                size_bytes: file_size(&logs_path),
            },
            BundleFile {
                path: "protocol_traces.jsonl".to_string(),
                content_type: "application/x-jsonl".to_string(),
                size_bytes: file_size(&traces_path),
            },
        ];

        // Include extra files with resolved sizes.
        {
            let extra = self.extra_files.lock().unwrap();
            for ef in extra.iter() {
                let full_path = self.bundle_dir.join(&ef.path);
                files.push(BundleFile {
                    path: ef.path.clone(),
                    content_type: ef.content_type.clone(),
                    size_bytes: file_size(&full_path),
                });
            }
        }

        let manifest = BundleManifest {
            schema: BUNDLE_MANIFEST_SCHEMA_V1.to_string(),
            trace_id: self.logger.trace_id().to_string(),
            session_id: self.session_id.clone(),
            scenario: self.scenario.clone(),
            created_at: created.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            finalized_at: Some(now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            passed,
            files,
            metadata: self.metadata.lock().unwrap().clone(),
        };

        let manifest_path = self.bundle_dir.join("bundle.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&manifest_path, manifest_json)?;

        Ok(self.bundle_dir.clone())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Bundle Directory Convention
// ═══════════════════════════════════════════════════════════════════════════

/// Standard base directory for test artifact bundles.
///
/// Returns `{CARGO_MANIFEST_DIR}/target/test-artifacts/`.
/// Falls back to `./target/test-artifacts/` if `CARGO_MANIFEST_DIR` is unset.
fn bundle_base_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    Path::new(&manifest_dir)
        .join("target")
        .join("test-artifacts")
}

fn file_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bundle_creation_and_trace_id() {
        let bundle = ArtifactBundle::new("test_scenario");
        assert!(!bundle.trace_id().is_empty());
        assert_eq!(bundle.protocol_trace_count(), 0);
        assert!(
            bundle
                .bundle_dir()
                .to_string_lossy()
                .contains("test-artifacts")
        );
    }

    #[test]
    fn bundle_protocol_trace_recording() {
        let bundle = ArtifactBundle::new("trace_test");
        let payload = json!({
            "host_id": "host-1",
            "token": "secret-abc123",
            "pi_session_id": "session-1"
        });

        bundle.record_protocol_trace(ProtocolDirection::Outgoing, "auth_claim", &payload, None);
        bundle.record_protocol_trace(
            ProtocolDirection::Incoming,
            "auth_ok",
            &json!({"host_id": "host-1", "capabilities": ["browser_tools"]}),
            None,
        );

        assert_eq!(bundle.protocol_trace_count(), 2);
        let traces = bundle.protocol_traces();
        assert_eq!(traces[0].direction, ProtocolDirection::Outgoing);
        assert_eq!(traces[0].message_type, "auth_claim");
        // Token should be redacted.
        assert_eq!(
            traces[0].payload_summary["token"],
            json!("[REDACTED]"),
            "token field must be redacted in protocol trace"
        );
        // Non-sensitive fields preserved.
        assert_eq!(traces[0].payload_summary["host_id"], json!("host-1"));
        assert_eq!(traces[1].direction, ProtocolDirection::Incoming);
        assert_eq!(traces[1].message_type, "auth_ok");
    }

    #[test]
    fn bundle_protocol_trace_with_request_id() {
        let bundle = ArtifactBundle::new("req_id_test");
        bundle.record_protocol_trace(
            ProtocolDirection::Outgoing,
            "request",
            &json!({"op": "navigate", "url": "https://example.com"}),
            Some("chrome-42".to_string()),
        );

        let traces = bundle.protocol_traces();
        assert_eq!(traces[0].request_id.as_deref(), Some("chrome-42"));
    }

    #[test]
    fn bundle_metadata() {
        let bundle = ArtifactBundle::new("metadata_test");
        bundle.add_metadata("bead_id", "bd-1xz.2");
        bundle.add_metadata("host_id", "host-test");

        let meta = bundle.metadata.lock().unwrap();
        assert_eq!(meta.get("bead_id").unwrap(), "bd-1xz.2");
        assert_eq!(meta.get("host_id").unwrap(), "host-test");
        drop(meta);
    }

    #[test]
    fn bundle_session_id_correlation() {
        let mut bundle = ArtifactBundle::new("correlation_test");
        assert!(bundle.session_id.is_none());

        bundle.set_session_id("sess_abc123");
        assert_eq!(bundle.session_id.as_deref(), Some("sess_abc123"));
    }

    #[test]
    fn bundle_finalize_creates_directory_and_files() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let bundle = ArtifactBundle::new("finalize_test");

        // Override bundle_dir to use tempdir.
        let custom_dir = tempdir.path().join("custom-bundle");
        let bundle = ArtifactBundle {
            bundle_dir: custom_dir,
            ..bundle_into_parts(bundle)
        };

        bundle.logger().info("setup", "Test started");
        bundle.record_protocol_trace(
            ProtocolDirection::Outgoing,
            "auth_claim",
            &json!({"host_id": "h1"}),
            None,
        );
        bundle.add_metadata("test_key", "test_value");

        let result = bundle.finalize(Some(true));
        assert!(result.is_ok(), "finalize should succeed");

        let dir = result.unwrap();
        assert!(dir.join("bundle.json").exists(), "manifest must exist");
        assert!(dir.join("logs.jsonl").exists(), "logs must exist");
        assert!(
            dir.join("protocol_traces.jsonl").exists(),
            "traces must exist"
        );

        // Verify manifest contents.
        let manifest_raw = std::fs::read_to_string(dir.join("bundle.json")).expect("read manifest");
        let manifest: BundleManifest = serde_json::from_str(&manifest_raw).expect("parse manifest");
        assert_eq!(manifest.scenario, "finalize_test");
        assert_eq!(manifest.passed, Some(true));
        assert!(!manifest.trace_id.is_empty());
        assert!(manifest.finalized_at.is_some());
        assert_eq!(manifest.files.len(), 2); // logs + traces
        assert_eq!(manifest.metadata.get("test_key").unwrap(), "test_value");

        // Verify protocol traces are valid JSONL.
        let traces_raw =
            std::fs::read_to_string(dir.join("protocol_traces.jsonl")).expect("read traces");
        let lines: Vec<&str> = traces_raw.lines().collect();
        assert_eq!(lines.len(), 1, "should have 1 protocol trace line");
        let parsed: ProtocolTraceEntry = serde_json::from_str(lines[0]).expect("parse trace entry");
        assert_eq!(parsed.message_type, "auth_claim");
        assert_eq!(parsed.schema, PROTOCOL_TRACE_SCHEMA_V1);
    }

    #[test]
    fn bundle_finalize_with_extra_files() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let custom_dir = tempdir.path().join("extra-files-bundle");
        let bundle = ArtifactBundle::new("extra_files_test");
        let bundle = ArtifactBundle {
            bundle_dir: custom_dir.clone(),
            ..bundle_into_parts(bundle)
        };

        // Pre-create the extra file.
        std::fs::create_dir_all(&custom_dir).expect("create bundle dir");
        std::fs::write(custom_dir.join("screenshot.png"), b"fake-png-data")
            .expect("write screenshot");
        bundle.record_file("screenshot.png", "image/png");

        let result = bundle.finalize(Some(true));
        assert!(result.is_ok());

        let manifest_raw =
            std::fs::read_to_string(custom_dir.join("bundle.json")).expect("read manifest");
        let manifest: BundleManifest = serde_json::from_str(&manifest_raw).expect("parse manifest");
        assert_eq!(manifest.files.len(), 3); // logs + traces + screenshot
        let screenshot_file = manifest
            .files
            .iter()
            .find(|f| f.path == "screenshot.png")
            .expect("screenshot in manifest");
        assert_eq!(screenshot_file.content_type, "image/png");
        assert_eq!(screenshot_file.size_bytes, Some(13)); // "fake-png-data".len()
    }

    #[test]
    fn protocol_direction_serde_roundtrip() {
        let outgoing = ProtocolDirection::Outgoing;
        let incoming = ProtocolDirection::Incoming;

        let json_out = serde_json::to_string(&outgoing).expect("serialize outgoing");
        let json_in = serde_json::to_string(&incoming).expect("serialize incoming");

        assert_eq!(json_out, "\"outgoing\"");
        assert_eq!(json_in, "\"incoming\"");

        let parsed_out: ProtocolDirection =
            serde_json::from_str(&json_out).expect("deserialize outgoing");
        let parsed_in: ProtocolDirection =
            serde_json::from_str(&json_in).expect("deserialize incoming");

        assert_eq!(parsed_out, ProtocolDirection::Outgoing);
        assert_eq!(parsed_in, ProtocolDirection::Incoming);
    }

    #[test]
    fn bundle_manifest_serde_roundtrip() {
        let manifest = BundleManifest {
            schema: BUNDLE_MANIFEST_SCHEMA_V1.to_string(),
            trace_id: "abc123".to_string(),
            session_id: Some("sess_xyz".to_string()),
            scenario: "roundtrip_test".to_string(),
            created_at: "2026-02-25T00:00:00.000Z".to_string(),
            finalized_at: Some("2026-02-25T00:01:00.000Z".to_string()),
            passed: Some(true),
            files: vec![BundleFile {
                path: "logs.jsonl".to_string(),
                content_type: "application/x-jsonl".to_string(),
                size_bytes: Some(1234),
            }],
            metadata: BTreeMap::from([("key".to_string(), "value".to_string())]),
        };

        let json = serde_json::to_string(&manifest).expect("serialize manifest");
        let parsed: BundleManifest = serde_json::from_str(&json).expect("deserialize manifest");
        assert_eq!(parsed.trace_id, "abc123");
        assert_eq!(parsed.session_id.as_deref(), Some("sess_xyz"));
        assert_eq!(parsed.scenario, "roundtrip_test");
        assert_eq!(parsed.passed, Some(true));
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.metadata.get("key").unwrap(), "value");
    }

    #[test]
    fn protocol_trace_entry_redacts_sensitive_fields() {
        let bundle = ArtifactBundle::new("redaction_test");
        let payload = json!({
            "host_id": "safe-value",
            "token": "super-secret-token",
            "api_key": "sk-12345",
            "nested": {
                "password": "hunter2",
                "safe_field": "visible"
            }
        });

        bundle.record_protocol_trace(ProtocolDirection::Outgoing, "auth_claim", &payload, None);

        let traces = bundle.protocol_traces();
        let summary = &traces[0].payload_summary;

        assert_eq!(summary["host_id"], json!("safe-value"));
        assert_eq!(summary["token"], json!("[REDACTED]"));
        assert_eq!(summary["api_key"], json!("[REDACTED]"));
        assert_eq!(summary["nested"]["password"], json!("[REDACTED]"));
        assert_eq!(summary["nested"]["safe_field"], json!("visible"));
    }

    #[test]
    fn bundle_base_dir_convention() {
        let dir = bundle_base_dir();
        assert!(
            dir.to_string_lossy().ends_with("test-artifacts"),
            "bundle base dir should end with test-artifacts: {dir:?}"
        );
    }

    /// Helper to destructure a bundle for test customization (override `bundle_dir`).
    fn bundle_into_parts(bundle: ArtifactBundle) -> ArtifactBundle {
        bundle
    }
}
