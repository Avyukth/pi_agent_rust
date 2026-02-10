//! Black-box CLI scenario runner for E2E tests.
//!
//! Provides a declarative, parameterized harness that:
//! - Spawns the `pi` binary in a tmux session
//! - Drives it through a sequence of steps (send text, send key, wait)
//! - Assigns correlation IDs to each step for cross-log tracing
//! - Emits structured JSONL transcripts for replay and diff tooling
//!
//! # Example
//!
//! ```ignore
//! let scenario = CliScenario::new("basic_chat")
//!     .arg("--no-tools")
//!     .arg("--no-extensions")
//!     .env("PI_TEST_MODE", "1")
//!     .step(ScenarioStep::send_text("Hello", "Hello").label("greeting"))
//!     .step(ScenarioStep::wait("response text").timeout_secs(30))
//!     .exit(ExitStrategy::Graceful);
//!
//! let transcript = ScenarioRunner::run(scenario).expect("scenario failed");
//! assert!(transcript.exit_status.is_clean());
//! ```

use super::harness::TestHarness;
#[cfg(unix)]
use super::tmux::TuiSession;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Scenario definition types
// ---------------------------------------------------------------------------

/// A single step in a CLI scenario.
#[derive(Clone, Debug)]
pub struct ScenarioStep {
    /// What to do.
    pub action: StepAction,
    /// Text expected to appear in the pane after this step.
    pub expect: String,
    /// Per-step timeout (default: 15s).
    pub timeout: Duration,
    /// Human-readable label for logs and transcripts.
    pub label: Option<String>,
}

impl ScenarioStep {
    /// Send text followed by Enter and wait for `expect`.
    pub fn send_text(text: &str, expect: &str) -> Self {
        Self {
            action: StepAction::SendText(text.to_string()),
            expect: expect.to_string(),
            timeout: Duration::from_secs(15),
            label: None,
        }
    }

    /// Send a special key (e.g. "C-d", "C-c", "Enter") and wait for `expect`.
    pub fn send_key(key: &str, expect: &str) -> Self {
        Self {
            action: StepAction::SendKey(key.to_string()),
            expect: expect.to_string(),
            timeout: Duration::from_secs(15),
            label: None,
        }
    }

    /// Wait for `expect` to appear without sending anything.
    pub fn wait(expect: &str) -> Self {
        Self {
            action: StepAction::Wait,
            expect: expect.to_string(),
            timeout: Duration::from_secs(15),
            label: None,
        }
    }

    /// Set a human-readable label for this step.
    pub fn label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    /// Override the default timeout.
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Convenience: set timeout in seconds.
    pub const fn timeout_secs(self, secs: u64) -> Self {
        self.timeout(Duration::from_secs(secs))
    }
}

/// Action to perform in a scenario step.
#[derive(Clone, Debug)]
pub enum StepAction {
    /// Send text followed by Enter.
    SendText(String),
    /// Send a special key (tmux key name).
    SendKey(String),
    /// Wait without sending input.
    Wait,
}

impl fmt::Display for StepAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendText(t) => write!(f, "send_text: {t}"),
            Self::SendKey(k) => write!(f, "send_key: {k}"),
            Self::Wait => write!(f, "wait"),
        }
    }
}

/// How the scenario should exit.
#[derive(Clone, Debug)]
pub enum ExitStrategy {
    /// Send /exit, then Ctrl+D, then Ctrl+C (like `TuiSession::exit_gracefully`).
    Graceful,
    /// Send Ctrl+C.
    CtrlC,
    /// Send Ctrl+D (EOF).
    CtrlD,
    /// Let the session timeout without explicit exit.
    Timeout(Duration),
}

/// VCR playback configuration for offline scenarios.
#[derive(Clone, Debug)]
pub struct VcrConfig {
    pub cassette_dir: PathBuf,
    pub test_name: String,
}

/// A parameterized CLI scenario definition.
#[derive(Clone, Debug)]
pub struct CliScenario {
    /// Unique scenario name.
    pub name: String,
    /// CLI arguments.
    pub args: Vec<String>,
    /// Extra environment variables.
    pub env: BTreeMap<String, String>,
    /// Ordered sequence of steps.
    pub steps: Vec<ScenarioStep>,
    /// VCR configuration for offline testing.
    pub vcr: Option<VcrConfig>,
    /// How to exit the scenario.
    pub exit_strategy: ExitStrategy,
}

impl CliScenario {
    /// Create a new scenario with a name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            steps: Vec::new(),
            vcr: None,
            exit_strategy: ExitStrategy::Graceful,
        }
    }

    /// Add a CLI argument.
    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    /// Add multiple CLI arguments.
    pub fn args(mut self, args: &[&str]) -> Self {
        self.args
            .extend(args.iter().map(std::string::ToString::to_string));
        self
    }

    /// Set an environment variable.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    /// Append a step.
    pub fn step(mut self, step: ScenarioStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Set VCR playback configuration.
    pub fn vcr(mut self, config: VcrConfig) -> Self {
        self.vcr = Some(config);
        self
    }

    /// Set exit strategy.
    pub const fn exit(mut self, strategy: ExitStrategy) -> Self {
        self.exit_strategy = strategy;
        self
    }
}

// ---------------------------------------------------------------------------
// Transcript / result types
// ---------------------------------------------------------------------------

/// A correlation ID that links a step across logs and artifacts.
#[derive(Clone, Debug, Serialize)]
pub struct CorrelationId {
    /// Run-level ID (unique per scenario execution).
    pub run_id: String,
    /// Step index within the run.
    pub step_index: usize,
    /// Composite: `{run_id}/{step_index}`.
    pub composite: String,
}

impl CorrelationId {
    fn new(run_id: &str, step_index: usize) -> Self {
        Self {
            run_id: run_id.to_string(),
            step_index,
            composite: format!("{run_id}/{step_index}"),
        }
    }
}

/// An event boundary marker within a step.
#[derive(Clone, Debug, Serialize)]
pub struct EventBoundary {
    /// Type: `step_start`, `step_end`, `input_sent`, `output_matched`, `exit_attempt`.
    pub boundary_type: String,
    /// Milliseconds since scenario start.
    pub timestamp_ms: u64,
    /// Optional structured details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Result of executing a single step.
#[derive(Clone, Debug, Serialize)]
pub struct StepResult {
    pub correlation_id: CorrelationId,
    pub label: String,
    pub action: String,
    pub expected: String,
    pub pane_snapshot_lines: usize,
    pub elapsed_ms: u64,
    pub success: bool,
    pub event_boundaries: Vec<EventBoundary>,
}

/// Exit status of the scenario.
#[derive(Clone, Debug, Serialize)]
pub enum ExitStatus {
    Clean,
    ForcedExit { method: String },
    Timeout,
    SessionDied,
}

impl ExitStatus {
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

/// An artifact produced during the scenario run.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactEntry {
    pub name: String,
    pub path: String,
}

/// Complete transcript of a scenario execution.
#[derive(Clone, Debug, Serialize)]
pub struct ScenarioTranscript {
    /// Scenario name.
    pub scenario_name: String,
    /// Unique run ID.
    pub run_id: String,
    /// Per-step results.
    pub steps: Vec<StepResult>,
    /// How the session ended.
    pub exit_status: ExitStatus,
    /// Total wall-clock time in milliseconds.
    pub total_elapsed_ms: u64,
    /// Artifacts produced.
    pub artifacts: Vec<ArtifactEntry>,
}

impl ScenarioTranscript {
    /// Write the transcript as JSONL to a file.
    pub fn write_jsonl(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::fmt::Write as _;
        let mut buf = String::new();

        // Header line
        let header = serde_json::json!({
            "type": "scenario_header",
            "scenario_name": self.scenario_name,
            "run_id": self.run_id,
            "total_elapsed_ms": self.total_elapsed_ms,
            "exit_status": serde_json::to_value(&self.exit_status).unwrap_or_default(),
            "step_count": self.steps.len(),
        });
        let _ = writeln!(
            buf,
            "{}",
            serde_json::to_string(&header).unwrap_or_default()
        );

        // One line per step
        for step in &self.steps {
            let line = serde_json::json!({
                "type": "step_result",
                "correlation_id": step.correlation_id.composite,
                "run_id": step.correlation_id.run_id,
                "step_index": step.correlation_id.step_index,
                "label": step.label,
                "action": step.action,
                "expected": step.expected,
                "pane_snapshot_lines": step.pane_snapshot_lines,
                "elapsed_ms": step.elapsed_ms,
                "success": step.success,
                "event_boundary_count": step.event_boundaries.len(),
            });
            let _ = writeln!(buf, "{}", serde_json::to_string(&line).unwrap_or_default());
        }

        // Event boundaries (separate lines for grep-ability)
        for step in &self.steps {
            for boundary in &step.event_boundaries {
                let line = serde_json::json!({
                    "type": "event_boundary",
                    "correlation_id": step.correlation_id.composite,
                    "boundary_type": boundary.boundary_type,
                    "timestamp_ms": boundary.timestamp_ms,
                    "details": boundary.details,
                });
                let _ = writeln!(buf, "{}", serde_json::to_string(&line).unwrap_or_default());
            }
        }

        // Artifacts
        for artifact in &self.artifacts {
            let line = serde_json::json!({
                "type": "artifact",
                "name": artifact.name,
                "path": artifact.path,
            });
            let _ = writeln!(buf, "{}", serde_json::to_string(&line).unwrap_or_default());
        }

        std::fs::write(path, buf)
    }
}

// ---------------------------------------------------------------------------
// Scenario runner
// ---------------------------------------------------------------------------

/// Generate a deterministic run ID from the scenario name and a seed.
fn generate_run_id(scenario_name: &str, seed: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scenario_name.as_bytes());
    hasher.update(seed.to_le_bytes());
    let hash = hasher.finalize();
    format!(
        "{:x}",
        &hash[..8]
            .iter()
            .fold(0u64, |acc, &b| acc << 8 | u64::from(b))
    )
}

/// Scenario runner: executes scenarios via tmux and produces transcripts.
#[cfg(unix)]
pub struct ScenarioRunner;

#[cfg(unix)]
impl ScenarioRunner {
    /// Execute a single scenario and return its transcript.
    ///
    /// Returns `None` if tmux is unavailable.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn run(scenario: CliScenario) -> Option<ScenarioTranscript> {
        let mut session = TuiSession::new(&scenario.name)?;
        let run_id = generate_run_id(&scenario.name, session.harness.deterministic_seed());
        let start = Instant::now();

        session.harness.log().info_ctx(
            "scenario",
            format!("Starting scenario: {}", scenario.name),
            |ctx| {
                ctx.push(("run_id".into(), run_id.clone()));
                ctx.push(("step_count".into(), scenario.steps.len().to_string()));
                ctx.push(("args".into(), scenario.args.join(" ")));
            },
        );

        // Apply environment overrides
        for (key, value) in &scenario.env {
            session.set_env(key, value);
        }

        // Apply VCR config
        if let Some(vcr) = &scenario.vcr {
            session.set_env("VCR_MODE", "playback");
            session.set_env("VCR_CASSETTE_DIR", &vcr.cassette_dir.display().to_string());
            session.set_env("PI_VCR_TEST_NAME", &vcr.test_name);
        }

        // Launch
        let args: Vec<&str> = scenario.args.iter().map(String::as_str).collect();
        session.launch(&args);

        // Execute steps
        let mut step_results = Vec::new();
        for (i, step) in scenario.steps.iter().enumerate() {
            let cid = CorrelationId::new(&run_id, i);
            let label = step.label.clone().unwrap_or_else(|| format!("step_{i}"));

            let mut boundaries = Vec::new();
            let step_start_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

            boundaries.push(EventBoundary {
                boundary_type: "step_start".to_string(),
                timestamp_ms: step_start_ms,
                details: Some(serde_json::json!({
                    "action": step.action.to_string(),
                    "expected": &step.expect,
                })),
            });

            session.harness.log().info_ctx(
                "step",
                format!("[{cid}] {label}", cid = cid.composite),
                |ctx| {
                    ctx.push(("correlation_id".into(), cid.composite.clone()));
                    ctx.push(("action".into(), step.action.to_string()));
                    ctx.push(("expect".into(), step.expect.clone()));
                },
            );

            let input_sent_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let input_details = match &step.action {
                StepAction::SendText(text) => serde_json::json!({
                    "kind": "text",
                    "chars": text.chars().count(),
                }),
                StepAction::SendKey(key) => serde_json::json!({
                    "kind": "key",
                    "key": key,
                }),
                StepAction::Wait => serde_json::json!({
                    "kind": "wait",
                }),
            };
            boundaries.push(EventBoundary {
                boundary_type: "input_sent".to_string(),
                timestamp_ms: input_sent_ms,
                details: Some(input_details),
            });

            let step_clock = Instant::now();
            let (pane, success) = execute_step(&session, step);

            let output_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            boundaries.push(EventBoundary {
                boundary_type: if success {
                    "output_matched".to_string()
                } else {
                    "step_timeout".to_string()
                },
                timestamp_ms: output_ms,
                details: Some(serde_json::json!({
                    "pane_lines": pane.lines().count(),
                    "success": success,
                })),
            });

            let step_end_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            boundaries.push(EventBoundary {
                boundary_type: "step_end".to_string(),
                timestamp_ms: step_end_ms,
                details: None,
            });

            step_results.push(StepResult {
                correlation_id: cid,
                label,
                action: step.action.to_string(),
                expected: step.expect.clone(),
                pane_snapshot_lines: pane.lines().count(),
                elapsed_ms: u64::try_from(step_clock.elapsed().as_millis()).unwrap_or(u64::MAX),
                success,
                event_boundaries: boundaries,
            });

            if !success {
                session.harness.log().warn(
                    "scenario",
                    format!("Step {i} failed; aborting remaining steps"),
                );
                break;
            }
        }

        // Exit
        let exit_status = execute_exit(&session, &scenario.exit_strategy, &start);

        let exit_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        session.harness.log().info_ctx(
            "scenario",
            format!("Scenario complete: {}", scenario.name),
            |ctx| {
                ctx.push(("run_id".into(), run_id.clone()));
                ctx.push(("exit_status".into(), format!("{exit_status:?}")));
                ctx.push(("elapsed_ms".into(), exit_ms.to_string()));
            },
        );

        // Write TUI step artifacts first
        session.write_artifacts();

        let session_root = scenario.env.get("PI_SESSIONS_DIR").map_or_else(
            || session.harness.temp_dir().join("env").join("sessions"),
            PathBuf::from,
        );
        if let Some(session_path) = find_latest_session_jsonl(&session_root) {
            session
                .harness
                .record_artifact("session.jsonl", &session_path);
        }

        // Write transcript JSONL (with preliminary artifact list)
        let transcript_path = session.harness.temp_path("scenario-transcript.jsonl");
        let mut transcript = ScenarioTranscript {
            scenario_name: scenario.name.clone(),
            run_id,
            steps: step_results,
            exit_status,
            total_elapsed_ms: exit_ms,
            artifacts: Vec::new(), // filled after recording
        };

        if let Err(e) = transcript.write_jsonl(&transcript_path) {
            session
                .harness
                .log()
                .warn("scenario", format!("Failed to write transcript JSONL: {e}"));
        } else {
            session
                .harness
                .record_artifact("scenario-transcript.jsonl", &transcript_path);
        }

        // Now collect all artifacts including the transcript itself
        transcript.artifacts = collect_artifacts(&session.harness);

        Some(transcript)
    }

    /// Run multiple scenarios sequentially and collect transcripts.
    pub fn run_batch(scenarios: Vec<CliScenario>) -> Vec<(String, Option<ScenarioTranscript>)> {
        scenarios
            .into_iter()
            .map(|s| {
                let name = s.name.clone();
                let transcript = Self::run(s);
                (name, transcript)
            })
            .collect()
    }
}

/// Execute a single step against the TUI session.
///
/// Returns `(pane_content, success)`.
#[cfg(unix)]
fn execute_step(session: &TuiSession, step: &ScenarioStep) -> (String, bool) {
    match &step.action {
        StepAction::SendText(text) => {
            session.tmux.send_literal(text);
            session.tmux.send_key("Enter");
        }
        StepAction::SendKey(key) => {
            session.tmux.send_key(key);
        }
        StepAction::Wait => {}
    }

    match session
        .tmux
        .wait_for_pane_contains(&step.expect, step.timeout)
    {
        pane if pane.contains(&step.expect) => (pane, true),
        pane => (pane, false),
    }
}

/// Execute the exit strategy and return the resulting status.
#[cfg(unix)]
fn execute_exit(session: &TuiSession, strategy: &ExitStrategy, start: &Instant) -> ExitStatus {
    match strategy {
        ExitStrategy::Graceful => {
            session.exit_gracefully();
            if session.tmux.session_exists() {
                ExitStatus::ForcedExit {
                    method: "graceful_fallback".to_string(),
                }
            } else {
                ExitStatus::Clean
            }
        }
        ExitStrategy::CtrlC => {
            if session.tmux.session_exists() {
                let _ = session.tmux.try_send_key("C-c");
                std::thread::sleep(Duration::from_millis(200));
                let _ = session.tmux.try_send_key("C-c");
            }
            std::thread::sleep(Duration::from_secs(2));
            if session.tmux.session_exists() {
                ExitStatus::ForcedExit {
                    method: "ctrl_c".to_string(),
                }
            } else {
                ExitStatus::Clean
            }
        }
        ExitStrategy::CtrlD => {
            if session.tmux.session_exists() {
                let _ = session.tmux.try_send_key("C-d");
            }
            std::thread::sleep(Duration::from_secs(2));
            if session.tmux.session_exists() {
                ExitStatus::ForcedExit {
                    method: "ctrl_d".to_string(),
                }
            } else {
                ExitStatus::Clean
            }
        }
        ExitStrategy::Timeout(dur) => {
            let deadline = *dur;
            let elapsed = start.elapsed();
            if let Some(remaining) = deadline.checked_sub(elapsed) {
                std::thread::sleep(remaining);
            }
            if session.tmux.session_exists() {
                ExitStatus::Timeout
            } else {
                ExitStatus::SessionDied
            }
        }
    }
}

/// Collect artifact entries from the harness logger.
#[cfg(unix)]
fn collect_artifacts(harness: &TestHarness) -> Vec<ArtifactEntry> {
    harness
        .log()
        .artifacts()
        .iter()
        .map(|a| ArtifactEntry {
            name: a.name.clone(),
            path: a.path.clone(),
        })
        .collect()
}

#[cfg(unix)]
fn collect_jsonl_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_jsonl_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
}

#[cfg(unix)]
fn find_latest_session_jsonl(root: &Path) -> Option<PathBuf> {
    let mut files = Vec::new();
    collect_jsonl_files(root, &mut files);
    files.sort();
    files.pop()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_step_builder() {
        let step = ScenarioStep::send_text("hello", "world")
            .label("greeting")
            .timeout_secs(30);
        assert_eq!(step.label.as_deref(), Some("greeting"));
        assert_eq!(step.timeout, Duration::from_secs(30));
        assert_eq!(step.expect, "world");
        assert!(matches!(step.action, StepAction::SendText(ref t) if t == "hello"));
    }

    #[test]
    fn scenario_builder() {
        let scenario = CliScenario::new("test_scenario")
            .arg("--no-tools")
            .arg("--no-extensions")
            .env("FOO", "bar")
            .step(ScenarioStep::send_text("hi", "response"))
            .exit(ExitStrategy::CtrlC);

        assert_eq!(scenario.name, "test_scenario");
        assert_eq!(scenario.args, vec!["--no-tools", "--no-extensions"]);
        assert_eq!(scenario.env.get("FOO").unwrap(), "bar");
        assert_eq!(scenario.steps.len(), 1);
    }

    #[test]
    fn correlation_id_format() {
        let cid = CorrelationId::new("run-abc123", 5);
        assert_eq!(cid.composite, "run-abc123/5");
        assert_eq!(cid.run_id, "run-abc123");
        assert_eq!(cid.step_index, 5);
    }

    #[test]
    fn run_id_is_deterministic() {
        let id1 = generate_run_id("test", 42);
        let id2 = generate_run_id("test", 42);
        assert_eq!(id1, id2);

        let id3 = generate_run_id("test", 43);
        assert_ne!(id1, id3);
    }

    #[test]
    fn exit_status_is_clean() {
        assert!(ExitStatus::Clean.is_clean());
        assert!(!ExitStatus::Timeout.is_clean());
        assert!(!ExitStatus::SessionDied.is_clean());
        assert!(
            !ExitStatus::ForcedExit {
                method: "ctrl_c".to_string()
            }
            .is_clean()
        );
    }

    #[test]
    fn transcript_jsonl_roundtrip() {
        let transcript = ScenarioTranscript {
            scenario_name: "test".to_string(),
            run_id: "run-1".to_string(),
            steps: vec![StepResult {
                correlation_id: CorrelationId::new("run-1", 0),
                label: "step_0".to_string(),
                action: "send_text: hello".to_string(),
                expected: "world".to_string(),
                pane_snapshot_lines: 24,
                elapsed_ms: 150,
                success: true,
                event_boundaries: vec![
                    EventBoundary {
                        boundary_type: "step_start".to_string(),
                        timestamp_ms: 0,
                        details: None,
                    },
                    EventBoundary {
                        boundary_type: "output_matched".to_string(),
                        timestamp_ms: 150,
                        details: Some(serde_json::json!({ "pane_lines": 24 })),
                    },
                ],
            }],
            exit_status: ExitStatus::Clean,
            total_elapsed_ms: 500,
            artifacts: vec![ArtifactEntry {
                name: "log.jsonl".to_string(),
                path: "/tmp/log.jsonl".to_string(),
            }],
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("transcript.jsonl");
        transcript.write_jsonl(&path).expect("write");

        let content = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = content.lines().collect();

        // Header + 1 step + 2 boundaries + 1 artifact = 5 lines
        assert_eq!(lines.len(), 5, "expected 5 JSONL lines, got: {content}");

        let header: serde_json::Value = serde_json::from_str(lines[0]).expect("parse header");
        assert_eq!(header["type"], "scenario_header");
        assert_eq!(header["run_id"], "run-1");
        assert_eq!(header["step_count"], 1);

        let step: serde_json::Value = serde_json::from_str(lines[1]).expect("parse step");
        assert_eq!(step["type"], "step_result");
        assert_eq!(step["correlation_id"], "run-1/0");
        assert_eq!(step["success"], true);

        let boundary: serde_json::Value = serde_json::from_str(lines[2]).expect("parse boundary");
        assert_eq!(boundary["type"], "event_boundary");
        assert_eq!(boundary["boundary_type"], "step_start");

        let artifact: serde_json::Value = serde_json::from_str(lines[4]).expect("parse artifact");
        assert_eq!(artifact["type"], "artifact");
        assert_eq!(artifact["name"], "log.jsonl");
    }

    #[test]
    fn step_action_display() {
        assert_eq!(
            StepAction::SendText("hi".into()).to_string(),
            "send_text: hi"
        );
        assert_eq!(
            StepAction::SendKey("C-c".into()).to_string(),
            "send_key: C-c"
        );
        assert_eq!(StepAction::Wait.to_string(), "wait");
    }
}
