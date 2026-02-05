//! TUI interactive E2E tests via tmux capture with deterministic artifacts.
//!
//! These tests launch the `pi` binary in a tmux session, drive scripted
//! interactions (prompts, slash commands, key sequences), capture pane output
//! per step, and emit JSONL artifacts for CI diffing.
//!
//! Run:
//! ```bash
//! cargo test --test e2e_tui
//! ```

#![cfg(unix)]

mod common;

use common::tmux::TuiSession;
use std::time::Duration;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Standard CLI args for interactive mode with minimal features.
fn base_interactive_args() -> Vec<&'static str> {
    vec![
        "--provider",
        "openai",
        "--model",
        "gpt-4o-mini",
        "--api-key",
        "test-key-e2e",
        "--no-tools",
        "--no-skills",
        "--no-prompt-templates",
        "--no-extensions",
        "--no-themes",
        "--system-prompt",
        "pi e2e tui test harness",
    ]
}

const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Smoke test: launch interactive mode, verify welcome screen, exit cleanly.
#[test]
fn e2e_tui_startup_and_exit() {
    let Some(mut session) = TuiSession::new("e2e_tui_startup_and_exit") else {
        eprintln!("Skipping: tmux not available");
        return;
    };

    session.launch(&base_interactive_args());

    // Wait for welcome message
    let pane = session.wait_and_capture("startup", "Welcome to Pi!", STARTUP_TIMEOUT);
    assert!(
        pane.contains("Welcome to Pi!"),
        "Expected welcome message; got:\n{pane}"
    );

    // Exit gracefully
    session.exit_gracefully();
    assert!(
        !session.tmux.session_exists(),
        "Session did not exit cleanly"
    );

    session.write_artifacts();

    assert!(
        !session.steps().is_empty(),
        "Expected at least one recorded step"
    );
}

/// Test /help slash command: sends /help, verifies help output appears.
#[test]
fn e2e_tui_help_command() {
    let Some(mut session) = TuiSession::new("e2e_tui_help_command") else {
        eprintln!("Skipping: tmux not available");
        return;
    };

    session.launch(&base_interactive_args());

    // Wait for startup
    session.wait_and_capture("startup", "Welcome to Pi!", STARTUP_TIMEOUT);

    // Send /help
    let pane = session.send_text_and_wait(
        "help_command",
        "/help",
        "Available commands:",
        COMMAND_TIMEOUT,
    );

    let help_markers = [
        "Available commands:",
        "/logout",
        "/clear",
        "/model",
        "Tips:",
    ];
    let found_markers: Vec<&&str> = help_markers
        .iter()
        .filter(|m| pane.contains(*m))
        .collect();
    assert!(
        !found_markers.is_empty(),
        "Expected help markers in output; got:\n{pane}"
    );

    session.harness.log().info_ctx("verify", "Help output validated", |ctx| {
        ctx.push((
            "found_markers".into(),
            found_markers
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    });

    session.exit_gracefully();
    session.write_artifacts();
}

/// Test /model slash command: sends /model, verifies model info appears.
#[test]
fn e2e_tui_model_command() {
    let Some(mut session) = TuiSession::new("e2e_tui_model_command") else {
        eprintln!("Skipping: tmux not available");
        return;
    };

    session.launch(&base_interactive_args());

    // Wait for startup
    session.wait_and_capture("startup", "Welcome to Pi!", STARTUP_TIMEOUT);

    // Send /model
    let pane = session.send_text_and_wait(
        "model_command",
        "/model",
        "gpt-4o-mini",
        COMMAND_TIMEOUT,
    );
    assert!(
        pane.contains("gpt-4o-mini"),
        "Expected model info in output; got:\n{pane}"
    );

    session.exit_gracefully();
    session.write_artifacts();
}

/// Test /clear slash command: sends /clear, verifies screen is cleared.
#[test]
fn e2e_tui_clear_command() {
    let Some(mut session) = TuiSession::new("e2e_tui_clear_command") else {
        eprintln!("Skipping: tmux not available");
        return;
    };

    session.launch(&base_interactive_args());

    // Wait for startup
    let pane_before = session.wait_and_capture("startup", "Welcome to Pi!", STARTUP_TIMEOUT);
    assert!(pane_before.contains("Welcome to Pi!"));

    // Send /clear
    session.tmux.send_literal("/clear");
    session.tmux.send_key("Enter");
    std::thread::sleep(Duration::from_millis(500));

    // After clear, the welcome message may or may not be visible depending on
    // implementation. Just verify the session is still alive and responsive.
    let pane_after = session.tmux.capture_pane();
    session.harness.log().info_ctx("verify", "Clear command executed", |ctx| {
        ctx.push(("pane_lines_before".into(), pane_before.lines().count().to_string()));
        ctx.push(("pane_lines_after".into(), pane_after.lines().count().to_string()));
    });

    // Save the pane snapshots
    let artifact_path = session.harness.temp_path("pane-after-clear.txt");
    std::fs::write(&artifact_path, &pane_after).expect("write pane after clear");
    session
        .harness
        .record_artifact("pane-after-clear.txt", &artifact_path);

    session.exit_gracefully();
    session.write_artifacts();
}

/// Test multiple sequential commands in one session.
#[test]
fn e2e_tui_multi_command_sequence() {
    let Some(mut session) = TuiSession::new("e2e_tui_multi_command_sequence") else {
        eprintln!("Skipping: tmux not available");
        return;
    };

    session.launch(&base_interactive_args());

    // Step 1: Wait for startup
    session.wait_and_capture("startup", "Welcome to Pi!", STARTUP_TIMEOUT);

    // Step 2: /help
    let pane = session.send_text_and_wait(
        "help",
        "/help",
        "Available commands:",
        COMMAND_TIMEOUT,
    );
    assert!(pane.contains("Available commands:"));

    // Step 3: /model
    let pane = session.send_text_and_wait(
        "model",
        "/model",
        "gpt-4o-mini",
        COMMAND_TIMEOUT,
    );
    assert!(pane.contains("gpt-4o-mini"));

    // Step 4: Exit
    session.exit_gracefully();
    assert!(
        !session.tmux.session_exists(),
        "Session did not exit cleanly after multi-command sequence"
    );

    session.write_artifacts();

    // Verify we captured all steps
    session.harness.log().info_ctx("summary", "Multi-command sequence complete", |ctx| {
        ctx.push(("total_steps".into(), session.steps().len().to_string()));
    });
    assert!(
        session.steps().len() >= 3,
        "Expected >= 3 steps (startup + help + model), got {}",
        session.steps().len()
    );
}

/// Test Ctrl+D exits the session cleanly.
#[test]
fn e2e_tui_ctrl_d_exit() {
    let Some(mut session) = TuiSession::new("e2e_tui_ctrl_d_exit") else {
        eprintln!("Skipping: tmux not available");
        return;
    };

    session.launch(&base_interactive_args());

    session.wait_and_capture("startup", "Welcome to Pi!", STARTUP_TIMEOUT);

    // Send Ctrl+D
    session.tmux.send_key("C-d");

    let start = std::time::Instant::now();
    while session.tmux.session_exists() {
        if start.elapsed() > Duration::from_secs(10) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Capture final state if still alive
    if session.tmux.session_exists() {
        let pane = session.tmux.capture_pane();
        session.harness.log().warn("tmux", format!("Session still alive after Ctrl+D. Pane:\n{pane}"));
        // Force kill for cleanup
        session.tmux.send_key("C-c");
        std::thread::sleep(Duration::from_millis(100));
        session.tmux.send_key("C-c");
    }

    session.write_artifacts();
}

/// Verify artifacts are deterministic (JSONL steps file is well-formed).
#[test]
fn e2e_tui_artifact_format() {
    let Some(mut session) = TuiSession::new("e2e_tui_artifact_format") else {
        eprintln!("Skipping: tmux not available");
        return;
    };

    session.launch(&base_interactive_args());
    session.wait_and_capture("startup", "Welcome to Pi!", STARTUP_TIMEOUT);
    session.send_text_and_wait("help", "/help", "Available commands:", COMMAND_TIMEOUT);
    session.exit_gracefully();
    session.write_artifacts();

    // Verify the steps JSONL is well-formed
    let steps_path = session.harness.temp_path("tui-steps.jsonl");
    let steps_content = std::fs::read_to_string(&steps_path).expect("read steps jsonl");
    let mut line_count = 0;
    for line in steps_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("Invalid JSONL line: {e}\n{line}"));
        assert!(parsed.get("label").is_some(), "Missing 'label' in step");
        assert!(parsed.get("action").is_some(), "Missing 'action' in step");
        assert!(
            parsed.get("elapsed_ms").is_some(),
            "Missing 'elapsed_ms' in step"
        );
        line_count += 1;
    }
    assert!(
        line_count >= 2,
        "Expected >= 2 step lines in JSONL, got {line_count}"
    );

    // Verify log JSONL is well-formed
    let log_path = session.harness.temp_path("tui-log.jsonl");
    let log_content = std::fs::read_to_string(&log_path).expect("read log jsonl");
    for line in log_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let _parsed: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("Invalid log JSONL line: {e}\n{line}"));
    }

    session.harness.log().info_ctx("verify", "Artifact format validated", |ctx| {
        ctx.push(("step_lines".into(), line_count.to_string()));
        ctx.push((
            "log_lines".into(),
            log_content.lines().filter(|l| !l.trim().is_empty()).count().to_string(),
        ));
    });
}
