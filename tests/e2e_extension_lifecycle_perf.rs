//! E2E extension lifecycle and performance diagnostics (bd-3ar8v.4.9).
//!
//! Covers the full extension lifecycle: load → init → tool-call → event-hook →
//! budget-fallback → shutdown, with per-extension latency and resource diagnostics.
//! Uses real extensions from the conformance corpus (hello, pirate, diff).
//!
//! Outputs structured JSONL to `target/perf/e2e_lifecycle.jsonl` for CI integration.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_precision_loss,
    clippy::future_not_send,
    clippy::doc_markdown
)]

mod common;

use pi::extensions::{
    ExtensionEventName, ExtensionManager, JsExtensionLoadSpec, JsExtensionRuntimeHandle,
};
use pi::extensions_js::PiJsRuntimeConfig;
use pi::tools::ToolRegistry;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Extensions to test from the conformance corpus.
const LIFECYCLE_EXTENSIONS: &[&str] = &["hello", "pirate", "diff"];

/// Event dispatch iterations for latency measurement.
const EVENT_ITERATIONS: usize = 50;

/// Tool call iterations for latency measurement.
const TOOL_ITERATIONS: usize = 50;

/// Budget timeout for normal operations (ms).
const NORMAL_TIMEOUT_MS: u64 = 5_000;

/// Short timeout for budget-fallback testing (ms).
const SHORT_TIMEOUT_MS: u64 = 50;

// ─── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct LifecycleRecord {
    schema: String,
    extension: String,
    phase: String,
    iterations: usize,
    elapsed_ms: f64,
    per_call_us: f64,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DiagnosticsRecord {
    schema: String,
    extension: String,
    risk_ledger_entries: usize,
    hostcall_telemetry_entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_state: Option<QuotaSnapshot>,
    snapshot_version: u64,
}

#[derive(Debug, Clone, Serialize)]
struct QuotaSnapshot {
    budget_remaining_ns: u64,
    call_count: u32,
    last_call_ns: u64,
    total_elapsed_ns: u64,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn artifact_entry(name: &str) -> PathBuf {
    project_root()
        .join("tests/ext_conformance/artifacts")
        .join(name)
        .join(format!("{name}.ts"))
}

fn write_jsonl(records: &[Value], path: &Path) {
    use std::fmt::Write as _;
    let mut content = String::new();
    for record in records {
        let _ = writeln!(content, "{}", serde_json::to_string(record).unwrap_or_default());
    }
    let _ = fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")));
    fs::write(path, &content).unwrap_or_else(|e| {
        eprintln!("[error] failed to write {}: {e}", path.display());
    });
}

/// Create an `ExtensionManager` with a JS runtime, load the given spec, return manager.
fn setup_manager_with_extension(
    harness: &common::TestHarness,
    spec: &JsExtensionLoadSpec,
) -> ExtensionManager {
    let cwd = harness.temp_dir().to_path_buf();
    let manager = ExtensionManager::new();
    let tools = Arc::new(ToolRegistry::new(&[], &cwd, None));
    let js_config = PiJsRuntimeConfig {
        cwd: cwd.display().to_string(),
        ..Default::default()
    };

    let runtime = common::run_async({
        let manager = manager.clone();
        let tools = Arc::clone(&tools);
        async move {
            JsExtensionRuntimeHandle::start(js_config, tools, manager)
                .await
                .expect("start js runtime")
        }
    });
    manager.set_js_runtime(runtime);

    common::run_async({
        let manager = manager.clone();
        let spec = spec.clone();
        async move {
            manager
                .load_js_extensions(vec![spec])
                .await
                .expect("load extension");
        }
    });

    manager
}

fn shutdown(manager: &ExtensionManager) {
    let _ = common::run_async({
        let manager = manager.clone();
        async move { manager.shutdown(Duration::from_millis(500)).await }
    });
}

fn make_record(ext: &str, phase: &str, iterations: usize, elapsed: Duration, success: bool, error: Option<String>) -> LifecycleRecord {
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let per_call_us = if iterations > 0 {
        (elapsed.as_secs_f64() * 1_000_000.0) / iterations as f64
    } else {
        0.0
    };
    LifecycleRecord {
        schema: "pi.ext.lifecycle_perf.v1".to_string(),
        extension: ext.to_string(),
        phase: phase.to_string(),
        iterations,
        elapsed_ms,
        per_call_us,
        success,
        error,
    }
}

// ─── Phase Runners ──────────────────────────────────────────────────────────

/// Phase 1: Cold load — create manager + runtime + load from scratch.
fn phase_cold_load(ext_name: &str, spec: &JsExtensionLoadSpec, harness: &common::TestHarness) -> LifecycleRecord {
    let start = Instant::now();
    let cwd = harness.temp_dir().to_path_buf();

    let manager = ExtensionManager::new();
    let tools = Arc::new(ToolRegistry::new(&[], &cwd, None));
    let js_config = PiJsRuntimeConfig {
        cwd: cwd.display().to_string(),
        ..Default::default()
    };

    let result: Result<(), String> = (|| {
        let runtime = common::run_async({
            let manager = manager.clone();
            let tools = Arc::clone(&tools);
            async move {
                JsExtensionRuntimeHandle::start(js_config, tools, manager)
                    .await
                    .map_err(|e| e.to_string())
            }
        })?;
        manager.set_js_runtime(runtime);

        common::run_async({
            let manager = manager.clone();
            let spec = spec.clone();
            async move {
                manager
                    .load_js_extensions(vec![spec])
                    .await
                    .map_err(|e| e.to_string())
            }
        })?;

        Ok(())
    })();

    let elapsed = start.elapsed();
    shutdown(&manager);

    match result {
        Ok(()) => make_record(ext_name, "cold_load", 1, elapsed, true, None),
        Err(e) => make_record(ext_name, "cold_load", 1, elapsed, false, Some(e)),
    }
}

/// Phase 2: Event hook dispatch — fire `before_agent_start` N times.
fn phase_event_dispatch(ext_name: &str, manager: &ExtensionManager, iterations: usize) -> LifecycleRecord {
    let start = Instant::now();
    let mut successes = 0usize;
    let mut last_err = None;

    for _ in 0..iterations {
        let result = common::run_async({
            let manager = manager.clone();
            async move {
                manager
                    .dispatch_event_with_response(
                        ExtensionEventName::BeforeAgentStart,
                        Some(json!({"systemPrompt": "lifecycle test"})),
                        NORMAL_TIMEOUT_MS,
                    )
                    .await
            }
        });
        match result {
            Ok(_) => successes += 1,
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    let elapsed = start.elapsed();
    let success = successes == iterations;
    make_record(ext_name, "event_dispatch", iterations, elapsed, success, last_err)
}

/// Phase 3: Tool call — execute the extension's tool N times (if it has one).
fn phase_tool_call(ext_name: &str, manager: &ExtensionManager, iterations: usize) -> LifecycleRecord {
    let runtime = match manager.js_runtime() {
        Some(rt) => rt,
        None => {
            return make_record(
                ext_name,
                "tool_call",
                0,
                Duration::ZERO,
                false,
                Some("no JS runtime available".to_string()),
            );
        }
    };

    // Tool name matches extension name for hello/pirate; diff has "diff" command not tool.
    // Try the extension name as tool name first.
    let tool_name = ext_name.to_string();
    let ctx = json!({ "hasUI": false, "cwd": project_root().display().to_string() });

    let start = Instant::now();
    let mut successes = 0usize;
    let mut last_err = None;

    for i in 0..iterations {
        let result = futures::executor::block_on(runtime.execute_tool(
            tool_name.clone(),
            format!("lifecycle-{i}"),
            json!({"name": "test"}),
            ctx.clone(),
            NORMAL_TIMEOUT_MS,
        ));
        match result {
            Ok(_) => successes += 1,
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    let elapsed = start.elapsed();
    // Some extensions (pirate, diff) may not have a tool named after them — that's OK.
    make_record(ext_name, "tool_call", iterations, elapsed, successes > 0, last_err)
}

/// Phase 4: Budget fallback — dispatch with a very short timeout.
fn phase_budget_fallback(ext_name: &str, manager: &ExtensionManager) -> LifecycleRecord {
    let start = Instant::now();

    let result = common::run_async({
        let manager = manager.clone();
        async move {
            manager
                .dispatch_event_with_response(
                    ExtensionEventName::BeforeAgentStart,
                    Some(json!({"systemPrompt": "budget fallback test"})),
                    SHORT_TIMEOUT_MS,
                )
                .await
        }
    });

    let elapsed = start.elapsed();
    // Budget fallback should not hang — either succeed quickly or return error/None.
    let success = elapsed < Duration::from_secs(3);
    let error = if !success {
        Some(format!("budget fallback took {elapsed:?}, expected <3s"))
    } else {
        result.err().map(|e| e.to_string())
    };
    make_record(ext_name, "budget_fallback", 1, elapsed, success, error)
}

/// Phase 5: Shutdown — measure time to shut down the manager.
fn phase_shutdown(ext_name: &str, manager: &ExtensionManager) -> LifecycleRecord {
    let start = Instant::now();
    let ok = common::run_async({
        let manager = manager.clone();
        async move { manager.shutdown(Duration::from_secs(2)).await }
    });
    let elapsed = start.elapsed();
    let success = ok && elapsed < Duration::from_secs(2);
    let error = if !ok {
        Some("shutdown returned false".to_string())
    } else if elapsed >= Duration::from_secs(2) {
        Some(format!("shutdown took {elapsed:?}"))
    } else {
        None
    };
    make_record(ext_name, "shutdown", 1, elapsed, success, error)
}

/// Collect per-extension diagnostics.
fn collect_diagnostics(ext_name: &str, manager: &ExtensionManager) -> DiagnosticsRecord {
    let risk_ledger = manager.runtime_risk_ledger_artifact();
    let telemetry = manager.runtime_hostcall_telemetry_artifact();
    let quota = manager.quota_state(ext_name).map(|(budget, calls, last, total)| QuotaSnapshot {
        budget_remaining_ns: budget,
        call_count: calls,
        last_call_ns: last,
        total_elapsed_ns: total,
    });

    DiagnosticsRecord {
        schema: "pi.ext.lifecycle_diagnostics.v1".to_string(),
        extension: ext_name.to_string(),
        risk_ledger_entries: risk_ledger.entries.len(),
        hostcall_telemetry_entries: telemetry.entries.len(),
        quota_state: quota,
        snapshot_version: manager.snapshot_version(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// Full lifecycle test: load → event → tool → budget-fallback → diagnostics → shutdown
/// for each extension in the corpus.
#[test]
#[allow(clippy::too_many_lines)]
fn e2e_full_lifecycle_all_extensions() {
    let mut all_records: Vec<Value> = Vec::new();
    let mut per_ext_summary: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for ext_name in LIFECYCLE_EXTENSIONS {
        let entry = artifact_entry(ext_name);
        if !entry.exists() {
            eprintln!("[skip] {ext_name}: artifact not found at {}", entry.display());
            continue;
        }

        let spec = JsExtensionLoadSpec::from_entry_path(&entry).expect("load spec");
        let harness = common::TestHarness::new(format!("lifecycle_{ext_name}"));

        // Phase 1: Cold load
        eprintln!("[lifecycle] {ext_name}: cold_load");
        let cold = phase_cold_load(ext_name, &spec, &harness);
        all_records.push(serde_json::to_value(&cold).unwrap());
        per_ext_summary
            .entry(ext_name.to_string())
            .or_default()
            .push(format!("cold_load: {:.2}ms ok={}", cold.elapsed_ms, cold.success));

        // Create a persistent manager for remaining phases
        let manager = setup_manager_with_extension(&harness, &spec);

        // Phase 2: Event dispatch
        eprintln!("[lifecycle] {ext_name}: event_dispatch ({EVENT_ITERATIONS} iters)");
        let events = phase_event_dispatch(ext_name, &manager, EVENT_ITERATIONS);
        all_records.push(serde_json::to_value(&events).unwrap());
        per_ext_summary
            .entry(ext_name.to_string())
            .or_default()
            .push(format!(
                "event_dispatch: {:.1}us/call ok={}",
                events.per_call_us, events.success
            ));

        // Phase 3: Tool call
        eprintln!("[lifecycle] {ext_name}: tool_call ({TOOL_ITERATIONS} iters)");
        let tools = phase_tool_call(ext_name, &manager, TOOL_ITERATIONS);
        all_records.push(serde_json::to_value(&tools).unwrap());
        per_ext_summary
            .entry(ext_name.to_string())
            .or_default()
            .push(format!(
                "tool_call: {:.1}us/call ok={}",
                tools.per_call_us, tools.success
            ));

        // Phase 4: Budget fallback
        eprintln!("[lifecycle] {ext_name}: budget_fallback");
        let fallback = phase_budget_fallback(ext_name, &manager);
        all_records.push(serde_json::to_value(&fallback).unwrap());
        per_ext_summary
            .entry(ext_name.to_string())
            .or_default()
            .push(format!(
                "budget_fallback: {:.2}ms ok={}",
                fallback.elapsed_ms, fallback.success
            ));

        // Collect diagnostics before shutdown
        eprintln!("[lifecycle] {ext_name}: diagnostics");
        let diag = collect_diagnostics(ext_name, &manager);
        all_records.push(serde_json::to_value(&diag).unwrap());
        per_ext_summary
            .entry(ext_name.to_string())
            .or_default()
            .push(format!(
                "diag: risk={} telemetry={} snap={}",
                diag.risk_ledger_entries, diag.hostcall_telemetry_entries, diag.snapshot_version
            ));

        // Phase 5: Shutdown
        eprintln!("[lifecycle] {ext_name}: shutdown");
        let shut = phase_shutdown(ext_name, &manager);
        all_records.push(serde_json::to_value(&shut).unwrap());
        per_ext_summary
            .entry(ext_name.to_string())
            .or_default()
            .push(format!(
                "shutdown: {:.2}ms ok={}",
                shut.elapsed_ms, shut.success
            ));
    }

    // Write JSONL output
    let output_path = project_root().join("target/perf/e2e_lifecycle.jsonl");
    write_jsonl(&all_records, &output_path);
    eprintln!(
        "\n[output] {} records written to {}",
        all_records.len(),
        output_path.display()
    );

    // Print summary
    eprintln!("\n=== E2E Extension Lifecycle Summary ===");
    for (ext, phases) in &per_ext_summary {
        eprintln!("  {ext}:");
        for phase in phases {
            eprintln!("    {phase}");
        }
    }

    // Assertions
    assert!(
        per_ext_summary.len() >= 3,
        "expected >=3 extensions, got {}",
        per_ext_summary.len()
    );

    // All cold loads must succeed
    let cold_loads: Vec<&Value> = all_records
        .iter()
        .filter(|r| r.get("phase").and_then(Value::as_str) == Some("cold_load"))
        .collect();
    for rec in &cold_loads {
        assert_eq!(
            rec.get("success").and_then(Value::as_bool),
            Some(true),
            "cold_load failed for {}",
            rec.get("extension").and_then(Value::as_str).unwrap_or("?")
        );
    }

    // All shutdowns must succeed
    let shutdowns: Vec<&Value> = all_records
        .iter()
        .filter(|r| r.get("phase").and_then(Value::as_str) == Some("shutdown"))
        .collect();
    for rec in &shutdowns {
        assert_eq!(
            rec.get("success").and_then(Value::as_bool),
            Some(true),
            "shutdown failed for {}",
            rec.get("extension").and_then(Value::as_str).unwrap_or("?")
        );
    }

    // Budget fallback must not hang (success = returned within 3s)
    let fallbacks: Vec<&Value> = all_records
        .iter()
        .filter(|r| r.get("phase").and_then(Value::as_str) == Some("budget_fallback"))
        .collect();
    for rec in &fallbacks {
        assert_eq!(
            rec.get("success").and_then(Value::as_bool),
            Some(true),
            "budget_fallback hung for {}",
            rec.get("extension").and_then(Value::as_str).unwrap_or("?")
        );
    }

    // All records must have schema field
    for record in &all_records {
        assert!(
            record.get("schema").and_then(Value::as_str).is_some(),
            "record missing schema: {record}"
        );
    }
}

/// Verify that event dispatch latency is reasonable (< 100ms per call on average).
#[test]
fn event_dispatch_latency_within_budget() {
    for ext_name in LIFECYCLE_EXTENSIONS {
        let entry = artifact_entry(ext_name);
        if !entry.exists() {
            continue;
        }
        let spec = JsExtensionLoadSpec::from_entry_path(&entry).expect("load spec");
        let harness = common::TestHarness::new(format!("latency_event_{ext_name}"));
        let manager = setup_manager_with_extension(&harness, &spec);

        let record = phase_event_dispatch(ext_name, &manager, 20);
        eprintln!(
            "[latency] {ext_name} event_dispatch: {:.1}us/call",
            record.per_call_us
        );

        // Average should be under 100ms per call for well-behaved extensions.
        assert!(
            record.per_call_us < 100_000.0,
            "{ext_name}: event dispatch avg {:.1}us exceeds 100ms budget",
            record.per_call_us
        );

        shutdown(&manager);
    }
}

/// Verify cold load completes within 5 seconds for each extension.
#[test]
fn cold_load_within_budget() {
    for ext_name in LIFECYCLE_EXTENSIONS {
        let entry = artifact_entry(ext_name);
        if !entry.exists() {
            continue;
        }
        let spec = JsExtensionLoadSpec::from_entry_path(&entry).expect("load spec");
        let harness = common::TestHarness::new(format!("cold_load_{ext_name}"));

        let record = phase_cold_load(ext_name, &spec, &harness);
        eprintln!(
            "[cold_load] {ext_name}: {:.2}ms ok={}",
            record.elapsed_ms, record.success
        );

        assert!(record.success, "{ext_name}: cold load failed");
        assert!(
            record.elapsed_ms < 5000.0,
            "{ext_name}: cold load took {:.2}ms, exceeds 5s budget",
            record.elapsed_ms
        );
    }
}

/// Verify per-extension diagnostics are collected and contain expected fields.
#[test]
fn per_extension_diagnostics_collected() {
    for ext_name in LIFECYCLE_EXTENSIONS {
        let entry = artifact_entry(ext_name);
        if !entry.exists() {
            continue;
        }
        let spec = JsExtensionLoadSpec::from_entry_path(&entry).expect("load spec");
        let harness = common::TestHarness::new(format!("diag_{ext_name}"));
        let manager = setup_manager_with_extension(&harness, &spec);

        // Fire some events to generate telemetry
        for _ in 0..5 {
            let _ = common::run_async({
                let manager = manager.clone();
                async move {
                    manager
                        .dispatch_event(
                            ExtensionEventName::AgentStart,
                            Some(json!({"systemPrompt": "diag test", "model": "test"})),
                        )
                        .await
                }
            });
        }

        let diag = collect_diagnostics(ext_name, &manager);
        eprintln!(
            "[diag] {ext_name}: risk={} telemetry={} snap={}",
            diag.risk_ledger_entries, diag.hostcall_telemetry_entries, diag.snapshot_version
        );

        // Snapshot version should be > 0 after loading an extension
        assert!(
            diag.snapshot_version > 0,
            "{ext_name}: snapshot_version should be > 0"
        );

        // Serialization should produce valid JSON
        let json_val = serde_json::to_value(&diag).expect("serialize diagnostics");
        assert_eq!(
            json_val.get("schema").and_then(Value::as_str),
            Some("pi.ext.lifecycle_diagnostics.v1")
        );
        assert_eq!(
            json_val.get("extension").and_then(Value::as_str),
            Some(*ext_name)
        );

        shutdown(&manager);
    }
}

/// Rapid lifecycle cycling: create → load → dispatch → shutdown, repeated.
#[test]
fn rapid_lifecycle_cycling() {
    let cycles = 3;
    for ext_name in LIFECYCLE_EXTENSIONS {
        let entry = artifact_entry(ext_name);
        if !entry.exists() {
            continue;
        }
        let spec = JsExtensionLoadSpec::from_entry_path(&entry).expect("load spec");

        let start = Instant::now();
        for cycle in 0..cycles {
            let harness = common::TestHarness::new(format!("rapid_{ext_name}_{cycle}"));
            let manager = setup_manager_with_extension(&harness, &spec);

            // Quick dispatch
            let _ = common::run_async({
                let manager = manager.clone();
                async move {
                    manager
                        .dispatch_event_with_response(
                            ExtensionEventName::BeforeAgentStart,
                            Some(json!({"systemPrompt": "rapid cycle"})),
                            NORMAL_TIMEOUT_MS,
                        )
                        .await
                }
            });

            shutdown(&manager);
        }
        let total = start.elapsed();
        eprintln!(
            "[rapid] {ext_name}: {cycles} cycles in {total:?} ({:.2}ms/cycle)",
            total.as_secs_f64() * 1000.0 / cycles as f64
        );

        // Should not take more than 30s for 3 cycles
        assert!(
            total < Duration::from_secs(30),
            "{ext_name}: rapid cycling took {total:?}"
        );
    }
}

/// Verify that all lifecycle phases are represented in JSONL output.
#[test]
fn jsonl_output_schema_completeness() {
    let mut records: Vec<Value> = Vec::new();

    for ext_name in LIFECYCLE_EXTENSIONS {
        let entry = artifact_entry(ext_name);
        if !entry.exists() {
            continue;
        }
        let spec = JsExtensionLoadSpec::from_entry_path(&entry).expect("load spec");
        let harness = common::TestHarness::new(format!("schema_{ext_name}"));

        let cold = phase_cold_load(ext_name, &spec, &harness);
        records.push(serde_json::to_value(&cold).unwrap());

        let manager = setup_manager_with_extension(&harness, &spec);
        let events = phase_event_dispatch(ext_name, &manager, 5);
        records.push(serde_json::to_value(&events).unwrap());

        let tools = phase_tool_call(ext_name, &manager, 5);
        records.push(serde_json::to_value(&tools).unwrap());

        let fallback = phase_budget_fallback(ext_name, &manager);
        records.push(serde_json::to_value(&fallback).unwrap());

        let diag = collect_diagnostics(ext_name, &manager);
        records.push(serde_json::to_value(&diag).unwrap());

        let shut = phase_shutdown(ext_name, &manager);
        records.push(serde_json::to_value(&shut).unwrap());
    }

    // Verify all phases are present
    let phases: std::collections::HashSet<&str> = records
        .iter()
        .filter_map(|r| r.get("phase").and_then(Value::as_str))
        .collect();
    for expected in &["cold_load", "event_dispatch", "tool_call", "budget_fallback", "shutdown"] {
        assert!(phases.contains(expected), "missing phase: {expected}");
    }

    // Verify diagnostics records are present (different schema)
    let diag_count = records
        .iter()
        .filter(|r| {
            r.get("schema").and_then(Value::as_str) == Some("pi.ext.lifecycle_diagnostics.v1")
        })
        .count();
    assert!(
        diag_count >= 3,
        "expected >=3 diagnostics records, got {diag_count}"
    );

    // Verify all extensions are represented
    let extensions: std::collections::HashSet<&str> = records
        .iter()
        .filter_map(|r| r.get("extension").and_then(Value::as_str))
        .collect();
    assert!(
        extensions.len() >= 3,
        "expected >=3 extensions in output, got {}: {extensions:?}",
        extensions.len()
    );

    // All lifecycle records must have required fields
    for record in &records {
        assert!(
            record.get("schema").and_then(Value::as_str).is_some(),
            "record missing schema"
        );
        assert!(
            record.get("extension").and_then(Value::as_str).is_some(),
            "record missing extension"
        );
    }
}
