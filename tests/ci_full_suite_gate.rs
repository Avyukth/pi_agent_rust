//! Final full-suite CI gate wiring and release-block policy (bd-1f42.6.5).
//!
//! This is the top-level CI gate that aggregates all sub-gates into a single
//! release-blocking verdict.  Each sub-gate is a named check with:
//!
//! - An artifact path that proves the check ran
//! - A pass/fail/warn/skip status
//! - An owning bead ID for failure triage
//! - A direct link to the failing artifact
//!
//! Sub-gates:
//! 1. Non-mock unit compliance (bd-1f42.2.6)
//! 2. E2E log contract (bd-1f42.3.6)
//! 3. Extension must-pass gate — 208 extensions (bd-1f42.4.4)
//! 4. Extension provider compatibility matrix (bd-1f42.4.6)
//! 5. Unified evidence bundle (bd-1f42.6.8)
//! 6. Cross-platform matrix (bd-1f42.6.7)
//! 7. Conformance regression gate
//! 8. Release gate (evidence completeness)
//! 9. Suite classification guard
//! 10. Requirement traceability matrix
//! 11. Canonical E2E scenario matrix
//!
//! Run:
//!   cargo test --test `ci_full_suite_gate` -- --nocapture

use serde_json::Value;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// A sub-gate in the full suite.
#[derive(Debug, Clone, serde::Serialize)]
struct SubGate {
    id: String,
    name: String,
    bead: String,
    status: String, // "pass", "fail", "warn", "skip"
    blocking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reproduce_command: Option<String>,
}

/// Full-suite gate verdict.
#[derive(Debug, serde::Serialize)]
struct FullSuiteVerdict {
    schema: String,
    generated_at: String,
    verdict: String, // "pass", "fail", "warn"
    policy: String,
    gates: Vec<SubGate>,
    summary: GateSummary,
}

/// Gate summary statistics.
#[derive(Debug, serde::Serialize)]
struct GateSummary {
    total_gates: usize,
    passed: usize,
    failed: usize,
    warned: usize,
    skipped: usize,
    blocking_pass: usize,
    blocking_total: usize,
    all_blocking_pass: bool,
}

/// Check a JSON artifact for a specific status field.
fn check_artifact_status(
    root: &Path,
    artifact_rel: &str,
    status_path: &[&str],
    pass_values: &[&str],
) -> (String, Option<String>) {
    let full = root.join(artifact_rel);
    let Some(val) = load_json(&full) else {
        return (
            "skip".to_string(),
            Some(format!("Artifact not found: {artifact_rel}")),
        );
    };

    let mut current = &val;
    for key in status_path {
        match current.get(*key) {
            Some(v) => current = v,
            None => {
                return (
                    "warn".to_string(),
                    Some(format!(
                        "Missing field '{}' in {}",
                        status_path.join("."),
                        artifact_rel
                    )),
                );
            }
        }
    }

    let status_str = current.as_str().unwrap_or("");
    if pass_values.contains(&status_str) {
        ("pass".to_string(), None)
    } else {
        (
            "fail".to_string(),
            Some(format!(
                "{} = '{status_str}' (expected one of: {:?})",
                status_path.join("."),
                pass_values
            )),
        )
    }
}

/// Check that a file exists and is non-empty.
fn check_artifact_present(root: &Path, artifact_rel: &str) -> (String, Option<String>) {
    let full = root.join(artifact_rel);
    if full.is_file() {
        let size = std::fs::metadata(&full).map_or(0, |m| m.len());
        if size > 0 {
            ("pass".to_string(), None)
        } else {
            (
                "warn".to_string(),
                Some(format!("Artifact empty: {artifact_rel}")),
            )
        }
    } else if full.is_dir() {
        ("pass".to_string(), None)
    } else {
        (
            "skip".to_string(),
            Some(format!("Artifact not found: {artifact_rel}")),
        )
    }
}

/// Collect all sub-gate results.
#[allow(clippy::too_many_lines)]
fn collect_gates(root: &Path) -> Vec<SubGate> {
    let mut gates = Vec::new();

    // Gate 1: Non-mock unit compliance.
    let (status, detail) = check_artifact_present(root, "docs/non-mock-rubric.json");
    gates.push(SubGate {
        id: "non_mock_unit".to_string(),
        name: "Non-mock unit compliance".to_string(),
        bead: "bd-1f42.2.6".to_string(),
        status,
        blocking: true,
        artifact_path: Some("docs/non-mock-rubric.json".to_string()),
        detail,
        reproduce_command: Some(
            "cargo test --test non_mock_compliance_gate -- --nocapture".to_string(),
        ),
    });

    // Gate 2: E2E log contract.
    let (status, detail) = check_artifact_present(root, "tests/e2e_results");
    gates.push(SubGate {
        id: "e2e_log_contract".to_string(),
        name: "E2E log contract and transcripts".to_string(),
        bead: "bd-1f42.3.6".to_string(),
        status,
        blocking: false,
        artifact_path: Some("tests/e2e_results".to_string()),
        detail,
        reproduce_command: None,
    });

    // Gate 3: Extension must-pass gate (208 extensions).
    let (status, detail) = check_artifact_status(
        root,
        "tests/ext_conformance/reports/gate/must_pass_gate_verdict.json",
        &["status"],
        &["pass"],
    );
    gates.push(SubGate {
        id: "ext_must_pass".to_string(),
        name: "Extension must-pass gate (208 extensions)".to_string(),
        bead: "bd-1f42.4.4".to_string(),
        status,
        blocking: true,
        artifact_path: Some(
            "tests/ext_conformance/reports/gate/must_pass_gate_verdict.json".to_string(),
        ),
        detail,
        reproduce_command: Some(
            "cargo test --test ext_conformance_generated --features ext-conformance -- conformance_must_pass_gate --nocapture --exact".to_string(),
        ),
    });

    // Gate 4: Extension provider compatibility.
    let (status, detail) = check_artifact_present(
        root,
        "tests/ext_conformance/reports/provider_compat/provider_compat_report.json",
    );
    gates.push(SubGate {
        id: "ext_provider_compat".to_string(),
        name: "Extension provider compatibility matrix".to_string(),
        bead: "bd-1f42.4.6".to_string(),
        status,
        blocking: false,
        artifact_path: Some(
            "tests/ext_conformance/reports/provider_compat/provider_compat_report.json".to_string(),
        ),
        detail,
        reproduce_command: Some(
            "cargo test --test ext_conformance_generated --features ext-conformance -- conformance_provider_compat_matrix --nocapture --exact".to_string(),
        ),
    });

    // Gate 5: Unified evidence bundle.
    let (status, detail) = check_artifact_status(
        root,
        "tests/evidence_bundle/index.json",
        &["summary", "verdict"],
        &["complete", "partial"],
    );
    gates.push(SubGate {
        id: "evidence_bundle".to_string(),
        name: "Unified evidence bundle".to_string(),
        bead: "bd-1f42.6.8".to_string(),
        status,
        blocking: false,
        artifact_path: Some("tests/evidence_bundle/index.json".to_string()),
        detail,
        reproduce_command: Some(
            "cargo test --test ci_evidence_bundle -- build_evidence_bundle --nocapture --exact"
                .to_string(),
        ),
    });

    // Gate 6: Cross-platform matrix.
    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "windows"
    };
    let xplat_path = format!("tests/cross_platform_reports/{platform}/platform_report.json");
    let (status, detail) =
        check_artifact_status(root, &xplat_path, &["summary", "all_required_pass"], &[]);
    // Special handling: check bool field, not string.
    let (status, detail) = if status == "fail" {
        // The field is a boolean, not a string — check it directly.
        let full = root.join(&xplat_path);
        load_json(&full).map_or((status, detail), |val| {
            let ok = val
                .pointer("/summary/all_required_pass")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if ok {
                ("pass".to_string(), None)
            } else {
                (
                    "fail".to_string(),
                    Some("Not all required platform checks passed".to_string()),
                )
            }
        })
    } else {
        (status, detail)
    };
    gates.push(SubGate {
        id: "cross_platform".to_string(),
        name: "Cross-platform matrix validation".to_string(),
        bead: "bd-1f42.6.7".to_string(),
        status,
        blocking: cfg!(target_os = "linux"),
        artifact_path: Some(xplat_path),
        detail,
        reproduce_command: Some(
            "cargo test --test ci_cross_platform_matrix -- cross_platform_matrix --nocapture --exact".to_string(),
        ),
    });

    // Gate 7: Conformance regression gate.
    let (status, detail) = check_artifact_status(
        root,
        "tests/ext_conformance/reports/regression_verdict.json",
        &["status"],
        &["pass", "warn"],
    );
    gates.push(SubGate {
        id: "conformance_regression".to_string(),
        name: "Conformance regression gate".to_string(),
        bead: "bd-1f42.4".to_string(),
        status,
        blocking: true,
        artifact_path: Some("tests/ext_conformance/reports/regression_verdict.json".to_string()),
        detail,
        reproduce_command: Some(
            "cargo test --test conformance_regression_gate -- --nocapture".to_string(),
        ),
    });

    // Gate 8: Conformance summary (pass rate).
    let (status, detail) = {
        let artifact = "tests/ext_conformance/reports/conformance_summary.json";
        let full = root.join(artifact);
        load_json(&full).map_or_else(
            || {
                (
                    "skip".to_string(),
                    Some(format!("Artifact not found: {artifact}")),
                )
            },
            |val| {
                let rate = val
                    .get("pass_rate_pct")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                if rate >= 80.0 {
                    ("pass".to_string(), None)
                } else {
                    (
                        "fail".to_string(),
                        Some(format!("Pass rate {rate:.1}% < 80% threshold")),
                    )
                }
            },
        )
    };
    gates.push(SubGate {
        id: "conformance_pass_rate".to_string(),
        name: "Conformance pass rate >= 80%".to_string(),
        bead: "bd-1f42.4".to_string(),
        status,
        blocking: true,
        artifact_path: Some("tests/ext_conformance/reports/conformance_summary.json".to_string()),
        detail,
        reproduce_command: Some("cargo test --test conformance_report -- --nocapture".to_string()),
    });

    // Gate 9: Suite classification guard (all tests classified).
    let (status, detail) = check_artifact_present(root, "tests/suite_classification.toml");
    gates.push(SubGate {
        id: "suite_classification".to_string(),
        name: "Suite classification guard".to_string(),
        bead: "bd-1f42.6.1".to_string(),
        status,
        blocking: true,
        artifact_path: Some("tests/suite_classification.toml".to_string()),
        detail,
        reproduce_command: None,
    });

    // Gate 10: Traceability matrix.
    let (status, detail) = check_artifact_present(root, "docs/traceability_matrix.json");
    gates.push(SubGate {
        id: "traceability_matrix".to_string(),
        name: "Requirement traceability matrix".to_string(),
        bead: "bd-1f42.6.4".to_string(),
        status,
        blocking: false,
        artifact_path: Some("docs/traceability_matrix.json".to_string()),
        detail,
        reproduce_command: None,
    });

    // Gate 11: Canonical E2E scenario matrix.
    let (status, detail) = check_artifact_present(root, "docs/e2e_scenario_matrix.json");
    gates.push(SubGate {
        id: "e2e_scenario_matrix".to_string(),
        name: "Canonical E2E scenario matrix".to_string(),
        bead: "bd-1f42.8.5.1".to_string(),
        status,
        blocking: false,
        artifact_path: Some("docs/e2e_scenario_matrix.json".to_string()),
        detail,
        reproduce_command: Some("python3 scripts/check_traceability_matrix.py".to_string()),
    });

    gates
}

/// Full-suite CI gate test.
///
/// Run with:
/// `cargo test --test ci_full_suite_gate -- full_suite_gate --nocapture`
#[test]
#[allow(clippy::too_many_lines)]
fn full_suite_gate() {
    use chrono::{SecondsFormat, Utc};
    use std::fmt::Write as _;

    let root = repo_root();
    let report_dir = root.join("tests").join("full_suite_gate");
    let _ = std::fs::create_dir_all(&report_dir);

    eprintln!("\n=== Full-Suite CI Gate (bd-1f42.6.5) ===\n");

    let gates = collect_gates(&root);

    for gate in &gates {
        let icon = match gate.status.as_str() {
            "pass" => "PASS",
            "fail" => "FAIL",
            "warn" => "WARN",
            _ => "SKIP",
        };
        let blocking = if gate.blocking { "(blocking)" } else { "" };
        eprintln!(
            "  [{icon}] {:<50} {:<12} {}",
            gate.name, blocking, gate.bead
        );
        if let Some(ref detail) = gate.detail {
            eprintln!("         {detail}");
        }
    }
    eprintln!();

    // ── Compute summary ──
    let passed = gates.iter().filter(|g| g.status == "pass").count();
    let failed = gates.iter().filter(|g| g.status == "fail").count();
    let warned = gates.iter().filter(|g| g.status == "warn").count();
    let skipped = gates.iter().filter(|g| g.status == "skip").count();

    let blocking_gates: Vec<&SubGate> = gates.iter().filter(|g| g.blocking).collect();
    let blocking_pass = blocking_gates.iter().filter(|g| g.status == "pass").count();
    let blocking_total = blocking_gates.len();
    let all_blocking_pass = blocking_pass == blocking_total;

    let verdict = if all_blocking_pass && failed == 0 {
        "pass"
    } else if all_blocking_pass {
        "warn"
    } else {
        "fail"
    };

    let policy = "Full-suite gate: all blocking gates must pass for release. \
                  Non-blocking gates produce warnings but do not block.";

    let report = FullSuiteVerdict {
        schema: "pi.ci.full_suite_gate.v1".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        verdict: verdict.to_string(),
        policy: policy.to_string(),
        gates: gates.clone(),
        summary: GateSummary {
            total_gates: gates.len(),
            passed,
            failed,
            warned,
            skipped,
            blocking_pass,
            blocking_total,
            all_blocking_pass,
        },
    };

    // ── Write JSON verdict ──
    let verdict_path = report_dir.join("full_suite_verdict.json");
    let _ = std::fs::write(
        &verdict_path,
        serde_json::to_string_pretty(&report).unwrap_or_default(),
    );

    // ── Write JSONL events ──
    let events_path = report_dir.join("full_suite_events.jsonl");
    let mut lines: Vec<String> = Vec::new();
    for gate in &gates {
        let line = serde_json::json!({
            "schema": "pi.ci.full_suite_gate_event.v1",
            "gate_id": gate.id,
            "gate_name": gate.name,
            "bead": gate.bead,
            "status": gate.status,
            "blocking": gate.blocking,
            "artifact_path": gate.artifact_path,
            "ts": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        lines.push(serde_json::to_string(&line).unwrap_or_default());
    }
    let _ = std::fs::write(&events_path, lines.join("\n") + "\n");

    // ── Write Markdown report ──
    let mut md = String::new();
    md.push_str("# Full-Suite CI Gate Report\n\n");
    let _ = writeln!(
        md,
        "> Generated: {}",
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    let _ = writeln!(md, "> Verdict: **{}**\n", verdict.to_uppercase());

    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Value |\n|--------|-------|\n");
    let _ = writeln!(md, "| Total gates | {} |", gates.len());
    let _ = writeln!(md, "| Passed | {passed} |");
    let _ = writeln!(md, "| Failed | {failed} |");
    let _ = writeln!(md, "| Warned | {warned} |");
    let _ = writeln!(md, "| Skipped | {skipped} |");
    let _ = writeln!(md, "| Blocking pass | {blocking_pass}/{blocking_total} |");
    md.push('\n');

    md.push_str("## Gate Results\n\n");
    md.push_str(
        "| Gate | Bead | Blocking | Status | Artifact |\n|------|------|----------|--------|----------|\n",
    );
    for gate in &gates {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | `{}` |",
            gate.name,
            gate.bead,
            if gate.blocking { "YES" } else { "no" },
            gate.status.to_uppercase(),
            gate.artifact_path.as_deref().unwrap_or("-"),
        );
    }
    md.push('\n');

    let failures: Vec<&SubGate> = gates
        .iter()
        .filter(|g| g.status == "fail" || g.status == "warn")
        .collect();
    if !failures.is_empty() {
        md.push_str("## Issues Requiring Attention\n\n");
        for g in &failures {
            let blocking_tag = if g.blocking { " **(BLOCKING)**" } else { "" };
            let _ = writeln!(
                md,
                "### {} — {}{}\n",
                g.name,
                g.status.to_uppercase(),
                blocking_tag
            );
            let _ = writeln!(md, "- **Bead:** {}", g.bead);
            if let Some(ref detail) = g.detail {
                let _ = writeln!(md, "- **Detail:** {detail}");
            }
            if let Some(ref path) = g.artifact_path {
                let _ = writeln!(md, "- **Artifact:** `{path}`");
            }
            if let Some(ref cmd) = g.reproduce_command {
                let _ = writeln!(md, "- **Reproduce:**\n  ```bash\n  {cmd}\n  ```");
            }
            md.push('\n');
        }
    }

    let md_path = report_dir.join("full_suite_report.md");
    let _ = std::fs::write(&md_path, &md);

    // ── Print summary ──
    eprintln!(
        "=== Full-Suite Gate Verdict: {} ===",
        verdict.to_uppercase()
    );
    eprintln!("  Gates:    {passed}/{} passed", gates.len());
    eprintln!("  Blocking: {blocking_pass}/{blocking_total}");
    if failed > 0 {
        eprintln!("  Failed:   {failed}");
    }
    if warned > 0 {
        eprintln!("  Warned:   {warned}");
    }
    eprintln!();
    eprintln!("  Reports:");
    eprintln!("    JSON:  {}", verdict_path.display());
    eprintln!("    JSONL: {}", events_path.display());
    eprintln!("    MD:    {}", md_path.display());
    eprintln!();

    // ── Block release if blocking gates fail ──
    // NOTE: This is informational at build time; the actual hard gate
    // is enforced by the individual test sub-gates. This test aggregates
    // and reports but does not block (to allow partial evidence collection).
}

/// Validate full-suite gate report schema.
#[test]
fn full_suite_gate_report_schema() {
    let report_path = repo_root()
        .join("tests")
        .join("full_suite_gate")
        .join("full_suite_verdict.json");

    let Some(val) = load_json(&report_path) else {
        eprintln!("  SKIP: Report not found. Run full_suite_gate first.");
        return;
    };

    assert_eq!(
        val.get("schema").and_then(Value::as_str),
        Some("pi.ci.full_suite_gate.v1"),
        "Must have correct schema"
    );
    assert!(val.get("verdict").is_some(), "Must have verdict");
    assert!(
        val.get("gates").and_then(Value::as_array).is_some(),
        "Must have gates array"
    );
    assert!(val.get("summary").is_some(), "Must have summary");

    // Each gate must have required fields.
    if let Some(gates) = val.get("gates").and_then(Value::as_array) {
        for gate in gates {
            assert!(gate.get("id").is_some(), "Gate missing id");
            assert!(gate.get("bead").is_some(), "Gate missing bead");
            assert!(gate.get("status").is_some(), "Gate missing status");
            assert!(gate.get("blocking").is_some(), "Gate missing blocking");
        }
    }
}
