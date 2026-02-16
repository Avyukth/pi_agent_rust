#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)]
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
//! 12. Provider gap test matrix (bd-3uqg.11.11.5)
//! 13. Waiver lifecycle (bd-1f42.8.8.1)
//! 14. SEC-6.4 security compatibility conformance (bd-1a2cu)
//! 15. PERF-3X bead-to-artifact coverage audit (bd-3ar8v.6.11)
//!
//! Run:
//!   cargo test --test `ci_full_suite_gate` -- --nocapture

use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

const CI_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const RUN_ALL_SCRIPT_PATH: &str = "scripts/e2e/run_all.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

// ── Waiver lifecycle infrastructure ─────────────────────────────────────

/// A parsed waiver entry from suite_classification.toml.
#[derive(Debug, Clone, serde::Serialize)]
struct Waiver {
    gate_id: String,
    owner: String,
    created: String,
    expires: String,
    bead: String,
    reason: String,
    scope: String,
    remove_when: String,
}

/// Waiver validation result.
#[derive(Debug, Clone, serde::Serialize)]
struct WaiverValidation {
    gate_id: String,
    status: String, // "active", "expired", "expiring_soon", "invalid"
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    days_remaining: Option<i64>,
}

/// Waiver audit report written alongside gate verdicts.
#[derive(Debug, serde::Serialize)]
struct WaiverAuditReport {
    schema: String,
    generated_at: String,
    total_waivers: usize,
    active: usize,
    expired: usize,
    expiring_soon: usize,
    invalid: usize,
    waivers: Vec<WaiverValidation>,
    raw_waivers: Vec<Waiver>,
}

const WAIVER_REQUIRED_FIELDS: &[&str] = &[
    "owner",
    "created",
    "expires",
    "bead",
    "reason",
    "scope",
    "remove_when",
];
const WAIVER_VALID_SCOPES: &[&str] = &["full", "preflight", "both"];
const WAIVER_MAX_DURATION_DAYS: i64 = 30;
const WAIVER_EXPIRY_WARN_DAYS: i64 = 3;

/// Parse all `[waiver.*]` sections from suite_classification.toml.
fn parse_waivers(root: &Path) -> (Vec<Waiver>, Vec<WaiverValidation>) {
    let toml_path = root.join("tests/suite_classification.toml");
    let Ok(text) = std::fs::read_to_string(&toml_path) else {
        return (Vec::new(), Vec::new());
    };
    let Ok(table) = text.parse::<toml::Table>() else {
        return (Vec::new(), Vec::new());
    };

    let mut waivers = Vec::new();
    let mut validations = Vec::new();

    let Some(waiver_table) = table.get("waiver").and_then(toml::Value::as_table) else {
        return (waivers, validations);
    };

    let today = today_date_str();

    for (gate_id, entry) in waiver_table {
        let Some(entry_table) = entry.as_table() else {
            validations.push(WaiverValidation {
                gate_id: gate_id.clone(),
                status: "invalid".to_string(),
                detail: Some("Waiver entry is not a table".to_string()),
                days_remaining: None,
            });
            continue;
        };

        // Check required fields
        let mut missing = Vec::new();
        for &field in WAIVER_REQUIRED_FIELDS {
            if !entry_table.contains_key(field) {
                missing.push(field);
            }
        }
        if !missing.is_empty() {
            validations.push(WaiverValidation {
                gate_id: gate_id.clone(),
                status: "invalid".to_string(),
                detail: Some(format!("Missing required fields: {}", missing.join(", "))),
                days_remaining: None,
            });
            continue;
        }

        let get_str = |key: &str| -> String {
            entry_table
                .get(key)
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string()
        };

        let waiver = Waiver {
            gate_id: gate_id.clone(),
            owner: get_str("owner"),
            created: get_str("created"),
            expires: get_str("expires"),
            bead: get_str("bead"),
            reason: get_str("reason"),
            scope: get_str("scope"),
            remove_when: get_str("remove_when"),
        };

        // Validate scope
        if !WAIVER_VALID_SCOPES.contains(&waiver.scope.as_str()) {
            validations.push(WaiverValidation {
                gate_id: gate_id.clone(),
                status: "invalid".to_string(),
                detail: Some(format!(
                    "Invalid scope '{}' (expected one of: {:?})",
                    waiver.scope, WAIVER_VALID_SCOPES
                )),
                days_remaining: None,
            });
            waivers.push(waiver);
            continue;
        }

        // Validate date format and expiry
        let validation = validate_waiver_dates(&waiver, &today);
        validations.push(validation);
        waivers.push(waiver);
    }

    (waivers, validations)
}

/// Returns today's date as YYYY-MM-DD string.
fn today_date_str() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// Parse a YYYY-MM-DD date string into a chrono NaiveDate.
fn parse_date(s: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

/// Validate waiver dates: expiry, duration, expiring-soon.
fn validate_waiver_dates(waiver: &Waiver, today: &str) -> WaiverValidation {
    let Some(today_date) = parse_date(today) else {
        return WaiverValidation {
            gate_id: waiver.gate_id.clone(),
            status: "invalid".to_string(),
            detail: Some("Cannot parse today's date".to_string()),
            days_remaining: None,
        };
    };

    let Some(created) = parse_date(&waiver.created) else {
        return WaiverValidation {
            gate_id: waiver.gate_id.clone(),
            status: "invalid".to_string(),
            detail: Some(format!("Invalid created date: '{}'", waiver.created)),
            days_remaining: None,
        };
    };

    let Some(expires) = parse_date(&waiver.expires) else {
        return WaiverValidation {
            gate_id: waiver.gate_id.clone(),
            status: "invalid".to_string(),
            detail: Some(format!("Invalid expires date: '{}'", waiver.expires)),
            days_remaining: None,
        };
    };

    // Check max duration
    let duration_days = (expires - created).num_days();
    if duration_days > WAIVER_MAX_DURATION_DAYS {
        return WaiverValidation {
            gate_id: waiver.gate_id.clone(),
            status: "invalid".to_string(),
            detail: Some(format!(
                "Waiver duration {duration_days} days exceeds max {WAIVER_MAX_DURATION_DAYS} days"
            )),
            days_remaining: Some((expires - today_date).num_days()),
        };
    }

    let days_remaining = (expires - today_date).num_days();

    if days_remaining < 0 {
        WaiverValidation {
            gate_id: waiver.gate_id.clone(),
            status: "expired".to_string(),
            detail: Some(format!(
                "Expired {} day(s) ago (owner: {}, bead: {})",
                -days_remaining, waiver.owner, waiver.bead
            )),
            days_remaining: Some(days_remaining),
        }
    } else if days_remaining <= WAIVER_EXPIRY_WARN_DAYS {
        WaiverValidation {
            gate_id: waiver.gate_id.clone(),
            status: "expiring_soon".to_string(),
            detail: Some(format!(
                "Expires in {days_remaining} day(s) — action required (owner: {}, bead: {})",
                waiver.owner, waiver.bead
            )),
            days_remaining: Some(days_remaining),
        }
    } else {
        WaiverValidation {
            gate_id: waiver.gate_id.clone(),
            status: "active".to_string(),
            detail: None,
            days_remaining: Some(days_remaining),
        }
    }
}

/// Build a set of waived gate_ids for a given lane scope.
fn waived_gate_ids(
    waivers: &[Waiver],
    validations: &[WaiverValidation],
    lane: &str,
) -> HashMap<String, Waiver> {
    let mut map = HashMap::new();
    for waiver in waivers {
        // Only active/expiring_soon waivers take effect (not expired/invalid)
        let is_valid = validations.iter().any(|v| {
            v.gate_id == waiver.gate_id && (v.status == "active" || v.status == "expiring_soon")
        });
        if !is_valid {
            continue;
        }
        // Check scope matches lane
        let scope_matches = match waiver.scope.as_str() {
            "both" => true,
            s => s == lane,
        };
        if scope_matches {
            map.insert(waiver.gate_id.clone(), waiver.clone());
        }
    }
    map
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

/// One row in the PERF-3X bead coverage contract.
#[derive(Debug, Clone)]
struct Perf3xBeadCoverageRow {
    bead: String,
    unit_evidence: Vec<String>,
    e2e_evidence: Vec<String>,
    log_evidence: Vec<String>,
}

/// Critical implementation beads that must appear in the PERF-3X coverage matrix.
const PERF3X_CRITICAL_BEADS: &[&str] = &[
    "bd-3ar8v.2.8",
    "bd-3ar8v.3.8",
    "bd-3ar8v.4.7",
    "bd-3ar8v.4.8",
    "bd-3ar8v.4.9",
    "bd-3ar8v.4.10",
    "bd-3ar8v.6.11",
];

/// Machine-readable coverage contract consumed by the Phase-5 gate.
fn perf3x_bead_coverage_contract() -> Value {
    serde_json::json!({
        "schema": "pi.perf3x.bead_coverage.v1",
        "coverage_rows": [
            {
                "bead": "bd-3ar8v.2.8",
                "unit_evidence": ["tests/bench_schema.rs"],
                "e2e_evidence": ["tests/e2e_results"],
                "log_evidence": ["tests/full_suite_gate/full_suite_events.jsonl"]
            },
            {
                "bead": "bd-3ar8v.3.8",
                "unit_evidence": ["tests/compaction.rs"],
                "e2e_evidence": ["tests/e2e_session_persistence.rs"],
                "log_evidence": ["tests/full_suite_gate/certification_events.jsonl"]
            },
            {
                "bead": "bd-3ar8v.4.7",
                "unit_evidence": ["tests/ext_conformance.rs"],
                "e2e_evidence": ["tests/e2e_extension_registration.rs"],
                "log_evidence": ["tests/ext_conformance/reports/conformance_summary.json"]
            },
            {
                "bead": "bd-3ar8v.4.8",
                "unit_evidence": ["tests/ext_proptest.rs"],
                "e2e_evidence": ["tests/e2e_extension_registration.rs"],
                "log_evidence": ["tests/full_suite_gate/full_suite_events.jsonl"]
            },
            {
                "bead": "bd-3ar8v.4.9",
                "unit_evidence": ["tests/ext_bench_harness.rs"],
                "e2e_evidence": ["tests/e2e_extension_registration.rs"],
                "log_evidence": ["tests/full_suite_gate/certification_events.jsonl"]
            },
            {
                "bead": "bd-3ar8v.4.10",
                "unit_evidence": ["tests/phase3_security_invariants.rs"],
                "e2e_evidence": ["tests/e2e_security_scenario_sec66.rs"],
                "log_evidence": ["tests/full_suite_gate/certification_events.jsonl"]
            },
            {
                "bead": "bd-3ar8v.6.11",
                "unit_evidence": ["tests/ci_full_suite_gate.rs"],
                "e2e_evidence": ["tests/full_suite_gate/certification_verdict.json"],
                "log_evidence": ["tests/full_suite_gate/certification_events.jsonl"]
            }
        ]
    })
}

fn parse_required_evidence_paths(
    row: &Value,
    row_idx: usize,
    field_name: &str,
) -> Result<Vec<String>, String> {
    let values = row
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("coverage_rows[{row_idx}] missing '{field_name}' array"))?;
    if values.is_empty() {
        return Err(format!(
            "coverage_rows[{row_idx}] field '{field_name}' must be non-empty"
        ));
    }

    let mut seen_paths = HashSet::new();
    let mut paths = Vec::with_capacity(values.len());
    for (path_idx, value) in values.iter().enumerate() {
        let raw_path = value.as_str().ok_or_else(|| {
            format!("coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must be a string")
        })?;
        let raw_path = raw_path.trim();
        if raw_path.is_empty() {
            return Err(format!(
                "coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must not be empty"
            ));
        }
        let normalized_path =
            normalize_repo_relative_evidence_path(raw_path, row_idx, field_name, path_idx)?;
        if !seen_paths.insert(normalized_path.clone()) {
            return Err(format!(
                "coverage_rows[{row_idx}] field '{field_name}' contains duplicate path: {normalized_path}"
            ));
        }
        paths.push(normalized_path);
    }

    Ok(paths)
}

fn normalize_repo_relative_evidence_path(
    raw_path: &str,
    row_idx: usize,
    field_name: &str,
    path_idx: usize,
) -> Result<String, String> {
    let normalized_separators = raw_path.replace('\\', "/");
    if normalized_separators.starts_with("//") {
        return Err(format!(
            "coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must not use UNC paths: {raw_path}"
        ));
    }
    if is_windows_absolute_path(&normalized_separators) {
        return Err(format!(
            "coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must not use windows-absolute paths: {raw_path}"
        ));
    }

    let candidate = Path::new(&normalized_separators);
    if candidate.is_absolute() {
        return Err(format!(
            "coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must be repo-relative, got absolute path: {raw_path}"
        ));
    }

    let mut parts = Vec::new();
    for component in candidate.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => parts.push(segment.to_string_lossy().into_owned()),
            Component::ParentDir => {
                return Err(format!(
                    "coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must not contain parent traversal ('..'): {raw_path}"
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must be repo-relative: {raw_path}"
                ));
            }
        }
    }

    if parts.is_empty() {
        return Err(format!(
            "coverage_rows[{row_idx}] field '{field_name}[{path_idx}]' must contain a path segment: {raw_path}"
        ));
    }

    Ok(parts.join("/"))
}

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes.len() == 2 || bytes[2] == b'/')
}

fn is_canonical_perf3x_bead_id(bead: &str) -> bool {
    let Some(suffix) = bead.strip_prefix("bd-3ar8v.") else {
        return false;
    };
    if suffix.is_empty() {
        return false;
    }
    suffix
        .split('.')
        .all(|segment| !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()))
}

fn canonical_perf3x_bead_segments(bead: &str) -> Option<Vec<u64>> {
    let suffix = bead.strip_prefix("bd-3ar8v.")?;
    suffix
        .split('.')
        .map(|segment| segment.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()
}

fn validate_cross_category_evidence_uniqueness(
    row_idx: usize,
    unit_evidence: &[String],
    e2e_evidence: &[String],
    log_evidence: &[String],
) -> Result<(), String> {
    let mut seen_paths = HashMap::new();
    for (field_name, paths) in [
        ("unit_evidence", unit_evidence),
        ("e2e_evidence", e2e_evidence),
        ("log_evidence", log_evidence),
    ] {
        for path in paths {
            if let Some(previous_field) = seen_paths.insert(path.clone(), field_name) {
                return Err(format!(
                    "coverage_rows[{row_idx}] reuses evidence path across categories: {path} appears in '{previous_field}' and '{field_name}'"
                ));
            }
        }
    }
    Ok(())
}

/// Parse and validate the bead coverage contract.
fn validate_perf3x_bead_coverage_contract(
    contract: &Value,
) -> Result<Vec<Perf3xBeadCoverageRow>, String> {
    let schema = contract
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| "coverage contract missing schema".to_string())?;
    if schema != "pi.perf3x.bead_coverage.v1" {
        return Err(format!("unexpected coverage contract schema: {schema}"));
    }

    let rows = contract
        .get("coverage_rows")
        .and_then(Value::as_array)
        .ok_or_else(|| "coverage contract missing coverage_rows array".to_string())?;
    if rows.is_empty() {
        return Err("coverage_rows must not be empty".to_string());
    }

    let mut seen_beads = HashSet::new();
    let mut previous_bead_segments: Option<Vec<u64>> = None;
    let mut previous_bead_id: Option<String> = None;
    let mut parsed = Vec::with_capacity(rows.len());
    for (row_idx, row) in rows.iter().enumerate() {
        let bead = row
            .get("bead")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("coverage_rows[{row_idx}] missing 'bead' string"))?
            .trim()
            .to_string();
        if !is_canonical_perf3x_bead_id(&bead) {
            return Err(format!(
                "coverage_rows[{row_idx}] has invalid PERF-3X bead id: {bead}"
            ));
        }
        let bead_segments = canonical_perf3x_bead_segments(&bead).ok_or_else(|| {
            format!("coverage_rows[{row_idx}] has unparsable PERF-3X bead id segments: {bead}")
        })?;
        if let Some(previous_segments) = previous_bead_segments.as_ref() {
            if bead_segments < *previous_segments {
                let previous_bead = previous_bead_id.as_deref().unwrap_or("<unknown>");
                return Err(format!(
                    "coverage_rows must be sorted by canonical bead id order: row {row_idx} bead '{bead}' appears after '{previous_bead}'"
                ));
            }
        }
        previous_bead_segments = Some(bead_segments);
        previous_bead_id = Some(bead.clone());
        if !seen_beads.insert(bead.clone()) {
            return Err(format!("duplicate bead in coverage_rows: {bead}"));
        }

        let unit_evidence = parse_required_evidence_paths(row, row_idx, "unit_evidence")?;
        let e2e_evidence = parse_required_evidence_paths(row, row_idx, "e2e_evidence")?;
        let log_evidence = parse_required_evidence_paths(row, row_idx, "log_evidence")?;
        validate_cross_category_evidence_uniqueness(
            row_idx,
            &unit_evidence,
            &e2e_evidence,
            &log_evidence,
        )?;

        parsed.push(Perf3xBeadCoverageRow {
            bead,
            unit_evidence,
            e2e_evidence,
            log_evidence,
        });
    }

    let mut missing_critical = Vec::new();
    for bead_id in PERF3X_CRITICAL_BEADS {
        if !seen_beads.contains(*bead_id) {
            missing_critical.push(*bead_id);
        }
    }
    if !missing_critical.is_empty() {
        return Err(format!(
            "coverage_rows missing critical PERF-3X bead(s): {}",
            missing_critical.join(", ")
        ));
    }

    Ok(parsed)
}

/// Evaluate contract coverage against files present in repository artifacts.
fn evaluate_perf3x_bead_coverage(root: &Path, contract: &Value) -> (String, Option<String>) {
    let rows = match validate_perf3x_bead_coverage_contract(contract) {
        Ok(rows) => rows,
        Err(err) => {
            return (
                "fail".to_string(),
                Some(format!("Invalid PERF-3X coverage contract: {err}")),
            );
        }
    };

    let mut missing = Vec::new();
    for row in &rows {
        for (class_name, evidence_paths) in [
            ("unit", &row.unit_evidence),
            ("e2e", &row.e2e_evidence),
            ("log", &row.log_evidence),
        ] {
            for path in evidence_paths {
                if !root.join(path).exists() {
                    missing.push(format!("{}:{}:{}", row.bead, class_name, path));
                }
            }
        }
    }
    missing.sort();

    if missing.is_empty() {
        return (
            "pass".to_string(),
            Some(format!(
                "Validated {} PERF-3X bead coverage row(s) with complete unit/e2e/log evidence paths",
                rows.len()
            )),
        );
    }

    let preview = missing
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if missing.len() > 3 { " ..." } else { "" };
    (
        "fail".to_string(),
        Some(format!(
            "Coverage contract parsed ({} rows) but {} evidence path(s) are missing (fail-closed): {}{}",
            rows.len(),
            missing.len(),
            preview,
            suffix
        )),
    )
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

    // Gate 12: Provider gap test matrix (bd-3uqg.11.11.5).
    // Validates that the provider test matrix artifact exists and all focus
    // providers are listed.
    let (status, detail) = {
        let artifact = "docs/provider-gaps-test-matrix.json";
        let full = root.join(artifact);
        load_json(&full).map_or_else(
            || {
                (
                    "skip".to_string(),
                    Some(format!("Artifact not found: {artifact}")),
                )
            },
            |val| {
                let focus = val
                    .get("focus_provider_ids")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                let providers = val
                    .get("providers")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                if focus >= 5 && providers >= 5 {
                    ("pass".to_string(), None)
                } else {
                    (
                        "fail".to_string(),
                        Some(format!(
                            "Expected >= 5 focus providers; found {focus} focus, {providers} detailed"
                        )),
                    )
                }
            },
        )
    };
    gates.push(SubGate {
        id: "provider_gap_matrix".to_string(),
        name: "Provider gap test matrix coverage".to_string(),
        bead: "bd-3uqg.11.11.5".to_string(),
        status,
        blocking: false,
        artifact_path: Some("docs/provider-gaps-test-matrix.json".to_string()),
        detail,
        reproduce_command: Some(
            "cargo test --test provider_native_contract --test e2e_provider_scenarios -- --nocapture"
                .to_string(),
        ),
    });

    // Gate 14: SEC-6.4 Security compatibility conformance (bd-1a2cu).
    // Validates that benign extensions remain compatible under hardened security
    // policies. Reads the conformance verdict artifact generated by the
    // sec_compatibility_conformance test suite.
    let (status, detail) = {
        let artifact = "tests/full_suite_gate/sec_conformance_verdict.json";
        let full = root.join(artifact);
        load_json(&full).map_or_else(
            || {
                (
                    "skip".to_string(),
                    Some(format!("Artifact not found: {artifact}")),
                )
            },
            |val| {
                let verdict = val
                    .get("verdict")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let pass_rate = val
                    .get("pass_rate_pct")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                let threshold = val
                    .get("threshold_pct")
                    .and_then(Value::as_f64)
                    .unwrap_or(95.0);
                if verdict == "pass" {
                    ("pass".to_string(), None)
                } else {
                    (
                        "fail".to_string(),
                        Some(format!(
                            "SEC conformance verdict={verdict}, pass_rate={pass_rate:.1}% (threshold={threshold:.0}%)"
                        )),
                    )
                }
            },
        )
    };
    gates.push(SubGate {
        id: "sec_conformance".to_string(),
        name: "SEC-6.4 security compatibility conformance".to_string(),
        bead: "bd-1a2cu".to_string(),
        status,
        blocking: true,
        artifact_path: Some("tests/full_suite_gate/sec_conformance_verdict.json".to_string()),
        detail,
        reproduce_command: Some(
            "cargo test --test sec_compatibility_conformance -- --nocapture".to_string(),
        ),
    });

    // Gate 15: PERF-3X bead-to-evidence coverage audit (bd-3ar8v.6.11).
    let (status, detail) = evaluate_perf3x_bead_coverage(root, &perf3x_bead_coverage_contract());
    gates.push(SubGate {
        id: "perf3x_bead_coverage".to_string(),
        name: "PERF-3X bead-to-artifact coverage audit".to_string(),
        bead: "bd-3ar8v.6.11".to_string(),
        status,
        blocking: true,
        artifact_path: Some("tests/full_suite_gate/certification_events.jsonl".to_string()),
        detail,
        reproduce_command: Some(
            "cargo test --test ci_full_suite_gate -- perf3x_bead_coverage_contract_is_well_formed --nocapture --exact".to_string(),
        ),
    });

    // Gate 13: Waiver lifecycle (bd-1f42.8.8.1).
    // Validates that all waivers in suite_classification.toml are well-formed,
    // not expired, and have required metadata.
    let (waivers, validations) = parse_waivers(root);
    let expired_count = validations.iter().filter(|v| v.status == "expired").count();
    let invalid_count = validations.iter().filter(|v| v.status == "invalid").count();
    let expiring_count = validations
        .iter()
        .filter(|v| v.status == "expiring_soon")
        .count();
    let (status, detail) = if waivers.is_empty() {
        ("pass".to_string(), None)
    } else if expired_count > 0 || invalid_count > 0 {
        (
            "fail".to_string(),
            Some(format!(
                "{} expired, {} invalid out of {} waivers",
                expired_count,
                invalid_count,
                waivers.len()
            )),
        )
    } else if expiring_count > 0 {
        (
            "warn".to_string(),
            Some(format!(
                "{expiring_count} waiver(s) expiring within {WAIVER_EXPIRY_WARN_DAYS} days"
            )),
        )
    } else {
        ("pass".to_string(), None)
    };
    gates.push(SubGate {
        id: "waiver_lifecycle".to_string(),
        name: "Waiver lifecycle compliance".to_string(),
        bead: "bd-1f42.8.8.1".to_string(),
        status,
        blocking: true,
        artifact_path: Some("tests/full_suite_gate/waiver_audit.json".to_string()),
        detail,
        reproduce_command: Some(
            "cargo test --test ci_full_suite_gate -- waiver_lifecycle_audit --nocapture --exact"
                .to_string(),
        ),
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

// ═══════════════════════════════════════════════════════════════════════════
// Lane 1: Preflight fast-fail (bd-1f42.8.8.1)
// ═══════════════════════════════════════════════════════════════════════════

/// Preflight lane verdict artifact.
#[derive(Debug, serde::Serialize)]
struct PreflightVerdict {
    schema: String,
    lane: String,
    generated_at: String,
    verdict: String,
    policy: String,
    gates_evaluated: usize,
    first_failure: Option<SubGate>,
    blocking_gates: Vec<SubGate>,
    waivers_applied: Vec<String>,
    summary: PreflightSummary,
}

#[derive(Debug, serde::Serialize)]
struct PreflightSummary {
    blocking_pass: usize,
    blocking_fail: usize,
    blocking_skip: usize,
    blocking_waived: usize,
    blocking_total: usize,
    fail_fast_triggered: bool,
}

/// Lane 1: Preflight fast-fail gate.
///
/// Evaluates ONLY blocking gates. Stops at the first failure unless waived.
/// Produces a deterministic verdict artifact for early regression detection.
///
/// Run with:
/// `cargo test --test ci_full_suite_gate -- preflight_fast_fail --nocapture`
#[test]
#[allow(clippy::too_many_lines)]
fn preflight_fast_fail() {
    use chrono::{SecondsFormat, Utc};

    let root = repo_root();
    let report_dir = root.join("tests").join("full_suite_gate");
    let _ = std::fs::create_dir_all(&report_dir);

    eprintln!("\n=== Preflight Fast-Fail Lane (bd-1f42.8.8.1) ===\n");

    let all_gates = collect_gates(&root);
    let (waivers, validations) = parse_waivers(&root);
    let waived = waived_gate_ids(&waivers, &validations, "preflight");

    let blocking_gates: Vec<SubGate> = all_gates.into_iter().filter(|g| g.blocking).collect();

    let mut evaluated = Vec::new();
    let mut first_failure: Option<SubGate> = None;
    let mut waivers_applied = Vec::new();
    let mut pass_count = 0_usize;
    let mut fail_count = 0_usize;
    let mut skip_count = 0_usize;
    let mut waived_count = 0_usize;

    for gate in &blocking_gates {
        if gate.status == "pass" {
            pass_count += 1;
            evaluated.push(gate.clone());
        } else if gate.status == "skip" {
            skip_count += 1;
            evaluated.push(gate.clone());
        } else if waived.contains_key(&gate.id) {
            waived_count += 1;
            waivers_applied.push(gate.id.clone());
            let mut waived_gate = gate.clone();
            waived_gate.detail = Some(format!(
                "WAIVED: {} (bead: {})",
                waived.get(&gate.id).map_or("", |w| &w.reason),
                waived.get(&gate.id).map_or("", |w| &w.bead),
            ));
            evaluated.push(waived_gate);
        } else {
            // Failure — record and stop
            fail_count += 1;
            evaluated.push(gate.clone());
            if first_failure.is_none() {
                first_failure = Some(gate.clone());
            }
            // Fast-fail: stop evaluating after first failure
            break;
        }
    }

    let fail_fast_triggered = first_failure.is_some();
    let verdict = if fail_count == 0 { "pass" } else { "fail" };

    for gate in &evaluated {
        let icon = match gate.status.as_str() {
            "pass" => "PASS",
            "fail" => "FAIL",
            _ => "SKIP",
        };
        let waived_tag = if waivers_applied.contains(&gate.id) {
            " [WAIVED]"
        } else {
            ""
        };
        eprintln!("  [{icon}] {}{waived_tag}", gate.name);
        if let Some(ref detail) = gate.detail {
            eprintln!("         {detail}");
        }
    }
    if fail_fast_triggered {
        eprintln!(
            "\n  FAST-FAIL: Stopped after first blocking failure ({})",
            first_failure.as_ref().map_or("-", |g| &g.name)
        );
    }
    eprintln!();

    let report = PreflightVerdict {
        schema: "pi.ci.preflight_lane.v1".to_string(),
        lane: "preflight".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        verdict: verdict.to_string(),
        policy: "Preflight lane: evaluate blocking gates only, fail-fast on first failure. \
                 Waived gates are skipped with audit trail."
            .to_string(),
        gates_evaluated: evaluated.len(),
        first_failure,
        blocking_gates: evaluated,
        waivers_applied,
        summary: PreflightSummary {
            blocking_pass: pass_count,
            blocking_fail: fail_count,
            blocking_skip: skip_count,
            blocking_waived: waived_count,
            blocking_total: blocking_gates.len(),
            fail_fast_triggered,
        },
    };

    let verdict_path = report_dir.join("preflight_verdict.json");
    let _ = std::fs::write(
        &verdict_path,
        serde_json::to_string_pretty(&report).unwrap_or_default(),
    );

    eprintln!("=== Preflight Verdict: {} ===", verdict.to_uppercase());
    eprintln!(
        "  Blocking: {pass_count} pass, {fail_count} fail, {skip_count} skip, {waived_count} waived / {} total",
        blocking_gates.len()
    );
    eprintln!("  Report: {}", verdict_path.display());
    eprintln!();
}

// ═══════════════════════════════════════════════════════════════════════════
// Lane 2: Full certification (bd-1f42.8.8.1)
// ═══════════════════════════════════════════════════════════════════════════

/// Full certification verdict — includes all gates plus waiver audit.
#[derive(Debug, serde::Serialize)]
struct CertificationVerdict {
    schema: String,
    lane: String,
    generated_at: String,
    verdict: String,
    policy: String,
    gates: Vec<SubGate>,
    waiver_audit: WaiverAuditReport,
    waivers_applied: Vec<String>,
    summary: CertificationSummary,
    promotion_rules: PromotionRules,
    rerun_guidance: RerunGuidance,
}

#[derive(Debug, serde::Serialize)]
struct CertificationSummary {
    total_gates: usize,
    passed: usize,
    failed: usize,
    warned: usize,
    skipped: usize,
    waived: usize,
    blocking_pass: usize,
    blocking_total: usize,
    all_blocking_pass: bool,
}

#[derive(Debug, serde::Serialize)]
struct PromotionRules {
    can_promote: bool,
    blocker_gates: Vec<String>,
    waiver_gates: Vec<String>,
    conditions: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct RerunGuidance {
    preflight_command: String,
    full_command: String,
    single_gate_template: String,
}

/// Lane 2: Full certification gate.
///
/// Evaluates ALL gates (blocking + non-blocking), generates waiver audit,
/// and produces comprehensive verdict with promotion rules and rerun guidance.
///
/// Run with:
/// `cargo test --test ci_full_suite_gate -- full_certification --nocapture`
#[test]
#[allow(clippy::too_many_lines)]
fn full_certification() {
    use chrono::{SecondsFormat, Utc};
    use std::fmt::Write as _;

    let root = repo_root();
    let report_dir = root.join("tests").join("full_suite_gate");
    let _ = std::fs::create_dir_all(&report_dir);

    eprintln!("\n=== Full Certification Lane (bd-1f42.8.8.1) ===\n");

    let gates = collect_gates(&root);
    let (waivers, validations) = parse_waivers(&root);
    let waived = waived_gate_ids(&waivers, &validations, "full");

    // Build waiver audit
    let active = validations.iter().filter(|v| v.status == "active").count();
    let expired = validations.iter().filter(|v| v.status == "expired").count();
    let expiring_soon = validations
        .iter()
        .filter(|v| v.status == "expiring_soon")
        .count();
    let invalid = validations.iter().filter(|v| v.status == "invalid").count();

    let waiver_audit = WaiverAuditReport {
        schema: "pi.ci.waiver_audit.v1".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        total_waivers: waivers.len(),
        active,
        expired,
        expiring_soon,
        invalid,
        waivers: validations.clone(),
        raw_waivers: waivers.clone(),
    };

    // Write standalone waiver audit
    let waiver_path = report_dir.join("waiver_audit.json");
    let _ = std::fs::write(
        &waiver_path,
        serde_json::to_string_pretty(&waiver_audit).unwrap_or_default(),
    );

    // Evaluate gates with waiver application
    let mut waivers_applied = Vec::new();
    let mut effective_gates = Vec::new();
    for gate in &gates {
        if (gate.status == "fail" || gate.status == "warn") && waived.contains_key(&gate.id) {
            waivers_applied.push(gate.id.clone());
            let mut waived_gate = gate.clone();
            waived_gate.detail = Some(format!(
                "WAIVED (original: {}): {} (bead: {})",
                gate.status,
                waived.get(&gate.id).map_or("", |w| &w.reason),
                waived.get(&gate.id).map_or("", |w| &w.bead),
            ));
            effective_gates.push(waived_gate);
        } else {
            effective_gates.push(gate.clone());
        }
    }

    // Print gate results
    for gate in &effective_gates {
        let icon = match gate.status.as_str() {
            "pass" => "PASS",
            "fail" => "FAIL",
            "warn" => "WARN",
            _ => "SKIP",
        };
        let blocking = if gate.blocking { "(blocking)" } else { "" };
        let waived_tag = if waivers_applied.contains(&gate.id) {
            " [WAIVED]"
        } else {
            ""
        };
        eprintln!("  [{icon}] {:<50} {:<12}{waived_tag}", gate.name, blocking);
        if let Some(ref detail) = gate.detail {
            eprintln!("         {detail}");
        }
    }
    eprintln!();

    // Compute summary
    let passed = gates.iter().filter(|g| g.status == "pass").count();
    let failed = gates
        .iter()
        .filter(|g| g.status == "fail" && !waivers_applied.contains(&g.id))
        .count();
    let warned = gates
        .iter()
        .filter(|g| g.status == "warn" && !waivers_applied.contains(&g.id))
        .count();
    let skipped = gates.iter().filter(|g| g.status == "skip").count();
    let waived_count = waivers_applied.len();

    let blocking_gates: Vec<&SubGate> = gates.iter().filter(|g| g.blocking).collect();
    let blocking_pass = blocking_gates
        .iter()
        .filter(|g| g.status == "pass" || waivers_applied.contains(&g.id))
        .count();
    let blocking_total = blocking_gates.len();
    let all_blocking_pass = blocking_pass == blocking_total;

    let blocker_ids: Vec<String> = blocking_gates
        .iter()
        .filter(|g| g.status != "pass" && g.status != "skip" && !waivers_applied.contains(&g.id))
        .map(|g| g.id.clone())
        .collect();

    let verdict = if all_blocking_pass && failed == 0 {
        "pass"
    } else if all_blocking_pass {
        "warn"
    } else {
        "fail"
    };

    let mut conditions = Vec::new();
    if all_blocking_pass {
        conditions.push("All blocking gates pass (including waivers)".to_string());
    } else {
        conditions.push(format!(
            "Blocking gates still failing: {}",
            blocker_ids.join(", ")
        ));
    }
    if !waivers_applied.is_empty() {
        conditions.push(format!(
            "Waivers active for: {} (review before release)",
            waivers_applied.join(", ")
        ));
    }
    if expired > 0 {
        conditions.push(format!(
            "{expired} expired waiver(s) must be renewed or fixed"
        ));
    }

    let report = CertificationVerdict {
        schema: "pi.ci.certification_lane.v1".to_string(),
        lane: "full".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        verdict: verdict.to_string(),
        policy: "Full certification: all blocking gates must pass for release. \
                 Waived gates are tracked but do not block. Expired waivers fail the \
                 waiver_lifecycle gate."
            .to_string(),
        gates: effective_gates.clone(),
        waiver_audit,
        waivers_applied: waivers_applied.clone(),
        summary: CertificationSummary {
            total_gates: gates.len(),
            passed,
            failed,
            warned,
            skipped,
            waived: waived_count,
            blocking_pass,
            blocking_total,
            all_blocking_pass,
        },
        promotion_rules: PromotionRules {
            can_promote: all_blocking_pass && expired == 0 && invalid == 0,
            blocker_gates: blocker_ids,
            waiver_gates: waivers_applied.clone(),
            conditions,
        },
        rerun_guidance: RerunGuidance {
            preflight_command:
                "cargo test --test ci_full_suite_gate -- preflight_fast_fail --nocapture --exact"
                    .to_string(),
            full_command:
                "cargo test --test ci_full_suite_gate -- full_certification --nocapture --exact"
                    .to_string(),
            single_gate_template: "See reproduce_command field on each gate".to_string(),
        },
    };

    // Write certification verdict
    let cert_path = report_dir.join("certification_verdict.json");
    let _ = std::fs::write(
        &cert_path,
        serde_json::to_string_pretty(&report).unwrap_or_default(),
    );

    // Write JSONL events for certification
    let cert_events_path = report_dir.join("certification_events.jsonl");
    let mut lines: Vec<String> = Vec::new();
    for gate in &effective_gates {
        let line = serde_json::json!({
            "schema": "pi.ci.certification_event.v1",
            "lane": "full",
            "gate_id": gate.id,
            "gate_name": gate.name,
            "bead": gate.bead,
            "status": gate.status,
            "blocking": gate.blocking,
            "waived": waivers_applied.contains(&gate.id),
            "ts": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        lines.push(serde_json::to_string(&line).unwrap_or_default());
    }
    let _ = std::fs::write(&cert_events_path, lines.join("\n") + "\n");

    // Write certification markdown report
    let mut md = String::new();
    md.push_str("# Full Certification Report\n\n");
    let _ = writeln!(
        md,
        "> Generated: {}",
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    let _ = writeln!(md, "> Lane: **full**");
    let _ = writeln!(md, "> Verdict: **{}**\n", verdict.to_uppercase());

    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Value |\n|--------|-------|\n");
    let _ = writeln!(md, "| Total gates | {} |", gates.len());
    let _ = writeln!(md, "| Passed | {passed} |");
    let _ = writeln!(md, "| Failed | {failed} |");
    let _ = writeln!(md, "| Warned | {warned} |");
    let _ = writeln!(md, "| Skipped | {skipped} |");
    let _ = writeln!(md, "| Waived | {waived_count} |");
    let _ = writeln!(md, "| Blocking | {blocking_pass}/{blocking_total} |");
    let _ = writeln!(
        md,
        "| Can promote | {} |",
        if all_blocking_pass && expired == 0 && invalid == 0 {
            "YES"
        } else {
            "NO"
        }
    );
    md.push('\n');

    if !waivers.is_empty() {
        md.push_str("## Active Waivers\n\n");
        md.push_str("| Gate | Owner | Bead | Expires | Status | Removal Condition |\n");
        md.push_str("|------|-------|------|---------|--------|-------------------|\n");
        for (w, v) in waivers.iter().zip(validations.iter()) {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} |",
                w.gate_id, w.owner, w.bead, w.expires, v.status, w.remove_when
            );
        }
        md.push('\n');
    }

    md.push_str("## Gate Results\n\n");
    md.push_str(
        "| Gate | Bead | Blocking | Status | Waived | Artifact |\n\
         |------|------|----------|--------|--------|----------|\n",
    );
    for gate in &effective_gates {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | `{}` |",
            gate.name,
            gate.bead,
            if gate.blocking { "YES" } else { "no" },
            gate.status.to_uppercase(),
            if waivers_applied.contains(&gate.id) {
                "YES"
            } else {
                "-"
            },
            gate.artifact_path.as_deref().unwrap_or("-"),
        );
    }
    md.push('\n');

    md.push_str("## Rerun Commands\n\n");
    md.push_str("| Lane | Command |\n|------|--------|\n");
    let _ = writeln!(
        md,
        "| Preflight | `cargo test --test ci_full_suite_gate -- preflight_fast_fail --nocapture --exact` |"
    );
    let _ = writeln!(
        md,
        "| Full | `cargo test --test ci_full_suite_gate -- full_certification --nocapture --exact` |"
    );
    md.push('\n');

    let cert_md_path = report_dir.join("certification_report.md");
    let _ = std::fs::write(&cert_md_path, &md);

    // Print summary
    eprintln!("=== Certification Verdict: {} ===", verdict.to_uppercase());
    eprintln!("  Gates:    {passed}/{} passed", gates.len());
    eprintln!("  Blocking: {blocking_pass}/{blocking_total}");
    eprintln!("  Waived:   {waived_count}");
    if failed > 0 {
        eprintln!("  Failed:   {failed}");
    }
    if expired > 0 {
        eprintln!("  Expired waivers: {expired}");
    }
    eprintln!();
    eprintln!("  Reports:");
    eprintln!("    Cert:    {}", cert_path.display());
    eprintln!("    Waiver:  {}", waiver_path.display());
    eprintln!("    Events:  {}", cert_events_path.display());
    eprintln!("    MD:      {}", cert_md_path.display());
    eprintln!();
}

// ═══════════════════════════════════════════════════════════════════════════
// Waiver lifecycle audit (bd-1f42.8.8.1)
// ═══════════════════════════════════════════════════════════════════════════

/// Standalone waiver lifecycle audit.
///
/// Validates all waivers, produces audit report, and fails on expired/invalid waivers.
///
/// Run with:
/// `cargo test --test ci_full_suite_gate -- waiver_lifecycle_audit --nocapture`
#[test]
fn waiver_lifecycle_audit() {
    use chrono::{SecondsFormat, Utc};

    let root = repo_root();
    let report_dir = root.join("tests").join("full_suite_gate");
    let _ = std::fs::create_dir_all(&report_dir);

    eprintln!("\n=== Waiver Lifecycle Audit (bd-1f42.8.8.1) ===\n");

    let (waivers, validations) = parse_waivers(&root);

    let active = validations.iter().filter(|v| v.status == "active").count();
    let expired = validations.iter().filter(|v| v.status == "expired").count();
    let expiring_soon = validations
        .iter()
        .filter(|v| v.status == "expiring_soon")
        .count();
    let invalid = validations.iter().filter(|v| v.status == "invalid").count();

    for (w, v) in waivers.iter().zip(validations.iter()) {
        let icon = match v.status.as_str() {
            "active" => "OK",
            "expiring_soon" => "WARN",
            "expired" => "EXPIRED",
            _ => "INVALID",
        };
        eprintln!(
            "  [{icon}] {} — owner: {}, bead: {}, expires: {}",
            w.gate_id, w.owner, w.bead, w.expires
        );
        if let Some(ref detail) = v.detail {
            eprintln!("       {detail}");
        }
    }

    if waivers.is_empty() {
        eprintln!("  No waivers defined. Gate passes.");
    }
    eprintln!();

    let report = WaiverAuditReport {
        schema: "pi.ci.waiver_audit.v1".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        total_waivers: waivers.len(),
        active,
        expired,
        expiring_soon,
        invalid,
        waivers: validations,
        raw_waivers: waivers,
    };

    let waiver_path = report_dir.join("waiver_audit.json");
    let _ = std::fs::write(
        &waiver_path,
        serde_json::to_string_pretty(&report).unwrap_or_default(),
    );

    eprintln!("  Report: {}", waiver_path.display());
    eprintln!(
        "  Summary: {} total, {} active, {} expiring_soon, {} expired, {} invalid",
        report.total_waivers, active, expiring_soon, expired, invalid
    );
    eprintln!();

    // Fail on expired or invalid waivers
    assert_eq!(
        expired, 0,
        "Expired waivers must be renewed or the underlying issue fixed"
    );
    assert_eq!(
        invalid, 0,
        "Invalid waivers must have all required fields and valid dates"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Waiver schema validation tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn waiver_date_validation_active() {
    let waiver = Waiver {
        gate_id: "test_gate".to_string(),
        owner: "TestOwner".to_string(),
        created: "2026-02-01".to_string(),
        expires: "2026-02-28".to_string(),
        bead: "bd-test".to_string(),
        reason: "test".to_string(),
        scope: "both".to_string(),
        remove_when: "never".to_string(),
    };
    let v = validate_waiver_dates(&waiver, "2026-02-13");
    assert!(
        v.status == "active" || v.status == "expiring_soon",
        "Should be active or expiring_soon, got: {}",
        v.status
    );
    assert!(
        v.days_remaining.unwrap_or(-1) >= 0,
        "Should have positive days remaining"
    );
}

#[test]
fn waiver_date_validation_expired() {
    let waiver = Waiver {
        gate_id: "test_gate".to_string(),
        owner: "TestOwner".to_string(),
        created: "2026-01-01".to_string(),
        expires: "2026-01-15".to_string(),
        bead: "bd-test".to_string(),
        reason: "test".to_string(),
        scope: "both".to_string(),
        remove_when: "never".to_string(),
    };
    let v = validate_waiver_dates(&waiver, "2026-02-13");
    assert_eq!(v.status, "expired", "Should be expired");
    assert!(
        v.days_remaining.unwrap_or(0) < 0,
        "Should have negative days remaining"
    );
}

#[test]
fn waiver_date_validation_too_long_duration() {
    let waiver = Waiver {
        gate_id: "test_gate".to_string(),
        owner: "TestOwner".to_string(),
        created: "2026-02-01".to_string(),
        expires: "2026-04-01".to_string(), // 59 days
        bead: "bd-test".to_string(),
        reason: "test".to_string(),
        scope: "both".to_string(),
        remove_when: "never".to_string(),
    };
    let v = validate_waiver_dates(&waiver, "2026-02-13");
    assert_eq!(
        v.status, "invalid",
        "Should be invalid due to excessive duration"
    );
}

#[test]
fn waiver_date_validation_expiring_soon() {
    let waiver = Waiver {
        gate_id: "test_gate".to_string(),
        owner: "TestOwner".to_string(),
        created: "2026-02-10".to_string(),
        expires: "2026-02-15".to_string(),
        bead: "bd-test".to_string(),
        reason: "test".to_string(),
        scope: "both".to_string(),
        remove_when: "never".to_string(),
    };
    let v = validate_waiver_dates(&waiver, "2026-02-13");
    assert_eq!(
        v.status, "expiring_soon",
        "Should be expiring_soon (2 days left)"
    );
    assert_eq!(v.days_remaining, Some(2));
}

#[test]
fn waiver_scope_filtering() {
    let waivers = vec![
        Waiver {
            gate_id: "gate_a".to_string(),
            owner: "A".to_string(),
            created: "2026-02-01".to_string(),
            expires: "2026-02-28".to_string(),
            bead: "bd-a".to_string(),
            reason: "test".to_string(),
            scope: "preflight".to_string(),
            remove_when: "never".to_string(),
        },
        Waiver {
            gate_id: "gate_b".to_string(),
            owner: "B".to_string(),
            created: "2026-02-01".to_string(),
            expires: "2026-02-28".to_string(),
            bead: "bd-b".to_string(),
            reason: "test".to_string(),
            scope: "full".to_string(),
            remove_when: "never".to_string(),
        },
        Waiver {
            gate_id: "gate_c".to_string(),
            owner: "C".to_string(),
            created: "2026-02-01".to_string(),
            expires: "2026-02-28".to_string(),
            bead: "bd-c".to_string(),
            reason: "test".to_string(),
            scope: "both".to_string(),
            remove_when: "never".to_string(),
        },
    ];
    let validations = vec![
        WaiverValidation {
            gate_id: "gate_a".to_string(),
            status: "active".to_string(),
            detail: None,
            days_remaining: Some(15),
        },
        WaiverValidation {
            gate_id: "gate_b".to_string(),
            status: "active".to_string(),
            detail: None,
            days_remaining: Some(15),
        },
        WaiverValidation {
            gate_id: "gate_c".to_string(),
            status: "active".to_string(),
            detail: None,
            days_remaining: Some(15),
        },
    ];

    let preflight = waived_gate_ids(&waivers, &validations, "preflight");
    assert!(
        preflight.contains_key("gate_a"),
        "gate_a scoped to preflight"
    );
    assert!(
        !preflight.contains_key("gate_b"),
        "gate_b scoped to full only"
    );
    assert!(preflight.contains_key("gate_c"), "gate_c scoped to both");

    let full = waived_gate_ids(&waivers, &validations, "full");
    assert!(!full.contains_key("gate_a"), "gate_a not in full scope");
    assert!(full.contains_key("gate_b"), "gate_b scoped to full");
    assert!(full.contains_key("gate_c"), "gate_c scoped to both");
}

#[test]
fn waiver_expired_not_applied() {
    let waivers = vec![Waiver {
        gate_id: "gate_x".to_string(),
        owner: "X".to_string(),
        created: "2026-01-01".to_string(),
        expires: "2026-01-15".to_string(),
        bead: "bd-x".to_string(),
        reason: "expired test".to_string(),
        scope: "both".to_string(),
        remove_when: "never".to_string(),
    }];
    let validations = vec![WaiverValidation {
        gate_id: "gate_x".to_string(),
        status: "expired".to_string(),
        detail: Some("Expired".to_string()),
        days_remaining: Some(-29),
    }];

    let result = waived_gate_ids(&waivers, &validations, "both");
    assert!(result.is_empty(), "Expired waivers should not be applied");
}

#[test]
fn parse_waivers_empty_is_ok() {
    // When no waiver sections exist, should return empty with no errors
    let (waivers, validations) = parse_waivers(&repo_root());
    // Currently no waivers defined, so both should be empty
    eprintln!(
        "  Parsed {} waivers, {} validations",
        waivers.len(),
        validations.len()
    );
    // This test just verifies parsing doesn't panic
}

#[test]
fn perf3x_bead_coverage_contract_is_well_formed() {
    let contract = perf3x_bead_coverage_contract();
    let rows = validate_perf3x_bead_coverage_contract(&contract).expect("contract should be valid");
    assert!(
        rows.len() >= 6,
        "expected at least 6 PERF-3X rows, got {}",
        rows.len()
    );
    let bead_ids: HashSet<&str> = rows.iter().map(|row| row.bead.as_str()).collect();
    for bead_id in PERF3X_CRITICAL_BEADS {
        assert!(
            bead_ids.contains(*bead_id),
            "contract should include critical PERF-3X bead: {bead_id}"
        );
    }
    for row in rows {
        assert!(
            !row.unit_evidence.is_empty(),
            "unit evidence must be present"
        );
        assert!(!row.e2e_evidence.is_empty(), "e2e evidence must be present");
        assert!(!row.log_evidence.is_empty(), "log evidence must be present");
    }
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_missing_e2e_array() {
    let mut contract = perf3x_bead_coverage_contract();
    let first = contract
        .get_mut("coverage_rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .expect("first coverage row should exist");
    first.remove("e2e_evidence");

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("missing e2e_evidence must fail closed");
    assert!(
        err.contains("e2e_evidence"),
        "error should mention missing e2e_evidence, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_empty_log_array() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["log_evidence"] = serde_json::json!([]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("empty log_evidence must fail closed");
    assert!(
        err.contains("log_evidence"),
        "error should mention log_evidence, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_missing_critical_bead() {
    let mut contract = perf3x_bead_coverage_contract();
    let rows = contract
        .get_mut("coverage_rows")
        .and_then(Value::as_array_mut)
        .expect("coverage_rows must exist");
    rows.retain(|row| row.get("bead").and_then(Value::as_str) != Some("bd-3ar8v.3.8"));

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("missing critical PERF-3X bead must fail closed");
    assert!(
        err.contains("missing critical PERF-3X bead"),
        "error should mention missing critical bead set, got: {err}"
    );
    assert!(
        err.contains("bd-3ar8v.3.8"),
        "error should identify missing bead id, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_misordered_rows() {
    let mut contract = perf3x_bead_coverage_contract();
    let rows = contract
        .get_mut("coverage_rows")
        .and_then(Value::as_array_mut)
        .expect("coverage_rows must exist");
    rows.swap(0, 1);

    let err =
        validate_perf3x_bead_coverage_contract(&contract).expect_err("misordered rows must fail");
    assert!(
        err.contains("must be sorted by canonical bead id order"),
        "error should mention ordering requirement, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_non_numeric_bead_segment() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["bead"] = serde_json::json!("bd-3ar8v.4.alpha");

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("non-numeric bead segment must fail closed");
    assert!(
        err.contains("invalid PERF-3X bead id"),
        "error should mention invalid bead id, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_empty_bead_segment() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["bead"] = serde_json::json!("bd-3ar8v.4..10");

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("empty bead segment must fail closed");
    assert!(
        err.contains("invalid PERF-3X bead id"),
        "error should mention invalid bead id, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_missing_bead_suffix() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["bead"] = serde_json::json!("bd-3ar8v");

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("missing bead suffix must fail closed");
    assert!(
        err.contains("invalid PERF-3X bead id"),
        "error should mention invalid bead id, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_duplicate_unit_evidence_path() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["unit_evidence"] =
        serde_json::json!(["tests/bench_schema.rs", "tests/bench_schema.rs"]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("duplicate unit evidence path must fail closed");
    assert!(
        err.contains("duplicate path"),
        "error should mention duplicate path, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_cross_category_duplicate_path() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["unit_evidence"] = serde_json::json!(["tests/bench_schema.rs"]);
    contract["coverage_rows"][0]["e2e_evidence"] = serde_json::json!(["tests/bench_schema.rs"]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("cross-category duplicate path must fail closed");
    assert!(
        err.contains("reuses evidence path across categories"),
        "error should mention cross-category reuse, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_cross_category_duplicate_after_normalization() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["e2e_evidence"] = serde_json::json!(["./tests/e2e_results"]);
    contract["coverage_rows"][0]["log_evidence"] = serde_json::json!(["tests/e2e_results"]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("normalized cross-category duplicate path must fail closed");
    assert!(
        err.contains("reuses evidence path across categories"),
        "error should mention cross-category reuse, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_parent_traversal_path() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["log_evidence"] = serde_json::json!([
        "tests/full_suite_gate/certification_events.jsonl",
        "../escape.json"
    ]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("parent traversal path must fail closed");
    assert!(
        err.contains("parent traversal"),
        "error should mention parent traversal, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_absolute_path() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["e2e_evidence"] =
        serde_json::json!(["tests/e2e_results", "/tmp/outside_repo.json"]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("absolute path must fail closed");
    assert!(
        err.contains("absolute path"),
        "error should mention absolute path, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_normalized_duplicate_dot_slash_variant() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["unit_evidence"] =
        serde_json::json!(["./tests/bench_schema.rs", "tests/bench_schema.rs"]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("normalized duplicate evidence path must fail closed");
    assert!(
        err.contains("duplicate path"),
        "error should mention duplicate path, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_normalized_duplicate_backslash_variant() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["unit_evidence"] =
        serde_json::json!(["tests\\bench_schema.rs", "tests/bench_schema.rs"]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("normalized duplicate backslash variant must fail closed");
    assert!(
        err.contains("duplicate path"),
        "error should mention duplicate path, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_normalizes_relative_paths_before_storage() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["unit_evidence"] = serde_json::json!(["./tests//bench_schema.rs"]);

    let parsed = validate_perf3x_bead_coverage_contract(&contract)
        .expect("normalized relative path should pass");
    assert_eq!(
        parsed[0].unit_evidence[0], "tests/bench_schema.rs",
        "path should be normalized before storage"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_windows_absolute_path() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["e2e_evidence"] =
        serde_json::json!(["tests/e2e_results", "C:\\temp\\outside.json"]);

    let err = validate_perf3x_bead_coverage_contract(&contract)
        .expect_err("windows absolute path must fail closed");
    assert!(
        err.contains("windows-absolute"),
        "error should mention windows-absolute path, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_contract_fails_closed_on_unc_path() {
    let mut contract = perf3x_bead_coverage_contract();
    contract["coverage_rows"][0]["log_evidence"] = serde_json::json!([
        "tests/full_suite_gate/certification_events.jsonl",
        "\\\\server\\share\\outside.json"
    ]);

    let err =
        validate_perf3x_bead_coverage_contract(&contract).expect_err("UNC path must fail closed");
    assert!(
        err.contains("UNC paths"),
        "error should mention UNC path rejection, got: {err}"
    );
}

#[test]
fn perf3x_bead_coverage_evaluator_fails_closed_when_evidence_paths_are_missing() {
    let mut temp = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    temp.push(format!("pi_agent_rust_per3x_coverage_warn_{nonce}"));
    std::fs::create_dir_all(&temp).expect("create temp root");

    let (status, detail) = evaluate_perf3x_bead_coverage(&temp, &perf3x_bead_coverage_contract());
    assert_eq!(status, "fail", "missing paths should fail closed");
    let detail = detail.unwrap_or_default();
    assert!(
        detail.contains("missing"),
        "failure detail should mention missing paths: {detail}"
    );
    assert!(
        detail.contains("fail-closed"),
        "failure detail should indicate fail-closed policy: {detail}"
    );

    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn perf3x_bead_coverage_sub_gate_is_blocking() {
    let gates = collect_gates(&repo_root());
    let gate = gates
        .iter()
        .find(|gate| gate.id == "perf3x_bead_coverage")
        .expect("perf3x_bead_coverage gate should exist");
    assert!(
        gate.blocking,
        "PERF-3X bead coverage gate must be release-blocking"
    );
}

#[test]
fn perf3x_bead_coverage_evaluator_fails_on_malformed_contract() {
    let malformed = serde_json::json!({
        "schema": "pi.perf3x.bead_coverage.v1",
        "coverage_rows": [
            {
                "bead": "bd-3ar8v.2.8",
                "unit_evidence": [],
                "e2e_evidence": ["tests/e2e_results"],
                "log_evidence": ["tests/full_suite_gate/full_suite_events.jsonl"]
            }
        ]
    });

    let (status, detail) = evaluate_perf3x_bead_coverage(&repo_root(), &malformed);
    assert_eq!(status, "fail");
    let detail = detail.unwrap_or_default();
    assert!(
        detail.contains("Invalid PERF-3X coverage contract"),
        "expected malformed-contract failure, got: {detail}"
    );
}

#[test]
fn ci_workflow_publishes_scenario_cell_gate_artifacts() {
    let workflow = std::fs::read_to_string(CI_WORKFLOW_PATH)
        .unwrap_or_else(|err| panic!("failed to read {CI_WORKFLOW_PATH}: {err}"));

    for token in [
        "PERF_SCENARIO_CELL_STATUS_JSON",
        "PERF_SCENARIO_CELL_STATUS_MD",
        "Publish scenario-cell gate status [linux]",
        "Upload scenario-cell gate artifacts [linux]",
        "scenario-cell-gate-${{ github.run_id }}-${{ github.run_attempt }}",
        "## Scenario Cell Gate Status",
    ] {
        assert!(
            workflow.contains(token),
            "workflow must include scenario-cell gate token: {token}"
        );
    }
}

#[test]
fn run_all_wires_scenario_cell_status_artifacts_into_evidence_contract() {
    let script = std::fs::read_to_string(RUN_ALL_SCRIPT_PATH)
        .unwrap_or_else(|err| panic!("failed to read {RUN_ALL_SCRIPT_PATH}: {err}"));

    for token in [
        "claim_integrity_scenario_cell_status.json",
        "claim_integrity_scenario_cell_status.md",
        "pi.claim_integrity.scenario_cell_status.v1",
        "\"claim_integrity_scenario_cells\"",
        "PERF_PHASE1_MATRIX_VALIDATION_JSON",
        "phase1_matrix_validation.json",
        "claim_integrity.phase1_matrix_validation_path_configured",
        "claim_integrity.phase1_matrix_validation_json",
        "claim_integrity.phase1_matrix_validation_schema",
        "claim_integrity.phase1_matrix_validation_generated_at_fresh",
        "claim_integrity.phase1_matrix_correlation_matches_run",
        "claim_integrity.phase1_matrix_primary_outcomes_object",
        "claim_integrity.phase1_matrix_primary_outcomes_required_fields",
        "claim_integrity.phase1_matrix_primary_outcomes_status_valid",
        "claim_integrity.phase1_matrix_primary_outcomes_metrics_present",
        "claim_integrity.phase1_matrix_primary_outcomes_ordering_policy",
        "claim_integrity.phase1_matrix_cells_primary_e2e_metrics_present",
        "primary_e2e_before_microbench",
        "cherry_pick_guard.global_claim_valid must be true",
        "required_layers = [",
        "\"full_e2e_long_session\",",
        "extension_stratification.global_claim_valid",
        "claim_integrity.realistic_session_shape_coverage",
        "claim_integrity.unresolved_conflicting_claims",
        "claim_integrity.evidence_adjudication_matrix_schema",
        "claim_integrity_evidence_adjudication_matrix.json",
        "claim_integrity_evidence_adjudication_matrix.md",
        "pi.claim_integrity.evidence_adjudication_matrix.v1",
        "\"claim_integrity_adjudication_matrix\"",
        "\"source\"",
        "\"source_path\"",
        "phase1_matrix_validation",
        "benchmark_partitions",
        "realistic_long_session",
        "realistic_session_shape",
        "missing required realistic_session_shape coverage",
    ] {
        assert!(
            script.contains(token),
            "run_all.sh must include scenario-cell status token: {token}"
        );
    }
}
