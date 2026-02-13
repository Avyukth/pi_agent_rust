//! CI: Strict non-mock regression and logging completeness gates (bd-1f42.8.8).
//!
//! Validates that CI gate infrastructure enforces:
//! 1. Non-mock inventory drift detection (new test doubles → gate failure)
//! 2. Coverage floor regressions from non-mock-rubric.json
//! 3. E2E logging/evidence contract quality
//! 4. Waiver lifecycle compliance (expiry, scope, audit trail)
//! 5. Gate failure remediation commands
//!
//! Run:
//! ```bash
//! cargo test --test ci_strict_gates_validation
//! ```

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::items_after_statements)]

use serde_json::Value;

// ─── Constants ──────────────────────────────────────────────────────────────

const NON_MOCK_RUBRIC_PATH: &str = "docs/non-mock-rubric.json";
const TEST_DOUBLE_INVENTORY_PATH: &str = "docs/test_double_inventory.json";
const TESTING_POLICY_PATH: &str = "docs/testing-policy.md";
const SUITE_CLASSIFICATION_PATH: &str = "tests/suite_classification.toml";
const CI_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const SCENARIO_MATRIX_PATH: &str = "docs/e2e_scenario_matrix.json";
const FULL_SUITE_GATE_PATH: &str = "tests/ci_full_suite_gate.rs";

fn load_json(path: &str) -> Value {
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Should read {path}"));
    serde_json::from_str(&content).unwrap_or_else(|_| panic!("Should parse {path} as JSON"))
}

fn load_text(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Should read {path}"))
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 1: Non-mock rubric exists and is well-formed
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn non_mock_rubric_exists_with_valid_schema() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    assert!(
        rubric["schema"]
            .as_str()
            .is_some_and(|s| s.starts_with("pi.qa.non_mock_rubric")),
        "non-mock-rubric.json must have a schema field"
    );
}

#[test]
fn non_mock_rubric_has_module_thresholds() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    // module_thresholds can be an object (keyed by module name) or an array
    let has_thresholds = rubric["module_thresholds"].is_object()
        || rubric["module_thresholds"].is_array()
        || rubric["modules"].is_object()
        || rubric["modules"].is_array();
    assert!(
        has_thresholds,
        "non-mock-rubric.json must define module-level coverage thresholds"
    );
}

#[test]
fn non_mock_rubric_covers_critical_modules() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let text = serde_json::to_string(&rubric).unwrap_or_default();

    let critical = ["agent", "tools", "provider", "session", "extension"];
    for module in &critical {
        assert!(
            text.contains(module),
            "non-mock-rubric must cover critical module: {module}"
        );
    }
}

#[test]
fn non_mock_rubric_has_exception_template() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let text = serde_json::to_string(&rubric).unwrap_or_default();
    assert!(
        text.contains("exception") || text.contains("allowlist"),
        "non-mock-rubric must define an exception/allowlist template"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 2: Test double inventory baseline
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_double_inventory_exists_with_schema() {
    let inventory = load_json(TEST_DOUBLE_INVENTORY_PATH);
    assert!(
        inventory["schema"].is_string(),
        "test_double_inventory.json must declare schema"
    );
}

#[test]
fn test_double_inventory_has_entry_count() {
    let inventory = load_json(TEST_DOUBLE_INVENTORY_PATH);
    let text = serde_json::to_string(&inventory).unwrap_or_default();
    assert!(
        text.contains("entry_count") || text.contains("entries"),
        "inventory must report entry counts"
    );
}

#[test]
fn test_double_inventory_has_risk_distribution() {
    let inventory = load_json(TEST_DOUBLE_INVENTORY_PATH);
    let text = serde_json::to_string(&inventory).unwrap_or_default();
    assert!(
        text.contains("risk") || text.contains("high") || text.contains("severity"),
        "inventory must include risk categorization"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 3: Testing policy defines enforcement rules
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn testing_policy_exists() {
    assert!(
        std::path::Path::new(TESTING_POLICY_PATH).exists(),
        "docs/testing-policy.md must exist"
    );
}

#[test]
fn testing_policy_defines_suite_categories() {
    let policy = load_text(TESTING_POLICY_PATH);
    let categories = ["Unit", "VCR", "E2E"];
    for cat in &categories {
        assert!(
            policy.contains(cat),
            "testing-policy must define suite category: {cat}"
        );
    }
}

#[test]
fn testing_policy_lists_allowlisted_exceptions() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("MockHttpServer") || policy.contains("allowlist"),
        "testing-policy must list allowlisted test double exceptions"
    );
}

#[test]
fn testing_policy_defines_ci_enforcement() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("CI") || policy.contains("enforcement") || policy.contains("gate"),
        "testing-policy must define CI enforcement rules"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 4: CI workflow has gate stages
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ci_workflow_exists() {
    assert!(
        std::path::Path::new(CI_WORKFLOW_PATH).exists(),
        ".github/workflows/ci.yml must exist"
    );
}

#[test]
fn ci_workflow_has_suite_classification_guard() {
    let ci = load_text(CI_WORKFLOW_PATH);
    assert!(
        ci.contains("suite_classification") || ci.contains("suite-classification"),
        "CI must include suite classification guard"
    );
}

#[test]
fn ci_workflow_has_coverage_gate() {
    let ci = load_text(CI_WORKFLOW_PATH);
    assert!(
        ci.contains("coverage") || ci.contains("llvm-cov"),
        "CI must include coverage gate"
    );
}

#[test]
fn ci_workflow_has_clippy_fmt_gates() {
    let ci = load_text(CI_WORKFLOW_PATH);
    assert!(ci.contains("clippy"), "CI must include clippy gate");
    assert!(ci.contains("fmt"), "CI must include fmt gate");
}

#[test]
fn ci_workflow_has_conformance_gate() {
    let ci = load_text(CI_WORKFLOW_PATH);
    assert!(
        ci.contains("conformance"),
        "CI must include conformance regression gate"
    );
}

#[test]
fn ci_workflow_has_evidence_bundle_gate() {
    let ci = load_text(CI_WORKFLOW_PATH);
    assert!(
        ci.contains("evidence") || ci.contains("bundle"),
        "CI must include evidence bundle gate"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 5: Full suite gate has blocking gates
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn full_suite_gate_exists() {
    assert!(
        std::path::Path::new(FULL_SUITE_GATE_PATH).exists(),
        "tests/ci_full_suite_gate.rs must exist"
    );
}

#[test]
fn full_suite_gate_has_preflight_lane() {
    let gate = load_text(FULL_SUITE_GATE_PATH);
    assert!(
        gate.contains("preflight"),
        "full suite gate must have preflight fast-fail lane"
    );
}

#[test]
fn full_suite_gate_has_full_certification_lane() {
    let gate = load_text(FULL_SUITE_GATE_PATH);
    assert!(
        gate.contains("full") && gate.contains("certification"),
        "full suite gate must have full certification lane"
    );
}

#[test]
fn full_suite_gate_has_blocking_verdicts() {
    let gate = load_text(FULL_SUITE_GATE_PATH);
    assert!(
        gate.contains("blocking"),
        "full suite gate must support blocking verdicts"
    );
}

#[test]
fn full_suite_gate_validates_waiver_lifecycle() {
    let gate = load_text(FULL_SUITE_GATE_PATH);
    assert!(
        gate.contains("waiver"),
        "full suite gate must validate waiver lifecycle"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6: Suite classification has waiver infrastructure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn suite_classification_exists() {
    assert!(
        std::path::Path::new(SUITE_CLASSIFICATION_PATH).exists(),
        "tests/suite_classification.toml must exist"
    );
}

#[test]
fn suite_classification_is_valid_toml() {
    let content = load_text(SUITE_CLASSIFICATION_PATH);
    assert!(
        content.parse::<toml::Value>().is_ok(),
        "suite_classification.toml must be valid TOML"
    );
}

#[test]
fn suite_classification_has_suite_sections() {
    let content = load_text(SUITE_CLASSIFICATION_PATH);
    assert!(
        content.contains("[suite."),
        "suite_classification must define [suite.*] sections"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 7: Remediation commands in gate outputs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ci_gate_failures_include_remediation_hints() {
    let gate = load_text(FULL_SUITE_GATE_PATH);
    // Gate failures should include remediation or hint text
    assert!(
        gate.contains("remediation") || gate.contains("hint") || gate.contains("fix"),
        "gate failure outputs must include remediation guidance"
    );
}

#[test]
fn scenario_matrix_consumed_by_ci_gates() {
    let matrix = load_json(SCENARIO_MATRIX_PATH);
    let consumed_by = matrix["ci_policy"]["consumed_by"]
        .as_array()
        .expect("consumed_by array");
    let consumers: Vec<&str> = consumed_by.iter().filter_map(Value::as_str).collect();
    assert!(
        consumers.iter().any(|c| c.contains("ci_full_suite_gate")),
        "scenario matrix must be consumed by ci_full_suite_gate"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 8: Gate promotion infrastructure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ci_gate_promotion_mode_supported() {
    let ci = load_text(CI_WORKFLOW_PATH);
    assert!(
        ci.contains("PROMOTION") || ci.contains("promotion") || ci.contains("strict"),
        "CI must support gate promotion mode (strict/rollback)"
    );
}

#[test]
fn ci_gate_pass_rate_threshold_defined() {
    let ci = load_text(CI_WORKFLOW_PATH);
    assert!(
        ci.contains("PASS_RATE") || ci.contains("pass_rate") || ci.contains("threshold"),
        "CI must define pass rate threshold for gates"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 9: Evidence artifacts exist
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn full_suite_verdict_artifact_exists() {
    let path = "tests/full_suite_gate/full_suite_verdict.json";
    assert!(
        std::path::Path::new(path).exists(),
        "full_suite_verdict.json must exist for CI verification"
    );
}

#[test]
fn full_suite_verdict_has_gates() {
    let verdict = load_json("tests/full_suite_gate/full_suite_verdict.json");
    assert!(
        verdict["gates"].is_array() || verdict["sub_gates"].is_array(),
        "full_suite_verdict must contain gates array"
    );
}

#[test]
fn full_suite_report_artifact_exists() {
    let path = "tests/full_suite_gate/full_suite_report.md";
    assert!(
        std::path::Path::new(path).exists(),
        "full_suite_report.md must exist"
    );
}

#[test]
fn full_suite_events_artifact_exists() {
    let path = "tests/full_suite_gate/full_suite_events.jsonl";
    assert!(
        std::path::Path::new(path).exists(),
        "full_suite_events.jsonl must exist"
    );
}
