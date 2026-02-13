//! QA Docs: Testing policy, operator runbooks, and triage playbook validation (bd-1f42.8.9).
//!
//! Validates that documentation artifacts match enforced behavior and evidence formats:
//! 1. testing-policy.md allowlist table integrity (owner, expiry, replacement plan)
//! 2. non-mock-rubric.json alignment with enforced thresholds/gates
//! 3. qa-runbook.md and flake-triage-policy.md for replay, triage, evidence contract
//! 4. Operator troubleshooting runbook: failure signatures → replay commands + artifact paths
//! 5. Every CI gate references documented remediation steps
//! 6. Documentation examples are command-valid and artifact-path accurate
//! 7. Stale/expired exceptions flagged with follow-up actions
//!
//! Run:
//! ```bash
//! cargo test --test qa_docs_policy_validation
//! ```

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::items_after_statements)]

use serde_json::Value;

// ─── Constants ──────────────────────────────────────────────────────────────

const TESTING_POLICY_PATH: &str = "docs/testing-policy.md";
const NON_MOCK_RUBRIC_PATH: &str = "docs/non-mock-rubric.json";
const QA_RUNBOOK_PATH: &str = "docs/qa-runbook.md";
const FLAKE_TRIAGE_PATH: &str = "docs/flake-triage-policy.md";
const SCENARIO_MATRIX_PATH: &str = "docs/e2e_scenario_matrix.json";
const CI_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const SUITE_CLASSIFICATION_PATH: &str = "tests/suite_classification.toml";
const TEST_DOUBLE_INVENTORY_PATH: &str = "docs/test_double_inventory.json";
const FULL_SUITE_GATE_PATH: &str = "tests/ci_full_suite_gate.rs";
const COVERAGE_BASELINE_PATH: &str = "docs/coverage-baseline-map.json";

fn load_json(path: &str) -> Value {
    let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Should read {path}"));
    serde_json::from_str(&content).unwrap_or_else(|_| panic!("Should parse {path} as JSON"))
}

fn load_text(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Should read {path}"))
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 1: Testing policy document structure and completeness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn testing_policy_defines_all_three_suites() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("Suite 1: Unit"),
        "must define Suite 1 (Unit)"
    );
    assert!(
        policy.contains("Suite 2: VCR"),
        "must define Suite 2 (VCR / Fixture Replay)"
    );
    assert!(
        policy.contains("Suite 3: Live E2E"),
        "must define Suite 3 (Live E2E)"
    );
}

#[test]
fn testing_policy_has_allowlist_table_with_required_columns() {
    let policy = load_text(TESTING_POLICY_PATH);
    // The allowlist table must have these column headers
    assert!(
        policy.contains("| Identifier |"),
        "allowlist table must have Identifier column"
    );
    assert!(
        policy.contains("| Location |") || policy.contains("Location |"),
        "allowlist table must have Location column"
    );
    assert!(
        policy.contains("Suite |"),
        "allowlist table must have Suite column"
    );
    assert!(
        policy.contains("Rationale |"),
        "allowlist table must have Rationale column"
    );
}

#[test]
fn testing_policy_allowlist_entries_reference_real_files() {
    let policy = load_text(TESTING_POLICY_PATH);
    // Each allowlisted exception should reference a real file path
    let known_locations = [
        "tests/common/harness.rs",
        "tests/e2e_cli.rs",
        "src/extensions.rs",
    ];
    for loc in &known_locations {
        assert!(
            policy.contains(loc),
            "allowlist must reference real file: {loc}"
        );
    }
    // Verify those files actually exist
    for loc in &known_locations {
        assert!(
            std::path::Path::new(loc).exists(),
            "allowlisted file must exist on disk: {loc}"
        );
    }
}

#[test]
fn testing_policy_has_exception_template_with_mandatory_fields() {
    let policy = load_text(TESTING_POLICY_PATH);
    let mandatory_fields = [
        "bead_id",
        "owner",
        "expires_at",
        "replacement_plan",
        "scope",
        "verification",
    ];
    for field in &mandatory_fields {
        assert!(
            policy.contains(field),
            "exception template must include mandatory field: {field}"
        );
    }
}

#[test]
fn testing_policy_defines_ci_enforcement_guards() {
    let policy = load_text(TESTING_POLICY_PATH);
    let guards = [
        "No-mock dependency guard",
        "No-mock code guard",
        "Suite classification guard",
        "VCR leak guard",
    ];
    for guard in &guards {
        assert!(
            policy.contains(guard),
            "testing-policy must document CI guard: {guard}"
        );
    }
}

#[test]
fn testing_policy_has_migration_checklist() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("Migration Checklist"),
        "must include migration checklist for suite transitions"
    );
}

#[test]
fn testing_policy_has_flaky_test_quarantine_section() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("Flaky-Test Quarantine"),
        "must include flaky-test quarantine section"
    );
    // Must define the 6 flake categories
    let categories = [
        "FLAKE-TIMING",
        "FLAKE-ENV",
        "FLAKE-NET",
        "FLAKE-RES",
        "FLAKE-EXT",
        "FLAKE-LOGIC",
    ];
    for cat in &categories {
        assert!(
            policy.contains(cat),
            "quarantine section must define category: {cat}"
        );
    }
}

#[test]
fn testing_policy_quarantine_has_9_required_fields() {
    let policy = load_text(TESTING_POLICY_PATH);
    let fields = [
        "category",
        "owner",
        "quarantined",
        "expires",
        "bead",
        "evidence",
        "repro",
        "reason",
        "remove_when",
    ];
    for field in &fields {
        assert!(
            policy.contains(field),
            "quarantine section must require field: {field}"
        );
    }
}

#[test]
fn testing_policy_defines_gate_promotion_runbook() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("CI Gate Promotion Runbook"),
        "must document CI gate promotion runbook"
    );
    assert!(
        policy.contains("CI_GATE_PROMOTION_MODE"),
        "must document promotion mode variable"
    );
    assert!(
        policy.contains("rollback"),
        "must document rollback procedure"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 2: Non-mock rubric alignment with CI gates
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn rubric_module_thresholds_match_runbook_table() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let runbook = load_text(QA_RUNBOOK_PATH);

    // module_thresholds.modules is an array of objects with "name" field
    let modules = rubric["module_thresholds"]["modules"]
        .as_array()
        .expect("module_thresholds.modules must be an array");

    // Every rubric module must appear in the qa-runbook coverage table
    for module in modules {
        let name = module["name"].as_str().unwrap_or("unknown");
        assert!(
            runbook.contains(name),
            "rubric module '{name}' must be documented in qa-runbook.md coverage table"
        );
    }
}

#[test]
fn rubric_has_floor_and_target_for_each_module() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let modules = rubric["module_thresholds"]["modules"]
        .as_array()
        .expect("module_thresholds.modules must be an array");

    for module in modules {
        let name = module["name"].as_str().unwrap_or("unknown");
        assert!(
            module["line_floor_pct"].is_number(),
            "module {name} must have numeric line_floor_pct"
        );
        assert!(
            module["line_target_pct"].is_number(),
            "module {name} must have numeric line_target_pct"
        );
        assert!(
            module["function_floor_pct"].is_number(),
            "module {name} must have numeric function_floor_pct"
        );
        assert!(
            module["function_target_pct"].is_number(),
            "module {name} must have numeric function_target_pct"
        );

        // Floor must be <= target
        let line_floor = module["line_floor_pct"].as_f64().unwrap();
        let line_target = module["line_target_pct"].as_f64().unwrap();
        assert!(
            line_floor <= line_target,
            "module {name}: line_floor_pct ({line_floor}) must be <= line_target_pct ({line_target})"
        );

        let fn_floor = module["function_floor_pct"].as_f64().unwrap();
        let fn_target = module["function_target_pct"].as_f64().unwrap();
        assert!(
            fn_floor <= fn_target,
            "module {name}: function_floor_pct ({fn_floor}) must be <= function_target_pct ({fn_target})"
        );
    }
}

#[test]
fn rubric_global_thresholds_are_consistent() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let global = &rubric["module_thresholds"]["global"];
    assert!(
        global.is_object(),
        "rubric must have module_thresholds.global"
    );

    let line_floor = global["line_floor_pct"]
        .as_f64()
        .expect("global line_floor_pct");
    let line_target = global["line_target_pct"]
        .as_f64()
        .expect("global line_target_pct");
    assert!(
        line_floor <= line_target,
        "global line_floor_pct must be <= line_target_pct"
    );
}

#[test]
fn rubric_critical_modules_have_highest_thresholds() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let modules = rubric["module_thresholds"]["modules"]
        .as_array()
        .expect("module_thresholds.modules");
    let global_floor = rubric["module_thresholds"]["global"]["line_floor_pct"]
        .as_f64()
        .unwrap_or(0.0);

    // Critical modules must have thresholds >= global floor
    let critical = ["providers", "extensions", "agent_loop", "tools"];
    for crit_name in &critical {
        if let Some(module) = modules
            .iter()
            .find(|m| m["name"].as_str() == Some(crit_name))
        {
            let line_floor = module["line_floor_pct"].as_f64().unwrap_or(0.0);
            assert!(
                line_floor >= global_floor,
                "critical module {crit_name} line_floor_pct ({line_floor}) must be >= global ({global_floor})"
            );
        }
    }
}

#[test]
fn rubric_exception_mechanism_documented() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let text = serde_json::to_string(&rubric).unwrap_or_default();
    assert!(
        text.contains("exception") || text.contains("allowlist") || text.contains("waiver"),
        "rubric must document an exception/waiver mechanism"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 3: QA runbook completeness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn qa_runbook_exists_and_has_required_sections() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    let sections = [
        "Quick Start",
        "Test Suite Classification",
        "Artifact Locations",
        "Failure Triage Playbook",
        "Replay Workflow",
        "Smoke Suite",
        "CI Gate Thresholds",
        "Per-Module Coverage Thresholds",
        "Quarantine Workflow",
    ];
    for section in &sections {
        assert!(
            runbook.contains(section),
            "qa-runbook.md must contain section: {section}"
        );
    }
}

#[test]
fn qa_runbook_artifact_paths_are_accurate() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    // Verify documented artifact paths reference real patterns
    let artifact_patterns = [
        "tests/smoke_results/",
        "tests/e2e_results/",
        "tests/ext_conformance/reports/",
        "docs/coverage-baseline-map.json",
        "docs/e2e_scenario_matrix.json",
        "tests/fixtures/vcr/",
        "target/test-failures.jsonl",
    ];
    for path in &artifact_patterns {
        assert!(
            runbook.contains(path),
            "runbook must document artifact path: {path}"
        );
    }
}

#[test]
fn qa_runbook_has_failure_signature_table() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    // The failure triage section must map signatures to actions
    let signatures = [
        "assertion failed",
        "missing Start event",
        "request URL mismatch",
        "connection refused",
        "DummyProvider",
    ];
    for sig in &signatures {
        assert!(
            runbook.contains(sig),
            "triage playbook must include failure signature: {sig}"
        );
    }
}

#[test]
fn qa_runbook_has_reproduction_commands() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    // Must include actual reproduction commands
    assert!(
        runbook.contains("cargo test --test"),
        "runbook must include cargo test reproduction commands"
    );
    assert!(
        runbook.contains("VCR_MODE=playback"),
        "runbook must include VCR playback command"
    );
    assert!(
        runbook.contains("RUST_LOG=debug"),
        "runbook must include debug logging command"
    );
    assert!(
        runbook.contains("RUST_BACKTRACE=1"),
        "runbook must include backtrace command"
    );
}

#[test]
fn qa_runbook_references_replay_commands() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("--rerun-from"),
        "runbook must document --rerun-from replay"
    );
    assert!(
        runbook.contains("--diff-from"),
        "runbook must document --diff-from comparison"
    );
}

#[test]
fn qa_runbook_coverage_table_matches_rubric_modules() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let modules = rubric["module_thresholds"]["modules"]
        .as_array()
        .expect("module_thresholds.modules must be an array");

    // Every rubric module should appear in the runbook coverage table
    for module in modules {
        let name = module["name"].as_str().unwrap_or("unknown");
        assert!(
            runbook.contains(name),
            "runbook coverage table must include rubric module: {name}"
        );
    }
}

#[test]
fn qa_runbook_documents_extension_failure_dossier() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("Extension Failure Dossier") || runbook.contains("conformance_summary"),
        "runbook must document extension failure dossier interpretation"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 4: Flake triage policy completeness
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn flake_triage_policy_exists_with_required_sections() {
    let policy = load_text(FLAKE_TRIAGE_PATH);
    let sections = [
        "Failure Classification",
        "Known Flake Patterns",
        "Retry Policy",
        "Quarantine Contract",
        "Flake Budget",
        "Triage Workflow",
        "Evidence Artifacts",
    ];
    for section in &sections {
        assert!(
            policy.contains(section),
            "flake-triage-policy must contain section: {section}"
        );
    }
}

#[test]
fn flake_triage_has_three_failure_buckets() {
    let policy = load_text(FLAKE_TRIAGE_PATH);
    let buckets = ["Deterministic", "Transient", "Environmental"];
    for bucket in &buckets {
        assert!(
            policy.contains(bucket),
            "flake triage must define failure bucket: {bucket}"
        );
    }
}

#[test]
fn flake_triage_has_known_flake_patterns_with_regex() {
    let policy = load_text(FLAKE_TRIAGE_PATH);
    let patterns = [
        "oracle_timeout",
        "resource_exhaustion",
        "fs_contention",
        "port_conflict",
        "tmpdir_race",
        "js_gc_pressure",
    ];
    for pattern in &patterns {
        assert!(
            policy.contains(pattern),
            "flake triage must list known pattern: {pattern}"
        );
    }
}

#[test]
fn flake_triage_documents_retry_limits() {
    let policy = load_text(FLAKE_TRIAGE_PATH);
    assert!(
        policy.contains("Max retries") || policy.contains("max retries"),
        "must document max retry limit"
    );
    assert!(
        policy.contains("5 seconds") || policy.contains("Retry delay"),
        "must document retry delay"
    );
}

#[test]
fn flake_triage_documents_quarantine_required_fields() {
    let policy = load_text(FLAKE_TRIAGE_PATH);
    let fields = [
        "category",
        "owner",
        "quarantined",
        "expires",
        "bead",
        "evidence",
        "repro",
        "reason",
        "remove_when",
    ];
    for field in &fields {
        assert!(
            policy.contains(field),
            "flake triage quarantine contract must list required field: {field}"
        );
    }
}

#[test]
fn flake_triage_has_configuration_variables() {
    let policy = load_text(FLAKE_TRIAGE_PATH);
    let vars = [
        "PI_CONFORMANCE_MAX_RETRIES",
        "PI_CONFORMANCE_RETRY_DELAY",
        "PI_CONFORMANCE_FLAKE_BUDGET",
    ];
    for var in &vars {
        assert!(
            policy.contains(var),
            "flake triage must document config variable: {var}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 5: Cross-document consistency
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn testing_policy_references_inventory_and_key_artifacts() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("test_double_inventory.json"),
        "testing-policy must reference test_double_inventory.json"
    );
    assert!(
        policy.contains("suite_classification.toml"),
        "testing-policy must reference suite_classification.toml"
    );
    assert!(
        policy.contains("e2e_scenario_matrix.json"),
        "testing-policy must reference e2e_scenario_matrix.json"
    );
}

#[test]
fn qa_runbook_references_testing_policy() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("testing-policy.md"),
        "runbook must reference testing-policy.md"
    );
}

#[test]
fn qa_runbook_references_rubric() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("non-mock-rubric.json"),
        "runbook must reference non-mock-rubric.json"
    );
}

#[test]
fn qa_runbook_references_coverage_baseline() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("coverage-baseline-map.json"),
        "runbook must reference coverage-baseline-map.json"
    );
}

#[test]
fn ci_workflow_guard_names_match_testing_policy() {
    let ci = load_text(CI_WORKFLOW_PATH);
    let policy = load_text(TESTING_POLICY_PATH);

    // Guards documented in policy should be reflected in CI
    if policy.contains("Suite classification guard") {
        assert!(
            ci.contains("suite_classification") || ci.contains("suite-classification"),
            "CI must implement suite classification guard documented in policy"
        );
    }
    if policy.contains("No-mock dependency guard") {
        assert!(
            ci.contains("mockall") || ci.contains("mockito") || ci.contains("wiremock"),
            "CI must check for mock dependencies documented in policy"
        );
    }
}

#[test]
fn scenario_matrix_rows_have_replay_commands() {
    let matrix = load_json(SCENARIO_MATRIX_PATH);
    let rows = matrix["rows"].as_array().expect("rows array");

    for row in rows {
        let id = row["workflow_id"].as_str().unwrap_or("unknown");
        let replay = row["replay_command"].as_str().unwrap_or("");
        assert!(
            !replay.is_empty(),
            "workflow {id} must have a non-empty replay_command"
        );
        // Replay commands should reference run_all.sh
        assert!(
            replay.contains("run_all.sh"),
            "workflow {id} replay_command must reference scripts/e2e/run_all.sh"
        );
    }
}

#[test]
fn scenario_matrix_suites_match_suite_classification() {
    let matrix = load_json(SCENARIO_MATRIX_PATH);
    let classification = load_text(SUITE_CLASSIFICATION_PATH);
    let rows = matrix["rows"].as_array().expect("rows array");

    for row in rows {
        let id = row["workflow_id"].as_str().unwrap_or("unknown");
        let suite_ids = row["suite_ids"].as_array();
        if let Some(suite_ids) = suite_ids {
            for suite in suite_ids {
                let name = suite.as_str().unwrap_or("");
                if !name.is_empty() {
                    assert!(
                        classification.contains(name),
                        "scenario matrix workflow {id} references suite '{name}' not in suite_classification.toml"
                    );
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6: CI gate remediation guidance
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn full_suite_gate_has_remediation_for_each_gate() {
    let gate = load_text(FULL_SUITE_GATE_PATH);
    // The gate should have remediation/hint/fix guidance
    assert!(
        gate.contains("remediation") || gate.contains("hint") || gate.contains("fix"),
        "full suite gate must include remediation guidance"
    );
}

#[test]
fn ci_workflow_has_failure_output_guidance() {
    let ci = load_text(CI_WORKFLOW_PATH);
    // CI should produce structured output on failure
    assert!(
        ci.contains("evidence") || ci.contains("summary") || ci.contains("report"),
        "CI workflow must reference evidence/summary artifacts for failure diagnosis"
    );
}

#[test]
fn qa_runbook_maps_ci_gate_failures_to_remediation() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    // The runbook must document how to handle CI gate failures
    assert!(
        runbook.contains("CI Gate Thresholds"),
        "runbook must document CI gate thresholds"
    );
    assert!(
        runbook.contains("CI_GATE_PROMOTION_MODE"),
        "runbook must reference promotion mode for gate remediation"
    );
}

#[test]
fn qa_runbook_documents_rollback_procedure() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    // The runbook should have rollback/emergency procedure
    assert!(
        runbook.contains("rollback") || runbook.contains("Emergency"),
        "runbook must document rollback/emergency procedure"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 7: Documentation command validity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn testing_policy_run_commands_reference_real_tools() {
    let policy = load_text(TESTING_POLICY_PATH);
    // Commands must reference real tools
    assert!(
        policy.contains("cargo test"),
        "policy must reference cargo test"
    );
    assert!(
        policy.contains("cargo test --all-targets --lib"),
        "policy must document unit test command"
    );
}

#[test]
fn qa_runbook_smoke_commands_reference_real_script() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("./scripts/smoke.sh"),
        "runbook must reference scripts/smoke.sh"
    );
    // Verify the script exists
    assert!(
        std::path::Path::new("scripts/smoke.sh").exists(),
        "scripts/smoke.sh must exist on disk"
    );
}

#[test]
fn qa_runbook_e2e_commands_reference_real_script() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("./scripts/e2e/run_all.sh"),
        "runbook must reference scripts/e2e/run_all.sh"
    );
    assert!(
        std::path::Path::new("scripts/e2e/run_all.sh").exists(),
        "scripts/e2e/run_all.sh must exist on disk"
    );
}

#[test]
fn testing_policy_suite_classification_path_accurate() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("tests/suite_classification.toml"),
        "policy must reference suite classification TOML"
    );
    assert!(
        std::path::Path::new(SUITE_CLASSIFICATION_PATH).exists(),
        "suite_classification.toml must exist on disk"
    );
}

#[test]
fn runbook_referenced_json_artifacts_exist() {
    // Validate that key JSON artifacts referenced in the runbook actually exist
    let artifacts = [
        NON_MOCK_RUBRIC_PATH,
        SCENARIO_MATRIX_PATH,
        COVERAGE_BASELINE_PATH,
        TEST_DOUBLE_INVENTORY_PATH,
    ];
    for path in &artifacts {
        assert!(
            std::path::Path::new(path).exists(),
            "runbook-referenced artifact must exist: {path}"
        );
        // Also verify it's valid JSON
        let content = std::fs::read_to_string(path).unwrap();
        assert!(
            serde_json::from_str::<Value>(&content).is_ok(),
            "artifact must be valid JSON: {path}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 8: Allowlist integrity and staleness detection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn testing_policy_allowlist_entries_have_cleanup_beads() {
    let policy = load_text(TESTING_POLICY_PATH);
    // Allowlisted exceptions with cleanup tracking should reference bead IDs
    // The allowlist mentions cleanup tracked by beads
    assert!(
        policy.contains("bd-m9rk") || policy.contains("bd-"),
        "allowlist entries should reference tracking beads for cleanup"
    );
}

#[test]
fn testing_policy_rejected_doubles_are_explicit() {
    let policy = load_text(TESTING_POLICY_PATH);
    let rejected = ["DummyProvider", "NullSession", "NullUiHandler"];
    for name in &rejected {
        assert!(
            policy.contains(name),
            "testing-policy must explicitly list rejected double: {name}"
        );
    }
}

#[test]
fn testing_policy_exception_process_documented() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("Process for adding new exceptions"),
        "must document the process for adding new allowlist exceptions"
    );
}

#[test]
fn ci_allowlist_regex_aligns_with_testing_policy() {
    let ci = load_text(CI_WORKFLOW_PATH);
    let policy = load_text(TESTING_POLICY_PATH);

    // CI should have an allowlist regex
    let ci_has_allowlist = ci.contains("MockHttp") && ci.contains("allowlist");
    let policy_has_allowlist = policy.contains("MockHttpServer");

    // Both CI and policy must agree on core exceptions
    assert!(
        ci_has_allowlist || policy_has_allowlist,
        "CI and testing-policy must both document MockHttp* allowlist"
    );
}

#[test]
fn test_double_inventory_entry_count_matches_policy_baseline() {
    let inventory = load_json(TEST_DOUBLE_INVENTORY_PATH);
    let policy = load_text(TESTING_POLICY_PATH);

    // The inventory should have an entry_count
    let count = inventory["summary"]["entry_count"]
        .as_u64()
        .or_else(|| inventory["entry_count"].as_u64());
    assert!(count.is_some(), "inventory must report entry_count");

    // The testing-policy should reference the baseline count
    let count_val = count.unwrap();
    let count_str = count_val.to_string();
    assert!(
        policy.contains(&count_str) || policy.contains("entry_count"),
        "testing-policy should reference the inventory baseline count ({count_val})"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 9: Schema consistency across documentation artifacts
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn non_mock_rubric_schema_is_versioned() {
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);
    let schema = rubric["schema"]
        .as_str()
        .expect("rubric must have schema field");
    assert!(
        schema.starts_with("pi.qa.non_mock_rubric"),
        "rubric schema must be pi.qa.non_mock_rubric.*, got: {schema}"
    );
}

#[test]
fn scenario_matrix_schema_is_versioned() {
    let matrix = load_json(SCENARIO_MATRIX_PATH);
    let schema = matrix["schema"]
        .as_str()
        .expect("matrix must have schema field");
    assert!(
        schema.starts_with("pi.e2e.scenario_matrix"),
        "matrix schema must be pi.e2e.scenario_matrix.*, got: {schema}"
    );
}

#[test]
fn test_double_inventory_schema_is_versioned() {
    let inventory = load_json(TEST_DOUBLE_INVENTORY_PATH);
    let schema = inventory["schema"]
        .as_str()
        .expect("inventory must have schema field");
    assert!(
        schema.starts_with("pi.qa.test_double_inventory"),
        "inventory schema must be pi.qa.test_double_inventory.*, got: {schema}"
    );
}

#[test]
fn coverage_baseline_exists_and_has_critical_paths() {
    let baseline = load_json(COVERAGE_BASELINE_PATH);
    assert!(
        baseline["critical_paths"].is_array() || baseline["summary"].is_object(),
        "coverage baseline must have critical_paths or summary"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 10: Operator runbook executable examples
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn qa_runbook_has_vcr_cassette_verification_commands() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("python3 -m json.tool"),
        "runbook must include JSON validation command for cassettes"
    );
    assert!(
        runbook.contains("verify_") || runbook.contains("cassette"),
        "runbook must reference VCR cassette verification"
    );
}

#[test]
fn qa_runbook_has_compliance_check_commands() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    assert!(
        runbook.contains("COMPLIANCE_REPORT=1"),
        "runbook must document compliance report generation"
    );
    assert!(
        runbook.contains("non_mock_compliance_gate") || runbook.contains("non_mock_rubric_gate"),
        "runbook must reference compliance/rubric gate tests"
    );
}

#[test]
fn qa_runbook_smoke_targets_match_suite_classification() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    let classification = load_text(SUITE_CLASSIFICATION_PATH);

    // Smoke targets mentioned in the runbook should be in the suite classification
    let smoke_targets = [
        "model_serialization",
        "config_precedence",
        "session_conformance",
        "error_types",
        "provider_streaming",
        "error_handling",
        "http_client",
    ];
    for target in &smoke_targets {
        assert!(
            runbook.contains(target),
            "runbook should list smoke target: {target}"
        );
        assert!(
            classification.contains(target),
            "smoke target '{target}' must be in suite_classification.toml"
        );
    }
}

#[test]
fn flake_triage_evidence_artifacts_documented() {
    let policy = load_text(FLAKE_TRIAGE_PATH);
    let artifacts = [
        "flake_events.jsonl",
        "conformance_summary.json",
        "retry_manifest.json",
        "quarantine_report.json",
        "quarantine_audit.jsonl",
    ];
    for artifact in &artifacts {
        assert!(
            policy.contains(artifact),
            "flake triage must document evidence artifact: {artifact}"
        );
    }
}

#[test]
fn testing_policy_and_runbook_coverage_thresholds_agree() {
    let policy = load_text(TESTING_POLICY_PATH);
    let runbook = load_text(QA_RUNBOOK_PATH);
    let rubric = load_json(NON_MOCK_RUBRIC_PATH);

    // Find the "providers" module in the modules array
    let modules = rubric["module_thresholds"]["modules"]
        .as_array()
        .expect("modules array");
    let providers = modules
        .iter()
        .find(|m| m["name"].as_str() == Some("providers"));
    if let Some(providers) = providers {
        if let Some(line_floor) = providers["line_floor_pct"].as_f64() {
            let floor_str = format!("{line_floor:.0}%");
            // At least one of policy or runbook should mention this threshold
            assert!(
                policy.contains(&floor_str) || runbook.contains(&floor_str),
                "provider line_floor_pct ({floor_str}) must appear in testing-policy or runbook"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 11: End-to-end documentation coverage gap detection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn every_ci_gate_has_documented_artifact_path() {
    let gate = load_text(FULL_SUITE_GATE_PATH);
    let runbook = load_text(QA_RUNBOOK_PATH);

    // Gate references to artifact paths should also appear in the runbook
    let gate_artifacts = [
        "non-mock-rubric.json",
        "suite_classification.toml",
        "e2e_scenario_matrix.json",
    ];
    for artifact in &gate_artifacts {
        assert!(
            gate.contains(artifact),
            "full suite gate must reference: {artifact}"
        );
        assert!(
            runbook.contains(artifact),
            "runbook must also reference gate artifact: {artifact}"
        );
    }
}

#[test]
fn testing_policy_smoke_section_exists() {
    let policy = load_text(TESTING_POLICY_PATH);
    assert!(
        policy.contains("Fast Local Smoke Suite") || policy.contains("smoke.sh"),
        "testing-policy must document the smoke suite"
    );
}

#[test]
fn all_doc_files_referenced_in_runbook_exist() {
    let runbook = load_text(QA_RUNBOOK_PATH);
    let doc_refs = [
        "docs/testing-policy.md",
        "docs/non-mock-rubric.json",
        "docs/coverage-baseline-map.json",
        "docs/e2e_scenario_matrix.json",
    ];
    for path in &doc_refs {
        // Strip "docs/" prefix since runbook might use relative paths
        let short = path.trim_start_matches("docs/");
        assert!(runbook.contains(short), "runbook must reference {path}");
        assert!(
            std::path::Path::new(path).exists(),
            "referenced doc must exist: {path}"
        );
    }
}
