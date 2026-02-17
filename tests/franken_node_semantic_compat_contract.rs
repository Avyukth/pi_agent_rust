use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/franken-node-semantic-compatibility-matrix-contract.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_contract() -> Value {
    let path = repo_root().join(CONTRACT_PATH);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as JSON: {err}", path.display()))
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn normalize_upper_snake(raw: &str) -> String {
    let mut normalized = String::with_capacity(raw.len());
    let mut last_was_sep = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_uppercase());
            last_was_sep = false;
        } else if !last_was_sep {
            normalized.push('_');
            last_was_sep = true;
        }
    }
    normalized.trim_matches('_').to_string()
}

#[test]
fn semantic_compat_contract_exists_and_is_valid_json() {
    let path = repo_root().join(CONTRACT_PATH);
    assert!(
        path.is_file(),
        "missing semantic compatibility contract artifact: {}",
        path.display()
    );
    let _ = load_contract();
}

#[test]
fn semantic_compat_contract_has_expected_schema_and_bead_linkage() {
    let contract = load_contract();
    assert_eq!(
        contract["schema"],
        Value::String("pi.frankennode.semantic_compatibility_matrix_contract.v1".to_string()),
        "semantic compatibility contract schema mismatch"
    );

    let version = contract["contract_version"]
        .as_str()
        .expect("contract_version must be present");
    assert!(
        parse_semver(version).is_some(),
        "contract_version must be semantic version x.y.z, got: {version}"
    );

    assert_eq!(
        contract["bead_id"],
        Value::String("bd-3ar8v.7.3".to_string()),
        "bead linkage must target bd-3ar8v.7.3"
    );
    assert_eq!(
        contract["support_bead_id"],
        Value::String("bd-3ar8v.7.3.1".to_string()),
        "support bead linkage must target bd-3ar8v.7.3.1"
    );
}

#[test]
fn semantic_compat_contract_scenario_taxonomy_is_complete_and_unique() {
    let contract = load_contract();
    let scenarios = contract["scenario_taxonomy"]
        .as_array()
        .expect("scenario_taxonomy must be an array");
    assert!(
        scenarios.len() >= 5,
        "scenario_taxonomy must define at least five core scenarios"
    );

    let mut scenario_ids = HashSet::new();
    for scenario in scenarios {
        let id = scenario["scenario_id"]
            .as_str()
            .expect("scenario_id must be present on every taxonomy row");
        assert!(
            scenario_ids.insert(id),
            "duplicate scenario_id detected in taxonomy: {id}"
        );

        let criticality = scenario["criticality"]
            .as_str()
            .expect("criticality must be present on every taxonomy row");
        assert!(
            matches!(criticality, "high" | "medium" | "low"),
            "invalid criticality level for {id}: {criticality}"
        );

        let required_surfaces = scenario["required_surfaces"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: required_surfaces must be an array"));
        assert!(
            !required_surfaces.is_empty(),
            "{id}: required_surfaces must not be empty"
        );
    }

    for required in [
        "SCN-module-resolution-esm-cjs",
        "SCN-node-builtin-apis",
        "SCN-event-loop-io-ordering",
        "SCN-tooling-and-package-workflows",
        "SCN-error-and-diagnostics-parity",
    ] {
        assert!(
            scenario_ids.contains(required),
            "scenario taxonomy missing required scenario_id: {required}"
        );
    }
}

#[test]
fn semantic_compat_contract_verdict_policy_is_fail_closed() {
    let contract = load_contract();
    let allowed = contract["verdict_policy"]["allowed_row_verdicts"]
        .as_array()
        .expect("verdict_policy.allowed_row_verdicts must be an array");
    let allowed_set: HashSet<&str> = allowed.iter().filter_map(Value::as_str).collect();
    for required in [
        "EXACT_PARITY",
        "ACCEPTABLE_SUPERSET",
        "PARTIAL_PARITY",
        "INCOMPATIBLE",
    ] {
        assert!(
            allowed_set.contains(required),
            "allowed_row_verdicts missing required verdict: {required}"
        );
    }

    let blockers = contract["verdict_policy"]["release_blockers"]
        .as_array()
        .expect("verdict_policy.release_blockers must be an array");
    assert!(
        !blockers.is_empty(),
        "verdict_policy.release_blockers must not be empty"
    );

    let rules = &contract["verdict_policy"]["global_claim_rules"];
    for required_bool in [
        "forbid_full_replacement_when_any_high_row_non_exact",
        "forbid_global_claim_when_lineage_missing",
        "require_explicit_scope_for_partial_parity",
    ] {
        assert_eq!(
            rules[required_bool].as_bool(),
            Some(true),
            "global_claim_rules.{required_bool} must be true"
        );
    }
}

#[test]
fn semantic_compat_contract_lineage_fields_are_required_and_hard_fail() {
    let contract = load_contract();
    let fields = contract["evidence_lineage_contract"]["required_fields"]
        .as_array()
        .expect("evidence_lineage_contract.required_fields must be an array");
    let field_set: HashSet<&str> = fields.iter().filter_map(Value::as_str).collect();
    for required in [
        "run_id",
        "scenario_id",
        "fixture_id",
        "oracle_source",
        "observed_runtime",
        "comparison_result",
        "artifact_path",
        "captured_at_utc",
    ] {
        assert!(
            field_set.contains(required),
            "required lineage field missing: {required}"
        );
    }

    assert_eq!(
        contract["evidence_lineage_contract"]["lineage_failure_policy"],
        Value::String("hard_fail".to_string()),
        "lineage failure policy must be hard_fail"
    );
}

#[test]
fn semantic_compat_contract_declares_executable_row_schema_and_adjudication_policy() {
    let contract = load_contract();
    let row_schema = &contract["executable_row_schema"];
    let required_fields = row_schema["required_fields"]
        .as_array()
        .expect("executable_row_schema.required_fields must be an array");
    let required_field_set: HashSet<&str> =
        required_fields.iter().filter_map(Value::as_str).collect();

    for required in [
        "scenario_id",
        "expected_baseline",
        "observed_runtime",
        "comparison_result",
        "verdict",
        "lineage",
    ] {
        assert!(
            required_field_set.contains(required),
            "required executable row field missing: {required}"
        );
    }

    assert_eq!(
        row_schema["scenario_id_normalization"]["trim_whitespace"].as_bool(),
        Some(true),
        "scenario_id_normalization.trim_whitespace must be true"
    );
    assert_eq!(
        row_schema["scenario_id_normalization"]["require_exact_taxonomy_match"].as_bool(),
        Some(true),
        "scenario_id_normalization.require_exact_taxonomy_match must be true"
    );
    assert_eq!(
        row_schema["verdict_normalization"]["trim_whitespace"].as_bool(),
        Some(true),
        "verdict_normalization.trim_whitespace must be true"
    );
    assert_eq!(
        row_schema["verdict_normalization"]["case"],
        Value::String("upper_snake".to_string()),
        "verdict_normalization.case must be upper_snake"
    );
    assert_eq!(
        row_schema["adjudication_policy"]["rule"],
        Value::String("comparison_result_must_match_verdict_after_normalization".to_string()),
        "adjudication_policy.rule mismatch"
    );
    assert_eq!(
        row_schema["adjudication_policy"]["failure_policy"],
        Value::String("hard_fail".to_string()),
        "adjudication_policy.failure_policy must be hard_fail"
    );
}

#[test]
fn semantic_compat_contract_declares_downstream_blocking_and_integration_links() {
    let contract = load_contract();
    let blocked = contract["downstream_dependencies"]["blocked_beads"]
        .as_array()
        .expect("downstream_dependencies.blocked_beads must be an array");
    let blocked_set: HashSet<&str> = blocked.iter().filter_map(Value::as_str).collect();
    for required in [
        "bd-3ar8v.7.4",
        "bd-3ar8v.7.5",
        "bd-3ar8v.7.8",
        "bd-3ar8v.7.11",
        "bd-3ar8v.7.14",
    ] {
        assert!(
            blocked_set.contains(required),
            "blocked_beads must include downstream dependency: {required}"
        );
    }

    let integration_contracts = contract["downstream_dependencies"]["integration_contracts"]
        .as_array()
        .expect("downstream_dependencies.integration_contracts must be an array");
    let integration_set: HashSet<&str> = integration_contracts
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        integration_set.contains("docs/franken-node-claim-gating-contract.json"),
        "integration contract linkage must include docs/franken-node-claim-gating-contract.json"
    );
}

fn sample_lineage(scenario_id: &str) -> Value {
    serde_json::json!({
        "run_id": "run-franken-semantic-001",
        "scenario_id": scenario_id,
        "fixture_id": format!("fixture-{scenario_id}"),
        "oracle_source": "node-baseline-fixture",
        "observed_runtime": "frankennode",
        "comparison_result": "EXACT_PARITY",
        "artifact_path": format!("tests/e2e_results/{scenario_id}/semantic_row.json"),
        "captured_at_utc": "2026-02-17T00:00:00Z"
    })
}

fn sample_row(scenario_id: &str, verdict: &str) -> Value {
    serde_json::json!({
        "scenario_id": scenario_id,
        "expected_baseline": "Node.js",
        "observed_runtime": "frankennode",
        "comparison_result": verdict,
        "verdict": verdict,
        "lineage": sample_lineage(scenario_id),
    })
}

#[allow(clippy::too_many_lines)]
fn evaluate_executable_semantic_matrix(contract: &Value, rows: &[Value]) -> Value {
    let taxonomy = contract["scenario_taxonomy"]
        .as_array()
        .expect("scenario_taxonomy must be an array");
    let taxonomy_map = taxonomy
        .iter()
        .filter_map(|row| {
            let id = row.get("scenario_id").and_then(Value::as_str)?;
            let criticality = row.get("criticality").and_then(Value::as_str)?;
            Some((id.to_string(), criticality.to_string()))
        })
        .collect::<std::collections::HashMap<_, _>>();

    let required_lineage_fields = contract["evidence_lineage_contract"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array")
        .iter()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let allowed_verdicts = contract["verdict_policy"]["allowed_row_verdicts"]
        .as_array()
        .expect("allowed_row_verdicts must be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<HashSet<_>>();
    let executable_row_schema = &contract["executable_row_schema"];
    let required_row_fields = executable_row_schema["required_fields"]
        .as_array()
        .expect("executable_row_schema.required_fields must be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let trim_scenario_id = executable_row_schema["scenario_id_normalization"]["trim_whitespace"]
        .as_bool()
        .unwrap_or(false);
    let trim_verdict = executable_row_schema["verdict_normalization"]["trim_whitespace"]
        .as_bool()
        .unwrap_or(false);
    let verdict_case = executable_row_schema["verdict_normalization"]["case"]
        .as_str()
        .unwrap_or("identity");
    let adjudication_rule = executable_row_schema["adjudication_policy"]["rule"]
        .as_str()
        .unwrap_or("");

    let mut covered_scenario_ids = HashSet::new();
    let mut incompatible_high = Vec::new();
    let mut missing_lineage = Vec::new();
    let mut missing_required_row_fields = Vec::new();
    let mut adjudication_mismatches = Vec::new();
    let mut unknown_scenarios = Vec::new();
    let mut invalid_verdict_rows = Vec::new();
    let mut evaluated_rows = Vec::new();

    for row in rows {
        let raw_scenario_id = row
            .get("scenario_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let scenario_id = if trim_scenario_id {
            raw_scenario_id.trim().to_string()
        } else {
            raw_scenario_id
        };

        let missing_fields = required_row_fields
            .iter()
            .filter(|field| match **field {
                "lineage" => row.get("lineage").and_then(Value::as_object).is_none(),
                key => row
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .is_none_or(str::is_empty),
            })
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !missing_fields.is_empty() {
            missing_required_row_fields.push(serde_json::json!({
                "scenario_id": scenario_id,
                "missing_fields": missing_fields,
            }));
        }

        let raw_verdict = row
            .get("verdict")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let normalized_verdict_input = if trim_verdict {
            raw_verdict.trim().to_string()
        } else {
            raw_verdict
        };
        let verdict = if verdict_case == "upper_snake" {
            normalize_upper_snake(&normalized_verdict_input)
        } else {
            normalized_verdict_input
        };

        let raw_comparison_result = row
            .get("comparison_result")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let normalized_comparison_input = if trim_verdict {
            raw_comparison_result.trim().to_string()
        } else {
            raw_comparison_result
        };
        let comparison_result = if verdict_case == "upper_snake" {
            normalize_upper_snake(&normalized_comparison_input)
        } else {
            normalized_comparison_input
        };
        let criticality = taxonomy_map
            .get(&scenario_id)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        if criticality == "unknown" {
            unknown_scenarios.push(scenario_id.clone());
        } else if !scenario_id.is_empty() {
            covered_scenario_ids.insert(scenario_id.clone());
        }
        if !allowed_verdicts.contains(verdict.as_str()) {
            invalid_verdict_rows.push(scenario_id.clone());
        }

        let lineage = row.get("lineage").and_then(Value::as_object);
        let missing_lineage_fields = required_lineage_fields
            .iter()
            .filter(|field| {
                lineage
                    .and_then(|lineage| lineage.get(field.as_str()))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .is_none_or(str::is_empty)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !missing_lineage_fields.is_empty() {
            missing_lineage.push(serde_json::json!({
                "scenario_id": scenario_id,
                "missing_fields": missing_lineage_fields,
            }));
        }

        if adjudication_rule == "comparison_result_must_match_verdict_after_normalization"
            && !verdict.is_empty()
            && !comparison_result.is_empty()
            && verdict != comparison_result
        {
            adjudication_mismatches.push(format!(
                "{scenario_id}:comparison_result={comparison_result}:verdict={verdict}"
            ));
        }

        if criticality == "high" && verdict == "INCOMPATIBLE" {
            incompatible_high.push(scenario_id.clone());
        }

        evaluated_rows.push(serde_json::json!({
            "scenario_id": scenario_id,
            "criticality": criticality,
            "verdict": verdict,
            "comparison_result": comparison_result,
            "lineage_missing_fields": missing_lineage_fields,
        }));
    }

    let missing_high_scenarios = taxonomy
        .iter()
        .filter_map(|row| {
            let scenario_id = row.get("scenario_id").and_then(Value::as_str)?;
            let criticality = row.get("criticality").and_then(Value::as_str)?;
            (criticality == "high" && !covered_scenario_ids.contains(scenario_id))
                .then(|| scenario_id.to_string())
        })
        .collect::<Vec<_>>();

    let mut blocking_reasons = Vec::new();
    if !incompatible_high.is_empty() {
        blocking_reasons.push(format!(
            "incompatible_high_critical_scenarios={}",
            incompatible_high.join(",")
        ));
    }
    if !missing_lineage.is_empty() {
        blocking_reasons.push(format!("missing_lineage_rows={}", missing_lineage.len()));
    }
    if !missing_required_row_fields.is_empty() {
        blocking_reasons.push(format!(
            "missing_required_row_fields={}",
            missing_required_row_fields.len()
        ));
    }
    if !adjudication_mismatches.is_empty() {
        blocking_reasons.push(format!(
            "adjudication_mismatches={}",
            adjudication_mismatches.len()
        ));
    }
    if !missing_high_scenarios.is_empty() {
        blocking_reasons.push(format!(
            "missing_high_critical_scenarios={}",
            missing_high_scenarios.join(",")
        ));
    }
    if !unknown_scenarios.is_empty() {
        blocking_reasons.push(format!("unknown_scenarios={}", unknown_scenarios.join(",")));
    }
    if !invalid_verdict_rows.is_empty() {
        blocking_reasons.push(format!(
            "invalid_verdict_rows={}",
            invalid_verdict_rows.join(",")
        ));
    }

    serde_json::json!({
        "schema": "pi.frankennode.semantic_compatibility_matrix_report.v1",
        "summary": {
            "release_gate_status": if blocking_reasons.is_empty() { "ready" } else { "blocked" },
            "total_rows": rows.len(),
            "incompatible_high_critical_count": incompatible_high.len(),
            "missing_lineage_count": missing_lineage.len(),
            "missing_required_row_fields_count": missing_required_row_fields.len(),
            "adjudication_mismatch_count": adjudication_mismatches.len(),
            "missing_high_critical_scenarios": missing_high_scenarios,
            "blocking_reasons": blocking_reasons,
        },
        "rows": evaluated_rows,
    })
}

#[test]
fn semantic_compat_executable_harness_fails_closed_on_high_critical_incompatibility() {
    let contract = load_contract();
    let rows = vec![
        sample_row("SCN-module-resolution-esm-cjs", "INCOMPATIBLE"),
        sample_row("SCN-node-builtin-apis", "EXACT_PARITY"),
        sample_row("SCN-event-loop-io-ordering", "EXACT_PARITY"),
    ];

    let report = evaluate_executable_semantic_matrix(&contract, &rows);
    assert_eq!(
        report["summary"]["release_gate_status"],
        Value::String("blocked".to_string()),
        "high-critical INCOMPATIBLE row must block release gate"
    );
    assert!(
        report["summary"]["blocking_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons
                .iter()
                .filter_map(Value::as_str)
                .any(|reason| reason.contains("incompatible_high_critical_scenarios"))),
        "blocking reasons must include incompatible_high_critical_scenarios"
    );
}

#[test]
fn semantic_compat_executable_harness_fails_closed_on_missing_lineage_fields() {
    let contract = load_contract();
    let mut incomplete = sample_row("SCN-module-resolution-esm-cjs", "EXACT_PARITY");
    let incomplete_lineage = incomplete
        .get_mut("lineage")
        .and_then(Value::as_object_mut)
        .expect("lineage must be an object");
    incomplete_lineage["run_id"] = Value::String(String::new());

    let rows = vec![
        incomplete,
        sample_row("SCN-node-builtin-apis", "EXACT_PARITY"),
        sample_row("SCN-event-loop-io-ordering", "EXACT_PARITY"),
    ];

    let report = evaluate_executable_semantic_matrix(&contract, &rows);
    assert_eq!(
        report["summary"]["release_gate_status"],
        Value::String("blocked".to_string()),
        "missing lineage fields must fail closed"
    );
    assert_eq!(
        report["summary"]["missing_lineage_count"]
            .as_u64()
            .unwrap_or_default(),
        1,
        "missing lineage rows count should surface the incomplete row"
    );
}

#[test]
fn semantic_compat_executable_harness_reports_ready_when_high_rows_exact_with_lineage() {
    let contract = load_contract();
    let rows = vec![
        sample_row("SCN-module-resolution-esm-cjs", "EXACT_PARITY"),
        sample_row("SCN-node-builtin-apis", "EXACT_PARITY"),
        sample_row("SCN-event-loop-io-ordering", "EXACT_PARITY"),
    ];

    let report = evaluate_executable_semantic_matrix(&contract, &rows);
    assert_eq!(
        report["schema"],
        Value::String("pi.frankennode.semantic_compatibility_matrix_report.v1".to_string()),
        "executable harness must emit expected report schema"
    );
    assert_eq!(
        report["summary"]["release_gate_status"],
        Value::String("ready".to_string()),
        "all covered high-critical rows exact with full lineage should be ready"
    );
    assert_eq!(
        report["summary"]["total_rows"].as_u64().unwrap_or_default(),
        3,
        "summary total_rows should match evaluated rows"
    );
}

#[test]
fn semantic_compat_executable_harness_normalizes_verdict_and_comparison_case() {
    let contract = load_contract();
    let rows = vec![
        sample_row(" SCN-module-resolution-esm-cjs ", " exact parity "),
        sample_row("SCN-node-builtin-apis", "ACCEPTABLE-SUPERSET"),
        sample_row("SCN-event-loop-io-ordering", "exact_parity"),
    ];

    let report = evaluate_executable_semantic_matrix(&contract, &rows);
    assert_eq!(
        report["summary"]["release_gate_status"],
        Value::String("ready".to_string()),
        "trim+case normalization should preserve valid verdict rows"
    );
    assert_eq!(
        report["summary"]["adjudication_mismatch_count"]
            .as_u64()
            .unwrap_or_default(),
        0,
        "normalized comparison_result/verdict values should agree"
    );
}

#[test]
fn semantic_compat_executable_harness_fails_closed_on_missing_required_row_fields() {
    let contract = load_contract();
    let mut missing_expected = sample_row("SCN-module-resolution-esm-cjs", "EXACT_PARITY");
    missing_expected["expected_baseline"] = Value::String(String::new());
    let rows = vec![
        missing_expected,
        sample_row("SCN-node-builtin-apis", "EXACT_PARITY"),
        sample_row("SCN-event-loop-io-ordering", "EXACT_PARITY"),
    ];

    let report = evaluate_executable_semantic_matrix(&contract, &rows);
    assert_eq!(
        report["summary"]["release_gate_status"],
        Value::String("blocked".to_string()),
        "rows missing required executable schema fields must fail closed"
    );
    assert_eq!(
        report["summary"]["missing_required_row_fields_count"]
            .as_u64()
            .unwrap_or_default(),
        1,
        "missing required row fields count should surface schema violations"
    );
}

#[test]
fn semantic_compat_executable_harness_fails_closed_on_adjudication_mismatch() {
    let contract = load_contract();
    let mut mismatch = sample_row("SCN-module-resolution-esm-cjs", "EXACT_PARITY");
    mismatch["comparison_result"] = Value::String("INCOMPATIBLE".to_string());
    let rows = vec![
        mismatch,
        sample_row("SCN-node-builtin-apis", "EXACT_PARITY"),
        sample_row("SCN-event-loop-io-ordering", "EXACT_PARITY"),
    ];

    let report = evaluate_executable_semantic_matrix(&contract, &rows);
    assert_eq!(
        report["summary"]["release_gate_status"],
        Value::String("blocked".to_string()),
        "comparison_result/verdict mismatches must block release claims"
    );
    assert_eq!(
        report["summary"]["adjudication_mismatch_count"]
            .as_u64()
            .unwrap_or_default(),
        1,
        "adjudication mismatch count should capture divergent verdict rows"
    );
}
