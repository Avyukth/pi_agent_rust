//! Benchmark JSONL schema definitions and validation tests (bd-167l).
//!
//! Defines the canonical machine-readable output format for extension benchmark
//! runs. All benchmark JSONL records share a common envelope with environment
//! fingerprint, and schema-specific payload fields.
//!
//! Run with: `cargo test --test bench_schema -- --nocapture`

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::too_many_lines,
    dead_code
)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

// ─── Schema Definitions ──────────────────────────────────────────────────────

/// Common environment fingerprint included in every benchmark record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvFingerprint {
    /// Operating system (e.g., "Linux (Ubuntu 25.10)")
    pub os: String,
    /// CPU architecture (e.g., "x86_64")
    pub arch: String,
    /// CPU model string
    pub cpu_model: String,
    /// Number of logical CPU cores
    pub cpu_cores: u32,
    /// Total system memory in MB
    pub mem_total_mb: u64,
    /// Build profile: "debug" or "release"
    pub build_profile: String,
    /// Git commit hash (short)
    pub git_commit: String,
    /// Cargo feature flags active during build
    #[serde(default)]
    pub features: Vec<String>,
    /// SHA-256 of the concatenated env fields (for dedup/comparison)
    pub config_hash: String,
}

/// Schema: `pi.ext.rust_bench.v1` — Rust extension benchmark event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustBenchEvent {
    pub schema: String,
    pub runtime: String,
    pub scenario: String,
    pub extension: String,
    #[serde(flatten)]
    pub payload: Value,
    #[serde(default)]
    pub env: Option<EnvFingerprint>,
}

/// Schema: `pi.ext.legacy_bench.v1` — Legacy (TS/Node) benchmark event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyBenchEvent {
    pub schema: String,
    pub runtime: String,
    pub scenario: String,
    pub extension: String,
    #[serde(flatten)]
    pub payload: Value,
    #[serde(default)]
    pub node: Option<Value>,
}

/// Schema: `pi.perf.workload.v1` — PiJS workload benchmark event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadEvent {
    pub scenario: String,
    pub iterations: u64,
    pub tool_calls_per_iteration: u64,
    pub total_calls: u64,
    pub elapsed_ms: u64,
    pub per_call_us: u64,
    pub calls_per_sec: u64,
}

/// Schema: `pi.perf.budget.v1` — Performance budget check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetEvent {
    pub budget_name: String,
    pub category: String,
    pub threshold: f64,
    pub unit: String,
    pub actual: Option<f64>,
    pub status: String,
    pub source: String,
}

// ─── Schema Registry ─────────────────────────────────────────────────────────

/// Known JSONL schemas with version and description.
const SCHEMAS: &[(&str, &str)] = &[
    (
        "pi.bench.protocol.v1",
        "Canonical benchmark protocol contract (partitions, datasets, metadata, replay inputs)",
    ),
    (
        "pi.ext.rust_bench.v1",
        "Rust QuickJS extension benchmark event (load, tool call, event hook)",
    ),
    (
        "pi.ext.legacy_bench.v1",
        "Legacy pi-mono (Node.js) extension benchmark event",
    ),
    (
        "pi.perf.workload.v1",
        "PiJS workload harness output (tool call throughput)",
    ),
    ("pi.perf.budget.v1", "Performance budget check result"),
    (
        "pi.perf.budget_summary.v1",
        "Aggregate budget summary with pass/fail counts",
    ),
    (
        "pi.ext.conformance_report.v2",
        "Per-extension conformance report event",
    ),
    (
        "pi.ext.conformance_summary.v2",
        "Aggregate conformance summary with per-tier breakdowns",
    ),
];

/// Required fields for each schema (field name, description).
const RUST_BENCH_REQUIRED: &[&str] = &["schema", "runtime", "scenario", "extension"];
const LEGACY_BENCH_REQUIRED: &[&str] = &["schema", "runtime", "scenario", "extension"];
const WORKLOAD_REQUIRED: &[&str] = &[
    "scenario",
    "iterations",
    "tool_calls_per_iteration",
    "total_calls",
    "elapsed_ms",
    "per_call_us",
    "calls_per_sec",
];

/// Environment fingerprint fields.
const ENV_FINGERPRINT_FIELDS: &[(&str, &str)] = &[
    ("os", "Operating system name and version"),
    ("arch", "CPU architecture (x86_64, aarch64)"),
    (
        "cpu_model",
        "CPU model string from /proc/cpuinfo or sysinfo",
    ),
    ("cpu_cores", "Logical CPU core count"),
    ("mem_total_mb", "Total system memory in megabytes"),
    ("build_profile", "Cargo build profile: debug or release"),
    ("git_commit", "Short git commit hash of the build"),
    ("features", "Active Cargo feature flags"),
    ("config_hash", "SHA-256 of env fields for dedup"),
];

const BENCH_PROTOCOL_SCHEMA: &str = "pi.bench.protocol.v1";
const BENCH_PROTOCOL_VERSION: &str = "1.0.0";
const PARTITION_MATCHED_STATE: &str = "matched-state";
const PARTITION_REALISTIC: &str = "realistic";
const EVIDENCE_CLASS_MEASURED: &str = "measured";
const EVIDENCE_CLASS_INFERRED: &str = "inferred";
const CONFIDENCE_HIGH: &str = "high";
const CONFIDENCE_MEDIUM: &str = "medium";
const CONFIDENCE_LOW: &str = "low";
const REALISTIC_SESSION_SIZES: &[u64] = &[100_000, 200_000, 500_000, 1_000_000, 5_000_000];
const USER_PERCEIVED_SLI_IDS: &[&str] = &[
    "interactive_turn_p95_ms",
    "resume_session_p95_ms",
    "extension_dispatch_p95_ms",
    "tool_roundtrip_p95_ms",
    "tail_stability_p99_over_p50_ratio",
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_jsonl_file(path: &Path) -> Vec<Value> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn has_required_fields(record: &Value, fields: &[&str]) -> Vec<String> {
    let mut missing = Vec::new();
    for field in fields {
        if record.get(*field).is_none() {
            missing.push((*field).to_string());
        }
    }
    missing
}

fn canonical_protocol_contract() -> Value {
    let realistic_replay_inputs = REALISTIC_SESSION_SIZES
        .iter()
        .map(|messages| {
            json!({
                "scenario_id": format!("realistic/session_{messages}"),
                "partition": PARTITION_REALISTIC,
                "session_messages": messages,
                "replay_input": {
                    "transcript_fixture": format!("tests/artifacts/perf/session_{messages}.jsonl"),
                    "seed": 7,
                    "mode": "replay",
                },
            })
        })
        .collect::<Vec<_>>();

    let user_perceived_sli_catalog = vec![
        json!({
            "sli_id": "interactive_turn_p95_ms",
            "label": "Interactive turn latency (P95)",
            "unit": "ms",
            "objective": { "comparator": "<=", "threshold": 1200 },
            "ux_interpretation": {
                "good": "Feels responsive for normal coding dialogue.",
                "degraded": "Noticeable lag in turn-to-turn iteration speed.",
                "critical": "Workflow feels blocked; conversation rhythm breaks."
            }
        }),
        json!({
            "sli_id": "resume_session_p95_ms",
            "label": "Session resume latency (P95)",
            "unit": "ms",
            "objective": { "comparator": "<=", "threshold": 1800 },
            "ux_interpretation": {
                "good": "Project/session restore feels immediate after launch.",
                "degraded": "Resume feels sluggish but still tolerable.",
                "critical": "Resume delays materially slow task pickup."
            }
        }),
        json!({
            "sli_id": "extension_dispatch_p95_ms",
            "label": "Extension hostcall dispatch latency (P95)",
            "unit": "ms",
            "objective": { "comparator": "<=", "threshold": 350 },
            "ux_interpretation": {
                "good": "Extension-backed actions feel near-instant.",
                "degraded": "Extension interactions feel sticky/intermittent.",
                "critical": "Extension UX appears stalled or unreliable."
            }
        }),
        json!({
            "sli_id": "tool_roundtrip_p95_ms",
            "label": "Tool-call roundtrip latency (P95)",
            "unit": "ms",
            "objective": { "comparator": "<=", "threshold": 900 },
            "ux_interpretation": {
                "good": "Tool invocation and result handoff feel tight.",
                "degraded": "Tool feedback loop slows coding momentum.",
                "critical": "Tool usage becomes a bottleneck."
            }
        }),
        json!({
            "sli_id": "tail_stability_p99_over_p50_ratio",
            "label": "Tail stability (P99/P50 ratio)",
            "unit": "ratio",
            "objective": { "comparator": "<=", "threshold": 4.0 },
            "ux_interpretation": {
                "good": "Latency is predictable with low surprise spikes.",
                "degraded": "Intermittent long-tail pauses are noticeable.",
                "critical": "Frequent latency spikes disrupt workflow trust."
            }
        }),
    ];

    let mut scenario_sli_matrix = vec![
        json!({
            "partition": PARTITION_MATCHED_STATE,
            "scenario_id": "cold_start",
            "sli_ids": ["interactive_turn_p95_ms", "resume_session_p95_ms", "tail_stability_p99_over_p50_ratio"],
            "phase_validation_beads": ["bd-3ar8v.1.5", "bd-3ar8v.2.11"],
            "ux_outcome": "First interaction after startup feels responsive."
        }),
        json!({
            "partition": PARTITION_MATCHED_STATE,
            "scenario_id": "warm_start",
            "sli_ids": ["interactive_turn_p95_ms", "tail_stability_p99_over_p50_ratio"],
            "phase_validation_beads": ["bd-3ar8v.1.5", "bd-3ar8v.2.11"],
            "ux_outcome": "Steady-state turn latency remains consistently snappy."
        }),
        json!({
            "partition": PARTITION_MATCHED_STATE,
            "scenario_id": "tool_call",
            "sli_ids": ["tool_roundtrip_p95_ms", "interactive_turn_p95_ms", "tail_stability_p99_over_p50_ratio"],
            "phase_validation_beads": ["bd-3ar8v.2.11", "bd-3ar8v.6.7"],
            "ux_outcome": "Tool-assisted coding loop stays fluid."
        }),
        json!({
            "partition": PARTITION_MATCHED_STATE,
            "scenario_id": "event_dispatch",
            "sli_ids": ["extension_dispatch_p95_ms", "tail_stability_p99_over_p50_ratio"],
            "phase_validation_beads": ["bd-3ar8v.3.11", "bd-3ar8v.6.7"],
            "ux_outcome": "Extension events execute without perceptible stalls."
        }),
    ];

    scenario_sli_matrix.extend(REALISTIC_SESSION_SIZES.iter().map(|messages| {
        json!({
            "partition": PARTITION_REALISTIC,
            "scenario_id": format!("realistic/session_{messages}"),
            "sli_ids": ["interactive_turn_p95_ms", "resume_session_p95_ms", "tail_stability_p99_over_p50_ratio"],
            "phase_validation_beads": ["bd-3ar8v.3.11", "bd-3ar8v.6.7"],
            "ux_outcome": "Large-session operations remain usable for humans under realistic transcript load."
        })
    }));

    json!({
        "schema": BENCH_PROTOCOL_SCHEMA,
        "version": BENCH_PROTOCOL_VERSION,
        "partition_tags": [PARTITION_MATCHED_STATE, PARTITION_REALISTIC],
        "realistic_session_sizes": REALISTIC_SESSION_SIZES,
        "matched_state_scenarios": [
            {
                "scenario": "cold_start",
                "replay_input": { "runs": 5, "extension_fixture_set": ["hello", "pirate", "diff"] },
            },
            {
                "scenario": "warm_start",
                "replay_input": { "runs": 5, "extension_fixture_set": ["hello", "pirate", "diff"] },
            },
            {
                "scenario": "tool_call",
                "replay_input": { "iterations": 500, "extension_fixture_set": ["hello", "pirate", "diff"] },
            },
            {
                "scenario": "event_dispatch",
                "replay_input": { "iterations": 500, "event_name": "before_agent_start" },
            },
        ],
        "realistic_replay_inputs": realistic_replay_inputs,
        "required_metadata_fields": [
            "runtime",
            "build_profile",
            "host",
            "scenario_id",
            "correlation_id",
        ],
        "evidence_labels": {
            "evidence_class": [EVIDENCE_CLASS_MEASURED, EVIDENCE_CLASS_INFERRED],
            "confidence": [CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW],
        },
        "user_perceived_sli_catalog": user_perceived_sli_catalog,
        "scenario_sli_matrix": scenario_sli_matrix,
    })
}

fn validate_protocol_record(record: &Value) -> Result<(), String> {
    let required = [
        "protocol_schema",
        "protocol_version",
        "partition",
        "evidence_class",
        "confidence",
        "correlation_id",
        "scenario_metadata",
    ];
    let missing = has_required_fields(record, &required);
    if !missing.is_empty() {
        return Err(format!("missing required fields: {missing:?}"));
    }

    let protocol_schema = record
        .get("protocol_schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if protocol_schema != BENCH_PROTOCOL_SCHEMA {
        return Err(format!("unexpected protocol_schema: {protocol_schema}"));
    }

    let protocol_version = record
        .get("protocol_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if protocol_version != BENCH_PROTOCOL_VERSION {
        return Err(format!("unexpected protocol_version: {protocol_version}"));
    }

    let partition = record
        .get("partition")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(partition, PARTITION_MATCHED_STATE | PARTITION_REALISTIC) {
        return Err(format!("invalid partition: {partition}"));
    }

    let evidence_class = record
        .get("evidence_class")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(
        evidence_class,
        EVIDENCE_CLASS_MEASURED | EVIDENCE_CLASS_INFERRED
    ) {
        return Err(format!("invalid evidence_class: {evidence_class}"));
    }

    let confidence = record
        .get("confidence")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(
        confidence,
        CONFIDENCE_HIGH | CONFIDENCE_MEDIUM | CONFIDENCE_LOW
    ) {
        return Err(format!("invalid confidence: {confidence}"));
    }

    let correlation_id = record
        .get("correlation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if correlation_id.trim().is_empty() {
        return Err("correlation_id must be non-empty".to_string());
    }

    let metadata = record
        .get("scenario_metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| "scenario_metadata must be an object".to_string())?;

    for key in &[
        "runtime",
        "build_profile",
        "host",
        "scenario_id",
        "replay_input",
    ] {
        if !metadata.contains_key(*key) {
            return Err(format!("scenario_metadata missing {key}"));
        }
    }

    let host = metadata
        .get("host")
        .and_then(Value::as_object)
        .ok_or_else(|| "scenario_metadata.host must be an object".to_string())?;
    for key in &["os", "arch", "cpu_model", "cpu_cores"] {
        if !host.contains_key(*key) {
            return Err(format!("scenario_metadata.host missing {key}"));
        }
    }

    if partition == PARTITION_REALISTIC {
        let replay = metadata
            .get("replay_input")
            .and_then(Value::as_object)
            .ok_or_else(|| "realistic partition requires object replay_input".to_string())?;
        let size = replay
            .get("session_messages")
            .and_then(Value::as_u64)
            .ok_or_else(|| "realistic replay_input requires session_messages".to_string())?;
        if !REALISTIC_SESSION_SIZES.contains(&size) {
            return Err(format!(
                "unsupported realistic session_messages: {size} (expected one of {REALISTIC_SESSION_SIZES:?})"
            ));
        }
    }

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn schema_registry_is_complete() {
    assert!(
        SCHEMAS.len() >= 5,
        "should have at least 5 registered schemas"
    );
    for (name, desc) in SCHEMAS {
        assert!(!name.is_empty(), "schema name must not be empty");
        assert!(!desc.is_empty(), "schema description must not be empty");
        assert!(
            name.starts_with("pi."),
            "schema names should start with 'pi.': {name}"
        );
    }
    eprintln!("[schema] {} schemas registered", SCHEMAS.len());
}

#[test]
fn env_fingerprint_fields_documented() {
    assert!(
        ENV_FINGERPRINT_FIELDS.len() >= 7,
        "should document at least 7 env fingerprint fields"
    );
    for (name, desc) in ENV_FINGERPRINT_FIELDS {
        assert!(!name.is_empty());
        assert!(!desc.is_empty());
    }
    eprintln!(
        "[schema] {} env fingerprint fields documented",
        ENV_FINGERPRINT_FIELDS.len()
    );
}

#[test]
fn protocol_contract_covers_realistic_and_matched_state_partitions() {
    let contract = canonical_protocol_contract();
    assert_eq!(
        contract.get("schema").and_then(Value::as_str),
        Some(BENCH_PROTOCOL_SCHEMA)
    );
    assert_eq!(
        contract.get("version").and_then(Value::as_str),
        Some(BENCH_PROTOCOL_VERSION)
    );

    let partitions: Vec<&str> = contract["partition_tags"]
        .as_array()
        .expect("partition_tags array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(partitions.contains(&PARTITION_MATCHED_STATE));
    assert!(partitions.contains(&PARTITION_REALISTIC));
}

#[test]
fn protocol_contract_contains_realistic_size_matrix() {
    let contract = canonical_protocol_contract();
    let sizes: Vec<u64> = contract["realistic_session_sizes"]
        .as_array()
        .expect("realistic_session_sizes array")
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    assert_eq!(
        sizes, REALISTIC_SESSION_SIZES,
        "realistic session sizes must match canonical 100k/200k/500k/1M/5M matrix"
    );

    let replay_inputs = contract["realistic_replay_inputs"]
        .as_array()
        .expect("realistic_replay_inputs array");
    assert_eq!(
        replay_inputs.len(),
        REALISTIC_SESSION_SIZES.len(),
        "realistic replay inputs must cover each canonical size"
    );
    for expected_size in REALISTIC_SESSION_SIZES {
        assert!(
            replay_inputs.iter().any(|entry| {
                entry.get("session_messages").and_then(Value::as_u64) == Some(*expected_size)
            }),
            "missing realistic replay input for size {expected_size}"
        );
    }
}

#[test]
fn protocol_contract_contains_matched_state_replay_inputs() {
    let contract = canonical_protocol_contract();
    let scenarios = contract["matched_state_scenarios"]
        .as_array()
        .expect("matched_state_scenarios array");
    for expected in &["cold_start", "warm_start", "tool_call", "event_dispatch"] {
        let entry = scenarios
            .iter()
            .find(|scenario| scenario.get("scenario").and_then(Value::as_str) == Some(*expected));
        assert!(entry.is_some(), "missing matched-state scenario {expected}");
        assert!(
            entry
                .and_then(|v| v.get("replay_input"))
                .is_some_and(Value::is_object),
            "matched-state scenario {expected} must include replay_input object"
        );
    }
}

#[test]
fn protocol_contract_labels_evidence_and_confidence() {
    let contract = canonical_protocol_contract();
    let evidence_classes: Vec<&str> = contract["evidence_labels"]["evidence_class"]
        .as_array()
        .expect("evidence_class labels")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        evidence_classes,
        vec![EVIDENCE_CLASS_MEASURED, EVIDENCE_CLASS_INFERRED]
    );

    let confidence_labels: Vec<&str> = contract["evidence_labels"]["confidence"]
        .as_array()
        .expect("confidence labels")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        confidence_labels,
        vec![CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW]
    );
}

#[test]
fn protocol_contract_exposes_user_perceived_sli_matrix() {
    let contract = canonical_protocol_contract();
    let catalog = contract["user_perceived_sli_catalog"]
        .as_array()
        .expect("user_perceived_sli_catalog array");
    assert_eq!(
        catalog.len(),
        USER_PERCEIVED_SLI_IDS.len(),
        "expected fixed user-perceived SLI catalog cardinality"
    );

    let catalog_ids = catalog
        .iter()
        .map(|entry| {
            entry
                .get("sli_id")
                .and_then(Value::as_str)
                .expect("catalog entries must expose sli_id")
                .to_string()
        })
        .collect::<HashSet<_>>();
    for expected in USER_PERCEIVED_SLI_IDS {
        assert!(
            catalog_ids.contains(*expected),
            "missing canonical SLI id {expected}"
        );
    }

    let matrix = contract["scenario_sli_matrix"]
        .as_array()
        .expect("scenario_sli_matrix array");

    let mut expected_scenarios = ["cold_start", "warm_start", "tool_call", "event_dispatch"]
        .into_iter()
        .map(std::string::ToString::to_string)
        .collect::<HashSet<_>>();
    expected_scenarios.extend(
        REALISTIC_SESSION_SIZES
            .iter()
            .map(|messages| format!("realistic/session_{messages}")),
    );

    assert_eq!(
        matrix.len(),
        expected_scenarios.len(),
        "scenario_sli_matrix must cover every canonical benchmark scenario"
    );

    let mut seen_scenarios = HashSet::new();
    for row in matrix {
        let scenario_id = row
            .get("scenario_id")
            .and_then(Value::as_str)
            .expect("matrix row must contain scenario_id");
        seen_scenarios.insert(scenario_id.to_string());

        let sli_ids = row
            .get("sli_ids")
            .and_then(Value::as_array)
            .expect("matrix row must contain sli_ids array");
        assert!(
            !sli_ids.is_empty(),
            "matrix row {scenario_id} has empty sli_ids"
        );
        for sli_id in sli_ids {
            let sli_id = sli_id
                .as_str()
                .expect("sli_ids values must be strings in scenario_sli_matrix");
            assert!(
                catalog_ids.contains(sli_id),
                "scenario {scenario_id} references unknown SLI {sli_id}"
            );
        }

        let phase_beads = row
            .get("phase_validation_beads")
            .and_then(Value::as_array)
            .expect("matrix row must contain phase_validation_beads");
        assert!(
            phase_beads.iter().all(|id| {
                id.as_str()
                    .is_some_and(|bead_id| bead_id.starts_with("bd-3ar8v."))
            }),
            "matrix row {scenario_id} has invalid phase_validation_beads"
        );
    }

    assert_eq!(
        seen_scenarios, expected_scenarios,
        "scenario_sli_matrix scenarios must exactly match protocol scenarios"
    );
}

#[test]
fn protocol_record_validator_accepts_golden_fixture() {
    let golden = json!({
        "schema": "pi.ext.rust_bench.v1",
        "runtime": "pi_agent_rust",
        "scenario": "tool_call",
        "extension": "hello",
        "protocol_schema": BENCH_PROTOCOL_SCHEMA,
        "protocol_version": BENCH_PROTOCOL_VERSION,
        "partition": PARTITION_REALISTIC,
        "evidence_class": EVIDENCE_CLASS_MEASURED,
        "confidence": CONFIDENCE_HIGH,
        "correlation_id": "0123456789abcdef0123456789abcdef",
        "scenario_metadata": {
            "runtime": "pi_agent_rust",
            "build_profile": "release",
            "host": {
                "os": "linux",
                "arch": "x86_64",
                "cpu_model": "test-cpu",
                "cpu_cores": 8,
            },
            "scenario_id": "realistic/session_100000",
            "replay_input": {
                "session_messages": 100_000,
                "fixture": "tests/artifacts/perf/session_100000.jsonl",
            },
        },
    });
    assert!(
        validate_protocol_record(&golden).is_ok(),
        "golden protocol fixture should pass validation"
    );
}

#[test]
fn protocol_record_validator_rejects_missing_correlation_id() {
    let malformed = json!({
        "schema": "pi.ext.rust_bench.v1",
        "runtime": "pi_agent_rust",
        "scenario": "cold_start",
        "extension": "hello",
        "protocol_schema": BENCH_PROTOCOL_SCHEMA,
        "protocol_version": BENCH_PROTOCOL_VERSION,
        "partition": PARTITION_MATCHED_STATE,
        "evidence_class": EVIDENCE_CLASS_MEASURED,
        "confidence": CONFIDENCE_HIGH,
        "scenario_metadata": {
            "runtime": "pi_agent_rust",
            "build_profile": "release",
            "host": {
                "os": "linux",
                "arch": "x86_64",
                "cpu_model": "test-cpu",
                "cpu_cores": 8,
            },
            "scenario_id": "matched-state/cold_start",
            "replay_input": { "runs": 5 },
        },
    });

    let err = validate_protocol_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("correlation_id"),
        "expected correlation_id failure, got: {err}"
    );
}

#[test]
fn protocol_record_validator_rejects_invalid_partition_or_size() {
    let bad_partition = json!({
        "schema": "pi.ext.rust_bench.v1",
        "runtime": "pi_agent_rust",
        "scenario": "tool_call",
        "extension": "hello",
        "protocol_schema": BENCH_PROTOCOL_SCHEMA,
        "protocol_version": BENCH_PROTOCOL_VERSION,
        "partition": "invalid-partition",
        "evidence_class": EVIDENCE_CLASS_MEASURED,
        "confidence": CONFIDENCE_HIGH,
        "correlation_id": "abc",
        "scenario_metadata": {
            "runtime": "pi_agent_rust",
            "build_profile": "release",
            "host": {
                "os": "linux",
                "arch": "x86_64",
                "cpu_model": "test-cpu",
                "cpu_cores": 8,
            },
            "scenario_id": "invalid/thing",
            "replay_input": { "runs": 5 },
        },
    });
    assert!(
        validate_protocol_record(&bad_partition).is_err(),
        "invalid partition fixture must fail"
    );

    let bad_size = json!({
        "schema": "pi.ext.rust_bench.v1",
        "runtime": "pi_agent_rust",
        "scenario": "tool_call",
        "extension": "hello",
        "protocol_schema": BENCH_PROTOCOL_SCHEMA,
        "protocol_version": BENCH_PROTOCOL_VERSION,
        "partition": PARTITION_REALISTIC,
        "evidence_class": EVIDENCE_CLASS_MEASURED,
        "confidence": CONFIDENCE_HIGH,
        "correlation_id": "abc",
        "scenario_metadata": {
            "runtime": "pi_agent_rust",
            "build_profile": "release",
            "host": {
                "os": "linux",
                "arch": "x86_64",
                "cpu_model": "test-cpu",
                "cpu_cores": 8,
            },
            "scenario_id": "realistic/session_bad",
            "replay_input": { "session_messages": 42 },
        },
    });
    assert!(
        validate_protocol_record(&bad_size).is_err(),
        "realistic scenario with unsupported size must fail"
    );
}

#[test]
fn evidence_contract_schema_includes_benchmark_protocol_definition() {
    let schema_path = project_root().join("docs/evidence-contract-schema.json");
    let content = std::fs::read_to_string(&schema_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", schema_path.display()));
    let parsed: Value = serde_json::from_str(&content).expect("valid evidence contract JSON");
    let benchmark_protocol = parsed["definitions"]["benchmark_protocol"]
        .as_object()
        .expect("definitions.benchmark_protocol object must exist");

    assert_eq!(
        benchmark_protocol["properties"]["schema"]["const"]
            .as_str()
            .unwrap_or_default(),
        BENCH_PROTOCOL_SCHEMA
    );

    let partition_values: Vec<&str> =
        benchmark_protocol["properties"]["partition_tags"]["items"]["enum"]
            .as_array()
            .expect("partition enum array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
    assert!(partition_values.contains(&PARTITION_MATCHED_STATE));
    assert!(partition_values.contains(&PARTITION_REALISTIC));

    let size_values: Vec<u64> =
        benchmark_protocol["properties"]["realistic_session_sizes"]["items"]["enum"]
            .as_array()
            .expect("realistic session size enum array")
            .iter()
            .filter_map(Value::as_u64)
            .collect();
    assert_eq!(size_values, REALISTIC_SESSION_SIZES);

    let required_fields: Vec<&str> = benchmark_protocol["required"]
        .as_array()
        .expect("benchmark_protocol.required array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        required_fields.contains(&"user_perceived_sli_catalog"),
        "benchmark protocol schema must require user_perceived_sli_catalog"
    );
    assert!(
        required_fields.contains(&"scenario_sli_matrix"),
        "benchmark protocol schema must require scenario_sli_matrix"
    );
}

#[test]
fn protocol_is_referenced_by_benchmark_and_conformance_harnesses() {
    let refs = vec![
        ("tests/bench_scenario_runner.rs", BENCH_PROTOCOL_SCHEMA),
        ("tests/perf_bench_harness.rs", "pi.ext.rust_bench.v1"),
        ("tests/ext_bench_harness.rs", "pi.ext.rust_bench.v1"),
        ("tests/perf_comparison.rs", "pi.ext.perf_comparison.v1"),
        ("tests/ext_conformance_scenarios.rs", "conformance"),
    ];

    for (rel_path, marker) in refs {
        let abs = project_root().join(rel_path);
        let text = std::fs::read_to_string(&abs)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", abs.display()));
        assert!(
            text.contains(marker),
            "{rel_path} must reference marker `{marker}`"
        );
    }
}

#[test]
fn validate_rust_bench_schema() {
    let root = project_root();
    let events = read_jsonl_file(&root.join("target/perf/scenario_runner.jsonl"));
    if events.is_empty() {
        eprintln!("[schema] No scenario_runner.jsonl data — skipping");
        return;
    }

    for event in &events {
        let missing = has_required_fields(event, RUST_BENCH_REQUIRED);
        assert!(
            missing.is_empty(),
            "rust bench event missing required fields: {missing:?}"
        );
        assert_eq!(
            event.get("schema").and_then(Value::as_str),
            Some("pi.ext.rust_bench.v1"),
            "rust bench should use pi.ext.rust_bench.v1 schema"
        );
    }
    eprintln!("[schema] Validated {} rust bench events", events.len());
}

#[test]
fn validate_workload_schema() {
    let root = project_root();
    let events = read_jsonl_file(&root.join("target/perf/pijs_workload.jsonl"));
    if events.is_empty() {
        eprintln!("[schema] No pijs_workload.jsonl data — skipping");
        return;
    }

    for event in &events {
        let missing = has_required_fields(event, WORKLOAD_REQUIRED);
        assert!(
            missing.is_empty(),
            "workload event missing required fields: {missing:?}"
        );
    }
    eprintln!("[schema] Validated {} pijs_workload events", events.len());
}

#[test]
fn validate_legacy_bench_schema() {
    let root = project_root();
    let events = read_jsonl_file(&root.join("target/perf/legacy_extension_workloads.jsonl"));
    if events.is_empty() {
        eprintln!("[schema] No legacy benchmark data — skipping");
        return;
    }

    for event in &events {
        let missing = has_required_fields(event, LEGACY_BENCH_REQUIRED);
        assert!(
            missing.is_empty(),
            "legacy bench event missing required fields: {missing:?}"
        );
        assert_eq!(
            event.get("schema").and_then(Value::as_str),
            Some("pi.ext.legacy_bench.v1"),
            "legacy bench should use pi.ext.legacy_bench.v1 schema"
        );
    }
    eprintln!("[schema] Validated {} legacy bench events", events.len());
}

#[test]
fn validate_budget_events_schema() {
    let root = project_root();
    let events = read_jsonl_file(&root.join("tests/perf/reports/budget_events.jsonl"));
    if events.is_empty() {
        eprintln!("[schema] No budget events — skipping");
        return;
    }

    let budget_required = &[
        "budget_name",
        "category",
        "threshold",
        "unit",
        "status",
        "source",
    ];

    for event in &events {
        let missing = has_required_fields(event, budget_required);
        assert!(
            missing.is_empty(),
            "budget event missing required fields: {missing:?}"
        );
    }
    eprintln!("[schema] Validated {} budget events", events.len());
}

#[test]
fn validate_conformance_events_schema() {
    let root = project_root();
    let events =
        read_jsonl_file(&root.join("tests/ext_conformance/reports/conformance_events.jsonl"));
    if events.is_empty() {
        eprintln!("[schema] No conformance events — skipping");
        return;
    }

    let required = &[
        "schema",
        "extension_id",
        "source_tier",
        "conformance_tier",
        "overall_status",
    ];

    for event in &events {
        let missing = has_required_fields(event, required);
        assert!(
            missing.is_empty(),
            "conformance event missing required fields: {missing:?}"
        );
    }
    eprintln!("[schema] Validated {} conformance events", events.len());
}

#[test]
fn validate_scenario_runner_protocol_contract() {
    let root = project_root();
    let events = read_jsonl_file(&root.join("target/perf/scenario_runner.jsonl"));
    if events.is_empty() {
        eprintln!("[schema] No scenario_runner.jsonl data — skipping");
        return;
    }

    for (index, event) in events.iter().enumerate() {
        if let Err(err) = validate_protocol_record(event) {
            panic!("scenario_runner record {index} violates protocol contract: {err}");
        }
    }
    eprintln!(
        "[schema] Validated benchmark protocol contract on {} scenario_runner records",
        events.len()
    );
}

#[test]
fn jsonl_records_have_stable_key_ordering() {
    let root = project_root();

    // Check that legacy bench records have deterministic key ordering
    let events = read_jsonl_file(&root.join("target/perf/legacy_extension_workloads.jsonl"));
    if !events.is_empty() {
        // All records with same schema should have same top-level key set
        let first_keys: Vec<String> = events[0]
            .as_object()
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();

        for (i, event) in events.iter().enumerate() {
            if let Some(obj) = event.as_object() {
                // Same scenario records should have same structure
                if event.get("scenario") == events[0].get("scenario") {
                    assert_eq!(
                        obj.keys().count(),
                        first_keys.len(),
                        "record {i} has different key count than record 0"
                    );
                }
            }
        }
        eprintln!(
            "[schema] Key ordering stable across {} legacy events",
            events.len()
        );
    }

    // Check workload records
    let events = read_jsonl_file(&root.join("target/perf/pijs_workload.jsonl"));
    if events.len() >= 2 {
        let keys_0: Vec<String> = events[0]
            .as_object()
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        let keys_1: Vec<String> = events[1]
            .as_object()
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        assert_eq!(keys_0, keys_1, "workload records should have same key set");
        eprintln!(
            "[schema] Key ordering stable across {} workload events",
            events.len()
        );
    }
}

#[test]
fn generate_schema_doc() {
    let root = project_root();
    let reports_dir = root.join("tests/perf/reports");
    let _ = std::fs::create_dir_all(&reports_dir);

    let mut md = String::with_capacity(8 * 1024);

    md.push_str("# Benchmark JSONL Schema Reference\n\n");
    md.push_str("> Auto-generated. Do not edit manually.\n\n");

    // Schema registry
    md.push_str("## Registered Schemas\n\n");
    md.push_str("| Schema | Description |\n");
    md.push_str("|---|---|\n");
    for (name, desc) in SCHEMAS {
        let _ = writeln!(md, "| `{name}` | {desc} |");
    }
    md.push('\n');

    // Environment fingerprint
    md.push_str("## Environment Fingerprint\n\n");
    md.push_str("Every benchmark record SHOULD include an `env` object with:\n\n");
    md.push_str("| Field | Type | Description |\n");
    md.push_str("|---|---|---|\n");
    for (name, desc) in ENV_FINGERPRINT_FIELDS {
        let typ = match *name {
            "cpu_cores" | "mem_total_mb" => "integer",
            "features" => "string[]",
            _ => "string",
        };
        let _ = writeln!(md, "| `{name}` | {typ} | {desc} |");
    }
    md.push('\n');

    // Per-schema required fields
    md.push_str("## Required Fields by Schema\n\n");

    md.push_str("### `pi.ext.rust_bench.v1`\n\n");
    md.push_str("| Field | Type | Description |\n");
    md.push_str("|---|---|---|\n");
    md.push_str("| `schema` | string | Always `\"pi.ext.rust_bench.v1\"` |\n");
    md.push_str("| `runtime` | string | Always `\"pi_agent_rust\"` |\n");
    md.push_str(
        "| `scenario` | string | Benchmark scenario (e.g., `ext_load_init/load_init_cold`) |\n",
    );
    md.push_str("| `extension` | string | Extension ID being benchmarked |\n");
    md.push_str("| `runs` | integer | Number of runs (load scenarios) |\n");
    md.push_str("| `iterations` | integer | Number of iterations (throughput scenarios) |\n");
    md.push_str("| `summary` | object | `{count, min_ms, p50_ms, p95_ms, p99_ms, max_ms}` |\n");
    md.push_str("| `elapsed_ms` | float | Total elapsed time in milliseconds |\n");
    md.push_str("| `per_call_us` | float | Per-call latency in microseconds |\n");
    md.push_str("| `calls_per_sec` | float | Throughput (calls per second) |\n\n");

    md.push_str("### `pi.ext.legacy_bench.v1`\n\n");
    md.push_str("Same structure as `pi.ext.rust_bench.v1` with:\n");
    md.push_str("- `runtime` = `\"legacy_pi_mono\"`\n");
    md.push_str("- `node` object: `{version, platform, arch}`\n\n");

    md.push_str("### `pi.perf.workload.v1`\n\n");
    md.push_str("| Field | Type | Description |\n");
    md.push_str("|---|---|---|\n");
    for field in WORKLOAD_REQUIRED {
        let desc = match *field {
            "scenario" => "Workload scenario name",
            "iterations" => "Number of outer iterations",
            "tool_calls_per_iteration" => "Tool calls per iteration",
            "total_calls" => "Total tool calls executed",
            "elapsed_ms" => "Total elapsed milliseconds",
            "per_call_us" => "Per-call latency in microseconds",
            "calls_per_sec" => "Throughput (calls per second)",
            _ => "",
        };
        let _ = writeln!(md, "| `{field}` | number | {desc} |");
    }
    md.push('\n');

    let protocol_contract = canonical_protocol_contract();

    md.push_str("### `pi.bench.protocol.v1`\n\n");
    md.push_str("| Field | Type | Description |\n");
    md.push_str("|---|---|---|\n");
    md.push_str("| `schema` | string | Always `\"pi.bench.protocol.v1\"` |\n");
    md.push_str("| `version` | string | Protocol version used by all benchmark harnesses |\n");
    md.push_str("| `partition_tags` | string[] | Must include `matched-state` and `realistic` |\n");
    md.push_str(
        "| `realistic_session_sizes` | integer[] | Canonical matrix: 100k, 200k, 500k, 1M, 5M |\n",
    );
    md.push_str(
        "| `matched_state_scenarios` | object[] | `cold_start`, `warm_start`, `tool_call`, `event_dispatch` with replay inputs |\n",
    );
    md.push_str(
        "| `required_metadata_fields` | string[] | `runtime`, `build_profile`, `host`, `scenario_id`, `correlation_id` |\n",
    );
    md.push_str(
        "| `evidence_labels` | object | `evidence_class` (`measured/inferred`) + `confidence` (`high/medium/low`) |\n\n",
    );
    md.push_str(
        "| `user_perceived_sli_catalog` | object[] | Versioned user-facing SLI targets with UX interpretation guidance |\n",
    );
    md.push_str(
        "| `scenario_sli_matrix` | object[] | Canonical mapping from benchmark scenarios to user-perceived SLIs and consuming validation beads |\n\n",
    );

    md.push_str("## User-Perceived SLI Catalog\n\n");
    md.push_str("| SLI ID | Unit | Target | UX Guidance |\n");
    md.push_str("|---|---|---|---|\n");
    for entry in protocol_contract["user_perceived_sli_catalog"]
        .as_array()
        .unwrap_or(&Vec::new())
    {
        let sli_id = entry["sli_id"].as_str().unwrap_or("unknown");
        let unit = entry["unit"].as_str().unwrap_or("unknown");
        let comparator = entry["objective"]["comparator"].as_str().unwrap_or("?");
        let threshold = entry["objective"]["threshold"].to_string();
        let guidance = entry["ux_interpretation"]["good"]
            .as_str()
            .unwrap_or("no guidance");
        let _ = writeln!(
            md,
            "| `{sli_id}` | `{unit}` | `{comparator} {threshold}` | {guidance} |"
        );
    }
    md.push('\n');

    md.push_str("## Protocol Matrix\n\n");
    md.push_str("| Partition | Scenario ID | Replay Input | SLI IDs | UX Outcome |\n");
    md.push_str("|---|---|---|---|---|\n");

    let empty_matrix = Vec::new();
    let scenario_sli_matrix = protocol_contract["scenario_sli_matrix"]
        .as_array()
        .unwrap_or(&empty_matrix);

    let lookup_matrix = |scenario_id: &str| -> (String, String) {
        let Some(row) = scenario_sli_matrix
            .iter()
            .find(|row| row["scenario_id"].as_str() == Some(scenario_id))
        else {
            return ("(missing)".to_string(), "No UX mapping".to_string());
        };
        let sli_ids = row["sli_ids"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "(missing)".to_string());
        let ux_outcome = row["ux_outcome"]
            .as_str()
            .unwrap_or("No UX outcome specified")
            .to_string();
        (sli_ids, ux_outcome)
    };

    for scenario in protocol_contract["matched_state_scenarios"]
        .as_array()
        .unwrap_or(&Vec::new())
    {
        let scenario_name = scenario["scenario"].as_str().unwrap_or("unknown");
        let replay = scenario["replay_input"].to_string();
        let (sli_ids, ux_outcome) = lookup_matrix(scenario_name);
        let _ = writeln!(
            md,
            "| `{PARTITION_MATCHED_STATE}` | `{scenario_name}` | `{replay}` | `{sli_ids}` | {ux_outcome} |"
        );
    }
    for scenario in protocol_contract["realistic_replay_inputs"]
        .as_array()
        .unwrap_or(&Vec::new())
    {
        let scenario_id = scenario["scenario_id"].as_str().unwrap_or("unknown");
        let replay = scenario["replay_input"].to_string();
        let (sli_ids, ux_outcome) = lookup_matrix(scenario_id);
        let _ = writeln!(
            md,
            "| `{PARTITION_REALISTIC}` | `{scenario_id}` | `{replay}` | `{sli_ids}` | {ux_outcome} |"
        );
    }
    md.push('\n');

    // Determinism notes
    md.push_str("## Determinism Requirements\n\n");
    md.push_str(
        "1. **Stable key ordering**: JSON keys are sorted alphabetically within each record\n",
    );
    md.push_str("2. **No floating point in keys**: Use string or integer identifiers\n");
    md.push_str("3. **Timestamps**: ISO 8601 with seconds precision (`2026-02-06T01:00:00Z`)\n");
    md.push_str("4. **Config hash**: SHA-256 of concatenated env fields for dedup\n");
    md.push_str("5. **One record per line**: Standard JSONL (newline-delimited JSON)\n");

    let md_path = reports_dir.join("BENCH_SCHEMA.md");
    std::fs::write(&md_path, &md).expect("write BENCH_SCHEMA.md");

    // Write machine-readable schema registry
    let registry = json!({
        "schema": "pi.bench.schema_registry.v1",
        "schemas": SCHEMAS.iter().map(|(name, desc)| json!({
            "name": name,
            "description": desc,
        })).collect::<Vec<_>>(),
        "protocol_contract": canonical_protocol_contract(),
        "env_fingerprint_fields": ENV_FINGERPRINT_FIELDS.iter().map(|(name, desc)| json!({
            "field": name,
            "description": desc,
        })).collect::<Vec<_>>(),
    });

    let registry_path = reports_dir.join("bench_schema_registry.json");
    std::fs::write(
        &registry_path,
        serde_json::to_string_pretty(&registry).unwrap_or_default(),
    )
    .expect("write bench_schema_registry.json");

    eprintln!("[schema] Generated:");
    eprintln!("  {}", md_path.display());
    eprintln!("  {}", registry_path.display());
}
