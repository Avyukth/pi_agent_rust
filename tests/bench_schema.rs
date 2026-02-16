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
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
    (
        "pi.perf.extension_benchmark_stratification.v1",
        "Layered extension benchmark artifact linking cold-load, per-call, and full E2E evidence with claim-integrity guards",
    ),
    (
        "pi.perf.phase1_matrix_validation.v1",
        "Phase-1 realistic/matched-state matrix validation with stage attribution and release-gate readiness",
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
const PARTITION_WEIGHT_MATCHED_STATE: f64 = 0.3;
const PARTITION_WEIGHT_REALISTIC: f64 = 0.7;
const EVIDENCE_CLASS_MEASURED: &str = "measured";
const EVIDENCE_CLASS_INFERRED: &str = "inferred";
const CONFIDENCE_HIGH: &str = "high";
const CONFIDENCE_MEDIUM: &str = "medium";
const CONFIDENCE_LOW: &str = "low";
const EXT_STRATIFICATION_SCHEMA: &str = "pi.perf.extension_benchmark_stratification.v1";
const PHASE1_MATRIX_SCHEMA: &str = "pi.perf.phase1_matrix_validation.v1";
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

#[cfg(unix)]
fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pi-{prefix}-{nanos}"))
}

#[cfg(unix)]
fn write_executable(path: &Path, content: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, content).expect("write executable stub");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("set executable permission");
}

#[cfg(unix)]
#[allow(clippy::literal_string_with_formatting_args)] // bash ${VAR} syntax, not Rust fmt
fn install_fake_orchestrate_toolchain(bin_dir: &Path) {
    let cargo_stub = r#"#!/usr/bin/env bash
set -euo pipefail
target_dir="${CARGO_TARGET_DIR:-target}"
test_name=""
for ((i=1; i<=$#; i++)); do
  if [[ "${!i}" == "--test" ]]; then
    j=$((i+1))
    if [[ $j -le $# ]]; then
      test_name="${!j}"
    fi
  fi
done

mkdir -p "$target_dir/perf"

case "$test_name" in
  bench_scenario_runner)
    cat >"$target_dir/perf/scenario_runner.jsonl" <<'JSON'
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"cold_start","extension":"hello","stats":{"p95_ms":18.0},"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","partition":"matched-state","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"matched-state/cold_start","replay_input":{"runs":5}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"tool_call","extension":"hello","per_call_us":33.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","partition":"matched-state","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"matched-state/tool_call","replay_input":{"iterations":500}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"matched-state","open_ms":48.0,"append_ms":36.0,"save_ms":22.0,"index_ms":11.0,"total_ms":117.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"matched-state/session_100000","replay_input":{"session_messages":100000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"matched-state","open_ms":62.0,"append_ms":45.0,"save_ms":29.0,"index_ms":13.0,"total_ms":149.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"matched-state/session_200000","replay_input":{"session_messages":200000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"matched-state","open_ms":91.0,"append_ms":68.0,"save_ms":43.0,"index_ms":18.0,"total_ms":220.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"matched-state/session_500000","replay_input":{"session_messages":500000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"matched-state","open_ms":136.0,"append_ms":101.0,"save_ms":64.0,"index_ms":24.0,"total_ms":325.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"matched-state/session_1000000","replay_input":{"session_messages":1000000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"matched-state","open_ms":212.0,"append_ms":158.0,"save_ms":97.0,"index_ms":35.0,"total_ms":502.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"matched-state/session_5000000","replay_input":{"session_messages":5000000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"realistic","open_ms":44.0,"append_ms":32.0,"save_ms":19.0,"index_ms":10.0,"total_ms":105.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"realistic/session_100000","replay_input":{"session_messages":100000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"realistic","open_ms":57.0,"append_ms":41.0,"save_ms":25.0,"index_ms":12.0,"total_ms":135.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"realistic/session_200000","replay_input":{"session_messages":200000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"realistic","open_ms":84.0,"append_ms":61.0,"save_ms":37.0,"index_ms":16.0,"total_ms":198.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"realistic/session_500000","replay_input":{"session_messages":500000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"realistic","open_ms":124.0,"append_ms":90.0,"save_ms":54.0,"index_ms":21.0,"total_ms":289.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"realistic/session_1000000","replay_input":{"session_messages":1000000}}}
{"schema":"pi.ext.rust_bench.v1","runtime":"pi_agent_rust","scenario":"session_workload_matrix","extension":"core","partition":"realistic","open_ms":198.0,"append_ms":146.0,"save_ms":88.0,"index_ms":33.0,"total_ms":465.0,"protocol_schema":"pi.bench.protocol.v1","protocol_version":"1.0.0","evidence_class":"measured","confidence":"high","correlation_id":"stub-correlation","scenario_metadata":{"runtime":"pi_agent_rust","build_profile":"perf","host":{"os":"linux","arch":"x86_64","cpu_model":"stub","cpu_cores":8},"scenario_id":"realistic/session_5000000","replay_input":{"session_messages":5000000}}}
JSON
    cat >"$target_dir/perf/legacy_extension_workloads.jsonl" <<'JSON'
{"schema":"pi.ext.legacy_bench.v1","scenario":"ext_load_init/load_init_cold","extension":"hello","summary":{"p50_ms":10.0}}
{"schema":"pi.ext.legacy_bench.v1","scenario":"ext_tool_call/hello","extension":"hello","per_call_us":20.0}
JSON
    ;;
  ext_bench_harness)
    cat >"$target_dir/perf/ext_bench_harness.jsonl" <<'JSON'
{"schema":"pi.ext.rust_bench.v1","scenario":"cold_load","extension":"hello","success":true,"stats":{"p95_us":18000}}
JSON
    cat >"$target_dir/perf/ext_bench_harness_report.json" <<'JSON'
{"schema":"pi.bench.harness_report.v1","summary":{"total_scenarios":1}}
JSON
    ;;
  perf_bench_harness)
    cat >"$target_dir/perf/pijs_workload.jsonl" <<'JSON'
{"schema":"pi.perf.workload.v1","scenario":"200x10","iterations":200,"tool_calls_per_iteration":10,"total_calls":2000,"elapsed_ms":1200,"per_call_us":45,"calls_per_sec":1666}
JSON
    ;;
esac
exit 0
"#;
    write_executable(&bin_dir.join("cargo"), cargo_stub);
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
        "partition_weighting": {
            PARTITION_MATCHED_STATE: PARTITION_WEIGHT_MATCHED_STATE,
            PARTITION_REALISTIC: PARTITION_WEIGHT_REALISTIC,
            "weights_sum_to": 1.0,
        },
        "partition_interpretation": {
            "primary_partition": PARTITION_REALISTIC,
            "secondary_partition": PARTITION_MATCHED_STATE,
            "global_claim_requires_partitions": [PARTITION_MATCHED_STATE, PARTITION_REALISTIC],
            "forbid_single_partition_conclusion": true,
            "interpretation_notes": {
                PARTITION_MATCHED_STATE: "Use matched-state for controlled equivalence and attribution; do not generalize alone.",
                PARTITION_REALISTIC: "Use realistic workloads as primary user-impact evidence and release-facing performance narrative.",
            },
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

    let scenario_id = metadata
        .get("scenario_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if scenario_id.trim().is_empty() {
        return Err("scenario_metadata.scenario_id must be non-empty".to_string());
    }

    if partition == PARTITION_REALISTIC {
        if !scenario_id.starts_with("realistic/session_") {
            return Err(format!(
                "realistic partition requires scenario_id prefixed with realistic/session_: {scenario_id}"
            ));
        }
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
    } else {
        let matched_valid = [
            "cold_start",
            "warm_start",
            "tool_call",
            "event_dispatch",
            "matched-state/cold_start",
            "matched-state/warm_start",
            "matched-state/tool_call",
            "matched-state/event_dispatch",
        ];
        if !matched_valid.contains(&scenario_id) {
            return Err(format!(
                "matched-state partition requires canonical scenario_id, got: {scenario_id}"
            ));
        }
    }

    Ok(())
}

fn validate_extension_stratification_record(record: &Value) -> Result<(), String> {
    let required_top_level = [
        "schema",
        "run_id",
        "correlation_id",
        "layers",
        "claim_integrity",
        "lineage",
    ];
    let missing = has_required_fields(record, &required_top_level);
    if !missing.is_empty() {
        return Err(format!("missing required fields: {missing:?}"));
    }

    let schema = record
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if schema != EXT_STRATIFICATION_SCHEMA {
        return Err(format!("unexpected schema: {schema}"));
    }

    let layers = record
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| "layers must be an array".to_string())?;
    if layers.len() < 3 {
        return Err("layers must include cold-load, per-call, and full-e2e entries".to_string());
    }

    let mut layer_ids = HashSet::new();
    for layer in layers {
        let layer_obj = layer
            .as_object()
            .ok_or_else(|| "layer must be an object".to_string())?;
        for field in &[
            "layer_id",
            "display_name",
            "scenario_tags",
            "absolute_metrics",
            "relative_metrics",
            "confidence",
            "evidence_state",
            "lineage",
        ] {
            if !layer_obj.contains_key(*field) {
                return Err(format!("layer missing {field}"));
            }
        }
        let layer_id = layer_obj
            .get("layer_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if layer_id.trim().is_empty() {
            return Err("layer_id must be non-empty".to_string());
        }
        layer_ids.insert(layer_id.to_string());

        let scenario_tags = layer_obj
            .get("scenario_tags")
            .and_then(Value::as_array)
            .ok_or_else(|| "scenario_tags must be an array".to_string())?;
        if scenario_tags.is_empty() {
            return Err(format!("layer {layer_id} must include scenario_tags"));
        }

        let absolute_metrics = layer_obj
            .get("absolute_metrics")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("layer {layer_id} absolute_metrics must be object"))?;
        for field in &["metric_name", "unit"] {
            if !absolute_metrics.contains_key(*field) {
                return Err(format!("layer {layer_id} absolute_metrics missing {field}"));
            }
        }

        let relative_metrics = layer_obj
            .get("relative_metrics")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("layer {layer_id} relative_metrics must be object"))?;
        for field in &[
            "rust_vs_node_ratio",
            "rust_vs_node_ratio_basis",
            "rust_vs_bun_ratio",
            "rust_vs_bun_ratio_basis",
        ] {
            if !relative_metrics.contains_key(*field) {
                return Err(format!("layer {layer_id} relative_metrics missing {field}"));
            }
        }

        let lineage = layer_obj
            .get("lineage")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("layer {layer_id} lineage must be object"))?;
        let run_id_lineage = lineage
            .get("run_id_lineage")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("layer {layer_id} lineage.run_id_lineage must be array"))?;
        if run_id_lineage.len() < 2 {
            return Err(format!(
                "layer {layer_id} lineage.run_id_lineage must include run_id + correlation_id"
            ));
        }
    }

    for expected in &[
        "cold_load_init",
        "per_call_dispatch_micro",
        "full_e2e_long_session",
    ] {
        if !layer_ids.contains(*expected) {
            return Err(format!("missing required layer_id: {expected}"));
        }
    }

    let claim_integrity = record
        .get("claim_integrity")
        .and_then(Value::as_object)
        .ok_or_else(|| "claim_integrity must be an object".to_string())?;
    for field in &["anti_conflation", "cherry_pick_guard", "partition_coverage"] {
        if !claim_integrity.contains_key(*field) {
            return Err(format!("claim_integrity missing {field}"));
        }
    }
    let cherry_pick_guard = claim_integrity
        .get("cherry_pick_guard")
        .and_then(Value::as_object)
        .ok_or_else(|| "claim_integrity.cherry_pick_guard must be object".to_string())?;
    for field in &[
        "requires_all_layers_for_global_claim",
        "layer_coverage",
        "global_claim_valid",
        "invalidity_reasons",
    ] {
        if !cherry_pick_guard.contains_key(*field) {
            return Err(format!("claim_integrity.cherry_pick_guard missing {field}"));
        }
    }

    let lineage = record
        .get("lineage")
        .and_then(Value::as_object)
        .ok_or_else(|| "lineage must be an object".to_string())?;
    let top_level_run_id_lineage = lineage
        .get("run_id_lineage")
        .and_then(Value::as_array)
        .ok_or_else(|| "lineage.run_id_lineage must be an array".to_string())?;
    if top_level_run_id_lineage.len() < 2 {
        return Err("lineage.run_id_lineage must include run_id + correlation_id".to_string());
    }

    Ok(())
}

fn validate_phase1_matrix_validation_record(record: &Value) -> Result<(), String> {
    let required_top_level = [
        "schema",
        "run_id",
        "correlation_id",
        "matrix_requirements",
        "matrix_cells",
        "stage_summary",
        "primary_outcomes",
        "regression_guards",
        "evidence_links",
        "consumption_contract",
        "lineage",
    ];
    let missing = has_required_fields(record, &required_top_level);
    if !missing.is_empty() {
        return Err(format!("missing required fields: {missing:?}"));
    }

    let schema = record
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if schema != PHASE1_MATRIX_SCHEMA {
        return Err(format!("unexpected schema: {schema}"));
    }
    let run_id = record
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "run_id must be a string".to_string())?;
    if run_id.trim().is_empty() {
        return Err("run_id must be non-empty".to_string());
    }
    let correlation_id = record
        .get("correlation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "correlation_id must be a string".to_string())?;
    if correlation_id.trim().is_empty() {
        return Err("correlation_id must be non-empty".to_string());
    }

    let matrix_requirements = record
        .get("matrix_requirements")
        .and_then(Value::as_object)
        .ok_or_else(|| "matrix_requirements must be an object".to_string())?;
    for field in &[
        "required_partition_tags",
        "required_session_message_sizes",
        "required_cell_count",
    ] {
        if !matrix_requirements.contains_key(*field) {
            return Err(format!("matrix_requirements missing {field}"));
        }
    }
    let required_partition_tags = matrix_requirements
        .get("required_partition_tags")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "matrix_requirements.required_partition_tags must be an array".to_string()
        })?;
    if required_partition_tags.is_empty() {
        return Err("matrix_requirements.required_partition_tags must not be empty".to_string());
    }
    let mut required_partitions = HashSet::new();
    for partition in required_partition_tags {
        let partition = partition.as_str().ok_or_else(|| {
            "matrix_requirements.required_partition_tags entries must be strings".to_string()
        })?;
        if partition.trim().is_empty() {
            return Err(
                "matrix_requirements.required_partition_tags entries must be non-empty strings"
                    .to_string(),
            );
        }
        required_partitions.insert(partition.to_string());
    }
    if required_partitions.len() != required_partition_tags.len() {
        return Err(
            "matrix_requirements.required_partition_tags must not contain duplicates".to_string(),
        );
    }

    let required_session_message_sizes = matrix_requirements
        .get("required_session_message_sizes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "matrix_requirements.required_session_message_sizes must be an array".to_string()
        })?;
    if required_session_message_sizes.is_empty() {
        return Err(
            "matrix_requirements.required_session_message_sizes must not be empty".to_string(),
        );
    }
    let mut required_sizes = HashSet::new();
    for size in required_session_message_sizes {
        let size = size.as_u64().ok_or_else(|| {
            "matrix_requirements.required_session_message_sizes entries must be integers"
                .to_string()
        })?;
        if size == 0 {
            return Err(
                "matrix_requirements.required_session_message_sizes entries must be > 0"
                    .to_string(),
            );
        }
        required_sizes.insert(size);
    }
    if required_sizes.len() != required_session_message_sizes.len() {
        return Err(
            "matrix_requirements.required_session_message_sizes must not contain duplicates"
                .to_string(),
        );
    }

    let required_cell_count = matrix_requirements
        .get("required_cell_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "matrix_requirements.required_cell_count must be a positive integer".to_string()
        })?;
    if required_cell_count == 0 {
        return Err("matrix_requirements.required_cell_count must be > 0".to_string());
    }
    let max_unique_cells = required_partitions.len() as u64 * required_sizes.len() as u64;
    if required_cell_count > max_unique_cells {
        return Err(format!(
            "matrix_requirements.required_cell_count ({required_cell_count}) exceeds unique partition-size combinations ({max_unique_cells})"
        ));
    }

    let matrix_cells = record
        .get("matrix_cells")
        .and_then(Value::as_array)
        .ok_or_else(|| "matrix_cells must be an array".to_string())?;
    if matrix_cells.is_empty() {
        return Err("matrix_cells must not be empty".to_string());
    }
    if required_cell_count != matrix_cells.len() as u64 {
        return Err(format!(
            "matrix_requirements.required_cell_count ({required_cell_count}) does not match matrix_cells length ({})",
            matrix_cells.len()
        ));
    }
    let mut seen_partition_size_cells = HashSet::new();
    for cell in matrix_cells {
        let cell_obj = cell
            .as_object()
            .ok_or_else(|| "matrix cell must be an object".to_string())?;
        for field in &[
            "workload_partition",
            "session_messages",
            "scenario_id",
            "status",
            "stage_attribution",
            "primary_e2e",
            "lineage",
        ] {
            if !cell_obj.contains_key(*field) {
                return Err(format!("matrix cell missing {field}"));
            }
        }
        let workload_partition = cell_obj
            .get("workload_partition")
            .and_then(Value::as_str)
            .ok_or_else(|| "matrix cell workload_partition must be a string".to_string())?;
        if !required_partitions.contains(workload_partition) {
            return Err(format!(
                "matrix cell workload_partition '{workload_partition}' not listed in matrix_requirements.required_partition_tags"
            ));
        }
        let session_messages = cell_obj
            .get("session_messages")
            .and_then(Value::as_u64)
            .ok_or_else(|| "matrix cell session_messages must be an integer".to_string())?;
        if !required_sizes.contains(&session_messages) {
            return Err(format!(
                "matrix cell session_messages ({session_messages}) not listed in matrix_requirements.required_session_message_sizes"
            ));
        }
        let partition_size_key = (workload_partition.to_string(), session_messages);
        if !seen_partition_size_cells.insert(partition_size_key) {
            return Err(format!(
                "matrix cell duplicates partition-size key ({workload_partition}, {session_messages})"
            ));
        }

        let status = cell_obj
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !matches!(status, "pass" | "fail") {
            return Err(format!("matrix cell has invalid status: {status}"));
        }

        let stage = cell_obj
            .get("stage_attribution")
            .and_then(Value::as_object)
            .ok_or_else(|| "matrix cell stage_attribution must be object".to_string())?;
        for field in &[
            "open_ms",
            "append_ms",
            "save_ms",
            "index_ms",
            "total_stage_ms",
        ] {
            if !stage.contains_key(*field) {
                return Err(format!("matrix cell stage_attribution missing {field}"));
            }
        }

        let primary = cell_obj
            .get("primary_e2e")
            .and_then(Value::as_object)
            .ok_or_else(|| "matrix cell primary_e2e must be object".to_string())?;
        for field in &["wall_clock_ms", "rust_vs_node_ratio", "rust_vs_bun_ratio"] {
            if !primary.contains_key(*field) {
                return Err(format!("matrix cell primary_e2e missing {field}"));
            }
            // Only require positive values for passing cells; "fail" cells
            // may have null metrics when the underlying data is missing.
            if status == "pass" {
                let _ = require_positive_metric(primary, "matrix cell primary_e2e", field)?;
            }
        }
    }

    let stage_summary = record
        .get("stage_summary")
        .and_then(Value::as_object)
        .ok_or_else(|| "stage_summary must be an object".to_string())?;
    for field in &[
        "required_stage_keys",
        "operation_stage_coverage",
        "cells_with_complete_stage_breakdown",
        "cells_missing_stage_breakdown",
        "covered_cells",
        "missing_cells",
    ] {
        if !stage_summary.contains_key(*field) {
            return Err(format!("stage_summary missing {field}"));
        }
    }
    let covered_cells = stage_summary
        .get("covered_cells")
        .and_then(Value::as_u64)
        .ok_or_else(|| "stage_summary.covered_cells must be an integer".to_string())?;
    let complete_cells = stage_summary
        .get("cells_with_complete_stage_breakdown")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "stage_summary.cells_with_complete_stage_breakdown must be an integer".to_string()
        })?;
    let missing_cells_count = stage_summary
        .get("cells_missing_stage_breakdown")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "stage_summary.cells_missing_stage_breakdown must be an integer".to_string()
        })?;
    let missing_cells = stage_summary
        .get("missing_cells")
        .and_then(Value::as_array)
        .ok_or_else(|| "stage_summary.missing_cells must be an array".to_string())?;
    if complete_cells + missing_cells_count != matrix_cells.len() as u64 {
        return Err(format!(
            "stage_summary complete+missing ({complete_cells}+{missing_cells_count}) must equal matrix_cells length ({})",
            matrix_cells.len()
        ));
    }
    if covered_cells != complete_cells {
        return Err(format!(
            "stage_summary.covered_cells ({covered_cells}) must equal cells_with_complete_stage_breakdown ({complete_cells})"
        ));
    }
    if missing_cells.len() as u64 != missing_cells_count {
        return Err(format!(
            "stage_summary.missing_cells length ({}) must equal cells_missing_stage_breakdown ({missing_cells_count})",
            missing_cells.len()
        ));
    }

    let primary_outcomes = record
        .get("primary_outcomes")
        .and_then(Value::as_object)
        .ok_or_else(|| "primary_outcomes must be an object".to_string())?;
    for field in &[
        "status",
        "wall_clock_ms",
        "rust_vs_node_ratio",
        "rust_vs_bun_ratio",
        "ordering_policy",
    ] {
        if !primary_outcomes.contains_key(*field) {
            return Err(format!("primary_outcomes missing {field}"));
        }
    }
    let primary_status = primary_outcomes
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| "primary_outcomes.status must be a string".to_string())?;
    if !matches!(primary_status, "pass" | "fail") {
        return Err(format!(
            "primary_outcomes.status has invalid value: {primary_status}"
        ));
    }
    if primary_status == "pass" {
        for field in &["wall_clock_ms", "rust_vs_node_ratio", "rust_vs_bun_ratio"] {
            let _ = require_positive_metric(primary_outcomes, "primary_outcomes", field)?;
        }
    }
    let ordering_policy = primary_outcomes
        .get("ordering_policy")
        .and_then(Value::as_str)
        .ok_or_else(|| "primary_outcomes.ordering_policy must be a string".to_string())?;
    if ordering_policy != "primary_e2e_before_microbench" {
        return Err(format!(
            "primary_outcomes.ordering_policy must be 'primary_e2e_before_microbench', got: {ordering_policy}"
        ));
    }

    let regression_guards = record
        .get("regression_guards")
        .and_then(Value::as_object)
        .ok_or_else(|| "regression_guards must be an object".to_string())?;
    for field in &["memory", "correctness", "security"] {
        if !regression_guards.contains_key(*field) {
            return Err(format!("regression_guards missing {field}"));
        }
    }

    let consumption_contract = record
        .get("consumption_contract")
        .and_then(Value::as_object)
        .ok_or_else(|| "consumption_contract must be an object".to_string())?;
    if !consumption_contract.contains_key("artifact_ready_for_phase5") {
        return Err("consumption_contract missing artifact_ready_for_phase5".to_string());
    }

    let lineage = record
        .get("lineage")
        .and_then(Value::as_object)
        .ok_or_else(|| "lineage must be an object".to_string())?;
    let run_id_lineage = lineage
        .get("run_id_lineage")
        .and_then(Value::as_array)
        .ok_or_else(|| "lineage.run_id_lineage must be an array".to_string())?;
    if run_id_lineage.len() < 2 {
        return Err("lineage.run_id_lineage must include run_id + correlation_id".to_string());
    }
    let lineage_run_id = run_id_lineage
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| "lineage.run_id_lineage[0] must be run_id string".to_string())?;
    if lineage_run_id != run_id {
        return Err(format!(
            "lineage.run_id_lineage[0] ({lineage_run_id}) must match run_id ({run_id})"
        ));
    }
    let lineage_correlation_id = run_id_lineage
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| "lineage.run_id_lineage[1] must be correlation_id string".to_string())?;
    if lineage_correlation_id != correlation_id {
        return Err(format!(
            "lineage.run_id_lineage[1] ({lineage_correlation_id}) must match correlation_id ({correlation_id})"
        ));
    }

    Ok(())
}

fn require_positive_metric(
    obj: &serde_json::Map<String, Value>,
    context: &str,
    field: &str,
) -> Result<f64, String> {
    let value = obj
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("{context}.{field} must be a positive finite number"))?;
    if !value.is_finite() || value <= 0.0 {
        return Err(format!(
            "{context}.{field} must be a positive finite number, got: {value}"
        ));
    }
    Ok(value)
}

fn phase1_matrix_validation_golden_fixture() -> Value {
    json!({
        "schema": PHASE1_MATRIX_SCHEMA,
        "run_id": "20260216T010101Z",
        "correlation_id": "abc123def456",
        "matrix_requirements": {
            "required_partition_tags": ["matched-state", "realistic"],
            "required_session_message_sizes": [100_000, 200_000, 500_000, 1_000_000, 5_000_000],
            "required_cell_count": 2
        },
        "matrix_cells": [
            {
                "workload_partition": "matched-state",
                "session_messages": 100_000,
                "scenario_id": "matched-state/session_100000",
                "status": "pass",
                "missing_reasons": [],
                "stage_attribution": {
                    "open_ms": 48.0,
                    "append_ms": 36.0,
                    "save_ms": 22.0,
                    "index_ms": 11.0,
                    "total_stage_ms": 117.0
                },
                "primary_e2e": {
                    "wall_clock_ms": 1200.0,
                    "rust_vs_node_ratio": 2.2,
                    "rust_vs_bun_ratio": 2.2
                },
                "microbench_context": {
                    "cold_load_ms": 18.0,
                    "per_call_us": 33.0
                },
                "lineage": {
                    "source_record_index": 2,
                    "source_artifacts": ["target/perf/scenario_runner.jsonl"]
                }
            },
            {
                "workload_partition": "realistic",
                "session_messages": 100_000,
                "scenario_id": "realistic/session_100000",
                "status": "pass",
                "missing_reasons": [],
                "stage_attribution": {
                    "open_ms": 44.0,
                    "append_ms": 32.0,
                    "save_ms": 19.0,
                    "index_ms": 10.0,
                    "total_stage_ms": 105.0
                },
                "primary_e2e": {
                    "wall_clock_ms": 1200.0,
                    "rust_vs_node_ratio": 2.2,
                    "rust_vs_bun_ratio": 2.2
                },
                "microbench_context": {
                    "cold_load_ms": 18.0,
                    "per_call_us": 33.0
                },
                "lineage": {
                    "source_record_index": 7,
                    "source_artifacts": ["target/perf/scenario_runner.jsonl"]
                }
            }
        ],
        "stage_summary": {
            "required_stage_keys": ["open_ms", "append_ms", "save_ms", "index_ms"],
            "operation_stage_coverage": {
                "open_ms": 2,
                "append_ms": 2,
                "save_ms": 2,
                "index_ms": 2
            },
            "cells_with_complete_stage_breakdown": 2,
            "cells_missing_stage_breakdown": 0,
            "covered_cells": 2,
            "missing_cells": []
        },
        "primary_outcomes": {
            "status": "pass",
            "wall_clock_ms": 1200.0,
            "rust_vs_node_ratio": 2.2,
            "rust_vs_bun_ratio": 2.2,
            "ordering_policy": "primary_e2e_before_microbench"
        },
        "regression_guards": {
            "memory": "pass",
            "correctness": "pass",
            "security": "pass",
            "failure_or_gap_reasons": []
        },
        "evidence_links": {
            "phase1_unit_and_fault_injection": {
                "suite_logs": {},
                "fault_injection_script": "scripts/e2e/run_persistence_fault_injection.sh",
                "fault_injection_summary_path": null
            },
            "required_artifacts": {
                "scenario_runner": "target/perf/scenario_runner.jsonl",
                "stratification": "target/perf/extension_benchmark_stratification.json",
                "baseline_variance_confidence": "target/perf/baseline_variance_confidence.json"
            }
        },
        "consumption_contract": {
            "downstream_beads": ["bd-3ar8v.2.12"],
            "artifact_ready_for_phase5": true,
            "fail_closed_conditions": ["missing_stage_metrics"]
        },
        "lineage": {
            "run_id_lineage": ["20260216T010101Z", "abc123def456"],
            "source_manifest_path": "target/perf/runs/20260216T010101Z/manifest.json"
        }
    })
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
fn protocol_contract_defines_partition_weighting_and_guardrails() {
    let contract = canonical_protocol_contract();

    let matched_weight = contract["partition_weighting"][PARTITION_MATCHED_STATE]
        .as_f64()
        .expect("matched-state weight");
    let realistic_weight = contract["partition_weighting"][PARTITION_REALISTIC]
        .as_f64()
        .expect("realistic weight");
    let weights_sum_to = contract["partition_weighting"]["weights_sum_to"]
        .as_f64()
        .expect("weights_sum_to");
    assert!((weights_sum_to - 1.0).abs() < f64::EPSILON);
    assert!(
        ((matched_weight + realistic_weight) - weights_sum_to).abs() < f64::EPSILON,
        "partition weights must sum to 1.0"
    );
    assert!(
        realistic_weight > matched_weight,
        "realistic partition should carry higher release-facing weight"
    );

    assert_eq!(
        contract["partition_interpretation"]["primary_partition"].as_str(),
        Some(PARTITION_REALISTIC)
    );
    assert_eq!(
        contract["partition_interpretation"]["secondary_partition"].as_str(),
        Some(PARTITION_MATCHED_STATE)
    );
    assert_eq!(
        contract["partition_interpretation"]["forbid_single_partition_conclusion"].as_bool(),
        Some(true)
    );

    let required_partitions =
        contract["partition_interpretation"]["global_claim_requires_partitions"]
            .as_array()
            .expect("global_claim_requires_partitions array");
    let required: HashSet<&str> = required_partitions
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        required.contains(PARTITION_MATCHED_STATE) && required.contains(PARTITION_REALISTIC),
        "global claim rules must require both partitions"
    );
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
fn extension_stratification_validator_accepts_golden_fixture() {
    let golden = json!({
        "schema": EXT_STRATIFICATION_SCHEMA,
        "run_id": "20260216T010101Z",
        "correlation_id": "abc123def456",
        "layers": [
            {
                "layer_id": "cold_load_init",
                "display_name": "Cold-load and initialization",
                "scenario_tags": ["cold-load", "init", "microbench"],
                "absolute_metrics": {"metric_name": "cold_load_p95", "value": 12.4, "unit": "ms"},
                "relative_metrics": {
                    "rust_vs_node_ratio": 1.8,
                    "rust_vs_node_ratio_basis": "direct_or_derived",
                    "rust_vs_bun_ratio": 1.8,
                    "rust_vs_bun_ratio_basis": "node_proxy"
                },
                "confidence": CONFIDENCE_MEDIUM,
                "evidence_state": EVIDENCE_CLASS_INFERRED,
                "lineage": {
                    "run_id_lineage": ["20260216T010101Z", "abc123def456"],
                    "source_artifacts": ["target/perf/ext_bench_harness.jsonl"],
                    "suite_logs": {},
                    "source_manifest_path": "target/perf/runs/20260216T010101Z/manifest.json"
                }
            },
            {
                "layer_id": "per_call_dispatch_micro",
                "display_name": "Per-call dispatch microbench",
                "scenario_tags": ["per-call", "dispatch", "microbench"],
                "absolute_metrics": {"metric_name": "dispatch_per_call", "value": 42.0, "unit": "us"},
                "relative_metrics": {
                    "rust_vs_node_ratio": 1.2,
                    "rust_vs_node_ratio_basis": "direct_or_derived",
                    "rust_vs_bun_ratio": 1.2,
                    "rust_vs_bun_ratio_basis": "node_proxy"
                },
                "confidence": CONFIDENCE_HIGH,
                "evidence_state": EVIDENCE_CLASS_MEASURED,
                "lineage": {
                    "run_id_lineage": ["20260216T010101Z", "abc123def456"],
                    "source_artifacts": ["target/perf/scenario_runner.jsonl"],
                    "suite_logs": {},
                    "source_manifest_path": "target/perf/runs/20260216T010101Z/manifest.json"
                }
            },
            {
                "layer_id": "full_e2e_long_session",
                "display_name": "Full end-to-end long-session workload",
                "scenario_tags": ["full-e2e", "long-session", "release-facing"],
                "absolute_metrics": {"metric_name": "long_session_elapsed", "value": 950.0, "unit": "ms"},
                "relative_metrics": {
                    "rust_vs_node_ratio": null,
                    "rust_vs_node_ratio_basis": "missing",
                    "rust_vs_bun_ratio": null,
                    "rust_vs_bun_ratio_basis": "missing"
                },
                "confidence": CONFIDENCE_LOW,
                "evidence_state": "absolute_only",
                "lineage": {
                    "run_id_lineage": ["20260216T010101Z", "abc123def456"],
                    "source_artifacts": ["target/perf/pijs_workload.jsonl"],
                    "suite_logs": {},
                    "source_manifest_path": "target/perf/runs/20260216T010101Z/manifest.json"
                }
            }
        ],
        "claim_integrity": {
            "anti_conflation": {
                "cold_load_wins_do_not_imply_per_call_or_e2e": true,
                "per_call_wins_do_not_imply_full_e2e": true,
                "full_e2e_is_release_facing_primary_signal": true
            },
            "cherry_pick_guard": {
                "requires_all_layers_for_global_claim": true,
                "layer_coverage": {
                    "cold_load_init": true,
                    "per_call_dispatch_micro": true,
                    "full_e2e_long_session": false
                },
                "global_claim_valid": false,
                "invalidity_reasons": ["missing_layer_coverage:full_e2e_long_session"]
            },
            "partition_coverage": {"matched-state": true, "realistic": false}
        },
        "lineage": {
            "run_id_lineage": ["20260216T010101Z", "abc123def456"],
            "source_manifest_path": "target/perf/runs/20260216T010101Z/manifest.json"
        }
    });

    assert!(
        validate_extension_stratification_record(&golden).is_ok(),
        "golden extension stratification fixture should pass validation"
    );
}

#[test]
fn extension_stratification_validator_rejects_missing_claim_integrity() {
    let malformed = json!({
        "schema": EXT_STRATIFICATION_SCHEMA,
        "run_id": "20260216T010101Z",
        "correlation_id": "abc123def456",
        "layers": [],
        "lineage": { "run_id_lineage": ["20260216T010101Z", "abc123def456"] }
    });

    let err = validate_extension_stratification_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("claim_integrity"),
        "expected missing claim_integrity failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_accepts_golden_fixture() {
    let golden = phase1_matrix_validation_golden_fixture();

    assert!(
        validate_phase1_matrix_validation_record(&golden).is_ok(),
        "golden phase1 matrix fixture should pass validation"
    );
}

#[test]
fn phase1_matrix_validator_rejects_non_numeric_primary_e2e_metric() {
    let mut malformed = phase1_matrix_validation_golden_fixture();
    malformed["matrix_cells"][0]["primary_e2e"]["wall_clock_ms"] = json!("1200ms");

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("matrix cell primary_e2e.wall_clock_ms"),
        "expected primary_e2e wall_clock type failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_non_positive_primary_outcomes_ratio() {
    let mut malformed = phase1_matrix_validation_golden_fixture();
    malformed["primary_outcomes"]["rust_vs_bun_ratio"] = json!(0.0);

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("primary_outcomes.rust_vs_bun_ratio"),
        "expected primary_outcomes ratio positivity failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_missing_stage_attribution() {
    let malformed = json!({
        "schema": PHASE1_MATRIX_SCHEMA,
        "run_id": "20260216T010101Z",
        "correlation_id": "abc123def456",
        "matrix_requirements": {
            "required_partition_tags": ["matched-state", "realistic"],
            "required_session_message_sizes": [100_000],
            "required_cell_count": 1
        },
        "matrix_cells": [
            {
                "workload_partition": "matched-state",
                "session_messages": 100_000,
                "scenario_id": "matched-state/session_100000",
                "status": "pass",
                "primary_e2e": {
                    "wall_clock_ms": 1200.0,
                    "rust_vs_node_ratio": 2.2,
                    "rust_vs_bun_ratio": 2.2
                },
                "lineage": {
                    "source_record_index": 0,
                    "source_artifacts": []
                }
            }
        ],
        "stage_summary": {
            "required_stage_keys": ["open_ms", "append_ms", "save_ms", "index_ms"],
            "operation_stage_coverage": {"open_ms": 1, "append_ms": 1, "save_ms": 1, "index_ms": 1},
            "cells_with_complete_stage_breakdown": 1,
            "cells_missing_stage_breakdown": 0,
            "covered_cells": 1,
            "missing_cells": []
        },
        "primary_outcomes": {
            "status": "pass",
            "wall_clock_ms": 1200.0,
            "rust_vs_node_ratio": 2.2,
            "rust_vs_bun_ratio": 2.2,
            "ordering_policy": "primary_e2e_before_microbench"
        },
        "regression_guards": {
            "memory": "pass",
            "correctness": "pass",
            "security": "pass"
        },
        "evidence_links": {
            "phase1_unit_and_fault_injection": {},
            "required_artifacts": {}
        },
        "consumption_contract": {
            "artifact_ready_for_phase5": false
        },
        "lineage": {
            "run_id_lineage": ["20260216T010101Z", "abc123def456"]
        }
    });

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("stage_attribution"),
        "expected stage_attribution validation failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_required_cell_count_mismatch() {
    let malformed = json!({
        "schema": PHASE1_MATRIX_SCHEMA,
        "run_id": "20260216T010101Z",
        "correlation_id": "abc123def456",
        "matrix_requirements": {
            "required_partition_tags": ["matched-state", "realistic"],
            "required_session_message_sizes": [100_000],
            "required_cell_count": 2
        },
        "matrix_cells": [
            {
                "workload_partition": "matched-state",
                "session_messages": 100_000,
                "scenario_id": "matched-state/session_100000",
                "status": "pass",
                "stage_attribution": {
                    "open_ms": 48.0,
                    "append_ms": 36.0,
                    "save_ms": 22.0,
                    "index_ms": 11.0,
                    "total_stage_ms": 117.0
                },
                "primary_e2e": {
                    "wall_clock_ms": 1200.0,
                    "rust_vs_node_ratio": 2.2,
                    "rust_vs_bun_ratio": 2.2
                },
                "lineage": {
                    "source_record_index": 0,
                    "source_artifacts": []
                }
            }
        ],
        "stage_summary": {
            "required_stage_keys": ["open_ms", "append_ms", "save_ms", "index_ms"],
            "operation_stage_coverage": {"open_ms": 1, "append_ms": 1, "save_ms": 1, "index_ms": 1},
            "cells_with_complete_stage_breakdown": 1,
            "cells_missing_stage_breakdown": 0,
            "covered_cells": 1,
            "missing_cells": []
        },
        "primary_outcomes": {
            "status": "pass",
            "wall_clock_ms": 1200.0,
            "rust_vs_node_ratio": 2.2,
            "rust_vs_bun_ratio": 2.2,
            "ordering_policy": "primary_e2e_before_microbench"
        },
        "regression_guards": {
            "memory": "pass",
            "correctness": "pass",
            "security": "pass"
        },
        "evidence_links": {
            "phase1_unit_and_fault_injection": {},
            "required_artifacts": {}
        },
        "consumption_contract": {
            "artifact_ready_for_phase5": false
        },
        "lineage": {
            "run_id_lineage": ["20260216T010101Z", "abc123def456"]
        }
    });

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("required_cell_count"),
        "expected required_cell_count mismatch failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_stage_summary_count_mismatch() {
    let malformed = json!({
        "schema": PHASE1_MATRIX_SCHEMA,
        "run_id": "20260216T010101Z",
        "correlation_id": "abc123def456",
        "matrix_requirements": {
            "required_partition_tags": ["matched-state", "realistic"],
            "required_session_message_sizes": [100_000],
            "required_cell_count": 1
        },
        "matrix_cells": [
            {
                "workload_partition": "matched-state",
                "session_messages": 100_000,
                "scenario_id": "matched-state/session_100000",
                "status": "pass",
                "stage_attribution": {
                    "open_ms": 48.0,
                    "append_ms": 36.0,
                    "save_ms": 22.0,
                    "index_ms": 11.0,
                    "total_stage_ms": 117.0
                },
                "primary_e2e": {
                    "wall_clock_ms": 1200.0,
                    "rust_vs_node_ratio": 2.2,
                    "rust_vs_bun_ratio": 2.2
                },
                "lineage": {
                    "source_record_index": 0,
                    "source_artifacts": []
                }
            }
        ],
        "stage_summary": {
            "required_stage_keys": ["open_ms", "append_ms", "save_ms", "index_ms"],
            "operation_stage_coverage": {"open_ms": 1, "append_ms": 1, "save_ms": 1, "index_ms": 1},
            "cells_with_complete_stage_breakdown": 0,
            "cells_missing_stage_breakdown": 0,
            "covered_cells": 0,
            "missing_cells": []
        },
        "primary_outcomes": {
            "status": "pass",
            "wall_clock_ms": 1200.0,
            "rust_vs_node_ratio": 2.2,
            "rust_vs_bun_ratio": 2.2,
            "ordering_policy": "primary_e2e_before_microbench"
        },
        "regression_guards": {
            "memory": "pass",
            "correctness": "pass",
            "security": "pass"
        },
        "evidence_links": {
            "phase1_unit_and_fault_injection": {},
            "required_artifacts": {}
        },
        "consumption_contract": {
            "artifact_ready_for_phase5": false
        },
        "lineage": {
            "run_id_lineage": ["20260216T010101Z", "abc123def456"]
        }
    });

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("stage_summary complete+missing"),
        "expected stage_summary mismatch failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_non_primary_ordering_policy() {
    let malformed = json!({
        "schema": PHASE1_MATRIX_SCHEMA,
        "run_id": "20260216T010101Z",
        "correlation_id": "abc123def456",
        "matrix_requirements": {
            "required_partition_tags": ["matched-state", "realistic"],
            "required_session_message_sizes": [100_000],
            "required_cell_count": 1
        },
        "matrix_cells": [
            {
                "workload_partition": "matched-state",
                "session_messages": 100_000,
                "scenario_id": "matched-state/session_100000",
                "status": "pass",
                "stage_attribution": {
                    "open_ms": 48.0,
                    "append_ms": 36.0,
                    "save_ms": 22.0,
                    "index_ms": 11.0,
                    "total_stage_ms": 117.0
                },
                "primary_e2e": {
                    "wall_clock_ms": 1200.0,
                    "rust_vs_node_ratio": 2.2,
                    "rust_vs_bun_ratio": 2.2
                },
                "lineage": {
                    "source_record_index": 0,
                    "source_artifacts": []
                }
            }
        ],
        "stage_summary": {
            "required_stage_keys": ["open_ms", "append_ms", "save_ms", "index_ms"],
            "operation_stage_coverage": {"open_ms": 1, "append_ms": 1, "save_ms": 1, "index_ms": 1},
            "cells_with_complete_stage_breakdown": 1,
            "cells_missing_stage_breakdown": 0,
            "covered_cells": 1,
            "missing_cells": []
        },
        "primary_outcomes": {
            "status": "pass",
            "wall_clock_ms": 1200.0,
            "rust_vs_node_ratio": 2.2,
            "rust_vs_bun_ratio": 2.2,
            "ordering_policy": "microbench_before_primary_e2e"
        },
        "regression_guards": {
            "memory": "pass",
            "correctness": "pass",
            "security": "pass"
        },
        "evidence_links": {
            "phase1_unit_and_fault_injection": {},
            "required_artifacts": {}
        },
        "consumption_contract": {
            "artifact_ready_for_phase5": false
        },
        "lineage": {
            "run_id_lineage": ["20260216T010101Z", "abc123def456"]
        }
    });

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("ordering_policy"),
        "expected ordering policy failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_required_cell_count_exceeding_partition_size_space() {
    let mut malformed = phase1_matrix_validation_golden_fixture();
    malformed["matrix_requirements"]["required_partition_tags"] = json!(["matched-state"]);
    malformed["matrix_requirements"]["required_session_message_sizes"] = json!([100_000]);
    malformed["matrix_requirements"]["required_cell_count"] = json!(2);

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("exceeds unique partition-size combinations"),
        "expected partition/size cardinality failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_duplicate_partition_size_cells() {
    let mut malformed = phase1_matrix_validation_golden_fixture();
    malformed["matrix_requirements"]["required_partition_tags"] =
        json!(["matched-state", "realistic"]);
    malformed["matrix_requirements"]["required_session_message_sizes"] = json!([100_000]);
    malformed["matrix_requirements"]["required_cell_count"] = json!(2);
    malformed["matrix_cells"][1]["workload_partition"] = json!("matched-state");
    malformed["matrix_cells"][1]["scenario_id"] = json!("matched-state/session_100000_dup");

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("duplicates partition-size key"),
        "expected duplicate partition-size cell failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_cell_partition_not_in_requirements() {
    let mut malformed = phase1_matrix_validation_golden_fixture();
    malformed["matrix_requirements"]["required_partition_tags"] =
        json!(["matched-state", "realistic"]);
    malformed["matrix_requirements"]["required_session_message_sizes"] = json!([100_000]);
    malformed["matrix_requirements"]["required_cell_count"] = json!(2);
    malformed["matrix_cells"][0]["workload_partition"] = json!("experimental");

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("workload_partition 'experimental'"),
        "expected unknown partition failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_empty_run_id() {
    let mut malformed = phase1_matrix_validation_golden_fixture();
    malformed["run_id"] = json!(" ");

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("run_id must be non-empty"),
        "expected non-empty run_id failure, got: {err}"
    );
}

#[test]
fn phase1_matrix_validator_rejects_lineage_mismatch_with_top_level_ids() {
    let mut malformed = phase1_matrix_validation_golden_fixture();
    malformed["lineage"]["run_id_lineage"][0] = json!("other-run");

    let err = validate_phase1_matrix_validation_record(&malformed).expect_err("fixture must fail");
    assert!(
        err.contains("must match run_id"),
        "expected lineage/run_id mismatch failure, got: {err}"
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
    assert!(
        required_fields.contains(&"partition_weighting"),
        "benchmark protocol schema must require partition_weighting"
    );
    assert!(
        required_fields.contains(&"partition_interpretation"),
        "benchmark protocol schema must require partition_interpretation"
    );

    assert_eq!(
        benchmark_protocol["properties"]["partition_interpretation"]["properties"]
            ["forbid_single_partition_conclusion"]["const"]
            .as_bool(),
        Some(true),
        "schema must enforce no single-partition release conclusion"
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
fn orchestrate_script_emits_extension_stratification_contract() {
    let script_path = project_root().join("scripts/perf/orchestrate.sh");
    let content = fs::read_to_string(&script_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", script_path.display()));

    for token in &[
        "extension_benchmark_stratification.json",
        EXT_STRATIFICATION_SCHEMA,
        "\"cold_load_init\"",
        "\"per_call_dispatch_micro\"",
        "\"full_e2e_long_session\"",
        "microbench_only_claim",
        "global_claim_missing_partition_coverage",
    ] {
        assert!(
            content.contains(token),
            "orchestrate stratification phase must include token: {token}"
        );
    }
}

#[test]
fn orchestrate_script_emits_phase1_matrix_validation_contract() {
    let script_path = project_root().join("scripts/perf/orchestrate.sh");
    let content = fs::read_to_string(&script_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", script_path.display()));

    for token in &[
        "phase1_matrix_validation.json",
        PHASE1_MATRIX_SCHEMA,
        "\"required_session_message_sizes\"",
        "\"cells_with_complete_stage_breakdown\"",
        "\"primary_e2e_before_microbench\"",
        "\"artifact_ready_for_phase5\"",
    ] {
        assert!(
            content.contains(token),
            "orchestrate phase-1 matrix phase must include token: {token}"
        );
    }
}

#[cfg(unix)]
fn run_orchestrate_with_fake_toolchain() -> (std::process::Output, PathBuf) {
    let temp_root = unique_temp_dir("orchestrate-stratification");
    let bin_dir = temp_root.join("bin");
    let target_dir = temp_root.join("target");
    let output_dir = temp_root.join("run");

    fs::create_dir_all(&bin_dir).expect("create bin dir");
    fs::create_dir_all(&target_dir).expect("create target dir");
    fs::create_dir_all(&output_dir).expect("create output dir");
    install_fake_orchestrate_toolchain(&bin_dir);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("bash")
        .arg("scripts/perf/orchestrate.sh")
        .arg("--profile")
        .arg("full")
        .arg("--skip-build")
        .arg("--skip-env-check")
        .current_dir(project_root())
        .env("PATH", path)
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("PERF_OUTPUT_DIR", &output_dir)
        .env("PERF_SKIP_CRITERION", "1")
        .output()
        .expect("run orchestrate.sh");

    (output, temp_root)
}

#[cfg(unix)]
#[test]
fn orchestrate_generates_extension_stratification_artifact() {
    let (output, temp_root) = run_orchestrate_with_fake_toolchain();
    assert!(
        output.status.success(),
        "orchestrate.sh should succeed with stub toolchain. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output_dir = temp_root.join("run");
    let manifest_path = output_dir.join("manifest.json");
    let stratification_path = output_dir
        .join("results")
        .join("extension_benchmark_stratification.json");

    assert!(
        stratification_path.exists(),
        "stratification artifact must be written: {}",
        stratification_path.display()
    );
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest.json"))
            .expect("parse manifest.json");
    let stratification: Value = serde_json::from_str(
        &fs::read_to_string(&stratification_path)
            .expect("read extension_benchmark_stratification.json"),
    )
    .expect("parse extension_benchmark_stratification.json");

    if let Err(err) = validate_extension_stratification_record(&stratification) {
        panic!("stratification artifact violates schema contract: {err}");
    }

    assert_eq!(
        stratification.get("schema").and_then(Value::as_str),
        Some(EXT_STRATIFICATION_SCHEMA)
    );
    assert_eq!(
        stratification.get("run_id").and_then(Value::as_str),
        manifest.get("timestamp").and_then(Value::as_str),
        "stratification run_id must match manifest timestamp"
    );
    assert_eq!(
        stratification.get("correlation_id").and_then(Value::as_str),
        manifest.get("correlation_id").and_then(Value::as_str),
        "stratification correlation_id must match manifest"
    );
    let run_id_lineage = stratification["lineage"]["run_id_lineage"]
        .as_array()
        .expect("lineage.run_id_lineage array");
    assert_eq!(
        run_id_lineage[0].as_str(),
        manifest.get("timestamp").and_then(Value::as_str),
        "lineage[0] must be manifest timestamp"
    );
    assert_eq!(
        run_id_lineage[1].as_str(),
        manifest.get("correlation_id").and_then(Value::as_str),
        "lineage[1] must be manifest correlation_id"
    );

    assert_eq!(
        manifest["extension_benchmark_stratification"]["schema"].as_str(),
        Some(EXT_STRATIFICATION_SCHEMA),
        "manifest must reference stratification schema"
    );
    assert!(
        stratification["claim_integrity"]["anti_conflation"]
            ["cold_load_wins_do_not_imply_per_call_or_e2e"]
            .as_bool()
            .is_some_and(|v| v),
        "anti-conflation guardrail must be explicit in claim_integrity"
    );

    let _ = fs::remove_dir_all(temp_root);
}

#[cfg(unix)]
#[test]
fn orchestrate_generates_phase1_matrix_validation_artifact() {
    let (output, temp_root) = run_orchestrate_with_fake_toolchain();
    assert!(
        output.status.success(),
        "orchestrate.sh should succeed with stub toolchain. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output_dir = temp_root.join("run");
    let manifest_path = output_dir.join("manifest.json");
    let matrix_path = output_dir
        .join("results")
        .join("phase1_matrix_validation.json");

    assert!(
        matrix_path.exists(),
        "phase-1 matrix artifact must be written: {}",
        matrix_path.display()
    );

    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest.json"))
            .expect("parse manifest.json");
    let matrix: Value =
        serde_json::from_str(&fs::read_to_string(&matrix_path).expect("read matrix artifact"))
            .expect("parse matrix artifact");

    if let Err(err) = validate_phase1_matrix_validation_record(&matrix) {
        panic!("phase1 matrix artifact violates schema contract: {err}");
    }

    assert_eq!(
        matrix.get("schema").and_then(Value::as_str),
        Some(PHASE1_MATRIX_SCHEMA)
    );
    assert_eq!(
        matrix.get("run_id").and_then(Value::as_str),
        manifest.get("timestamp").and_then(Value::as_str),
        "phase1 run_id must match manifest timestamp"
    );
    assert_eq!(
        matrix.get("correlation_id").and_then(Value::as_str),
        manifest.get("correlation_id").and_then(Value::as_str),
        "phase1 correlation_id must match manifest"
    );

    assert_eq!(
        manifest["phase1_matrix_validation"]["schema"].as_str(),
        Some(PHASE1_MATRIX_SCHEMA),
        "manifest must reference phase1 matrix schema"
    );
    assert_eq!(
        matrix["matrix_requirements"]["required_cell_count"].as_u64(),
        Some(10),
        "phase1 matrix should require 10 partition/size cells"
    );
    assert_eq!(
        matrix["stage_summary"]["cells_with_complete_stage_breakdown"].as_u64(),
        Some(10),
        "stub matrix should provide complete open/append/save attribution for every cell"
    );

    let cells = matrix["matrix_cells"]
        .as_array()
        .expect("matrix_cells array");
    assert_eq!(
        cells.len(),
        10,
        "matrix artifact should contain one cell per requirement"
    );

    let seen_partitions: HashSet<&str> = cells
        .iter()
        .filter_map(|cell| cell.get("workload_partition").and_then(Value::as_str))
        .collect();
    assert!(seen_partitions.contains("matched-state"));
    assert!(seen_partitions.contains("realistic"));

    let seen_sizes: HashSet<u64> = cells
        .iter()
        .filter_map(|cell| cell.get("session_messages").and_then(Value::as_u64))
        .collect();
    assert_eq!(
        seen_sizes,
        REALISTIC_SESSION_SIZES.iter().copied().collect(),
        "phase1 matrix must cover canonical 100k..5M sizes"
    );

    let _ = fs::remove_dir_all(temp_root);
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
        "| `partition_weighting` | object | Machine-readable partition weights (`realistic` + `matched-state`) with explicit sum-to-one contract |\n",
    );
    md.push_str(
        "| `partition_interpretation` | object | Primary/secondary partition roles and release guardrail forbidding single-partition conclusions |\n",
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
        let sli_ids = row["sli_ids"].as_array().map_or_else(
            || "(missing)".to_string(),
            |ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        );
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
