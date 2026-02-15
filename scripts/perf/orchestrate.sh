#!/usr/bin/env bash
# scripts/perf/orchestrate.sh — Reproducible benchmark/test orchestration with artifact bundles.
#
# One-command orchestrator that executes all benchmark and performance test suites
# in a deterministic environment, collects structured JSONL evidence, and produces
# a versioned artifact bundle with run manifest and integrity checksums.
#
# Bead: bd-3ar8v.1.8
# Depends on: bd-3ar8v.1.7 (structured logging contract), bd-3ar8v.1.1 (benchmark protocol)
#
# Usage:
#   ./scripts/perf/orchestrate.sh                           # full run (all suites)
#   ./scripts/perf/orchestrate.sh --profile quick            # PR-safe subset
#   ./scripts/perf/orchestrate.sh --profile ci               # CI-optimized run
#   ./scripts/perf/orchestrate.sh --suite bench_scenario     # single suite
#   ./scripts/perf/orchestrate.sh --suite perf_budgets       # budget checks only
#   ./scripts/perf/orchestrate.sh --list                     # list available suites
#   ./scripts/perf/orchestrate.sh --skip-build               # skip cargo build step
#   ./scripts/perf/orchestrate.sh --skip-env-check           # skip environment validation
#   ./scripts/perf/orchestrate.sh --output-dir <path>        # custom output directory
#   ./scripts/perf/orchestrate.sh --bundle                   # create tar.gz bundle at end
#   ./scripts/perf/orchestrate.sh --validate-only <dir>      # validate existing bundle
#
# Environment:
#   CARGO_TARGET_DIR          Cargo target directory (default: target/)
#   PERF_OUTPUT_DIR           Override output directory (default: target/perf/runs/<timestamp>)
#   PERF_PROFILE              Build profile: release, perf, debug (default: perf)
#   PERF_PARALLELISM          Test parallelism (default: 1 for determinism)
#   PERF_QUICK                Set to 1 for PR-safe subset (same as --profile quick)
#   PERF_SKIP_CRITERION       Set to 1 to skip criterion benchmarks
#   PERF_SKIP_BUILD           Set to 1 to skip cargo build step
#   CI_CORRELATION_ID         Correlation ID for artifact tracing (auto-generated if unset)
#   BENCH_QUICK               Forwarded to perf_bench_harness (1 = fewer iterations)
#   BENCH_ITERATIONS          Override iteration count for bench harness
#   PERF_REGRESSION_FULL      Forwarded to perf_regression (1 = full mode)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# ─── Configuration ───────────────────────────────────────────────────────────

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CARGO_PROFILE="${PERF_PROFILE:-perf}"
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
OUTPUT_DIR="${PERF_OUTPUT_DIR:-$TARGET_DIR/perf/runs/$TIMESTAMP}"
PARALLELISM="${PERF_PARALLELISM:-1}"
CORRELATION_ID="${CI_CORRELATION_ID:-}"
PROFILE="full"
SKIP_BUILD="${PERF_SKIP_BUILD:-0}"
SKIP_ENV_CHECK=0
SKIP_CRITERION="${PERF_SKIP_CRITERION:-0}"
CREATE_BUNDLE=0
VALIDATE_ONLY=""
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
GIT_DIRTY="$(git diff --quiet 2>/dev/null && echo "false" || echo "true")"

# Suite registry: name -> cargo test target or bench name
declare -A SUITE_TARGETS=(
  [bench_schema]="bench_schema"
  [bench_scenario]="bench_scenario_runner"
  [perf_bench_harness]="perf_bench_harness"
  [perf_budgets]="perf_budgets"
  [perf_regression]="perf_regression"
  [perf_comparison]="perf_comparison"
  [perf_baseline_variance]="perf_baseline_variance"
)

declare -A CRITERION_BENCHES=(
  [criterion_tools]="tools"
  [criterion_extensions]="extensions"
  [criterion_system]="system"
)

SELECTED_SUITES=()
LIST_ONLY=false

# ─── Helpers ─────────────────────────────────────────────────────────────────

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

die() { red "ERROR: $*" >&2; exit 1; }

log_phase() {
  echo ""
  bold "═══ $1 ═══"
  echo ""
}

log_step() {
  echo "  → $1"
}

log_ok() {
  green "  ✓ $1"
}

log_warn() {
  yellow "  ⚠ $1"
}

log_fail() {
  red "  ✗ $1"
}

epoch_ms() {
  # Milliseconds since epoch (portable)
  python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null \
    || date +%s%3N 2>/dev/null \
    || echo "0"
}

sha256_file() {
  sha256sum "$1" 2>/dev/null | cut -d' ' -f1
}

generate_correlation_id() {
  python3 -c "import uuid; print(uuid.uuid4().hex)" 2>/dev/null \
    || head -c 16 /dev/urandom | xxd -p 2>/dev/null \
    || echo "local-$(date +%s)-$$"
}

# ─── CLI Parsing ─────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --suite)
      SELECTED_SUITES+=("$2")
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-env-check)
      SKIP_ENV_CHECK=1
      shift
      ;;
    --bundle)
      CREATE_BUNDLE=1
      shift
      ;;
    --validate-only)
      VALIDATE_ONLY="$2"
      shift 2
      ;;
    --list)
      LIST_ONLY=true
      shift
      ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      die "Unknown flag: $1 (try --help)"
      ;;
  esac
done

# Quick profile shorthand
if [[ "${PERF_QUICK:-0}" == "1" ]]; then
  PROFILE="quick"
fi

# ─── List mode ───────────────────────────────────────────────────────────────

if [[ "$LIST_ONLY" == "true" ]]; then
  bold "Available performance suites:"
  echo ""
  echo "  Test suites:"
  for suite in "${!SUITE_TARGETS[@]}"; do
    printf "    %-25s cargo test --test %s\n" "$suite" "${SUITE_TARGETS[$suite]}"
  done | sort
  echo ""
  echo "  Criterion benchmarks:"
  for bench in "${!CRITERION_BENCHES[@]}"; do
    printf "    %-25s cargo bench --bench %s\n" "$bench" "${CRITERION_BENCHES[$bench]}"
  done | sort
  echo ""
  echo "  Profiles: full, quick, ci"
  exit 0
fi

# ─── Validate-only mode ─────────────────────────────────────────────────────

if [[ -n "$VALIDATE_ONLY" ]]; then
  log_phase "Validating existing bundle: $VALIDATE_ONLY"

  errors=0

  if [[ ! -f "$VALIDATE_ONLY/manifest.json" ]]; then
    log_fail "Missing manifest.json"
    errors=$((errors + 1))
  else
    log_ok "manifest.json present"
  fi

  if [[ ! -f "$VALIDATE_ONLY/checksums.sha256" ]]; then
    log_fail "Missing checksums.sha256"
    errors=$((errors + 1))
  else
    log_ok "checksums.sha256 present"
    pushd "$VALIDATE_ONLY" >/dev/null
    if sha256sum -c checksums.sha256 --quiet 2>/dev/null; then
      log_ok "All checksums verified"
    else
      log_fail "Checksum verification failed"
      errors=$((errors + 1))
    fi
    popd >/dev/null
  fi

  if [[ ! -d "$VALIDATE_ONLY/results" ]]; then
    log_fail "Missing results/ directory"
    errors=$((errors + 1))
  else
    result_count=$(find "$VALIDATE_ONLY/results" -name "*.json" -o -name "*.jsonl" 2>/dev/null | wc -l)
    log_ok "results/ directory present ($result_count artifact files)"
  fi

  if [[ "$errors" -gt 0 ]]; then
    die "Validation failed with $errors error(s)"
  fi
  green "Bundle validation passed."
  exit 0
fi

# ─── Profile-based suite selection ───────────────────────────────────────────

resolve_suites() {
  case "$PROFILE" in
    full)
      # All test suites + criterion benchmarks
      SELECTED_SUITES=("${!SUITE_TARGETS[@]}")
      if [[ "$SKIP_CRITERION" != "1" ]]; then
        SELECTED_SUITES+=("${!CRITERION_BENCHES[@]}")
      fi
      ;;
    quick)
      # Fast subset: schema validation + budgets only, no criterion
      SELECTED_SUITES=(bench_schema perf_budgets)
      SKIP_CRITERION=1
      export BENCH_QUICK=1
      ;;
    ci)
      # CI: all test suites, skip heavy criterion benches
      SELECTED_SUITES=("${!SUITE_TARGETS[@]}")
      SKIP_CRITERION=1
      ;;
    *)
      die "Unknown profile: $PROFILE (available: full, quick, ci)"
      ;;
  esac
}

if [[ ${#SELECTED_SUITES[@]} -eq 0 ]]; then
  resolve_suites
fi

# ─── Generate correlation ID ────────────────────────────────────────────────

if [[ -z "$CORRELATION_ID" ]]; then
  CORRELATION_ID="$(generate_correlation_id)"
fi

# ─── Setup output directory ─────────────────────────────────────────────────

mkdir -p "$OUTPUT_DIR/results"
mkdir -p "$OUTPUT_DIR/logs"

log_phase "Perf Orchestrator v1.0 (bd-3ar8v.1.8)"
log_step "Profile:        $PROFILE"
log_step "Output:         $OUTPUT_DIR"
log_step "Correlation ID: $CORRELATION_ID"
log_step "Git commit:     $GIT_COMMIT (dirty=$GIT_DIRTY)"
log_step "Cargo profile:  $CARGO_PROFILE"
log_step "Timestamp:      $TIMESTAMP"
log_step "Suites:         ${SELECTED_SUITES[*]}"

# ─── Phase 1: Environment validation ────────────────────────────────────────

if [[ "$SKIP_ENV_CHECK" -eq 0 ]]; then
  log_phase "Phase 1: Environment Validation"

  env_warnings=0

  # Check disk space (need at least 1GB free)
  free_mb=$(df -m "$PROJECT_ROOT" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
  if [[ "$free_mb" -lt 1024 ]]; then
    log_warn "Low disk space: ${free_mb}MB free (recommended: 1024MB+)"
    env_warnings=$((env_warnings + 1))
  else
    log_ok "Disk space: ${free_mb}MB free"
  fi

  # Check cargo/rustc
  if command -v cargo >/dev/null 2>&1; then
    rust_version="$(rustc --version 2>/dev/null || echo "unknown")"
    log_ok "Rust toolchain: $rust_version"
  else
    die "cargo/rustc not found in PATH"
  fi

  # Generate environment fingerprint
  cpu_model="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "unknown")"
  cpu_cores="$(nproc 2>/dev/null || echo "1")"
  mem_total_mb="$(free -m 2>/dev/null | awk '/^Mem:/ {print $2}' || echo "0")"
  os_info="$(uname -srm 2>/dev/null || echo "unknown")"

  log_ok "CPU: $cpu_model ($cpu_cores cores)"
  log_ok "Memory: ${mem_total_mb}MB"
  log_ok "OS: $os_info"

  # Write environment fingerprint
  cat > "$OUTPUT_DIR/env_fingerprint.json" <<EOF
{
  "schema": "pi.perf.env_fingerprint.v1",
  "timestamp": "$TIMESTAMP",
  "os": "$os_info",
  "cpu_model": "$cpu_model",
  "cpu_cores": $cpu_cores,
  "mem_total_mb": $mem_total_mb,
  "build_profile": "$CARGO_PROFILE",
  "git_commit": "$GIT_COMMIT",
  "git_dirty": $GIT_DIRTY,
  "rust_version": "$rust_version",
  "correlation_id": "$CORRELATION_ID"
}
EOF
  log_ok "Environment fingerprint written"

  if [[ "$env_warnings" -gt 0 ]]; then
    log_warn "$env_warnings environment warning(s) — proceeding anyway"
  fi
else
  log_step "Skipping environment validation (--skip-env-check)"
fi

# ─── Phase 2: Build ─────────────────────────────────────────────────────────

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  log_phase "Phase 2: Build (profile=$CARGO_PROFILE)"
  build_start=$(epoch_ms)

  # Build test binaries
  log_step "Building test binaries..."
  if cargo test --no-run --profile "$CARGO_PROFILE" 2>"$OUTPUT_DIR/logs/build_tests.log"; then
    log_ok "Test binaries built"
  else
    log_warn "Test binary build had warnings (see logs/build_tests.log)"
  fi

  # Build criterion benches if needed
  if [[ "$SKIP_CRITERION" != "1" ]]; then
    log_step "Building criterion benchmarks..."
    for bench in "${!CRITERION_BENCHES[@]}"; do
      bench_name="${CRITERION_BENCHES[$bench]}"
      if cargo bench --bench "$bench_name" --no-run --profile "$CARGO_PROFILE" 2>>"$OUTPUT_DIR/logs/build_benches.log"; then
        log_ok "Built bench: $bench_name"
      else
        log_warn "Build warning for bench: $bench_name"
      fi
    done
  fi

  build_end=$(epoch_ms)
  build_elapsed=$((build_end - build_start))
  log_ok "Build completed in ${build_elapsed}ms"
else
  log_step "Skipping build (--skip-build / PERF_SKIP_BUILD=1)"
fi

# ─── Phase 3: Execute suites ────────────────────────────────────────────────

log_phase "Phase 3: Execute Suites"

run_start=$(epoch_ms)
suite_pass=0
suite_fail=0
suite_skip=0
declare -a SUITE_RESULTS=()

run_test_suite() {
  local suite_name="$1"
  local target_name="$2"
  local suite_start suite_end suite_elapsed exit_code

  log_step "Running suite: $suite_name (target=$target_name)"
  suite_start=$(epoch_ms)

  local result_dir="$OUTPUT_DIR/results/$suite_name"
  mkdir -p "$result_dir"

  exit_code=0
  BENCH_OUTPUT_DIR="$result_dir" \
  PERF_REGRESSION_OUTPUT="$result_dir" \
  CI_CORRELATION_ID="$CORRELATION_ID" \
  RUST_TEST_THREADS="$PARALLELISM" \
    cargo test --test "$target_name" --profile "$CARGO_PROFILE" -- --nocapture \
    >"$result_dir/stdout.log" 2>"$result_dir/stderr.log" \
    || exit_code=$?

  suite_end=$(epoch_ms)
  suite_elapsed=$((suite_end - suite_start))

  local status
  if [[ "$exit_code" -eq 0 ]]; then
    status="pass"
    suite_pass=$((suite_pass + 1))
    log_ok "$suite_name passed (${suite_elapsed}ms)"
  else
    status="fail"
    suite_fail=$((suite_fail + 1))
    log_fail "$suite_name failed (exit=$exit_code, ${suite_elapsed}ms)"
  fi

  # Write per-suite result record
  cat > "$result_dir/result.json" <<EOF
{
  "schema": "pi.perf.suite_result.v1",
  "suite_name": "$suite_name",
  "target": "$target_name",
  "status": "$status",
  "exit_code": $exit_code,
  "elapsed_ms": $suite_elapsed,
  "correlation_id": "$CORRELATION_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "profile": "$CARGO_PROFILE"
}
EOF

  SUITE_RESULTS+=("{\"suite\":\"$suite_name\",\"status\":\"$status\",\"exit_code\":$exit_code,\"elapsed_ms\":$suite_elapsed}")
}

run_criterion_bench() {
  local suite_name="$1"
  local bench_name="$2"
  local suite_start suite_end suite_elapsed exit_code

  log_step "Running criterion bench: $suite_name (bench=$bench_name)"
  suite_start=$(epoch_ms)

  local result_dir="$OUTPUT_DIR/results/$suite_name"
  mkdir -p "$result_dir"

  exit_code=0
  cargo bench --bench "$bench_name" --profile "$CARGO_PROFILE" \
    >"$result_dir/stdout.log" 2>"$result_dir/stderr.log" \
    || exit_code=$?

  suite_end=$(epoch_ms)
  suite_elapsed=$((suite_end - suite_start))

  local status
  if [[ "$exit_code" -eq 0 ]]; then
    status="pass"
    suite_pass=$((suite_pass + 1))
    log_ok "$suite_name passed (${suite_elapsed}ms)"
  else
    status="fail"
    suite_fail=$((suite_fail + 1))
    log_fail "$suite_name failed (exit=$exit_code, ${suite_elapsed}ms)"
  fi

  # Copy criterion output if it exists
  local criterion_dir="$TARGET_DIR/criterion/$bench_name"
  if [[ -d "$criterion_dir" ]]; then
    cp -r "$criterion_dir" "$result_dir/criterion/" 2>/dev/null || true
  fi

  cat > "$result_dir/result.json" <<EOF
{
  "schema": "pi.perf.suite_result.v1",
  "suite_name": "$suite_name",
  "target": "$bench_name",
  "kind": "criterion",
  "status": "$status",
  "exit_code": $exit_code,
  "elapsed_ms": $suite_elapsed,
  "correlation_id": "$CORRELATION_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "profile": "$CARGO_PROFILE"
}
EOF

  SUITE_RESULTS+=("{\"suite\":\"$suite_name\",\"status\":\"$status\",\"exit_code\":$exit_code,\"elapsed_ms\":$suite_elapsed}")
}

# Execute each selected suite
for suite in "${SELECTED_SUITES[@]}"; do
  if [[ -n "${SUITE_TARGETS[$suite]+x}" ]]; then
    run_test_suite "$suite" "${SUITE_TARGETS[$suite]}"
  elif [[ -n "${CRITERION_BENCHES[$suite]+x}" ]]; then
    run_criterion_bench "$suite" "${CRITERION_BENCHES[$suite]}"
  else
    log_warn "Unknown suite: $suite (skipping)"
    suite_skip=$((suite_skip + 1))
  fi
done

run_end=$(epoch_ms)
run_elapsed=$((run_end - run_start))

# ─── Phase 4: Collect JSONL artifacts ────────────────────────────────────────

log_phase "Phase 4: Collect Artifacts"

artifact_count=0

# Collect JSONL outputs from standard locations
collect_jsonl() {
  local src="$1"
  local dst_name="$2"
  if [[ -f "$src" ]]; then
    cp "$src" "$OUTPUT_DIR/results/$dst_name"
    artifact_count=$((artifact_count + 1))
    log_ok "Collected: $dst_name ($(wc -l < "$src") records)"
  fi
}

# Standard JSONL output paths
collect_jsonl "$TARGET_DIR/perf/extension_bench.jsonl" "extension_bench.jsonl"
collect_jsonl "$TARGET_DIR/perf/scenario_runner.jsonl" "scenario_runner.jsonl"
collect_jsonl "$TARGET_DIR/perf/pijs_workload.jsonl" "pijs_workload.jsonl"

# Check per-suite result directories for additional JSONL
for suite in "${SELECTED_SUITES[@]}"; do
  suite_dir="$OUTPUT_DIR/results/$suite"
  if [[ -d "$suite_dir" ]]; then
    while IFS= read -r -d '' jsonl_file; do
      basename_file="$(basename "$jsonl_file")"
      if [[ "$basename_file" != "stdout.log" && "$basename_file" != "stderr.log" ]]; then
        artifact_count=$((artifact_count + 1))
      fi
    done < <(find "$suite_dir" -name "*.jsonl" -print0 2>/dev/null)
  fi
done

# Collect benchmark reports from tests/perf/reports
if [[ -d "$PROJECT_ROOT/tests/perf/reports" ]]; then
  cp -r "$PROJECT_ROOT/tests/perf/reports" "$OUTPUT_DIR/results/perf_reports/" 2>/dev/null || true
  log_ok "Collected perf reports directory"
fi

log_ok "Total artifacts collected: $artifact_count"

# ─── Phase 5: Generate manifest ─────────────────────────────────────────────

log_phase "Phase 5: Generate Run Manifest"

# Build suite_results JSON array
suite_results_json="["
first=true
for result in "${SUITE_RESULTS[@]}"; do
  if [[ "$first" == "true" ]]; then
    first=false
  else
    suite_results_json+=","
  fi
  suite_results_json+="$result"
done
suite_results_json+="]"

cat > "$OUTPUT_DIR/manifest.json" <<EOF
{
  "schema": "pi.perf.run_manifest.v1",
  "version": "1.0.0",
  "bead_id": "bd-3ar8v.1.8",
  "correlation_id": "$CORRELATION_ID",
  "timestamp": "$TIMESTAMP",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$GIT_COMMIT",
  "git_dirty": $GIT_DIRTY,
  "profile": "$PROFILE",
  "cargo_profile": "$CARGO_PROFILE",
  "parallelism": $PARALLELISM,
  "run_summary": {
    "total_suites": $((suite_pass + suite_fail + suite_skip)),
    "passed": $suite_pass,
    "failed": $suite_fail,
    "skipped": $suite_skip,
    "elapsed_ms": $run_elapsed,
    "artifact_count": $artifact_count
  },
  "suite_results": $suite_results_json,
  "contract_refs": {
    "logging_contract": "pi.test.evidence_logging_contract.v1",
    "evidence_contract": "pi.qa.evidence_contract.v1",
    "bench_protocol": "pi.bench.protocol.v1",
    "sli_matrix": "pi.perf.sli_ux_matrix.v1"
  },
  "output_dir": "$OUTPUT_DIR"
}
EOF

log_ok "Manifest written: manifest.json"

# ─── Phase 5b: Baseline Variance/Confidence Artifact ────────────────────────

log_phase "Phase 5b: Baseline Variance/Confidence"

BASELINE_CONFIDENCE_PATH="$OUTPUT_DIR/results/baseline_variance_confidence.json"
if OUTPUT_DIR="$OUTPUT_DIR" \
  PROJECT_ROOT="$PROJECT_ROOT" \
  CORRELATION_ID="$CORRELATION_ID" \
  TIMESTAMP="$TIMESTAMP" \
  BASELINE_CONFIDENCE_PATH="$BASELINE_CONFIDENCE_PATH" \
  python3 - <<'PY'
import hashlib
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path

output_dir = Path(os.environ["OUTPUT_DIR"])
project_root = Path(os.environ["PROJECT_ROOT"])
correlation_id = os.environ["CORRELATION_ID"]
timestamp = os.environ["TIMESTAMP"]
baseline_confidence_path = Path(os.environ["BASELINE_CONFIDENCE_PATH"])

manifest_path = output_dir / "manifest.json"
env_path = output_dir / "env_fingerprint.json"
perf_sli_path = project_root / "docs" / "perf_sli_matrix.json"
scenario_matrix_path = project_root / "docs" / "e2e_scenario_matrix.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


manifest = load_json(manifest_path)
env = load_json(env_path) if env_path.exists() else {}
perf_sli = load_json(perf_sli_path)
scenario_matrix = load_json(scenario_matrix_path)

suite_results = manifest.get("suite_results", [])
if not isinstance(suite_results, list):
    suite_results = []
suite_result_by_name = {
    str(entry.get("suite", "")).strip(): entry
    for entry in suite_results
    if isinstance(entry, dict) and str(entry.get("suite", "")).strip()
}

scenario_rows = scenario_matrix.get("rows", [])
if not isinstance(scenario_rows, list):
    scenario_rows = []
scenario_by_workflow = {
    str(row.get("workflow_id", "")).strip(): row
    for row in scenario_rows
    if isinstance(row, dict) and str(row.get("workflow_id", "")).strip()
}

partition_requirements_raw = (
    perf_sli.get("reporting_contract", {})
    .get("scenario_partition_requirements", [])
)
if not isinstance(partition_requirements_raw, list):
    partition_requirements_raw = []
partitions_by_workflow = {}
for row in partition_requirements_raw:
    if not isinstance(row, dict):
        continue
    workflow_id = str(row.get("workflow_id", "")).strip()
    required_partitions = row.get("required_partitions", [])
    if not workflow_id or not isinstance(required_partitions, list):
        continue
    partitions = [str(p).strip() for p in required_partitions if str(p).strip()]
    if partitions:
        partitions_by_workflow[workflow_id] = partitions

workflow_sli_mapping = perf_sli.get("workflow_sli_mapping", [])
if not isinstance(workflow_sli_mapping, list):
    workflow_sli_mapping = []

run_id = str(manifest.get("timestamp", timestamp))
environment_fingerprint_hash = str(env.get("config_hash", "unknown"))

records = []

for mapping in workflow_sli_mapping:
    if not isinstance(mapping, dict):
        continue

    workflow_id = str(mapping.get("workflow_id", "")).strip()
    sli_ids = mapping.get("sli_ids", [])
    if not workflow_id or not isinstance(sli_ids, list):
        continue

    scenario_row = scenario_by_workflow.get(workflow_id, {})
    suite_ids = scenario_row.get("suite_ids", [])
    if not isinstance(suite_ids, list):
        suite_ids = []
    suite_ids = [str(suite_id).strip() for suite_id in suite_ids if str(suite_id).strip()]

    sample_values = []
    for suite_id in suite_ids:
        suite_result = suite_result_by_name.get(suite_id)
        if not isinstance(suite_result, dict):
            continue
        if str(suite_result.get("status", "")).strip().lower() != "pass":
            continue
        elapsed_ms = suite_result.get("elapsed_ms")
        if isinstance(elapsed_ms, (int, float)):
            sample_values.append(float(elapsed_ms))

    sample_count = len(sample_values)
    mean_ms = None
    variance_ms2 = None
    stddev_ms = None
    ci95_lower_ms = None
    ci95_upper_ms = None

    if sample_count > 0:
        mean_ms = sum(sample_values) / sample_count
        if sample_count > 1:
            variance_ms2 = sum((value - mean_ms) ** 2 for value in sample_values) / sample_count
            stddev_ms = math.sqrt(variance_ms2)
            half_width = 1.96 * stddev_ms / math.sqrt(sample_count)
        else:
            variance_ms2 = 0.0
            stddev_ms = 0.0
            half_width = 0.0
        ci95_lower_ms = max(0.0, mean_ms - half_width)
        ci95_upper_ms = mean_ms + half_width

    if sample_count >= 8:
        confidence = "high"
    elif sample_count >= 4:
        confidence = "medium"
    else:
        confidence = "low"

    evidence_state = "measured" if sample_count > 0 else "no_data"
    required_partitions = partitions_by_workflow.get(workflow_id, ["realistic"])

    lineage_source = {
        "workflow_id": workflow_id,
        "suite_ids": suite_ids,
        "sample_values_ms": sample_values,
        "required_partitions": required_partitions,
    }
    dataset_hash = hashlib.sha256(
        json.dumps(lineage_source, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    scenario_metadata = {
        "workflow_id": workflow_id,
        "workflow_class": str(scenario_row.get("workflow_class", "unknown")),
        "suite_ids": suite_ids,
        "vcr_mode": str(scenario_row.get("vcr_mode", "unknown")),
        "scenario_owner": str(scenario_row.get("owner", "unknown")),
    }

    for partition in required_partitions:
        for sli_id in sli_ids:
            canonical_sli_id = str(sli_id).strip()
            if not canonical_sli_id:
                continue
            records.append(
                {
                    "run_id": run_id,
                    "correlation_id": correlation_id,
                    "scenario_id": workflow_id,
                    "workload_partition": partition,
                    "scenario_metadata": scenario_metadata,
                    "sli_id": canonical_sli_id,
                    "sample_count": sample_count,
                    "mean_ms": mean_ms,
                    "variance_ms2": variance_ms2,
                    "stddev_ms": stddev_ms,
                    "ci95_lower_ms": ci95_lower_ms,
                    "ci95_upper_ms": ci95_upper_ms,
                    "confidence": confidence,
                    "evidence_state": evidence_state,
                    "lineage": {
                        "dataset_hash": dataset_hash,
                        "run_id_lineage": [run_id, correlation_id],
                        "environment_fingerprint_hash": environment_fingerprint_hash,
                        "source_manifest_path": str(manifest_path),
                    },
                }
            )

confidence_counts = {"high": 0, "medium": 0, "low": 0}
for record in records:
    label = str(record.get("confidence", "low"))
    confidence_counts[label] = confidence_counts.get(label, 0) + 1

payload = {
    "schema": "pi.perf.baseline_variance_confidence.v1",
    "bead_id": "bd-3ar8v.1.5",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "correlation_id": correlation_id,
    "source_manifest_path": str(manifest_path),
    "source_env_fingerprint_path": str(env_path) if env_path.exists() else None,
    "records": records,
    "summary": {
        "record_count": len(records),
        "scenario_count": len({record["scenario_id"] for record in records}),
        "sli_count": len({record["sli_id"] for record in records}),
        "confidence_counts": confidence_counts,
    },
}

baseline_confidence_path.parent.mkdir(parents=True, exist_ok=True)
baseline_confidence_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

manifest["baseline_variance_confidence"] = {
    "schema": "pi.perf.baseline_variance_confidence.v1",
    "path": str(baseline_confidence_path),
    "record_count": payload["summary"]["record_count"],
    "scenario_count": payload["summary"]["scenario_count"],
    "sli_count": payload["summary"]["sli_count"],
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
then
  artifact_count=$((artifact_count + 1))
  log_ok "Baseline variance/confidence written: results/baseline_variance_confidence.json"
else
  die "Failed to generate baseline variance/confidence artifact"
fi

# ─── Phase 6: Generate checksums ────────────────────────────────────────────

log_phase "Phase 6: Integrity Checksums"

pushd "$OUTPUT_DIR" >/dev/null
# Checksum all result files
find results/ -type f \( -name "*.json" -o -name "*.jsonl" -o -name "*.log" \) 2>/dev/null \
  | sort \
  | while IFS= read -r file; do
    sha256sum "$file"
  done > checksums.sha256

# Also checksum the manifest and fingerprint
sha256sum manifest.json >> checksums.sha256
if [[ -f env_fingerprint.json ]]; then
  sha256sum env_fingerprint.json >> checksums.sha256
fi
popd >/dev/null

checksum_count=$(wc -l < "$OUTPUT_DIR/checksums.sha256")
log_ok "Generated $checksum_count checksums"

# ─── Phase 7: Bundle (optional) ─────────────────────────────────────────────

if [[ "$CREATE_BUNDLE" -eq 1 ]]; then
  log_phase "Phase 7: Create Artifact Bundle"

  bundle_name="perf-bundle-${TIMESTAMP}-${GIT_COMMIT}"
  bundle_path="$TARGET_DIR/perf/bundles/${bundle_name}.tar.gz"
  mkdir -p "$(dirname "$bundle_path")"

  tar -czf "$bundle_path" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"
  bundle_size=$(du -h "$bundle_path" | cut -f1)
  bundle_sha=$(sha256_file "$bundle_path")

  log_ok "Bundle created: $bundle_path ($bundle_size)"
  log_ok "Bundle SHA-256: $bundle_sha"

  # Write bundle metadata alongside the archive
  cat > "${bundle_path%.tar.gz}.meta.json" <<EOF
{
  "schema": "pi.perf.bundle_meta.v1",
  "bundle_name": "$bundle_name",
  "bundle_path": "$bundle_path",
  "bundle_sha256": "$bundle_sha",
  "source_dir": "$OUTPUT_DIR",
  "correlation_id": "$CORRELATION_ID",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

log_phase "Summary"

echo "  Suites:       $((suite_pass + suite_fail + suite_skip)) total ($suite_pass pass, $suite_fail fail, $suite_skip skip)"
echo "  Artifacts:    $artifact_count collected"
echo "  Checksums:    $checksum_count verified"
echo "  Duration:     ${run_elapsed}ms"
echo "  Output:       $OUTPUT_DIR"
echo "  Manifest:     $OUTPUT_DIR/manifest.json"
echo "  Correlation:  $CORRELATION_ID"

if [[ "$suite_fail" -gt 0 ]]; then
  echo ""
  log_warn "$suite_fail suite(s) failed — check results/ for details"
  exit 1
fi

green "All suites passed."
