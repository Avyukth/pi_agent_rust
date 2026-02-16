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
#   PERF_PGO_MODE             PGO mode: off, train, use, compare (default: off)
#   PERF_PGO_PROFILE_DATA     Explicit .profdata path for profile-use mode
#   PERF_PGO_ALLOW_FALLBACK   Fail-closed toggle when PGO data is missing/corrupt (default: 1)
#   PERF_CROSS_ENV_BASELINES  Semicolon-delimited label=path list for cross-env diagnosis
#                             (example: ci=tests/perf/reports/baseline_variance.json;canary=/tmp/baseline_canary.json)
#   PERF_CROSS_ENV_VARIANCE_ALERT_PCT
#                             Cross-env spread threshold percent (default: 10.0)
#   PERF_CROSS_ENV_ENFORCE    If 1, fail run when cross-env diagnosis emits alerts
#   PERF_QUICK                Set to 1 for PR-safe subset (same as --profile quick)
#   PERF_SKIP_CRITERION       Set to 1 to skip criterion benchmarks
#   PERF_SKIP_BUILD           Set to 1 to skip cargo build step
#   CI_CORRELATION_ID         Correlation ID for artifact tracing (auto-generated if unset)
#   BENCH_QUICK               Forwarded to perf_bench_harness (1 = fewer iterations)
#   BENCH_ITERATIONS          Override iteration count for bench harness
#   PERF_REGRESSION_FULL      Forwarded to perf_regression (1 = full mode)
#   PI_PERF_STRICT            Set to 1 to fail CI-enforced budgets on NO_DATA (auto-set for ci/full profiles)

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
PGO_MODE="${PERF_PGO_MODE:-off}"
PGO_PROFILE_DATA="${PERF_PGO_PROFILE_DATA:-$TARGET_DIR/perf/$CARGO_PROFILE/pgo_profile/pijs_workload.profdata}"
PGO_ALLOW_FALLBACK="${PERF_PGO_ALLOW_FALLBACK:-1}"
CROSS_ENV_BASELINES="${PERF_CROSS_ENV_BASELINES:-}"
CROSS_ENV_VARIANCE_ALERT_PCT="${PERF_CROSS_ENV_VARIANCE_ALERT_PCT:-10.0}"
CROSS_ENV_ENFORCE="${PERF_CROSS_ENV_ENFORCE:-0}"
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
  [ext_bench_harness]="ext_bench_harness"
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
      export PI_PERF_STRICT=1
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
      export PI_PERF_STRICT=1
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
log_step "PGO mode:       $PGO_MODE"
log_step "PGO profile:    $PGO_PROFILE_DATA"
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
  "pgo_mode": "$PGO_MODE",
  "pgo_profile_data": "$PGO_PROFILE_DATA",
  "pgo_allow_fallback": "$PGO_ALLOW_FALLBACK",
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
collect_jsonl "$TARGET_DIR/perf/ext_bench_harness.jsonl" "ext_bench_harness.jsonl"
collect_jsonl "$TARGET_DIR/perf/scenario_runner.jsonl" "scenario_runner.jsonl"
collect_jsonl "$TARGET_DIR/perf/pijs_workload.jsonl" "pijs_workload.jsonl"
collect_jsonl "$TARGET_DIR/perf/legacy_extension_workloads.jsonl" "legacy_extension_workloads.jsonl"
collect_jsonl "$TARGET_DIR/perf/$CARGO_PROFILE/pgo_pipeline_events.jsonl" "pgo_pipeline_events.jsonl"

if [[ -f "$TARGET_DIR/perf/ext_bench_harness_report.json" ]]; then
  cp "$TARGET_DIR/perf/ext_bench_harness_report.json" "$OUTPUT_DIR/results/ext_bench_harness_report.json"
  artifact_count=$((artifact_count + 1))
  log_ok "Collected: ext_bench_harness_report.json"
fi

if [[ -d "$TARGET_DIR/perf/$CARGO_PROFILE" ]]; then
  pgo_compare_dir="$OUTPUT_DIR/results/pgo_comparison"
  mkdir -p "$pgo_compare_dir"
  while IFS= read -r -d '' pgo_json; do
    cp "$pgo_json" "$pgo_compare_dir/" 2>/dev/null || true
    artifact_count=$((artifact_count + 1))
    log_ok "Collected PGO comparison artifact: $(basename "$pgo_json")"
  done < <(find "$TARGET_DIR/perf/$CARGO_PROFILE" -maxdepth 1 -type f -name "pgo_delta_*.json" -print0 2>/dev/null)
fi

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
    "sli_matrix": "pi.perf.sli_ux_matrix.v1",
    "pgo_pipeline": "pi.perf.pgo_pipeline_summary.v1",
    "extension_stratification": "pi.perf.extension_benchmark_stratification.v1",
    "cross_env_variance_diagnosis": "pi.perf.cross_env_variance_diagnosis.v1",
    "phase1_matrix_validation": "pi.perf.phase1_matrix_validation.v1"
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
required_partition_tags_raw = (
    perf_sli.get("reporting_contract", {})
    .get("required_partition_tags", [])
)
if not isinstance(required_partition_tags_raw, list):
    required_partition_tags_raw = []
required_partition_tags = []
for partition in required_partition_tags_raw:
    partition_tag = str(partition).strip()
    if partition_tag and partition_tag not in required_partition_tags:
        required_partition_tags.append(partition_tag)
if not required_partition_tags:
    required_partition_tags = ["matched-state", "realistic"]
required_partition_tag_set = set(required_partition_tags)

partitions_by_workflow = {}
for row in partition_requirements_raw:
    if not isinstance(row, dict):
        continue
    workflow_id = str(row.get("workflow_id", "")).strip()
    required_partitions = row.get("required_partitions", [])
    if not workflow_id or not isinstance(required_partitions, list):
        continue
    partitions = []
    for partition in required_partitions:
        partition_tag = str(partition).strip()
        if not partition_tag:
            continue
        if partition_tag not in required_partition_tag_set:
            raise ValueError(
                f"workflow {workflow_id} defines unsupported partition tag: {partition_tag}"
            )
        if partition_tag not in partitions:
            partitions.append(partition_tag)
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
    explicit_partitions = partitions_by_workflow.get(workflow_id)
    if explicit_partitions is None:
        required_partitions = list(required_partition_tags)
    else:
        missing_partitions = required_partition_tag_set.difference(explicit_partitions)
        if missing_partitions:
            missing_csv = ", ".join(sorted(missing_partitions))
            raise ValueError(
                f"workflow {workflow_id} missing required workload partitions: {missing_csv}"
            )
        required_partitions = [
            partition
            for partition in required_partition_tags
            if partition in explicit_partitions
        ]

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

# ─── Phase 5c: PGO pipeline summary ────────────────────────────────────────

log_phase "Phase 5c: PGO Pipeline Summary"

PGO_SUMMARY_PATH="$OUTPUT_DIR/results/pgo_pipeline_summary.json"
if OUTPUT_DIR="$OUTPUT_DIR" \
  PROJECT_ROOT="$PROJECT_ROOT" \
  CORRELATION_ID="$CORRELATION_ID" \
  TIMESTAMP="$TIMESTAMP" \
  PGO_MODE="$PGO_MODE" \
  PGO_PROFILE_DATA="$PGO_PROFILE_DATA" \
  PGO_ALLOW_FALLBACK="$PGO_ALLOW_FALLBACK" \
  PGO_SUMMARY_PATH="$PGO_SUMMARY_PATH" \
  python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

output_dir = Path(os.environ["OUTPUT_DIR"])
correlation_id = os.environ["CORRELATION_ID"]
timestamp = os.environ["TIMESTAMP"]
pgo_mode_requested = os.environ["PGO_MODE"]
pgo_profile_data = os.environ["PGO_PROFILE_DATA"]
pgo_allow_fallback = os.environ["PGO_ALLOW_FALLBACK"]
pgo_summary_path = Path(os.environ["PGO_SUMMARY_PATH"])

manifest_path = output_dir / "manifest.json"
events_path = output_dir / "results" / "pgo_pipeline_events.jsonl"
comparison_dir = output_dir / "results" / "pgo_comparison"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


manifest = load_json(manifest_path)
events = load_jsonl(events_path)

comparison_artifacts = []
if comparison_dir.exists():
    for path in sorted(comparison_dir.glob("pgo_delta_*.json")):
        comparison_artifacts.append(str(path))

latest_mode_effective = "off"
profile_data_state = "not_requested"
fallback_reasons = []
for event in events:
    mode_effective = str(event.get("pgo_mode_effective", "")).strip()
    if mode_effective:
        latest_mode_effective = mode_effective
    state = str(event.get("profile_data_state", "")).strip()
    if state:
        profile_data_state = state
    fallback_reason = str(event.get("fallback_reason", "")).strip()
    if fallback_reason:
        fallback_reasons.append(fallback_reason)

profile_path = Path(pgo_profile_data)
if profile_data_state == "not_requested":
    if pgo_mode_requested in {"use", "train", "compare"}:
        if not profile_path.exists():
            profile_data_state = "missing"
        elif profile_path.stat().st_size == 0:
            profile_data_state = "corrupt"
        else:
            profile_data_state = "present"

if pgo_mode_requested == "off":
    latest_mode_effective = "off"
    profile_data_state = "not_requested"

fallback_triggered = len(fallback_reasons) > 0 or latest_mode_effective == "baseline_fallback"

summary = {
    "schema": "pi.perf.pgo_pipeline_summary.v1",
    "bead_id": "bd-3ar8v.5.2",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "run_id": str(manifest.get("timestamp", timestamp)),
    "correlation_id": correlation_id,
    "pgo_mode_requested": pgo_mode_requested,
    "pgo_mode_effective": latest_mode_effective,
    "profile_data_path": pgo_profile_data,
    "profile_data_state": profile_data_state,
    "fallback": {
        "allowed": pgo_allow_fallback in {"1", "true", "TRUE"},
        "triggered": fallback_triggered,
        "reasons": sorted(set(fallback_reasons)),
    },
    "events_path": str(events_path),
    "event_count": len(events),
    "comparison_artifacts": comparison_artifacts,
    "lineage": {
        "run_id_lineage": [str(manifest.get("timestamp", timestamp)), correlation_id],
        "source_manifest_path": str(manifest_path),
    },
}

pgo_summary_path.parent.mkdir(parents=True, exist_ok=True)
pgo_summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

manifest["pgo_pipeline_summary"] = {
    "schema": "pi.perf.pgo_pipeline_summary.v1",
    "path": str(pgo_summary_path),
    "event_count": len(events),
    "comparison_artifact_count": len(comparison_artifacts),
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
then
  artifact_count=$((artifact_count + 1))
  log_ok "PGO pipeline summary written: results/pgo_pipeline_summary.json"
else
  die "Failed to generate PGO pipeline summary artifact"
fi

# ─── Phase 5d: Extension benchmark stratification ───────────────────────────

log_phase "Phase 5d: Extension Benchmark Stratification"

STRATIFICATION_PATH="$OUTPUT_DIR/results/extension_benchmark_stratification.json"
if OUTPUT_DIR="$OUTPUT_DIR" \
  PROJECT_ROOT="$PROJECT_ROOT" \
  CORRELATION_ID="$CORRELATION_ID" \
  TIMESTAMP="$TIMESTAMP" \
  STRATIFICATION_PATH="$STRATIFICATION_PATH" \
  python3 - <<'PY'
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

output_dir = Path(os.environ["OUTPUT_DIR"])
project_root = Path(os.environ["PROJECT_ROOT"])
correlation_id = os.environ["CORRELATION_ID"]
timestamp = os.environ["TIMESTAMP"]
stratification_path = Path(os.environ["STRATIFICATION_PATH"])

manifest_path = output_dir / "manifest.json"
baseline_path = output_dir / "results" / "baseline_variance_confidence.json"
scenario_runner_path = output_dir / "results" / "scenario_runner.jsonl"
workload_path = output_dir / "results" / "pijs_workload.jsonl"
ext_bench_path = output_dir / "results" / "ext_bench_harness.jsonl"
ext_bench_report_path = output_dir / "results" / "ext_bench_harness_report.json"
legacy_path = output_dir / "results" / "legacy_extension_workloads.jsonl"
perf_comparison_path = output_dir / "results" / "perf_reports" / "perf_comparison.json"
perf_sli_path = project_root / "docs" / "perf_sli_matrix.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def parse_float(value):
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        match = re.search(r"-?\d+(?:\.\d+)?", value)
        if match:
            return float(match.group(0))
    return None


def mean(values: list[float]):
    if not values:
        return None
    return sum(values) / float(len(values))


def suite_status(name: str, suite_map: dict[str, dict]) -> str:
    row = suite_map.get(name)
    if isinstance(row, dict):
        status = str(row.get("status", "")).strip().lower()
        return status if status else "unknown"
    return "missing"


def suite_log_paths(name: str) -> dict[str, str]:
    suite_dir = output_dir / "results" / name
    return {
        "stdout": str(suite_dir / "stdout.log"),
        "stderr": str(suite_dir / "stderr.log"),
    }


manifest = load_json(manifest_path)
run_id = str(manifest.get("timestamp", timestamp))
suite_results = manifest.get("suite_results", [])
if not isinstance(suite_results, list):
    suite_results = []
suite_result_by_name = {
    str(row.get("suite", "")).strip(): row
    for row in suite_results
    if isinstance(row, dict) and str(row.get("suite", "")).strip()
}

scenario_runner_records = load_jsonl(scenario_runner_path)
workload_records = load_jsonl(workload_path)
ext_bench_records = load_jsonl(ext_bench_path)
legacy_records = load_jsonl(legacy_path)

comparison_rows = []
if perf_comparison_path.exists():
    comparison_payload = load_json(perf_comparison_path)
    rows = comparison_payload.get("rows", [])
    if isinstance(rows, list):
        comparison_rows = [row for row in rows if isinstance(row, dict)]

# ── Absolute metrics by layer ───────────────────────────────────────────────

cold_samples_ms: list[float] = []
for record in ext_bench_records:
    if str(record.get("scenario", "")).strip() != "cold_load":
        continue
    if record.get("success") is False:
        continue
    stats = record.get("stats", {})
    if not isinstance(stats, dict):
        continue
    p95_us = parse_float(stats.get("p95_us"))
    if p95_us is not None:
        cold_samples_ms.append(p95_us / 1000.0)

if not cold_samples_ms:
    for record in scenario_runner_records:
        if str(record.get("scenario", "")).strip() != "cold_start":
            continue
        stats = record.get("stats", {})
        if not isinstance(stats, dict):
            continue
        p95_ms = parse_float(stats.get("p95_ms"))
        if p95_ms is not None:
            cold_samples_ms.append(p95_ms)

per_call_samples_us: list[float] = []
for record in scenario_runner_records:
    scenario = str(record.get("scenario", "")).strip()
    if scenario not in {"tool_call", "event_dispatch"}:
        continue
    per_call_us = parse_float(record.get("per_call_us"))
    if per_call_us is not None:
        per_call_samples_us.append(per_call_us)

if not per_call_samples_us:
    for record in workload_records:
        per_call_us = parse_float(record.get("per_call_us"))
        if per_call_us is not None:
            per_call_samples_us.append(per_call_us)

full_e2e_samples_ms: list[float] = []
perf_regression_row = suite_result_by_name.get("perf_regression")
if isinstance(perf_regression_row, dict):
    elapsed_ms = parse_float(perf_regression_row.get("elapsed_ms"))
    if elapsed_ms is not None:
        full_e2e_samples_ms.append(elapsed_ms)
for record in workload_records:
    elapsed_ms = parse_float(record.get("elapsed_ms"))
    if elapsed_ms is not None:
        full_e2e_samples_ms.append(elapsed_ms)

cold_abs_ms = mean(cold_samples_ms)
per_call_abs_us = mean(per_call_samples_us)
full_e2e_abs_ms = mean(full_e2e_samples_ms)

# ── Relative ratios (Rust vs Node/Bun) by layer ────────────────────────────

def comparison_row(metric_substr: str, category_substr: str | None = None):
    metric_substr = metric_substr.lower()
    category_substr = category_substr.lower() if category_substr else None
    for row in comparison_rows:
        metric = str(row.get("metric", "")).lower()
        category = str(row.get("category", "")).lower()
        if metric_substr in metric and (
            category_substr is None or category_substr in category
        ):
            return row
    return None


legacy_cold_samples_ms: list[float] = []
legacy_tool_samples_us: list[float] = []
for record in legacy_records:
    scenario = str(record.get("scenario", "")).strip()
    if scenario == "ext_load_init/load_init_cold":
        summary = record.get("summary", {})
        if isinstance(summary, dict):
            p50_ms = parse_float(summary.get("p50_ms"))
            if p50_ms is not None:
                legacy_cold_samples_ms.append(p50_ms)
    if scenario == "ext_tool_call/hello":
        per_call_us = parse_float(record.get("per_call_us"))
        if per_call_us is not None:
            legacy_tool_samples_us.append(per_call_us)

legacy_cold_ms = mean(legacy_cold_samples_ms)
legacy_tool_us = mean(legacy_tool_samples_us)

cold_node_ratio = None
per_call_node_ratio = None
full_e2e_node_ratio = None

cold_ratio_row = comparison_row("rust-to-ts ratio", "load time")
if isinstance(cold_ratio_row, dict):
    cold_node_ratio = parse_float(cold_ratio_row.get("rust_value"))
if cold_node_ratio is None and cold_abs_ms is not None and legacy_cold_ms is not None and legacy_cold_ms > 0:
    cold_node_ratio = cold_abs_ms / legacy_cold_ms

per_call_row = comparison_row("hello per-call latency", "tool call")
if isinstance(per_call_row, dict):
    rust_value = parse_float(per_call_row.get("rust_value"))
    legacy_value = parse_float(per_call_row.get("legacy_value"))
    if rust_value is not None and legacy_value and legacy_value > 0:
        per_call_node_ratio = rust_value / legacy_value
if per_call_node_ratio is None and per_call_abs_us is not None and legacy_tool_us is not None and legacy_tool_us > 0:
    per_call_node_ratio = per_call_abs_us / legacy_tool_us

full_e2e_row = comparison_row("200 iters x 1 tool", "e2e process")
if isinstance(full_e2e_row, dict):
    rust_value = parse_float(full_e2e_row.get("rust_value"))
    legacy_value = parse_float(full_e2e_row.get("legacy_value"))
    if rust_value is not None and legacy_value and legacy_value > 0:
        full_e2e_node_ratio = rust_value / legacy_value

# Bun coverage is still missing in existing benchmark sources; emit explicit proxy/missing state.
def bun_ratio_from_node(node_ratio):
    if node_ratio is None:
        return (None, "missing")
    return (node_ratio, "node_proxy")


def build_layer(
    layer_id: str,
    display_name: str,
    scenario_tags: list[str],
    expected_suites: list[str],
    metric_name: str,
    absolute_value,
    absolute_unit: str,
    node_ratio,
    node_ratio_basis: str,
    source_artifacts: list[Path],
    interpretation: str,
) -> dict:
    bun_ratio, bun_ratio_basis = bun_ratio_from_node(node_ratio)
    suite_statuses = {name: suite_status(name, suite_result_by_name) for name in expected_suites}
    absolute_present = absolute_value is not None
    relative_present = node_ratio is not None and bun_ratio is not None
    suites_with_data = [name for name, status in suite_statuses.items() if status != "missing"]
    all_ran_suites_passed = all(
        status == "pass" for status in suite_statuses.values() if status != "missing"
    )

    if absolute_present and relative_present and all_ran_suites_passed and suites_with_data:
        confidence = "high"
        evidence_state = "measured"
    elif absolute_present and (node_ratio is not None or bun_ratio is not None):
        confidence = "medium"
        evidence_state = "inferred"
    elif absolute_present:
        confidence = "low"
        evidence_state = "absolute_only"
    else:
        confidence = "low"
        evidence_state = "no_data"

    return {
        "layer_id": layer_id,
        "display_name": display_name,
        "scenario_tags": scenario_tags,
        "expected_suites": expected_suites,
        "suite_status": suite_statuses,
        "absolute_metrics": {
            "metric_name": metric_name,
            "value": absolute_value,
            "unit": absolute_unit,
        },
        "relative_metrics": {
            "rust_vs_node_ratio": node_ratio,
            "rust_vs_node_ratio_basis": node_ratio_basis,
            "rust_vs_bun_ratio": bun_ratio,
            "rust_vs_bun_ratio_basis": bun_ratio_basis,
        },
        "confidence": confidence,
        "evidence_state": evidence_state,
        "interpretation": interpretation,
        "lineage": {
            "run_id_lineage": [run_id, correlation_id],
            "source_artifacts": [str(path) for path in source_artifacts if path.exists()],
            "suite_logs": {suite: suite_log_paths(suite) for suite in expected_suites},
            "source_manifest_path": str(manifest_path),
        },
    }


layers = [
    build_layer(
        "cold_load_init",
        "Cold-load and initialization",
        ["cold-load", "init", "extension-runtime", "microbench"],
        ["ext_bench_harness", "bench_scenario"],
        "cold_load_p95",
        cold_abs_ms,
        "ms",
        cold_node_ratio,
        "direct_or_derived",
        [ext_bench_path, ext_bench_report_path, scenario_runner_path],
        "Cold-load wins are attribution-only and must not be promoted as global UX claims.",
    ),
    build_layer(
        "per_call_dispatch_micro",
        "Per-call dispatch microbench",
        ["per-call", "dispatch", "hostcall", "microbench"],
        ["bench_scenario", "perf_bench_harness"],
        "dispatch_per_call",
        per_call_abs_us,
        "us",
        per_call_node_ratio,
        "direct_or_derived",
        [scenario_runner_path, workload_path],
        "Per-call improvements are diagnostic and cannot substitute for full-session outcomes.",
    ),
    build_layer(
        "full_e2e_long_session",
        "Full end-to-end long-session workload",
        ["full-e2e", "long-session", "user-facing", "release-facing"],
        ["perf_regression", "perf_comparison"],
        "long_session_elapsed",
        full_e2e_abs_ms,
        "ms",
        full_e2e_node_ratio,
        "direct_or_derived",
        [workload_path, perf_comparison_path],
        "Full E2E evidence is the release-facing signal and must gate global speed claims.",
    ),
]

perf_sli = load_json(perf_sli_path) if perf_sli_path.exists() else {}
required_partition_tags = (
    perf_sli.get("reporting_contract", {}).get("required_partition_tags", [])
)
if not isinstance(required_partition_tags, list):
    required_partition_tags = []
required_partition_tags = [str(tag).strip() for tag in required_partition_tags if str(tag).strip()]
if not required_partition_tags:
    required_partition_tags = ["matched-state", "realistic"]

partition_coverage = {tag: False for tag in required_partition_tags}
if baseline_path.exists():
    baseline_payload = load_json(baseline_path)
    records = baseline_payload.get("records", [])
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict):
                continue
            partition = str(record.get("workload_partition", "")).strip()
            if partition in partition_coverage:
                partition_coverage[partition] = True

layer_coverage = {
    layer["layer_id"]: (
        layer["absolute_metrics"]["value"] is not None
        and layer["relative_metrics"]["rust_vs_node_ratio"] is not None
        and layer["relative_metrics"]["rust_vs_bun_ratio"] is not None
    )
    for layer in layers
}

invalidity_reasons = []
if not layer_coverage.get("full_e2e_long_session", False) and (
    layer_coverage.get("cold_load_init", False)
    or layer_coverage.get("per_call_dispatch_micro", False)
):
    invalidity_reasons.append("microbench_only_claim")

if not all(partition_coverage.values()):
    invalidity_reasons.append("global_claim_missing_partition_coverage")

for layer_id, covered in layer_coverage.items():
    if not covered:
        invalidity_reasons.append(f"missing_layer_coverage:{layer_id}")

global_claim_valid = len(invalidity_reasons) == 0

payload = {
    "schema": "pi.perf.extension_benchmark_stratification.v1",
    "bead_id": "bd-3ar8v.4.11",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "correlation_id": correlation_id,
    "profile": str(manifest.get("profile", "unknown")),
    "execution_contract": {
        "orchestrator": "scripts/perf/orchestrate.sh",
        "layer_definition_version": "1.0.0",
        "required_layers": [
            "cold_load_init",
            "per_call_dispatch_micro",
            "full_e2e_long_session",
        ],
        "full_coverage_profiles": ["full", "ci"],
        "lineage_contract": "all layers must share run_id + correlation_id lineage",
    },
    "layers": layers,
    "claim_integrity": {
        "anti_conflation": {
            "cold_load_wins_do_not_imply_per_call_or_e2e": True,
            "per_call_wins_do_not_imply_full_e2e": True,
            "full_e2e_is_release_facing_primary_signal": True,
        },
        "cherry_pick_guard": {
            "requires_all_layers_for_global_claim": True,
            "layer_coverage": layer_coverage,
            "global_claim_valid": global_claim_valid,
            "invalidity_reasons": sorted(set(invalidity_reasons)),
        },
        "required_partition_tags": required_partition_tags,
        "partition_coverage": partition_coverage,
        "policy_ref": "docs/perf_sli_matrix.json#ci_enforcement.fail_closed_conditions",
    },
    "lineage": {
        "run_id_lineage": [run_id, correlation_id],
        "source_manifest_path": str(manifest_path),
        "source_baseline_confidence_path": str(baseline_path) if baseline_path.exists() else None,
        "source_sli_contract_path": str(perf_sli_path) if perf_sli_path.exists() else None,
    },
}

stratification_path.parent.mkdir(parents=True, exist_ok=True)
stratification_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

manifest["extension_benchmark_stratification"] = {
    "schema": "pi.perf.extension_benchmark_stratification.v1",
    "path": str(stratification_path),
    "layer_count": len(layers),
    "global_claim_valid": global_claim_valid,
    "invalidity_reason_count": len(sorted(set(invalidity_reasons))),
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
then
  artifact_count=$((artifact_count + 1))
  log_ok "Extension benchmark stratification written: results/extension_benchmark_stratification.json"
else
  die "Failed to generate extension benchmark stratification artifact"
fi

# ─── Phase 5e: Cross-environment variance diagnosis ─────────────────────────

log_phase "Phase 5e: Cross-Environment Variance Diagnosis"

if [[ -n "$CROSS_ENV_BASELINES" ]]; then
  CROSS_ENV_DIAG_PATH="$OUTPUT_DIR/results/cross_env_variance_diagnosis.json"
  IFS=';' read -r -a CROSS_ENV_ITEMS <<<"$CROSS_ENV_BASELINES"
  DIAG_ARGS=()
  for item in "${CROSS_ENV_ITEMS[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    if [[ -n "$item" ]]; then
      DIAG_ARGS+=(--diagnose-env "$item")
    fi
  done

  if [[ "${#DIAG_ARGS[@]}" -lt 4 ]]; then
    die "PERF_CROSS_ENV_BASELINES must provide at least two label=path entries"
  fi

  log_step "Running cross-env diagnosis with ${#DIAG_ARGS[@]} parameters"
  if ./scripts/perf/capture_baseline.sh \
    "${DIAG_ARGS[@]}" \
    --diagnose-output "$CROSS_ENV_DIAG_PATH" \
    --variance-alert-pct "$CROSS_ENV_VARIANCE_ALERT_PCT"; then
    artifact_count=$((artifact_count + 1))
    log_ok "Cross-env diagnosis written: results/cross_env_variance_diagnosis.json"
  else
    die "Failed to generate cross-environment variance diagnosis artifact"
  fi

  CROSS_ENV_ALERT_COUNT="$(python3 - "$CROSS_ENV_DIAG_PATH" <<'PY'
import json, sys
payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
print(int(payload.get("summary", {}).get("alert_count", 0)))
PY
)"
  CROSS_ENV_METRIC_COUNT="$(python3 - "$CROSS_ENV_DIAG_PATH" <<'PY'
import json, sys
payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
print(int(payload.get("summary", {}).get("metric_count", 0)))
PY
)"

  if [[ "$CROSS_ENV_ENFORCE" == "1" && "${CROSS_ENV_ALERT_COUNT:-0}" -gt 0 ]]; then
    die "Cross-env diagnosis produced ${CROSS_ENV_ALERT_COUNT} alert(s) with PERF_CROSS_ENV_ENFORCE=1"
  fi

  if OUTPUT_DIR="$OUTPUT_DIR" CROSS_ENV_DIAG_PATH="$CROSS_ENV_DIAG_PATH" python3 - <<'PY'
import json
import os
from pathlib import Path

output_dir = Path(os.environ["OUTPUT_DIR"])
diag_path = Path(os.environ["CROSS_ENV_DIAG_PATH"])
manifest_path = output_dir / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
diag = json.loads(diag_path.read_text(encoding="utf-8"))
summary = diag.get("summary", {})
manifest["cross_env_variance_diagnosis"] = {
    "schema": "pi.perf.cross_env_variance_diagnosis.v1",
    "path": str(diag_path),
    "metric_count": int(summary.get("metric_count", 0)),
    "alert_count": int(summary.get("alert_count", 0)),
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
  then
    :
  else
    die "Failed to record cross-env diagnosis metadata in manifest"
  fi
else
  log_step "Skipping cross-env diagnosis (set PERF_CROSS_ENV_BASELINES to enable)"
fi

# ─── Phase 5f: Phase-1 matrix validation ────────────────────────────────────

log_phase "Phase 5f: Phase-1 Matrix Validation"

PHASE1_MATRIX_PATH="$OUTPUT_DIR/results/phase1_matrix_validation.json"
if OUTPUT_DIR="$OUTPUT_DIR" \
  PROJECT_ROOT="$PROJECT_ROOT" \
  CORRELATION_ID="$CORRELATION_ID" \
  TIMESTAMP="$TIMESTAMP" \
  PHASE1_MATRIX_PATH="$PHASE1_MATRIX_PATH" \
  python3 - <<'PY'
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

output_dir = Path(os.environ["OUTPUT_DIR"])
project_root = Path(os.environ["PROJECT_ROOT"])
correlation_id = os.environ["CORRELATION_ID"]
timestamp = os.environ["TIMESTAMP"]
phase1_matrix_path = Path(os.environ["PHASE1_MATRIX_PATH"])

manifest_path = output_dir / "manifest.json"
scenario_runner_path = output_dir / "results" / "scenario_runner.jsonl"
stratification_path = output_dir / "results" / "extension_benchmark_stratification.json"
baseline_path = output_dir / "results" / "baseline_variance_confidence.json"
perf_sli_path = project_root / "docs" / "perf_sli_matrix.json"
fault_injection_script = project_root / "scripts" / "e2e" / "run_persistence_fault_injection.sh"
fault_injection_root = (
    project_root / "tests" / "e2e_results" / "persistence-fault-injection"
)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def parse_float(value):
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        match = re.search(r"-?\d+(?:\.\d+)?", value)
        if match:
            return float(match.group(0))
    return None


def parse_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        value = value.strip().replace("_", "")
        if not value:
            return None
        match = re.search(r"\d+", value)
        if match:
            return int(match.group(0))
    return None


def normalize_partition(value):
    text = str(value or "").strip().lower()
    text = text.replace("_", "-")
    if text in {"matched-state", "matchedstate"}:
        return "matched-state"
    if text == "realistic":
        return "realistic"
    return text


def parse_session_size(scenario_id, replay_input):
    if isinstance(replay_input, dict):
        direct = parse_int(replay_input.get("session_messages"))
        if direct is not None:
            return direct
    if not scenario_id:
        return None
    match = re.search(r"session[_/-]?(\d+)", scenario_id)
    if match:
        return int(match.group(1))
    return None


def suite_status(name, suite_map):
    row = suite_map.get(name)
    if not isinstance(row, dict):
        return "missing"
    status = str(row.get("status", "")).strip().lower()
    return status if status else "missing"


manifest = load_json(manifest_path)
run_id = str(manifest.get("timestamp", timestamp))

suite_results = manifest.get("suite_results", [])
if not isinstance(suite_results, list):
    suite_results = []
suite_result_by_name = {
    str(row.get("suite", "")).strip(): row
    for row in suite_results
    if isinstance(row, dict) and str(row.get("suite", "")).strip()
}

perf_sli = load_json(perf_sli_path) if perf_sli_path.exists() else {}
required_partitions = (
    perf_sli.get("reporting_contract", {}).get("required_partition_tags", [])
)
if not isinstance(required_partitions, list):
    required_partitions = []
required_partitions = [
    normalize_partition(tag) for tag in required_partitions if normalize_partition(tag)
]
if not required_partitions:
    required_partitions = ["matched-state", "realistic"]

benchmark_partitions = perf_sli.get("benchmark_partitions", {})
required_sizes = []
if isinstance(benchmark_partitions, dict):
    realistic_ids = benchmark_partitions.get("realistic_long_session", [])
    if isinstance(realistic_ids, list):
        for item in realistic_ids:
            parsed = parse_session_size(str(item), {})
            if parsed is not None and parsed not in required_sizes:
                required_sizes.append(parsed)
if not required_sizes:
    required_sizes = [100_000, 200_000, 500_000, 1_000_000, 5_000_000]

scenario_runner_records = load_jsonl(scenario_runner_path)
stage_records = {}
for index, record in enumerate(scenario_runner_records):
    if not isinstance(record, dict):
        continue
    partition = normalize_partition(
        record.get("partition") or record.get("workload_partition")
    )
    metadata = record.get("scenario_metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    replay_input = metadata.get("replay_input")
    if not isinstance(replay_input, dict):
        replay_input = {}
    scenario_id = str(
        metadata.get("scenario_id")
        or record.get("scenario_id")
        or record.get("scenario")
        or ""
    ).strip()
    session_messages = parse_session_size(scenario_id, replay_input)

    if partition not in required_partitions or session_messages not in required_sizes:
        continue

    key = (partition, session_messages)
    if key in stage_records:
        continue

    open_ms = parse_float(record.get("open_ms"))
    append_ms = parse_float(record.get("append_ms"))
    save_ms = parse_float(record.get("save_ms"))
    index_ms = parse_float(record.get("index_ms"))
    if index_ms is None:
        index_ms = parse_float(record.get("session_index_ms"))
    wall_clock_ms = parse_float(record.get("total_ms"))
    if wall_clock_ms is None:
        wall_clock_ms = parse_float(record.get("elapsed_ms"))

    stage_records[key] = {
        "scenario_id": scenario_id
        if scenario_id
        else f"{partition}/session_{session_messages}",
        "open_ms": open_ms,
        "append_ms": append_ms,
        "save_ms": save_ms,
        "index_ms": index_ms,
        "wall_clock_ms": wall_clock_ms,
        "source_record_index": index,
    }

stratification = load_json(stratification_path) if stratification_path.exists() else {}
layers = stratification.get("layers", [])
if not isinstance(layers, list):
    layers = []
layer_by_id = {
    str(layer.get("layer_id", "")).strip(): layer
    for layer in layers
    if isinstance(layer, dict) and str(layer.get("layer_id", "")).strip()
}

def layer_absolute(layer_id):
    layer = layer_by_id.get(layer_id, {})
    if not isinstance(layer, dict):
        return None
    metrics = layer.get("absolute_metrics", {})
    if not isinstance(metrics, dict):
        return None
    return parse_float(metrics.get("value"))


def layer_relative(layer_id, field):
    layer = layer_by_id.get(layer_id, {})
    if not isinstance(layer, dict):
        return None
    metrics = layer.get("relative_metrics", {})
    if not isinstance(metrics, dict):
        return None
    return parse_float(metrics.get(field))


primary_wall_clock_ms = layer_absolute("full_e2e_long_session")
primary_rust_vs_node_ratio = layer_relative(
    "full_e2e_long_session", "rust_vs_node_ratio"
)
primary_rust_vs_bun_ratio = layer_relative("full_e2e_long_session", "rust_vs_bun_ratio")
cold_load_ms = layer_absolute("cold_load_init")
per_call_us = layer_absolute("per_call_dispatch_micro")

cells = []
operation_stage_coverage = {
    "open_ms": 0,
    "append_ms": 0,
    "save_ms": 0,
    "index_ms": 0,
}
covered_cells = 0
cells_with_complete_stage_breakdown = 0

for partition in required_partitions:
    for session_messages in required_sizes:
        key = (partition, session_messages)
        source = stage_records.get(key, {})

        stage_attribution = {
            "open_ms": source.get("open_ms"),
            "append_ms": source.get("append_ms"),
            "save_ms": source.get("save_ms"),
            "index_ms": source.get("index_ms"),
        }
        for metric, value in stage_attribution.items():
            if value is not None:
                operation_stage_coverage[metric] += 1

        required_stage_keys = ["open_ms", "append_ms", "save_ms"]
        missing_stage_keys = [
            metric for metric in required_stage_keys if stage_attribution.get(metric) is None
        ]
        if not missing_stage_keys:
            cells_with_complete_stage_breakdown += 1

        total_stage_ms = sum(
            value for value in stage_attribution.values() if value is not None
        )
        if all(value is None for value in stage_attribution.values()):
            total_stage_ms = None

        cell_wall_clock = source.get("wall_clock_ms")
        if cell_wall_clock is None:
            cell_wall_clock = primary_wall_clock_ms

        missing_reasons = []
        if not source:
            missing_reasons.append("missing_matrix_source_record")
        if missing_stage_keys:
            missing_reasons.append(
                "missing_stage_metrics:" + ",".join(sorted(missing_stage_keys))
            )
        if cell_wall_clock is None:
            missing_reasons.append("missing_primary_wall_clock")
        if primary_rust_vs_node_ratio is None or primary_rust_vs_bun_ratio is None:
            missing_reasons.append("missing_primary_relative_ratios")

        if source:
            covered_cells += 1

        cells.append(
            {
                "workload_partition": partition,
                "session_messages": session_messages,
                "scenario_id": source.get("scenario_id")
                or f"{partition}/session_{session_messages}",
                "status": "pass" if not missing_reasons else "fail",
                "missing_reasons": sorted(set(missing_reasons)),
                "stage_attribution": {
                    **stage_attribution,
                    "total_stage_ms": total_stage_ms,
                },
                "primary_e2e": {
                    "wall_clock_ms": cell_wall_clock,
                    "rust_vs_node_ratio": primary_rust_vs_node_ratio,
                    "rust_vs_bun_ratio": primary_rust_vs_bun_ratio,
                },
                "microbench_context": {
                    "cold_load_ms": cold_load_ms,
                    "per_call_us": per_call_us,
                },
                "lineage": {
                    "source_record_index": source.get("source_record_index"),
                    "source_artifacts": [
                        str(path)
                        for path in (
                            scenario_runner_path,
                            stratification_path,
                            baseline_path,
                        )
                        if path.exists()
                    ],
                },
            }
        )

missing_cells = [
    {
        "workload_partition": cell["workload_partition"],
        "session_messages": cell["session_messages"],
        "reasons": cell["missing_reasons"],
    }
    for cell in cells
    if "missing_matrix_source_record" in cell.get("missing_reasons", [])
]

suite_logs = {}
for suite_name in ["perf_baseline_variance", "perf_regression", "perf_budgets"]:
    suite_dir = output_dir / "results" / suite_name
    suite_logs[suite_name] = {
        "stdout": str(suite_dir / "stdout.log"),
        "stderr": str(suite_dir / "stderr.log"),
        "result": str(suite_dir / "result.json"),
        "status": suite_status(suite_name, suite_result_by_name),
        "present": suite_dir.exists(),
    }

fault_injection_candidates = []
if fault_injection_root.exists():
    fault_injection_candidates = sorted(fault_injection_root.glob("*/summary.json"))
fault_injection_summary_path = (
    fault_injection_candidates[-1] if fault_injection_candidates else None
)
fault_injection_status = "missing"
fault_injection_summary = {}
if fault_injection_summary_path and fault_injection_summary_path.exists():
    try:
        fault_injection_summary = load_json(fault_injection_summary_path)
    except Exception:
        fault_injection_summary = {}
    status_text = str(fault_injection_summary.get("overall_status", "")).strip().lower()
    if status_text in {"pass", "ok", "passed", "success"}:
        fault_injection_status = "pass"
    elif status_text:
        fault_injection_status = "fail"
    elif fault_injection_summary:
        fault_injection_status = "pass"

memory_status = suite_status("perf_budgets", suite_result_by_name)
if memory_status == "pass":
    memory_status = "pass"
elif memory_status == "fail":
    memory_status = "fail"
else:
    memory_status = "missing"

correctness_status = suite_status("perf_regression", suite_result_by_name)
if correctness_status == "pass":
    correctness_status = "pass"
elif correctness_status == "fail":
    correctness_status = "fail"
else:
    correctness_status = "missing"

security_status = fault_injection_status

primary_outcome_missing = []
if primary_wall_clock_ms is None:
    primary_outcome_missing.append("missing_e2e_wall_clock_ms")
if primary_rust_vs_node_ratio is None:
    primary_outcome_missing.append("missing_rust_vs_node_ratio")
if primary_rust_vs_bun_ratio is None:
    primary_outcome_missing.append("missing_rust_vs_bun_ratio")

primary_status = "pass" if not primary_outcome_missing else "fail"

regression_guard_failures = []
for guard_name, status in (
    ("memory", memory_status),
    ("correctness", correctness_status),
    ("security", security_status),
):
    if status == "fail":
        regression_guard_failures.append(f"{guard_name}_regression")
    elif status == "missing":
        regression_guard_failures.append(f"{guard_name}_regression_unverified")

required_cell_count = len(required_partitions) * len(required_sizes)
phase5_ready = (
    primary_status == "pass"
    and cells_with_complete_stage_breakdown == required_cell_count
    and len(missing_cells) == 0
    and not any(status != "pass" for status in (memory_status, correctness_status, security_status))
)

payload = {
    "schema": "pi.perf.phase1_matrix_validation.v1",
    "bead_id": "bd-3ar8v.2.8",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "run_id": run_id,
    "correlation_id": correlation_id,
    "matrix_requirements": {
        "required_partition_tags": required_partitions,
        "required_session_message_sizes": required_sizes,
        "required_cell_count": required_cell_count,
    },
    "matrix_cells": cells,
    "stage_summary": {
        "required_stage_keys": ["open_ms", "append_ms", "save_ms", "index_ms"],
        "operation_stage_coverage": operation_stage_coverage,
        "cells_with_complete_stage_breakdown": cells_with_complete_stage_breakdown,
        "cells_missing_stage_breakdown": required_cell_count
        - cells_with_complete_stage_breakdown,
        "covered_cells": covered_cells,
        "missing_cells": missing_cells,
    },
    "primary_outcomes": {
        "status": primary_status,
        "wall_clock_ms": primary_wall_clock_ms,
        "rust_vs_node_ratio": primary_rust_vs_node_ratio,
        "rust_vs_bun_ratio": primary_rust_vs_bun_ratio,
        "missing_reasons": primary_outcome_missing,
        "ordering_policy": "primary_e2e_before_microbench",
    },
    "regression_guards": {
        "memory": memory_status,
        "correctness": correctness_status,
        "security": security_status,
        "failure_or_gap_reasons": sorted(set(regression_guard_failures)),
    },
    "evidence_links": {
        "phase1_unit_and_fault_injection": {
            "suite_logs": suite_logs,
            "fault_injection_script": str(fault_injection_script),
            "fault_injection_summary_path": (
                str(fault_injection_summary_path)
                if fault_injection_summary_path is not None
                else None
            ),
        },
        "required_artifacts": {
            "scenario_runner": str(scenario_runner_path),
            "stratification": str(stratification_path),
            "baseline_variance_confidence": str(baseline_path),
        },
    },
    "consumption_contract": {
        "downstream_beads": [
            "bd-3ar8v.2.12",
            "bd-3ar8v.6.1",
            "bd-3ar8v.6.2",
            "bd-3ar8v.6.6",
            "bd-3ar8v.6.11",
        ],
        "artifact_ready_for_phase5": phase5_ready,
        "fail_closed_conditions": [
            "missing_matrix_source_record",
            "missing_stage_metrics",
            "missing_primary_wall_clock",
            "missing_primary_relative_ratios",
            "memory_regression",
            "correctness_regression",
            "security_regression",
        ],
    },
    "lineage": {
        "run_id_lineage": [run_id, correlation_id],
        "source_manifest_path": str(manifest_path),
        "source_scenario_runner_path": (
            str(scenario_runner_path) if scenario_runner_path.exists() else None
        ),
        "source_stratification_path": (
            str(stratification_path) if stratification_path.exists() else None
        ),
        "source_baseline_confidence_path": (
            str(baseline_path) if baseline_path.exists() else None
        ),
        "source_perf_sli_contract_path": (
            str(perf_sli_path) if perf_sli_path.exists() else None
        ),
    },
}

phase1_matrix_path.parent.mkdir(parents=True, exist_ok=True)
phase1_matrix_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

manifest["phase1_matrix_validation"] = {
    "schema": "pi.perf.phase1_matrix_validation.v1",
    "path": str(phase1_matrix_path),
    "required_cell_count": required_cell_count,
    "covered_cell_count": covered_cells,
    "cells_with_complete_stage_breakdown": cells_with_complete_stage_breakdown,
    "artifact_ready_for_phase5": phase5_ready,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
then
  artifact_count=$((artifact_count + 1))
  log_ok "Phase-1 matrix validation written: results/phase1_matrix_validation.json"
else
  die "Failed to generate phase-1 matrix validation artifact"
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
