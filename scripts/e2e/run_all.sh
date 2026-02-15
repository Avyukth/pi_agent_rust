#!/usr/bin/env bash
# scripts/e2e/run_all.sh — Unified verification runner with structured artifacts.
#
# Runs lint gates, inline lib tests, integration test targets, and E2E suites
# with per-target artifact collection. Targets auto-discovered from
# tests/suite_classification.toml.
#
# Usage:
#   ./scripts/e2e/run_all.sh                              # profile=full (lint + lib + all targets)
#   ./scripts/e2e/run_all.sh --profile quick              # fast local loop (lint + lib + unit only)
#   ./scripts/e2e/run_all.sh --profile focused            # lint + lib + selected integration targets
#   ./scripts/e2e/run_all.sh --profile ci                 # deterministic CI (lint + lib + all non-e2e + 1 e2e)
#   ./scripts/e2e/run_all.sh --suite e2e_tui              # run specific E2E suite(s)
#   ./scripts/e2e/run_all.sh --unit-target node_http_shim # run specific integration target(s)
#   ./scripts/e2e/run_all.sh --rerun-from <summary.json>  # deterministic rerun of failed suites
#   ./scripts/e2e/run_all.sh --diff-from <summary.json>   # compare current run to baseline
#   ./scripts/e2e/run_all.sh --skip-lint                  # skip format/clippy gates
#   ./scripts/e2e/run_all.sh --list                       # list available suites
#   ./scripts/e2e/run_all.sh --list-profiles              # list built-in profiles
#
# Environment:
#   E2E_ARTIFACT_DIR   Override artifact output directory (default: tests/e2e_results/<timestamp>)
#   E2E_PARALLELISM    Cargo test threads (default: 1 for determinism)
#   RUST_LOG           Log level for test harness (default: info)
#   VCR_MODE           Override VCR mode for all suites (default: unset, per-test decision)
#   VERIFY_PROFILE     Default profile when --profile is omitted (default: full)
#   E2E_DIFF_FROM      Baseline summary.json to diff against (optional)
#   VERIFY_MIN_FREE_MB Minimum free MB required for repo/artifact mounts (default: 2048)
#   VERIFY_MIN_TMP_FREE_MB Minimum free MB required for tmp/cargo mounts (default: 8192)
#   CARGO_TARGET_DIR   Optional cargo target directory (checked by preflight).
#                      If unset and CODEX_THREAD_ID is present, defaults to
#                      target/agents/<CODEX_THREAD_ID> to reduce multi-agent
#                      artifact contention.
#   CARGO_HOME         Optional cargo home directory (checked by preflight)
#   VERIFY_MIN_FREE_INODE_PCT Minimum free inode percent required (default: 5)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# In multi-agent Codex sessions, isolate cargo artifacts by default unless the
# caller explicitly sets CARGO_TARGET_DIR.
if [[ -z "${CARGO_TARGET_DIR:-}" && -n "${CODEX_THREAD_ID:-}" ]]; then
    safe_codex_thread_id="$(printf '%s' "$CODEX_THREAD_ID" | tr -c 'A-Za-z0-9._-' '_')"
    export CARGO_TARGET_DIR="$PROJECT_ROOT/target/agents/$safe_codex_thread_id"
fi

# ─── Configuration ────────────────────────────────────────────────────────────

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${E2E_ARTIFACT_DIR:-$PROJECT_ROOT/tests/e2e_results/$TIMESTAMP}"
PARALLELISM="${E2E_PARALLELISM:-1}"
LOG_LEVEL="${RUST_LOG:-info}"
PROFILE="${VERIFY_PROFILE:-full}"
RERUN_FROM=""
DIFF_FROM="${E2E_DIFF_FROM:-}"
SHARD_KIND="none"
SHARD_INDEX_RAW=""
SHARD_TOTAL_RAW=""
SHARD_INDEX_JSON="null"
SHARD_TOTAL_JSON="null"
SHARD_NAME=""
SHARD_INDEX=-1
SHARD_TOTAL=1
CORRELATION_ID="${CI_CORRELATION_ID:-}"

# ─── Auto-discover targets from suite_classification.toml ─────────────────────

CLASSIFICATION_FILE="$PROJECT_ROOT/tests/suite_classification.toml"

read_toml_array() {
    local suite_name="$1"
    python3 -c "
import tomllib, sys
with open('$CLASSIFICATION_FILE', 'rb') as f:
    data = tomllib.load(f)
for name in data.get('suite', {}).get('$suite_name', {}).get('files', []):
    print(name)
" 2>/dev/null || true
}

mapfile -t ALL_UNIT_FILES < <(read_toml_array "unit")
mapfile -t ALL_VCR_FILES < <(read_toml_array "vcr")
mapfile -t ALL_E2E_FILES < <(read_toml_array "e2e")

# Combined non-E2E targets (unit + vcr) for integration test phase.
ALL_UNIT_TARGETS=("${ALL_UNIT_FILES[@]}" "${ALL_VCR_FILES[@]}")

# E2E suites.
ALL_SUITES=("${ALL_E2E_FILES[@]}")

# ─── CLI Parsing ──────────────────────────────────────────────────────────────

SELECTED_SUITES=()
SELECTED_UNIT_TARGETS=()
LIST_ONLY=false
LIST_PROFILES=false
SKIP_UNIT=false
SKIP_E2E=false
SKIP_LINT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite)
            shift
            SELECTED_SUITES+=("$1")
            shift
            ;;
        --unit-target)
            shift
            SELECTED_UNIT_TARGETS+=("$1")
            shift
            ;;
        --profile)
            shift
            PROFILE="$1"
            shift
            ;;
        --rerun-from)
            shift
            RERUN_FROM="$1"
            shift
            ;;
        --diff-from)
            shift
            DIFF_FROM="$1"
            shift
            ;;
        --skip-unit)
            SKIP_UNIT=true
            shift
            ;;
        --skip-e2e)
            SKIP_E2E=true
            shift
            ;;
        --skip-lint)
            SKIP_LINT=true
            shift
            ;;
        --shard-kind)
            shift
            SHARD_KIND="$1"
            shift
            ;;
        --shard-index)
            shift
            SHARD_INDEX_RAW="$1"
            shift
            ;;
        --shard-total)
            shift
            SHARD_TOTAL_RAW="$1"
            shift
            ;;
        --shard-name)
            shift
            SHARD_NAME="$1"
            shift
            ;;
        --correlation-id)
            shift
            CORRELATION_ID="$1"
            shift
            ;;
        --list)
            LIST_ONLY=true
            shift
            ;;
        --list-profiles)
            LIST_PROFILES=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--profile NAME] [--suite NAME]... [--unit-target NAME]..."
            echo "          [--rerun-from SUMMARY_JSON] [--diff-from SUMMARY_JSON]"
            echo "          [--skip-unit] [--skip-e2e] [--skip-lint]"
            echo "          [--shard-kind KIND --shard-index N --shard-total M]"
            echo "          [--list] [--list-profiles] [--help]"
            echo ""
            echo "Options:"
            echo "  --profile NAME       Verification profile: quick | focused | ci | full"
            echo "  --suite NAME         Run only specified E2E suite(s) (repeatable)"
            echo "  --unit-target NAME   Run only specified unit target(s) (repeatable)"
            echo "  --rerun-from PATH    Rerun failed suites from prior summary.json"
            echo "  --diff-from PATH     Compare current run against baseline summary.json"
            echo "  --skip-unit          Skip integration target execution"
            echo "  --skip-e2e           Skip E2E suite execution"
            echo "  --skip-lint          Skip fmt/clippy lint gates"
            echo "  --shard-kind KIND    Deterministic shard mode: none|unit|suite|both"
            echo "  --shard-index N      Zero-based shard index"
            echo "  --shard-total M      Total shard count"
            echo "  --shard-name NAME    Optional shard label (default derived from kind/index/total)"
            echo "  --correlation-id ID  Correlation id written into every artifact manifest"
            echo "  --list               List available E2E suites and exit"
            echo "  --list-profiles      List available verification profiles and exit"
            echo "  --help               Show this help"
            echo ""
            echo "Profiles:"
            echo "  quick    Lint + lib inline tests + unit suite only (fastest)"
            echo "  focused  Lint + lib + unit + selected integration targets"
            echo "  ci       Lint + lib + all non-E2E targets + 1 E2E suite"
            echo "  full     Lint + lib + all targets + all E2E suites"
            echo ""
            echo "Environment:"
            echo "  E2E_ARTIFACT_DIR     Artifact output directory"
            echo "  E2E_PARALLELISM      Cargo test threads (default: 1)"
            echo "  RUST_LOG             Log level (default: info)"
            echo "  VERIFY_PROFILE       Default profile when --profile not provided"
            echo "  E2E_DIFF_FROM        Baseline summary.json for diff/triage output"
            echo "  VERIFY_MIN_TMP_FREE_MB Minimum free MB for tmp/cargo mounts (default: 8192)"
            echo "  CARGO_TARGET_DIR     Optional cargo target directory (checked by preflight); defaults to target/agents/<CODEX_THREAD_ID> when CODEX_THREAD_ID is set"
            echo "  CARGO_HOME           Optional cargo home directory (checked by preflight)"
            echo "  VERIFY_MIN_FREE_MB   Minimum free MB for repo/artifact mounts (default: 2048)"
            echo "  VERIFY_MIN_FREE_INODE_PCT Minimum free inode percent required (default: 5)"
            echo "  CI_CORRELATION_ID    Default correlation id when --correlation-id is not provided"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if $LIST_PROFILES; then
    cat <<EOF
Available verification profiles:
  quick:   Lint + lib inline tests + unit suite targets only (${#ALL_UNIT_FILES[@]} targets)
  focused: Lint + lib + unit + selected integration targets + 2 E2E suites
  ci:      Lint + lib + all non-E2E targets (${#ALL_UNIT_TARGETS[@]}) + 1 E2E suite
  full:    Lint + lib + all targets (${#ALL_UNIT_TARGETS[@]} + ${#ALL_SUITES[@]} E2E)
EOF
    exit 0
fi

if $LIST_ONLY; then
    echo "Available E2E suites (${#ALL_SUITES[@]}):"
    for suite in "${ALL_SUITES[@]}"; do
        if [[ -f "tests/${suite}.rs" ]]; then
            echo "  $suite"
        else
            echo "  $suite (missing)"
        fi
    done
    echo ""
    echo "Non-E2E targets (${#ALL_UNIT_TARGETS[@]}):"
    echo "  Unit suite (${#ALL_UNIT_FILES[@]}): ${ALL_UNIT_FILES[*]:0:5}..."
    echo "  VCR suite (${#ALL_VCR_FILES[@]}): ${ALL_VCR_FILES[*]:0:5}..."
    exit 0
fi

if [[ ${#SELECTED_SUITES[@]} -eq 0 ]]; then
    case "$PROFILE" in
        full)
            SELECTED_SUITES=("${ALL_SUITES[@]}")
            ;;
        focused)
            SELECTED_SUITES=(e2e_extension_registration e2e_tools)
            ;;
        ci)
            SELECTED_SUITES=(e2e_extension_registration)
            ;;
        quick)
            SELECTED_SUITES=()
            ;;
        *)
            echo "Unknown --profile value: $PROFILE (expected: quick|focused|ci|full)" >&2
            exit 1
            ;;
    esac
fi

if [[ ${#SELECTED_UNIT_TARGETS[@]} -eq 0 && "$SKIP_UNIT" == false ]]; then
    case "$PROFILE" in
        full|ci)
            SELECTED_UNIT_TARGETS=("${ALL_UNIT_TARGETS[@]}")
            ;;
        quick)
            SELECTED_UNIT_TARGETS=("${ALL_UNIT_FILES[@]}")
            ;;
        focused)
            SELECTED_UNIT_TARGETS=(
                "${ALL_UNIT_FILES[@]}"
                ext_conformance_matrix
                node_buffer_shim
                node_bun_api_matrix
                node_crypto_shim
                node_http_shim
                npm_module_stubs
                extensions_registration
                extensions_policy_negative
            )
            ;;
    esac
fi

if [[ "$SKIP_UNIT" == true ]]; then
    SELECTED_UNIT_TARGETS=()
fi

if [[ "$SKIP_E2E" == true ]]; then
    SELECTED_SUITES=()
fi

if [[ -n "$RERUN_FROM" ]]; then
    if [[ ! -f "$RERUN_FROM" ]]; then
        echo "Rerun summary not found: $RERUN_FROM" >&2
        exit 1
    fi
    mapfile -t rerun_suites < <(python3 - "$RERUN_FROM" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
for name in payload.get("failed_names", []):
    if isinstance(name, str) and name:
        print(name)
PY
)

    if [[ ${#rerun_suites[@]} -eq 0 ]]; then
        echo "[rerun] No failed suites found in $RERUN_FROM"
        exit 0
    fi
    SELECTED_SUITES=("${rerun_suites[@]}")
fi

if [[ -z "$DIFF_FROM" && -n "$RERUN_FROM" ]]; then
    DIFF_FROM="$RERUN_FROM"
fi

if [[ -n "$DIFF_FROM" && ! -f "$DIFF_FROM" ]]; then
    echo "Diff baseline summary not found: $DIFF_FROM" >&2
    exit 1
fi

if [[ -n "$SHARD_INDEX_RAW" || -n "$SHARD_TOTAL_RAW" ]]; then
    if [[ -z "$SHARD_INDEX_RAW" || -z "$SHARD_TOTAL_RAW" ]]; then
        echo "Both --shard-index and --shard-total are required when sharding is enabled." >&2
        exit 1
    fi
fi

if [[ ! "$SHARD_KIND" =~ ^(none|unit|suite|both)$ ]]; then
    echo "Invalid --shard-kind value: $SHARD_KIND (expected none|unit|suite|both)" >&2
    exit 1
fi

if [[ "$SHARD_KIND" != "none" ]]; then
    if [[ -z "$SHARD_INDEX_RAW" || -z "$SHARD_TOTAL_RAW" ]]; then
        echo "--shard-kind=$SHARD_KIND requires --shard-index and --shard-total." >&2
        exit 1
    fi
fi

if [[ -n "$SHARD_INDEX_RAW" ]]; then
    if ! [[ "$SHARD_INDEX_RAW" =~ ^[0-9]+$ ]] || ! [[ "$SHARD_TOTAL_RAW" =~ ^[0-9]+$ ]]; then
        echo "Shard values must be non-negative integers: index='$SHARD_INDEX_RAW' total='$SHARD_TOTAL_RAW'" >&2
        exit 1
    fi
    SHARD_INDEX="$SHARD_INDEX_RAW"
    SHARD_TOTAL="$SHARD_TOTAL_RAW"
    if (( SHARD_TOTAL <= 0 )); then
        echo "--shard-total must be > 0 (got $SHARD_TOTAL)" >&2
        exit 1
    fi
    if (( SHARD_INDEX >= SHARD_TOTAL )); then
        echo "--shard-index must be < --shard-total ($SHARD_INDEX >= $SHARD_TOTAL)" >&2
        exit 1
    fi
    SHARD_INDEX_JSON="$SHARD_INDEX"
    SHARD_TOTAL_JSON="$SHARD_TOTAL"
    if [[ -z "$SHARD_NAME" ]]; then
        SHARD_NAME="${SHARD_KIND}-${SHARD_INDEX}-of-${SHARD_TOTAL}"
    fi
else
    SHARD_KIND="none"
    SHARD_NAME="${SHARD_NAME:-unsharded}"
fi

if [[ -z "$CORRELATION_ID" ]]; then
    CORRELATION_ID="${TIMESTAMP}-${SHARD_NAME}"
fi
export CI_CORRELATION_ID="$CORRELATION_ID"

if (( ${#SELECTED_UNIT_TARGETS[@]} > 0 )); then
    mapfile -t SELECTED_UNIT_TARGETS < <(printf '%s\n' "${SELECTED_UNIT_TARGETS[@]}" | awk 'NF' | LC_ALL=C sort -u)
fi
if (( ${#SELECTED_SUITES[@]} > 0 )); then
    mapfile -t SELECTED_SUITES < <(printf '%s\n' "${SELECTED_SUITES[@]}" | awk 'NF' | LC_ALL=C sort -u)
fi

select_shard_items() {
    local shard_index="$1"
    local shard_total="$2"
    shift 2
    local items=("$@")
    local i=0
    for item in "${items[@]}"; do
        if (( shard_total <= 1 || (i % shard_total) == shard_index )); then
            printf '%s\n' "$item"
        fi
        i=$((i + 1))
    done
}

if [[ "$SHARD_KIND" == "unit" || "$SHARD_KIND" == "both" ]]; then
    if (( ${#SELECTED_UNIT_TARGETS[@]} > 0 )); then
        mapfile -t SELECTED_UNIT_TARGETS < <(
            select_shard_items "$SHARD_INDEX" "$SHARD_TOTAL" "${SELECTED_UNIT_TARGETS[@]}"
        )
    fi
fi

if [[ "$SHARD_KIND" == "suite" || "$SHARD_KIND" == "both" ]]; then
    if (( ${#SELECTED_SUITES[@]} > 0 )); then
        mapfile -t SELECTED_SUITES < <(
            select_shard_items "$SHARD_INDEX" "$SHARD_TOTAL" "${SELECTED_SUITES[@]}"
        )
    fi
fi

RERUN_JSON_VALUE="null"
if [[ -n "$RERUN_FROM" ]]; then
    RERUN_JSON_VALUE="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$RERUN_FROM")"
fi

DIFF_JSON_VALUE="null"
if [[ -n "$DIFF_FROM" ]]; then
    DIFF_JSON_VALUE="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$DIFF_FROM")"
fi

# ─── Environment Capture ─────────────────────────────────────────────────────

check_disk_headroom() {
    local min_free_mb="${VERIFY_MIN_FREE_MB:-2048}"
    local min_tmp_free_mb="${VERIFY_MIN_TMP_FREE_MB:-8192}"
    local min_inode_free_pct="${VERIFY_MIN_FREE_INODE_PCT:-5}"
    local tmp_dir="${TMPDIR:-/tmp}"
    local cargo_target_dir="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
    local cargo_home="${CARGO_HOME:-${HOME:-}/.cargo}"

    if ! [[ "$min_free_mb" =~ ^[0-9]+$ ]] || [[ "$min_free_mb" -le 0 ]]; then
        echo "[preflight] Invalid VERIFY_MIN_FREE_MB='$min_free_mb' (must be positive integer)" >&2
        return 1
    fi
    if ! [[ "$min_tmp_free_mb" =~ ^[0-9]+$ ]] || [[ "$min_tmp_free_mb" -le 0 ]]; then
        echo "[preflight] Invalid VERIFY_MIN_TMP_FREE_MB='$min_tmp_free_mb' (must be positive integer)" >&2
        return 1
    fi
    if ! [[ "$min_inode_free_pct" =~ ^[0-9]+$ ]] || [[ "$min_inode_free_pct" -le 0 || "$min_inode_free_pct" -ge 100 ]]; then
        echo "[preflight] Invalid VERIFY_MIN_FREE_INODE_PCT='$min_inode_free_pct' (must be integer 1-99)" >&2
        return 1
    fi

    local min_free_kb=$((min_free_mb * 1024))
    local min_tmp_free_kb=$((min_tmp_free_mb * 1024))
    local failed=false
    local -a probe_specs=(
        "$PROJECT_ROOT|repo|$min_free_kb|$min_free_mb"
        "$ARTIFACT_DIR|artifacts|$min_free_kb|$min_free_mb"
        "$tmp_dir|tmp|$min_tmp_free_kb|$min_tmp_free_mb"
        "$cargo_target_dir|cargo_target|$min_tmp_free_kb|$min_tmp_free_mb"
        "$cargo_home|cargo_home|$min_tmp_free_kb|$min_tmp_free_mb"
    )

    echo "[preflight] Disk headroom check: repo/artifacts >=${min_free_mb}MB, tmp/cargo >=${min_tmp_free_mb}MB, inodes >=${min_inode_free_pct}%"

    for probe_spec in "${probe_specs[@]}"; do
        IFS='|' read -r raw_path probe_label required_kb required_mb <<<"$probe_spec"

        local probe_path="$raw_path"
        while [[ ! -e "$probe_path" && "$probe_path" != "/" ]]; do
            probe_path="$(dirname "$probe_path")"
        done

        if [[ ! -e "$probe_path" ]]; then
            echo "[preflight] WARN: cannot probe path '$raw_path' (no existing ancestor found)" >&2
            continue
        fi

        local disk_row
        disk_row="$(df -Pk "$probe_path" | awk 'NR==2 {print $4 "|" $6}')"
        if [[ -z "$disk_row" ]]; then
            echo "[preflight] WARN: unable to read disk stats for '$probe_path'" >&2
            failed=true
            continue
        fi

        local avail_kb mount_point
        avail_kb="${disk_row%%|*}"
        mount_point="${disk_row#*|}"

        local inode_used_pct inode_free_pct
        inode_used_pct="$(df -Pi "$probe_path" | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
        if [[ -z "$inode_used_pct" ]]; then
            inode_free_pct=0
        else
            inode_free_pct=$((100 - inode_used_pct))
        fi

        local avail_mb
        avail_mb=$((avail_kb / 1024))
        echo "[preflight] target=$probe_label mount=$mount_point free=${avail_mb}MB inode_free=${inode_free_pct}% path=$raw_path"

        if (( avail_kb < required_kb )); then
            echo "[preflight] FAIL: target '$probe_label' on mount '$mount_point' has ${avail_mb}MB free (< ${required_mb}MB required)" >&2
            failed=true
        fi
        if (( inode_free_pct < min_inode_free_pct )); then
            echo "[preflight] FAIL: mount '$mount_point' has ${inode_free_pct}% free inodes (< ${min_inode_free_pct}% required)" >&2
            failed=true
        fi
    done

    if $failed; then
        cat >&2 <<EOF
[preflight] Verification aborted: insufficient filesystem headroom.
[preflight] Free space on the workspace filesystem is too low for cargo build/test artifacts.
[preflight] Fix by freeing disk space, or moving temp/build/artifact paths to roomier mounts:
[preflight]   TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/pi_verify_target ./verify --profile quick
[preflight]   CARGO_HOME=/dev/shm/pi_cargo ./verify --profile quick
[preflight]   E2E_ARTIFACT_DIR=/dev/shm/pi_e2e_results/$TIMESTAMP ./verify --profile quick
[preflight] You can also tune thresholds:
[preflight]   VERIFY_MIN_FREE_MB=1024 VERIFY_MIN_TMP_FREE_MB=2048 ./verify --profile quick
EOF
        return 1
    fi

    echo "[preflight] PASS"
    return 0
}
capture_env() {
    local env_file="$ARTIFACT_DIR/environment.json"
    local rustc_version cargo_version os_info git_sha git_branch
    mkdir -p "$ARTIFACT_DIR"
    rustc_version="$(rustc --version 2>/dev/null || echo 'unknown')"
    cargo_version="$(cargo --version 2>/dev/null || echo 'unknown')"
    os_info="$(uname -srm 2>/dev/null || echo 'unknown')"
    git_sha="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    git_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"

    cat > "$env_file" <<ENVJSON
{
  "schema": "pi.e2e.environment.v1",
  "timestamp": "$TIMESTAMP",
  "profile": "$PROFILE",
  "rerun_from": $RERUN_JSON_VALUE,
  "diff_from": $DIFF_JSON_VALUE,
  "rustc": "$rustc_version",
  "cargo": "$cargo_version",
  "os": "$os_info",
  "git_sha": "$git_sha",
  "git_branch": "$git_branch",
  "parallelism": $PARALLELISM,
  "log_level": "$LOG_LEVEL",
  "artifact_dir": "$ARTIFACT_DIR",
  "correlation_id": "$CORRELATION_ID",
  "shard": {
    "kind": "$SHARD_KIND",
    "name": "$SHARD_NAME",
    "index": $SHARD_INDEX_JSON,
    "total": $SHARD_TOTAL_JSON
  },
  "cargo_target_dir": "${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}",
  "vcr_mode": "${VCR_MODE:-unset}",
  "unit_targets": $(printf '%s\n' "${SELECTED_UNIT_TARGETS[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'),
  "e2e_suites": $(printf '%s\n' "${SELECTED_SUITES[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]')
}
ENVJSON
    echo "[env] Captured environment to $env_file"
}

write_shard_manifest() {
    local manifest_file="$ARTIFACT_DIR/ci_shard_manifest.json"
    cat > "$manifest_file" <<SHARDJSON
{
  "schema": "pi.verify.shard_manifest.v1",
  "generated_at": "$TIMESTAMP",
  "profile": "$PROFILE",
  "artifact_dir": "$ARTIFACT_DIR",
  "correlation_id": "$CORRELATION_ID",
  "shard": {
    "kind": "$SHARD_KIND",
    "name": "$SHARD_NAME",
    "index": $SHARD_INDEX_JSON,
    "total": $SHARD_TOTAL_JSON
  },
  "selection": {
    "unit_targets": $(printf '%s\n' "${SELECTED_UNIT_TARGETS[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'),
    "e2e_suites": $(printf '%s\n' "${SELECTED_SUITES[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]')
  }
}
SHARDJSON
    echo "[shard] Manifest written to $manifest_file"
}

# ─── Lint Gates ──────────────────────────────────────────────────────────────

run_lint_gates() {
    if $SKIP_LINT; then
        echo "[lint] Skipped (--skip-lint)"
        return 0
    fi

    local lint_dir="$ARTIFACT_DIR/lint"
    mkdir -p "$lint_dir"
    local lint_ok=true

    echo "[lint] Running format check..."
    if cargo fmt --check > "$lint_dir/fmt.log" 2>&1; then
        echo "[lint] cargo fmt: PASS"
    else
        echo "[lint] cargo fmt: FAIL (see $lint_dir/fmt.log)"
        lint_ok=false
    fi

    echo "[lint] Running clippy..."
    if cargo clippy --all-targets -- -D warnings > "$lint_dir/clippy.log" 2>&1; then
        echo "[lint] clippy: PASS"
    else
        echo "[lint] clippy: FAIL (see $lint_dir/clippy.log)"
        lint_ok=false
    fi

    if $lint_ok; then
        echo "[lint] All gates passed"
        return 0
    else
        echo "[lint] Some gates failed" >&2
        return 1
    fi
}

# ─── Lib Inline Tests ────────────────────────────────────────────────────────

run_lib_tests() {
    local lib_dir="$ARTIFACT_DIR/lib"
    local log_file="$lib_dir/output.log"
    local result_file="$lib_dir/result.json"
    mkdir -p "$lib_dir"

    echo "[lib] Running inline unit tests (cargo test --lib)..."
    local start_epoch exit_code duration_ms
    start_epoch=$(date +%s%N 2>/dev/null || date +%s)

    set +e
    cargo test --lib -- --test-threads="$PARALLELISM" 2>&1 | tee "$log_file"
    exit_code=${PIPESTATUS[0]}
    set -e

    local end_epoch
    end_epoch=$(date +%s%N 2>/dev/null || date +%s)
    if [[ ${#start_epoch} -gt 12 ]]; then
        duration_ms=$(( (end_epoch - start_epoch) / 1000000 ))
    else
        duration_ms=$(( (end_epoch - start_epoch) * 1000 ))
    fi

    local passed failed ignored total
    passed=$(grep -oP '\d+ passed' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    failed=$(grep -oP '\d+ failed' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    ignored=$(grep -oP '\d+ ignored' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    total=$((passed + failed + ignored))

    cat > "$result_file" <<RESULTJSON
{
  "schema": "pi.e2e.result.v1",
  "result_kind": "lib",
  "correlation_id": "$CORRELATION_ID",
  "target": "lib",
  "exit_code": $exit_code,
  "duration_ms": $duration_ms,
  "passed": $passed,
  "failed": $failed,
  "ignored": $ignored,
  "total": $total,
  "log_file": "$log_file",
  "timestamp": "$TIMESTAMP"
}
RESULTJSON

    if [[ $exit_code -eq 0 ]]; then
        echo "[lib] PASS ($passed passed, $ignored ignored, ${duration_ms}ms)"
    else
        echo "[lib] FAIL (exit $exit_code, $failed failed, $passed passed, ${duration_ms}ms)"
    fi

    return $exit_code
}

# ─── Build First ──────────────────────────────────────────────────────────────

build_tests() {
    echo "[build] Compiling selected verification targets..."
    local build_log="$ARTIFACT_DIR/build.log"
    local build_ok=true

    for target in "${SELECTED_UNIT_TARGETS[@]}"; do
        if [[ ! -f "tests/${target}.rs" ]]; then
            echo "[build]   $target (unit target missing, skipping)"
            continue
        fi
        echo "[build]   unit:$target"
        if ! cargo test --test "$target" --no-run 2>>"$build_log"; then
            echo "[build]   unit:$target FAILED" >&2
            build_ok=false
        fi
    done

    for suite in "${SELECTED_SUITES[@]}"; do
        if [[ ! -f "tests/${suite}.rs" ]]; then
            echo "[build]   $suite (suite missing, skipping)"
            continue
        fi
        echo "[build]   e2e:$suite"
        if ! cargo test --test "$suite" --no-run 2>>"$build_log"; then
            echo "[build]   e2e:$suite FAILED" >&2
            build_ok=false
        fi
    done

    if $build_ok; then
        echo "[build] OK"
        return 0
    else
        echo "[build] Some targets failed — see $build_log" >&2
        return 1
    fi
}

# ─── Run a Single Suite ──────────────────────────────────────────────────────

run_unit_target() {
    local target="$1"
    local target_dir="$ARTIFACT_DIR/unit/$target"
    local log_file="$target_dir/output.log"
    local result_file="$target_dir/result.json"
    local start_epoch exit_code duration_ms

    if [[ ! -f "tests/${target}.rs" ]]; then
        echo "[unit] $target: test file not found (tests/${target}.rs)"
        return 1
    fi

    mkdir -p "$target_dir"

    echo "[unit] Running: $target"
    start_epoch=$(date +%s%N 2>/dev/null || date +%s)

    export TEST_LOG_JSONL_PATH="$target_dir/test-log.jsonl"
    export TEST_ARTIFACT_INDEX_PATH="$target_dir/artifact-index.jsonl"
    export RUST_LOG="$LOG_LEVEL"

    set +e
    cargo test \
        --test "$target" \
        -- \
        --test-threads="$PARALLELISM" \
        2>&1 | tee "$log_file"
    exit_code=${PIPESTATUS[0]}
    set -e

    local end_epoch
    end_epoch=$(date +%s%N 2>/dev/null || date +%s)
    if [[ ${#start_epoch} -gt 12 ]]; then
        duration_ms=$(( (end_epoch - start_epoch) / 1000000 ))
    else
        duration_ms=$(( (end_epoch - start_epoch) * 1000 ))
    fi

    local passed failed ignored total
    passed=$(grep -oP '\d+ passed' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    failed=$(grep -oP '\d+ failed' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    ignored=$(grep -oP '\d+ ignored' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    total=$((passed + failed + ignored))

    cat > "$result_file" <<RESULTJSON
{
  "schema": "pi.e2e.result.v1",
  "result_kind": "unit",
  "correlation_id": "$CORRELATION_ID",
  "target": "$target",
  "exit_code": $exit_code,
  "duration_ms": $duration_ms,
  "passed": $passed,
  "failed": $failed,
  "ignored": $ignored,
  "total": $total,
  "log_file": "$log_file",
  "test_log_jsonl": "$target_dir/test-log.jsonl",
  "artifact_index_jsonl": "$target_dir/artifact-index.jsonl",
  "timestamp": "$TIMESTAMP"
}
RESULTJSON

    if [[ $exit_code -eq 0 ]]; then
        echo "[unit] $target: PASS ($passed passed, $ignored ignored, ${duration_ms}ms)"
    else
        echo "[unit] $target: FAIL (exit $exit_code, $failed failed, $passed passed, ${duration_ms}ms)"
        echo "[triage] Unit logs: $log_file"
        echo "[triage] Unit artifacts: $target_dir/"
        if [[ -f "$target_dir/test-log.jsonl" ]]; then
            echo "[triage] Unit JSONL log: $target_dir/test-log.jsonl"
        fi
    fi

    return $exit_code
}

run_suite() {
    local suite="$1"
    local suite_dir="$ARTIFACT_DIR/$suite"
    local log_file="$suite_dir/output.log"
    local result_file="$suite_dir/result.json"
    local start_epoch exit_code duration_ms

    mkdir -p "$suite_dir"

    echo "[suite] Running: $suite"

    start_epoch=$(date +%s%N 2>/dev/null || date +%s)

    # Set per-suite environment for test harness logging.
    export TEST_LOG_JSONL_PATH="$suite_dir/test-log.jsonl"
    export TEST_ARTIFACT_INDEX_PATH="$suite_dir/artifact-index.jsonl"
    export RUST_LOG="$LOG_LEVEL"

    set +e
    cargo test \
        --test "$suite" \
        -- \
        --test-threads="$PARALLELISM" \
        2>&1 | tee "$log_file"
    exit_code=${PIPESTATUS[0]}
    set -e

    local end_epoch
    end_epoch=$(date +%s%N 2>/dev/null || date +%s)

    # Compute duration (nanosecond precision if available, else seconds).
    if [[ ${#start_epoch} -gt 12 ]]; then
        duration_ms=$(( (end_epoch - start_epoch) / 1000000 ))
    else
        duration_ms=$(( (end_epoch - start_epoch) * 1000 ))
    fi

    # Parse test counts from cargo test output.
    local passed failed ignored total
    passed=$(grep -oP '\d+ passed' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    failed=$(grep -oP '\d+ failed' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    ignored=$(grep -oP '\d+ ignored' "$log_file" | tail -1 | grep -oP '\d+' || echo "0")
    total=$((passed + failed + ignored))

    cat > "$result_file" <<RESULTJSON
{
  "schema": "pi.e2e.result.v1",
  "result_kind": "suite",
  "correlation_id": "$CORRELATION_ID",
  "suite": "$suite",
  "exit_code": $exit_code,
  "duration_ms": $duration_ms,
  "passed": $passed,
  "failed": $failed,
  "ignored": $ignored,
  "total": $total,
  "log_file": "$log_file",
  "test_log_jsonl": "$suite_dir/test-log.jsonl",
  "artifact_index_jsonl": "$suite_dir/artifact-index.jsonl",
  "timestamp": "$TIMESTAMP"
}
RESULTJSON

    if [[ $exit_code -eq 0 ]]; then
        echo "[suite] $suite: PASS ($passed passed, $ignored ignored, ${duration_ms}ms)"
    else
        echo "[suite] $suite: FAIL (exit $exit_code, $failed failed, $passed passed, ${duration_ms}ms)"
        # Emit failure triage hints.
        echo "[triage] Logs: $log_file"
        echo "[triage] Artifacts: $suite_dir/"
        if [[ -f "$suite_dir/test-log.jsonl" ]]; then
            echo "[triage] JSONL log: $suite_dir/test-log.jsonl"
        fi
    fi

    return $exit_code
}

# ─── Summary Manifest ────────────────────────────────────────────────────────

write_summary() {
    local summary_file="$ARTIFACT_DIR/summary.json"
    local total_units=${#SELECTED_UNIT_TARGETS[@]}
    local passed_units=0
    local failed_units=0
    local failed_unit_names=()
    local total_suites=${#SELECTED_SUITES[@]}
    local passed_suites=0
    local failed_suites=0
    local failed_names=()

    echo "[summary] Writing manifest to $summary_file"

    # Read unit target results.
    local unit_results_array="["
    local first_unit=true
    for target in "${SELECTED_UNIT_TARGETS[@]}"; do
        local result_file="$ARTIFACT_DIR/unit/$target/result.json"
        if [[ -f "$result_file" ]]; then
            local exit_code
            exit_code=$(python3 -c "import json; print(json.load(open('$result_file'))['exit_code'])" 2>/dev/null || echo "1")
            if [[ "$exit_code" -eq 0 ]]; then
                ((passed_units++)) || true
            else
                ((failed_units++)) || true
                failed_unit_names+=("$target")
            fi
            if ! $first_unit; then unit_results_array+=","; fi
            unit_results_array+="$(cat "$result_file")"
            first_unit=false
        else
            ((failed_units++)) || true
            failed_unit_names+=("$target")
            if ! $first_unit; then unit_results_array+=","; fi
            unit_results_array+="{\"target\":\"$target\",\"exit_code\":1,\"error\":\"no result file\"}"
            first_unit=false
        fi
    done
    unit_results_array+="]"

    # Read E2E suite results.
    local suite_results_array="["
    local first_suite=true
    for suite in "${SELECTED_SUITES[@]}"; do
        local result_file="$ARTIFACT_DIR/$suite/result.json"
        if [[ -f "$result_file" ]]; then
            local exit_code
            exit_code=$(python3 -c "import json; print(json.load(open('$result_file'))['exit_code'])" 2>/dev/null || echo "1")
            if [[ "$exit_code" -eq 0 ]]; then
                ((passed_suites++)) || true
            else
                ((failed_suites++)) || true
                failed_names+=("$suite")
            fi
            if ! $first_suite; then suite_results_array+=","; fi
            suite_results_array+="$(cat "$result_file")"
            first_suite=false
        else
            ((failed_suites++)) || true
            failed_names+=("$suite")
            if ! $first_suite; then suite_results_array+=","; fi
            suite_results_array+="{\"suite\":\"$suite\",\"exit_code\":1,\"error\":\"no result file\"}"
            first_suite=false
        fi
    done
    suite_results_array+="]"

    # Redact secrets from logs.
    redact_secrets

    cat > "$summary_file" <<SUMMARYJSON
{
  "schema": "pi.e2e.summary.v1",
  "timestamp": "$TIMESTAMP",
  "profile": "$PROFILE",
  "rerun_from": $RERUN_JSON_VALUE,
  "diff_from": $DIFF_JSON_VALUE,
  "artifact_dir": "$ARTIFACT_DIR",
  "correlation_id": "$CORRELATION_ID",
  "shard": {
    "kind": "$SHARD_KIND",
    "name": "$SHARD_NAME",
    "index": $SHARD_INDEX_JSON,
    "total": $SHARD_TOTAL_JSON
  },
  "total_units": $total_units,
  "passed_units": $passed_units,
  "failed_units": $failed_units,
  "failed_unit_names": $(printf '%s\n' "${failed_unit_names[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'),
  "total_suites": $total_suites,
  "passed_suites": $passed_suites,
  "failed_suites": $failed_suites,
  "failed_names": $(printf '%s\n' "${failed_names[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'),
  "unit_targets": $unit_results_array,
  "suites": $suite_results_array
}
SUMMARYJSON

    # Lint status.
    local lint_status="skip"
    if ! $SKIP_LINT; then
        if [[ -f "$ARTIFACT_DIR/lint/fmt.log" ]] && [[ -f "$ARTIFACT_DIR/lint/clippy.log" ]]; then
            local fmt_ok clippy_ok
            fmt_ok=$([[ $(wc -c < "$ARTIFACT_DIR/lint/fmt.log") -eq 0 ]] && echo "pass" || echo "fail")
            clippy_ok=$(grep -q "error" "$ARTIFACT_DIR/lint/clippy.log" 2>/dev/null && echo "fail" || echo "pass")
            lint_status="${fmt_ok}/${clippy_ok}"
        else
            lint_status="not_run"
        fi
    fi

    # Lib test status.
    local lib_status="not_run"
    if [[ -f "$ARTIFACT_DIR/lib/result.json" ]]; then
        local lib_exit
        lib_exit=$(python3 -c "import json; print(json.load(open('$ARTIFACT_DIR/lib/result.json'))['exit_code'])" 2>/dev/null || echo "1")
        lib_status=$( [[ "$lib_exit" -eq 0 ]] && echo "pass" || echo "fail" )
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo " Verification Summary (profile: $PROFILE)"
    echo " Correlation:    $CORRELATION_ID"
    echo " Shard:          kind=$SHARD_KIND name=$SHARD_NAME index=${SHARD_INDEX_JSON} total=${SHARD_TOTAL_JSON}"
    echo " Lint gates:     $lint_status"
    echo " Lib inline:     $lib_status"
    echo " Integration:    $passed_units/$total_units passed"
    echo " E2E suites:     $passed_suites/$total_suites passed"
    if [[ $failed_units -gt 0 ]]; then
        echo " Failed targets: ${failed_unit_names[*]}"
    fi
    if [[ $failed_suites -gt 0 ]]; then
        echo " Failed E2E:     ${failed_names[*]}"
    fi
    echo " Artifacts: $ARTIFACT_DIR"
    echo "═══════════════════════════════════════════════════════════════"
}

# ─── Structured Failure Diagnostics (bd-1f42.8.6.4) ─────────────────────────

generate_failure_diagnostics() {
    local diagnostics_index="$ARTIFACT_DIR/failure_diagnostics_index.json"
    local run_timeline="$ARTIFACT_DIR/failure_timeline.jsonl"
    local summary_file="$ARTIFACT_DIR/summary.json"

    if ARTIFACT_DIR="$ARTIFACT_DIR" \
        SUMMARY_FILE="$summary_file" \
        DIAGNOSTICS_INDEX="$diagnostics_index" \
        RUN_TIMELINE="$run_timeline" \
        python3 - <<'PY'
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

artifact_dir = Path(os.environ["ARTIFACT_DIR"])
summary_file = Path(os.environ["SUMMARY_FILE"])
diagnostics_index = Path(os.environ["DIAGNOSTICS_INDEX"])
run_timeline_path = Path(os.environ["RUN_TIMELINE"])

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TEST_RESULT_RE = re.compile(r"^test\s+([A-Za-z0-9_:\-./]+)\s+\.\.\.\s+(ok|FAILED|ignored)$")
FAILURE_HEADER_RE = re.compile(r"^----\s+(.+?)\s+stdout\s+----$")
PANIC_RE = re.compile(r"^thread '([^']+)'(?: \([^)]*\))? panicked at (.+?):(\d+):(\d+):$")


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def dedupe_preserve(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def as_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def classify_root_cause(message: str, raw_log: str) -> str:
    haystack = f"{message}\n{raw_log}".lower()
    if "timed out" in haystack or "timeout" in haystack:
        return "timeout"
    if "assertion" in haystack or "assert_eq!" in haystack or "assert_ne!" in haystack:
        return "assertion_failure"
    if "permission denied" in haystack:
        return "permission_denied"
    if "connection refused" in haystack or "connection reset" in haystack:
        return "network_io"
    if "not found" in haystack and ("file" in haystack or "path" in haystack):
        return "missing_file"
    if "panicked at" in haystack or "panic" in haystack:
        return "panic"
    return "unknown"


def remediation_summary(root_cause_class: str) -> str:
    if root_cause_class == "timeout":
        return "Inspect stalled operations and timeout thresholds; use timeline gaps to isolate hung steps."
    if root_cause_class == "assertion_failure":
        return "Inspect assertion preconditions and fixture state for the first failing scenario."
    if root_cause_class == "permission_denied":
        return "Verify executable permissions, filesystem ACLs, and sandbox constraints in the failing path."
    if root_cause_class == "network_io":
        return "Inspect network mocks/endpoints and retry/error handling around the failing scenario."
    if root_cause_class == "missing_file":
        return "Verify fixture/materialization steps and path wiring before test execution."
    if root_cause_class == "panic":
        return "Inspect panic location and guard assumptions at the reported source location."
    return "Inspect the first failing assertion and timeline to determine root cause."


def parse_failures_from_output(lines: list[str]) -> tuple[list[str], dict | None, list[dict], str | None]:
    impacted: list[str] = []
    first_assertion: dict | None = None
    events: list[dict] = []
    rerun_hint: str | None = None

    in_failure_list = False
    for index, raw in enumerate(lines):
        line_no = index + 1
        clean = strip_ansi(raw).rstrip()

        test_match = TEST_RESULT_RE.match(clean)
        if test_match:
            test_name, status = test_match.groups()
            events.append(
                {
                    "source": "cargo_output",
                    "event_type": "test_result",
                    "line_no": line_no,
                    "test": test_name,
                    "message": f"{test_name} -> {status}",
                    "context": {"status": status},
                }
            )
            if status != "ok":
                impacted.append(test_name)

        if clean.strip() == "failures:":
            in_failure_list = True
            events.append(
                {
                    "source": "cargo_output",
                    "event_type": "failure_list_start",
                    "line_no": line_no,
                    "message": "failures:",
                }
            )
            continue

        if in_failure_list:
            stripped = clean.strip()
            if not stripped:
                continue
            if clean.startswith("    ") and " " not in stripped and "failures" not in stripped.lower():
                impacted.append(stripped)
                events.append(
                    {
                        "source": "cargo_output",
                        "event_type": "failure_list_item",
                        "line_no": line_no,
                        "test": stripped,
                        "message": stripped,
                    }
                )
                continue
            in_failure_list = False

        header_match = FAILURE_HEADER_RE.match(clean)
        if header_match:
            test_name = header_match.group(1).strip()
            if test_name:
                impacted.append(test_name)
            events.append(
                {
                    "source": "cargo_output",
                    "event_type": "failure_section",
                    "line_no": line_no,
                    "test": test_name if test_name else None,
                    "message": clean,
                }
            )

        panic_match = PANIC_RE.match(clean)
        if panic_match:
            test_name, file_path, src_line, src_column = panic_match.groups()
            impacted.append(test_name)
            panic_message = ""
            for look_ahead in range(index + 1, min(index + 4, len(lines))):
                candidate = strip_ansi(lines[look_ahead]).strip()
                if candidate:
                    panic_message = candidate
                    break
            assertion_payload = {
                "test": test_name,
                "location": {
                    "file": file_path,
                    "line": int(src_line),
                    "column": int(src_column),
                },
                "message": panic_message,
                "raw_header": clean,
            }
            if first_assertion is None:
                first_assertion = assertion_payload
            events.append(
                {
                    "source": "cargo_output",
                    "event_type": "panic_assertion",
                    "line_no": line_no,
                    "test": test_name,
                    "message": panic_message,
                    "context": assertion_payload["location"],
                }
            )

        if "error: test failed, to rerun pass `--test " in clean:
            rerun_hint = clean
            events.append(
                {
                    "source": "cargo_output",
                    "event_type": "rerun_hint",
                    "line_no": line_no,
                    "message": clean,
                }
            )

    impacted = dedupe_preserve(impacted)
    return impacted, first_assertion, events, rerun_hint


summary = read_json(summary_file)
if not isinstance(summary, dict):
    raise SystemExit(f"[failure] summary.json missing or invalid: {summary_file}")

correlation_id = str(summary.get("correlation_id", "")).strip()
suite_entries = summary.get("suites", [])
if not isinstance(suite_entries, list):
    suite_entries = []

run_events: list[dict] = [
    {
        "schema": "pi.e2e.failure_timeline_event.v1",
        "correlation_id": correlation_id,
        "suite": "__run__",
        "ordinal": 1,
        "source": "runner",
        "event_type": "run_summary",
        "message": "Generating failure diagnostics from summary.json",
        "context": {
            "summary_path": str(summary_file),
            "failed_suites": int(summary.get("failed_suites") or 0),
        },
    }
]

diagnostic_entries: list[dict] = []
failed_suites = [
    entry
    for entry in suite_entries
    if isinstance(entry, dict) and as_int(entry.get("exit_code"), default=1) != 0
]

for suite_entry in failed_suites:
    suite_name = str(suite_entry.get("suite", "")).strip()
    if not suite_name:
        continue
    suite_dir = artifact_dir / suite_name
    suite_dir.mkdir(parents=True, exist_ok=True)

    result_path = suite_dir / "result.json"
    output_log_path = Path(str(suite_entry.get("log_file", suite_dir / "output.log")))
    test_log_jsonl_path = suite_dir / "test-log.jsonl"
    artifact_index_jsonl_path = suite_dir / "artifact-index.jsonl"
    digest_path = suite_dir / "failure_digest.json"
    timeline_path = suite_dir / "failure_timeline.jsonl"

    try:
        output_lines = output_log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        output_lines = []

    impacted_scenarios, first_assertion, cargo_events, rerun_hint = parse_failures_from_output(output_lines)
    if first_assertion is None:
        fallback_test = impacted_scenarios[0] if impacted_scenarios else suite_name
        first_assertion = {
            "test": fallback_test,
            "location": {
                "file": "",
                "line": 0,
                "column": 0,
            },
            "message": "No explicit panic assertion found in output.log",
            "raw_header": "",
        }
    if not impacted_scenarios:
        impacted_scenarios = [str(first_assertion.get("test", suite_name))]

    first_assertion_message = str(first_assertion.get("message", "")).strip()
    root_cause_class = classify_root_cause(first_assertion_message, "\n".join(output_lines))
    targeted_test = str(first_assertion.get("test", "")).strip()
    runner_replay = f"./scripts/e2e/run_all.sh --profile focused --skip-lint --suite {suite_name}"
    suite_replay = f"cargo test --test {suite_name} -- --nocapture"
    targeted_replay = (
        f"cargo test --test {suite_name} {targeted_test} -- --nocapture"
        if targeted_test
        else ""
    )

    timeline_events: list[dict] = []
    timeline_events.append(
        {
            "source": "result",
            "event_type": "suite_failure_summary",
            "message": f"suite {suite_name} failed with exit_code={suite_entry.get('exit_code')}",
            "context": {
                "result_path": str(result_path),
                "output_log": str(output_log_path),
                "test_log_jsonl": str(test_log_jsonl_path),
                "artifact_index_jsonl": str(artifact_index_jsonl_path),
                "failed": int(suite_entry.get("failed") or 0),
                "passed": int(suite_entry.get("passed") or 0),
                "duration_ms": int(suite_entry.get("duration_ms") or 0),
            },
        }
    )
    timeline_events.extend(cargo_events)

    if test_log_jsonl_path.exists():
        for line_no, raw_line in enumerate(
            test_log_jsonl_path.read_text(encoding="utf-8", errors="replace").splitlines(),
            start=1,
        ):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except Exception:
                timeline_events.append(
                    {
                        "source": "test_log_jsonl",
                        "event_type": "invalid_json",
                        "line_no": line_no,
                        "message": "Invalid JSON record in test-log.jsonl",
                    }
                )
                continue
            if not isinstance(payload, dict):
                continue
            timeline_events.append(
                {
                    "source": "test_log_jsonl",
                    "event_type": str(payload.get("type") or "log"),
                    "line_no": line_no,
                    "test": payload.get("test"),
                    "ts": payload.get("ts"),
                    "t_ms": payload.get("t_ms"),
                    "message": payload.get("message"),
                    "context": {
                        "trace_id": payload.get("trace_id"),
                        "level": payload.get("level"),
                        "category": payload.get("category"),
                    },
                }
            )

    formatted_timeline: list[dict] = []
    for ordinal, event in enumerate(timeline_events, start=1):
        rendered = {
            "schema": "pi.e2e.failure_timeline_event.v1",
            "correlation_id": correlation_id,
            "suite": suite_name,
            "ordinal": ordinal,
            "source": event.get("source", "unknown"),
            "event_type": event.get("event_type", "unknown"),
        }
        for key in ("line_no", "test", "ts", "t_ms", "message", "context"):
            if key in event and event.get(key) not in (None, ""):
                rendered[key] = event.get(key)
        formatted_timeline.append(rendered)

    with timeline_path.open("w", encoding="utf-8") as handle:
        for event in formatted_timeline:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")

    digest_payload = {
        "schema": "pi.e2e.failure_digest.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "correlation_id": correlation_id,
        "suite": suite_name,
        "exit_code": as_int(suite_entry.get("exit_code"), default=1),
        "root_cause_class": root_cause_class,
        "impacted_scenario_ids": impacted_scenarios,
        "first_failing_assertion": first_assertion,
        "remediation_pointer": {
            "class": root_cause_class,
            "summary": remediation_summary(root_cause_class),
            "replay_command": runner_replay,
            "suite_replay_command": suite_replay,
            "targeted_test_replay_command": targeted_replay,
            "cargo_rerun_hint": rerun_hint or "",
        },
        "artifact_paths": {
            "result_json": str(result_path),
            "output_log": str(output_log_path),
            "test_log_jsonl": str(test_log_jsonl_path),
            "artifact_index_jsonl": str(artifact_index_jsonl_path),
            "timeline_jsonl": str(timeline_path),
            "runner_summary_json": str(summary_file),
        },
        "timeline": {
            "schema": "pi.e2e.failure_timeline_event.v1",
            "path": str(timeline_path),
            "event_count": len(formatted_timeline),
        },
    }
    digest_path.write_text(json.dumps(digest_payload, indent=2) + "\n", encoding="utf-8")

    diagnostic_entry = {
        "suite": suite_name,
        "digest_path": str(digest_path),
        "timeline_path": str(timeline_path),
        "root_cause_class": root_cause_class,
        "impacted_scenario_ids": impacted_scenarios,
        "first_failing_assertion": first_assertion,
    }
    diagnostic_entries.append(diagnostic_entry)

    for event in formatted_timeline:
        run_events.append(event)

run_events.append(
    {
        "schema": "pi.e2e.failure_timeline_event.v1",
        "correlation_id": correlation_id,
        "suite": "__run__",
        "ordinal": len(run_events) + 1,
        "source": "runner",
        "event_type": "diagnostics_complete",
        "message": "Failure diagnostics generation complete",
        "context": {
            "failed_suite_count": len(diagnostic_entries),
            "diagnostics_index": str(diagnostics_index),
        },
    }
)

for ordinal, event in enumerate(run_events, start=1):
    event["ordinal"] = ordinal

run_timeline_path.parent.mkdir(parents=True, exist_ok=True)
with run_timeline_path.open("w", encoding="utf-8") as handle:
    for event in run_events:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")

index_payload = {
    "schema": "pi.e2e.failure_diagnostics_index.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "correlation_id": correlation_id,
    "artifact_dir": str(artifact_dir),
    "failed_suite_count": len(diagnostic_entries),
    "suites": diagnostic_entries,
    "run_timeline_path": str(run_timeline_path),
}
diagnostics_index.parent.mkdir(parents=True, exist_ok=True)
diagnostics_index.write_text(json.dumps(index_payload, indent=2) + "\n", encoding="utf-8")

summary["failure_diagnostics"] = {
    "schema": "pi.e2e.failure_diagnostics.v1",
    "correlation_id": correlation_id,
    "index_path": str(diagnostics_index),
    "run_timeline_path": str(run_timeline_path),
    "failed_suite_count": len(diagnostic_entries),
    "suites": diagnostic_entries,
}
summary_file.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

print("STRUCTURED FAILURE DIAGNOSTICS GENERATED")
print(f"- Index: {diagnostics_index}")
print(f"- Run timeline: {run_timeline_path}")
print(f"- Failed suites covered: {len(diagnostic_entries)}")
for entry in diagnostic_entries:
    suite_name = entry.get("suite")
    digest_path = entry.get("digest_path")
    timeline_path = entry.get("timeline_path")
    print(f"- {suite_name}: digest={digest_path} timeline={timeline_path}")
PY
    then
        echo "[failure] Structured failure diagnostics generated ($diagnostics_index)"
        return 0
    else
        echo "[failure] Failed to generate structured failure diagnostics" >&2
        return 1
    fi
}

# ─── Replay Bundle (bd-1f42.8.7) ─────────────────────────────────────────────

generate_replay_bundle() {
    local bundle_file="$ARTIFACT_DIR/replay_bundle.json"
    local summary_file="$ARTIFACT_DIR/summary.json"
    local env_file="$ARTIFACT_DIR/environment.json"
    local diagnostics_index="$ARTIFACT_DIR/failure_diagnostics_index.json"

    if ARTIFACT_DIR="$ARTIFACT_DIR" \
        BUNDLE_FILE="$bundle_file" \
        SUMMARY_FILE="$summary_file" \
        ENV_FILE="$env_file" \
        DIAGNOSTICS_INDEX="$diagnostics_index" \
        PROFILE="$PROFILE" \
        SHARD_KIND="$SHARD_KIND" \
        SHARD_INDEX_JSON="$SHARD_INDEX_JSON" \
        SHARD_TOTAL_JSON="$SHARD_TOTAL_JSON" \
        CORRELATION_ID="$CORRELATION_ID" \
        python3 - <<'PY'
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

artifact_dir = Path(os.environ["ARTIFACT_DIR"])
bundle_file = Path(os.environ["BUNDLE_FILE"])
summary_file = Path(os.environ["SUMMARY_FILE"])
env_file = Path(os.environ["ENV_FILE"])
diagnostics_index_file = Path(os.environ["DIAGNOSTICS_INDEX"])
profile = os.environ.get("PROFILE", "full")
shard_kind = os.environ.get("SHARD_KIND", "none")
shard_index_json = os.environ.get("SHARD_INDEX_JSON", "null")
shard_total_json = os.environ.get("SHARD_TOTAL_JSON", "null")
correlation_id = os.environ.get("CORRELATION_ID", "")


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def run_cmd(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except Exception:
        return "unknown"


# Read environment context.
env_data = read_json(env_file) or {}
environment = {
    "profile": env_data.get("profile", profile),
    "shard_kind": env_data.get("shard", {}).get("kind", shard_kind),
    "shard_index": env_data.get("shard", {}).get("index"),
    "shard_total": env_data.get("shard", {}).get("total"),
    "rustc_version": env_data.get("rustc", run_cmd(["rustc", "--version"])),
    "cargo_target_dir": env_data.get("cargo_target_dir", os.environ.get("CARGO_TARGET_DIR", "target")),
    "vcr_mode": env_data.get("vcr_mode", os.environ.get("VCR_MODE", "unset")),
    "git_sha": env_data.get("git_sha", run_cmd(["git", "rev-parse", "--short", "HEAD"])),
    "git_branch": env_data.get("git_branch", run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"])),
    "os": env_data.get("os", run_cmd(["uname", "-srm"])),
}

# Read summary for failed suites/units.
summary = read_json(summary_file) or {}
failed_suite_names = summary.get("failed_names", [])
failed_unit_names = summary.get("failed_unit_names", [])

# Build per-suite replay entries from failure digests.
failed_suites = []
diagnostics = read_json(diagnostics_index_file) or {}
diag_suites = diagnostics.get("suites", [])
diag_by_name = {s.get("suite"): s for s in diag_suites if isinstance(s, dict)}

for suite_name in failed_suite_names:
    diag = diag_by_name.get(suite_name, {})
    digest_path = diag.get("digest_path", "")
    digest_data = read_json(Path(digest_path)) if digest_path else None
    remediation = (digest_data or {}).get("remediation_pointer", {})

    failed_suites.append({
        "suite": suite_name,
        "exit_code": (digest_data or {}).get("exit_code", 1),
        "root_cause_class": diag.get("root_cause_class", "unknown"),
        "runner_replay": remediation.get("replay_command",
            f"./scripts/e2e/run_all.sh --profile focused --skip-lint --suite {suite_name}"),
        "cargo_replay": remediation.get("suite_replay_command",
            f"cargo test --test {suite_name} -- --nocapture"),
        "targeted_replay": remediation.get("targeted_test_replay_command", ""),
        "digest_path": digest_path,
    })

# Build per-unit replay entries.
failed_unit_targets = []
for target_name in failed_unit_names:
    failed_unit_targets.append({
        "target": target_name,
        "exit_code": 1,
        "cargo_replay": f"cargo test --test {target_name} -- --nocapture",
    })

# Build one-command replay.
one_command = f"./scripts/e2e/run_all.sh --rerun-from {summary_file}"

bundle = {
    "schema": "pi.e2e.replay_bundle.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "correlation_id": correlation_id,
    "source_summary_path": str(summary_file),
    "one_command_replay": one_command,
    "environment": environment,
    "failed_suites": failed_suites,
    "failed_unit_targets": failed_unit_targets,
    "failed_gates": [],
    "summary": {
        "total_failed_suites": len(failed_suites),
        "total_failed_units": len(failed_unit_targets),
        "total_failed_gates": 0,
        "all_commands_reference_valid_targets": True,
    },
}

bundle_file.parent.mkdir(parents=True, exist_ok=True)
bundle_file.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

# Also append replay_bundle reference to summary.json.
summary["replay_bundle"] = {
    "schema": "pi.e2e.replay_bundle.v1",
    "path": str(bundle_file),
    "one_command_replay": one_command,
    "failed_suite_count": len(failed_suites),
    "failed_unit_count": len(failed_unit_targets),
}
summary_file.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

print("REPLAY BUNDLE GENERATED")
print(f"- Bundle: {bundle_file}")
print(f"- One-command replay: {one_command}")
print(f"- Failed suites: {len(failed_suites)}")
print(f"- Failed units: {len(failed_unit_targets)}")
PY
    then
        echo "[replay] Replay bundle generated ($bundle_file)"
        return 0
    else
        echo "[replay] Failed to generate replay bundle" >&2
        return 1
    fi
}

# ─── Capability Profile Matrix (bd-k5q5.7.5) ────────────────────────────────

generate_extension_profile_matrix() {
    local matrix_file="$ARTIFACT_DIR/extension_profile_matrix.json"
    local matrix_markdown="$ARTIFACT_DIR/extension_profile_matrix.md"
    local summary_file="$ARTIFACT_DIR/summary.json"

    if ARTIFACT_DIR="$ARTIFACT_DIR" \
        PROJECT_ROOT="$PROJECT_ROOT" \
        MATRIX_FILE="$matrix_file" \
        MATRIX_MARKDOWN="$matrix_markdown" \
        SUMMARY_FILE="$summary_file" \
        python3 - <<'PY'
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

artifact_dir = Path(os.environ["ARTIFACT_DIR"])
project_root = Path(os.environ["PROJECT_ROOT"])
matrix_file = Path(os.environ["MATRIX_FILE"])
matrix_markdown = Path(os.environ["MATRIX_MARKDOWN"])
summary_file = Path(os.environ["SUMMARY_FILE"])

conformance_events_path = (
    project_root / "tests" / "ext_conformance" / "reports" / "conformance_events.jsonl"
)
negative_events_path = (
    project_root / "tests" / "ext_conformance" / "reports" / "negative" / "negative_events.jsonl"
)

for path in (conformance_events_path, negative_events_path):
    if not path.exists():
        print(f"[profiles] required input missing: {path}", file=sys.stderr)
        print("[profiles] Skipping profile matrix generation (conformance events not available)")
        sys.exit(0)


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            text = raw.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"[profiles] invalid JSONL in {path} line {line_no}: {exc}") from exc
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def explain_policy(profile: str) -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--bin",
        "pi",
        "--",
        "--explain-extension-policy",
        "--extension-policy",
        profile,
    ]
    result = subprocess.run(
        command,
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            "[profiles] failed to query policy "
            f"for profile={profile}: rc={result.returncode}\n{result.stderr}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"[profiles] explain-policy output is not JSON for profile={profile}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[profiles] explain-policy payload is not an object for profile={profile}")
    return payload


def infer_capabilities(event: dict) -> list[str]:
    caps = set()
    raw_caps = event.get("capabilities", {})
    if not isinstance(raw_caps, dict):
        return []
    if raw_caps.get("uses_exec") is True:
        caps.add("exec")
    if raw_caps.get("uses_http") is True:
        caps.add("http")
    if raw_caps.get("uses_ui") is True:
        caps.add("ui")
    if raw_caps.get("uses_session") is True:
        caps.add("session")
    if raw_caps.get("registers_tools") is True:
        caps.add("tool")
    subscribers = raw_caps.get("subscribes_events")
    if isinstance(subscribers, list) and any(isinstance(item, str) and item for item in subscribers):
        caps.add("events")
    return sorted(caps)


conformance_events = load_jsonl(conformance_events_path)
negative_events = load_jsonl(negative_events_path)

profiles = ["safe", "balanced", "permissive"]
mode_for_profile = {
    "safe": "strict",
    "balanced": "prompt",
    "permissive": "permissive",
}

policy_payloads: dict[str, dict] = {}
policy_decisions: dict[str, dict[str, str]] = {}

for profile in profiles:
    payload = explain_policy(profile)
    policy_payloads[profile] = payload
    decisions: dict[str, str] = {}
    for entry in payload.get("capability_decisions", []):
        if not isinstance(entry, dict):
            continue
        capability = entry.get("capability")
        decision = entry.get("decision")
        if isinstance(capability, str) and capability and isinstance(decision, str) and decision:
            decisions[capability] = decision.lower()
    policy_decisions[profile] = decisions

testable_events: list[dict] = []
for event in conformance_events:
    status = str(event.get("overall_status", "")).upper()
    if status in {"PASS", "FAIL"}:
        testable_events.append(event)

profile_rows: dict[str, dict] = {}

for profile in profiles:
    decisions = policy_decisions[profile]
    decision_counts = Counter(decisions.values())

    projected_pass = 0
    projected_fail_existing = 0
    projected_blocked = 0
    blocked_by_capability: Counter[str] = Counter()
    blocked_examples: list[dict] = []

    for event in testable_events:
        extension_id = str(event.get("extension_id", "unknown"))
        overall_status = str(event.get("overall_status", "")).upper()
        inferred = infer_capabilities(event)
        denied_caps = [cap for cap in inferred if decisions.get(cap) == "deny"]

        if denied_caps:
            projected_blocked += 1
            for cap in denied_caps:
                blocked_by_capability[cap] += 1
            if len(blocked_examples) < 50:
                blocked_examples.append(
                    {
                        "extension_id": extension_id,
                        "denied_capabilities": denied_caps,
                        "baseline_status": overall_status,
                    }
                )
        elif overall_status == "PASS":
            projected_pass += 1
        else:
            projected_fail_existing += 1

    projected_total = projected_pass + projected_fail_existing + projected_blocked
    projected_pass_rate_pct = (
        round((projected_pass / projected_total) * 100.0, 2) if projected_total else 0.0
    )

    profile_rows[profile] = {
        "requested_profile": payload.get("requested_profile"),
        "effective_profile": payload.get("effective_profile"),
        "profile_source": payload.get("profile_source"),
        "decision_counts": {
            "allow": int(decision_counts.get("allow", 0)),
            "prompt": int(decision_counts.get("prompt", 0)),
            "deny": int(decision_counts.get("deny", 0)),
        },
        "projected": {
            "testable_extensions": projected_total,
            "pass": projected_pass,
            "fail_existing": projected_fail_existing,
            "blocked": projected_blocked,
            "pass_rate_pct": projected_pass_rate_pct,
        },
        "blocked_operation_summary": {
            "by_capability": dict(sorted(blocked_by_capability.items())),
            "blocked_extension_count": projected_blocked,
            "blocked_extension_examples": blocked_examples,
        },
    }

checked = 0
matched = 0
mismatches: list[dict] = []
skipped_unknown: Counter[str] = Counter()
skipped_fixture_override: Counter[str] = Counter()

for profile in profiles:
    mode = mode_for_profile[profile]
    decisions = policy_decisions[profile]
    for event in negative_events:
        if str(event.get("mode", "")) != mode:
            continue
        capability = str(event.get("capability", "")).strip()
        if not capability:
            continue
        runtime_decision = str(event.get("actual_decision", "")).strip().lower()
        if not runtime_decision:
            continue

        # The negative-conformance fixture intentionally enforces a global deny-list
        # for dangerous capabilities in permissive mode. That override context is
        # stricter than CLI preflight output and should not be flagged as mismatch.
        if profile == "permissive" and capability in {"exec", "env"}:
            skipped_fixture_override[capability] += 1
            continue

        preflight_decision = decisions.get(capability)
        if preflight_decision is None:
            skipped_unknown[capability] += 1
            continue

        checked += 1
        if preflight_decision == runtime_decision:
            matched += 1
            continue
        mismatches.append(
            {
                "profile": profile,
                "mode": mode,
                "capability": capability,
                "preflight_decision": preflight_decision,
                "runtime_decision": runtime_decision,
                "reason": event.get("reason"),
                "test_name": event.get("test_name"),
            }
        )

payload = {
    "schema": "pi.e2e.extension_profile_matrix.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "source_files": {
        "conformance_events": str(conformance_events_path),
        "negative_events": str(negative_events_path),
    },
    "profiles": profile_rows,
    "preflight_runtime_consistency": {
        "checked_capability_decisions": checked,
        "matched_capability_decisions": matched,
        "mismatched_capability_decisions": len(mismatches),
        "mismatches": mismatches,
        "skipped_unknown_capabilities": dict(sorted(skipped_unknown.items())),
        "skipped_fixture_overrides": dict(sorted(skipped_fixture_override.items())),
    },
}

matrix_file.parent.mkdir(parents=True, exist_ok=True)
matrix_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

markdown_lines = [
    "# Extension Capability Profile Matrix",
    "",
    f"- Generated at: `{payload['generated_at']}`",
    f"- Conformance source: `{conformance_events_path}`",
    f"- Runtime policy source: `{negative_events_path}`",
    "",
    "## Profile Projection",
    "",
    "| Profile | Pass | Fail (existing) | Blocked | Pass rate | Deny decisions | Prompt decisions | Allow decisions |",
    "|---|---:|---:|---:|---:|---:|---:|---:|",
]

for profile in profiles:
    row = profile_rows[profile]
    projected = row["projected"]
    counts = row["decision_counts"]
    markdown_lines.append(
        "| "
        f"{profile} | "
        f"{projected['pass']} | "
        f"{projected['fail_existing']} | "
        f"{projected['blocked']} | "
        f"{projected['pass_rate_pct']:.2f}% | "
        f"{counts['deny']} | "
        f"{counts['prompt']} | "
        f"{counts['allow']} |"
    )

markdown_lines.extend(
    [
        "",
        "## Preflight vs Runtime Consistency",
        "",
        f"- Checked decisions: `{checked}`",
        f"- Matched decisions: `{matched}`",
        f"- Mismatches: `{len(mismatches)}`",
        "",
    ]
)
if mismatches:
    markdown_lines.append("### Mismatches")
    markdown_lines.append("")
    for mismatch in mismatches:
        markdown_lines.append(
            "- "
            f"`{mismatch['profile']}` `{mismatch['capability']}`: "
            f"preflight={mismatch['preflight_decision']} runtime={mismatch['runtime_decision']} "
            f"(test `{mismatch['test_name']}`)"
        )
    markdown_lines.append("")

if skipped_unknown:
    markdown_lines.append("### Skipped Unknown Capabilities")
    markdown_lines.append("")
    for capability, count in sorted(skipped_unknown.items()):
        markdown_lines.append(f"- `{capability}`: {count}")
    markdown_lines.append("")

if skipped_fixture_override:
    markdown_lines.append("### Skipped Fixture Overrides")
    markdown_lines.append("")
    for capability, count in sorted(skipped_fixture_override.items()):
        markdown_lines.append(f"- `{capability}`: {count} (negative fixture explicit deny override)")
    markdown_lines.append("")

matrix_markdown.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")

if summary_file.exists():
    try:
        summary_payload = json.loads(summary_file.read_text(encoding="utf-8"))
        if isinstance(summary_payload, dict):
            summary_payload["extension_profile_matrix"] = {
                "schema": "pi.e2e.extension_profile_matrix.v1",
                "path": str(matrix_file),
                "markdown_path": str(matrix_markdown),
                "preflight_runtime_mismatches": len(mismatches),
                "checked_capability_decisions": checked,
                "profiles": {
                    profile: {
                        "projected_pass_rate_pct": profile_rows[profile]["projected"]["pass_rate_pct"],
                        "blocked_extensions": profile_rows[profile]["projected"]["blocked"],
                    }
                    for profile in profiles
                },
            }
            summary_file.write_text(json.dumps(summary_payload, indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        raise SystemExit(f"[profiles] failed to enrich summary.json: {exc}") from exc

print("PROFILE MATRIX GENERATED")
print(f"- JSON: {matrix_file}")
print(f"- Markdown: {matrix_markdown}")
print(
    "- Preflight/runtime consistency: "
    f"checked={checked}, matched={matched}, mismatches={len(mismatches)}"
)
for profile in profiles:
    projected = profile_rows[profile]["projected"]
    print(
        f"- {profile}: pass={projected['pass']} "
        f"fail_existing={projected['fail_existing']} blocked={projected['blocked']} "
        f"pass_rate={projected['pass_rate_pct']:.2f}%"
    )
PY
    then
        echo "[profiles] Capability profile matrix generated ($matrix_file)"
        return 0
    else
        echo "[profiles] Failed to generate capability profile matrix" >&2
        return 1
    fi
}

# ─── Soak Longevity Evidence (bd-k5q5.7.10) ──────────────────────────────────

generate_soak_longevity_report() {
    local soak_file="$ARTIFACT_DIR/soak_longevity_report.json"
    local soak_markdown="$ARTIFACT_DIR/soak_longevity_report.md"
    local soak_events="$ARTIFACT_DIR/soak_longevity_events.jsonl"
    local summary_file="$ARTIFACT_DIR/summary.json"

    if ARTIFACT_DIR="$ARTIFACT_DIR" \
        PROJECT_ROOT="$PROJECT_ROOT" \
        SOAK_FILE="$soak_file" \
        SOAK_MARKDOWN="$soak_markdown" \
        SOAK_EVENTS="$soak_events" \
        SUMMARY_FILE="$summary_file" \
        python3 - <<'PY'
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

artifact_dir = Path(os.environ["ARTIFACT_DIR"])
project_root = Path(os.environ["PROJECT_ROOT"])
soak_file = Path(os.environ["SOAK_FILE"])
soak_markdown = Path(os.environ["SOAK_MARKDOWN"])
soak_events = Path(os.environ["SOAK_EVENTS"])
summary_file = Path(os.environ["SUMMARY_FILE"])

perf_dir = project_root / "target" / "perf"
mem_report_path = perf_dir / "ext_memory_stress_report.json"
mem_csv_path = perf_dir / "ext_memory_stress.csv"
stress_triage_path = perf_dir / "stress_triage.json"
stress_events_path = perf_dir / "stress_events.jsonl"
profile_rotation_path = perf_dir / "stress_profile_rotation.json"


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def as_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ratio(numerator, denominator):
    if numerator is None or denominator in (None, 0):
        return None
    return float(numerator) / float(denominator)


def slope(points):
    if len(points) < 2:
        return None
    first_t, first_v = points[0]
    last_t, last_v = points[-1]
    delta_t = last_t - first_t
    if delta_t <= 0:
        return None
    return (last_v - first_v) / delta_t


summary_payload = read_json(summary_file) or {}
unit_status = {}
for target in summary_payload.get("unit_targets", []):
    if not isinstance(target, dict):
        continue
    name = target.get("target")
    if not isinstance(name, str) or not name:
        continue
    unit_status[name] = target.get("exit_code") == 0

required_targets = ["ext_memory_stress", "extensions_stress"]
missing_targets = [name for name in required_targets if name not in unit_status]
failed_targets = [name for name in required_targets if unit_status.get(name) is False]
required_targets_executed = not missing_targets and not failed_targets

mem_report = read_json(mem_report_path)
stress_triage = read_json(stress_triage_path)
profile_rotation = read_json(profile_rotation_path)

rss_points = []
heap_points = []
if mem_csv_path.exists():
    with mem_csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            elapsed = as_float(row.get("elapsed_secs"))
            rss_kb = as_float(row.get("rss_kb"))
            heap_kb = as_float(row.get("quickjs_heap_kb"))
            if elapsed is None:
                continue
            if rss_kb is not None:
                rss_points.append((elapsed, rss_kb))
            if heap_kb is not None:
                heap_points.append((elapsed, heap_kb))

memory_metrics = {
    "rss_baseline_kb": None,
    "rss_peak_kb": None,
    "rss_growth_factor": None,
    "rss_slope_kb_per_sec": slope(rss_points),
    "monotonic_rss_growth": None,
    "quickjs_baseline_kb": None,
    "quickjs_peak_kb": None,
    "quickjs_growth_factor": None,
    "quickjs_slope_kb_per_sec": slope(heap_points),
    "monotonic_quickjs_growth": None,
    "event_errors": None,
    "events_dispatched": None,
    "error_rate_pct": None,
}

if isinstance(mem_report, dict):
    memory_metrics["rss_baseline_kb"] = as_int(mem_report.get("rss_baseline_kb"))
    memory_metrics["rss_peak_kb"] = as_int(mem_report.get("rss_peak_kb"))
    memory_metrics["rss_growth_factor"] = as_float(mem_report.get("rss_growth_factor"))
    memory_metrics["monotonic_rss_growth"] = bool(mem_report.get("monotonic_rss_growth"))
    memory_metrics["quickjs_baseline_kb"] = as_int(mem_report.get("quickjs_baseline_kb"))
    memory_metrics["quickjs_peak_kb"] = as_int(mem_report.get("quickjs_peak_kb"))
    memory_metrics["quickjs_growth_factor"] = as_float(mem_report.get("quickjs_growth_factor"))
    memory_metrics["monotonic_quickjs_growth"] = bool(
        mem_report.get("monotonic_quickjs_growth")
    )
    memory_metrics["event_errors"] = as_int(mem_report.get("event_errors")) or 0
    memory_metrics["events_dispatched"] = as_int(mem_report.get("events_dispatched")) or 0
    if memory_metrics["events_dispatched"] > 0:
        memory_metrics["error_rate_pct"] = round(
            (memory_metrics["event_errors"] / memory_metrics["events_dispatched"]) * 100.0,
            4,
        )

triage_results = {}
if isinstance(stress_triage, dict):
    triage_results = stress_triage.get("results", {})
if not isinstance(triage_results, dict):
    triage_results = {}

triage_latency = triage_results.get("latency", {})
if not isinstance(triage_latency, dict):
    triage_latency = {}
triage_rss = triage_results.get("rss", {})
if not isinstance(triage_rss, dict):
    triage_rss = {}

triage_event_count = as_int(triage_results.get("event_count")) or 0
triage_error_count = as_int(triage_results.get("error_count")) or 0
triage_error_rate_pct = (
    round((triage_error_count / triage_event_count) * 100.0, 4)
    if triage_event_count > 0
    else None
)

timing_metrics = {
    "p99_first_us": as_int(triage_latency.get("p99_first_us")),
    "p99_last_us": as_int(triage_latency.get("p99_last_us")),
    "latency_degradation_ratio": ratio(
        as_float(triage_latency.get("p99_last_us")),
        as_float(triage_latency.get("p99_first_us")),
    ),
    "latency_ok": bool(triage_latency.get("ok")) if triage_latency else None,
    "events_dispatched": triage_event_count,
    "error_count": triage_error_count,
    "error_rate_pct": triage_error_rate_pct,
    "rss_growth_pct": as_float(triage_rss.get("growth_pct")),
    "rss_ok": bool(triage_rss.get("ok")) if triage_rss else None,
}

profile_rotation_metrics = {
    "present": isinstance(profile_rotation, dict),
    "overall_pass": None,
    "slice_count": 0,
    "profiles": [],
}
if isinstance(profile_rotation, dict):
    slices = profile_rotation.get("slices", [])
    if not isinstance(slices, list):
        slices = []
    profile_rotation_metrics["overall_pass"] = bool(profile_rotation.get("overall_pass"))
    profile_rotation_metrics["slice_count"] = len(slices)
    profile_rotation_metrics["profiles"] = [
        str(slice_payload.get("profile"))
        for slice_payload in slices
        if isinstance(slice_payload, dict) and slice_payload.get("profile")
    ]

thresholds = {
    "rss_growth_factor_max": 2.0,
    "quickjs_growth_factor_max": 2.0,
    "latency_degradation_ratio_max": 2.0,
    "p99_last_us_max": 25_000,
    "error_rate_pct_max": 25.0,
    "profile_rotation_required": True,
}

checks = []
failed_checks = []


def add_check(check_id, ok, actual, threshold, required=True):
    checks.append(
        {
            "id": check_id,
            "ok": bool(ok),
            "actual": actual,
            "threshold": threshold,
            "required": required,
        }
    )
    if required and not ok:
        failed_checks.append(check_id)


add_check(
    "prerequisites.required_targets_executed",
    required_targets_executed,
    {
        "missing_targets": missing_targets,
        "failed_targets": failed_targets,
    },
    "ext_memory_stress + extensions_stress exit_code=0",
)

add_check(
    "inputs.ext_memory_stress_report_present",
    isinstance(mem_report, dict),
    str(mem_report_path),
    "report must exist and parse as JSON",
)
add_check(
    "inputs.extensions_stress_triage_present",
    isinstance(stress_triage, dict),
    str(stress_triage_path),
    "report must exist and parse as JSON",
)
add_check(
    "inputs.profile_rotation_report_present",
    isinstance(profile_rotation, dict),
    str(profile_rotation_path),
    "report must exist and parse as JSON",
)

rss_growth_factor = memory_metrics["rss_growth_factor"]
add_check(
    "memory.rss_growth_factor",
    rss_growth_factor is not None and rss_growth_factor <= thresholds["rss_growth_factor_max"],
    rss_growth_factor,
    f"<= {thresholds['rss_growth_factor_max']}",
)

quickjs_growth_factor = memory_metrics["quickjs_growth_factor"]
add_check(
    "memory.quickjs_growth_factor",
    quickjs_growth_factor is not None
    and quickjs_growth_factor <= thresholds["quickjs_growth_factor_max"],
    quickjs_growth_factor,
    f"<= {thresholds['quickjs_growth_factor_max']}",
)

add_check(
    "memory.no_monotonic_rss_growth",
    memory_metrics["monotonic_rss_growth"] is False,
    memory_metrics["monotonic_rss_growth"],
    "must be false",
)
add_check(
    "memory.no_monotonic_quickjs_growth",
    memory_metrics["monotonic_quickjs_growth"] is False,
    memory_metrics["monotonic_quickjs_growth"],
    "must be false",
)

latency_ratio = timing_metrics["latency_degradation_ratio"]
p99_last_us = timing_metrics["p99_last_us"]
add_check(
    "timing.latency_degradation_ratio",
    (
        latency_ratio is not None
        and (
            latency_ratio <= thresholds["latency_degradation_ratio_max"]
            or (p99_last_us is not None and p99_last_us <= thresholds["p99_last_us_max"])
        )
    ),
    latency_ratio,
    (
        f"<= {thresholds['latency_degradation_ratio_max']} "
        f"or p99_last_us <= {thresholds['p99_last_us_max']}"
    ),
)

triage_error_rate = timing_metrics["error_rate_pct"]
add_check(
    "errors.extensions_stress_error_rate_pct",
    triage_error_rate is not None and triage_error_rate <= thresholds["error_rate_pct_max"],
    triage_error_rate,
    f"<= {thresholds['error_rate_pct_max']}",
)

mem_error_rate = memory_metrics["error_rate_pct"]
add_check(
    "errors.ext_memory_stress_error_rate_pct",
    mem_error_rate is not None and mem_error_rate <= thresholds["error_rate_pct_max"],
    mem_error_rate,
    f"<= {thresholds['error_rate_pct_max']}",
)

add_check(
    "profile_rotation.overall_pass",
    profile_rotation_metrics["overall_pass"] is True,
    profile_rotation_metrics["overall_pass"],
    "must be true",
)

overall_pass = len(failed_checks) == 0
if not required_targets_executed:
    status = "missing_prerequisites"
elif overall_pass:
    status = "pass"
else:
    status = "threshold_failure"

events_payloads = []
if stress_events_path.exists():
    with stress_events_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            events_payloads.append(
                {
                    "schema": "pi.e2e.soak_longevity_event.v1",
                    "source": "extensions_stress",
                    "event_type": payload.get("schema", "unknown"),
                    "payload": payload,
                }
            )

for elapsed, rss_kb in rss_points:
    quickjs_kb = None
    for t_heap, heap_kb in heap_points:
        if t_heap == elapsed:
            quickjs_kb = heap_kb
            break
    events_payloads.append(
        {
            "schema": "pi.e2e.soak_longevity_event.v1",
            "source": "ext_memory_stress",
            "event_type": "pi.ext.memory_stress.sample.v1",
            "payload": {
                "elapsed_secs": elapsed,
                "rss_kb": rss_kb,
                "quickjs_heap_kb": quickjs_kb,
            },
        }
    )

events_payloads.append(
    {
        "schema": "pi.e2e.soak_longevity_event.v1",
        "source": "soak_longevity",
        "event_type": "pi.e2e.soak_longevity.summary.v1",
        "payload": {
            "status": status,
            "pass": overall_pass,
            "failed_checks": failed_checks,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }
)

soak_events.parent.mkdir(parents=True, exist_ok=True)
with soak_events.open("w", encoding="utf-8") as handle:
    for payload in events_payloads:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")

report_payload = {
    "schema": "pi.e2e.soak_longevity.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "status": status,
    "pass": overall_pass,
    "prerequisites": {
        "required_targets": required_targets,
        "required_targets_executed": required_targets_executed,
        "missing_targets": missing_targets,
        "failed_targets": failed_targets,
    },
    "source_files": {
        "ext_memory_stress_report": str(mem_report_path),
        "ext_memory_stress_csv": str(mem_csv_path),
        "extensions_stress_triage": str(stress_triage_path),
        "extensions_stress_events": str(stress_events_path),
        "profile_rotation_report": str(profile_rotation_path),
    },
    "metrics": {
        "memory": memory_metrics,
        "timing": timing_metrics,
        "profile_rotation": profile_rotation_metrics,
    },
    "thresholds": thresholds,
    "checks": checks,
    "failed_checks": failed_checks,
}

soak_file.parent.mkdir(parents=True, exist_ok=True)
soak_file.write_text(json.dumps(report_payload, indent=2) + "\n", encoding="utf-8")

markdown_lines = [
    "# Soak Longevity Verification",
    "",
    f"- Generated at: `{report_payload['generated_at']}`",
    f"- Status: `{status}`",
    f"- Overall pass: `{overall_pass}`",
    "",
    "## Key Metrics",
    "",
    "| Metric | Value |",
    "|---|---:|",
    f"| RSS growth factor | {memory_metrics['rss_growth_factor']} |",
    f"| QuickJS growth factor | {memory_metrics['quickjs_growth_factor']} |",
    f"| Latency degradation ratio (p99 last / first) | {timing_metrics['latency_degradation_ratio']} |",
    f"| extensions_stress error rate (%) | {timing_metrics['error_rate_pct']} |",
    f"| ext_memory_stress error rate (%) | {memory_metrics['error_rate_pct']} |",
    f"| Profile rotation pass | {profile_rotation_metrics['overall_pass']} |",
    "",
    "## Failed Checks",
    "",
]
if failed_checks:
    markdown_lines.extend([f"- `{check_id}`" for check_id in failed_checks])
else:
    markdown_lines.append("- None")
markdown_lines.append("")
markdown_lines.append(f"- Events: `{soak_events}`")
soak_markdown.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")

if isinstance(summary_payload, dict):
    summary_payload["soak_longevity"] = {
        "schema": "pi.e2e.soak_longevity.v1",
        "path": str(soak_file),
        "markdown_path": str(soak_markdown),
        "events_path": str(soak_events),
        "status": status,
        "pass": overall_pass,
        "failed_checks": failed_checks,
    }
    summary_file.write_text(json.dumps(summary_payload, indent=2) + "\n", encoding="utf-8")

print("SOAK LONGEVITY REPORT GENERATED")
print(f"- JSON: {soak_file}")
print(f"- Markdown: {soak_markdown}")
print(f"- Events: {soak_events}")
print(f"- Status: {status}")
print(f"- Failed checks: {len(failed_checks)}")
PY
    then
        echo "[soak] Soak longevity report generated ($soak_file)"
        return 0
    else
        echo "[soak] Failed to generate soak longevity report" >&2
        return 1
    fi
}

# ─── User-Focused Release Readiness Summary (bd-k5q5.7.11) ──────────────────

generate_release_readiness_report() {
    local readiness_file="$ARTIFACT_DIR/release_readiness_summary.json"
    local readiness_markdown="$ARTIFACT_DIR/release_readiness_summary.md"
    local summary_file="$ARTIFACT_DIR/summary.json"
    local profile_matrix_file="$ARTIFACT_DIR/extension_profile_matrix.json"
    local soak_file="$ARTIFACT_DIR/soak_longevity_report.json"
    local conformance_summary_file="$PROJECT_ROOT/tests/ext_conformance/reports/conformance_summary.json"
    local conformance_report_md="$PROJECT_ROOT/tests/ext_conformance/reports/CONFORMANCE_REPORT.md"
    local contract_file="$ARTIFACT_DIR/evidence_contract.json"

    if ARTIFACT_DIR="$ARTIFACT_DIR" \
        READINESS_FILE="$readiness_file" \
        READINESS_MARKDOWN="$readiness_markdown" \
        SUMMARY_FILE="$summary_file" \
        PROFILE_MATRIX_FILE="$profile_matrix_file" \
        SOAK_FILE="$soak_file" \
        CONFORMANCE_SUMMARY_FILE="$conformance_summary_file" \
        CONFORMANCE_REPORT_MD="$conformance_report_md" \
        CONTRACT_FILE="$contract_file" \
        python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

artifact_dir = Path(os.environ["ARTIFACT_DIR"])
readiness_file = Path(os.environ["READINESS_FILE"])
readiness_markdown = Path(os.environ["READINESS_MARKDOWN"])
summary_file = Path(os.environ["SUMMARY_FILE"])
profile_matrix_file = Path(os.environ["PROFILE_MATRIX_FILE"])
soak_file = Path(os.environ["SOAK_FILE"])
conformance_summary_file = Path(os.environ["CONFORMANCE_SUMMARY_FILE"])
conformance_report_md = Path(os.environ["CONFORMANCE_REPORT_MD"])
contract_file = Path(os.environ["CONTRACT_FILE"])


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


summary = read_json(summary_file) or {}
profile_matrix = read_json(profile_matrix_file) or {}
soak_report = read_json(soak_file) or {}
conformance_summary = read_json(conformance_summary_file) or {}
contract_payload = read_json(contract_file)
summary_correlation_id = ""
if isinstance(summary, dict):
    summary_correlation_id = str(summary.get("correlation_id", "")).strip()

counts = conformance_summary.get("counts", {}) if isinstance(conformance_summary, dict) else {}
conformance_total = as_int(counts.get("total"))
conformance_pass = as_int(counts.get("pass"))
conformance_fail = as_int(counts.get("fail"))
conformance_na = as_int(counts.get("na"))
conformance_pass_rate = as_float(conformance_summary.get("pass_rate_pct"))

failed_units = as_int(summary.get("failed_units"))
failed_suites = as_int(summary.get("failed_suites"))
total_units = as_int(summary.get("total_units"))
total_suites = as_int(summary.get("total_suites"))

suite_entries = summary.get("suites", [])
if not isinstance(suite_entries, list):
    suite_entries = []
passing_suites = []
failing_suites = []
for suite in suite_entries:
    if not isinstance(suite, dict):
        continue
    suite_name = str(suite.get("suite", "")).strip()
    if not suite_name:
        continue
    if as_int(suite.get("exit_code"), default=1) == 0:
        passing_suites.append(suite_name)
    else:
        failing_suites.append(suite_name)

unit_entries = summary.get("unit_targets", [])
if not isinstance(unit_entries, list):
    unit_entries = []
failing_unit_targets = []
for target in unit_entries:
    if not isinstance(target, dict):
        continue
    target_name = str(target.get("target", "")).strip()
    if not target_name:
        continue
    if as_int(target.get("exit_code"), default=1) != 0:
        failing_unit_targets.append(target_name)

profiles_payload = profile_matrix.get("profiles", {}) if isinstance(profile_matrix, dict) else {}
if not isinstance(profiles_payload, dict):
    profiles_payload = {}

consistency = (
    profile_matrix.get("preflight_runtime_consistency", {})
    if isinstance(profile_matrix, dict)
    else {}
)
if not isinstance(consistency, dict):
    consistency = {}
mismatches = as_int(consistency.get("mismatched_capability_decisions"))
checked = as_int(consistency.get("checked_capability_decisions"))

profile_order = ["safe", "balanced", "permissive"]
profile_recommendation_defaults = {
    "safe": "Default profile for untrusted extensions",
    "balanced": "Recommended for general extension development",
    "permissive": "Use only for trusted local extensions",
}

profile_rows = {}
for profile_name in profile_order:
    row = profiles_payload.get(profile_name, {})
    if not isinstance(row, dict):
        row = {}
    projected = row.get("projected", {})
    if not isinstance(projected, dict):
        projected = {}
    blocked_summary = row.get("blocked_operation_summary", {})
    if not isinstance(blocked_summary, dict):
        blocked_summary = {}

    blocked = as_int(projected.get("blocked"))
    pass_rate_pct = as_float(projected.get("pass_rate_pct"))
    testable = as_int(projected.get("testable_extensions"))
    projected_pass = as_int(projected.get("pass"))
    projected_fail_existing = as_int(projected.get("fail_existing"))

    if profile_name == "balanced" and pass_rate_pct >= 85.0 and blocked <= 5:
        recommendation = "Recommended default for most users"
    elif profile_name == "safe":
        recommendation = "Safest default with strongest capability restrictions"
    elif profile_name == "permissive":
        recommendation = "Trusted-only mode; enables dangerous capabilities"
    else:
        recommendation = profile_recommendation_defaults[profile_name]

    profile_rows[profile_name] = {
        "projected_pass_rate_pct": round(pass_rate_pct, 2),
        "projected_pass": projected_pass,
        "projected_fail_existing": projected_fail_existing,
        "blocked_extensions": blocked,
        "testable_extensions": testable,
        "recommendation": recommendation,
        "blocked_operation_summary": blocked_summary,
    }

soak_pass = bool(soak_report.get("pass")) if isinstance(soak_report, dict) else False
soak_status = str(soak_report.get("status", "missing")) if isinstance(soak_report, dict) else "missing"
soak_failed_checks = (
    soak_report.get("failed_checks", []) if isinstance(soak_report, dict) else []
)
if not isinstance(soak_failed_checks, list):
    soak_failed_checks = []

overall_ready = (
    failed_units == 0
    and failed_suites == 0
    and conformance_fail == 0
    and conformance_na == 0
    and mismatches == 0
    and soak_pass
)

known_risks = []
remediation_steps = []


def add_risk(risk_id, severity, summary_text, details, evidence, command):
    known_risks.append(
        {
            "id": risk_id,
            "severity": severity,
            "summary": summary_text,
            "details": details,
            "evidence": evidence,
        }
    )
    if command:
        remediation_steps.append(
            {
                "risk_id": risk_id,
                "action": summary_text,
                "command": command,
            }
        )


if failed_units > 0:
    add_risk(
        "unit_target_failures",
        "high",
        "One or more integration/unit targets failed in the verification run",
        f"Failing unit targets: {failing_unit_targets}",
        str(summary_file),
        "./scripts/e2e/run_all.sh --profile focused --skip-lint",
    )

if failed_suites > 0:
    add_risk(
        "e2e_suite_failures",
        "high",
        "One or more user-facing workflow suites failed",
        f"Failing suites: {failing_suites}",
        str(summary_file),
        " ".join(
            [
                "./scripts/e2e/run_all.sh",
                "--profile",
                "focused",
                "--skip-lint",
                *sum((["--suite", suite] for suite in failing_suites), []),
            ]
        ),
    )

if conformance_fail > 0:
    add_risk(
        "conformance_failures",
        "high",
        "Conformance corpus has failing extensions",
        f"{conformance_fail} extension(s) currently fail conformance",
        str(conformance_summary_file),
        "cargo test --test ext_conformance_generated conformance_full_report --features ext-conformance -- --nocapture",
    )

if conformance_na > 0:
    add_risk(
        "conformance_na_gaps",
        "medium",
        "Conformance corpus still includes N/A coverage gaps",
        f"{conformance_na} extension(s) are not yet classified PASS/FAIL",
        str(conformance_summary_file),
        "cargo test --test ext_conformance_scenarios --features ext-conformance scenario_conformance_suite -- --nocapture",
    )

if mismatches > 0:
    add_risk(
        "profile_policy_mismatch",
        "high",
        "Preflight/runtime capability policy mismatch detected",
        f"{mismatches} mismatched capability decision(s) out of {checked} checked",
        str(profile_matrix_file),
        "cargo test --test e2e_cli -- --nocapture",
    )

if not soak_pass:
    add_risk(
        "soak_longevity_failure",
        "high",
        "Soak/longevity verification failed thresholds",
        f"status={soak_status}, failed_checks={soak_failed_checks}",
        str(soak_file),
        "cargo test --test ext_memory_stress ext_memory_stress_inline -- --nocapture && cargo test --test extensions_stress stress_policy_profile_rotation -- --nocapture",
    )

if conformance_report_md.exists():
    report_has_evidence_index = "## Evidence Index" in conformance_report_md.read_text(
        encoding="utf-8"
    )
    if not report_has_evidence_index:
        add_risk(
            "missing_evidence_index",
            "medium",
            "Conformance markdown report missing evidence index section",
            "Expected '## Evidence Index' section not found",
            str(conformance_report_md),
            "cargo test --test conformance_report generate_conformance_report -- --nocapture",
        )

policy_guidance = []
for profile_name in profile_order:
    policy_guidance.append(
        {
            "profile": profile_name,
            "guidance": profile_recommendation_defaults[profile_name],
            "diagnostic_command": (
                f"./target/debug/pi --explain-extension-policy --extension-policy {profile_name}"
            ),
        }
    )

workflow_pass_rate = 100.0
if total_suites > 0:
    workflow_pass_rate = round(((total_suites - failed_suites) / total_suites) * 100.0, 2)

status = "ready" if overall_ready else "not_ready"

payload = {
    "schema": "pi.e2e.release_readiness.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "correlation_id": summary_correlation_id,
    "status": status,
    "overall_ready": overall_ready,
    "summary": {
        "profile": str(summary.get("profile", "unknown")),
        "conformance_total": conformance_total,
        "conformance_pass": conformance_pass,
        "conformance_fail": conformance_fail,
        "conformance_na": conformance_na,
        "conformance_pass_rate_pct": round(conformance_pass_rate, 2),
        "total_units": total_units,
        "failed_units": failed_units,
        "total_suites": total_suites,
        "failed_suites": failed_suites,
    },
    "profiles": profile_rows,
    "workflow_outcomes": {
        "passing_suites": sorted(passing_suites),
        "failing_suites": sorted(failing_suites),
        "failing_unit_targets": sorted(failing_unit_targets),
        "suite_pass_rate_pct": workflow_pass_rate,
    },
    "known_risks": known_risks,
    "remediation": {
        "immediate": remediation_steps,
        "policy_guidance": policy_guidance,
    },
    "evidence": {
        "summary_json": str(summary_file),
        "profile_matrix_json": str(profile_matrix_file),
        "soak_longevity_report_json": str(soak_file),
        "conformance_summary_json": str(conformance_summary_file),
        "conformance_report_markdown": str(conformance_report_md),
        "evidence_contract_json": str(contract_file),
    },
}

readiness_file.parent.mkdir(parents=True, exist_ok=True)
readiness_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

lines = [
    "# Release Readiness Summary",
    "",
    f"- Generated at: `{payload['generated_at']}`",
    f"- Status: `{status}`",
    f"- Overall ready: `{overall_ready}`",
    "",
    "## Profile Safety Snapshot",
    "",
    "| Profile | Projected pass rate | Blocked extensions | Recommendation |",
    "|---|---:|---:|---|",
]
for profile_name in profile_order:
    row = profile_rows.get(profile_name, {})
    lines.append(
        f"| {profile_name} | {row.get('projected_pass_rate_pct', 0.0):.2f}% | "
        f"{row.get('blocked_extensions', 0)} | {row.get('recommendation', '')} |"
    )

lines.extend(
    [
        "",
        "## Workflow Outcomes",
        "",
        f"- Suite pass rate: `{workflow_pass_rate:.2f}%`",
        f"- Passing suites ({len(passing_suites)}): "
        + (", ".join(sorted(passing_suites)) if passing_suites else "none"),
        f"- Failing suites ({len(failing_suites)}): "
        + (", ".join(sorted(failing_suites)) if failing_suites else "none"),
        f"- Failing unit targets ({len(failing_unit_targets)}): "
        + (", ".join(sorted(failing_unit_targets)) if failing_unit_targets else "none"),
        "",
        "## Known Risks",
        "",
    ]
)

if known_risks:
    for risk in known_risks:
        lines.extend(
            [
                f"- `{risk['id']}` ({risk['severity']}): {risk['summary']}",
                f"  - details: {risk['details']}",
                f"  - evidence: `{risk['evidence']}`",
            ]
        )
else:
    lines.append("- None")

lines.extend(
    [
        "",
        "## Recommended Remediation",
        "",
    ]
)

if remediation_steps:
    for step in remediation_steps:
        lines.extend(
            [
                f"- `{step['risk_id']}`: {step['action']}",
                f"  - command: `{step['command']}`",
            ]
        )
else:
    lines.append("- No immediate remediation required.")

lines.extend(
    [
        "",
        "## Policy Guidance",
        "",
    ]
)
for guidance in policy_guidance:
    lines.extend(
        [
            f"- `{guidance['profile']}`: {guidance['guidance']}",
            f"  - diagnostic: `{guidance['diagnostic_command']}`",
        ]
    )

readiness_markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")

if isinstance(summary, dict):
    summary["release_readiness"] = {
        "schema": "pi.e2e.release_readiness.v1",
        "correlation_id": summary_correlation_id,
        "path": str(readiness_file),
        "markdown_path": str(readiness_markdown),
        "status": status,
        "overall_ready": overall_ready,
        "risk_count": len(known_risks),
        "failing_suites": sorted(failing_suites),
        "failing_unit_targets": sorted(failing_unit_targets),
    }
    summary_file.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

print("RELEASE READINESS SUMMARY GENERATED")
print(f"- JSON: {readiness_file}")
print(f"- Markdown: {readiness_markdown}")
print(f"- Status: {status}")
print(f"- Risks: {len(known_risks)}")
PY
    then
        echo "[readiness] Release-readiness summary generated ($readiness_file)"
        return 0
    else
        echo "[readiness] Failed to generate release-readiness summary" >&2
        return 1
    fi
}

# ─── Secret Redaction ─────────────────────────────────────────────────────────

redact_secrets() {
    if ARTIFACT_DIR="$ARTIFACT_DIR" python3 - <<'PY'
import os
import re
from pathlib import Path

artifact_dir = Path(os.environ["ARTIFACT_DIR"])
if not artifact_dir.exists():
    raise SystemExit(0)

patterns: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "sk-REDACTED"),
    (re.compile(r"\bkey-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE), "key-REDACTED"),
    (
        re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
        r"\1REDACTED",
    ),
    (
        re.compile(
            r"(?i)\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|GOOGLE_API_KEY|AZURE_OPENAI_API_KEY)="
            r"[^\s\"']+"
        ),
        lambda match: f"{match.group(1)}=REDACTED",
    ),
    (
        re.compile(
            r"(?i)(\"?(authorization|x-api-key|api[_-]?key|access[_-]?token|"
            r"refresh[_-]?token|cookie|password|secret)\"?\s*[:=]\s*\"?)([^\s\",]+)(\"?)"
        ),
        r"\1REDACTED\4",
    ),
]

for path in artifact_dir.rglob("*"):
    if not path.is_file():
        continue
    if path.suffix not in {".log", ".jsonl", ".json"}:
        continue
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    redacted = text
    for pattern, replacement in patterns:
        redacted = pattern.sub(replacement, redacted)
    if redacted != text:
        path.write_text(redacted, encoding="utf-8")
PY
    then
        :
    else
        echo "[redaction] Python redaction pass failed (continuing with unmodified artifacts)" >&2
    fi
}

# ─── Evidence Diff + Triage ──────────────────────────────────────────────────

generate_triage_diff() {
    local baseline_summary="$DIFF_FROM"
    local current_summary="$ARTIFACT_DIR/summary.json"
    local diff_file="$ARTIFACT_DIR/triage_diff.json"

    if [[ -z "$baseline_summary" ]]; then
        return 0
    fi
    if [[ ! -f "$baseline_summary" ]]; then
        echo "[triage] Baseline summary not found: $baseline_summary" >&2
        return 1
    fi
    if [[ ! -f "$current_summary" ]]; then
        echo "[triage] Current summary missing: $current_summary" >&2
        return 1
    fi

    if CURRENT_SUMMARY="$current_summary" \
        BASELINE_SUMMARY="$baseline_summary" \
        DIFF_FILE="$diff_file" \
        PROJECT_ROOT="$PROJECT_ROOT" \
        python3 - <<'PY'
import json
import os
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

current_summary_path = Path(os.environ["CURRENT_SUMMARY"])
baseline_summary_path = Path(os.environ["BASELINE_SUMMARY"])
diff_file = Path(os.environ["DIFF_FILE"])
project_root = Path(os.environ["PROJECT_ROOT"])


def read_summary(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to read summary {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"summary {path} is not a JSON object")
    return payload


def build_index(summary: dict, section_key: str, name_key: str) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    section = summary.get(section_key, [])
    if not isinstance(section, list):
        return indexed
    for item in section:
        if not isinstance(item, dict):
            continue
        name = item.get(name_key)
        if isinstance(name, str) and name.strip():
            indexed[name] = item
    return indexed


def resolve_path(path_value: object, *, anchor: Path) -> Path | None:
    if not isinstance(path_value, str):
        return None
    candidate_text = path_value.strip()
    if not candidate_text:
        return None
    candidate = Path(candidate_text)
    if not candidate.is_absolute():
        candidate = anchor / candidate
    return candidate.resolve()


def read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def normalize_scenario_ids(raw_ids: object) -> list[str]:
    if not isinstance(raw_ids, list):
        return []
    scenario_ids = sorted(
        {
            str(item).strip()
            for item in raw_ids
            if isinstance(item, str) and str(item).strip()
        }
    )
    return scenario_ids


def assertion_signature(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    except Exception:
        return None


def load_failure_diagnostics(summary: dict, summary_path: Path) -> dict[str, dict]:
    diagnostics_meta = summary.get("failure_diagnostics")
    if not isinstance(diagnostics_meta, dict):
        return {}

    index_path = resolve_path(
        diagnostics_meta.get("index_path"),
        anchor=summary_path.parent,
    )
    if index_path is None:
        return {}
    index_payload = read_json(index_path)
    if not isinstance(index_payload, dict):
        return {}

    entries = index_payload.get("suites")
    if not isinstance(entries, list):
        return {}

    diagnostics: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        suite_name = entry.get("suite")
        if not isinstance(suite_name, str) or not suite_name.strip():
            continue
        suite_name = suite_name.strip()

        digest_path = resolve_path(entry.get("digest_path"), anchor=index_path.parent)
        digest_payload = read_json(digest_path) if digest_path is not None else None

        impacted = normalize_scenario_ids(entry.get("impacted_scenario_ids"))
        if not impacted and isinstance(digest_payload, dict):
            impacted = normalize_scenario_ids(digest_payload.get("impacted_scenario_ids"))

        first_assertion = (
            digest_payload.get("first_failing_assertion")
            if isinstance(digest_payload, dict)
            else None
        )
        first_assertion_sig = assertion_signature(first_assertion)

        timeline_event_count = None
        timeline_path = None
        if isinstance(digest_payload, dict):
            timeline_meta = digest_payload.get("timeline")
            if isinstance(timeline_meta, dict):
                event_count = timeline_meta.get("event_count")
                if isinstance(event_count, int):
                    timeline_event_count = event_count
                timeline_path = resolve_path(
                    timeline_meta.get("path"),
                    anchor=digest_path.parent if digest_path is not None else summary_path.parent,
                )

        diagnostics[suite_name] = {
            "suite": suite_name,
            "root_cause_class": str(
                entry.get("root_cause_class")
                or (digest_payload or {}).get("root_cause_class")
                or "unknown"
            ),
            "impacted_scenario_ids": impacted,
            "first_failing_assertion_signature": first_assertion_sig,
            "timeline_event_count": timeline_event_count,
            "digest_path": str(digest_path) if digest_path is not None else None,
            "timeline_path": str(timeline_path) if timeline_path is not None else None,
        }

    return diagnostics


def build_category_map(diff_payload: dict) -> dict[str, str]:
    category_map: dict[str, str] = {}
    category_order = [
        "regressions",
        "new_failures",
        "unresolved_failures",
        "fixed",
        "removed",
        "added_pass",
        "stable_pass",
    ]
    category_name = {
        "regressions": "regression",
        "new_failures": "new_failure",
        "unresolved_failures": "unresolved_failure",
        "fixed": "fixed",
        "removed": "removed",
        "added_pass": "added_pass",
        "stable_pass": "stable_pass",
    }
    for category in category_order:
        records = diff_payload.get(category, [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            name = record.get("name")
            if isinstance(name, str) and name:
                category_map[name] = category_name.get(category, "unknown")
    return category_map


def build_semantic_diffs(
    suite_categories: dict[str, str],
    baseline_diag: dict[str, dict],
    current_diag: dict[str, dict],
) -> tuple[list[dict], int]:
    all_suites = sorted(set(baseline_diag) | set(current_diag))
    entries: list[dict] = []
    unresolved_count = 0

    for suite_name in all_suites:
        baseline_entry = baseline_diag.get(suite_name)
        current_entry = current_diag.get(suite_name)
        mismatch_kinds: list[str] = []

        if baseline_entry is None and current_entry is not None:
            mismatch_kinds.append("missing_baseline_diagnostics")
        elif baseline_entry is not None and current_entry is None:
            mismatch_kinds.append("missing_current_diagnostics")
        elif baseline_entry is not None and current_entry is not None:
            if baseline_entry.get("root_cause_class") != current_entry.get("root_cause_class"):
                mismatch_kinds.append("root_cause_class_changed")
            if baseline_entry.get("impacted_scenario_ids") != current_entry.get(
                "impacted_scenario_ids"
            ):
                mismatch_kinds.append("impacted_scenarios_changed")
            if baseline_entry.get("first_failing_assertion_signature") != current_entry.get(
                "first_failing_assertion_signature"
            ):
                mismatch_kinds.append("first_failing_assertion_changed")
            if baseline_entry.get("timeline_event_count") != current_entry.get(
                "timeline_event_count"
            ):
                mismatch_kinds.append("timeline_event_count_changed")

        if not mismatch_kinds:
            continue

        category = suite_categories.get(suite_name, "unknown")
        unresolved = category in {"regression", "new_failure", "unresolved_failure"}
        if unresolved:
            unresolved_count += 1

        entries.append(
            {
                "suite": suite_name,
                "classification": category,
                "unresolved": unresolved,
                "mismatch_kinds": mismatch_kinds,
                "artifact_links": {
                    "baseline_digest": None if baseline_entry is None else baseline_entry.get("digest_path"),
                    "current_digest": None if current_entry is None else current_entry.get("digest_path"),
                    "baseline_timeline": None if baseline_entry is None else baseline_entry.get("timeline_path"),
                    "current_timeline": None if current_entry is None else current_entry.get("timeline_path"),
                },
                "baseline": baseline_entry,
                "current": current_entry,
                "recommended_command": f"cargo test --test {shlex.quote(suite_name)} -- --nocapture",
            }
        )

    entries.sort(
        key=lambda entry: (
            0 if entry.get("unresolved") else 1,
            str(entry.get("classification")),
            str(entry.get("suite")),
        )
    )
    return entries, unresolved_count


def build_mirrored_scenario_report(
    *,
    scenario_rows: list[dict],
    baseline_suite_index: dict[str, dict],
    current_suite_index: dict[str, dict],
    semantic_by_suite: dict[str, dict],
) -> dict:
    seen_suites = set(baseline_suite_index) | set(current_suite_index)
    workflows: list[dict] = []
    candidate_workflows = 0

    for row in scenario_rows:
        if not isinstance(row, dict):
            continue
        if row.get("status") != "covered":
            continue

        suite_ids = row.get("suite_ids")
        if not isinstance(suite_ids, list):
            continue
        normalized_suite_ids = [
            suite.strip()
            for suite in suite_ids
            if isinstance(suite, str) and suite.strip()
        ]
        if not normalized_suite_ids:
            continue

        candidate_workflows += 1
        if not any(suite_name in seen_suites for suite_name in normalized_suite_ids):
            continue

        missing_in_baseline = [
            suite_name
            for suite_name in normalized_suite_ids
            if suite_name not in baseline_suite_index
        ]
        missing_in_current = [
            suite_name
            for suite_name in normalized_suite_ids
            if suite_name not in current_suite_index
        ]
        semantic_entries = [
            semantic_by_suite[suite_name]
            for suite_name in normalized_suite_ids
            if suite_name in semantic_by_suite
        ]
        unresolved_semantic_suites = [
            str(entry.get("suite"))
            for entry in semantic_entries
            if bool(entry.get("unresolved"))
        ]

        if missing_in_baseline or missing_in_current:
            status = "incomplete_mirroring"
        elif unresolved_semantic_suites:
            status = "semantic_mismatch"
        else:
            status = "aligned"

        workflows.append(
            {
                "workflow_id": row.get("workflow_id"),
                "workflow_title": row.get("workflow_title"),
                "status": status,
                "suite_ids": normalized_suite_ids,
                "replay_command": row.get("replay_command"),
                "missing_in_baseline": missing_in_baseline,
                "missing_in_current": missing_in_current,
                "unresolved_semantic_suites": unresolved_semantic_suites,
                "artifact_links": {
                    "baseline_summary": str(baseline_summary_path),
                    "current_summary": str(current_summary_path),
                    "baseline_suite_logs": {
                        suite_name: baseline_suite_index[suite_name].get("log_file")
                        for suite_name in normalized_suite_ids
                        if suite_name in baseline_suite_index
                    },
                    "current_suite_logs": {
                        suite_name: current_suite_index[suite_name].get("log_file")
                        for suite_name in normalized_suite_ids
                        if suite_name in current_suite_index
                    },
                },
            }
        )

    workflows.sort(key=lambda entry: str(entry.get("workflow_id") or ""))
    evaluated_workflows = len(workflows)
    incomplete_count = sum(
        1 for entry in workflows if entry.get("status") == "incomplete_mirroring"
    )
    semantic_mismatch_count = sum(
        1 for entry in workflows if entry.get("status") == "semantic_mismatch"
    )
    aligned_count = sum(1 for entry in workflows if entry.get("status") == "aligned")

    return {
        "schema": "pi.e2e.mirrored_scenarios.v1",
        "source_matrix_path": str(project_root / "docs" / "e2e_scenario_matrix.json"),
        "summary": {
            "covered_workflow_candidates": candidate_workflows,
            "evaluated_workflows": evaluated_workflows,
            "aligned_workflows": aligned_count,
            "semantic_mismatch_workflows": semantic_mismatch_count,
            "incomplete_mirroring_workflows": incomplete_count,
        },
        "workflows": workflows,
    }


def classify_change(
    *,
    name: str,
    baseline: dict | None,
    current: dict | None,
) -> tuple[str, dict]:
    baseline_exit = None if baseline is None else baseline.get("exit_code")
    current_exit = None if current is None else current.get("exit_code")

    baseline_ok = baseline_exit == 0
    current_ok = current_exit == 0

    record = {
        "name": name,
        "baseline_exit_code": baseline_exit,
        "current_exit_code": current_exit,
        "baseline_log_file": None if baseline is None else baseline.get("log_file"),
        "current_log_file": None if current is None else current.get("log_file"),
    }

    if baseline is None and current is not None:
        return ("added_pass" if current_ok else "new_failure"), record
    if baseline is not None and current is None:
        return "removed", record
    if baseline_ok and not current_ok:
        return "regression", record
    if not baseline_ok and current_ok:
        return "fixed", record
    if not baseline_ok and not current_ok:
        return "unresolved_failure", record
    return "stable_pass", record


def diff_section(
    *,
    baseline: dict,
    current: dict,
    section_key: str,
    name_key: str,
) -> dict:
    baseline_index = build_index(baseline, section_key, name_key)
    current_index = build_index(current, section_key, name_key)

    categories = {
        "regressions": [],
        "fixed": [],
        "unresolved_failures": [],
        "new_failures": [],
        "added_pass": [],
        "removed": [],
        "stable_pass": [],
    }

    all_names = sorted(set(baseline_index) | set(current_index))
    for name in all_names:
        category, record = classify_change(
            name=name,
            baseline=baseline_index.get(name),
            current=current_index.get(name),
        )
        if category == "new_failure":
            categories["new_failures"].append(record)
        else:
            categories[category if category in categories else "stable_pass"].append(record)

    return {
        "baseline_total": len(baseline_index),
        "current_total": len(current_index),
        **categories,
    }


def build_runner_command(unit_targets: list[str], suites: list[str]) -> str:
    parts = ["./scripts/e2e/run_all.sh", "--profile", "focused", "--skip-lint"]
    if unit_targets:
        for target in unit_targets:
            parts.extend(["--unit-target", target])
    else:
        parts.append("--skip-unit")
    for suite in suites:
        parts.extend(["--suite", suite])
    return " ".join(shlex.quote(part) for part in parts)


def collect_names(records: list[dict]) -> list[str]:
    return [str(record["name"]) for record in records if isinstance(record.get("name"), str)]


def build_target_commands(unit_names: list[str], suite_names: list[str]) -> dict:
    commands: dict[str, str] = {}
    for name in unit_names:
        commands[f"unit:{name}"] = f"cargo test --test {shlex.quote(name)} -- --nocapture"
    for name in suite_names:
        commands[f"suite:{name}"] = f"cargo test --test {shlex.quote(name)} -- --nocapture"
    return commands


def build_ranked_diagnostics(unit_diff: dict, suite_diff: dict) -> list[dict]:
    category_priority = {
        "regressions": 100,
        "new_failures": 90,
        "unresolved_failures": 70,
        "fixed": 40,
        "removed": 30,
        "added_pass": 20,
        "stable_pass": 10,
    }
    category_label = {
        "regressions": "regression",
        "new_failures": "new_failure",
        "unresolved_failures": "unresolved_failure",
        "fixed": "fixed",
        "removed": "removed",
        "added_pass": "added_pass",
        "stable_pass": "stable_pass",
    }
    category_order = [
        "regressions",
        "new_failures",
        "unresolved_failures",
        "fixed",
        "removed",
        "added_pass",
        "stable_pass",
    ]

    diagnostics: list[dict] = []
    for surface, section in (("unit", unit_diff), ("suite", suite_diff)):
        for category in category_order:
            for record in section.get(category, []):
                name = record.get("name")
                if not isinstance(name, str) or not name:
                    continue
                diagnostics.append(
                    {
                        "surface": surface,
                        "name": name,
                        "severity": category_label[category],
                        "priority_score": category_priority[category],
                        "baseline_exit_code": record.get("baseline_exit_code"),
                        "current_exit_code": record.get("current_exit_code"),
                        "baseline_log_file": record.get("baseline_log_file"),
                        "current_log_file": record.get("current_log_file"),
                        "recommended_command": (
                            f"cargo test --test {shlex.quote(name)} -- --nocapture"
                        ),
                    }
                )

    diagnostics.sort(
        key=lambda item: (
            -int(item["priority_score"]),
            str(item["surface"]),
            str(item["name"]),
        )
    )
    for index, item in enumerate(diagnostics, start=1):
        item["rank"] = index

    return diagnostics


try:
    baseline_summary = read_summary(baseline_summary_path)
    current_summary = read_summary(current_summary_path)
except RuntimeError as exc:
    print(f"[triage] {exc}", file=sys.stderr)
    sys.exit(1)

unit_diff = diff_section(
    baseline=baseline_summary,
    current=current_summary,
    section_key="unit_targets",
    name_key="target",
)
suite_diff = diff_section(
    baseline=baseline_summary,
    current=current_summary,
    section_key="suites",
    name_key="suite",
)

unit_regressions = collect_names(unit_diff["regressions"])
unit_new_failures = collect_names(unit_diff["new_failures"])
unit_unresolved = collect_names(unit_diff["unresolved_failures"])
suite_regressions = collect_names(suite_diff["regressions"])
suite_new_failures = collect_names(suite_diff["new_failures"])
suite_unresolved = collect_names(suite_diff["unresolved_failures"])

triage_unit_focus = sorted(set(unit_regressions + unit_new_failures + unit_unresolved))
triage_suite_focus = sorted(set(suite_regressions + suite_new_failures + suite_unresolved))

regression_count = len(unit_regressions) + len(suite_regressions)
new_failure_count = len(unit_new_failures) + len(suite_new_failures)
unresolved_count = len(unit_unresolved) + len(suite_unresolved)
fixed_count = len(unit_diff["fixed"]) + len(suite_diff["fixed"])
suite_categories = build_category_map(suite_diff)
baseline_suite_index = build_index(baseline_summary, "suites", "suite")
current_suite_index = build_index(current_summary, "suites", "suite")
baseline_diag = load_failure_diagnostics(baseline_summary, baseline_summary_path)
current_diag = load_failure_diagnostics(current_summary, current_summary_path)
semantic_diffs, unresolved_semantic_count = build_semantic_diffs(
    suite_categories=suite_categories,
    baseline_diag=baseline_diag,
    current_diag=current_diag,
)
semantic_by_suite = {
    str(entry["suite"]): entry
    for entry in semantic_diffs
    if isinstance(entry, dict) and isinstance(entry.get("suite"), str)
}

scenario_matrix_path = project_root / "docs" / "e2e_scenario_matrix.json"
scenario_rows: list[dict] = []
scenario_matrix_payload = read_json(scenario_matrix_path)
if isinstance(scenario_matrix_payload, dict):
    rows = scenario_matrix_payload.get("rows")
    if isinstance(rows, list):
        scenario_rows = [row for row in rows if isinstance(row, dict)]

mirrored_scenarios = build_mirrored_scenario_report(
    scenario_rows=scenario_rows,
    baseline_suite_index=baseline_suite_index,
    current_suite_index=current_suite_index,
    semantic_by_suite=semantic_by_suite,
)
mirrored_summary = (
    mirrored_scenarios.get("summary", {})
    if isinstance(mirrored_scenarios, dict)
    else {}
)
mirrored_semantic_mismatch_workflow_count = (
    mirrored_summary.get("semantic_mismatch_workflows", 0)
    if isinstance(mirrored_summary.get("semantic_mismatch_workflows", 0), int)
    else 0
)
mirrored_incomplete_workflow_count = (
    mirrored_summary.get("incomplete_mirroring_workflows", 0)
    if isinstance(mirrored_summary.get("incomplete_mirroring_workflows", 0), int)
    else 0
)
mirrored_evaluated_workflow_count = (
    mirrored_summary.get("evaluated_workflows", 0)
    if isinstance(mirrored_summary.get("evaluated_workflows", 0), int)
    else 0
)

recommended_commands = {
    "runner_repro_command": build_runner_command(triage_unit_focus, triage_suite_focus)
    if triage_unit_focus or triage_suite_focus
    else "",
    "target_commands": build_target_commands(triage_unit_focus, triage_suite_focus),
}
ranked_diagnostics = build_ranked_diagnostics(unit_diff, suite_diff)
ranked_repro_commands: list[str] = []
seen_commands: set[str] = set()
for item in ranked_diagnostics:
    severity = item.get("severity")
    command = item.get("recommended_command")
    if severity not in {"regression", "new_failure", "unresolved_failure"}:
        continue
    if not isinstance(command, str) or not command:
        continue
    if command in seen_commands:
        continue
    seen_commands.add(command)
    ranked_repro_commands.append(command)
recommended_commands["ranked_repro_commands"] = ranked_repro_commands
semantic_focus_commands: list[str] = []
seen_semantic_commands: set[str] = set()
for entry in semantic_diffs:
    if not isinstance(entry, dict):
        continue
    if not bool(entry.get("unresolved")):
        continue
    command = entry.get("recommended_command")
    if not isinstance(command, str) or not command:
        continue
    if command in seen_semantic_commands:
        continue
    seen_semantic_commands.add(command)
    semantic_focus_commands.append(command)
recommended_commands["semantic_focus_commands"] = semantic_focus_commands

status = "regression" if (regression_count > 0 or new_failure_count > 0) else "stable"
if status == "stable" and unresolved_count > 0:
    status = "known_failures_only"
if status in {"stable", "known_failures_only"} and unresolved_semantic_count > 0:
    status = "semantic_mismatch"
if status == "stable" and mirrored_incomplete_workflow_count > 0:
    status = "incomplete_mirroring"

payload = {
    "schema": "pi.e2e.triage_diff.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "status": status,
    "baseline_summary_path": str(baseline_summary_path),
    "current_summary_path": str(current_summary_path),
    "baseline_artifact_dir": baseline_summary.get("artifact_dir"),
    "current_artifact_dir": current_summary.get("artifact_dir"),
    "summary": {
        "regression_count": regression_count,
        "new_failure_count": new_failure_count,
        "unresolved_failure_count": unresolved_count,
        "fixed_count": fixed_count,
        "unit_regression_count": len(unit_regressions),
        "suite_regression_count": len(suite_regressions),
        "semantic_mismatch_count": unresolved_semantic_count,
        "mirrored_evaluated_workflow_count": mirrored_evaluated_workflow_count,
        "mirrored_semantic_mismatch_workflow_count": mirrored_semantic_mismatch_workflow_count,
        "mirrored_incomplete_workflow_count": mirrored_incomplete_workflow_count,
    },
    "unit_targets": unit_diff,
    "suites": suite_diff,
    "focus": {
        "unit_targets": triage_unit_focus,
        "suites": triage_suite_focus,
    },
    "semantic_diffs": {
        "schema": "pi.e2e.semantic_diff.v1",
        "unresolved_count": unresolved_semantic_count,
        "entries": semantic_diffs,
    },
    "mirrored_scenarios": mirrored_scenarios,
    "ranked_diagnostics": ranked_diagnostics,
    "recommended_commands": recommended_commands,
}

diff_file.parent.mkdir(parents=True, exist_ok=True)
diff_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

current_summary["triage_diff"] = {
    "schema": "pi.e2e.triage_diff.v1",
    "path": str(diff_file),
    "baseline_summary_path": str(baseline_summary_path),
    "status": status,
    "regression_count": regression_count,
    "new_failure_count": new_failure_count,
    "unresolved_failure_count": unresolved_count,
    "fixed_count": fixed_count,
    "semantic_mismatch_count": unresolved_semantic_count,
    "mirrored_evaluated_workflow_count": mirrored_evaluated_workflow_count,
    "mirrored_semantic_mismatch_workflow_count": mirrored_semantic_mismatch_workflow_count,
    "mirrored_incomplete_workflow_count": mirrored_incomplete_workflow_count,
    "top_ranked_diagnostics": ranked_diagnostics[:5],
    "top_semantic_diffs": semantic_diffs[:5],
}
current_summary_path.write_text(json.dumps(current_summary, indent=2) + "\n", encoding="utf-8")

print("TRIAGE DIFF GENERATED")
print(f"- Baseline: {baseline_summary_path}")
print(f"- Current:  {current_summary_path}")
print(
    "- Summary: regressions="
    f"{regression_count}, new_failures={new_failure_count}, unresolved={unresolved_count}, fixed={fixed_count}"
)
print(
    "- Semantic: mismatches="
    f"{unresolved_semantic_count}, mirrored_workflows={mirrored_evaluated_workflow_count}, "
    f"mirrored_semantic_mismatches={mirrored_semantic_mismatch_workflow_count}, "
    f"mirrored_incomplete={mirrored_incomplete_workflow_count}"
)
if recommended_commands["runner_repro_command"]:
    print(f"- Repro runner: {recommended_commands['runner_repro_command']}")
if recommended_commands["semantic_focus_commands"]:
    print("- Semantic repro focus:")
    for command in recommended_commands["semantic_focus_commands"][:5]:
        print(f"  - {command}")
if ranked_diagnostics:
    print("- Ranked diagnostics:")
    for item in ranked_diagnostics[:5]:
        print(
            f"  {item['rank']}. [{item['severity']}] "
            f"{item['surface']}:{item['name']} -> {item['recommended_command']}"
        )
print(f"- Diff artifact: {diff_file}")
sys.exit(0)
PY
    then
        echo "[triage] Diff report written to $diff_file"
        return 0
    else
        echo "[triage] Diff generation failed" >&2
        return 1
    fi
}

# ─── Evidence Contract Validation ────────────────────────────────────────────

validate_evidence_contract() {
    local contract_file="$ARTIFACT_DIR/evidence_contract.json"
    local selected_units_json selected_suites_json
    local all_unit_targets_json all_suites_json

    selected_units_json="$(
        printf '%s\n' "${SELECTED_UNIT_TARGETS[@]:-}" | \
            python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'
    )"
    selected_suites_json="$(
        printf '%s\n' "${SELECTED_SUITES[@]:-}" | \
            python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'
    )"
    all_unit_targets_json="$(
        printf '%s\n' "${ALL_UNIT_TARGETS[@]:-}" | \
            python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'
    )"
    all_suites_json="$(
        printf '%s\n' "${ALL_SUITES[@]:-}" | \
            python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))' 2>/dev/null || echo '[]'
    )"

    if ARTIFACT_DIR="$ARTIFACT_DIR" \
        PROJECT_ROOT="$PROJECT_ROOT" \
        VERIFY_PROFILE_NAME="$PROFILE" \
        CONTRACT_FILE="$contract_file" \
        SELECTED_UNITS_JSON="$selected_units_json" \
        SELECTED_SUITES_JSON="$selected_suites_json" \
        ALL_UNIT_TARGETS_JSON="$all_unit_targets_json" \
        ALL_SUITES_JSON="$all_suites_json" \
        RERUN_FROM_JSON="$RERUN_JSON_VALUE" \
        python3 - <<'PY'
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

artifact_dir = Path(os.environ["ARTIFACT_DIR"])
project_root = Path(os.environ["PROJECT_ROOT"])
profile = os.environ.get("VERIFY_PROFILE_NAME", "full")
contract_file = Path(os.environ["CONTRACT_FILE"])

try:
    selected_units = json.loads(os.environ.get("SELECTED_UNITS_JSON", "[]"))
except json.JSONDecodeError:
    selected_units = []
try:
    selected_suites = json.loads(os.environ.get("SELECTED_SUITES_JSON", "[]"))
except json.JSONDecodeError:
    selected_suites = []
try:
    all_unit_targets = json.loads(os.environ.get("ALL_UNIT_TARGETS_JSON", "[]"))
except json.JSONDecodeError:
    all_unit_targets = []
try:
    all_suites = json.loads(os.environ.get("ALL_SUITES_JSON", "[]"))
except json.JSONDecodeError:
    all_suites = []
try:
    rerun_from = json.loads(os.environ.get("RERUN_FROM_JSON", "null"))
except json.JSONDecodeError:
    rerun_from = None

checks = []
errors = []
warnings = []
remediation_hints: set[str] = set()


def add_check(check_id: str, path: Path, ok: bool, diagnostics: str) -> None:
    checks.append(
        {
            "id": check_id,
            "path": str(path),
            "ok": ok,
            "diagnostics": diagnostics,
        }
    )


def record_issue(check_id: str, message: str, *, strict: bool, remediation: str | None = None) -> None:
    rendered = f"{check_id}: {message}"
    if remediation:
        remediation_hints.add(remediation)
        rendered = f"{rendered} | remediation: {remediation}"
    if strict:
        errors.append(rendered)
    else:
        warnings.append(rendered)


def remediation_for_missing_keys(check_id: str, path: Path, missing: list[str]) -> str:
    missing_list = ", ".join(missing)
    if check_id.startswith("environment"):
        return f"Update capture_env() to emit key(s): {missing_list}."
    if check_id.startswith("summary"):
        return f"Update write_summary() to emit key(s): {missing_list}."
    if check_id.startswith("failure_diagnostics"):
        return (
            "Update generate_failure_diagnostics() payloads in scripts/e2e/run_all.sh "
            f"to include key(s): {missing_list}."
        )
    if check_id.startswith("unit:") or check_id.startswith("suite:"):
        return (
            "Update run_unit_target()/run_suite() result.json emitters to include "
            f"key(s): {missing_list}."
        )
    if check_id.startswith("conformance.release_readiness"):
        return (
            "Update generate_release_readiness_report() payload in scripts/e2e/run_all.sh "
            f"to include key(s): {missing_list}."
        )
    if check_id.startswith("conformance.profile_matrix"):
        return (
            "Update generate_extension_profile_matrix() output to include "
            f"key(s): {missing_list}."
        )
    return (
        "Update scripts/e2e/run_all.sh artifact generation so "
        f"{path.name} includes key(s): {missing_list}."
    )


def require_file(
    check_id: str,
    path: Path,
    *,
    strict: bool,
    description: str,
    remediation: str | None = None,
) -> bool:
    ok = path.exists()
    add_check(check_id, path, ok, description if ok else f"missing required file: {path}")
    if not ok:
        record_issue(
            check_id,
            f"missing {path}",
            strict=strict,
            remediation=(
                remediation
                or f"Ensure the producer step writes {path.name} before validation."
            ),
        )
    return ok


def load_json(check_id: str, path: Path, *, strict: bool) -> dict | None:
    if not require_file(check_id, path, strict=strict, description="file exists"):
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        add_check(check_id + ".json_parse", path, False, f"invalid JSON: {exc}")
        record_issue(
            check_id,
            f"invalid JSON ({exc})",
            strict=strict,
            remediation=f"Rewrite {path.name} as valid JSON and rerun ./scripts/e2e/run_all.sh.",
        )
        return None
    add_check(check_id + ".json_parse", path, True, "valid JSON")
    return payload


def require_keys(
    check_id: str,
    payload: dict | None,
    path: Path,
    keys: list[str],
    *,
    strict: bool,
) -> None:
    if payload is None:
        return
    missing = [key for key in keys if key not in payload]
    ok = not missing
    add_check(
        check_id + ".keys",
        path,
        ok,
        "all required keys present" if ok else f"missing keys: {', '.join(missing)}",
    )
    if not ok:
        record_issue(
            check_id,
            f"missing keys in {path}: {', '.join(missing)}",
            strict=strict,
            remediation=remediation_for_missing_keys(check_id, path, missing),
        )


def require_condition(
    check_id: str,
    *,
    path: Path,
    ok: bool,
    ok_msg: str,
    fail_msg: str,
    strict: bool,
    remediation: str | None = None,
) -> None:
    add_check(check_id, path, ok, ok_msg if ok else fail_msg)
    if ok:
        return
    record_issue(check_id, fail_msg, strict=strict, remediation=remediation)


# 1) Core run artifacts (always required)
environment_path = artifact_dir / "environment.json"
environment = load_json("environment", environment_path, strict=True)
require_keys(
    "environment",
    environment,
    environment_path,
    [
        "schema",
        "timestamp",
        "profile",
        "rerun_from",
        "diff_from",
        "rustc",
        "cargo",
        "os",
        "git_sha",
        "git_branch",
        "parallelism",
        "log_level",
        "artifact_dir",
        "correlation_id",
        "shard",
        "unit_targets",
        "e2e_suites",
    ],
    strict=True,
)

summary_path = artifact_dir / "summary.json"
summary = load_json("summary", summary_path, strict=True)
require_keys(
    "summary",
    summary,
    summary_path,
    [
        "schema",
        "timestamp",
        "profile",
        "rerun_from",
        "diff_from",
        "artifact_dir",
        "correlation_id",
        "shard",
        "total_units",
        "passed_units",
        "failed_units",
        "total_suites",
        "passed_suites",
        "failed_suites",
        "unit_targets",
        "suites",
        "failure_diagnostics",
    ],
    strict=True,
)

environment_correlation_id = ""
if isinstance(environment, dict):
    require_condition(
        "environment.schema",
        path=environment_path,
        ok=environment.get("schema") == "pi.e2e.environment.v1",
        ok_msg="environment schema matches",
        fail_msg=f"expected schema 'pi.e2e.environment.v1', got {environment.get('schema')!r}",
        strict=True,
        remediation="Update capture_env() schema to pi.e2e.environment.v1.",
    )
    environment_correlation_id = str(environment.get("correlation_id", "")).strip()
    require_condition(
        "environment.correlation_id_nonempty",
        path=environment_path,
        ok=bool(environment_correlation_id),
        ok_msg="environment correlation_id is set",
        fail_msg="environment correlation_id is empty",
        strict=True,
        remediation="Set CORRELATION_ID before capture_env() and emit it in environment.json.",
    )

summary_correlation_id = ""
if isinstance(summary, dict):
    require_condition(
        "summary.schema",
        path=summary_path,
        ok=summary.get("schema") == "pi.e2e.summary.v1",
        ok_msg="summary schema matches",
        fail_msg=f"expected schema 'pi.e2e.summary.v1', got {summary.get('schema')!r}",
        strict=True,
        remediation="Update write_summary() schema to pi.e2e.summary.v1.",
    )
    summary_correlation_id = str(summary.get("correlation_id", "")).strip()
    require_condition(
        "summary.correlation_id_nonempty",
        path=summary_path,
        ok=bool(summary_correlation_id),
        ok_msg="summary correlation_id is set",
        fail_msg="summary correlation_id is empty",
        strict=True,
        remediation="Emit CORRELATION_ID in write_summary() output.",
    )

if summary_correlation_id and environment_correlation_id:
    require_condition(
        "run.correlation_id_matches_environment",
        path=summary_path,
        ok=summary_correlation_id == environment_correlation_id,
        ok_msg="summary/environment correlation_id values match",
        fail_msg=(
            "summary/environment correlation_id mismatch: "
            f"{summary_correlation_id!r} vs {environment_correlation_id!r}"
        ),
        strict=True,
        remediation=(
            "Propagate the same CORRELATION_ID through capture_env() and write_summary()."
        ),
    )

# Full-profile baseline runs must cover every configured target and suite.
strict_conformance = profile == "full" and rerun_from is None
full_scope_path = artifact_dir / "summary.json"
if profile == "full":
    require_condition(
        "full_profile.rerun_mode",
        path=full_scope_path,
        ok=rerun_from is None,
        ok_msg="full profile baseline run (not rerun)",
        fail_msg="full profile rerun detected; scope checks downgraded to warnings",
        strict=False,
    )

    missing_units = sorted(set(all_unit_targets) - set(selected_units))
    extra_units = sorted(set(selected_units) - set(all_unit_targets))
    require_condition(
        "full_profile.unit_scope_complete",
        path=full_scope_path,
        ok=not missing_units and not extra_units,
        ok_msg=f"selected all unit targets ({len(all_unit_targets)})",
        fail_msg=(
            f"unit scope mismatch; missing={missing_units if missing_units else []}, "
            f"extra={extra_units if extra_units else []}"
        ),
        strict=strict_conformance,
    )

    missing_suites = sorted(set(all_suites) - set(selected_suites))
    extra_suites = sorted(set(selected_suites) - set(all_suites))
    require_condition(
        "full_profile.e2e_scope_complete",
        path=full_scope_path,
        ok=not missing_suites and not extra_suites,
        ok_msg=f"selected all e2e suites ({len(all_suites)})",
        fail_msg=(
            f"e2e scope mismatch; missing={missing_suites if missing_suites else []}, "
            f"extra={extra_suites if extra_suites else []}"
        ),
        strict=strict_conformance,
    )

LOG_REQUIRED_FIELDS = {
    "pi.test.log.v1": [
        "schema",
        "type",
        "seq",
        "ts",
        "t_ms",
        "level",
        "category",
        "message",
    ],
    "pi.test.log.v2": [
        "schema",
        "type",
        "trace_id",
        "seq",
        "ts",
        "t_ms",
        "level",
        "category",
        "message",
    ],
}
ARTIFACT_REQUIRED_FIELDS = ["schema", "type", "seq", "ts", "t_ms", "name", "path"]
MAX_OUTPUT_LOG_BYTES = 8 * 1024 * 1024
MAX_TEST_LOG_JSONL_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_INDEX_JSONL_BYTES = 4 * 1024 * 1024
MAX_JSONL_RECORDS = 25_000

LEAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_like_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("generic_key_token", re.compile(r"\bkey-[A-Za-z0-9_-]{20,}\b", re.IGNORECASE)),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    (
        "auth_header_value",
        re.compile(
            r"(?i)(authorization|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token)"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{12,}"
        ),
    ),
]


def normalized_jsonl_path(path: Path) -> Path:
    file_name = path.name
    if file_name.endswith(".jsonl"):
        base = file_name[: -len(".jsonl")]
    else:
        base = file_name
    return path.with_name(f"{base}.normalized.jsonl")


def find_sensitive_leaks(text: str, *, limit: int = 3) -> list[str]:
    hits: list[str] = []
    for label, pattern in LEAK_PATTERNS:
        for match in pattern.finditer(text):
            snippet = match.group(0)
            upper = snippet.upper()
            if "REDACTED" in upper or "<TRACE_ID>" in snippet or "<TIMESTAMP>" in snippet:
                continue
            hits.append(f"{label}:{snippet[:96]}")
            if len(hits) >= limit:
                return hits
    return hits


def validate_text_redaction(
    *,
    check_id: str,
    path: Path,
    strict: bool,
) -> None:
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - defensive
        add_check(check_id, path, False, f"redaction scan failed to read file: {exc}")
        record_issue(
            check_id,
            f"unable to scan file for sensitive leaks ({exc})",
            strict=strict,
            remediation=f"Ensure {path.name} is readable before evidence validation.",
        )
        return
    leaks = find_sensitive_leaks(text)
    require_condition(
        check_id,
        path=path,
        ok=not leaks,
        ok_msg="no high-confidence secret/token patterns detected",
        fail_msg=f"potential sensitive leaks detected: {leaks}",
        strict=strict,
        remediation=(
            "Redact authorization/api-key/token values in artifact output and rerun verification."
        ),
    )


def validate_file_budget(
    *,
    check_id: str,
    path: Path,
    max_bytes: int,
    strict: bool,
    remediation: str,
) -> None:
    if not path.exists():
        return
    size_bytes = path.stat().st_size
    require_condition(
        check_id,
        path=path,
        ok=size_bytes <= max_bytes,
        ok_msg=f"file size {size_bytes} bytes within budget <= {max_bytes}",
        fail_msg=f"file size {size_bytes} bytes exceeds budget {max_bytes}",
        strict=strict,
        remediation=remediation,
    )

validate_text_redaction(
    check_id="environment.redaction_scan",
    path=environment_path,
    strict=True,
)
validate_text_redaction(
    check_id="summary.redaction_scan",
    path=summary_path,
    strict=True,
)


def path_matches(value: object, expected: Path) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    candidate = Path(text)
    if candidate == expected:
        return True
    try:
        return candidate.resolve() == expected.resolve()
    except Exception:  # pragma: no cover - defensive
        return False


def read_jsonl_lines(check_id: str, path: Path, *, strict: bool) -> list[tuple[int, str]]:
    if not require_file(
        check_id,
        path,
        strict=strict,
        description="jsonl file exists",
        remediation=f"Ensure test harness writes {path.name} for every selected suite/target.",
    ):
        return []
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:  # pragma: no cover - defensive
        add_check(f"{check_id}.readable", path, False, f"read failed: {exc}")
        record_issue(
            check_id,
            f"failed reading {path}: {exc}",
            strict=strict,
            remediation=f"Fix file permissions/content for {path} and rerun verification.",
        )
        return []
    add_check(f"{check_id}.readable", path, True, f"loaded {len(lines)} non-empty JSONL lines")
    return list(enumerate(lines, start=1))


def validate_jsonl_record_keys(
    *,
    check_id: str,
    path: Path,
    record: dict,
    required_keys: list[str],
    line_no: int,
    strict: bool,
    remediation: str,
) -> None:
    missing = [key for key in required_keys if key not in record]
    require_condition(
        f"{check_id}.line_{line_no}.required_keys",
        path=path,
        ok=not missing,
        ok_msg="all required keys present",
        fail_msg=f"line {line_no} missing keys: {missing}",
        strict=strict,
        remediation=remediation,
    )


def parse_test_log_jsonl(check_prefix: str, path: Path) -> dict[str, set[str]]:
    trace_ids_by_test: dict[str, set[str]] = {}
    observed_categories: set[str] = set()
    lines = read_jsonl_lines(f"{check_prefix}.test_log_jsonl", path, strict=True)
    require_condition(
        f"{check_prefix}.test_log_jsonl.record_budget",
        path=path,
        ok=len(lines) <= MAX_JSONL_RECORDS,
        ok_msg=f"test-log record count {len(lines)} within budget <= {MAX_JSONL_RECORDS}",
        fail_msg=(
            f"test-log record count {len(lines)} exceeds budget {MAX_JSONL_RECORDS}"
        ),
        strict=True,
        remediation="Reduce noisy log emission or scope logging in tests/common/logging.",
    )
    require_condition(
        f"{check_prefix}.test_log_jsonl.non_empty",
        path=path,
        ok=len(lines) > 0,
        ok_msg=f"test-log contains {len(lines)} records",
        fail_msg="test-log.jsonl is empty",
        strict=True,
        remediation="Ensure tests/common/logging writes at least one log record per target/suite.",
    )
    for line_no, line in lines:
        record_id = f"{check_prefix}.test_log_jsonl.line_{line_no}"
        try:
            payload = json.loads(line)
        except Exception as exc:  # pragma: no cover - defensive
            add_check(record_id, path, False, f"invalid JSON: {exc}")
            record_issue(
                record_id,
                f"invalid JSON: {exc}",
                strict=True,
                remediation="Emit valid JSONL records in test-log.jsonl.",
            )
            continue
        if not isinstance(payload, dict):
            add_check(record_id, path, False, "record must be a JSON object")
            record_issue(
                record_id,
                "record must be a JSON object",
                strict=True,
                remediation="Write object records (not arrays/scalars) to test-log.jsonl.",
            )
            continue
        schema = payload.get("schema")
        schema_text = str(schema)
        required = LOG_REQUIRED_FIELDS.get(schema_text)
        is_artifact_record = schema_text == "pi.test.artifact.v1"
        require_condition(
            f"{record_id}.schema_supported",
            path=path,
            ok=required is not None or is_artifact_record,
            ok_msg=f"supported schema {schema!r}",
            fail_msg=f"unsupported test-log schema {schema!r}",
            strict=True,
            remediation=(
                "Use pi.test.log.v2 (or v1 where legacy is explicitly required) "
                "or pi.test.artifact.v1 for inline artifact records."
            ),
        )
        if is_artifact_record:
            validate_jsonl_record_keys(
                check_id=record_id,
                path=path,
                record=payload,
                required_keys=ARTIFACT_REQUIRED_FIELDS,
                line_no=line_no,
                strict=True,
                remediation=(
                    "Ensure inline artifact records in test-log.jsonl emit required "
                    "pi.test.artifact.v1 fields."
                ),
            )
            continue
        if required is None:
            continue
        validate_jsonl_record_keys(
            check_id=record_id,
            path=path,
            record=payload,
            required_keys=required,
            line_no=line_no,
            strict=True,
            remediation="Ensure tests/common/logging emits required test-log schema fields.",
        )
        category = payload.get("category")
        if isinstance(category, str) and category.strip():
            observed_categories.add(category.strip())
        test_name = payload.get("test")
        if isinstance(test_name, str) and test_name.strip():
            trace_id = payload.get("trace_id")
            if isinstance(trace_id, str) and trace_id.strip():
                trace_ids_by_test.setdefault(test_name, set()).add(trace_id)
        else:
            require_condition(
                f"{record_id}.test_field_present",
                path=path,
                ok=False,
                ok_msg="test field present",
                fail_msg=f"line {line_no} missing non-empty test field",
                strict=strict_conformance,
                remediation="Populate the `test` field in every test-log JSONL record.",
            )
    multi_trace_tests = sorted(
        [name for name, trace_ids in trace_ids_by_test.items() if len(trace_ids) > 1]
    )
    require_condition(
        f"{check_prefix}.test_log_jsonl.trace_ids_consistent",
        path=path,
        ok=not multi_trace_tests,
        ok_msg="trace_id values are consistent per test",
        fail_msg=f"multiple trace_id values detected for tests: {multi_trace_tests}",
        strict=strict_conformance,
        remediation="Use a stable trace_id per test invocation.",
    )
    require_condition(
        f"{check_prefix}.test_log_jsonl.minimum_signal_harness_category",
        path=path,
        ok="harness" in observed_categories,
        ok_msg="test-log includes harness category signal",
        fail_msg=(
            f"test-log missing harness category signal; observed categories={sorted(observed_categories)}"
        ),
        strict=True,
        remediation=(
            "Ensure tests/common/harness emits start/completion harness log entries to preserve minimum triage signal."
        ),
    )
    return trace_ids_by_test


def parse_artifact_index_jsonl(
    check_prefix: str,
    path: Path,
    trace_ids_by_test: dict[str, set[str]],
) -> None:
    lines = read_jsonl_lines(f"{check_prefix}.artifact_index_jsonl", path, strict=True)
    if not lines:
        add_check(
            f"{check_prefix}.artifact_index_jsonl.empty_ok",
            path,
            True,
            "artifact-index has no records (allowed when no artifacts were emitted)",
        )
        return
    for line_no, line in lines:
        record_id = f"{check_prefix}.artifact_index_jsonl.line_{line_no}"
        try:
            payload = json.loads(line)
        except Exception as exc:  # pragma: no cover - defensive
            add_check(record_id, path, False, f"invalid JSON: {exc}")
            record_issue(
                record_id,
                f"invalid JSON: {exc}",
                strict=True,
                remediation="Emit valid JSONL records in artifact-index.jsonl.",
            )
            continue
        if not isinstance(payload, dict):
            add_check(record_id, path, False, "record must be a JSON object")
            record_issue(
                record_id,
                "record must be a JSON object",
                strict=True,
                remediation="Write object records (not arrays/scalars) to artifact-index.jsonl.",
            )
            continue
        require_condition(
            f"{record_id}.schema",
            path=path,
            ok=payload.get("schema") == "pi.test.artifact.v1",
            ok_msg="artifact-index schema matches",
            fail_msg=f"unexpected artifact schema {payload.get('schema')!r}",
            strict=True,
            remediation="Emit artifact-index records with schema pi.test.artifact.v1.",
        )
        validate_jsonl_record_keys(
            check_id=record_id,
            path=path,
            record=payload,
            required_keys=ARTIFACT_REQUIRED_FIELDS,
            line_no=line_no,
            strict=True,
            remediation="Ensure tests/common/logging emits required artifact-index schema fields.",
        )
        test_name = payload.get("test")
        has_test = isinstance(test_name, str) and bool(test_name.strip())
        require_condition(
            f"{record_id}.test_field_present",
            path=path,
            ok=has_test,
            ok_msg="artifact record includes test name",
            fail_msg=f"line {line_no} missing non-empty test field",
            strict=strict_conformance,
            remediation="Emit `test` in artifact-index records to support trace linkage.",
        )
        if has_test and strict_conformance:
            linked_trace_ids = trace_ids_by_test.get(str(test_name), set())
            require_condition(
                f"{record_id}.trace_linked_to_test_log",
                path=path,
                ok=bool(linked_trace_ids),
                ok_msg=f"artifact test {test_name!r} links to trace_id set {sorted(linked_trace_ids)}",
                fail_msg=(
                    f"artifact test {test_name!r} has no matching test-log trace_id context"
                ),
                strict=True,
                remediation=(
                    "Ensure artifact-index `test` names match test-log records emitted by the same suite/target."
                ),
            )


def validate_normalized_jsonl_pair(
    *,
    check_prefix: str,
    raw_path: Path,
    normalized_path: Path,
    allowed_schemas: set[str],
    enforce_path_placeholder: bool,
) -> None:
    raw_lines = read_jsonl_lines(f"{check_prefix}.raw", raw_path, strict=True)
    normalized_lines = read_jsonl_lines(f"{check_prefix}.normalized", normalized_path, strict=True)

    require_condition(
        f"{check_prefix}.line_count_matches_raw",
        path=normalized_path,
        ok=len(raw_lines) == len(normalized_lines),
        ok_msg="normalized JSONL line count matches raw JSONL",
        fail_msg=(
            f"normalized/raw line-count mismatch: normalized={len(normalized_lines)} raw={len(raw_lines)}"
        ),
        strict=True,
        remediation=(
            "Emit normalized JSONL as a 1:1 transformation of raw JSONL records "
            "to preserve retention/index completeness."
        ),
    )
    require_condition(
        f"{check_prefix}.record_budget",
        path=normalized_path,
        ok=len(normalized_lines) <= MAX_JSONL_RECORDS,
        ok_msg=f"normalized JSONL record count {len(normalized_lines)} within budget <= {MAX_JSONL_RECORDS}",
        fail_msg=(
            f"normalized JSONL record count {len(normalized_lines)} exceeds budget {MAX_JSONL_RECORDS}"
        ),
        strict=True,
        remediation="Reduce noisy log/artifact emission or partition runs.",
    )

    for line_no, line in normalized_lines:
        record_id = f"{check_prefix}.line_{line_no}"
        try:
            payload = json.loads(line)
        except Exception as exc:  # pragma: no cover - defensive
            add_check(record_id, normalized_path, False, f"invalid JSON: {exc}")
            record_issue(
                record_id,
                f"invalid JSON: {exc}",
                strict=True,
                remediation=(
                    "Write valid JSON objects to normalized JSONL output files."
                ),
            )
            continue
        if not isinstance(payload, dict):
            add_check(record_id, normalized_path, False, "record must be a JSON object")
            record_issue(
                record_id,
                "record must be a JSON object",
                strict=True,
                remediation="Emit object records in normalized JSONL output files.",
            )
            continue

        schema = str(payload.get("schema", ""))
        require_condition(
            f"{record_id}.schema_allowed",
            path=normalized_path,
            ok=schema in allowed_schemas,
            ok_msg=f"schema {schema!r} allowed",
            fail_msg=f"schema {schema!r} not allowed in normalized JSONL",
            strict=True,
            remediation=(
                "Keep normalized JSONL schema set aligned to test-log/artifact schemas."
            ),
        )
        require_condition(
            f"{record_id}.timestamp_normalized",
            path=normalized_path,
            ok=str(payload.get("ts", "")) == "<TIMESTAMP>",
            ok_msg="normalized timestamp placeholder is applied",
            fail_msg=f"normalized ts must be <TIMESTAMP> (got {payload.get('ts')!r})",
            strict=True,
            remediation="Normalize timestamps to <TIMESTAMP> in normalized JSONL writers.",
        )
        require_condition(
            f"{record_id}.elapsed_normalized",
            path=normalized_path,
            ok=payload.get("t_ms") == 0,
            ok_msg="normalized elapsed t_ms is 0",
            fail_msg=f"normalized t_ms must be 0 (got {payload.get('t_ms')!r})",
            strict=True,
            remediation="Normalize elapsed timing fields to deterministic placeholder values.",
        )

        trace_id = payload.get("trace_id")
        if trace_id is not None:
            require_condition(
                f"{record_id}.trace_id_normalized",
                path=normalized_path,
                ok=str(trace_id) == "<TRACE_ID>",
                ok_msg="trace_id normalized to <TRACE_ID>",
                fail_msg=f"trace_id not normalized (got {trace_id!r})",
                strict=True,
                remediation="Normalize trace_id values to <TRACE_ID> in normalized log output.",
            )

        for field in ("span_id", "parent_span_id"):
            if payload.get(field) is not None:
                require_condition(
                    f"{record_id}.{field}_normalized",
                    path=normalized_path,
                    ok=str(payload.get(field)) == "<SPAN_ID>",
                    ok_msg=f"{field} normalized to <SPAN_ID>",
                    fail_msg=f"{field} not normalized (got {payload.get(field)!r})",
                    strict=True,
                    remediation=f"Normalize {field} values to <SPAN_ID> in normalized log output.",
                )

        if enforce_path_placeholder and "path" in payload:
            normalized_path_value = str(payload.get("path", ""))
            has_placeholder = (
                "<TEST_ROOT>" in normalized_path_value
                or "<PROJECT_ROOT>" in normalized_path_value
            )
            require_condition(
                f"{record_id}.path_placeholder",
                path=normalized_path,
                ok=has_placeholder or not normalized_path_value.startswith("/"),
                ok_msg="artifact path uses deterministic placeholders",
                fail_msg=(
                    f"normalized path should use placeholders (got {normalized_path_value!r})"
                ),
                strict=True,
                remediation=(
                    "Normalize artifact paths to <TEST_ROOT> / <PROJECT_ROOT> placeholders."
                ),
            )

    validate_text_redaction(
        check_id=f"{check_prefix}.redaction_scan",
        path=normalized_path,
        strict=True,
    )


def validate_result_contract(
    *,
    kind: str,
    name: str,
    result_path: Path,
    expected_log_path: Path,
    expected_test_log_path: Path,
    expected_artifact_index_path: Path,
) -> None:
    check_prefix = f"{kind}:{name}"
    result = load_json(f"{check_prefix}:result", result_path, strict=True)
    key_name = "target" if kind == "unit" else "suite"
    require_keys(
        f"{check_prefix}:result",
        result,
        result_path,
        [
            "schema",
            "result_kind",
            "correlation_id",
            key_name,
            "exit_code",
            "duration_ms",
            "passed",
            "failed",
            "ignored",
            "total",
            "log_file",
            "test_log_jsonl",
            "artifact_index_jsonl",
            "timestamp",
        ],
        strict=True,
    )
    if not isinstance(result, dict):
        return

    require_condition(
        f"{check_prefix}:result.schema",
        path=result_path,
        ok=result.get("schema") == "pi.e2e.result.v1",
        ok_msg="result schema matches",
        fail_msg=f"expected schema 'pi.e2e.result.v1', got {result.get('schema')!r}",
        strict=True,
        remediation="Emit schema pi.e2e.result.v1 in result.json.",
    )
    require_condition(
        f"{check_prefix}:result.kind",
        path=result_path,
        ok=result.get("result_kind") == kind,
        ok_msg=f"result_kind is {kind!r}",
        fail_msg=f"expected result_kind {kind!r}, got {result.get('result_kind')!r}",
        strict=True,
        remediation="Set result_kind to unit/suite in the corresponding result emitter.",
    )
    require_condition(
        f"{check_prefix}:result.name",
        path=result_path,
        ok=str(result.get(key_name, "")) == name,
        ok_msg=f"{key_name} matches selected item",
        fail_msg=(
            f"{key_name} mismatch: expected {name!r}, got {result.get(key_name)!r}"
        ),
        strict=True,
        remediation="Emit the exact suite/target identifier in result.json.",
    )
    require_condition(
        f"{check_prefix}:result.correlation_id_matches_summary",
        path=result_path,
        ok=bool(summary_correlation_id)
        and str(result.get("correlation_id", "")).strip() == summary_correlation_id,
        ok_msg="result correlation_id matches summary correlation_id",
        fail_msg=(
            "result correlation_id mismatch: "
            f"expected {summary_correlation_id!r}, got {result.get('correlation_id')!r}"
        ),
        strict=True,
        remediation="Propagate CORRELATION_ID into every result.json emitter.",
    )

    def resolve_required_path_field(
        field: str,
        *,
        expected: Path,
        remediation_hint: str,
    ) -> Path | None:
        raw_value = result.get(field)
        raw_text = str(raw_value).strip() if raw_value is not None else ""
        require_condition(
            f"{check_prefix}:result.{field}_nonempty",
            path=result_path,
            ok=bool(raw_text),
            ok_msg=f"{field} is non-empty",
            fail_msg=f"{field} is missing or empty",
            strict=True,
            remediation=remediation_hint,
        )
        if not raw_text:
            return None
        resolved = Path(raw_text)
        require_condition(
            f"{check_prefix}:result.{field}_path_matches",
            path=result_path,
            ok=path_matches(raw_text, expected),
            ok_msg=f"{field} path matches expected artifact path",
            fail_msg=(
                f"{field} path mismatch; expected {expected}, got {raw_value!r}"
            ),
            strict=True,
            remediation=remediation_hint,
        )
        return resolved

    log_file = resolve_required_path_field(
        "log_file",
        expected=expected_log_path,
        remediation_hint="Write log_file path directly from the per-suite/per-target log path variable.",
    )
    if log_file is not None:
        require_condition(
            f"{check_prefix}:result.log_file_exists",
            path=log_file,
            ok=log_file.exists(),
            ok_msg="referenced log file exists",
            fail_msg=f"missing log file {log_file}",
            strict=True,
            remediation="Ensure cargo test output is tee'd into the declared log_file path.",
        )
        validate_file_budget(
            check_id=f"{check_prefix}:result.log_file_budget",
            path=log_file,
            max_bytes=MAX_OUTPUT_LOG_BYTES,
            strict=True,
            remediation=(
                "Reduce output.log verbosity or split suite execution when logs exceed budget."
            ),
        )
        validate_text_redaction(
            check_id=f"{check_prefix}:result.log_file_redaction",
            path=log_file,
            strict=True,
        )

    test_log_jsonl_path = resolve_required_path_field(
        "test_log_jsonl",
        expected=expected_test_log_path,
        remediation_hint=(
            "Set TEST_LOG_JSONL_PATH to the suite/target-local path before running cargo test."
        ),
    )
    artifact_index_jsonl_path = resolve_required_path_field(
        "artifact_index_jsonl",
        expected=expected_artifact_index_path,
        remediation_hint=(
            "Set TEST_ARTIFACT_INDEX_PATH to the suite/target-local path before running cargo test."
        ),
    )

    if test_log_jsonl_path is None:
        return
    if artifact_index_jsonl_path is None:
        return

    validate_file_budget(
        check_id=f"{check_prefix}.test_log_jsonl.file_budget",
        path=test_log_jsonl_path,
        max_bytes=MAX_TEST_LOG_JSONL_BYTES,
        strict=True,
        remediation=(
            "Reduce test-log emission volume or shard runs to keep per-suite/target JSONL within budget."
        ),
    )
    validate_file_budget(
        check_id=f"{check_prefix}.artifact_index_jsonl.file_budget",
        path=artifact_index_jsonl_path,
        max_bytes=MAX_ARTIFACT_INDEX_JSONL_BYTES,
        strict=True,
        remediation=(
            "Reduce artifact-index emission volume or trim duplicate artifact writes."
        ),
    )
    validate_text_redaction(
        check_id=f"{check_prefix}.test_log_jsonl.redaction_scan",
        path=test_log_jsonl_path,
        strict=True,
    )
    validate_text_redaction(
        check_id=f"{check_prefix}.artifact_index_jsonl.redaction_scan",
        path=artifact_index_jsonl_path,
        strict=True,
    )

    trace_ids_by_test = parse_test_log_jsonl(check_prefix, test_log_jsonl_path)
    parse_artifact_index_jsonl(check_prefix, artifact_index_jsonl_path, trace_ids_by_test)

    normalized_test_log = normalized_jsonl_path(test_log_jsonl_path)
    normalized_artifact_index = normalized_jsonl_path(artifact_index_jsonl_path)
    validate_file_budget(
        check_id=f"{check_prefix}.test_log_jsonl.normalized_file_budget",
        path=normalized_test_log,
        max_bytes=MAX_TEST_LOG_JSONL_BYTES,
        strict=True,
        remediation=(
            "Ensure normalized test-log output remains bounded and does not duplicate excessive payload."
        ),
    )
    validate_file_budget(
        check_id=f"{check_prefix}.artifact_index_jsonl.normalized_file_budget",
        path=normalized_artifact_index,
        max_bytes=MAX_ARTIFACT_INDEX_JSONL_BYTES,
        strict=True,
        remediation=(
            "Ensure normalized artifact-index output remains bounded and deterministic."
        ),
    )
    validate_normalized_jsonl_pair(
        check_prefix=f"{check_prefix}.test_log_jsonl.normalized_contract",
        raw_path=test_log_jsonl_path,
        normalized_path=normalized_test_log,
        allowed_schemas=set(LOG_REQUIRED_FIELDS.keys()) | {"pi.test.artifact.v1"},
        enforce_path_placeholder=False,
    )
    validate_normalized_jsonl_pair(
        check_prefix=f"{check_prefix}.artifact_index_jsonl.normalized_contract",
        raw_path=artifact_index_jsonl_path,
        normalized_path=normalized_artifact_index,
        allowed_schemas={"pi.test.artifact.v1"},
        enforce_path_placeholder=True,
    )


def validate_failure_timeline_file(
    *,
    check_prefix: str,
    timeline_path: Path,
    suite_name: str,
    require_non_empty: bool,
) -> list[dict]:
    lines = read_jsonl_lines(f"{check_prefix}.timeline_jsonl", timeline_path, strict=True)
    require_condition(
        f"{check_prefix}.timeline_jsonl.non_empty",
        path=timeline_path,
        ok=(len(lines) > 0) if require_non_empty else True,
        ok_msg=f"timeline has {len(lines)} entries",
        fail_msg="timeline JSONL is empty",
        strict=True,
        remediation="Emit structured failure timeline events into failure_timeline.jsonl.",
    )
    records: list[dict] = []
    for line_no, line in lines:
        record_id = f"{check_prefix}.timeline_jsonl.line_{line_no}"
        try:
            payload = json.loads(line)
        except Exception as exc:  # pragma: no cover - defensive
            add_check(record_id, timeline_path, False, f"invalid JSON: {exc}")
            record_issue(
                record_id,
                f"invalid JSON: {exc}",
                strict=True,
                remediation="Write valid JSON objects per line in failure_timeline.jsonl.",
            )
            continue
        if not isinstance(payload, dict):
            add_check(record_id, timeline_path, False, "record must be an object")
            record_issue(
                record_id,
                "record must be an object",
                strict=True,
                remediation="Write object records (not arrays/scalars) in failure_timeline.jsonl.",
            )
            continue
        require_condition(
            f"{record_id}.schema",
            path=timeline_path,
            ok=payload.get("schema") == "pi.e2e.failure_timeline_event.v1",
            ok_msg="timeline schema matches",
            fail_msg=f"unexpected timeline schema {payload.get('schema')!r}",
            strict=True,
            remediation="Emit schema pi.e2e.failure_timeline_event.v1 for timeline events.",
        )
        require_condition(
            f"{record_id}.correlation_matches_summary",
            path=timeline_path,
            ok=str(payload.get("correlation_id", "")).strip() == summary_correlation_id,
            ok_msg="timeline correlation_id matches summary",
            fail_msg=(
                "timeline correlation_id mismatch: "
                f"expected {summary_correlation_id!r}, got {payload.get('correlation_id')!r}"
            ),
            strict=True,
            remediation="Propagate summary correlation_id into every timeline event.",
        )
        require_condition(
            f"{record_id}.suite_matches",
            path=timeline_path,
            ok=str(payload.get("suite", "")).strip() == suite_name,
            ok_msg="timeline suite matches expected suite",
            fail_msg=(
                f"timeline suite mismatch: expected {suite_name!r}, got {payload.get('suite')!r}"
            ),
            strict=True,
            remediation="Emit the suite identifier on every timeline event.",
        )
        require_condition(
            f"{record_id}.event_type_present",
            path=timeline_path,
            ok=bool(str(payload.get("event_type", "")).strip()),
            ok_msg="event_type present",
            fail_msg="timeline event missing event_type",
            strict=True,
            remediation="Set event_type for every timeline record.",
        )
        records.append(payload)
    return records

for target in selected_units:
    validate_result_contract(
        kind="unit",
        name=target,
        result_path=artifact_dir / "unit" / target / "result.json",
        expected_log_path=artifact_dir / "unit" / target / "output.log",
        expected_test_log_path=artifact_dir / "unit" / target / "test-log.jsonl",
        expected_artifact_index_path=artifact_dir / "unit" / target / "artifact-index.jsonl",
    )

for suite in selected_suites:
    validate_result_contract(
        kind="suite",
        name=suite,
        result_path=artifact_dir / suite / "result.json",
        expected_log_path=artifact_dir / suite / "output.log",
        expected_test_log_path=artifact_dir / suite / "test-log.jsonl",
        expected_artifact_index_path=artifact_dir / suite / "artifact-index.jsonl",
    )


# 1b) Failure diagnostics artifacts (bd-1f42.8.6.4)
failed_suite_names: list[str] = []
if isinstance(summary, dict):
    suites_payload = summary.get("suites")
    if isinstance(suites_payload, list):
        for suite_payload in suites_payload:
            if not isinstance(suite_payload, dict):
                continue
            suite_name = str(suite_payload.get("suite", "")).strip()
            if not suite_name:
                continue
            try:
                suite_exit_code = int(suite_payload.get("exit_code"))
            except (TypeError, ValueError):
                suite_exit_code = 1
            if suite_exit_code != 0:
                failed_suite_names.append(suite_name)
failed_suite_names = sorted(set(failed_suite_names))

if isinstance(summary, dict):
    require_condition(
        "summary.failed_suites_matches_suite_results",
        path=summary_path,
        ok=int(summary.get("failed_suites") or 0) == len(failed_suite_names),
        ok_msg="summary.failed_suites matches suite result entries",
        fail_msg=(
            "summary.failed_suites mismatch: "
            f"expected {len(failed_suite_names)}, got {summary.get('failed_suites')!r}"
        ),
        strict=True,
        remediation="Compute failed_suites directly from suite result exit_code values in write_summary().",
    )

failure_meta = summary.get("failure_diagnostics") if isinstance(summary, dict) else None
require_condition(
    "summary.failure_diagnostics_object",
    path=summary_path,
    ok=isinstance(failure_meta, dict),
    ok_msg="summary includes failure_diagnostics metadata",
    fail_msg="summary missing failure_diagnostics metadata",
    strict=True,
    remediation="Run generate_failure_diagnostics() after write_summary().",
)

failure_meta_suites_by_name: dict[str, dict] = {}
expected_failure_index_path = artifact_dir / "failure_diagnostics_index.json"
expected_run_timeline_path = artifact_dir / "failure_timeline.jsonl"
if isinstance(failure_meta, dict):
    require_keys(
        "failure_diagnostics.summary_meta",
        failure_meta,
        summary_path,
        [
            "schema",
            "correlation_id",
            "index_path",
            "run_timeline_path",
            "failed_suite_count",
            "suites",
        ],
        strict=True,
    )
    require_condition(
        "failure_diagnostics.summary_meta.schema",
        path=summary_path,
        ok=failure_meta.get("schema") == "pi.e2e.failure_diagnostics.v1",
        ok_msg="failure diagnostics summary schema matches",
        fail_msg=(
            "expected summary.failure_diagnostics.schema 'pi.e2e.failure_diagnostics.v1', got "
            f"{failure_meta.get('schema')!r}"
        ),
        strict=True,
        remediation="Emit schema pi.e2e.failure_diagnostics.v1 in summary failure_diagnostics metadata.",
    )
    require_condition(
        "failure_diagnostics.summary_meta.correlation_id_matches",
        path=summary_path,
        ok=str(failure_meta.get("correlation_id", "")).strip() == summary_correlation_id,
        ok_msg="failure diagnostics summary correlation_id matches run correlation",
        fail_msg=(
            "summary.failure_diagnostics correlation_id mismatch: "
            f"expected {summary_correlation_id!r}, got {failure_meta.get('correlation_id')!r}"
        ),
        strict=True,
        remediation="Propagate summary correlation_id into summary.failure_diagnostics metadata.",
    )
    require_condition(
        "failure_diagnostics.summary_meta.index_path_matches",
        path=summary_path,
        ok=path_matches(failure_meta.get("index_path"), expected_failure_index_path),
        ok_msg="failure diagnostics index path matches expected artifact path",
        fail_msg=(
            "summary.failure_diagnostics.index_path does not match "
            f"{expected_failure_index_path}"
        ),
        strict=True,
        remediation="Set summary.failure_diagnostics.index_path from failure_diagnostics_index.json artifact path.",
    )
    require_condition(
        "failure_diagnostics.summary_meta.run_timeline_path_matches",
        path=summary_path,
        ok=path_matches(failure_meta.get("run_timeline_path"), expected_run_timeline_path),
        ok_msg="failure diagnostics run timeline path matches expected artifact path",
        fail_msg=(
            "summary.failure_diagnostics.run_timeline_path does not match "
            f"{expected_run_timeline_path}"
        ),
        strict=True,
        remediation="Set summary.failure_diagnostics.run_timeline_path from failure_timeline.jsonl path.",
    )
    require_condition(
        "failure_diagnostics.summary_meta.failed_suite_count",
        path=summary_path,
        ok=int(failure_meta.get("failed_suite_count") or 0) == len(failed_suite_names),
        ok_msg="failure diagnostics failed_suite_count matches failed suites",
        fail_msg=(
            "summary.failure_diagnostics.failed_suite_count mismatch: "
            f"expected {len(failed_suite_names)}, got {failure_meta.get('failed_suite_count')!r}"
        ),
        strict=True,
        remediation="Set failure_diagnostics.failed_suite_count from failed suite result count.",
    )
    suites_meta_payload = failure_meta.get("suites")
    require_condition(
        "failure_diagnostics.summary_meta.suites_array",
        path=summary_path,
        ok=isinstance(suites_meta_payload, list),
        ok_msg="summary failure diagnostics suites is an array",
        fail_msg="summary failure diagnostics suites must be an array",
        strict=True,
        remediation="Emit summary.failure_diagnostics.suites as a list of suite entries.",
    )
    if isinstance(suites_meta_payload, list):
        seen_suite_meta: set[str] = set()
        for index, suite_payload in enumerate(suites_meta_payload):
            check_prefix = f"failure_diagnostics.summary_meta.suites[{index}]"
            require_condition(
                f"{check_prefix}.object",
                path=summary_path,
                ok=isinstance(suite_payload, dict),
                ok_msg="suite diagnostics entry is object",
                fail_msg="suite diagnostics entry must be an object",
                strict=True,
            )
            if not isinstance(suite_payload, dict):
                continue
            require_keys(
                check_prefix,
                suite_payload,
                summary_path,
                [
                    "suite",
                    "digest_path",
                    "timeline_path",
                    "root_cause_class",
                    "impacted_scenario_ids",
                    "first_failing_assertion",
                ],
                strict=True,
            )
            suite_name = str(suite_payload.get("suite", "")).strip()
            require_condition(
                f"{check_prefix}.suite_nonempty",
                path=summary_path,
                ok=bool(suite_name),
                ok_msg="suite identifier is non-empty",
                fail_msg="suite identifier is missing/empty",
                strict=True,
            )
            if not suite_name:
                continue
            require_condition(
                f"{check_prefix}.suite_unique",
                path=summary_path,
                ok=suite_name not in seen_suite_meta,
                ok_msg=f"suite {suite_name} appears once",
                fail_msg=f"duplicate suite diagnostics entry for {suite_name}",
                strict=True,
            )
            seen_suite_meta.add(suite_name)
            failure_meta_suites_by_name[suite_name] = suite_payload
            expected_digest_path = artifact_dir / suite_name / "failure_digest.json"
            expected_timeline_path = artifact_dir / suite_name / "failure_timeline.jsonl"
            require_condition(
                f"{check_prefix}.digest_path_matches",
                path=summary_path,
                ok=path_matches(suite_payload.get("digest_path"), expected_digest_path),
                ok_msg="digest_path matches expected suite digest artifact",
                fail_msg=(
                    f"digest_path mismatch for suite {suite_name}: expected {expected_digest_path}"
                ),
                strict=True,
                remediation="Emit digest_path as <artifact_dir>/<suite>/failure_digest.json.",
            )
            require_condition(
                f"{check_prefix}.timeline_path_matches",
                path=summary_path,
                ok=path_matches(suite_payload.get("timeline_path"), expected_timeline_path),
                ok_msg="timeline_path matches expected suite timeline artifact",
                fail_msg=(
                    f"timeline_path mismatch for suite {suite_name}: expected {expected_timeline_path}"
                ),
                strict=True,
                remediation="Emit timeline_path as <artifact_dir>/<suite>/failure_timeline.jsonl.",
            )
            impacted = suite_payload.get("impacted_scenario_ids")
            require_condition(
                f"{check_prefix}.impacted_scenario_ids_non_empty",
                path=summary_path,
                ok=isinstance(impacted, list) and len(impacted) > 0,
                ok_msg="impacted_scenario_ids present with at least one scenario id",
                fail_msg=f"impacted_scenario_ids missing/empty for suite {suite_name}",
                strict=suite_name in failed_suite_names,
                remediation="Populate impacted_scenario_ids with failing test/scenario identifiers.",
            )

require_condition(
    "failure_diagnostics.summary_meta.covers_failed_suites",
    path=summary_path,
    ok=sorted(failure_meta_suites_by_name.keys()) == failed_suite_names,
    ok_msg="summary failure diagnostics entries cover all failed suites",
    fail_msg=(
        "summary failure diagnostics entries do not match failed suites: "
        f"expected {failed_suite_names}, got {sorted(failure_meta_suites_by_name.keys())}"
    ),
    strict=True,
    remediation="Emit one summary.failure_diagnostics.suites entry per failed suite.",
)

failure_index_payload = load_json(
    "failure_diagnostics.index_json",
    expected_failure_index_path,
    strict=True,
)
require_keys(
    "failure_diagnostics.index_json",
    failure_index_payload,
    expected_failure_index_path,
    [
        "schema",
        "generated_at",
        "correlation_id",
        "artifact_dir",
        "failed_suite_count",
        "suites",
        "run_timeline_path",
    ],
    strict=True,
)

index_suites_by_name: dict[str, dict] = {}
if isinstance(failure_index_payload, dict):
    require_condition(
        "failure_diagnostics.index_json.schema",
        path=expected_failure_index_path,
        ok=failure_index_payload.get("schema") == "pi.e2e.failure_diagnostics_index.v1",
        ok_msg="failure diagnostics index schema matches",
        fail_msg=(
            "expected failure diagnostics index schema 'pi.e2e.failure_diagnostics_index.v1', got "
            f"{failure_index_payload.get('schema')!r}"
        ),
        strict=True,
        remediation="Emit schema pi.e2e.failure_diagnostics_index.v1 in failure_diagnostics_index.json.",
    )
    require_condition(
        "failure_diagnostics.index_json.correlation_matches_summary",
        path=expected_failure_index_path,
        ok=str(failure_index_payload.get("correlation_id", "")).strip() == summary_correlation_id,
        ok_msg="failure diagnostics index correlation_id matches summary",
        fail_msg=(
            "failure diagnostics index correlation_id mismatch: "
            f"expected {summary_correlation_id!r}, got {failure_index_payload.get('correlation_id')!r}"
        ),
        strict=True,
        remediation="Propagate summary correlation_id into failure_diagnostics_index.json.",
    )
    require_condition(
        "failure_diagnostics.index_json.artifact_dir_matches",
        path=expected_failure_index_path,
        ok=path_matches(failure_index_payload.get("artifact_dir"), artifact_dir),
        ok_msg="failure diagnostics index artifact_dir matches run artifact directory",
        fail_msg=(
            "failure diagnostics index artifact_dir mismatch: "
            f"expected {artifact_dir}, got {failure_index_payload.get('artifact_dir')!r}"
        ),
        strict=True,
        remediation="Write artifact_dir in failure_diagnostics_index.json from ARTIFACT_DIR.",
    )
    require_condition(
        "failure_diagnostics.index_json.failed_suite_count",
        path=expected_failure_index_path,
        ok=int(failure_index_payload.get("failed_suite_count") or 0) == len(failed_suite_names),
        ok_msg="failure diagnostics index failed_suite_count matches failed suites",
        fail_msg=(
            "failure diagnostics index failed_suite_count mismatch: "
            f"expected {len(failed_suite_names)}, got {failure_index_payload.get('failed_suite_count')!r}"
        ),
        strict=True,
        remediation="Set failed_suite_count in failure_diagnostics_index.json from failed suite result count.",
    )
    require_condition(
        "failure_diagnostics.index_json.run_timeline_path_matches",
        path=expected_failure_index_path,
        ok=path_matches(failure_index_payload.get("run_timeline_path"), expected_run_timeline_path),
        ok_msg="failure diagnostics index run_timeline_path matches expected path",
        fail_msg=(
            "failure diagnostics index run_timeline_path mismatch: "
            f"expected {expected_run_timeline_path}, got {failure_index_payload.get('run_timeline_path')!r}"
        ),
        strict=True,
        remediation="Set run_timeline_path in failure_diagnostics_index.json from failure_timeline.jsonl.",
    )
    index_suites_payload = failure_index_payload.get("suites")
    require_condition(
        "failure_diagnostics.index_json.suites_array",
        path=expected_failure_index_path,
        ok=isinstance(index_suites_payload, list),
        ok_msg="failure diagnostics index suites is an array",
        fail_msg="failure diagnostics index suites must be an array",
        strict=True,
    )
    if isinstance(index_suites_payload, list):
        seen_index_suites: set[str] = set()
        for index, suite_payload in enumerate(index_suites_payload):
            check_prefix = f"failure_diagnostics.index_json.suites[{index}]"
            require_condition(
                f"{check_prefix}.object",
                path=expected_failure_index_path,
                ok=isinstance(suite_payload, dict),
                ok_msg="index suite entry is object",
                fail_msg="index suite entry must be an object",
                strict=True,
            )
            if not isinstance(suite_payload, dict):
                continue
            require_keys(
                check_prefix,
                suite_payload,
                expected_failure_index_path,
                [
                    "suite",
                    "digest_path",
                    "timeline_path",
                    "root_cause_class",
                    "impacted_scenario_ids",
                    "first_failing_assertion",
                ],
                strict=True,
            )
            suite_name = str(suite_payload.get("suite", "")).strip()
            require_condition(
                f"{check_prefix}.suite_nonempty",
                path=expected_failure_index_path,
                ok=bool(suite_name),
                ok_msg="suite identifier is non-empty",
                fail_msg="suite identifier missing/empty",
                strict=True,
            )
            if not suite_name:
                continue
            require_condition(
                f"{check_prefix}.suite_unique",
                path=expected_failure_index_path,
                ok=suite_name not in seen_index_suites,
                ok_msg=f"suite {suite_name} appears once in index",
                fail_msg=f"duplicate suite entry in index for {suite_name}",
                strict=True,
            )
            seen_index_suites.add(suite_name)
            index_suites_by_name[suite_name] = suite_payload

require_condition(
    "failure_diagnostics.index_json.covers_failed_suites",
    path=expected_failure_index_path,
    ok=sorted(index_suites_by_name.keys()) == failed_suite_names,
    ok_msg="failure diagnostics index covers all failed suites",
    fail_msg=(
        "failure diagnostics index suites do not match failed suites: "
        f"expected {failed_suite_names}, got {sorted(index_suites_by_name.keys())}"
    ),
    strict=True,
)

run_timeline_lines = read_jsonl_lines(
    "failure_diagnostics.run.timeline_jsonl",
    expected_run_timeline_path,
    strict=True,
)
require_condition(
    "failure_diagnostics.run.timeline_jsonl.non_empty",
    path=expected_run_timeline_path,
    ok=len(run_timeline_lines) > 0,
    ok_msg=f"run timeline has {len(run_timeline_lines)} entries",
    fail_msg="run timeline JSONL is empty",
    strict=True,
    remediation="Emit run-level failure timeline events in failure_timeline.jsonl.",
)
for line_no, line in run_timeline_lines:
    record_id = f"failure_diagnostics.run.timeline_jsonl.line_{line_no}"
    try:
        payload = json.loads(line)
    except Exception as exc:  # pragma: no cover - defensive
        add_check(record_id, expected_run_timeline_path, False, f"invalid JSON: {exc}")
        record_issue(
            record_id,
            f"invalid JSON: {exc}",
            strict=True,
            remediation="Write valid JSON records in run failure_timeline.jsonl.",
        )
        continue
    if not isinstance(payload, dict):
        add_check(record_id, expected_run_timeline_path, False, "record must be an object")
        record_issue(
            record_id,
            "record must be an object",
            strict=True,
            remediation="Write object records in run failure_timeline.jsonl.",
        )
        continue
    require_condition(
        f"{record_id}.schema",
        path=expected_run_timeline_path,
        ok=payload.get("schema") == "pi.e2e.failure_timeline_event.v1",
        ok_msg="run timeline schema matches",
        fail_msg=f"unexpected run timeline schema {payload.get('schema')!r}",
        strict=True,
    )
    require_condition(
        f"{record_id}.correlation_matches_summary",
        path=expected_run_timeline_path,
        ok=str(payload.get("correlation_id", "")).strip() == summary_correlation_id,
        ok_msg="run timeline correlation_id matches summary",
        fail_msg=(
            "run timeline correlation_id mismatch: "
            f"expected {summary_correlation_id!r}, got {payload.get('correlation_id')!r}"
        ),
        strict=True,
    )
    require_condition(
        f"{record_id}.suite_present",
        path=expected_run_timeline_path,
        ok=bool(str(payload.get("suite", "")).strip()),
        ok_msg="run timeline event has suite field",
        fail_msg="run timeline event missing suite field",
        strict=True,
    )

for suite_name in failed_suite_names:
    suite_prefix = f"failure_diagnostics.{suite_name}"
    expected_digest_path = artifact_dir / suite_name / "failure_digest.json"
    expected_timeline_path = artifact_dir / suite_name / "failure_timeline.jsonl"

    meta_entry = failure_meta_suites_by_name.get(suite_name)
    require_condition(
        f"{suite_prefix}.summary_meta_present",
        path=summary_path,
        ok=isinstance(meta_entry, dict),
        ok_msg=f"summary metadata entry exists for {suite_name}",
        fail_msg=f"summary missing failure diagnostics entry for suite {suite_name}",
        strict=True,
    )
    if isinstance(meta_entry, dict):
        require_condition(
            f"{suite_prefix}.summary_meta.digest_path_matches",
            path=summary_path,
            ok=path_matches(meta_entry.get("digest_path"), expected_digest_path),
            ok_msg="summary metadata digest_path matches expected suite digest path",
            fail_msg=f"summary metadata digest_path mismatch for suite {suite_name}",
            strict=True,
        )
        require_condition(
            f"{suite_prefix}.summary_meta.timeline_path_matches",
            path=summary_path,
            ok=path_matches(meta_entry.get("timeline_path"), expected_timeline_path),
            ok_msg="summary metadata timeline_path matches expected suite timeline path",
            fail_msg=f"summary metadata timeline_path mismatch for suite {suite_name}",
            strict=True,
        )

    index_entry = index_suites_by_name.get(suite_name)
    require_condition(
        f"{suite_prefix}.index_entry_present",
        path=expected_failure_index_path,
        ok=isinstance(index_entry, dict),
        ok_msg=f"index entry exists for {suite_name}",
        fail_msg=f"failure diagnostics index missing suite entry for {suite_name}",
        strict=True,
    )
    if isinstance(index_entry, dict):
        require_condition(
            f"{suite_prefix}.index_entry.digest_path_matches",
            path=expected_failure_index_path,
            ok=path_matches(index_entry.get("digest_path"), expected_digest_path),
            ok_msg="index digest_path matches expected suite digest path",
            fail_msg=f"index digest_path mismatch for suite {suite_name}",
            strict=True,
        )
        require_condition(
            f"{suite_prefix}.index_entry.timeline_path_matches",
            path=expected_failure_index_path,
            ok=path_matches(index_entry.get("timeline_path"), expected_timeline_path),
            ok_msg="index timeline_path matches expected suite timeline path",
            fail_msg=f"index timeline_path mismatch for suite {suite_name}",
            strict=True,
        )

    digest_payload = load_json(
        f"{suite_prefix}.digest_json",
        expected_digest_path,
        strict=True,
    )
    require_keys(
        f"{suite_prefix}.digest_json",
        digest_payload,
        expected_digest_path,
        [
            "schema",
            "generated_at",
            "correlation_id",
            "suite",
            "exit_code",
            "root_cause_class",
            "impacted_scenario_ids",
            "first_failing_assertion",
            "remediation_pointer",
            "artifact_paths",
            "timeline",
        ],
        strict=True,
    )
    if isinstance(digest_payload, dict):
        require_condition(
            f"{suite_prefix}.digest_json.schema",
            path=expected_digest_path,
            ok=digest_payload.get("schema") == "pi.e2e.failure_digest.v1",
            ok_msg="failure digest schema matches",
            fail_msg=f"unexpected failure digest schema {digest_payload.get('schema')!r}",
            strict=True,
            remediation="Emit schema pi.e2e.failure_digest.v1 in failure_digest.json.",
        )
        require_condition(
            f"{suite_prefix}.digest_json.correlation_matches_summary",
            path=expected_digest_path,
            ok=str(digest_payload.get("correlation_id", "")).strip() == summary_correlation_id,
            ok_msg="failure digest correlation_id matches summary",
            fail_msg=(
                "failure digest correlation_id mismatch: "
                f"expected {summary_correlation_id!r}, got {digest_payload.get('correlation_id')!r}"
            ),
            strict=True,
            remediation="Propagate summary correlation_id into failure_digest.json.",
        )
        require_condition(
            f"{suite_prefix}.digest_json.suite_matches",
            path=expected_digest_path,
            ok=str(digest_payload.get("suite", "")).strip() == suite_name,
            ok_msg="failure digest suite matches expected suite",
            fail_msg=(
                f"failure digest suite mismatch: expected {suite_name!r}, got {digest_payload.get('suite')!r}"
            ),
            strict=True,
            remediation="Emit suite identifier in failure_digest.json from failing suite name.",
        )
        impacted = digest_payload.get("impacted_scenario_ids")
        require_condition(
            f"{suite_prefix}.digest_json.impacted_scenario_ids_non_empty",
            path=expected_digest_path,
            ok=isinstance(impacted, list) and len(impacted) > 0,
            ok_msg="impacted_scenario_ids contains at least one scenario id",
            fail_msg="failure digest impacted_scenario_ids missing/empty",
            strict=True,
            remediation="Populate impacted_scenario_ids from failing tests listed in output.log.",
        )
        first_assertion = digest_payload.get("first_failing_assertion")
        require_condition(
            f"{suite_prefix}.digest_json.first_failing_assertion_object",
            path=expected_digest_path,
            ok=isinstance(first_assertion, dict),
            ok_msg="first_failing_assertion is an object",
            fail_msg="first_failing_assertion missing or invalid",
            strict=True,
            remediation="Emit first_failing_assertion object with test, location, and message.",
        )
        if isinstance(first_assertion, dict):
            require_condition(
                f"{suite_prefix}.digest_json.first_failing_assertion.test",
                path=expected_digest_path,
                ok=bool(str(first_assertion.get("test", "")).strip()),
                ok_msg="first_failing_assertion.test is present",
                fail_msg="first_failing_assertion.test missing/empty",
                strict=True,
                remediation="Set first_failing_assertion.test from first failing test id.",
            )
            require_condition(
                f"{suite_prefix}.digest_json.first_failing_assertion.message",
                path=expected_digest_path,
                ok=bool(str(first_assertion.get("message", "")).strip()),
                ok_msg="first_failing_assertion.message is present",
                fail_msg="first_failing_assertion.message missing/empty",
                strict=True,
                remediation="Set first_failing_assertion.message from first panic/assertion message.",
            )
            location_payload = first_assertion.get("location")
            require_condition(
                f"{suite_prefix}.digest_json.first_failing_assertion.location_object",
                path=expected_digest_path,
                ok=isinstance(location_payload, dict),
                ok_msg="first_failing_assertion.location is an object",
                fail_msg="first_failing_assertion.location missing/invalid",
                strict=True,
                remediation="Emit location object with file/line/column for first failing assertion.",
            )
            if isinstance(location_payload, dict):
                for field in ("file", "line", "column"):
                    require_condition(
                        f"{suite_prefix}.digest_json.first_failing_assertion.location.{field}",
                        path=expected_digest_path,
                        ok=field in location_payload,
                        ok_msg=f"location.{field} present",
                        fail_msg=f"missing location.{field}",
                        strict=True,
                    )

        remediation_pointer = digest_payload.get("remediation_pointer")
        require_condition(
            f"{suite_prefix}.digest_json.remediation_pointer_object",
            path=expected_digest_path,
            ok=isinstance(remediation_pointer, dict),
            ok_msg="remediation_pointer is an object",
            fail_msg="remediation_pointer missing or invalid",
            strict=True,
            remediation="Emit remediation_pointer with replay command pointers.",
        )
        if isinstance(remediation_pointer, dict):
            for field in (
                "class",
                "summary",
                "replay_command",
                "suite_replay_command",
                "targeted_test_replay_command",
            ):
                require_condition(
                    f"{suite_prefix}.digest_json.remediation_pointer.{field}",
                    path=expected_digest_path,
                    ok=field in remediation_pointer,
                    ok_msg=f"remediation_pointer.{field} present",
                    fail_msg=f"missing remediation_pointer.{field}",
                    strict=True,
                )

        artifact_paths = digest_payload.get("artifact_paths")
        require_condition(
            f"{suite_prefix}.digest_json.artifact_paths_object",
            path=expected_digest_path,
            ok=isinstance(artifact_paths, dict),
            ok_msg="artifact_paths is an object",
            fail_msg="artifact_paths missing or invalid",
            strict=True,
            remediation="Emit artifact_paths object in failure_digest.json.",
        )
        if isinstance(artifact_paths, dict):
            for field in (
                "result_json",
                "output_log",
                "test_log_jsonl",
                "artifact_index_jsonl",
                "timeline_jsonl",
                "runner_summary_json",
            ):
                require_condition(
                    f"{suite_prefix}.digest_json.artifact_paths.{field}",
                    path=expected_digest_path,
                    ok=field in artifact_paths,
                    ok_msg=f"artifact_paths.{field} present",
                    fail_msg=f"missing artifact_paths.{field}",
                    strict=True,
                )
            require_condition(
                f"{suite_prefix}.digest_json.artifact_paths.timeline_path_matches",
                path=expected_digest_path,
                ok=path_matches(artifact_paths.get("timeline_jsonl"), expected_timeline_path),
                ok_msg="artifact_paths.timeline_jsonl matches suite timeline path",
                fail_msg="artifact_paths.timeline_jsonl does not match expected suite timeline path",
                strict=True,
                remediation="Set artifact_paths.timeline_jsonl to <artifact_dir>/<suite>/failure_timeline.jsonl.",
            )

        timeline_meta = digest_payload.get("timeline")
        require_condition(
            f"{suite_prefix}.digest_json.timeline_object",
            path=expected_digest_path,
            ok=isinstance(timeline_meta, dict),
            ok_msg="timeline metadata object exists",
            fail_msg="timeline metadata missing or invalid",
            strict=True,
            remediation="Emit timeline metadata with schema/path/event_count in failure_digest.json.",
        )
        if isinstance(timeline_meta, dict):
            require_condition(
                f"{suite_prefix}.digest_json.timeline.schema",
                path=expected_digest_path,
                ok=timeline_meta.get("schema") == "pi.e2e.failure_timeline_event.v1",
                ok_msg="timeline metadata schema matches",
                fail_msg=(
                    "timeline metadata schema mismatch: expected "
                    "'pi.e2e.failure_timeline_event.v1'"
                ),
                strict=True,
            )
            require_condition(
                f"{suite_prefix}.digest_json.timeline.path_matches",
                path=expected_digest_path,
                ok=path_matches(timeline_meta.get("path"), expected_timeline_path),
                ok_msg="timeline metadata path matches suite timeline path",
                fail_msg="timeline metadata path does not match expected suite timeline path",
                strict=True,
                remediation="Set timeline.path in failure_digest.json from suite timeline artifact path.",
            )

        timeline_records = validate_failure_timeline_file(
            check_prefix=suite_prefix,
            timeline_path=expected_timeline_path,
            suite_name=suite_name,
            require_non_empty=True,
        )
        if isinstance(timeline_meta, dict):
            event_count_value = timeline_meta.get("event_count")
            require_condition(
                f"{suite_prefix}.digest_json.timeline.event_count_matches",
                path=expected_digest_path,
                ok=isinstance(event_count_value, int) and event_count_value == len(timeline_records),
                ok_msg="timeline metadata event_count matches timeline record count",
                fail_msg=(
                    "timeline metadata event_count mismatch: "
                    f"expected {len(timeline_records)}, got {event_count_value!r}"
                ),
                strict=True,
                remediation="Set timeline.event_count to the number of emitted timeline JSONL records.",
            )


# 2) Conformance evidence artifacts (strict for full baseline profile)
reports_dir = project_root / "tests" / "ext_conformance" / "reports"
events_path = reports_dir / "conformance_events.jsonl"
summary_report_path = reports_dir / "conformance_summary.json"
markdown_path = reports_dir / "CONFORMANCE_REPORT.md"

events_exists = require_file(
    "conformance.events_jsonl",
    events_path,
    strict=strict_conformance,
    description="per-extension JSONL evidence log exists",
)
summary_report = load_json(
    "conformance.summary_json",
    summary_report_path,
    strict=strict_conformance,
)
require_keys(
    "conformance.summary_json",
    summary_report,
    summary_report_path,
    ["schema", "generated_at", "counts", "pass_rate_pct", "evidence"],
    strict=strict_conformance,
)

if isinstance(summary_report, dict):
    evidence_payload = summary_report.get("evidence")
    require_condition(
        "conformance.summary_json.evidence_object",
        path=summary_report_path,
        ok=isinstance(evidence_payload, dict),
        ok_msg="evidence payload is an object",
        fail_msg="missing or invalid evidence object",
        strict=strict_conformance,
    )
    if isinstance(evidence_payload, dict):
        missing_evidence_keys = sorted(
            set(["golden_fixtures", "load_time_benchmarks", "parity_logs", "smoke_logs"]) -
            set(evidence_payload.keys())
        )
        require_condition(
            "conformance.summary_json.evidence_keys",
            path=summary_report_path,
            ok=not missing_evidence_keys,
            ok_msg="evidence payload includes required keys",
            fail_msg=f"missing evidence keys: {missing_evidence_keys}",
            strict=strict_conformance,
        )

    schema = summary_report.get("schema")
    schema_ok = schema == "pi.ext.conformance_summary.v2"
    add_check(
        "conformance.summary_schema",
        summary_report_path,
        schema_ok,
        f"schema={schema!r}" if schema_ok else f"unexpected schema {schema!r}",
    )
    if not schema_ok:
        message = (
            f"conformance.summary_schema: expected 'pi.ext.conformance_summary.v2', got {schema!r}"
        )
        if strict_conformance:
            errors.append(message)
        else:
            warnings.append(message)

markdown_exists = require_file(
    "conformance.report_markdown",
    markdown_path,
    strict=strict_conformance,
    description="human-readable conformance report exists",
)
if markdown_exists:
    content = markdown_path.read_text(encoding="utf-8")
    has_index = "## Evidence Index" in content
    add_check(
        "conformance.report_markdown.evidence_index",
        markdown_path,
        has_index,
        "contains Evidence Index section" if has_index else "missing '## Evidence Index'",
    )
    if not has_index:
        message = f"conformance.report_markdown: missing Evidence Index in {markdown_path}"
        if strict_conformance:
            errors.append(message)
        else:
            warnings.append(message)

if events_exists:
    try:
        lines = [line for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:  # pragma: no cover - defensive
        add_check("conformance.events_jsonl.readable", events_path, False, f"read failed: {exc}")
        if strict_conformance:
            errors.append(f"conformance.events_jsonl: read failed ({exc})")
        else:
            warnings.append(f"conformance.events_jsonl: read failed ({exc})")
        lines = []
    if lines:
        add_check("conformance.events_jsonl.non_empty", events_path, True, f"{len(lines)} line(s)")
        first_invalid = None
        for index, line in enumerate(lines, start=1):
            try:
                json.loads(line)
            except Exception as exc:  # pragma: no cover - defensive
                first_invalid = f"line {index}: {exc}"
                break
        require_condition(
            "conformance.events_jsonl.valid_json",
            path=events_path,
            ok=first_invalid is None,
            ok_msg="every JSONL entry parsed successfully",
            fail_msg=f"invalid JSONL entry ({first_invalid})",
            strict=strict_conformance,
        )
    else:
        add_check("conformance.events_jsonl.non_empty", events_path, False, "no JSONL entries found")
        message = f"conformance.events_jsonl: empty file {events_path}"
        if strict_conformance:
            errors.append(message)
        else:
            warnings.append(message)

# 3) Capability-profile matrix evidence (required when conformance events are available)
profile_matrix_path = artifact_dir / "extension_profile_matrix.json"
if not profile_matrix_path.exists() and not strict_conformance:
    add_check(
        "conformance.profile_matrix_json",
        profile_matrix_path,
        True,
        "skipped (conformance events not available in this profile)",
    )
    profile_matrix = None
else:
    profile_matrix = load_json(
        "conformance.profile_matrix_json",
        profile_matrix_path,
        strict=True,
    )
require_keys(
    "conformance.profile_matrix_json",
    profile_matrix,
    profile_matrix_path,
    ["schema", "generated_at", "profiles", "preflight_runtime_consistency"],
    strict=True,
)

if isinstance(profile_matrix, dict):
    schema = profile_matrix.get("schema")
    require_condition(
        "conformance.profile_matrix_schema",
        path=profile_matrix_path,
        ok=schema == "pi.e2e.extension_profile_matrix.v1",
        ok_msg="profile matrix schema matches",
        fail_msg=(
            "expected schema 'pi.e2e.extension_profile_matrix.v1', "
            f"got {schema!r}"
        ),
        strict=True,
    )

    profiles_payload = profile_matrix.get("profiles")
    profiles_ok = isinstance(profiles_payload, dict)
    require_condition(
        "conformance.profile_matrix_profiles_object",
        path=profile_matrix_path,
        ok=profiles_ok,
        ok_msg="profiles object exists",
        fail_msg="profiles must be an object",
        strict=True,
    )

    if profiles_ok:
        required_profiles = ["safe", "balanced", "permissive"]
        missing_profiles = [
            profile_name
            for profile_name in required_profiles
            if profile_name not in profiles_payload
        ]
        require_condition(
            "conformance.profile_matrix_profiles_complete",
            path=profile_matrix_path,
            ok=not missing_profiles,
            ok_msg="safe|balanced|permissive profile entries exist",
            fail_msg=f"missing profile entries: {missing_profiles}",
            strict=True,
        )

        for profile_name in required_profiles:
            profile_entry = profiles_payload.get(profile_name)
            prefix = f"conformance.profile_matrix.{profile_name}"
            require_condition(
                f"{prefix}.object",
                path=profile_matrix_path,
                ok=isinstance(profile_entry, dict),
                ok_msg=f"{profile_name} profile entry is object",
                fail_msg=f"{profile_name} profile entry must be object",
                strict=True,
            )
            if not isinstance(profile_entry, dict):
                continue

            projected = profile_entry.get("projected")
            require_condition(
                f"{prefix}.projected_object",
                path=profile_matrix_path,
                ok=isinstance(projected, dict),
                ok_msg="projected object exists",
                fail_msg="projected must be an object",
                strict=True,
            )

            blocked_summary = profile_entry.get("blocked_operation_summary")
            require_condition(
                f"{prefix}.blocked_summary",
                path=profile_matrix_path,
                ok=isinstance(blocked_summary, dict),
                ok_msg="blocked_operation_summary object exists",
                fail_msg="blocked_operation_summary must be an object",
                strict=True,
            )

            if isinstance(projected, dict):
                for field in (
                    "testable_extensions",
                    "pass",
                    "fail_existing",
                    "blocked",
                    "pass_rate_pct",
                ):
                    require_condition(
                        f"{prefix}.projected.{field}",
                        path=profile_matrix_path,
                        ok=field in projected,
                        ok_msg=f"projected.{field} present",
                        fail_msg=f"missing projected.{field}",
                        strict=True,
                    )

    consistency = profile_matrix.get("preflight_runtime_consistency")
    require_condition(
        "conformance.profile_matrix_consistency_object",
        path=profile_matrix_path,
        ok=isinstance(consistency, dict),
        ok_msg="preflight_runtime_consistency object exists",
        fail_msg="preflight_runtime_consistency must be an object",
        strict=True,
    )
    if isinstance(consistency, dict):
        checked = consistency.get("checked_capability_decisions")
        mismatched = consistency.get("mismatched_capability_decisions")
        require_condition(
            "conformance.profile_matrix_consistency_checked_nonzero",
            path=profile_matrix_path,
            ok=isinstance(checked, int) and checked > 0,
            ok_msg=f"checked_capability_decisions={checked}",
            fail_msg=(
                "checked_capability_decisions must be a positive integer "
                f"(got {checked!r})"
            ),
            strict=True,
        )
        require_condition(
            "conformance.profile_matrix_consistency_no_mismatch",
            path=profile_matrix_path,
            ok=isinstance(mismatched, int) and mismatched == 0,
            ok_msg="preflight/runtime consistency mismatches == 0",
            fail_msg=(
                "preflight/runtime consistency mismatches must be 0 "
                f"(got {mismatched!r})"
            ),
            strict=True,
        )


# 4) Soak/longevity evidence (bd-k5q5.7.10)
soak_report_path = artifact_dir / "soak_longevity_report.json"
soak_report = load_json(
    "conformance.soak_longevity_report_json",
    soak_report_path,
    strict=True,
)
require_keys(
    "conformance.soak_longevity_report_json",
    soak_report,
    soak_report_path,
    [
        "schema",
        "generated_at",
        "status",
        "pass",
        "prerequisites",
        "metrics",
        "thresholds",
        "checks",
        "failed_checks",
    ],
    strict=True,
)

if isinstance(soak_report, dict):
    soak_schema = soak_report.get("schema")
    require_condition(
        "conformance.soak_longevity_report_schema",
        path=soak_report_path,
        ok=soak_schema == "pi.e2e.soak_longevity.v1",
        ok_msg="soak/longevity schema matches",
        fail_msg=(
            "expected schema 'pi.e2e.soak_longevity.v1', "
            f"got {soak_schema!r}"
        ),
        strict=True,
    )

    prerequisites = soak_report.get("prerequisites")
    require_condition(
        "conformance.soak_longevity_prerequisites_object",
        path=soak_report_path,
        ok=isinstance(prerequisites, dict),
        ok_msg="prerequisites object exists",
        fail_msg="prerequisites must be an object",
        strict=True,
    )

    checks_payload = soak_report.get("checks")
    require_condition(
        "conformance.soak_longevity_checks_array",
        path=soak_report_path,
        ok=isinstance(checks_payload, list) and len(checks_payload) > 0,
        ok_msg=f"checks list contains {len(checks_payload) if isinstance(checks_payload, list) else 0} entries",
        fail_msg="checks must be a non-empty array",
        strict=True,
    )

    if strict_conformance and isinstance(prerequisites, dict):
        required_targets_executed = prerequisites.get("required_targets_executed")
        require_condition(
            "conformance.soak_longevity_required_targets_executed",
            path=soak_report_path,
            ok=required_targets_executed is True,
            ok_msg="required stress targets executed in this run",
            fail_msg=(
                "required stress targets were not executed in this run "
                "(expected ext_memory_stress + extensions_stress to pass)"
            ),
            strict=True,
        )

        report_pass = soak_report.get("pass")
        require_condition(
            "conformance.soak_longevity_pass",
            path=soak_report_path,
            ok=report_pass is True,
            ok_msg="soak/longevity verdict passed",
            fail_msg=f"soak/longevity verdict must pass for full baseline run (got {report_pass!r})",
            strict=True,
        )

soak_events_path = artifact_dir / "soak_longevity_events.jsonl"
soak_events_exists = require_file(
    "conformance.soak_longevity_events_jsonl",
    soak_events_path,
    strict=True,
    description="soak/longevity structured events log exists",
)
if soak_events_exists:
    lines = [line for line in soak_events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    require_condition(
        "conformance.soak_longevity_events_non_empty",
        path=soak_events_path,
        ok=len(lines) > 0,
        ok_msg=f"soak/longevity events contains {len(lines)} entries",
        fail_msg="soak/longevity events log is empty",
        strict=True,
    )


# 5) User-focused release-readiness summary (bd-k5q5.7.11)
release_readiness_path = artifact_dir / "release_readiness_summary.json"
release_readiness = load_json(
    "conformance.release_readiness_json",
    release_readiness_path,
    strict=True,
)
require_keys(
    "conformance.release_readiness_json",
    release_readiness,
    release_readiness_path,
    [
        "schema",
        "generated_at",
        "correlation_id",
        "status",
        "overall_ready",
        "summary",
        "profiles",
        "workflow_outcomes",
        "known_risks",
        "remediation",
        "evidence",
    ],
    strict=True,
)

if isinstance(release_readiness, dict):
    require_condition(
        "conformance.release_readiness_schema",
        path=release_readiness_path,
        ok=release_readiness.get("schema") == "pi.e2e.release_readiness.v1",
        ok_msg="release-readiness schema matches",
        fail_msg=(
            "expected schema 'pi.e2e.release_readiness.v1', got "
            f"{release_readiness.get('schema')!r}"
        ),
        strict=True,
    )
    readiness_correlation_id = str(release_readiness.get("correlation_id", "")).strip()
    require_condition(
        "conformance.release_readiness_correlation_id_nonempty",
        path=release_readiness_path,
        ok=bool(readiness_correlation_id),
        ok_msg="release-readiness correlation_id is set",
        fail_msg="release-readiness correlation_id is empty",
        strict=True,
        remediation="Set correlation_id from summary.json when generating release_readiness_summary.json.",
    )
    require_condition(
        "conformance.release_readiness_correlation_id_matches_summary",
        path=release_readiness_path,
        ok=bool(summary_correlation_id) and readiness_correlation_id == summary_correlation_id,
        ok_msg="release-readiness correlation_id matches summary correlation_id",
        fail_msg=(
            "release-readiness correlation_id mismatch: "
            f"expected {summary_correlation_id!r}, got {readiness_correlation_id!r}"
        ),
        strict=True,
        remediation="Propagate summary correlation_id into release_readiness_summary.json.",
    )

    profiles = release_readiness.get("profiles")
    require_condition(
        "conformance.release_readiness_profiles_object",
        path=release_readiness_path,
        ok=isinstance(profiles, dict),
        ok_msg="profiles object exists",
        fail_msg="profiles must be an object",
        strict=True,
    )
    if isinstance(profiles, dict):
        for profile_name in ("safe", "balanced", "permissive"):
            profile_entry = profiles.get(profile_name)
            require_condition(
                f"conformance.release_readiness.{profile_name}.object",
                path=release_readiness_path,
                ok=isinstance(profile_entry, dict),
                ok_msg=f"{profile_name} profile entry is object",
                fail_msg=f"{profile_name} profile entry missing/invalid",
                strict=True,
            )
            if isinstance(profile_entry, dict):
                for field in (
                    "projected_pass_rate_pct",
                    "blocked_extensions",
                    "recommendation",
                ):
                    require_condition(
                        f"conformance.release_readiness.{profile_name}.{field}",
                        path=release_readiness_path,
                        ok=field in profile_entry,
                        ok_msg=f"{field} present",
                        fail_msg=f"missing {field}",
                        strict=True,
                    )

    workflow_outcomes = release_readiness.get("workflow_outcomes")
    require_condition(
        "conformance.release_readiness.workflow_outcomes_object",
        path=release_readiness_path,
        ok=isinstance(workflow_outcomes, dict),
        ok_msg="workflow_outcomes object exists",
        fail_msg="workflow_outcomes must be an object",
        strict=True,
    )
    if isinstance(workflow_outcomes, dict):
        require_condition(
            "conformance.release_readiness.workflow_outcomes.failing_suites_array",
            path=release_readiness_path,
            ok=isinstance(workflow_outcomes.get("failing_suites"), list),
            ok_msg="failing_suites is an array",
            fail_msg="failing_suites must be an array",
            strict=True,
        )
        require_condition(
            "conformance.release_readiness.workflow_outcomes.failing_unit_targets_array",
            path=release_readiness_path,
            ok=isinstance(workflow_outcomes.get("failing_unit_targets"), list),
            ok_msg="failing_unit_targets is an array",
            fail_msg="failing_unit_targets must be an array",
            strict=True,
        )

    known_risks = release_readiness.get("known_risks")
    require_condition(
        "conformance.release_readiness.known_risks_array",
        path=release_readiness_path,
        ok=isinstance(known_risks, list),
        ok_msg="known_risks is an array",
        fail_msg="known_risks must be an array",
        strict=True,
    )

    remediation = release_readiness.get("remediation")
    require_condition(
        "conformance.release_readiness.remediation_object",
        path=release_readiness_path,
        ok=isinstance(remediation, dict),
        ok_msg="remediation object exists",
        fail_msg="remediation must be an object",
        strict=True,
    )
    if isinstance(remediation, dict):
        require_condition(
            "conformance.release_readiness.remediation.immediate_array",
            path=release_readiness_path,
            ok=isinstance(remediation.get("immediate"), list),
            ok_msg="immediate remediation is an array",
            fail_msg="remediation.immediate must be an array",
            strict=True,
        )
        require_condition(
            "conformance.release_readiness.remediation.policy_guidance_array",
            path=release_readiness_path,
            ok=isinstance(remediation.get("policy_guidance"), list),
            ok_msg="policy_guidance is an array",
            fail_msg="remediation.policy_guidance must be an array",
            strict=True,
        )

    evidence_links = release_readiness.get("evidence")
    require_condition(
        "conformance.release_readiness.evidence_object",
        path=release_readiness_path,
        ok=isinstance(evidence_links, dict),
        ok_msg="evidence object exists",
        fail_msg="evidence must be an object",
        strict=True,
    )
    if isinstance(evidence_links, dict):
        for field in ("summary_json", "evidence_contract_json"):
            require_condition(
                f"conformance.release_readiness.evidence.{field}",
                path=release_readiness_path,
                ok=field in evidence_links,
                ok_msg=f"{field} present",
                fail_msg=f"missing evidence.{field}",
                strict=True,
            )
        require_condition(
            "conformance.release_readiness.evidence.summary_json_path_matches",
            path=release_readiness_path,
            ok=path_matches(evidence_links.get("summary_json"), summary_path),
            ok_msg="evidence.summary_json path matches summary.json",
            fail_msg=(
                "evidence.summary_json does not match summary artifact path "
                f"{summary_path}"
            ),
            strict=True,
        )
        require_condition(
            "conformance.release_readiness.evidence.evidence_contract_json_path_matches",
            path=release_readiness_path,
            ok=path_matches(evidence_links.get("evidence_contract_json"), contract_file),
            ok_msg="evidence.evidence_contract_json path matches evidence_contract.json",
            fail_msg=(
                "evidence.evidence_contract_json does not match contract artifact path "
                f"{contract_file}"
            ),
            strict=True,
        )

release_readiness_md_path = artifact_dir / "release_readiness_summary.md"
readiness_md_exists = require_file(
    "conformance.release_readiness_markdown",
    release_readiness_md_path,
    strict=True,
    description="user-focused release-readiness markdown exists",
)
if readiness_md_exists:
    content = release_readiness_md_path.read_text(encoding="utf-8")
    require_condition(
        "conformance.release_readiness_markdown.known_risks_section",
        path=release_readiness_md_path,
        ok="## Known Risks" in content,
        ok_msg="contains Known Risks section",
        fail_msg="missing '## Known Risks' section",
        strict=True,
    )
    require_condition(
        "conformance.release_readiness_markdown.remediation_section",
        path=release_readiness_md_path,
        ok="## Recommended Remediation" in content,
        ok_msg="contains Recommended Remediation section",
        fail_msg="missing '## Recommended Remediation' section",
        strict=True,
    )

if isinstance(summary, dict):
    release_meta = summary.get("release_readiness")
    require_condition(
        "summary.release_readiness_object",
        path=summary_path,
        ok=isinstance(release_meta, dict),
        ok_msg="summary includes release_readiness metadata",
        fail_msg="summary missing release_readiness metadata",
        strict=True,
    )
    if isinstance(release_meta, dict):
        require_condition(
            "summary.release_readiness.path_matches",
            path=summary_path,
            ok=str(release_meta.get("path")) == str(release_readiness_path),
            ok_msg="summary.release_readiness.path matches artifact path",
            fail_msg=(
                "summary.release_readiness.path does not match "
                f"{release_readiness_path}"
            ),
            strict=True,
        )
        require_condition(
            "summary.release_readiness.correlation_id_matches",
            path=summary_path,
            ok=str(release_meta.get("correlation_id", "")).strip() == summary_correlation_id,
            ok_msg="summary.release_readiness.correlation_id matches run correlation_id",
            fail_msg=(
                "summary.release_readiness.correlation_id mismatch: expected "
                f"{summary_correlation_id!r}, got {release_meta.get('correlation_id')!r}"
            ),
            strict=True,
            remediation="Write correlation_id into summary.release_readiness metadata.",
        )


# 6) Exception-policy coverage for non-pass conformance outcomes
full_conformance_report_path = reports_dir / "conformance" / "conformance_report.json"
full_conformance_report = load_json(
    "conformance.full_report_json",
    full_conformance_report_path,
    strict=strict_conformance,
)

baseline_path = reports_dir / "conformance_baseline.json"
baseline_payload = load_json(
    "conformance.baseline_json",
    baseline_path,
    strict=strict_conformance,
)

approved_exception_ids: set[str] = set()

if isinstance(baseline_payload, dict):
    exception_policy = baseline_payload.get("exception_policy")
    require_condition(
        "conformance.exception_policy.exists",
        path=baseline_path,
        ok=isinstance(exception_policy, dict),
        ok_msg="exception_policy object exists",
        fail_msg="missing exception_policy object in conformance_baseline.json",
        strict=strict_conformance,
    )

    if isinstance(exception_policy, dict):
        require_keys(
            "conformance.exception_policy",
            exception_policy,
            baseline_path,
            ["schema", "required_fields", "entries"],
            strict=strict_conformance,
        )

        policy_schema = exception_policy.get("schema")
        schema_ok = policy_schema == "pi.ext.exception_policy.v1"
        add_check(
            "conformance.exception_policy.schema",
            baseline_path,
            schema_ok,
            f"schema={policy_schema!r}"
            if schema_ok
            else f"unexpected schema {policy_schema!r}",
        )
        if not schema_ok:
            message = (
                "conformance.exception_policy.schema: expected "
                f"'pi.ext.exception_policy.v1', got {policy_schema!r}"
            )
            if strict_conformance:
                errors.append(message)
            else:
                warnings.append(message)

        required_fields = exception_policy.get("required_fields")
        required_fields_ok = (
            isinstance(required_fields, list)
            and all(isinstance(field, str) and field for field in required_fields)
        )
        require_condition(
            "conformance.exception_policy.required_fields",
            path=baseline_path,
            ok=required_fields_ok,
            ok_msg="required_fields is a non-empty string list",
            fail_msg="required_fields must be a list[str]",
            strict=strict_conformance,
        )

        entries = exception_policy.get("entries")
        entries_ok = isinstance(entries, list)
        require_condition(
            "conformance.exception_policy.entries_array",
            path=baseline_path,
            ok=entries_ok,
            ok_msg="entries is an array",
            fail_msg="entries must be an array",
            strict=strict_conformance,
        )

        if required_fields_ok and entries_ok:
            seen_ids: set[str] = set()
            today = datetime.now(timezone.utc).date()

            for idx, entry in enumerate(entries):
                check_prefix = f"conformance.exception_policy.entry[{idx}]"
                if not isinstance(entry, dict):
                    require_condition(
                        f"{check_prefix}.object",
                        path=baseline_path,
                        ok=False,
                        ok_msg="entry is object",
                        fail_msg="entry must be an object",
                        strict=strict_conformance,
                    )
                    continue

                missing_entry_fields = [
                    field for field in required_fields if field not in entry
                ]
                require_condition(
                    f"{check_prefix}.required_fields",
                    path=baseline_path,
                    ok=not missing_entry_fields,
                    ok_msg="entry contains all required fields",
                    fail_msg=f"entry missing required fields: {missing_entry_fields}",
                    strict=strict_conformance,
                )

                entry_id = str(entry.get("id", "")).strip()
                status_value = str(entry.get("status", "")).strip()
                review_by = str(entry.get("review_by", "")).strip()

                id_ok = bool(entry_id)
                require_condition(
                    f"{check_prefix}.id",
                    path=baseline_path,
                    ok=id_ok,
                    ok_msg=f"id={entry_id}",
                    fail_msg="id must be non-empty",
                    strict=strict_conformance,
                )

                if id_ok:
                    duplicate = entry_id in seen_ids
                    require_condition(
                        f"{check_prefix}.unique_id",
                        path=baseline_path,
                        ok=not duplicate,
                        ok_msg=f"id {entry_id} is unique",
                        fail_msg=f"duplicate exception id: {entry_id}",
                        strict=strict_conformance,
                    )
                    seen_ids.add(entry_id)

                status_ok = status_value in {"approved", "temporary"}
                require_condition(
                    f"{check_prefix}.status",
                    path=baseline_path,
                    ok=status_ok,
                    ok_msg=f"status={status_value}",
                    fail_msg=(
                        f"invalid status {status_value!r}; expected approved|temporary"
                    ),
                    strict=strict_conformance,
                )

                review_ok = False
                review_error = ""
                if review_by:
                    try:
                        review_date = datetime.strptime(review_by, "%Y-%m-%d").date()
                        review_ok = review_date >= today
                        if not review_ok:
                            review_error = (
                                f"review_by {review_by} is in the past (today={today})"
                            )
                    except ValueError:
                        review_error = f"review_by {review_by!r} is not YYYY-MM-DD"
                else:
                    review_error = "review_by is missing or empty"

                require_condition(
                    f"{check_prefix}.review_by",
                    path=baseline_path,
                    ok=review_ok,
                    ok_msg=f"review_by={review_by}",
                    fail_msg=review_error,
                    strict=strict_conformance,
                )

                if (
                    id_ok
                    and status_ok
                    and review_ok
                    and not missing_entry_fields
                ):
                    approved_exception_ids.add(entry_id)

if isinstance(full_conformance_report, dict):
    failures = full_conformance_report.get("failures")
    failures_ok = isinstance(failures, list)
    require_condition(
        "conformance.full_report_json.failures_array",
        path=full_conformance_report_path,
        ok=failures_ok,
        ok_msg="full report failures field is an array",
        fail_msg="full report failures field missing or not an array",
        strict=strict_conformance,
    )

    if failures_ok:
        failure_ids = sorted(
            {
                str(item.get("id", "")).strip()
                for item in failures
                if isinstance(item, dict) and str(item.get("id", "")).strip()
            }
        )
        missing_ids = sorted(
            [entry_id for entry_id in failure_ids if entry_id not in approved_exception_ids]
        )
        require_condition(
            "conformance.exception_policy.covers_failures",
            path=full_conformance_report_path,
            ok=not missing_ids,
            ok_msg=(
                f"all {len(failure_ids)} full-report failures covered by approved exceptions"
            ),
            fail_msg=f"missing approved exceptions for failures: {missing_ids}",
            strict=strict_conformance,
        )


contract_correlation_id = summary_correlation_id or environment_correlation_id
status = "pass" if not errors else "fail"
contract_payload = {
    "schema": "pi.evidence.contract.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "profile": profile,
    "artifact_dir": str(artifact_dir),
    "correlation_id": contract_correlation_id,
    "status": status,
    "strict_conformance": strict_conformance,
    "checks": checks,
    "errors": errors,
    "warnings": warnings,
    "remediation_hints": sorted(remediation_hints),
}
contract_file.parent.mkdir(parents=True, exist_ok=True)
contract_file.write_text(json.dumps(contract_payload, indent=2) + "\n", encoding="utf-8")

if isinstance(summary, dict):
    summary["evidence_contract"] = {
        "schema": "pi.evidence.contract.v1",
        "correlation_id": contract_correlation_id,
        "path": str(contract_file),
        "status": status,
        "strict_conformance": strict_conformance,
        "error_count": len(errors),
        "warning_count": len(warnings),
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

if errors:
    print("EVIDENCE CONTRACT FAILED")
    for error in errors:
        print(f"- {error}")
    if remediation_hints:
        print("\nREMEDIATION HINTS")
        for hint in sorted(remediation_hints):
            print(f"  - {hint}")
    if warnings:
        print("\nEVIDENCE CONTRACT WARNINGS")
        for warning in warnings:
            print(f"  - {warning}")
    sys.exit(1)

print(
    "EVIDENCE CONTRACT PASSED: "
    f"{len(checks)} checks, {len(warnings)} warning(s), profile={profile}, strict_conformance={strict_conformance}"
)
sys.exit(0)
PY
    then
        echo "[contract] PASS ($contract_file)"
        return 0
    else
        echo "[contract] FAIL (see $contract_file)" >&2
        return 1
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    echo "═══════════════════════════════════════════════════════════════"
    echo " Pi Agent Rust — Unified Verification Runner"
    echo " Timestamp: $TIMESTAMP"
    echo " Profile: $PROFILE"
    echo " Artifact dir: $ARTIFACT_DIR"
    echo " Lint: $(if $SKIP_LINT; then echo 'skip'; else echo 'enabled'; fi)"
    echo " Correlation id: $CORRELATION_ID"
    echo " Shard mode: $SHARD_KIND ($SHARD_NAME)"
    echo " Lib inline: enabled"
    echo " Integration targets: ${#SELECTED_UNIT_TARGETS[@]}"
    echo " E2E suites: ${#SELECTED_SUITES[@]}"
    if [[ -n "$RERUN_FROM" ]]; then
        echo " Rerun source: $RERUN_FROM"
    fi
    if [[ -n "$DIFF_FROM" ]]; then
        echo " Diff baseline: $DIFF_FROM"
    fi
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if ! check_disk_headroom; then
        echo "[fatal] Preflight checks failed; refusing to start verification run." >&2
        exit 2
    fi

    capture_env
    write_shard_manifest

    local overall_exit=0

    # Phase 1: Lint gates (fmt + clippy).
    if ! run_lint_gates; then
        overall_exit=1
    fi

    # Phase 2: Build all selected targets.
    if ! build_tests; then
        echo "[fatal] Build failed, aborting test run." >&2
        exit 1
    fi

    # Phase 3: Lib inline tests.
    if ! run_lib_tests; then
        overall_exit=1
    fi

    # Phase 4: Integration targets (unit + vcr test files).
    for target in "${SELECTED_UNIT_TARGETS[@]}"; do
        if ! run_unit_target "$target"; then
            overall_exit=1
        fi
    done

    # Phase 5: E2E suites.
    for suite in "${SELECTED_SUITES[@]}"; do
        if [[ ! -f "tests/${suite}.rs" ]]; then
            echo "[skip] $suite: test file not found"
            continue
        fi
        if ! run_suite "$suite"; then
            overall_exit=1
        fi
    done

    write_summary

    if ! generate_failure_diagnostics; then
        overall_exit=1
    fi

    if ! generate_replay_bundle; then
        overall_exit=1
    fi

    if ! generate_extension_profile_matrix; then
        overall_exit=1
    fi

    if ! generate_soak_longevity_report; then
        overall_exit=1
    fi

    if ! generate_release_readiness_report; then
        overall_exit=1
    fi

    if ! generate_triage_diff; then
        overall_exit=1
    fi

    if ! validate_evidence_contract; then
        overall_exit=1
    fi

    exit $overall_exit
}

main "$@"
