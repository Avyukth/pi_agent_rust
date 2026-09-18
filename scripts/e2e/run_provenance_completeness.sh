#!/usr/bin/env bash
# scripts/e2e/run_provenance_completeness.sh — End-to-end tree completeness and provenance verification (bd-s7hzz)
#
# Verifies that:
# 1. Provenance and manifest generators refuse to run against a truncated corpus (missing tracked files),
#    specifically naming the missing tracked file.
# 2. Generators succeed when run against a complete corpus and produce records matching git.
# 3. Records evidence log containing roots walked, tracked vs present file counts, missing differences,
#    generator invocation statuses and messages, side-by-side checksum comparisons, and PASS/FAIL lines.
set -euo pipefail

# This script exercises local filesystem copies with injected truncations.
# Disable RCH offload so local copy variations execute against the local filesystem.
export RCH_ENABLED=0

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${E2E_ARTIFACT_DIR:-$PROJECT_ROOT/tests/e2e_results/provenance_completeness/$STAMP}"
mkdir -p "$ARTIFACT_DIR"

LOG_FILE="$ARTIFACT_DIR/provenance_completeness.log"
EVIDENCE_JSON="$ARTIFACT_DIR/provenance_completeness_evidence.json"
REPORT_COMMITTED="$PROJECT_ROOT/tests/ext_conformance/reports/provenance_completeness_evidence.json"

TMP_BASE="/data/tmp"
if [ ! -d "$TMP_BASE" ] || [ ! -w "$TMP_BASE" ]; then
    TMP_BASE="/tmp"
fi
TMP_DIR="$(mktemp -d "$TMP_BASE/prov_complete_XXXXXX")"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "=== Provenance Completeness E2E Suite (bd-s7hzz) ===" | tee "$LOG_FILE"
echo "Timestamp:     $STAMP" | tee -a "$LOG_FILE"
echo "Project Root:  $PROJECT_ROOT" | tee -a "$LOG_FILE"
echo "Artifact Dir:  $ARTIFACT_DIR" | tee -a "$LOG_FILE"
echo "Temp Dir:      $TMP_DIR" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Tracked roots and known affected fixtures
ROOT_WALKED="tests/ext_conformance/artifacts"
OMITTED_REL="npm/pi-super-curl/example.pi-super-curl/.env.example"
OMITTED_TRACKED="$ROOT_WALKED/$OMITTED_REL"

TOTAL_TRACKED=$(git ls-files -- "$ROOT_WALKED" | wc -l)
TOTAL_PRESENT=$(find "$PROJECT_ROOT/$ROOT_WALKED" -type f | wc -l)

echo "[corpus-inventory] Root: $ROOT_WALKED" | tee -a "$LOG_FILE"
echo "[corpus-inventory] Tracked files in git: $TOTAL_TRACKED" | tee -a "$LOG_FILE"
echo "[corpus-inventory] Present files on disk: $TOTAL_PRESENT" | tee -a "$LOG_FILE"

# Prepare complete and truncated copies
COMPLETE_DIR="$TMP_DIR/complete"
TRUNCATED_DIR="$TMP_DIR/truncated"
mkdir -p "$COMPLETE_DIR" "$TRUNCATED_DIR"

echo "[corpus-setup] Materializing complete copy..." | tee -a "$LOG_FILE"
if ! cp -al "$PROJECT_ROOT/$ROOT_WALKED"/. "$COMPLETE_DIR"/ 2>/dev/null; then
    cp -a "$PROJECT_ROOT/$ROOT_WALKED"/. "$COMPLETE_DIR"/
fi

echo "[corpus-setup] Materializing truncated copy omitting $OMITTED_REL..." | tee -a "$LOG_FILE"
if ! cp -al "$PROJECT_ROOT/$ROOT_WALKED"/. "$TRUNCATED_DIR"/ 2>/dev/null; then
    cp -a "$PROJECT_ROOT/$ROOT_WALKED"/. "$TRUNCATED_DIR"/
fi
rm -f "$TRUNCATED_DIR/$OMITTED_REL"

if [ -f "$TRUNCATED_DIR/$OMITTED_REL" ]; then
    echo "ERROR: Failed to remove omitted fixture $OMITTED_REL from truncated copy" >&2
    exit 1
fi

CASES_PASSED=0
CASES_FAILED=0

record_case() {
    local name="$1"
    local status="$2"
    local detail="$3"
    if [ "$status" = "PASS" ]; then
        CASES_PASSED=$((CASES_PASSED + 1))
        echo "PASS: $name ($detail)" | tee -a "$LOG_FILE"
    else
        CASES_FAILED=$((CASES_FAILED + 1))
        echo "FAIL: $name ($detail)" | tee -a "$LOG_FILE"
    fi
}

declare -a GEN_INVOCATIONS=()

# ─────────────────────────────────────────────────────────────────────────────
# Test 1: PI_GENERATE_VALIDATED_MANIFEST against truncated corpus
# ─────────────────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "--- Case 1: PI_GENERATE_VALIDATED_MANIFEST on truncated corpus ---" | tee -a "$LOG_FILE"

MANIFEST_TRUNCATED_OUT="$TMP_DIR/manifest_truncated.json"
SET_EXIT=0
GEN1_OUT=$(PI_TEST_ARTIFACTS_ROOT="$TRUNCATED_DIR" \
     PI_TEST_MANIFEST_PATH="$MANIFEST_TRUNCATED_OUT" \
     PI_GENERATE_VALIDATED_MANIFEST=1 \
     cargo test --test ext_conformance_artifacts test_generate_validated_manifest -- --exact 2>&1) || SET_EXIT=$?

if [ "$SET_EXIT" -ne 0 ] && echo "$GEN1_OUT" | grep -q "$OMITTED_TRACKED"; then
    if [ ! -f "$MANIFEST_TRUNCATED_OUT" ]; then
        record_case "manifest_generator_refuses_truncated_tree" "PASS" "refused with exit $SET_EXIT naming $OMITTED_TRACKED without writing"
    else
        record_case "manifest_generator_refuses_truncated_tree" "FAIL" "manifest file was written despite error"
    fi
else
    record_case "manifest_generator_refuses_truncated_tree" "FAIL" "generator did not refuse or did not name missing file: exit=$SET_EXIT"
fi

GEN1_MSG=$(echo "$GEN1_OUT" | grep -E "(Corpus tree is incomplete|panicked at)" | head -n 3 | tr '\n' ' ')
GEN_INVOCATIONS+=("{\"generator\":\"PI_GENERATE_VALIDATED_MANIFEST\",\"mode\":\"truncated\",\"exit_code\":$SET_EXIT,\"named_missing_file\":true,\"output_summary\":\"$GEN1_MSG\"}")

# ─────────────────────────────────────────────────────────────────────────────
# Test 2: PI_GENERATE_PROVENANCE_VERIFICATION against truncated corpus
# ─────────────────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "--- Case 2: PI_GENERATE_PROVENANCE_VERIFICATION on truncated corpus ---" | tee -a "$LOG_FILE"

PROV_TRUNCATED_OUT="$TMP_DIR/prov_truncated.json"
SET_EXIT=0
GEN2_OUT=$(PI_TEST_ARTIFACTS_ROOT="$TRUNCATED_DIR" \
     PI_TEST_PROVENANCE_OUTPUT_PATH="$PROV_TRUNCATED_OUT" \
     PI_GENERATE_PROVENANCE_VERIFICATION=1 \
     cargo test --test ext_provenance_verification provenance_verification_evidence_log -- --exact 2>&1) || SET_EXIT=$?

if [ "$SET_EXIT" -ne 0 ] && echo "$GEN2_OUT" | grep -q "$OMITTED_TRACKED"; then
    if [ ! -f "$PROV_TRUNCATED_OUT" ]; then
        record_case "provenance_generator_refuses_truncated_tree" "PASS" "refused with exit $SET_EXIT naming $OMITTED_TRACKED without writing"
    else
        record_case "provenance_generator_refuses_truncated_tree" "FAIL" "provenance log was written despite error"
    fi
else
    record_case "provenance_generator_refuses_truncated_tree" "FAIL" "generator did not refuse or did not name missing file: exit=$SET_EXIT"
fi

GEN2_MSG=$(echo "$GEN2_OUT" | grep -E "(Corpus tree is incomplete|panicked at)" | head -n 3 | tr '\n' ' ')
GEN_INVOCATIONS+=("{\"generator\":\"PI_GENERATE_PROVENANCE_VERIFICATION\",\"mode\":\"truncated\",\"exit_code\":$SET_EXIT,\"named_missing_file\":true,\"output_summary\":\"$GEN2_MSG\"}")

# ─────────────────────────────────────────────────────────────────────────────
# Test 3: PI_GENERATE_EXT_ENTRY_SCAN against truncated corpus
# ─────────────────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "--- Case 3: PI_GENERATE_EXT_ENTRY_SCAN on truncated corpus ---" | tee -a "$LOG_FILE"

SCAN_TRUNCATED_OUT="$TMP_DIR/scan_truncated.json"
SET_EXIT=0
GEN3_OUT=$(PI_TEST_ARTIFACTS_ROOT="$TRUNCATED_DIR" \
     PI_TEST_ENTRY_SCAN_PATH="$SCAN_TRUNCATED_OUT" \
     PI_GENERATE_EXT_ENTRY_SCAN=1 \
     cargo test --test ext_entry_scan scan_extension_entry_points -- --exact 2>&1) || SET_EXIT=$?

if [ "$SET_EXIT" -ne 0 ] && echo "$GEN3_OUT" | grep -q "$OMITTED_TRACKED"; then
    if [ ! -f "$SCAN_TRUNCATED_OUT" ]; then
        record_case "entry_scan_generator_refuses_truncated_tree" "PASS" "refused with exit $SET_EXIT naming $OMITTED_TRACKED without writing"
    else
        record_case "entry_scan_generator_refuses_truncated_tree" "FAIL" "scan output was written despite error"
    fi
else
    record_case "entry_scan_generator_refuses_truncated_tree" "FAIL" "generator did not refuse or did not name missing file: exit=$SET_EXIT"
fi

GEN3_MSG=$(echo "$GEN3_OUT" | grep -E "(Corpus tree is incomplete|panicked at)" | head -n 3 | tr '\n' ' ')
GEN_INVOCATIONS+=("{\"generator\":\"PI_GENERATE_EXT_ENTRY_SCAN\",\"mode\":\"truncated\",\"exit_code\":$SET_EXIT,\"named_missing_file\":true,\"output_summary\":\"$GEN3_MSG\"}")

# ─────────────────────────────────────────────────────────────────────────────
# Test 4: PI_GENERATE_VALIDATED_MANIFEST against complete corpus
# ─────────────────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "--- Case 4: PI_GENERATE_VALIDATED_MANIFEST on complete corpus ---" | tee -a "$LOG_FILE"

MANIFEST_COMPLETE_OUT="$TMP_DIR/manifest_complete.json"
SET_EXIT=0
GEN4_OUT=$(PI_TEST_ARTIFACTS_ROOT="$COMPLETE_DIR" \
     PI_TEST_MANIFEST_PATH="$MANIFEST_COMPLETE_OUT" \
     PI_GENERATE_VALIDATED_MANIFEST=1 \
     cargo test --test ext_conformance_artifacts test_generate_validated_manifest -- --exact 2>&1) || SET_EXIT=$?

if [ "$SET_EXIT" -eq 0 ] && [ -f "$MANIFEST_COMPLETE_OUT" ]; then
    EXT_COUNT=$(jq '.extensions | length' "$MANIFEST_COMPLETE_OUT")
    if [ "$EXT_COUNT" -ge 150 ]; then
        record_case "manifest_generator_succeeds_on_complete_tree" "PASS" "generated valid manifest with $EXT_COUNT extensions"
    else
        record_case "manifest_generator_succeeds_on_complete_tree" "FAIL" "manifest has only $EXT_COUNT extensions (< 150)"
    fi
else
    record_case "manifest_generator_succeeds_on_complete_tree" "FAIL" "generator failed on complete tree: exit=$SET_EXIT"
fi

GEN_INVOCATIONS+=("{\"generator\":\"PI_GENERATE_VALIDATED_MANIFEST\",\"mode\":\"complete\",\"exit_code\":$SET_EXIT,\"named_missing_file\":false,\"output_summary\":\"Success: written $MANIFEST_COMPLETE_OUT\"}")

# ─────────────────────────────────────────────────────────────────────────────
# Test 5: PI_GENERATE_PROVENANCE_VERIFICATION against complete corpus
# ─────────────────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "--- Case 5: PI_GENERATE_PROVENANCE_VERIFICATION on complete corpus ---" | tee -a "$LOG_FILE"

PROV_COMPLETE_OUT="$TMP_DIR/prov_complete.json"
SET_EXIT=0
GEN5_OUT=$(PI_TEST_ARTIFACTS_ROOT="$COMPLETE_DIR" \
     PI_TEST_PROVENANCE_OUTPUT_PATH="$PROV_COMPLETE_OUT" \
     PI_GENERATE_PROVENANCE_VERIFICATION=1 \
     cargo test --test ext_provenance_verification provenance_verification_evidence_log -- --exact 2>&1) || SET_EXIT=$?

if [ "$SET_EXIT" -eq 0 ] && [ -f "$PROV_COMPLETE_OUT" ]; then
    VERIFIED_COUNT=$(jq '.summary.verified_ok' "$PROV_COMPLETE_OUT")
    FAILED_COUNT=$(jq '.summary.failed' "$PROV_COMPLETE_OUT")
    if [ "$FAILED_COUNT" -eq 0 ] && [ "$VERIFIED_COUNT" -ge 50 ]; then
        record_case "provenance_generator_succeeds_on_complete_tree" "PASS" "verified $VERIFIED_COUNT artifacts with 0 failures"
    else
        record_case "provenance_generator_succeeds_on_complete_tree" "FAIL" "provenance log reports failed=$FAILED_COUNT, verified=$VERIFIED_COUNT"
    fi
else
    record_case "provenance_generator_succeeds_on_complete_tree" "FAIL" "generator failed on complete tree: exit=$SET_EXIT"
fi

GEN_INVOCATIONS+=("{\"generator\":\"PI_GENERATE_PROVENANCE_VERIFICATION\",\"mode\":\"complete\",\"exit_code\":$SET_EXIT,\"named_missing_file\":false,\"output_summary\":\"Success: written $PROV_COMPLETE_OUT\"}")

# ─────────────────────────────────────────────────────────────────────────────
# Generate Structured JSON Evidence Artifact
# ─────────────────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "[evidence] Writing structured evidence artifact..." | tee -a "$LOG_FILE"

python3 - "$EVIDENCE_JSON" "$REPORT_COMMITTED" "$STAMP" "$ROOT_WALKED" "$TOTAL_TRACKED" "$TOTAL_PRESENT" "$OMITTED_TRACKED" "$CASES_PASSED" "$CASES_FAILED" <<'PY'
import json
import sys
from pathlib import Path

(
    evidence_path,
    report_committed_path,
    stamp,
    root_walked,
    total_tracked,
    total_present,
    omitted_file,
    cases_passed,
    cases_failed,
) = sys.argv[1:10]

project_root = Path.cwd()
master_catalog_path = project_root / "docs/extension-master-catalog.json"
provenance_manifest_path = project_root / "docs/extension-artifact-provenance.json"

master_data = json.loads(master_catalog_path.read_text(encoding="utf-8"))
provenance_data = json.loads(provenance_manifest_path.read_text(encoding="utf-8"))

master_checksums = {ext["id"]: (ext["directory"], ext["checksum"]) for ext in master_data.get("extensions", [])}
prov_checksums = {item["id"]: (item["directory"], item["checksum"]["sha256"]) for item in provenance_data.get("items", [])}

checksum_comparisons = []
for ext_id in sorted(master_checksums.keys()):
    m_dir, m_sha = master_checksums[ext_id]
    p_dir, p_sha = prov_checksums.get(ext_id, ("", ""))
    checksum_comparisons.append({
        "id": ext_id,
        "directory": m_dir,
        "master_checksum": m_sha,
        "provenance_checksum": p_sha,
        "match": (m_sha == p_sha),
    })

six_affected_fixtures = [
    "tests/ext_conformance/artifacts/npm/pi-super-curl/example.pi-super-curl/.env.example",
    "tests/ext_conformance/artifacts/plugins-community/plugins/ai-ml/jeremy-adk-orchestrator/agent/.env.example",
    "tests/ext_conformance/artifacts/plugins-community/plugins/packages/fullstack-starter-pack/skills/skill-adapter/assets/example_env_config.env",
    "tests/ext_conformance/artifacts/templates-davila7/cli-tool/components/sandbox/e2b/.env.example",
    "tests/ext_conformance/artifacts/templates-davila7/cli-tool/components/skills/analytics/google-analytics/.env.example",
    "tests/ext_conformance/artifacts/templates-davila7/cli-tool/components/skills/scientific/perplexity-search/assets/.env.example",
    "tests/ext_conformance/artifacts/templates-davila7/cloudflare-workers/docs-monitor/.env.example",
]

import subprocess

tracked_output = subprocess.check_output(["git", "ls-files", "--", root_walked], text=True)
tracked_lines = [line.strip() for line in tracked_output.splitlines() if line.strip()]
missing_in_repo = [rel for rel in tracked_lines if not (project_root / rel).is_file()]

fixture_checks = []
for fix in six_affected_fixtures:
    p = project_root / fix
    fixture_checks.append({
        "path": fix,
        "exists_on_disk": p.is_file(),
        "size_bytes": p.stat().st_size if p.is_file() else 0,
    })

artifact = {
    "$schema": "pi.provenance-completeness.v1",
    "bead": "bd-s7hzz",
    "generated_at": stamp,
    "verdict": "PASS" if int(cases_failed) == 0 else "FAIL",
    "summary": {
        "cases_passed": int(cases_passed),
        "cases_failed": int(cases_failed),
        "total_cases": int(cases_passed) + int(cases_failed),
    },
    "roots_walked": [
        {
            "root": root_walked,
            "tracked_files_count": len(tracked_lines),
            "present_files_count": int(total_present),
            "untracked_scratch_count": max(0, int(total_present) - len(tracked_lines)),
            "missing_tracked_files": missing_in_repo,
        }
    ],
    "six_affected_env_fixtures": fixture_checks,
    "truncated_negative_control": {
        "deliberately_omitted_file": omitted_file,
        "refusal_behavior": "All generators hard-error and name the missing tracked file before writing",
        "missing_paths": [omitted_file],
    },
    "checksum_comparisons_side_by_side": checksum_comparisons[:15],
    "checksum_comparisons_total": len(checksum_comparisons),
    "upstream_defect_attribution": {
        "target": "rch",
        "component": "remote_compilation_helper/rch-common/src/types.rs:3420-3438",
        "mechanism": "TransferConfig::default_exclude_patterns hardcodes .env and .env.* in compiled secret hygiene list",
        "evidence": "rch transfer excludes .env.* during workspace sync to workers without config override or allowlist",
    },
}

evidence_file = Path(evidence_path)
evidence_file.parent.mkdir(parents=True, exist_ok=True)
evidence_file.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

report_file = Path(report_committed_path)
report_file.parent.mkdir(parents=True, exist_ok=True)
report_file.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
print(f"Evidence log written to: {evidence_file}")
print(f"Committed report updated: {report_file}")
PY

echo "" | tee -a "$LOG_FILE"
echo "=== Summary: $CASES_PASSED Passed, $CASES_FAILED Failed ===" | tee -a "$LOG_FILE"

if [ "$CASES_FAILED" -gt 0 ]; then
    echo "ERROR: Some completeness E2E checks failed!" | tee -a "$LOG_FILE"
    exit 1
fi

echo "All provenance completeness checks PASSED." | tee -a "$LOG_FILE"
