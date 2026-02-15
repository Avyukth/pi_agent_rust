#!/usr/bin/env bash
# validate_fuzz_p2.sh — Phase 2 Fuzz Validation Suite
#
# Builds all fuzz harnesses, runs each for a configurable duration (default 60s),
# and generates a structured JSON report.
#
# Usage:
#   ./scripts/validate_fuzz_p2.sh              # 60s per target
#   ./scripts/validate_fuzz_p2.sh --time=10    # 10s per target (quick smoke)
#   ./scripts/validate_fuzz_p2.sh --time=300   # 5 min per target (thorough)
#
# Reports are saved to fuzz/reports/
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FUZZ_DIR="$PROJECT_ROOT/fuzz"
REPORT_DIR="$FUZZ_DIR/reports"

# Parse arguments
MAX_TIME=60
for arg in "$@"; do
    case "$arg" in
        --time=*) MAX_TIME="${arg#--time=}" ;;
        --help|-h)
            echo "Usage: $0 [--time=SECONDS]"
            echo "  Default: 60 seconds per target"
            exit 0
            ;;
    esac
done

mkdir -p "$REPORT_DIR"

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPORT_FILE="$REPORT_DIR/p2_validation_$(date +%Y%m%d_%H%M%S).json"

echo "=== FUZZ-V2 Phase 2 Validation Suite ==="
echo "Time per target: ${MAX_TIME}s"
echo "Report: $REPORT_FILE"
echo ""

# -------------------------------------------------------------------
# Step 1: Build all fuzz targets
# -------------------------------------------------------------------
echo ">>> Building all fuzz targets..."
BUILD_LOG="$REPORT_DIR/build.log"
cd "$FUZZ_DIR"

BUILD_START=$(date +%s)
if cargo fuzz build 2>&1 | tee "$BUILD_LOG"; then
    BUILD_STATUS="pass"
    BUILD_EXIT=0
else
    BUILD_STATUS="fail"
    BUILD_EXIT=$?
fi
BUILD_END=$(date +%s)
BUILD_TIME_MS=$(( (BUILD_END - BUILD_START) * 1000 ))
echo ""
echo "Build status: $BUILD_STATUS (${BUILD_TIME_MS}ms)"
echo ""

if [ "$BUILD_STATUS" = "fail" ]; then
    # Generate minimal report and exit
    cat > "$REPORT_FILE" <<EOFJSON
{
  "phase": "P2",
  "timestamp": "$TIMESTAMP",
  "build_status": "fail",
  "build_time_ms": $BUILD_TIME_MS,
  "targets": [],
  "summary": {
    "total_targets": 0,
    "passed": 0,
    "failed": 0,
    "crashed": 0,
    "total_corpus_growth": 0,
    "total_time_ms": $BUILD_TIME_MS
  }
}
EOFJSON
    echo "Build failed. Report saved to $REPORT_FILE"
    exit 1
fi

# -------------------------------------------------------------------
# Step 2: List all fuzz targets
# -------------------------------------------------------------------
TARGETS=$(cargo fuzz list 2>/dev/null)
TOTAL_TARGETS=$(echo "$TARGETS" | wc -l)
echo "Found $TOTAL_TARGETS fuzz targets."
echo ""

# -------------------------------------------------------------------
# Step 3: Run each target
# -------------------------------------------------------------------
OVERALL_EXIT=0
TARGET_RESULTS=""
PASSED=0
FAILED=0
CRASHED=0
TOTAL_CORPUS_GROWTH=0
TOTAL_RUN_TIME=0
TARGET_IDX=0

for target in $TARGETS; do
    TARGET_IDX=$((TARGET_IDX + 1))
    echo ">>> [$TARGET_IDX/$TOTAL_TARGETS] Running $target for ${MAX_TIME}s..."

    TARGET_LOG="$REPORT_DIR/${target}.log"
    CORPUS_DIR="$FUZZ_DIR/corpus/$target"
    ARTIFACT_DIR="$FUZZ_DIR/artifacts/$target"

    mkdir -p "$CORPUS_DIR" "$ARTIFACT_DIR"

    # Count initial corpus size
    INITIAL_CORPUS=0
    if [ -d "$CORPUS_DIR" ]; then
        INITIAL_CORPUS=$(find "$CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l)
    fi

    # Count seed corpus (in corpus/<target>/ subdirectory)
    SEED_CORPUS="$INITIAL_CORPUS"

    # Run the fuzzer
    RUN_START=$(date +%s%N)
    cargo fuzz run "$target" \
        -- -max_total_time="$MAX_TIME" \
        -artifact_prefix="$ARTIFACT_DIR/" \
        2>&1 | tee "$TARGET_LOG"
    TARGET_EXIT=${PIPESTATUS[0]}
    RUN_END=$(date +%s%N)
    RUN_MS=$(( (RUN_END - RUN_START) / 1000000 ))
    TOTAL_RUN_TIME=$((TOTAL_RUN_TIME + RUN_MS))

    # Count final corpus size
    FINAL_CORPUS=0
    if [ -d "$CORPUS_DIR" ]; then
        FINAL_CORPUS=$(find "$CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l)
    fi
    NEW_CORPUS=$((FINAL_CORPUS - INITIAL_CORPUS))
    if [ "$NEW_CORPUS" -lt 0 ]; then
        NEW_CORPUS=0
    fi
    TOTAL_CORPUS_GROWTH=$((TOTAL_CORPUS_GROWTH + NEW_CORPUS))

    # Count crashes
    CRASH_COUNT=0
    if [ -d "$ARTIFACT_DIR" ]; then
        CRASH_COUNT=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f -name "crash-*" 2>/dev/null | wc -l)
    fi

    # Determine status
    if [ "$TARGET_EXIT" -eq 0 ]; then
        TARGET_STATUS="pass"
        PASSED=$((PASSED + 1))
    elif [ "$CRASH_COUNT" -gt 0 ]; then
        TARGET_STATUS="crashed"
        CRASHED=$((CRASHED + 1))
        OVERALL_EXIT=1
    else
        TARGET_STATUS="fail"
        FAILED=$((FAILED + 1))
        OVERALL_EXIT=1
    fi

    echo "    Status: $TARGET_STATUS | Time: ${RUN_MS}ms | Corpus: $INITIAL_CORPUS -> $FINAL_CORPUS (+$NEW_CORPUS) | Crashes: $CRASH_COUNT"
    echo ""

    # Build JSON entry (using printf to avoid jq dependency)
    if [ -n "$TARGET_RESULTS" ]; then
        TARGET_RESULTS="${TARGET_RESULTS},"
    fi
    TARGET_RESULTS="${TARGET_RESULTS}
    {
      \"name\": \"$target\",
      \"status\": \"$TARGET_STATUS\",
      \"exit_code\": $TARGET_EXIT,
      \"time_ms\": $RUN_MS,
      \"corpus_size\": $FINAL_CORPUS,
      \"new_corpus_entries\": $NEW_CORPUS,
      \"seed_corpus_size\": $SEED_CORPUS,
      \"crashes_found\": $CRASH_COUNT,
      \"log_file\": \"fuzz/reports/${target}.log\"
    }"
done

# -------------------------------------------------------------------
# Step 4: Generate JSON report
# -------------------------------------------------------------------
TOTAL_TIME_MS=$((BUILD_TIME_MS + TOTAL_RUN_TIME))

cat > "$REPORT_FILE" <<EOFJSON
{
  "phase": "P2",
  "timestamp": "$TIMESTAMP",
  "build_status": "$BUILD_STATUS",
  "build_time_ms": $BUILD_TIME_MS,
  "max_time_per_target_s": $MAX_TIME,
  "targets": [$TARGET_RESULTS
  ],
  "summary": {
    "total_targets": $TOTAL_TARGETS,
    "passed": $PASSED,
    "failed": $FAILED,
    "crashed": $CRASHED,
    "total_corpus_growth": $TOTAL_CORPUS_GROWTH,
    "total_time_ms": $TOTAL_TIME_MS
  }
}
EOFJSON

echo ""
echo "=== Summary ==="
echo "Total targets: $TOTAL_TARGETS"
echo "Passed: $PASSED | Failed: $FAILED | Crashed: $CRASHED"
echo "Total corpus growth: $TOTAL_CORPUS_GROWTH"
echo "Total time: $((TOTAL_TIME_MS / 1000))s"
echo "Report: $REPORT_FILE"
echo ""

if [ "$OVERALL_EXIT" -ne 0 ]; then
    echo "RESULT: FAIL (some targets crashed or failed)"
else
    echo "RESULT: PASS (all targets ran without crashes)"
fi

exit "$OVERALL_EXIT"
