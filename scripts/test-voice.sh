#!/usr/bin/env bash
# Voice test suite runner for pi_agent_rust.
#
# bd-19o.1.10.6: Runs all voice-related Rust tests and emits
# structured JSON summary. CI-compatible exit codes.
#
# Usage:
#   scripts/test-voice.sh           # human-readable
#   scripts/test-voice.sh --json    # structured JSON output
set -euo pipefail

cd "$(dirname "$0")/.."

JSON_MODE=false
if [[ "${1:-}" == "--json" ]]; then
  JSON_MODE=true
fi

# Collect test names from both voice-related filters.
# `voice` catches protocol, tools, CLI, VS1 tests.
# `trace_replay` catches trace fixture replay tests.
VOICE_TESTS=$(cargo test --lib -- 'voice' --list 2>/dev/null | grep ': test$' | sed 's/: test$//')
TRACE_TESTS=$(cargo test --lib -- 'trace_replay' --list 2>/dev/null | grep ': test$' | sed 's/: test$//')

# Deduplicate
ALL_TESTS=$(printf '%s\n%s' "$VOICE_TESTS" "$TRACE_TESTS" | sort -u)
TOTAL=$(echo "$ALL_TESTS" | wc -l | tr -d ' ')

# Run both test groups and capture results.
START_MS=$(($(date +%s) * 1000))
FAIL=0
PASS_COUNT=0
FAIL_COUNT=0
RESULTS=""

run_filter() {
  local filter="$1"
  local output
  output=$(cargo test --lib -q -- "$filter" 2>&1) || true

  # Parse the summary line: "test result: ok. X passed; Y failed; ..."
  local summary_line
  summary_line=$(echo "$output" | grep '^test result:' | tail -1)

  local passed failed
  passed=$(echo "$summary_line" | grep -o '[0-9]* passed' | grep -o '[0-9]*')
  failed=$(echo "$summary_line" | grep -o '[0-9]* failed' | grep -o '[0-9]*')

  PASS_COUNT=$((PASS_COUNT + ${passed:-0}))
  FAIL_COUNT=$((FAIL_COUNT + ${failed:-0}))

  if [[ "${failed:-0}" -gt 0 ]]; then
    FAIL=1
  fi

  if [[ "$JSON_MODE" == false ]]; then
    echo "$output"
  fi
}

# Run both filters
run_filter "voice"
run_filter "trace_replay"

END_MS=$(($(date +%s) * 1000))
DURATION_MS=$((END_MS - START_MS))

if [[ "$JSON_MODE" == true ]]; then
  cat <<EOF
{
  "suite": "voice",
  "language": "rust",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_ms": $DURATION_MS,
  "totals": {
    "total": $((PASS_COUNT + FAIL_COUNT)),
    "pass": $PASS_COUNT,
    "fail": $FAIL_COUNT,
    "skip": 0
  },
  "summary": {
    "voice-protocol": { "filter": "voice" },
    "trace-replay": { "filter": "trace_replay" }
  }
}
EOF
else
  echo ""
  echo "========================================"
  echo "Voice Test Suite Summary (Rust)"
  echo "========================================"
  echo "  Total:  $((PASS_COUNT + FAIL_COUNT))"
  echo "  Pass:   $PASS_COUNT"
  echo "  Fail:   $FAIL_COUNT"
  echo "  Duration: ${DURATION_MS}ms"
  echo "========================================"
fi

exit $FAIL
