#!/usr/bin/env python3
"""Generate machine-readable parity evidence from cargo test output.

Parses cargo test stdout for pass/fail counts across parity test suites
and emits a structured JSON artifact suitable for CI gate consumption.

Usage:
    python3 scripts/ci/generate_parity_evidence.py \
        --output path/to/parity_evidence.json \
        --log path/to/output.log
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "pi.ci.parity_evidence.v1"

PARITY_SUITES = [
    "json_mode_parity",
    "cross_surface_parity",
    "config_precedence",
    "vcr_parity_validation",
    "e2e_cross_provider_parity",
]

# Matches cargo test summary lines like:
#   test result: ok. 104 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.42s
RESULT_RE = re.compile(
    r"test result: (ok|FAILED)\.\s+"
    r"(\d+) passed;\s+"
    r"(\d+) failed;\s+"
    r"(\d+) ignored"
)

# Matches running line like:
#   Running tests/json_mode_parity.rs (target/debug/deps/json_mode_parity-abc123)
RUNNING_RE = re.compile(r"Running (?:tests/)?(\S+?)(?:\.rs)?\s")


def parse_log(log_text: str) -> dict:
    """Parse cargo test output and return per-suite results."""
    suites = {}
    current_suite = None

    for line in log_text.splitlines():
        running_match = RUNNING_RE.search(line)
        if running_match:
            raw = running_match.group(1)
            # Normalize: strip path prefixes, extract stem
            stem = raw.rsplit("/", 1)[-1]
            # cargo test output may include the hash suffix
            stem = stem.split("-")[0] if "-" in stem else stem
            if stem in PARITY_SUITES:
                current_suite = stem

        result_match = RESULT_RE.search(line)
        if result_match and current_suite:
            status = result_match.group(1)
            passed = int(result_match.group(2))
            failed = int(result_match.group(3))
            ignored = int(result_match.group(4))
            suites[current_suite] = {
                "status": "pass" if status == "ok" else "fail",
                "passed": passed,
                "failed": failed,
                "ignored": ignored,
                "total": passed + failed + ignored,
            }
            current_suite = None

    return suites


def build_evidence(suites: dict) -> dict:
    """Build the evidence payload."""
    total_passed = sum(s["passed"] for s in suites.values())
    total_failed = sum(s["failed"] for s in suites.values())
    total_tests = sum(s["total"] for s in suites.values())

    all_pass = all(s["status"] == "pass" for s in suites.values())
    missing = [name for name in PARITY_SUITES if name not in suites]

    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": "pass" if (all_pass and not missing) else "fail",
        "summary": {
            "suites_expected": len(PARITY_SUITES),
            "suites_found": len(suites),
            "suites_missing": missing,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "total_tests": total_tests,
            "pass_rate_pct": round(
                100.0 * total_passed / total_tests, 2
            ) if total_tests > 0 else 0.0,
        },
        "suites": suites,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, help="Path for output JSON"
    )
    parser.add_argument(
        "--log", required=True, help="Path to cargo test log"
    )
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"ERROR: log file not found: {log_path}", file=sys.stderr)
        return 1

    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    suites = parse_log(log_text)
    evidence = build_evidence(suites)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )

    print(f"Parity evidence: {output_path}")
    print(f"  Verdict: {evidence['verdict']}")
    print(f"  Suites: {evidence['summary']['suites_found']}/{evidence['summary']['suites_expected']}")
    print(f"  Tests: {evidence['summary']['total_passed']}/{evidence['summary']['total_tests']} passed")

    if evidence["summary"]["suites_missing"]:
        print(f"  Missing: {', '.join(evidence['summary']['suites_missing'])}")

    return 0 if evidence["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
