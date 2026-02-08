#!/usr/bin/env python3
"""Build authoritative scenario inventory from conformance report data.

Combines extension-level conformance (load + register) and scenario-level
conformance (execution + assertions) into a single machine-readable JSON
with cause taxonomy for all failures.

Usage:
    python3 tests/ext_conformance/build_inventory.py

Output:
    tests/ext_conformance/reports/inventory.json
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = PROJECT_ROOT / "tests" / "ext_conformance" / "reports"
CONFORMANCE_REPORT = REPORTS_DIR / "conformance" / "conformance_report.json"
SCENARIO_REPORT = REPORTS_DIR / "scenario_conformance.json"
OUTPUT_PATH = REPORTS_DIR / "inventory.json"

# ─── Cause taxonomy ────────────────────────────────────────────────────────

CAUSE_TAXONOMY = {
    "manifest_mismatch": {
        "code": "manifest_mismatch",
        "description": "Extension loads but registers different commands/tools/flags than manifest expects",
        "remediation": "Audit manifest or update extension to register expected items",
        "severity": "medium",
    },
    "missing_npm_package": {
        "code": "missing_npm_package",
        "description": "Extension requires an npm package not available as a virtual module stub",
        "remediation": "Add virtual module stub in extensions_js.rs",
        "severity": "medium",
    },
    "multi_file_dependency": {
        "code": "multi_file_dependency",
        "description": "Extension uses relative imports to unbundled sibling/parent modules",
        "remediation": "Bundle multi-file extensions or add relative path resolution",
        "severity": "low",
    },
    "runtime_error": {
        "code": "runtime_error",
        "description": "Extension crashes during initialization (missing data, broken API, FS dependency)",
        "remediation": "Investigate per-extension; may need environment setup or shim fixes",
        "severity": "medium",
    },
    "test_fixture": {
        "code": "test_fixture",
        "description": "Not a real extension; test-only fixture in manifest",
        "remediation": "Exclude from conformance or mark as N/A",
        "severity": "info",
    },
    "mock_gap": {
        "code": "mock_gap",
        "description": "Scenario mock infrastructure doesn't fully support the extension's hostcall pattern",
        "remediation": "Enhance MockSpecInterceptor or ConformanceSession",
        "severity": "high",
    },
    "assertion_gap": {
        "code": "assertion_gap",
        "description": "Scenario expectations not met due to assertion infrastructure limitations",
        "remediation": "Fix assertion logic or update expected values",
        "severity": "high",
    },
    "vcr_stub_gap": {
        "code": "vcr_stub_gap",
        "description": "VCR/stub HTTP mock doesn't produce valid response for extension parser",
        "remediation": "Improve synthetic HTTP response or add extension-specific VCR rules",
        "severity": "medium",
    },
}


def classify_extension_failure(ext_id: str, reason: str) -> str:
    """Classify an extension-level failure into a cause code."""
    if not reason:
        return "runtime_error"

    # Known test fixtures
    if ext_id == "base_fixtures":
        return "test_fixture"

    # Missing command/tool/flag → manifest mismatch
    if re.search(r"Missing (command|tool|flag)", reason):
        return "manifest_mismatch"
    if "expects tools but none registered" in reason:
        return "manifest_mismatch"

    # Unsupported module specifier → could be npm package or multi-file
    if "Unsupported module specifier" in reason:
        spec = re.search(r"specifier: (.+?)(?:\n|$)", reason)
        if spec:
            specifier = spec.group(1).strip()
            # Relative imports → multi-file dependency
            if specifier.startswith(".") or specifier.startswith(".."):
                return "multi_file_dependency"
            # npm packages
            return "missing_npm_package"
        return "missing_npm_package"

    # Load errors (ENOENT, not a function, cannot read property)
    if "Load error" in reason or "ENOENT" in reason:
        return "runtime_error"
    if "not a function" in reason or "cannot read property" in reason:
        return "runtime_error"

    # Test fixture
    if "base_fixtures" in reason:
        return "test_fixture"

    return "runtime_error"


def classify_scenario_failure(result: dict) -> str:
    """Classify a scenario-level failure into a cause code."""
    diffs = result.get("diffs", [])
    error = result.get("error", "")

    # Error during execution → mock or runtime gap
    if error:
        if "No image data" in error or "parse" in error.lower():
            return "vcr_stub_gap"
        return "mock_gap"

    # Diff failures → check what type
    diff_text = " ".join(diffs)
    if "ui_status" in diff_text or "ui_notify" in diff_text:
        return "mock_gap"
    if "exec_called" in diff_text:
        return "mock_gap"
    if "returns_contains" in diff_text or "content_contains" in diff_text:
        return "assertion_gap"

    return "assertion_gap"


def build_inventory():
    """Build the combined inventory."""
    # Load extension-level report
    if not CONFORMANCE_REPORT.exists():
        print(f"ERROR: {CONFORMANCE_REPORT} not found. Run conformance_full_report first.", file=sys.stderr)
        sys.exit(1)

    with open(CONFORMANCE_REPORT) as f:
        ext_report = json.load(f)

    # Load scenario-level report
    if not SCENARIO_REPORT.exists():
        print(f"ERROR: {SCENARIO_REPORT} not found. Run scenario_conformance_suite first.", file=sys.stderr)
        sys.exit(1)

    with open(SCENARIO_REPORT) as f:
        scn_report = json.load(f)

    # Build extension inventory
    ext_entries = []
    ext_failures = {f["id"]: f for f in ext_report.get("failures", [])}

    # Parse JSONL for full data
    events_path = REPORTS_DIR / "conformance" / "conformance_events.jsonl"
    ext_results = {}
    if events_path.exists():
        with open(events_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                ext_results[entry["id"]] = entry

    for ext_id, data in sorted(ext_results.items()):
        status = data["status"]
        cause_code = None
        cause_detail = None

        if status == "fail":
            failure = ext_failures.get(ext_id, {})
            reason = failure.get("reason", data.get("failure_reason", ""))
            cause_code = classify_extension_failure(ext_id, reason)
            cause_detail = reason
        elif status == "skip":
            cause_code = None
            cause_detail = data.get("failure_reason")

        # Map to PASS/FAIL/N-A
        if status == "pass":
            inv_status = "PASS"
        elif status == "skip":
            inv_status = "N-A"
        else:
            inv_status = "FAIL"

        ext_entries.append({
            "id": ext_id,
            "type": "extension",
            "tier": data.get("tier", 0),
            "status": inv_status,
            "cause_code": cause_code,
            "cause_detail": cause_detail,
            "registrations": {
                "commands": data.get("commands_registered", 0),
                "flags": data.get("flags_registered", 0),
                "tools": data.get("tools_registered", 0),
                "providers": data.get("providers_registered", 0),
            },
            "duration_ms": data.get("duration_ms", 0),
        })

    # Build scenario inventory
    scn_entries = []
    for result in scn_report.get("results", []):
        status = result["status"]
        cause_code = None
        cause_detail = None

        if status == "fail":
            cause_code = classify_scenario_failure(result)
            diffs = result.get("diffs", [])
            error = result.get("error")
            cause_detail = error if error else "; ".join(diffs)
        elif status == "skip":
            cause_code = None
            cause_detail = result.get("skip_reason")
        elif status == "error":
            cause_code = "runtime_error"
            cause_detail = result.get("error")

        if status == "pass":
            inv_status = "PASS"
        elif status == "skip":
            inv_status = "N-A"
        else:
            inv_status = "FAIL"

        scn_entries.append({
            "id": result["scenario_id"],
            "type": "scenario",
            "extension_id": result["extension_id"],
            "kind": result["kind"],
            "summary": result["summary"],
            "status": inv_status,
            "source_tier": result.get("source_tier", ""),
            "runtime_tier": result.get("runtime_tier", ""),
            "cause_code": cause_code,
            "cause_detail": cause_detail,
            "duration_ms": result.get("duration_ms", 0),
        })

    # Aggregate counts
    ext_pass = sum(1 for e in ext_entries if e["status"] == "PASS")
    ext_fail = sum(1 for e in ext_entries if e["status"] == "FAIL")
    ext_na = sum(1 for e in ext_entries if e["status"] == "N-A")

    scn_pass = sum(1 for e in scn_entries if e["status"] == "PASS")
    scn_fail = sum(1 for e in scn_entries if e["status"] == "FAIL")
    scn_na = sum(1 for e in scn_entries if e["status"] == "N-A")

    # Cause distribution
    cause_counts = {}
    for entry in ext_entries + scn_entries:
        code = entry.get("cause_code")
        if code:
            cause_counts[code] = cause_counts.get(code, 0) + 1

    # Build output
    inventory = {
        "schema": "pi.ext.inventory.v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "extensions": {
                "total": len(ext_entries),
                "pass": ext_pass,
                "fail": ext_fail,
                "na": ext_na,
                "pass_rate_pct": round(ext_pass / max(ext_pass + ext_fail, 1) * 100, 1),
            },
            "scenarios": {
                "total": len(scn_entries),
                "pass": scn_pass,
                "fail": scn_fail,
                "na": scn_na,
                "pass_rate_pct": round(scn_pass / max(scn_pass + scn_fail, 1) * 100, 1),
            },
        },
        "cause_taxonomy": {
            code: {**meta, "count": cause_counts.get(code, 0)}
            for code, meta in CAUSE_TAXONOMY.items()
        },
        "cause_distribution": dict(sorted(cause_counts.items(), key=lambda x: -x[1])),
        "extensions": ext_entries,
        "scenarios": scn_entries,
        "regression_thresholds": {
            "tier1_pass_rate_min_pct": 100.0,
            "tier2_pass_rate_min_pct": 95.0,
            "overall_pass_rate_min_pct": 80.0,
            "scenario_pass_rate_min_pct": 85.0,
            "max_new_failures": 3,
        },
    }

    # Write output
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(inventory, f, indent=2, sort_keys=False)
        f.write("\n")

    print(f"Inventory written to {OUTPUT_PATH}")
    print(f"  Extensions: {ext_pass}/{len(ext_entries)} PASS ({inventory['summary']['extensions']['pass_rate_pct']}%)")
    print(f"  Scenarios:  {scn_pass}/{len(scn_entries)} PASS ({inventory['summary']['scenarios']['pass_rate_pct']}%)")
    print(f"  Cause distribution: {json.dumps(cause_counts)}")


if __name__ == "__main__":
    build_inventory()
