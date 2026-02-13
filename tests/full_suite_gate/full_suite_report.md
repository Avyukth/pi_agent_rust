# Full-Suite CI Gate Report

> Generated: 2026-02-13T04:38:24Z
> Verdict: **FAIL**

## Summary

| Metric | Value |
|--------|-------|
| Total gates | 11 |
| Passed | 7 |
| Failed | 1 |
| Warned | 0 |
| Skipped | 3 |
| Blocking pass | 4/6 |

## Gate Results

| Gate | Bead | Blocking | Status | Artifact |
|------|------|----------|--------|----------|
| Non-mock unit compliance | bd-1f42.2.6 | YES | PASS | `docs/non-mock-rubric.json` |
| E2E log contract and transcripts | bd-1f42.3.6 | no | PASS | `tests/e2e_results` |
| Extension must-pass gate (208 extensions) | bd-1f42.4.4 | YES | SKIP | `tests/ext_conformance/reports/gate/must_pass_gate_verdict.json` |
| Extension provider compatibility matrix | bd-1f42.4.6 | no | SKIP | `tests/ext_conformance/reports/provider_compat/provider_compat_report.json` |
| Unified evidence bundle | bd-1f42.6.8 | no | SKIP | `tests/evidence_bundle/index.json` |
| Cross-platform matrix validation | bd-1f42.6.7 | YES | FAIL | `tests/cross_platform_reports/linux/platform_report.json` |
| Conformance regression gate | bd-1f42.4 | YES | PASS | `tests/ext_conformance/reports/regression_verdict.json` |
| Conformance pass rate >= 80% | bd-1f42.4 | YES | PASS | `tests/ext_conformance/reports/conformance_summary.json` |
| Suite classification guard | bd-1f42.6.1 | YES | PASS | `tests/suite_classification.toml` |
| Requirement traceability matrix | bd-1f42.6.4 | no | PASS | `docs/traceability_matrix.json` |
| Canonical E2E scenario matrix | bd-1f42.8.5.1 | no | PASS | `docs/e2e_scenario_matrix.json` |

## Issues Requiring Attention

### Cross-platform matrix validation — FAIL **(BLOCKING)**

- **Bead:** bd-1f42.6.7
- **Detail:** Not all required platform checks passed
- **Artifact:** `tests/cross_platform_reports/linux/platform_report.json`
- **Reproduce:**
  ```bash
  cargo test --test ci_cross_platform_matrix -- cross_platform_matrix --nocapture --exact
  ```

