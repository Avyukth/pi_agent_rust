# Full Certification Report

> Generated: 2026-02-16T11:00:43Z
> Lane: **full**
> Verdict: **FAIL**

## Summary

| Metric | Value |
|--------|-------|
| Total gates | 14 |
| Passed | 13 |
| Failed | 0 |
| Warned | 0 |
| Skipped | 1 |
| Waived | 0 |
| Blocking | 7/8 |
| Can promote | NO |

## Gate Results

| Gate | Bead | Blocking | Status | Waived | Artifact |
|------|------|----------|--------|--------|----------|
| Non-mock unit compliance | bd-1f42.2.6 | YES | PASS | - | `docs/non-mock-rubric.json` |
| E2E log contract and transcripts | bd-1f42.3.6 | no | PASS | - | `tests/e2e_results` |
| Extension must-pass gate (208 extensions) | bd-1f42.4.4 | YES | SKIP | - | `tests/ext_conformance/reports/gate/must_pass_gate_verdict.json` |
| Extension provider compatibility matrix | bd-1f42.4.6 | no | PASS | - | `tests/ext_conformance/reports/provider_compat/provider_compat_report.json` |
| Unified evidence bundle | bd-1f42.6.8 | no | PASS | - | `tests/evidence_bundle/index.json` |
| Cross-platform matrix validation | bd-1f42.6.7 | YES | PASS | - | `tests/cross_platform_reports/linux/platform_report.json` |
| Conformance regression gate | bd-1f42.4 | YES | PASS | - | `tests/ext_conformance/reports/regression_verdict.json` |
| Conformance pass rate >= 80% | bd-1f42.4 | YES | PASS | - | `tests/ext_conformance/reports/conformance_summary.json` |
| Suite classification guard | bd-1f42.6.1 | YES | PASS | - | `tests/suite_classification.toml` |
| Requirement traceability matrix | bd-1f42.6.4 | no | PASS | - | `docs/traceability_matrix.json` |
| Canonical E2E scenario matrix | bd-1f42.8.5.1 | no | PASS | - | `docs/e2e_scenario_matrix.json` |
| Provider gap test matrix coverage | bd-3uqg.11.11.5 | no | PASS | - | `docs/provider-gaps-test-matrix.json` |
| SEC-6.4 security compatibility conformance | bd-1a2cu | YES | PASS | - | `tests/full_suite_gate/sec_conformance_verdict.json` |
| Waiver lifecycle compliance | bd-1f42.8.8.1 | YES | PASS | - | `tests/full_suite_gate/waiver_audit.json` |

## Rerun Commands

| Lane | Command |
|------|--------|
| Preflight | `cargo test --test ci_full_suite_gate -- preflight_fast_fail --nocapture --exact` |
| Full | `cargo test --test ci_full_suite_gate -- full_certification --nocapture --exact` |

