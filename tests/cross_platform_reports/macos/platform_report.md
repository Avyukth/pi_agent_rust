# Cross-Platform CI Matrix — MACOS

> Generated: 2026-02-25T13:20:20Z
> OS: macos / aarch64
> Required checks: 5/5 passed

## Check Results

| Check | Policy | Status | Tag |
|-------|--------|--------|-----|
| Cargo check compiles | required | PASS | - |
| Test infrastructure functional | required | PASS | - |
| Temp directory writable | required | PASS | - |
| Git CLI available | required | PASS | - |
| Conformance artifacts present | informational | PASS | - |
| E2E TUI test support (tmux) | informational | PASS | - |
| POSIX file permission support | informational | PASS | - |
| Extension test artifacts present | informational | PASS | - |
| Evidence bundle index present | informational | PASS | - |
| Suite classification file present and valid | required | PASS | - |

## Merge Policy

| Platform | Role |
|----------|------|
| Linux | **Required** — all required checks must pass |
| macOS | Informational — failures logged, not blocking |
| Windows | Informational — failures logged, not blocking |

