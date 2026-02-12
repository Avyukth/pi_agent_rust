#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Default to tmpfs-backed build/test paths to reduce disk pressure in multi-agent runs.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/dev/shm/pi_agent_rust/${USER:-agent}}"
export TMPDIR="${TMPDIR:-${CARGO_TARGET_DIR}/tmp}"
mkdir -p "$TMPDIR"

cargo test --test provider_registry_guardrails -- --nocapture
