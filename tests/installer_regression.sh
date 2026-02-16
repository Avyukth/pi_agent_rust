#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${ROOT}/install.sh"
WORK_ROOT="${TMPDIR:-/tmp}/pi-installer-regression-$(date -u +%Y%m%dT%H%M%SZ)-$$"

PASS_COUNT=0
FAIL_COUNT=0

mkdir -p "${WORK_ROOT}"

usage() {
  cat <<'USAGE'
Usage: tests/installer_regression.sh

Runs installer-focused regression checks for:
  - option parsing
  - checksum verification branches
  - sigstore/cosign verification branches
  - completion installation branches
USAGE
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return 0
  fi
  echo "missing sha256 tool (sha256sum or shasum)" >&2
  return 1
}

case_dir() {
  local name="$1"
  local dir="${WORK_ROOT}/${name}"
  mkdir -p "$dir/home" "$dir/state" "$dir/data" "$dir/config" "$dir/dest" "$dir/fixtures" "$dir/fakebin"
  printf '%s\n' "$dir"
}

write_existing_pi_stub() {
  local dir="$1"
  cat > "${dir}/fakebin/pi" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  echo "pi 0.1.0 (existing-rust-stub)"
  exit 0
fi
echo "existing pi stub"
STUB
  chmod +x "${dir}/fakebin/pi"
}

write_cosign_stub() {
  local dir="$1"
  local mode="$2"
  cat > "${dir}/fakebin/cosign" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [ -n "\${COSIGN_LOG_PATH:-}" ]; then
  printf '%s\n' "\$*" >> "\${COSIGN_LOG_PATH}"
fi
if [ "${mode}" = "fail" ]; then
  echo "cosign fixture: forced failure" >&2
  exit 1
fi
exit 0
EOF
  chmod +x "${dir}/fakebin/cosign"
}

write_artifact_binary() {
  local path="$1"
  local mode="$2"
  cat > "$path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
MODE="${mode}"

if [ "\${1:-}" = "--version" ]; then
  echo "pi 9.9.9 (fixture)"
  exit 0
fi

if [ "\${1:-}" = "completions" ]; then
  if [ "\${2:-}" = "--help" ]; then
    if [ "\${MODE}" = "unsupported" ]; then
      exit 1
    fi
    exit 0
  fi

  case "\${MODE}" in
    completion_fail)
      exit 1
      ;;
    completion_empty)
      exit 0
      ;;
    completion_ok)
      case "\${2:-}" in
        bash)
          echo "# bash completion for pi fixture"
          exit 0
          ;;
        zsh)
          echo "#compdef pi"
          exit 0
          ;;
        fish)
          echo "complete -c pi"
          exit 0
          ;;
        *)
          exit 1
          ;;
      esac
      ;;
    *)
      exit 1
      ;;
  esac
fi

if [ "\${1:-}" = "completion" ]; then
  if [ "\${2:-}" = "--help" ]; then
    exit 1
  fi
  exit 1
fi

exit 1
EOF
  chmod +x "$path"
}

run_installer() {
  local dir="$1"
  shift
  local out="${dir}/output.log"
  local rc_file="${dir}/exit_code"
  local path_value="${dir}/fakebin:/usr/bin:/bin"

  (
    set +e
    HOME="${dir}/home" \
    XDG_STATE_HOME="${dir}/state" \
    XDG_DATA_HOME="${dir}/data" \
    XDG_CONFIG_HOME="${dir}/config" \
    PATH="${path_value}" \
    SHELL="/bin/bash" \
    bash "${INSTALLER}" "$@" >"${out}" 2>&1
    echo "$?" > "${rc_file}"
  )
}

exit_code_of() {
  local dir="$1"
  cat "${dir}/exit_code"
}

assert_exit_code() {
  local dir="$1"
  local expected="$2"
  local actual
  actual="$(exit_code_of "$dir")"
  if [ "$actual" != "$expected" ]; then
    echo "expected exit ${expected}, got ${actual}" >&2
    echo "--- output (${dir}) ---" >&2
    cat "${dir}/output.log" >&2
    return 1
  fi
}

assert_output_contains() {
  local dir="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "${dir}/output.log"; then
    echo "missing output text: ${needle}" >&2
    echo "--- output (${dir}) ---" >&2
    cat "${dir}/output.log" >&2
    return 1
  fi
}

run_test() {
  local name="$1"
  if "$name"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] ${name}"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[FAIL] ${name}"
  fi
}

test_help_lists_installer_flags() {
  local dir
  dir="$(case_dir "help-flags")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --help
  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "--artifact-url URL"
  assert_output_contains "$dir" "--checksum HEX"
  assert_output_contains "$dir" "--sigstore-bundle-url URL"
  assert_output_contains "$dir" "--completions SHELL"
  assert_output_contains "$dir" "--no-agent-skills"
}

test_invalid_completions_value_fails() {
  local dir
  dir="$(case_dir "invalid-completions")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --completions nope --no-gum
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Invalid --completions value"
}

test_unknown_option_fails() {
  local dir
  dir="$(case_dir "unknown-option")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --totally-unknown-flag
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Unknown option"
}

test_missing_option_value_fails() {
  local dir
  dir="$(case_dir "missing-option-value")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --version
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Option --version requires a value"
}

test_missing_option_value_when_next_arg_is_flag_fails() {
  local dir
  dir="$(case_dir "missing-option-value-next-flag")"
  write_existing_pi_stub "$dir"
  run_installer "$dir" --version --no-gum
  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Option --version requires a value"
}

test_custom_artifact_download_failure_does_not_source_fallback_without_version() {
  local dir missing_artifact
  dir="$(case_dir "custom-artifact-no-version-fallback")"
  write_existing_pi_stub "$dir"
  missing_artifact="${dir}/fixtures/missing-pi"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --dest "${dir}/dest" \
    --artifact-url "file://${missing_artifact}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Custom artifact download failed; cannot fall back to source without a release tag"
  assert_output_contains "$dir" "Pass --version vX.Y.Z with --artifact-url, or use --from-source directly"
}

test_agent_skills_install_by_default() {
  local dir artifact artifact_url checksum claude_skill codex_skill
  dir="$(case_dir "agent-skills-default")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  claude_skill="${dir}/home/.claude/skills/pi-agent-rust/SKILL.md"
  codex_skill="${dir}/home/.codex/skills/pi-agent-rust/SKILL.md"

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    installed (claude,codex)"
  [ -f "$claude_skill" ] || { echo "missing Claude skill: $claude_skill" >&2; return 1; }
  [ -f "$codex_skill" ] || { echo "missing Codex skill: $codex_skill" >&2; return 1; }
  grep -Fq "pi_agent_rust installer managed skill" "$claude_skill" || {
    echo "missing managed marker in Claude skill" >&2
    return 1
  }
  grep -Fq "pi_agent_rust installer managed skill" "$codex_skill" || {
    echo "missing managed marker in Codex skill" >&2
    return 1
  }
}

test_no_agent_skills_opt_out() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "agent-skills-opt-out")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-agent-skills \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    skipped (--no-agent-skills)"
  if [ -e "${dir}/home/.claude/skills/pi-agent-rust/SKILL.md" ]; then
    echo "Claude skill should not be installed when --no-agent-skills is used" >&2
    return 1
  fi
  if [ -e "${dir}/home/.codex/skills/pi-agent-rust/SKILL.md" ]; then
    echo "Codex skill should not be installed when --no-agent-skills is used" >&2
    return 1
  fi
}

test_existing_custom_skill_dirs_are_not_overwritten() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "agent-skills-custom-preserve")"
  write_existing_pi_stub "$dir"

  mkdir -p "${dir}/home/.claude/skills/pi-agent-rust"
  mkdir -p "${dir}/home/.codex/skills/pi-agent-rust"
  printf 'custom\n' > "${dir}/home/.claude/skills/pi-agent-rust/NOT_A_SKILL.txt"
  printf 'custom\n' > "${dir}/home/.codex/skills/pi-agent-rust/NOT_A_SKILL.txt"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Skills:    skipped (existing custom skill)"
  [ -f "${dir}/home/.claude/skills/pi-agent-rust/NOT_A_SKILL.txt" ] || {
    echo "Claude custom skill dir should be preserved" >&2
    return 1
  }
  [ -f "${dir}/home/.codex/skills/pi-agent-rust/NOT_A_SKILL.txt" ] || {
    echo "Codex custom skill dir should be preserved" >&2
    return 1
  }
}

test_checksum_inline_success() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "checksum-inline-success")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Checksum verified for"
  assert_output_contains "$dir" "Checksum:  verified (--checksum)"
}

test_checksum_mismatch_fails_hard() {
  local dir artifact artifact_url wrong_checksum
  dir="$(case_dir "checksum-mismatch")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  wrong_checksum="0000000000000000000000000000000000000000000000000000000000000000"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${wrong_checksum}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Checksum mismatch"
  assert_output_contains "$dir" "Release checksum verification failed; aborting install"
}

test_checksum_missing_manifest_entry_fails_hard() {
  local dir artifact artifact_url checksum_manifest
  dir="$(case_dir "checksum-missing-entry")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"

  checksum_manifest="${dir}/fixtures/custom.sha256"
  cat > "$checksum_manifest" <<'MANIFEST'
1111111111111111111111111111111111111111111111111111111111111111  other-artifact
2222222222222222222222222222222222222222222222222222222222222222  another-artifact
MANIFEST

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum-url "file://${checksum_manifest}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "No checksum entry found"
  assert_output_contains "$dir" "Release checksum verification failed; aborting install"
}

test_sigstore_bundle_unavailable_soft_skip() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "sigstore-bundle-unavailable")"
  write_existing_pi_stub "$dir"
  write_cosign_stub "$dir" "pass"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Sigstore bundle not found; skipping signature verification"
  assert_output_contains "$dir" "Signature: skipped (bundle unavailable)"
}

test_sigstore_cosign_failure_fails_hard() {
  local dir artifact artifact_url bundle checksum
  dir="$(case_dir "sigstore-cosign-fail")"
  write_existing_pi_stub "$dir"
  write_cosign_stub "$dir" "fail"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"
  bundle="${dir}/fixtures/pi-fixture.sigstore.json"
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n' > "$bundle"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --sigstore-bundle-url "file://${bundle}" \
    --no-completions

  assert_exit_code "$dir" 1
  assert_output_contains "$dir" "Sigstore verification failed"
  assert_output_contains "$dir" "Release signature verification failed; aborting install"
}

test_sigstore_cosign_success() {
  local dir artifact artifact_url bundle checksum
  dir="$(case_dir "sigstore-cosign-success")"
  write_existing_pi_stub "$dir"
  write_cosign_stub "$dir" "pass"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"
  bundle="${dir}/fixtures/pi-fixture.sigstore.json"
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n' > "$bundle"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --sigstore-bundle-url "file://${bundle}" \
    --no-completions

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Signature verified (cosign)"
  assert_output_contains "$dir" "Signature: verified"
}

test_completions_unsupported_build_soft_skip() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "completions-unsupported")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "unsupported"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --completions bash

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Shell completions: skipped (binary has no completion subcommand)"
  assert_output_contains "$dir" "Shell:     skipped (unsupported by this pi build)"
}

test_completions_generation_failure_recorded() {
  local dir artifact artifact_url checksum
  dir="$(case_dir "completions-generation-fail")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "completion_fail"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --completions bash

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Failed to generate bash completions"
  assert_output_contains "$dir" "Shell:     failed (completion generation error)"
}

test_completions_success_writes_file() {
  local dir artifact artifact_url checksum completion_file
  dir="$(case_dir "completions-success")"
  write_existing_pi_stub "$dir"

  artifact="${dir}/fixtures/pi-fixture"
  write_artifact_binary "$artifact" "completion_ok"
  artifact_url="file://${artifact}"
  checksum="$(sha256_file "$artifact")"

  run_installer "$dir" \
    --yes --no-gum --offline \
    --version v9.9.9 \
    --dest "${dir}/dest" \
    --artifact-url "${artifact_url}" \
    --checksum "${checksum}" \
    --completions bash

  completion_file="${dir}/data/bash-completion/completions/pi"

  assert_exit_code "$dir" 0
  assert_output_contains "$dir" "Installed bash completions to"
  assert_output_contains "$dir" "Shell:     installed (bash)"
  if [ ! -f "$completion_file" ]; then
    echo "expected completion file: ${completion_file}" >&2
    return 1
  fi
  if ! grep -Fq "bash completion for pi fixture" "$completion_file"; then
    echo "completion file missing expected content: ${completion_file}" >&2
    cat "$completion_file" >&2
    return 1
  fi
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  run_test test_help_lists_installer_flags
  run_test test_invalid_completions_value_fails
  run_test test_unknown_option_fails
  run_test test_missing_option_value_fails
  run_test test_missing_option_value_when_next_arg_is_flag_fails
  run_test test_custom_artifact_download_failure_does_not_source_fallback_without_version
  run_test test_agent_skills_install_by_default
  run_test test_no_agent_skills_opt_out
  run_test test_existing_custom_skill_dirs_are_not_overwritten
  run_test test_checksum_inline_success
  run_test test_checksum_mismatch_fails_hard
  run_test test_checksum_missing_manifest_entry_fails_hard
  run_test test_sigstore_bundle_unavailable_soft_skip
  run_test test_sigstore_cosign_failure_fails_hard
  run_test test_sigstore_cosign_success
  run_test test_completions_unsupported_build_soft_skip
  run_test test_completions_generation_failure_recorded
  run_test test_completions_success_writes_file

  echo ""
  echo "work dir: ${WORK_ROOT}"
  echo "passed:   ${PASS_COUNT}"
  echo "failed:   ${FAIL_COUNT}"

  if [ "${FAIL_COUNT}" -gt 0 ]; then
    exit 1
  fi
}

main "$@"
