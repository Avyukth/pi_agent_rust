# Fuzzing in pi_agent_rust

This directory contains `cargo-fuzz` harnesses and seed corpora for coverage-guided fuzzing.

## Requirements

- Rust nightly toolchain (project default)
- `cargo-fuzz` installed
- `rch` available for CPU-heavy runs (required in this repo)

Install `cargo-fuzz` if needed:

```bash
cargo install cargo-fuzz
```

## Directory Layout

- `fuzz/Cargo.toml`: fuzz package and target registrations
- `fuzz/fuzz_targets/*.rs`: libFuzzer harness implementations
- `fuzz/corpus/<target>/`: seed corpora per target
- `fuzz/artifacts/<target>/`: crash artifacts and reproducers

## Current Targets

- `fuzz_smoke`: infrastructure smoke test
- `fuzz_sse_parser`: SSE parser chunking invariant (`feed`/`flush`)
- `fuzz_sse_stream`: byte-level UTF-8 + SSE processing
- `fuzz_session_jsonl`: session JSONL open/decode paths
- `fuzz_session_entry`: standalone `SessionEntry` serde paths
- `fuzz_message_deser`: message/content deserialization entry points
- `fuzz_message_roundtrip`: serde round-trip invariants
- `fuzz_tool_paths`: path resolution/normalization behavior
- `fuzz_grep_pattern`: grep pattern handling (regex/literal)
- `fuzz_edit_match`: edit matching/replacement behavior
- `fuzz_provider_event`: provider `process_event()` flows (Anthropic/OpenAI/Gemini/Cohere/OpenAI Responses/Azure/Vertex)

## Running Fuzzers

Always run heavy fuzz commands through `rch`.

Set high-capacity temporary paths first:

```bash
export CARGO_TARGET_DIR="/dev/shm/pi_agent_rust/${USER:-agent}"
export TMPDIR="/dev/shm/pi_agent_rust/${USER:-agent}/tmp"
mkdir -p "$TMPDIR"
cd fuzz
```

Single-target smoke run (60s):

```bash
rch exec -- cargo fuzz run fuzz_sse_parser -- -max_total_time=60
```

Quick multi-target sweep:

```bash
for t in \
  fuzz_sse_parser fuzz_sse_stream fuzz_session_jsonl fuzz_session_entry \
  fuzz_message_deser fuzz_message_roundtrip fuzz_tool_paths fuzz_grep_pattern \
  fuzz_edit_match fuzz_provider_event
  do
    rch exec -- cargo fuzz run "$t" -- -max_total_time=30
  done
```

## Seed Corpus Management

General rule: each corpus should contain diverse valid inputs plus known edge/failure shapes.

Current corpus directories:

- `fuzz_sse_parser`, `fuzz_sse_stream`
- `fuzz_session_jsonl`, `fuzz_session_entry`
- `fuzz_message_deser`, `fuzz_message_roundtrip`
- `fuzz_tool_paths`, `fuzz_grep_pattern`, `fuzz_edit_match`
- `fuzz_provider_event`
- forward-looking seed sets for pending harnesses: `fuzz_config`, `fuzz_extension_payload`

Recommended source material for new seeds:

- `tests/fixtures/provider_responses/*.json`
- `tests/fixtures/vcr/*.json`
- `tests/conformance/fixtures/*.json`
- `tests/ext_conformance/mock_specs/*.json`
- representative `tests/**/*.jsonl` logs

When adding seeds:

1. Keep files small and focused (one scenario per seed file).
2. Mix parseable and malformed payloads.
3. Preserve provenance in filenames where possible (`provider_case_event`, `fixture_case`, etc.).
4. Re-run at least a short smoke fuzz pass for affected targets.

## Crash Triage Workflow

When a target crashes, `cargo-fuzz` writes a reproducer under `fuzz/artifacts/<target>/`.

1. Reproduce deterministically:

```bash
rch exec -- cargo fuzz run <target> fuzz/artifacts/<target>/crash-... 
```

2. Minimize corpus/crash input:

```bash
rch exec -- cargo fuzz cmin <target>
```

3. Fix root cause in source code.
4. Add regression coverage:

- add or keep minimized crash input in corpus when appropriate
- add unit/integration test if the behavior maps to a stable contract

5. Re-run smoke fuzzing for that target.

## Multi-Agent Coordination

Before editing harnesses/corpus in shared sessions:

- reserve paths via MCP Agent Mail (`file_reservation_paths`)
- announce start/completion in the bead thread
- release reservations after completion

This prevents corpus and harness collisions when multiple agents fuzz in parallel.
