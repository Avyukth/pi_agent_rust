# Chrome Extension Bridge: Port Status

> **Branch:** `feat/chrome-bridge-main`
> **Base:** upstream `main` at `b4c06bea6` (release v0.7.1, 2026-10-02)
> **Source of the port:** `fork/dev` at `c00c9d1db` (2026-02-28, pi 0.1.7)
> **Companion extension:** <https://github.com/Avyukth/pi_chrome_extension>
> **Status:** compiles and passes its integration suites, but is **not ready
> for real use**. One known runtime bug is diagnosed and unfixed (section 4.1).

This document records what was ported, what was changed along the way, what
was verified, and everything that is still missing.

---

## 1. What this is

The Chrome extension drives the user's real browser on behalf of the agent. It
talks to a native messaging host named `com.franken.pi_rust_browser_extension`.
That host is `pi --mode chrome-native-host`, and it relays frames between
Chrome's stdio pipe and a Unix domain socket that an agent session
(`pi --chrome`) connects to.

```
Extension <-> Chrome native messaging (stdio) <-> pi --mode chrome-native-host
                                                    <-> Unix socket in $XDG_RUNTIME_DIR/pi/
                                                  pi --chrome (ChromeBridge + 21 tools)
```

This is separate from the upstream headless CDP `browser` tool
(`src/browser.rs`, `docs/tools/browser.md`), which is untouched.

## 2. Why a port instead of a rebase

`fork/dev` was 138 commits ahead of its merge base and 3980 commits behind
upstream. Its non-chrome changes to shared files (`agent.rs`, `rpc.rs`,
`http/client.rs`, `logging.rs`, `perf_evidence.rs`) were large and unrelated.
The chrome module itself depends on only three internal APIs
(`error::{Error, Result}`, `model::{ContentBlock, TextContent}`,
`tools::{Tool, ToolOutput, ToolUpdate}`), so it was copied forward and the
integration points were re-applied by hand against current upstream.

## 3. What was ported and changed

### 3.1 Copied verbatim from `fork/dev`

- `src/chrome/` (9 files: `mod.rs`, `native_host.rs`, `protocol.rs`,
  `tools.rs`, `observer.rs`, `install.rs`, `config.rs`, `esl_journal.rs`,
  `gif.rs`)
- `tests/chrome_bridge.rs`, `chrome_tools.rs`, `chrome_observer.rs`,
  `chrome_safety.rs`, `chrome_fault_injection.rs`, `chrome_soak.rs`,
  `e2e_chrome.rs`, `browser_fixture_tests.rs`, `tests/browser_fixtures/`
- `tests/common/artifact_bundle.rs`, `tests/common/voice_helpers.rs`
- `.github/workflows/chrome-version-pin.yml`, `scripts/test-voice.sh`

### 3.2 Integration re-applied on upstream

| File | Change |
|---|---|
| `src/lib.rs` | `pub mod chrome;` |
| `src/cli.rs` | `--chrome`, `--chrome-voice`, `--setup-chrome`, `--chrome-extension-id`; `--mode chrome-native-host`; flags added to the `known_long_option` pre-parser allowlist |
| `src/config.rs` | `chrome: Option<ChromeConfig>` field and merge |
| `src/tools.rs` | `ToolRegistry::register_chrome_tools` / `register_voice_tools`, plus two gating tests |
| `src/agent.rs` | `set_chrome_bridge`, `set_voice_enabled`, `drain_observations`, call site before `TurnEnd` on the tool-result path; three ported test modules |
| `src/main.rs` | `--setup-chrome` early exit; current-thread runtime for native host mode; native host dispatch in `run()`; bridge creation and tool registration after `AgentSession` construction via `extend_tools` |
| `tests/common/mod.rs` | module declarations for the two new helpers |
| `Cargo.toml` | `image-resize` added to default features (section 3.4) |

### 3.3 API drift fixed

- `Tool::is_read_only()` no longer exists upstream. The 11 read-only chrome
  tools now override `effects()` and return `ToolEffects::read()`. Tests were
  updated to compare effects.
- `sha2` 0.11 digests no longer implement `LowerHex`. `RequestFingerprint` now
  hex-encodes bytes manually.
- asupersync 0.5 `oneshot::Receiver::recv` takes `&mut self`.
- New free functions `chrome::tools::chrome_tool_set` and `voice_tool_set`
  return boxed tools, because upstream registers late tools through
  `Agent::extend_tools` on a shared registry.
- `test_tool_registry_with_browser_tools` hard-coded 7 builtin tools. It now
  asserts that `find` is the only name overlapping the builtin set.
- One ported agent test asserted on `hidden_custom_count`, a field upstream
  removed. That assertion was dropped.

### 3.4 Behaviour changes worth reviewing

- **Wire op names (bug fix).** Three tools sent ops the extension's dispatch
  table does not contain, so every call would have failed with "Unknown tool
  operation". The model-facing tool names are unchanged; only the wire op
  changed:

  | Tool name | Old wire op | New wire op |
  |---|---|---|
  | `javascript` | `javascript` | `javascript_tool` |
  | `read_console_messages` | `read_console_messages` | `read_console` |
  | `read_network_requests` | `read_network_requests` | `read_network` |

  These match both the extension's `TOOL_HANDLERS` and the bridge's own
  `classify_execution_class`.
- **Installer binary choice (bug fix).** `setup_chrome` used the first `pi` on
  `PATH` for the wrapper script. It now prefers `std::env::current_exe()`,
  because a `pi` on `PATH` may be an older build without the bridge.
- **`image-resize` is now a default feature.** `src/chrome/gif.rs` needs the
  `image` crate, which upstream made optional. The alternative is to gate
  `gif.rs` and `GifCreatorTool` behind the feature. This was the smaller
  change and matches how `fork/dev` built, but it changes upstream's default
  build and should be a deliberate decision.

## 4. What is missing

### 4.1 BLOCKER: bridge reader thread is not woken under asupersync 0.5

**Symptom.** `chrome::tests::test_non_idempotent_retry_after_host_restart_returns_indeterminate`
hangs forever. It is marked `#[ignore]` on this branch so test runs terminate.
The test's assertions pass; the hang is in `Drop for ChromeBridge`, which joins
the reader thread.

**Root cause (confirmed with strace).** `connect_to_record` creates the
`UnixStream` and performs the handshake on the caller's runtime, then moves
the `OwnedReadHalf` to a dedicated std thread that runs its own
`current_thread` runtime. In asupersync 0.5 the socket's reactor registration
stays bound to the runtime that created it. The reader thread's first
`recvfrom` returns `EAGAIN`, it re-arms the fd on the *original* runtime's
epoll instance, and then waits on its own epoll, which never contains the
socket. It is never woken again.

The first connection in that test only works because EOF had already arrived
before the reader's first poll. The other 368 unit tests pass for the same
reason: their mock hosts answer before the reader first polls.

**Why it matters outside the test.** With a real extension, responses take
tens to hundreds of milliseconds. The reader will hit `EAGAIN` first and may
then never deliver the response, so tool calls can hang until timeout. Wake-up
then depends on the main runtime happening to process the event and wake a
task that lives on another runtime. Treat `pi --chrome` as unreliable until
this is fixed.

**Planned fix (not applied).**

1. Connect with `std::os::unix::net::UnixStream`, `try_clone()` it twice
   (reader, shutdown control), and wrap the original with
   `asupersync::net::unix::UnixStream::from_std` for the handshake and for
   async writes on the caller's runtime.
2. Replace the async `reader_loop` with a synchronous loop on the std clone.
   `from_std` makes the shared file description non-blocking, so on
   `WouldBlock` wait with `rustix::event::poll` (add the `event` feature to
   the existing `rustix` dependency). Decode all complete frames per read.
3. Keep the control clone in the bridge. In `mark_disconnected`,
   `disconnect` and `Drop`, call `shutdown(Shutdown::Both)` on it before
   joining, so the reader always observes EOF. The current code assumes that
   dropping the write half unblocks the reader, which is not true.
4. Store the whole `UnixStream` as the writer instead of `OwnedWriteHalf`.
5. Remove the `#[ignore]` and re-run the unit tests.

The native host (`native_host.rs`) runs on a single runtime and does not have
this pattern.

### 4.2 Not verified

- **No live end-to-end run.** Nothing has been tested against real Chrome
  with the real extension. The machine used for the port had no display.
- **`--setup-chrome` has not been run.** No native messaging manifest or
  wrapper script is installed.
- **No release build** of this branch exists. Only debug check and test
  builds were done.
- **`cargo clippy --all-targets -- -D warnings` was not run.** Upstream CI
  enforces it and its lint groups are much stricter than in February, so the
  9 chrome source files will likely need a lint pass.
- **`cargo fmt --check` was not run.**
- **The full upstream test suite was not run.** Only the chrome suites and
  chrome-filtered unit tests were. The `image-resize` default and the new
  `Config.chrome` field could affect snapshot or schema tests elsewhere
  (for example config surface diffs under `docs/`).
- **`tests/chrome_soak.rs` was compiled but not run.**
- **Voice path** (`--chrome-voice`) is compiled and unit-tested only.

### 4.3 Test results at this commit

| Suite | Result |
|---|---|
| `browser_fixture_tests` | 9 passed |
| `chrome_bridge` | 16 passed |
| `chrome_fault_injection` | 12 passed |
| `chrome_observer` | 12 passed |
| `chrome_safety` | 156 passed |
| `chrome_tools` | 136 passed |
| `e2e_chrome` | 147 passed |
| lib unit tests filtered to chrome, drain, trace replay, VS1, registration | 368 passed, 1 hangs (now ignored) |

The lib unit tests were last run before the `#[ignore]` attribute was added
and were not re-run afterwards.

### 4.4 Not ported from `fork/dev`

- `src/logging.rs` and `src/perf_evidence.rs` (dev-only infrastructure, not
  needed by the bridge).
- `benches/socket_latency.rs`, `benches/optimizations.rs` and their baselines.
- `tests/oq1_tool_selection.rs`, `tests/provider_observation_smoke.rs`,
  `tests/voice_helpers_smoke.rs`.
- `Capability::Browser` in `src/extensions.rs`.
- All of dev's unrelated edits to providers, RPC, compaction, session and the
  HTTP client.

### 4.5 Known gaps on the extension side

These are in `pi_chrome_extension`, recorded in its `review.md`, and are not
addressed by this branch:

- `data-pi-ref` attributes are never written to the DOM, so `computer`
  actions that target an element by ref fall back to a fragile index match.
- `findElements` uses its own ref counter, so its refs do not match the
  accessibility tree's refs.
- `javascript_tool` only accepts a single expression, not statements.
- The review lists two critical security findings and a wiring failure that
  were marked "must fix before merge".

### 4.6 Missing documentation and polish

- No user-facing doc for `--chrome` in `README.md` or `docs/tools/`.
- No `ChromeConfig` entry in `docs/settings.md`.
- No domain allowlist for the extension bridge. The CDP `browser` tool has
  one; this bridge can navigate anywhere the user's browser can.
- Registering all 21 tools adds several thousand tokens of schema. On small
  local context windows (for example 28k) a way to register a subset would
  help.

## 5. How to finish and try it

```bash
# 1. apply the fix in 4.1, then:
cargo test --lib -- chrome::
cargo clippy --all-targets -- -D warnings
cargo build --release

# 2. install the native host (writes the Chrome manifest and a wrapper script)
./target/release/pi --setup-chrome

# 3. build and load the extension
cd ../pi_chrome_extension && npm install && npm run build
#    chrome://extensions -> Developer mode -> Load unpacked -> dist/
#    expected extension id: fndheanlhfcfggmeilfedkcjkhibgmlp

# 4. run an agent session with browser tools
./target/release/pi --chrome
```

Build note: this branch uses the pinned `nightly-2026-08-31` toolchain from
`rust-toolchain.toml`. The old `fork/dev` branch only builds with
`cargo +nightly-2026-04-03` and needs
`legacy_pi_mono_code/pi-mono/packages/ai/src/models.generated.ts` copied in.
