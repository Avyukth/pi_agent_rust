# Issue #239: ConHost input ownership investigation

## Status

This is diagnostic/regression groundwork, **not a verified fix for abaynp's
report**. `console_input.rs` is currently used by the probe and tests only;
production integration in `src/interactive_ftui.rs` remains pending. Do not
close #239 on the basis of this change. The authoring environment had neither
DSR nor Rust: `dsr quality --tool pi_agent_rust` returned command-not-found
(exit 127). No Rust, Windows, or real-ConHost test result is claimed.

The source reviewed was pi commit `c7a2c90887ff8ed7281a064b31ac6570128f24ff`,
whose lockfile selects FTUI 0.7.0 and Crossterm 0.29.0.

## Concrete gap, not yet a reproduced trigger

Pi's `release_terminal`/`reacquire_terminal` change raw mode and emit ANSI mouse
sequences. FTUI's terminal session similarly writes ANSI mouse sequences.
Crossterm's Windows raw-mode implementation clears only line, echo and
processed-input bits. It does not clear QuickEdit or establish native mouse
and resize input flags. By contrast, Crossterm's native `EnableMouseCapture`
implementation clears QuickEdit and sets mouse, window and extended flags.

This leaves a concrete ConHost selection/input-mode difference worth testing.
It does not establish that selection caused the reported blank screen or that
all ConHost stalls have the same cause. Another diagnostic discriminator is
`ENABLE_PROCESSED_INPUT`: when it is enabled, Windows handles Ctrl+C instead of
placing it in the input buffer. A live UI with cooked/processed input would
point toward a failed terminal reacquisition rather than a normal keybinding.

Relevant primary sources:

- [Windows SetConsoleMode](https://learn.microsoft.com/en-us/windows/console/setconsolemode)
- [Crossterm upstream Windows terminal modes](https://github.com/crossterm-rs/crossterm/blob/master/src/terminal/sys/windows.rs)
- [Crossterm upstream native mouse capture](https://github.com/crossterm-rs/crossterm/blob/master/src/event/sys/windows.rs)
- [FTUI 0.7.0 terminal lifecycle](https://github.com/Dicklesworthstone/frankentui/blob/v0.7.0/crates/ftui-core/src/terminal_session.rs)

The current Pi handler already filters releases, gates SIGTSTP suspension to
Unix, and runs the external editor synchronously on the event-loop thread.
Those facts rule out simply reapplying the duplicate-key or asynchronous-editor
fixes as an explanation. The in-model watchdog measures completed callbacks;
it cannot, by itself, report a callback that never returns or a runtime I/O
operation outside a callback that stops progress.

## Probe

Use the `ftui_conhost_probe` example built by an appropriate DSR lane. From the
same cmd/ConHost window, run these separately with new trace filenames:

```text
ftui_conhost_probe.exe baseline.jsonl
ftui_conhost_probe.exe native.jsonl --native-input
```

Repeat both with `--fullscreen` to compare alternate-screen and inline modes.
The default probe uses inline mode. Keep the console's QuickEdit setting the
same between the baseline and comparison runs. Type, resize, and click/drag
in the console. `q` quits. `s` synchronously cycles the native input portion of
an editor handoff; it does not launch an editor or claim to exercise a full
external-editor lifecycle. The probe has no provider, agent or Pi session.

A separate observer writes and flushes JSONL every 500 ms. The model requests
FTUI timer ticks every 250 ms. The observer never calls poll/read on terminal
input and never writes to stdout/stderr. Records contain counters, mode bits,
callback age and phase, not key values, typed text, prompts or credentials.
Existing trace files are never overwritten. The native-input flag applies the
candidate scoped mode lease in the probe only and is rejected on non-Windows
hosts. A trace-write failure asks the model to quit on its next timer tick;
the observer's I/O error is then returned instead of silently losing evidence.

Interpretation requires the accompanying reproduction observations:

- Increasing callback age with stalled tick/view counts and `outside-model`
  narrows the stall to outside model callbacks. It does **not** distinguish
  native input polling, output writes, or command delivery by itself.
- Advancing ticks with no new key events while typing points toward input
  delivery, not a completely stopped model loop.
- `quick_edit: true` is a precondition to investigate, not proof of active
  selection. The probe does not query console selection state.
- `processed_input`, `line_input` or `echo_input` during the active loop help
  identify a lost raw-mode transition. The initial/final records are expected
  to show shell modes. Sampling can straddle startup/shutdown transitions;
  a single cooked-mode record near either boundary is not proof of a stall.
- View counts mean model rendering completed, not that terminal output was
  flushed. A stopped observer or a mode-query error is not a passing result.

## Candidate lease and tests

`src/interactive_ftui/console_input.rs` opens `CONIN$` with read/write access,
uses the existing safe `winapi-util` dependency, preserves one original mode
across handoffs, reapplies native flags on resume, and restores the original
mode before restart/exit. It honors mouse-capture opt-out. Its two-step restore
handles the documented requirement to set `ENABLE_EXTENDED_FLAGS` while
changing QuickEdit. Failed mode writes/readbacks are errors, not silent success.

`tests/ftui_conhost_console.rs` includes portable policy tests and one explicitly
ignored, exclusive-real-console Windows test. The portable tests model extended
mode semantics, cover all 1,024 low-bit combinations, verify preservation of
unowned bits, and check that repeated editor mode changes do not overwrite the
original baseline. They do not simulate a real ConHost selection stall.

The native test checks actual Get/SetConsoleMode transitions and raw-mode
handoffs, with outer cleanup even on assertion failure. It must be selected in
a DSR Windows lane with exclusive console access, not unignored on a redirected
or parallel test runner. Compilation, formatting, FTUI regressions and the
native comparison are still unverified. Use DSR, not Cargo or GitHub Actions as
an alternate quality route.

## Pending production wiring

Declare `mod console_input` in `interactive_ftui.rs`. Acquire its lease after
the log redirect guard and before `App::run`; always finish it before dropping
the log guard, joining the driver, or calling `/restart`. If acquisition fails,
explicitly drop the unrun App before joining the driver: the model otherwise
retains the submit sender and the driver can wait forever for disconnection.
Call `suspend()` after disabling raw mode in `release_terminal`, and `resume()`
after enabling raw mode but before output in `reacquire_terminal`. Keep native
restoration errors separate from editor errors when investigating a cooked-input
stall. Do not treat the pending wiring as evidence that the original report is
resolved.
