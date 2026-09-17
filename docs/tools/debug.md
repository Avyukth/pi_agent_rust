# Native debugger workflows

The `debug` tool drives an installed Debug Adapter Protocol (DAP) adapter.
It is discoverable through `xdev` or selectable explicitly with `--tools debug`.
Tracking: `bd-cv653.1.2`. Implementation: `src/debug.rs` and `src/debug/`.

## Launch with breakpoints already installed

```json
{
  "action": "launch",
  "program": "app.py",
  "adapter": "debugpy",
  "stopOnEntry": true,
  "initialBreakpoints": [
    {"file": "app.py", "line": 12},
    {"file": "app.py", "line": 24, "condition": "count > 3"}
  ],
  "exceptionFilters": ["raised"]
}
```

`initialBreakpoints` and `exceptionFilters` work for both launch and attach.
Source entries are grouped by normalized file path, sent after `initialized`,
and acknowledged before `configurationDone`. The launch/attach response is
awaited concurrently because some adapters defer it until configuration ends.
Configuration errors are not ignored; a failed startup does not become the
current session. ConfigurationDone is sent only when the adapter advertises it.
Exception filter IDs and optional breakpoint features must be advertised by the
selected adapter. `sessions` includes its capabilities.

`stopOnEntry` defaults to true for launch. The response contains the observed
`execution` state; the tool does not invent an entry stop when the adapter is
running, stopped for another reason, or already exited. Explicitly terminate
an existing session before starting another. This prevents a second launch
silently replacing and killing the first debug session.

The existing lldb-dap and debugpy adapters use stdio. An SDK host can supply
trusted `AdapterSpec` definitions using `DebugTool::with_adapters`. The current
built-in Delve entry still requires a TCP transport integration: `dlv dap` does
not speak this stdio transport. This increment does not implement that backend,
a debugger installer, or arbitrary model-selected adapter executables.

## Retained breakpoint sets

```json
{"action":"set_breakpoint","file":"app.py","line":12}
{"action":"set_breakpoint","file":"app.py","line":24,"condition":"count > 3"}
{"action":"set_breakpoint","file":"app.py","line":30,"logMessage":"count={count}"}
{"action":"remove_breakpoint","file":"app.py","line":12}
{"action":"list_breakpoints"}
```

DAP's set-breakpoint requests replace whole sets. Pi now retains the desired
set per source file and per function/instruction/data family. Adding or changing
one breakpoint resends the set without losing the others. Source keys are
line plus optional column, instruction keys are reference plus offset, function
keys are names, and data keys are opaque data IDs. Repeating a key updates that
entry. Returned adapter IDs, actual source positions, verified flags and messages
are preserved. A successful request can still contain an unverified breakpoint;
that is not reported as verified.

Removal with a key removes only that entry. Omitting line for a source removal
clears that file; omitting name/reference/dataId clears the respective family.
The tool supports `remove_function_breakpoint` as well as instruction and data
removal. `condition`, `hitCondition` and source `logMessage` require the adapter's
corresponding capabilities. Per-session limits are 1,024 breakpoints and 256 sets.

```json
{"action":"set_function_breakpoint","name":"parse_record"}
{"action":"set_instruction_breakpoint","reference":"0x401000","offset":4}
{"action":"data_breakpoint_info","name":"count","variablesReference":41,"frameId":21}
{"action":"set_data_breakpoint","dataId":"<returned opaque dataId>","accessType":"write"}
{"action":"remove_data_breakpoint","dataId":"<returned opaque dataId>"}
```

Use the dataId returned by `data_breakpoint_info`, not the variable name itself.
Capabilities and data IDs are adapter-specific. The tool does not claim every
adapter can set instruction or data breakpoints. `list_breakpoints` reports
last-acknowledged sets and verification, not an authoritative live view of later
asynchronous binding changes. Failed, malformed, timed-out or abandoned updates
mark their set unsynchronized. The next edit resends the retained full set.
Raw `custom_request` cannot bypass the typed replacement-set/lifecycle actions.

## Step and inspect objects

```json
{"action":"stack_trace","threadId":7,"start":0,"limit":20}
{"action":"evaluate","expression":"record","context":"watch"}
{"action":"variables","variablesReference":66,"filter":"named","start":0,"limit":20}
{"action":"step_over","threadId":7}
{"action":"continue","threadId":7}
```

Evaluation without frameId resolves the selected stopped thread's top frame.
Its result preserves `variablesReference`, named/indexed child counts, memory
references and presentation hints so objects can be expanded in subsequent calls.
Variables and stack frames support paging. Adapter-specific child display names
are returned verbatim; use the supplied evaluateName when available.

Continue and stepping invalidate the old stop before dispatch. A fresh stopped
event arriving before the response is retained; a later stop is actually awaited.
This prevents `step_over` returning the old entry breakpoint immediately. A
rejected resume restores the prior state only when no newer execution event has
arrived. A timeout or disconnected transport does not restore stale frame access.
The current state model remains coarse/session-wide, not an independent state
machine for every thread. Debug adapters enforce the selected thread's actual
state. Frame and variable references are valid only for their suspension lifetime.

## Transport ownership and bounds

The adapter process is owned by the session, with a separate process group on
Unix. Spawn checks the current context's capabilities. Established sessions are
not owned by a completed launch call's cancellation token. Every request checks
I/O/timer capability and cancellation at dispatch.

Stdin writes run on one dedicated writer thread behind a bounded queue instead
of blocking an async worker. The queue and pending table each admit at most 32
requests; outbound frames are capped at 2 MiB. Reverse-request refusals use the
same writer lane, so the reader does not deadlock on a full stdin pipe.

Output events go to the bounded output tail, not the control-event queue. A
verbose program therefore cannot displace the stopped/initialized event behind
its output. The remaining event queue holds at most 512 control events, each
bounded to 64 KiB of serialized body; overflow retires the connection and fails
waiters rather than silently losing execution state. Inbound framing retains
the shared parser's 64 MiB per-frame cap.

Dropping a request removes its pending sender. Queued, unsent frames are revoked;
a partially written frame causes connection teardown, because reusing that stream
would corrupt following frames. A dispatch timeout also retires a blocked writer.
A request whose complete frame was already delivered may still execute remotely;
local cancellation is not rollback and does not automatically retry the command.
OS process cleanup and blocking filesystem operations are not hard real-time.

## Validation status

This implementation session could not run the authoritative quality command:

```sh
dsr quality --tool pi_agent_rust
```

It returned `dsr: command not found` (127); no Rust compiler was installed.
Rust tests in the debugger modules were authored, not executed. They exercise
breakpoint replacement/removal, failed configuration, both step-event orderings,
variable expansion, output flooding, pending-wait cancellation, writer backpressure
and blocked stdin. `PI_DEBUG_REQUIRE_PROTOCOL=1` makes missing Python a failure
in the newly added Python-backed protocol cases. Existing live lldb lanes retain
their dependency skips and the pre-existing ignored launch-pacing case.

An independent live debugpy protocol probe passed 12 checks: prelaunch two-source
breakpoints, entry stop, stack/scopes, removal of one breakpoint while retaining
the second, object expansion, a fresh step stop, and clearing the final set.
The probe's first attempt incorrectly assumed a dict child's display name was
unquoted; that assertion was corrected to use evaluateName and the complete probe
was rerun. No Rust code was executed by this probe. No compiled-adapter, DSR pass,
Delve, cross-platform, release, or Bead-closure claim is implied.

Protocol reference: Microsoft Debug Adapter Protocol overview and specification.
