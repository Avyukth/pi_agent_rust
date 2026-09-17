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
running, stopped for another reason, or already exited. End an existing session
before starting another. A second launch cannot silently replace the first.

Built-in lldb-dap and debugpy adapters use stdio. Delve uses the owned loopback
TCP transport described below. SDK hosts can supply trusted `AdapterSpec`
definitions through `DebugTool::with_adapters`; the ID `dlv` selects Delve's
transport. Adapter commands are resolved to actual absolute executable paths
before changing the child working directory. This is not a sandbox or debugger
installer, and tool arguments cannot choose an arbitrary adapter executable.

## Go programs, packages and tests

Install a suitable Delve (`dlv`) and Go toolchain separately. Ordinary Go source
files and package directories containing Go files or `go.mod` select Delve
when its registered executable is available. The directory scan for automatic
selection is bounded; use `adapter: "dlv"` to select it explicitly.

```json
{
  "action": "launch",
  "program": "./cmd/server",
  "adapter": "dlv",
  "args": ["--port", "8080"],
  "initialBreakpoints": [
    {"file": "cmd/server/main.go", "line": 24}
  ],
  "startupTimeoutMs": 180000
}
```

The inferred Go mode is `debug` for a `.go` source or local package directory,
`test` for a file ending in `_test.go`, and `exec` for a prebuilt binary. Use
`goMode` to choose explicitly. A compiled Go binary needs `adapter: "dlv"`
because a filename does not reliably identify its source language.

```json
{"action":"launch","program":"./bin/server","adapter":"dlv","goMode":"exec"}
{"action":"launch","program":"./parser","goMode":"test","args":["-test.run","^TestParse$","-test.v"]}
```

`goMode` is launch-only and accepts `debug`, `test` or `exec`. Go source/test
compilation is performed by Delve, not by interpreting a shell command supplied
by the model. Argument arrays are sent literally. Build outputs go into a
private temporary directory retained for the debug session and cleaned up after
the owned adapter is stopped. Pi does not choose a fixed build filename inside
the workspace or overwrite the original target. Go's own caches and any module
downloads remain ordinary toolchain side effects. Build flags, remote servers,
replay/core modes and remote package import paths are not exposed here.

`startupTimeoutMs` gives launch/attach and its initial configuration one shared
budget: 120 seconds by default, at most 300 seconds. It includes Go compilation
and all initial breakpoint configuration. It does not include adapter process
discovery, the initialize request, or the separate optional entry-stop wait.
Failure or cancellation before adoption drops the adapter and its temporary
build directory; a partial startup is never returned as an active session.

### Delve connection and ownership

Pi starts `dlv dap` with `--listen=127.0.0.1:0 --only-same-user=true`. The OS
chooses the port; Pi parses the endpoint announced by that owned process rather
than reserving and releasing a port for another process to race. Discovery
accepts only the expected IPv4 loopback binding and a nonzero port. Startup
output has line and total-byte bounds. A missing/invalid announcement, process
exit, connection error or timeout fails startup without trying another server.

The connect operation runs off the async worker and has its own bounded socket
connect timeout. Native DAP frames travel over TCP; Delve/debuggee stdout and
stderr are drained separately into the bounded output tail. Debuggee output
therefore cannot be mistaken for DAP framing. Closing the session shuts down
both socket directions before process cleanup so blocked reader/writer lanes
are woken. The model cannot supply a raw endpoint or disable the same-user
restriction. Loopback and process ownership are not authentication against other
code running as the same OS user; use an isolated development environment when
that is part of the threat model.

## Attach, disconnect and termination

```json
{"action":"attach","adapter":"dlv","pid":4242}
{"action":"disconnect"}
```

Attach selects the local process ID through the registered adapter. OS debugger
permissions still apply; Pi does not elevate privileges or relax ptrace policy.
Use `disconnect` to leave an attached target running. Use `terminate` to request
termination of a target. Both agent-facing actions now wait for the adapter's
DAP disconnect acknowledgement instead of swallowing a rejected terminate
request and claiming success.

Pi tracks whether the session originated from launch or attach. When the
adapter advertises `supportTerminateDebuggee`, it sends the explicit
`terminateDebuggee` choice. Without that optional capability, it follows DAP's
implicit launch-terminate / attach-preserve rule. A request to terminate an
attached process is rejected locally if the adapter cannot advertise that
choice; the live session remains available for inspection or disconnect.
A live adapter's rejection also leaves the session available. A lost transport
surfaces an error and releases the dead session slot so a future launch is not
permanently blocked.

Preserving a Pi-launched program through `disconnect` is not supported: its
owned process group and temporary build output still belong to this session.
Use `terminate` for that case. Results report the requested disposition and
adapter acknowledgement, not independent proof that an arbitrary external PID
has exited. Cancellation or hard process teardown cannot promise transactional
restoration of an attached application's state. The low-level public
`DapSession::terminate` remains a best-effort SDK/fixture cleanup API; the
agent-facing tool uses the checked path above.

## Retained breakpoint sets

```json
{"action":"set_breakpoint","file":"app.py","line":12}
{"action":"set_breakpoint","file":"app.py","line":24,"condition":"count > 3"}
{"action":"set_breakpoint","file":"app.py","line":30,"logMessage":"count={count}"}
{"action":"remove_breakpoint","file":"app.py","line":12}
{"action":"list_breakpoints"}
```

DAP's set-breakpoint requests replace whole sets. Pi retains the desired set
per source file and per function/instruction/data family. Adding or changing
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
Capabilities and data IDs are adapter-specific. Not every adapter supports
instruction/data breakpoints or logpoints. `list_breakpoints` reports
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
The state model remains coarse/session-wide, not an independent state machine
for every thread. Debug adapters enforce the selected thread's actual state.
Frame and variable references are valid only for their suspension lifetime.

## Transport bounds and validation

Spawn checks the current context's capabilities. Established sessions are not
owned by a completed launch call's cancellation token. Every request checks
I/O/timer capability and cancellation at dispatch. The tool declares process
and network effects. Unix adapter processes have separate owned process groups.

Stdio and TCP share a bounded writer lane rather than performing writes on the
async worker. The queue and pending table each admit at most 32 requests;
outbound frames are capped at 2 MiB. Reverse-request refusals use the same lane.
Output events go to the bounded output tail, not the control-event queue. The
remaining queue holds at most 512 control events, each bounded to 64 KiB of
serialized body. Overflow retires the connection and fails waiters rather than
silently losing execution state. The shared inbound parser caps frames at 64 MiB.

Dropping a request removes its pending sender and revokes queued unsent frames.
A partially written frame retires the connection; reusing it would corrupt later
frames. A dispatch timeout also retires a blocked writer. A complete delivered
request can still execute remotely: local cancellation is not rollback, and Pi
does not automatically retry. OS process cleanup and blocking filesystem calls
are not preemptible hard real-time operations.

The Go/TCP increment adds 15 Rust test functions covering target/mode selection,
actual framed loopback protocol fixtures, compilation budget, private artifacts,
startup cancellation, malformed discovery, output separation and checked target
disposition. Existing debugger tests are retained. Python-backed protocol cases
fail on missing Python when `PI_DEBUG_REQUIRE_PROTOCOL=1`; otherwise they report
a dependency skip. Existing live lldb tests retain their pre-existing skips and
ignored launch-pacing case.

**Implementation-session validation:** neither Rust nor DSR was installed.
`dsr quality --tool pi_agent_rust` returned `dsr: command not found` (127).
The Rust tests were authored, not executed; compilation, rustfmt and Clippy
remain unverified. A separate live debugpy 1.8.20 TCP probe passed five checks:
initialize/capabilities, an attached breakpoint, a stopped external target,
disconnect acknowledgement, and that target remaining alive afterward. The
probe initially assumed the optional termination capability was present; it was
corrected to exercise the implicit attach-preserve behavior and rerun.
That probe does not execute Rust or Delve. Delve was absent, so actual Go
compilation/debugging, Delve attach, and cross-platform behavior remain unverified.
No DSR pass, release readiness or Bead-closure claim follows from this work.

Protocol references: [Delve DAP](https://github.com/go-delve/delve/blob/master/Documentation/api/dap/README.md),
[Delve DAP command](https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv_dap.md),
and [Microsoft DAP specification](https://microsoft.github.io/debug-adapter-protocol/specification).
