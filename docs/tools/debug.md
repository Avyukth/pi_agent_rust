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

Initial source breakpoints and exception filters work for launch and attach.
Sources are grouped by normalized path, configured after `initialized`, and
acknowledged before `configurationDone`. Launch/attach is awaited concurrently
because some adapters defer its response until configuration ends. A failed
configuration never becomes the current session. `configurationDone` is sent
only when advertised; optional breakpoint features and exception filter IDs
must also be advertised. `sessions` includes the adapter's capabilities.

`stopOnEntry` defaults to true for launch. Results contain the observed state,
not an invented entry stop. End an existing session before starting another;
a second launch cannot silently replace it. Built-in lldb-dap and debugpy use
stdio; Delve uses the owned loopback TCP transport below. Trusted SDK hosts may
supply `AdapterSpec` definitions through `DebugTool::with_adapters`; the `dlv`
ID selects Delve's transport. Executables resolve to actual absolute paths
before changing the child working directory. The model cannot select an
arbitrary executable. Pi does not install or sandbox debugger adapters.

## Go programs, packages and tests

Install Delve (`dlv`) and the Go toolchain separately. Go source files and
package directories containing Go files or `go.mod` select Delve when its
registered executable exists. Auto-selection's directory scan is bounded;
`adapter: "dlv"` selects it explicitly.

```json
{
  "action": "launch",
  "program": "./cmd/server",
  "adapter": "dlv",
  "args": ["--port", "8080"],
  "initialBreakpoints": [{"file": "cmd/server/main.go", "line": 24}],
  "startupTimeoutMs": 180000
}
```

Go mode is inferred as `debug` for a source or package directory, `test` for a
`_test.go` file, and `exec` for a prebuilt binary. `goMode` is a launch-only
override. A compiled Go binary needs `adapter: "dlv"`; its filename does not
reliably identify the source language.

```json
{"action":"launch","program":"./bin/server","adapter":"dlv","goMode":"exec"}
{"action":"launch","program":"./parser","goMode":"test","args":["-test.run","^TestParse$","-test.v"]}
```

Delve performs source/test compilation. Argument arrays are literal, not shell
source. Build output goes into a private temporary directory owned by the
session, retained until after adapter cleanup. Pi does not choose a fixed
workspace build filename or overwrite the target. Toolchain caches and module
downloads remain normal Go side effects. Build flags, remote package import
paths, remote servers and replay/core modes are not exposed here.

`startupTimeoutMs` covers the launch/attach request and initial configuration
with one budget, default 120 seconds, maximum 300 seconds. It includes Go
compilation, but excludes adapter discovery, initialize and the optional entry
stop wait. Failed or cancelled startup drops its unadopted adapter and artifacts.

### Delve connection and ownership

Pi starts `dlv dap --listen=127.0.0.1:0 --only-same-user=true`. It parses the
owned process's bounded readiness announcement instead of reserving/releasing
a port for another process to race. Discovery requires the expected IPv4
loopback binding and a nonzero port. Invalid discovery, process exit, timeout
or connect failure does not try another server.

Socket connection runs off the async worker with its own deadline. TCP carries
DAP frames; Delve/debuggee stdout and stderr feed a separate bounded output
tail, never the protocol decoder. Session closure shuts down both socket
directions before process cleanup to wake blocked reader/writer lanes. The
model cannot supply an endpoint or disable the same-user restriction. These
controls do not authenticate against other code running as the same OS user.
Use an isolated development environment for untrusted programs or adapters.

## Attach, disconnect and termination

```json
{"action":"attach","adapter":"dlv","pid":4242}
{"action":"disconnect"}
```

OS debugger permissions still apply; Pi does not elevate privileges or relax
ptrace policy. `disconnect` requests preservation of an attached target;
`terminate` requests termination. Both wait for the DAP disconnect response.
Results report the requested disposition and adapter acknowledgement, not
independent proof that an arbitrary external PID exited.

The session records launch versus attach origin. With `supportTerminateDebuggee`
it sends the explicit termination choice. Without that optional capability,
DAP's implicit launch-terminate / attach-preserve rule applies. An unsupported
request to terminate an attached process fails locally; an adapter rejection
also leaves the live session available. A dead transport releases the session
slot rather than blocking future launches permanently.

Preserving a Pi-launched program through `disconnect` is unsupported because
its process group and temporary build outputs still belong to Pi. Use
`terminate`. Cancellation or hard teardown cannot promise transactional
restoration of an attached application's state. Low-level SDK
`DapSession::terminate` remains best-effort cleanup; the tool uses checked
acknowledgements instead.

## Retained breakpoint sets

```json
{"action":"set_breakpoint","file":"app.py","line":12}
{"action":"set_breakpoint","file":"app.py","line":24,"condition":"count > 3"}
{"action":"set_breakpoint","file":"app.py","line":30,"logMessage":"count={count}"}
{"action":"remove_breakpoint","file":"app.py","line":12}
{"action":"list_breakpoints"}
```

DAP replaces entire breakpoint sets. Pi retains one set per source and per
function/instruction/data family, so editing one entry does not erase peers.
Source keys are line plus optional column; function keys are names; instruction
keys are reference plus offset; data keys are opaque IDs. Repeating a key updates
it. Returned adapter IDs, actual positions, verification and messages remain
visible. An unverified breakpoint is not reported as verified.

Remove with a key to delete one entry. Omit line to clear a file, or omit the
family's name/reference/dataId to clear that set. Conditions, hit conditions
and source logpoints require advertised capabilities. Limits are 1,024 total
breakpoints and 256 sets. Failed, malformed or abandoned updates mark a set
unsynchronized; the next edit resends its retained full configuration. Inventory
is last-acknowledged configuration, not a live view of asynchronous rebinding.

```json
{"action":"set_function_breakpoint","name":"parse_record"}
{"action":"set_instruction_breakpoint","reference":"0x401000","offset":4}
{"action":"data_breakpoint_info","name":"count"}
{"action":"set_data_breakpoint","dataId":"<returned opaque dataId>","accessType":"write"}
{"action":"remove_data_breakpoint","dataId":"<returned opaque dataId>"}
```

For a variable inside an object, supply its parent's `variablesReference` to
`data_breakpoint_info`; an optional frame must belong to the same suspension.
Use the returned dataId, not the variable name, for data-breakpoint changes.

## Thread-aware execution and diagnosis

```json
{"action":"threads"}
{"action":"stack_trace","threadId":7,"start":0,"limit":20}
{"action":"step_over","threadId":7,"singleThread":true,"granularity":"line"}
{"action":"continue","threadId":7,"singleThread":true}
{"action":"pause","threadId":7}
{"action":"exception_info","threadId":7}
```

Thread IDs above are illustrative: use the actual IDs returned by `threads`.
`threads`, `sessions`, launch and execution results include a bounded per-thread
state view. Aggregate `state: stopped` means a known thread is stopped, not that
every thread is stopped. Each stopped thread retains its reason, revision and
available description/text/hit-breakpoint IDs. `preserveFocusHint` is respected
when choosing the default stopped thread.

An absent `allThreadsStopped` flag stops only the indicated thread; an absent
`allThreadsContinued` flag resumes all threads. Explicit partial events preserve
unaffected peers. Thread start/exit events update membership. A threads response
racing a newer event does not overwrite that event's membership; query again to
refresh. Missing or malformed control state fails explicitly. At most 4,096
threads are tracked.

`singleThread` is available for continue and step operations only and requires
`supportsSingleThreadExecutionRequests`. Step `granularity` accepts statement,
line or instruction, gated by `supportsSteppingGranularity`. Unsupported options
fail before execution rather than being ignored. Pause without an ID queries
threads and prefers a running one. Pausing an already stopped selected thread
returns `alreadyStopped: true` without claiming a new input event.

Resume invalidates the relevant old stop before dispatch. A fresh stop before
the response wins. Rejection restores only transitions still owned by that
request; it cannot undo a later event on the same or another thread. Partial
continue replies preserve untouched peers. Step/pause waits require a fresh
stop, and a single-thread wait requires that thread rather than an already
stopped peer. They wait up to five seconds; a null stop is not a claim that the
program stopped. Cancellation/timeout cannot roll back accepted execution.

`exception_info` requires a stopped selected thread and
`supportsExceptionInfoRequest`. It returns the actual exception ID, break mode,
description and available structured details, including stack traces and nested
causes. Missing mandatory response fields are errors, not invented diagnoses.

## Expand and modify suspended objects

Start with `stack_trace` or `evaluate`, then use returned handles:

```json
{"action":"evaluate","expression":"record","context":"watch","threadId":7}
{"action":"scopes","frameId":1001}
{"action":"variables","variablesReference":1002,"filter":"named","start":0,"limit":20}
{"action":"set_variable","variablesReference":1002,"name":"count","value":"41"}
{"action":"set_expression","expression":"record[\"answer\"]","value":"99","threadId":7}
```

Numbers 1001 and 1002 are placeholders for returned handles, not raw adapter IDs.
`frameId` and `variablesReference` are now **opaque Pi handles** bound to one
thread and suspension. Zero variablesReference still means no children. Passing
a frame handle as an object handle, a stale handle, or a handle with another
thread's ID fails before using it. Reused adapter IDs after stepping or session
restart receive different local handles. Handle IDs remain JSON-safe integers
and are not reused within the running Pi process. They are not persistent IDs
across restarting the Pi process.

Evaluation defaults to the selected stopped thread's top frame. Its response
retains child counts, type, presentation hints and memory references; variables
and stack frames support paging. Refer to returned evaluateName expressions
rather than assuming a display label is a valid language expression. Unsupported
raw location-reference fields are omitted rather than exposed as usable handles.

`set_variable` changes a named child of a parent container; `set_expression`
assigns a language expression in a frame. They require `supportsSetVariable`
and `supportsSetExpression`, respectively. `value` is a NUL-free string of at
most 64 KiB, interpreted by the debuggee's language, not a host shell. Empty
strings are passed through for the adapter to validate. Responses preserve the
actual returned value/type and any new expandable object handle.

Assignments change live process state. Object/container handles for that thread
are revoked **before** dispatch, including on future cancellation or malformed
acknowledgement. Refresh scopes/evaluation after assignment. Existing frame
handles remain usable only while their suspension and inspection epoch remain
valid. A returned error does not imply that a remote assignment was undone.
Evaluation itself may execute language code with side effects.

Known resumes invalidate the affected thread's handles; unaffected stopped peers
retain theirs. DAP `invalidated` events conservatively expire all frame/object
handles, even when the event contains narrower hints. An inspection response
racing a resume or invalidation is discarded instead of exposing stale IDs.
Mutation replies may install new handles after an invalidation caused by that
mutation, provided the thread remains in the same stop. At most 8,192 live
frame/object handles are retained; oversized result sets fail explicitly.

Typed lifecycle, execution, breakpoint and inspection commands cannot be sent
through `custom_request`. Other vendor requests expire all inspection handles
before dispatch because their effects are not known. For SDK users,
`DapSession::call` is raw DAP; `call_stopped` translates managed handles for typed
inspection. Do not mix raw and managed IDs. Memory/instruction reference strings
remain adapter-specific and are not part of the managed frame/object namespace.
These checks are not OS isolation or transactional execution guarantees.

## Transport bounds and validation status

Sessions own their adapter processes and Unix process groups, not the completed
launch call's cancellation token. Dispatch checks capabilities and cancellation.
Stdin writes and reverse-request refusals use a bounded dedicated writer lane,
not blocking writes on an async worker. Outbound frames are capped at 2 MiB;
the writer queue and pending table each allow at most 32 requests. Dropped
requests remove pending waiters and revoke unsent frames. A partial cancelled
write retires the stream; already delivered requests may execute remotely and
are not retried automatically.

Output events go to the bounded output tail, not the 512-entry control queue.
Control messages are limited to 64 KiB each; overflow retires the connection
instead of silently dropping stopped/initialized state. Incoming framing retains
the shared parser's 64 MiB per-frame cap. Socket/pipe cleanup and blocking local
filesystem operations are not preemptible hard real-time operations.

The thread/inspection increment adds 26 Rust test functions: ten execution-state
cases, five handle cases, one invalidation-state case, and ten tool-level cases.
Existing debugger/Delve tests are retained and the two raw-ID assumptions in the
older tool tests are updated to use returned handles. Protocol fixtures check
partial resume, both step response orders, peer preservation, ID reuse, assignment
wire shapes, missing capabilities and invalidation during a response. Python-backed
cases fail on missing Python with `PI_DEBUG_REQUIRE_PROTOCOL=1`, otherwise report
a dependency skip. None of these new Rust tests ran in the implementation session.

The authoritative entry point remains:

```sh
dsr quality --tool pi_agent_rust
```

This environment has neither Rust nor DSR installed; the invocation returned
`dsr: command not found` (127). Compilation, rustfmt/Clippy and the Rust tests
remain unverified. A separate live debugpy probe passed 12 raw-protocol checks:
a two-thread program stopped at a breakpoint, scoped values were inspected and
modified with setVariable/setExpression, an updated object was expanded, and a
real ValueError was diagnosed with exceptionInfo. Debugpy did not advertise
single-thread execution in that probe, so single-thread behavior has authored
unit/protocol coverage only. The probe does not execute Pi's Rust state machine,
managed-handle layer or adapters. No build, DSR pass, cross-platform result,
Delve live validation, release readiness or Bead closure is claimed.

Protocol references: [Microsoft DAP specification](https://microsoft.github.io/debug-adapter-protocol/specification),
[Delve DAP](https://github.com/go-delve/delve/blob/master/Documentation/api/dap/README.md),
and [Delve DAP command](https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv_dap.md).
