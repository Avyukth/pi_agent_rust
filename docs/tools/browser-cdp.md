# Native browser automation (CDP attach)

The browser tool now sends real Chrome DevTools Protocol commands over the
existing asupersync HTTP/WebSocket transports. A connection failure, missing
selector, JavaScript exception, rejected navigation or expired deadline is an
error. Production never substitutes canned results or a one-pixel screenshot.

## Connect a browser

Enable the existing browser setting and include `browser` in the selected tools:

```json
{"browser":{"enable_browser":true}}
```

Start a dedicated Chromium profile in a separate terminal, then start Pi:

```sh
chromium --headless=new --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=9222 --user-data-dir="$HOME/.cache/pi-browser-profile"

PI_BROWSER_CDP_URL=http://127.0.0.1:9222 \
  pi --tools read,write,edit,bash,browser
```

The endpoint defaults to `http://127.0.0.1:9222`. SDK callers can override it with
`BrowserTool::with_cdp_endpoint`. Only IPv4 loopback and `localhost` are accepted;
remote hosts, URL credentials, endpoint query strings and discovery responses
that change the port are rejected. The CDP port grants browser control: do not
expose it to a network or point the tool at a personal browser profile.

This is an **attach backend**, not a browser installer or process launcher.
`executable_path`, `headless`, `user_agent` and `remote_debugging_port` settings do
not configure an already-running process. Pass browser flags at startup and set
`PI_BROWSER_CDP_URL` for a nondefault port. The attached browser/profile remains
running after a tool operation and may retain cookies and login state. Omit
`--headless=new` when an interactive login is needed in that dedicated profile.

## Operations

```json
{"action":"open","tab":"research","url":"https://example.com"}
{"action":"snapshot","tab":"research"}
{"action":"fill","selector":"#search","text":"structured concurrency"}
{"action":"click","selector":"@e3"}
{"action":"press","key":"Ctrl+a"}
{"action":"wait_for","selector":".results","timeout_ms":10000}
{"action":"evaluate","script":"({title: document.title, count: document.links.length})"}
{"action":"screenshot","output_path":"screenshots/research.png"}
```

`open` creates a named blank target when needed, then navigates it. Reusing a
name navigates that target. `goto` requires an existing tab. `list_tabs` reads
actual browser page targets; an unclaimed target is addressed by its target ID.
`close` closes the actual target. “Active” means the tool's selected tab, not a
claim about which desktop window has focus.

Navigation waits for the matching document's DOMContentLoaded/load lifecycle
event, rather than treating a successful command send as a loaded page. Downloads
and CDP navigation errors are not reported as successful page loads.

`snapshot` produces up to 200 meaningful accessibility-backed DOM references.
`ax_tree` additionally returns up to 1,000 actual accessibility nodes and marks
truncation. References retain their identity across snapshots/connections in the
same document. They are not CSS aliases: a detached/replaced node or a new
document makes an old reference unusable. Names are captured, not editable field
values. CSS selectors and references address the main frame; cross-frame
selection is not implemented.

Clicks use native mouse events after checking visibility and obstruction. Text
entry uses native CDP input; `fill` replaces and verifies the retained text,
while `type` inserts at the current selection. Read-only, disabled, detached and
unsupported controls fail explicitly. Key chords support Ctrl/Control,
Alt, Shift and Meta/Cmd/Command. `scroll` accepts `delta_x`/`delta_y` in CSS pixels
(defaults 0/600). `wait_for` polls for visibility and really times out.

Screenshots contain actual viewport pixels. The PNG is saved to the requested
path and returned as an image content block so the model can inspect it without
a separate file read. Input scripts run in an isolated world and receive
arguments as structured CDP values, not interpolated executable source.

## Boundaries and validation

`timeout_ms` bounds the entire operation, including waiting for another call,
connection setup and command replies (default 30 seconds; `wait_for`: 5 seconds;
maximum 120 seconds). Cancellation drops the operation's socket. A remote action
already accepted by Chromium cannot be rolled back by cancellation.

`domain_allowlist` matches parsed hosts, never URL substrings. `example.com` is
exact; `*.example.com` permits proper subdomains; `*` permits any HTTP(S) host.
An empty list denies network navigation. `about:blank` is always allowed.
This is a navigation/access guard, **not network isolation**: attached pages,
subresources and arbitrary `evaluate` scripts can generate network traffic.
Use browser/container network policy for strict isolation.

Deterministic canned behavior is available only through `with_mock(true)` or
`PI_BROWSER_MOCK=1`. `with_mock(false)` overrides that environment variable.

Rust regression coverage is in `tests/browser_cdp.rs` and the browser modules.
The authoritative project validation remains `dsr quality --tool pi_agent_rust`.
The implementation session had no Rust/DSR runner; it did not establish a passing
Rust build. A separate manual Chromium 144 protocol probe passed 26 checks,
including the actual embedded DOM helper, native input, reconnecting backend
node references, stale/detached nodes, screenshot pixels and page prototype
isolation. Its DOM fixture used `about:blank` and `Page.setDocumentContent`
because the container's browser policy rejected HTTP-page navigation. That
probe is not a substitute for compiled adapter or DSR validation.
