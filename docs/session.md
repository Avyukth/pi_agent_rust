# Sessions (JSONL v3)

Pi persists conversations as **JSONL (JSON Lines)** files. Each line is a single JSON object.

- Line 1: a `session` header (metadata, not part of the tree)
- Remaining lines: `SessionEntry` records that form a **tree** via `id` / `parentId`

This file documents the Rust implementation in `src/session.rs` and how interactive commands
(`/resume`, `/tree`, `/fork`) interact with sessions.

## File Location

By default, sessions are stored under the global Pi directory:

```
~/.pi/agent/sessions/
```

You can override the base location via:

- `PI_CODING_AGENT_DIR` → changes the global dir (defaults to `~/.pi/agent`)
- `PI_SESSIONS_DIR` → overrides the sessions root directly

### Per-project directory

Pi stores sessions per working directory (`cwd`) under a folder derived from the current directory:

```
<sessions_dir>/--<cwd-with-separators-replaced>--/
```

Implementation: `encode_cwd()` in `src/session.rs`.

### Session filenames

When a session is first saved, Pi creates a filename like:

```
<timestamp>_<sessionIdPrefix>.jsonl
```

Where:
- `timestamp` is UTC (filename-safe, e.g. `2026-02-03T22-52-06.410Z`)
- `sessionIdPrefix` is the first 8 chars of the session UUID

Implementation: `Session::save()` in `src/session.rs`.

## Header (Line 1)

The first line is the session header:

```json
{"type":"session","version":3,"id":"<uuid>","timestamp":"2026-02-03T22:52:06.410Z","cwd":"/path/to/project"}
```

Common fields:

- `type`: always `"session"`
- `version`: current version is `3`
- `id`: UUID for this session file
- `timestamp`: UTC RFC3339 timestamp (millis)
- `cwd`: working directory string captured at creation time

Optional fields:

- `provider`, `modelId`: last-selected model info (best-effort restore)
- `thinkingLevel`: last-selected thinking level (best-effort restore)
- `branchedFrom`: path to a parent session file (created by `/fork`)

Compatibility note:
- The Rust loader accepts legacy `parentSession` as an alias for `branchedFrom`.

## Entries (Lines 2+)

Each entry is a JSON object with:

- `type`: entry kind (e.g. `"message"`, `"compaction"`)
- `id`: 8-char hex id (generated if missing on load)
- `parentId`: parent entry id, or `null` for the first entry
- `timestamp`: UTC RFC3339 timestamp (millis)

### Message entry (`type: "message"`)

Messages wrap a `message` payload whose `role` selects the variant:

#### User

```json
{"type":"message","id":"a1b2c3d4","parentId":null,"timestamp":"2026-02-03T22:52:06.410Z","message":{"role":"user","content":"Hello","timestamp":1706918401000}}
```

`content` is either:
- a string, or
- a list of `ContentBlock` objects (text/image/etc.)

#### Assistant

```json
{"type":"message","id":"b2c3d4e5","parentId":"a1b2c3d4","timestamp":"2026-02-03T22:52:10.000Z","message":{"role":"assistant","provider":"anthropic","model":"claude-sonnet","usage":{"totalTokens":123},"stopReason":"stop","content":[{"type":"text","text":"Hi!"}],"timestamp":1706918402000}}
```

#### Tool result

```json
{"type":"message","id":"c3d4e5f6","parentId":"b2c3d4e5","timestamp":"2026-02-03T22:52:12.000Z","message":{"role":"toolResult","toolCallId":"call_123","toolName":"bash","isError":false,"content":[{"type":"text","text":"output"}],"timestamp":1706918403000}}
```

#### Custom (extension message)

Extension-injected messages that **do participate** in LLM context:

```json
{"type":"message","id":"d4e5f6a7","parentId":"c3d4e5f6","timestamp":"2026-02-03T22:52:13.000Z","message":{"role":"custom","customType":"my-extension","content":"Injected context...","display":true}}
```

### Model change (`type: "model_change"`)

Recorded when the user changes models:

```json
{"type":"model_change","id":"e5f6g7h8","parentId":"...","timestamp":"...","provider":"openai","modelId":"gpt-4o"}
```

### Thinking level change (`type: "thinking_level_change"`)

```json
{"type":"thinking_level_change","id":"...","parentId":"...","timestamp":"...","thinkingLevel":"high"}
```

### Compaction (`type: "compaction"`)

Stores an LLM-generated summary of earlier context plus a `firstKeptEntryId` marker:

```json
{"type":"compaction","id":"...","parentId":"...","timestamp":"...","summary":"...","firstKeptEntryId":"...","tokensBefore":50000}
```

### Branch summary (`type: "branch_summary"`)

Stored when switching branches via `/tree` (optional):

```json
{"type":"branch_summary","id":"...","parentId":"...","timestamp":"...","fromId":"<oldLeafId>","summary":"..."}
```

### Label (`type: "label"`)

```json
{"type":"label","id":"...","parentId":"...","timestamp":"...","targetId":"<entryId>","label":"checkpoint"}
```

### Session info (`type: "session_info"`)

Set via `/name`:

```json
{"type":"session_info","id":"...","parentId":"...","timestamp":"...","name":"Refactor auth module"}
```

### Custom entry (`type: "custom"`)

Extension state that **does not participate** in LLM context:

```json
{"type":"custom","id":"...","parentId":"...","timestamp":"...","customType":"my-extension","data":{"count":42}}
```

## Tree Structure and Leaf

Entries form a tree; `parentId` links point backward.

- The session file stores the full tree (all branches).
- The interactive UI tracks a **current leaf** (`Session.leaf_id`) in memory.
- On load, the Rust implementation sets `leaf_id` to the **last entry in the file**.

The “current path” used for LLM context is the path from `leaf_id` back to the root.

## How Commands Affect Sessions

### `/resume`

Opens the session picker and loads a session file. The UI supports:
- Navigate with arrows / `j` / `k`
- Delete with `Ctrl+D` (then confirm with `y` / cancel with `n` / `Esc`)

Deletion prefers the `trash` CLI if available; otherwise it removes the file directly.

Implementation: `PiApp::load_session_from_path()` and `PiApp::delete_session_file()` in `src/interactive.rs`.

### `/tree`

Navigates within the **same session file** by changing the in-memory leaf and (optionally)
writing a `branch_summary` entry when leaving a branch.

Implementation: `TreeUiState` in `src/interactive.rs`, plus `Session` tree helpers in `src/session.rs`.

### `/fork`

Creates a **new session file** (with `branchedFrom` pointing at the previous session file),
switches to it, and pre-fills the editor so the selected user message can be edited/re-submitted.

Key semantics (legacy-compatible):
- The fork is created from the **parent** of the selected user message, so the next user submit
  branches cleanly (no consecutive user messages).

Implementation: `SlashCommand::Fork` in `src/interactive.rs`.

## Implementation Pointers

- `src/session.rs`:
  - `Session::save()` (path/filename scheme)
  - `SessionEntry`, `SessionMessage` (serialization)
  - `Session::get_path_to_entry()`, `entries_for_current_path()` (tree traversal)
  - `Session::to_messages_for_current_path()` (context building + compaction handling)
- `src/interactive.rs`:
  - `/resume` picker + deletion UX
  - `/tree` navigator
  - `/fork` session extraction + switch

