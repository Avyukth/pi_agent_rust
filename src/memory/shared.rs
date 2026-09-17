//! Session-scoped shared memory for cooperating agents (bd-1i2pn).
//!
//! Keys live in the project's SQLite bank, separate from facts and their FTS
//! index. The host supplies the session identity; tool arguments cannot select
//! another session. Compaction and same-session branch navigation retain keys.
//! A new/forked session id starts an isolated namespace; switching back or
//! reopening the same project/session recovers its keys. Nothing is copied or
//! injected into the project mental model or reflection corpus automatically.
//!
//! SQLite avoids a model-controlled path and atomically couples the content,
//! revision and quota checks. Shared values preserve exact text (unlike the
//! durable-fact screener); write acknowledgements and errors never echo values.

use super::{MemoryStore, now_ms};
use crate::agent_cx::AgentCx;
use crate::error::{Error, Result};
use crate::jobs::JobSessionScope;
use crate::session_sqlite::SqliteConnection;
use crate::tools::{Tool, ToolEffects, ToolOutput, ToolRegistry, ToolUpdate};
use fsqlite::{Row, SqliteValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

pub mod delegation;

pub const SHARED_MEMORY_SCHEMA: &str = "pi.memory.shared.v1";
pub const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_KEY_BYTES: usize = 128;
const MAX_SESSION_BYTES: usize = 512;
const MAX_SESSION_KEYS: i64 = 512;
const MAX_SESSION_VALUE_BYTES: i64 = 4 * 1024 * 1024;
const MAX_PROJECT_KEYS: i64 = 8192;
const MAX_PROJECT_VALUE_BYTES: i64 = 64 * 1024 * 1024;
const MAX_LIST_LIMIT: usize = 50;
const PREVIEW_CHARS: usize = 160;

const INIT_SQL: &str = "CREATE TABLE IF NOT EXISTS pi_shared_memory (
    session_id TEXT NOT NULL,
    memory_key TEXT NOT NULL,
    content TEXT NOT NULL,
    content_bytes INTEGER NOT NULL,
    revision TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (session_id, memory_key)
)";

fn failure(code: &str, message: &str) -> Error {
    Error::tool("memory", format!("{code}: {message}"))
}

fn storage_error() -> Error {
    failure(
        "PI_SHARED_MEMORY_STORAGE",
        "Shared memory storage operation failed",
    )
}

fn validate_session(session_id: &str) -> Result<()> {
    if session_id.trim().is_empty()
        || session_id.len() > MAX_SESSION_BYTES
        || session_id.chars().any(char::is_control)
    {
        return Err(failure(
            "PI_SHARED_MEMORY_SESSION_UNAVAILABLE",
            "A non-empty, bounded host session identity is required",
        ));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || !key.as_bytes()[0].is_ascii_alphanumeric()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(failure(
            "PI_SHARED_MEMORY_INVALID_KEY",
            "Keys must start with an ASCII letter or digit and contain at most 128 letters, digits, dots, underscores or hyphens",
        ));
    }
    Ok(())
}

fn valid_revision(revision: &str) -> bool {
    revision.len() == 32 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn conflict() -> Error {
    failure(
        "PI_SHARED_MEMORY_CONFLICT",
        "The key changed or already exists; read it and retry with its current revision",
    )
}

fn text(value: &str) -> SqliteValue {
    SqliteValue::Text(value.to_string().into())
}

fn string_column(row: &Row, index: usize) -> Result<String> {
    match row.values().get(index) {
        Some(SqliteValue::Text(value)) => Ok(value.to_string()),
        _ => Err(storage_error()),
    }
}

fn integer_column(row: &Row, index: usize) -> Result<i64> {
    match row.values().get(index) {
        Some(SqliteValue::Integer(value)) if *value >= 0 => Ok(*value),
        _ => Err(storage_error()),
    }
}

/// Metadata returned after an atomic write. Acknowledgement does not echo data.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedMemoryVersion {
    pub key: String,
    pub revision: String,
    pub bytes: usize,
    pub updated_at_ms: i64,
}

/// Complete value and its revision from a single database snapshot.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedMemoryValue {
    #[serde(flatten)]
    pub version: SharedMemoryVersion,
    pub content: String,
}

impl std::fmt::Debug for SharedMemoryValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedMemoryValue")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedMemorySummary {
    #[serde(flatten)]
    pub version: SharedMemoryVersion,
    pub preview: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedMemoryPage {
    pub entries: Vec<SharedMemorySummary>,
    /// Last returned key when more entries exist. Pass as `after` on the next call.
    pub next_cursor: Option<String>,
}

/// An immutable binding. A tool resolves its live session exactly once before
/// creating this view, so an in-flight write cannot be retargeted by a switch.
#[derive(Clone)]
pub struct SharedMemoryStore {
    bank: Arc<MemoryStore>,
    session_id: String,
}

impl SharedMemoryStore {
    /// Bind a project's bank to an explicitly authorized session. No I/O occurs.
    pub fn new(bank: Arc<MemoryStore>, session_id: impl Into<String>) -> Result<Self> {
        let session_id = session_id.into();
        validate_session(&session_id)?;
        Ok(Self { bank, session_id })
    }

    fn with_conn<T: Send>(
        &self,
        action: impl FnOnce(&SqliteConnection) -> Result<T> + Send,
    ) -> Result<T> {
        self.bank.with_conn(|conn| {
            conn.execute_raw(INIT_SQL).map_err(|_| storage_error())?;
            action(conn)
        })
    }

    /// Read only this bound session. Missing and other-session keys are identical.
    pub fn read(&self, key: &str) -> Result<Option<SharedMemoryValue>> {
        validate_key(key)?;
        self.with_conn(|conn| {
            let rows = conn
                .query_sync(
                    "SELECT memory_key, revision, content_bytes, updated_at_ms, content \
                 FROM pi_shared_memory WHERE session_id = ?1 AND memory_key = ?2",
                    &[text(&self.session_id), text(key)],
                )
                .map_err(|_| storage_error())?;
            let Some(row) = rows.first() else {
                return Ok(None);
            };
            let version = version_from_row(row)?;
            let content = string_column(row, 4)?;
            if content.len() != version.bytes || content.len() > MAX_VALUE_BYTES {
                return Err(storage_error());
            }
            Ok(Some(SharedMemoryValue { version, content }))
        })
    }

    /// Create or replace a key. `expected_revision = Some("absent")` creates
    /// only; another revision replaces only that exact version; `None` opts in
    /// to last-writer-wins. Every successful write creates a fresh revision,
    /// including identical content, preventing an ABA overwrite of newer work.
    #[allow(clippy::too_many_lines)] // Keep reservation, preconditions and mutation adjacent.
    pub fn write(
        &self,
        key: &str,
        content: &str,
        expected_revision: Option<&str>,
    ) -> Result<SharedMemoryVersion> {
        validate_key(key)?;
        if content.len() > MAX_VALUE_BYTES {
            return Err(failure(
                "PI_SHARED_MEMORY_VALUE_LIMIT",
                "Shared values are limited to 65536 UTF-8 bytes",
            ));
        }
        if expected_revision
            .is_some_and(|revision| revision != "absent" && !valid_revision(revision))
        {
            return Err(failure(
                "PI_SHARED_MEMORY_INVALID_REVISION",
                "Use a returned revision or 'absent'",
            ));
        }
        let bytes = i64::try_from(content.len()).map_err(|_| storage_error())?;
        self.with_conn(|conn| {
            super::transactions::run(conn, |conn| {
                let rows = conn
                    .query_sync(
                        "SELECT revision, content_bytes FROM pi_shared_memory \
                 WHERE session_id = ?1 AND memory_key = ?2",
                        &[text(&self.session_id), text(key)],
                    )
                    .map_err(|_| storage_error())?;
                let old = rows.first();
                let old_revision = old.map(|row| string_column(row, 0)).transpose()?;
                let matches = match expected_revision {
                    None => true,
                    Some("absent") => old.is_none(),
                    Some(expected) => old_revision.as_deref() == Some(expected),
                };
                if !matches {
                    return Err(conflict());
                }
                let old_bytes = old
                    .map(|row| integer_column(row, 1))
                    .transpose()?
                    .unwrap_or(0);
                check_quota(
                    conn,
                    Some(&self.session_id),
                    old.is_none(),
                    old_bytes,
                    bytes,
                )?;
                check_quota(conn, None, old.is_none(), old_bytes, bytes)?;
                let revision = uuid::Uuid::new_v4().simple().to_string();
                let updated_at_ms = now_ms();
                if old.is_some() {
                    conn.execute_sync(
                        "UPDATE pi_shared_memory SET content = ?1, content_bytes = ?2, \
                     revision = ?3, updated_at_ms = ?4 WHERE session_id = ?5 AND memory_key = ?6",
                        &[
                            text(content),
                            SqliteValue::Integer(bytes),
                            text(&revision),
                            SqliteValue::Integer(updated_at_ms),
                            text(&self.session_id),
                            text(key),
                        ],
                    )
                    .map_err(|_| storage_error())?;
                } else {
                    conn.execute_sync(
                        "INSERT INTO pi_shared_memory \
                     (content, content_bytes, revision, updated_at_ms, session_id, memory_key) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        &[
                            text(content),
                            SqliteValue::Integer(bytes),
                            text(&revision),
                            SqliteValue::Integer(updated_at_ms),
                            text(&self.session_id),
                            text(key),
                        ],
                    )
                    .map_err(|_| storage_error())?;
                }
                Ok(SharedMemoryVersion {
                    key: key.to_string(),
                    revision,
                    bytes: content.len(),
                    updated_at_ms,
                })
            })
        })
    }

    /// Explicit host cleanup: remove only the observed version of a key in
    /// this session. No automatic eviction or cross-session garbage collection.
    /// Returns false for an absent key; a different live revision is a conflict.
    pub fn remove(&self, key: &str, expected_revision: &str) -> Result<bool> {
        validate_key(key)?;
        if !valid_revision(expected_revision) {
            return Err(failure(
                "PI_SHARED_MEMORY_INVALID_REVISION",
                "Removal requires the observed revision",
            ));
        }
        self.with_conn(|conn| {
            super::transactions::run(conn, |conn| {
                let rows = conn.query_sync(
                "SELECT revision FROM pi_shared_memory WHERE session_id = ?1 AND memory_key = ?2",
                &[text(&self.session_id), text(key)],
            ).map_err(|_| storage_error())?;
                let Some(row) = rows.first() else {
                    return Ok(false);
                };
                if string_column(row, 0)? != expected_revision {
                    return Err(conflict());
                }
                conn.execute_sync(
                    "DELETE FROM pi_shared_memory WHERE session_id = ?1 AND memory_key = ?2",
                    &[text(&self.session_id), text(key)],
                )
                .map_err(|_| storage_error())?;
                Ok(true)
            })
        })
    }

    /// List a bounded key-ordered page. Prefix matching is literal, including
    /// underscores. Cursors are session-local lookup bounds, not authority.
    /// Pages are live views rather than a transaction spanning multiple calls.
    pub fn list(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<SharedMemoryPage> {
        if !prefix.is_empty() {
            validate_key(prefix)?;
        }
        if let Some(after) = after {
            validate_key(after)?;
        }
        if !(1..=MAX_LIST_LIMIT).contains(&limit) {
            return Err(failure(
                "PI_SHARED_MEMORY_LIST_LIMIT",
                "List limit must be between 1 and 50",
            ));
        }
        let upper = format!("{prefix}\u{7f}");
        self.with_conn(|conn| {
            let rows = conn.query_sync(
                "SELECT memory_key, revision, content_bytes, updated_at_ms, substr(content, 1, 160) \
                 FROM pi_shared_memory WHERE session_id = ?1 AND memory_key >= ?2 \
                 AND memory_key < ?3 AND memory_key > ?4 ORDER BY memory_key ASC LIMIT ?5",
                &[text(&self.session_id), text(prefix), text(&upper), text(after.unwrap_or("")),
                  SqliteValue::Integer(i64::try_from(limit + 1).map_err(|_| storage_error())?)],
            ).map_err(|_| storage_error())?;
            let has_more = rows.len() > limit;
            let mut entries = Vec::with_capacity(rows.len().min(limit));
            for row in rows.iter().take(limit) {
                entries.push(SharedMemorySummary {
                    version: version_from_row(row)?,
                    preview: string_column(row, 4)?.chars().take(PREVIEW_CHARS).collect(),
                });
            }
            let next_cursor = if has_more {
                entries.last().map(|entry| entry.version.key.clone())
            } else { None };
            Ok(SharedMemoryPage { entries, next_cursor })
        })
    }
}

fn version_from_row(row: &Row) -> Result<SharedMemoryVersion> {
    let bytes = usize::try_from(integer_column(row, 2)?).map_err(|_| storage_error())?;
    if bytes > MAX_VALUE_BYTES {
        return Err(storage_error());
    }
    Ok(SharedMemoryVersion {
        key: string_column(row, 0)?,
        revision: string_column(row, 1)?,
        bytes,
        updated_at_ms: integer_column(row, 3)?,
    })
}

fn check_quota(
    conn: &SqliteConnection,
    session: Option<&str>,
    creates_key: bool,
    previous_bytes: i64,
    next_bytes: i64,
) -> Result<()> {
    let (sql, params, max_keys, max_bytes) = session.map_or_else(
        || (
            "SELECT COUNT(*), COALESCE(SUM(content_bytes), 0) FROM pi_shared_memory",
            Vec::new(), MAX_PROJECT_KEYS, MAX_PROJECT_VALUE_BYTES,
        ),
        |session| (
            "SELECT COUNT(*), COALESCE(SUM(content_bytes), 0) FROM pi_shared_memory WHERE session_id = ?1",
            vec![text(session)], MAX_SESSION_KEYS, MAX_SESSION_VALUE_BYTES,
        ),
    );
    let rows = conn.query_sync(sql, &params).map_err(|_| storage_error())?;
    let row = rows.first().ok_or_else(storage_error)?;
    let count = integer_column(row, 0)?;
    let used = integer_column(row, 1)?;
    if used < previous_bytes
        || count.saturating_add(i64::from(creates_key)) > max_keys
        || used
            .saturating_sub(previous_bytes)
            .saturating_add(next_bytes)
            > max_bytes
    {
        return Err(failure(
            "PI_SHARED_MEMORY_CAPACITY",
            "Shared memory key or byte capacity is exhausted; existing values were preserved",
        ));
    }
    Ok(())
}

pub(super) fn session_requested(input: &Value) -> Result<bool> {
    match input.get("scope") {
        None => Ok(false),
        Some(Value::String(scope)) if scope == "project" => Ok(false),
        Some(Value::String(scope)) if scope == "session" => Ok(true),
        _ => Err(failure(
            "PI_SHARED_MEMORY_INVALID_SCOPE",
            "scope must be 'project' or 'session'",
        )),
    }
}

fn invalid_input() -> Error {
    failure(
        "PI_SHARED_MEMORY_INVALID_INPUT",
        "Invalid shared-memory arguments; session identity is host-controlled",
    )
}

fn scoped_input(mut input: Value) -> Result<Value> {
    if input.get("scope").is_some() && !session_requested(&input)? {
        return Err(failure(
            "PI_SHARED_MEMORY_INVALID_SCOPE",
            "This operation requires session scope",
        ));
    }
    // Optional means absent, not a null value that silently weakens a write
    // precondition or turns a read into a list when called outside validation.
    for key in ["key", "expectedRevision", "prefix", "after"] {
        if input.get(key).is_some_and(|value| !value.is_string()) {
            return Err(invalid_input());
        }
    }
    if input
        .get("limit")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(invalid_input());
    }
    if let Some(object) = input.as_object_mut() {
        object.remove("scope");
    }
    Ok(input)
}

fn parse_input<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(scoped_input(input)?).map_err(|_| invalid_input())
}

async fn bound_store(
    bank: &Arc<MemoryStore>,
    scope: Option<&JobSessionScope>,
) -> Result<SharedMemoryStore> {
    let owner = AgentCx::for_current_or_request();
    let checkpoint = || {
        owner.checkpoint().map_err(|_| {
            failure(
                "PI_SHARED_MEMORY_CANCELLED",
                "Shared memory operation cancelled before dispatch",
            )
        })
    };
    checkpoint()?;
    if !owner.capabilities().io {
        return Err(failure(
            "PI_SHARED_MEMORY_PERMISSION",
            "Shared memory requires I/O capability",
        ));
    }
    let scope = scope.ok_or_else(|| {
        failure(
            "PI_SHARED_MEMORY_SESSION_UNAVAILABLE",
            "Shared memory requires a bound session; no global fallback is used",
        )
    })?;
    let session_id = scope.session_id().await.map_err(|_| {
        failure(
            "PI_SHARED_MEMORY_SESSION_UNAVAILABLE",
            "The current session identity is unavailable",
        )
    })?;
    checkpoint()?;
    // Once dispatched, a synchronous SQLite mutation commits or rolls back;
    // do not report a late cancellation as though committed data were undone.
    SharedMemoryStore::new(Arc::clone(bank), session_id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriteInput {
    key: String,
    content: String,
    expected_revision: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadOrListInput {
    key: Option<String>,
    prefix: Option<String>,
    after: Option<String>,
    limit: Option<usize>,
}

pub(super) async fn write_output(
    bank: &Arc<MemoryStore>,
    scope: Option<&JobSessionScope>,
    input: Value,
) -> Result<ToolOutput> {
    let input: WriteInput = parse_input(input)?;
    let store = bound_store(bank, scope).await?;
    let version = store.write(
        &input.key,
        &input.content,
        input.expected_revision.as_deref(),
    )?;
    Ok(super::text_output(
        format!(
            "Stored shared key {} ({} bytes); revision {}",
            version.key, version.bytes, version.revision
        ),
        json!({"schema": SHARED_MEMORY_SCHEMA, "scope": "session", "value": version}),
        false,
    ))
}

pub(super) async fn read_or_list_output(
    bank: &Arc<MemoryStore>,
    scope: Option<&JobSessionScope>,
    input: Value,
) -> Result<ToolOutput> {
    let input: ReadOrListInput = parse_input(input)?;
    let store = bound_store(bank, scope).await?;
    if let Some(key) = input.key {
        if input.prefix.is_some() || input.after.is_some() || input.limit.is_some() {
            return Err(failure(
                "PI_SHARED_MEMORY_INVALID_INPUT",
                "A key read cannot also request listing options",
            ));
        }
        let value = store.read(&key)?.ok_or_else(|| {
            failure(
                "PI_SHARED_MEMORY_NOT_FOUND",
                "No shared value exists for this key in the current session",
            )
        })?;
        return Ok(super::text_output(
            value.content.clone(),
            json!({"schema": SHARED_MEMORY_SCHEMA, "scope": "session", "value": value}),
            false,
        ));
    }
    let page = store.list(
        input.prefix.as_deref().unwrap_or(""),
        input.after.as_deref(),
        input.limit.unwrap_or(25),
    )?;
    let lines = page
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{} ({} bytes), revision {}",
                entry.version.key, entry.version.bytes, entry.version.revision
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(super::text_output(
        if lines.is_empty() {
            "No shared keys in this session match the request.".to_string()
        } else {
            lines
        },
        json!({"schema": SHARED_MEMORY_SCHEMA, "scope": "session", "entries": page.entries, "nextCursor": page.next_cursor}),
        false,
    ))
}

#[derive(Clone, Copy)]
enum Operation {
    Read,
    Write,
    List,
}

/// Dedicated native tools for SDK/custom registries.
///
/// Registration binds the same live session scope as the existing registry
/// tools; standalone callers must explicitly call `bind_job_session_scope`. The
/// built-in retain/recall surfaces offer the same implementation with
/// `scope: "session"`.
pub struct SharedMemoryTool {
    bank: Arc<MemoryStore>,
    scope: Option<JobSessionScope>,
    operation: Operation,
}

impl SharedMemoryTool {
    #[must_use]
    pub const fn read(bank: Arc<MemoryStore>) -> Self {
        Self {
            bank,
            scope: None,
            operation: Operation::Read,
        }
    }
    #[must_use]
    pub const fn write(bank: Arc<MemoryStore>) -> Self {
        Self {
            bank,
            scope: None,
            operation: Operation::Write,
        }
    }
    #[must_use]
    pub const fn list(bank: Arc<MemoryStore>) -> Self {
        Self {
            bank,
            scope: None,
            operation: Operation::List,
        }
    }
}

impl ToolRegistry {
    /// Install all three native shared-memory tools in this registry. They
    /// inherit its live session binding, including later session changes.
    /// Collision preflight leaves the registry unchanged rather than shadowing
    /// an existing or temporarily inactive extension tool.
    pub fn enable_shared_memory(&mut self, bank: Arc<MemoryStore>) -> Result<()> {
        for name in ["read_memory", "write_memory", "list_memory"] {
            if self.get(name).is_some()
                || self.inactive_tools().iter().any(|tool| tool.name() == name)
            {
                return Err(failure(
                    "PI_SHARED_MEMORY_TOOL_COLLISION",
                    "A shared-memory tool name is already registered",
                ));
            }
        }
        let tools: Vec<Box<dyn Tool>> = vec![
            Box::new(SharedMemoryTool::read(Arc::clone(&bank))),
            Box::new(SharedMemoryTool::write(Arc::clone(&bank))),
            Box::new(SharedMemoryTool::list(bank)),
        ];
        self.extend(tools);
        Ok(())
    }
}

#[async_trait::async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl Tool for SharedMemoryTool {
    fn name(&self) -> &str {
        match self.operation {
            Operation::Read => "read_memory",
            Operation::Write => "write_memory",
            Operation::List => "list_memory",
        }
    }
    fn label(&self) -> &str {
        self.name()
    }
    fn description(&self) -> &str {
        match self.operation {
            Operation::Read => {
                "Read a shared key and its revision from the current session; other sessions are inaccessible."
            }
            Operation::Write => {
                "Write exact text to a shared session key. Use expectedRevision from a prior read, or 'absent' to create only. Values survive compaction but never become project facts automatically."
            }
            Operation::List => {
                "List shared session keys with bounded previews, revisions, literal prefix filtering and key cursors."
            }
        }
    }
    fn parameters(&self) -> Value {
        match self.operation {
            Operation::Read => {
                json!({"type":"object","properties":{"key":{"type":"string","maxLength":128}},"required":["key"],"additionalProperties":false})
            }
            Operation::Write => json!({"type":"object","properties":{
                "key":{"type":"string","maxLength":128}, "content":{"type":"string","description":"Exact UTF-8 text, at most 65536 bytes"},
                "expectedRevision":{"type":"string","description":"Returned revision, or absent for create-only; omitted opts into last-writer-wins"}
            },"required":["key","content"],"additionalProperties":false}),
            Operation::List => json!({"type":"object","properties":{
                "prefix":{"type":"string"}, "after":{"type":"string"}, "limit":{"type":"integer","minimum":1,"maximum":50}
            },"additionalProperties":false}),
        }
    }
    fn effects(&self) -> ToolEffects {
        match self.operation {
            Operation::Write => ToolEffects::write(),
            _ => ToolEffects::read(),
        }
    }
    fn bind_job_session_scope(&mut self, scope: JobSessionScope) {
        self.scope = Some(scope);
    }
    async fn execute(
        &self,
        _id: &str,
        input: Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        match self.operation {
            Operation::Write => write_output(&self.bank, self.scope.as_ref(), input).await,
            Operation::Read if input.get("key").and_then(Value::as_str).is_none() => Err(failure(
                "PI_SHARED_MEMORY_INVALID_INPUT",
                "read_memory requires key",
            )),
            Operation::List if input.get("key").is_some() => Err(failure(
                "PI_SHARED_MEMORY_INVALID_INPUT",
                "list_memory does not accept key",
            )),
            _ => read_or_list_output(&self.bank, self.scope.as_ref(), input).await,
        }
    }
}
