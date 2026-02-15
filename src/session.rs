//! Session management and persistence.
//!
//! Sessions are stored as JSONL files with a tree structure that enables
//! branching and history navigation.

use crate::agent_cx::AgentCx;
use crate::cli::Cli;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::extensions::ExtensionSession;
use crate::model::{
    AssistantMessage, ContentBlock, Message, TextContent, ToolResultMessage, UserContent,
    UserMessage,
};
use crate::session_index::{SessionIndex, enqueue_session_index_snapshot_update};
use crate::session_store_v2::{self, SessionStoreV2};
use crate::tui::PiConsole;
use asupersync::channel::oneshot;
use asupersync::sync::Mutex;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Current session file format version.
pub const SESSION_VERSION: u8 = 3;

/// Handle to a thread-safe shared session.
#[derive(Clone, Debug)]
pub struct SessionHandle(pub Arc<Mutex<Session>>);

#[async_trait]
impl ExtensionSession for SessionHandle {
    async fn get_state(&self) -> Value {
        let cx = AgentCx::for_request();
        let Ok(session) = self.0.lock(cx.cx()).await else {
            return serde_json::json!({
                "model": null,
                "thinkingLevel": "off",
                "durabilityMode": "balanced",
                "isStreaming": false,
                "isCompacting": false,
                "steeringMode": "one-at-a-time",
                "followUpMode": "one-at-a-time",
                "sessionFile": null,
                "sessionId": "",
                "sessionName": null,
                "autoCompactionEnabled": false,
                "messageCount": 0,
                "pendingMessageCount": 0,
            });
        };
        let session_file = session.path.as_ref().map(|p| p.display().to_string());
        let session_id = session.header.id.clone();
        let session_name = session.get_name();
        let thinking_level = session
            .header
            .thinking_level
            .clone()
            .unwrap_or_else(|| "off".to_string());
        let message_count = session
            .entries_for_current_path()
            .iter()
            .filter(|entry| matches!(entry, SessionEntry::Message(_)))
            .count();
        let pending_message_count = session.autosave_metrics().pending_mutations;
        let durability_mode = session.autosave_durability_mode().as_str();
        serde_json::json!({
            "model": null,
            "thinkingLevel": thinking_level,
            "durabilityMode": durability_mode,
            "isStreaming": false,
            "isCompacting": false,
            "steeringMode": "one-at-a-time",
            "followUpMode": "one-at-a-time",
            "sessionFile": session_file,
            "sessionId": session_id,
            "sessionName": session_name,
            "autoCompactionEnabled": false,
            "messageCount": message_count,
            "pendingMessageCount": pending_message_count,
        })
    }

    async fn get_messages(&self) -> Vec<SessionMessage> {
        let cx = AgentCx::for_request();
        let Ok(session) = self.0.lock(cx.cx()).await else {
            return Vec::new();
        };
        // Return messages for the current branch only, filtered to
        // user/assistant/toolResult/bashExecution/custom per spec §3.3.
        session
            .entries_for_current_path()
            .iter()
            .filter_map(|entry| match entry {
                SessionEntry::Message(msg) => match msg.message {
                    SessionMessage::User { .. }
                    | SessionMessage::Assistant { .. }
                    | SessionMessage::ToolResult { .. }
                    | SessionMessage::BashExecution { .. }
                    | SessionMessage::Custom { .. } => Some(msg.message.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    async fn get_entries(&self) -> Vec<Value> {
        let cx = AgentCx::for_request();
        let Ok(session) = self.0.lock(cx.cx()).await else {
            return Vec::new();
        };
        session
            .entries
            .iter()
            .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
            .collect()
    }

    async fn get_branch(&self) -> Vec<Value> {
        let cx = AgentCx::for_request();
        let Ok(session) = self.0.lock(cx.cx()).await else {
            return Vec::new();
        };
        session
            .entries_for_current_path()
            .iter()
            .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
            .collect()
    }

    async fn set_name(&self, name: String) -> Result<()> {
        let cx = AgentCx::for_request();
        let mut session = self
            .0
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(format!("Failed to lock session: {e}")))?;
        session.set_name(&name);
        Ok(())
    }

    async fn append_message(&self, message: SessionMessage) -> Result<()> {
        let cx = AgentCx::for_request();
        let mut session = self
            .0
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(format!("Failed to lock session: {e}")))?;
        session.append_message(message);
        Ok(())
    }

    async fn append_custom_entry(&self, custom_type: String, data: Option<Value>) -> Result<()> {
        let cx = AgentCx::for_request();
        let mut session = self
            .0
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(format!("Failed to lock session: {e}")))?;
        if custom_type.trim().is_empty() {
            return Err(Error::validation("customType must not be empty"));
        }
        session.append_custom_entry(custom_type, data);
        Ok(())
    }

    async fn set_model(&self, provider: String, model_id: String) -> Result<()> {
        let cx = AgentCx::for_request();
        let mut session = self
            .0
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(format!("Failed to lock session: {e}")))?;
        session.append_model_change(provider.clone(), model_id.clone());
        session.set_model_header(Some(provider), Some(model_id), None);
        Ok(())
    }

    async fn get_model(&self) -> (Option<String>, Option<String>) {
        let cx = AgentCx::for_request();
        let Ok(session) = self.0.lock(cx.cx()).await else {
            return (None, None);
        };
        (
            session.header.provider.clone(),
            session.header.model_id.clone(),
        )
    }

    async fn set_thinking_level(&self, level: String) -> Result<()> {
        let cx = AgentCx::for_request();
        let mut session = self
            .0
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(format!("Failed to lock session: {e}")))?;
        session.append_thinking_level_change(level.clone());
        session.set_model_header(None, None, Some(level));
        Ok(())
    }

    async fn get_thinking_level(&self) -> Option<String> {
        let cx = AgentCx::for_request();
        let Ok(session) = self.0.lock(cx.cx()).await else {
            return None;
        };
        session.header.thinking_level.clone()
    }

    async fn set_label(&self, target_id: String, label: Option<String>) -> Result<()> {
        let cx = AgentCx::for_request();
        let mut session = self
            .0
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(format!("Failed to lock session: {e}")))?;
        if session.add_label(&target_id, label).is_none() {
            return Err(Error::validation(format!(
                "target entry '{target_id}' not found in session"
            )));
        }
        Ok(())
    }
}

/// Default base URL for the Pi session share viewer.
pub const DEFAULT_SHARE_VIEWER_URL: &str = "https://buildwithpi.ai/session/";

fn build_share_viewer_url(base_url: Option<&str>, gist_id: &str) -> String {
    let base_url = base_url
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_SHARE_VIEWER_URL);
    format!("{base_url}#{gist_id}")
}

/// Get the share viewer URL for a gist ID.
///
/// Matches legacy Pi Agent semantics:
/// - Use `PI_SHARE_VIEWER_URL` env var when set and non-empty
/// - Otherwise fall back to `DEFAULT_SHARE_VIEWER_URL`
/// - Final URL is `{base}#{gist_id}` (no trailing-slash normalization)
#[must_use]
pub fn get_share_viewer_url(gist_id: &str) -> String {
    let base_url = std::env::var("PI_SHARE_VIEWER_URL").ok();
    build_share_viewer_url(base_url.as_deref(), gist_id)
}

/// Session persistence backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStoreKind {
    Jsonl,
    #[cfg(feature = "sqlite-sessions")]
    Sqlite,
}

impl SessionStoreKind {
    fn from_config(config: &Config) -> Self {
        let Some(value) = config.session_store.as_deref() else {
            return Self::Jsonl;
        };

        if value.eq_ignore_ascii_case("jsonl") {
            return Self::Jsonl;
        }

        if value.eq_ignore_ascii_case("sqlite") {
            #[cfg(feature = "sqlite-sessions")]
            {
                return Self::Sqlite;
            }

            #[cfg(not(feature = "sqlite-sessions"))]
            {
                tracing::warn!(
                    "Config requests session_store=sqlite but binary lacks `sqlite-sessions`; falling back to jsonl"
                );
                return Self::Jsonl;
            }
        }

        tracing::warn!("Unknown session_store `{value}`, falling back to jsonl");
        Self::Jsonl
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            #[cfg(feature = "sqlite-sessions")]
            Self::Sqlite => "sqlite",
        }
    }
}

/// Default upper bound for queued autosave mutations before backpressure coalescing kicks in.
const DEFAULT_AUTOSAVE_MAX_PENDING_MUTATIONS: usize = 256;

fn autosave_max_pending_mutations() -> usize {
    std::env::var("PI_SESSION_AUTOSAVE_MAX_PENDING")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_AUTOSAVE_MAX_PENDING_MUTATIONS)
}

/// Default number of incremental appends before forcing a full checkpoint rewrite.
const DEFAULT_COMPACTION_CHECKPOINT_INTERVAL: u64 = 50;

fn compaction_checkpoint_interval() -> u64 {
    std::env::var("PI_SESSION_COMPACTION_INTERVAL")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_COMPACTION_CHECKPOINT_INTERVAL)
}

/// Durability mode for write-behind autosave behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutosaveDurabilityMode {
    Strict,
    Balanced,
    Throughput,
}

impl AutosaveDurabilityMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "balanced" => Some(Self::Balanced),
            "throughput" => Some(Self::Throughput),
            _ => None,
        }
    }

    fn from_env() -> Self {
        std::env::var("PI_SESSION_DURABILITY_MODE")
            .ok()
            .as_deref()
            .and_then(Self::parse)
            .unwrap_or(Self::Balanced)
    }

    const fn should_flush_on_shutdown(self) -> bool {
        matches!(self, Self::Strict | Self::Balanced)
    }

    const fn best_effort_on_shutdown(self) -> bool {
        matches!(self, Self::Balanced)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Throughput => "throughput",
        }
    }
}

fn resolve_autosave_durability_mode(
    cli_mode: Option<&str>,
    config_mode: Option<&str>,
    env_mode: Option<&str>,
) -> AutosaveDurabilityMode {
    cli_mode
        .and_then(AutosaveDurabilityMode::parse)
        .or_else(|| config_mode.and_then(AutosaveDurabilityMode::parse))
        .or_else(|| env_mode.and_then(AutosaveDurabilityMode::parse))
        .unwrap_or(AutosaveDurabilityMode::Balanced)
}

/// Autosave flush trigger used for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutosaveFlushTrigger {
    Manual,
    Periodic,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutosaveMutationKind {
    Message,
    Metadata,
    Label,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AutosaveFlushTicket {
    batch_size: usize,
    started_at: Instant,
    trigger: AutosaveFlushTrigger,
}

/// Snapshot of autosave queue state and lifecycle counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct AutosaveQueueMetrics {
    pub pending_mutations: usize,
    pub max_pending_mutations: usize,
    pub coalesced_mutations: u64,
    pub backpressure_events: u64,
    pub flush_started: u64,
    pub flush_succeeded: u64,
    pub flush_failed: u64,
    pub last_flush_batch_size: usize,
    pub last_flush_duration_ms: Option<u64>,
    pub last_flush_trigger: Option<AutosaveFlushTrigger>,
}

#[derive(Debug, Clone)]
struct AutosaveQueue {
    pending_mutations: usize,
    max_pending_mutations: usize,
    coalesced_mutations: u64,
    backpressure_events: u64,
    flush_started: u64,
    flush_succeeded: u64,
    flush_failed: u64,
    last_flush_batch_size: usize,
    last_flush_duration_ms: Option<u64>,
    last_flush_trigger: Option<AutosaveFlushTrigger>,
}

impl AutosaveQueue {
    fn new() -> Self {
        Self {
            pending_mutations: 0,
            max_pending_mutations: autosave_max_pending_mutations(),
            coalesced_mutations: 0,
            backpressure_events: 0,
            flush_started: 0,
            flush_succeeded: 0,
            flush_failed: 0,
            last_flush_batch_size: 0,
            last_flush_duration_ms: None,
            last_flush_trigger: None,
        }
    }

    #[cfg(test)]
    fn with_limit(max_pending_mutations: usize) -> Self {
        let mut queue = Self::new();
        queue.max_pending_mutations = max_pending_mutations.max(1);
        queue
    }

    const fn metrics(&self) -> AutosaveQueueMetrics {
        AutosaveQueueMetrics {
            pending_mutations: self.pending_mutations,
            max_pending_mutations: self.max_pending_mutations,
            coalesced_mutations: self.coalesced_mutations,
            backpressure_events: self.backpressure_events,
            flush_started: self.flush_started,
            flush_succeeded: self.flush_succeeded,
            flush_failed: self.flush_failed,
            last_flush_batch_size: self.last_flush_batch_size,
            last_flush_duration_ms: self.last_flush_duration_ms,
            last_flush_trigger: self.last_flush_trigger,
        }
    }

    const fn enqueue_mutation(&mut self, _kind: AutosaveMutationKind) {
        if self.pending_mutations == 0 {
            self.pending_mutations = 1;
            return;
        }
        self.coalesced_mutations = self.coalesced_mutations.saturating_add(1);
        if self.pending_mutations < self.max_pending_mutations {
            self.pending_mutations += 1;
        } else {
            self.backpressure_events = self.backpressure_events.saturating_add(1);
        }
    }

    fn begin_flush(&mut self, trigger: AutosaveFlushTrigger) -> Option<AutosaveFlushTicket> {
        if self.pending_mutations == 0 {
            return None;
        }
        let batch_size = self.pending_mutations;
        self.pending_mutations = 0;
        self.flush_started = self.flush_started.saturating_add(1);
        self.last_flush_batch_size = batch_size;
        self.last_flush_trigger = Some(trigger);
        Some(AutosaveFlushTicket {
            batch_size,
            started_at: Instant::now(),
            trigger,
        })
    }

    fn finish_flush(&mut self, ticket: AutosaveFlushTicket, success: bool) {
        let elapsed = ticket.started_at.elapsed().as_millis();
        let elapsed = u64::try_from(elapsed.min(u128::from(u64::MAX)))
            .expect("elapsed milliseconds clamped to u64::MAX");
        self.last_flush_duration_ms = Some(elapsed);
        self.last_flush_trigger = Some(ticket.trigger);
        if success {
            self.flush_succeeded = self.flush_succeeded.saturating_add(1);
            return;
        }

        self.flush_failed = self.flush_failed.saturating_add(1);
        let restored = ticket.batch_size.min(self.max_pending_mutations);
        self.pending_mutations = self.pending_mutations.saturating_add(restored);
        let dropped = ticket.batch_size.saturating_sub(restored);
        if dropped > 0 {
            let dropped = dropped as u64;
            self.backpressure_events = self.backpressure_events.saturating_add(dropped);
            self.coalesced_mutations = self.coalesced_mutations.saturating_add(dropped);
        }
    }
}

// ============================================================================
// Session
// ============================================================================

/// A session manages conversation state and persistence.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session header
    pub header: SessionHeader,
    /// Session entries (messages, changes, etc.)
    pub entries: Vec<SessionEntry>,
    /// Path to the session file (None for in-memory)
    pub path: Option<PathBuf>,
    /// Current leaf entry ID
    pub leaf_id: Option<String>,
    /// Base directory for session storage (optional override)
    pub session_dir: Option<PathBuf>,
    store_kind: SessionStoreKind,
    /// Cached entry IDs for O(1) uniqueness checks when appending.
    entry_ids: HashSet<String>,

    // -- Performance caches (Gaps A/B/C) --
    /// True when all entries form a linear chain (no branching).
    /// When true, `entries_for_current_path()` returns all entries without
    /// building a parent map — the 99% fast path.
    is_linear: bool,
    /// Map from entry ID to index in `self.entries` for O(1) lookup.
    entry_index: HashMap<String, usize>,
    /// Incrementally maintained message count (avoids O(n) scan on save).
    cached_message_count: u64,
    /// Most recent session name from `SessionInfo` entries.
    cached_name: Option<String>,
    /// Write-behind autosave queue state and lifecycle counters.
    autosave_queue: AutosaveQueue,
    /// Current durability policy for shutdown final flush behavior.
    autosave_durability: AutosaveDurabilityMode,

    // -- Incremental append state --
    /// Number of entries already persisted to disk (high-water mark).
    persisted_entry_count: usize,
    /// True when header was modified since last save (forces full rewrite).
    header_dirty: bool,
    /// Incremental appends since last full rewrite (checkpoint counter).
    appends_since_checkpoint: u64,
}

/// Result of planning a `/fork` operation from a specific user message.
///
/// Mirrors legacy semantics:
/// - The new session's leaf is the *parent* of the selected user message (or `None` if root),
///   so the selected message can be re-submitted as a new branch without creating consecutive
///   user messages.
/// - The selected user message text is returned for editor pre-fill.
#[derive(Debug, Clone)]
pub struct ForkPlan {
    /// Entries to copy into the new session file (path to the fork leaf, inclusive).
    pub entries: Vec<SessionEntry>,
    /// Leaf ID to set in the new session (parent of selected user entry).
    pub leaf_id: Option<String>,
    /// Text of the selected user message (for editor pre-fill).
    pub selected_text: String,
}

/// Diagnostics captured while opening a session file.
#[derive(Debug, Clone, Default)]
pub struct SessionOpenDiagnostics {
    pub skipped_entries: Vec<SessionOpenSkippedEntry>,
    pub orphaned_parent_links: Vec<SessionOpenOrphanedParentLink>,
}

#[derive(Debug, Clone)]
pub struct SessionOpenSkippedEntry {
    /// 1-based line number in the session file.
    pub line_number: usize,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct SessionOpenOrphanedParentLink {
    pub entry_id: String,
    pub missing_parent_id: String,
}

/// Loading strategy for reconstructing a `Session` from a V2 store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2OpenMode {
    Full,
    ActivePath,
    Tail(u64),
}

impl SessionOpenDiagnostics {
    fn warning_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for skipped in &self.skipped_entries {
            lines.push(format!(
                "Warning: Skipping corrupted entry at line {} in session file: {}",
                skipped.line_number, skipped.error
            ));
        }

        if !self.skipped_entries.is_empty() {
            lines.push(format!(
                "Warning: Skipped {} corrupted entries while loading session",
                self.skipped_entries.len()
            ));
        }

        for orphan in &self.orphaned_parent_links {
            lines.push(format!(
                "Warning: Entry {} references missing parent {}",
                orphan.entry_id, orphan.missing_parent_id
            ));
        }

        if !self.orphaned_parent_links.is_empty() {
            lines.push(format!(
                "Warning: Detected {} orphaned parent links while loading session",
                self.orphaned_parent_links.len()
            ));
        }

        lines
    }
}

impl Session {
    /// Create a new session from CLI args and config.
    pub async fn new(cli: &Cli, config: &Config) -> Result<Self> {
        let session_dir = cli.session_dir.as_ref().map(PathBuf::from);
        let durability_mode = resolve_autosave_durability_mode(
            cli.session_durability.as_deref(),
            config.session_durability.as_deref(),
            std::env::var("PI_SESSION_DURABILITY_MODE").ok().as_deref(),
        );
        if cli.no_session {
            let mut session = Self::in_memory();
            session.set_autosave_durability_mode(durability_mode);
            return Ok(session);
        }

        if let Some(path) = &cli.session {
            let mut session = Self::open(path).await?;
            session.set_autosave_durability_mode(durability_mode);
            return Ok(session);
        }

        if cli.resume {
            let picker_input_override = config
                .session_picker_input
                .filter(|value| *value > 0)
                .map(|value| value.to_string());
            let mut session = Box::pin(Self::resume_with_picker(
                session_dir.as_deref(),
                config,
                picker_input_override,
            ))
            .await?;
            session.set_autosave_durability_mode(durability_mode);
            return Ok(session);
        }

        if cli.r#continue {
            let mut session = Self::continue_recent_in_dir(session_dir.as_deref(), config).await?;
            session.set_autosave_durability_mode(durability_mode);
            return Ok(session);
        }

        let store_kind = SessionStoreKind::from_config(config);
        let mut session = Self::create_with_dir_and_store(session_dir, store_kind);
        session.set_autosave_durability_mode(durability_mode);

        // Create a new session
        Ok(session)
    }

    /// Resume a session by prompting the user to select from recent sessions.
    #[allow(clippy::too_many_lines)]
    pub async fn resume_with_picker(
        override_dir: Option<&Path>,
        config: &Config,
        picker_input_override: Option<String>,
    ) -> Result<Self> {
        let is_interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        let mut picker_input_override = picker_input_override;
        if picker_input_override.is_none() && is_interactive {
            if let Some(session) = crate::session_picker::pick_session(override_dir).await {
                return Ok(session);
            }
        }

        let base_dir = override_dir.map_or_else(Config::sessions_dir, PathBuf::from);
        let store_kind = SessionStoreKind::from_config(config);
        let cwd = std::env::current_dir()?;
        let encoded_cwd = encode_cwd(&cwd);
        let project_session_dir = base_dir.join(&encoded_cwd);

        if !project_session_dir.exists() {
            return Ok(Self::create_with_dir_and_store(Some(base_dir), store_kind));
        }

        let entries: Vec<SessionPickEntry> = SessionIndex::for_sessions_root(&base_dir)
            .list_sessions(Some(&cwd.display().to_string()))
            .map(|list| {
                list.into_iter()
                    .filter_map(SessionPickEntry::from_meta)
                    .collect()
            })
            .unwrap_or_default();

        let scanned = scan_sessions_on_disk(&project_session_dir, entries.clone()).await?;
        let mut by_path: HashMap<PathBuf, SessionPickEntry> = HashMap::new();
        for entry in entries.into_iter().chain(scanned.into_iter()) {
            by_path
                .entry(entry.path.clone())
                .and_modify(|existing| {
                    if entry.last_modified_ms > existing.last_modified_ms {
                        *existing = entry.clone();
                    }
                })
                .or_insert(entry);
        }
        let mut entries = by_path.into_values().collect::<Vec<_>>();

        if entries.is_empty() {
            return Ok(Self::create_with_dir_and_store(Some(base_dir), store_kind));
        }

        entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_modified_ms));
        let max_entries = 20usize.min(entries.len());
        let mut entries = entries.into_iter().take(max_entries).collect::<Vec<_>>();

        let console = PiConsole::new();
        console.render_info("Select a session to resume:");

        let headers = ["#", "Timestamp", "Messages", "Name", "Path"];

        let mut attempts = 0;
        loop {
            if entries.is_empty() {
                console.render_warning("No resumable sessions available. Starting a new session.");
                return Ok(Self::create_with_dir_and_store(Some(base_dir), store_kind));
            }

            let mut rows: Vec<Vec<String>> = Vec::new();
            for (idx, entry) in entries.iter().enumerate() {
                rows.push(vec![
                    format!("{}", idx + 1),
                    entry.timestamp.clone(),
                    entry.message_count.to_string(),
                    entry.name.clone().unwrap_or_else(|| entry.id.clone()),
                    entry.path.display().to_string(),
                ]);
            }
            let row_refs: Vec<Vec<&str>> = rows
                .iter()
                .map(|row| row.iter().map(String::as_str).collect())
                .collect();
            console.render_table(&headers, &row_refs);

            attempts += 1;
            if attempts > 3 {
                console.render_warning("No selection made. Starting a new session.");
                return Ok(Self::create_with_dir_and_store(Some(base_dir), store_kind));
            }

            print!(
                "Enter selection (1-{}, blank to start new): ",
                entries.len()
            );
            let _ = std::io::stdout().flush();

            let input = if let Some(override_input) = picker_input_override.take() {
                override_input
            } else {
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                input
            };
            let input = input.trim();
            if input.is_empty() {
                console.render_info("Starting a new session.");
                return Ok(Self::create_with_dir_and_store(Some(base_dir), store_kind));
            }

            match input.parse::<usize>() {
                Ok(index) if index > 0 && index <= entries.len() => {
                    let selected = &entries[index - 1];
                    match Self::open(selected.path.to_string_lossy().as_ref()).await {
                        Ok(mut session) => {
                            session.session_dir = Some(base_dir.clone());
                            return Ok(session);
                        }
                        Err(err) => {
                            tracing::warn!(
                                path = %selected.path.display(),
                                error = %err,
                                "Failed to open selected session while resuming"
                            );
                            entries.remove(index - 1);

                            if is_interactive {
                                console.render_warning(
                                    "Selected session could not be opened. Pick another session.",
                                );
                                continue;
                            }

                            console.render_warning(
                                "Selected session could not be opened. Starting a new session.",
                            );
                            return Ok(Self::create_with_dir_and_store(
                                Some(base_dir.clone()),
                                store_kind,
                            ));
                        }
                    }
                }
                _ => {
                    console.render_warning("Invalid selection. Try again.");
                }
            }
        }
    }

    /// Create an in-memory (ephemeral) session.
    pub fn in_memory() -> Self {
        Self {
            header: SessionHeader::new(),
            entries: Vec::new(),
            path: None,
            leaf_id: None,
            session_dir: None,
            store_kind: SessionStoreKind::Jsonl,
            entry_ids: HashSet::new(),
            is_linear: true,
            entry_index: HashMap::new(),
            cached_message_count: 0,
            cached_name: None,
            autosave_queue: AutosaveQueue::new(),
            autosave_durability: AutosaveDurabilityMode::from_env(),
            persisted_entry_count: 0,
            header_dirty: false,
            appends_since_checkpoint: 0,
        }
    }

    /// Create a new session.
    pub fn create() -> Self {
        Self::create_with_dir(None)
    }

    /// Create a new session with an optional base directory override.
    pub fn create_with_dir(session_dir: Option<PathBuf>) -> Self {
        Self::create_with_dir_and_store(session_dir, SessionStoreKind::Jsonl)
    }

    pub fn create_with_dir_and_store(
        session_dir: Option<PathBuf>,
        store_kind: SessionStoreKind,
    ) -> Self {
        let header = SessionHeader::new();
        Self {
            header,
            entries: Vec::new(),
            path: None,
            leaf_id: None,
            session_dir,
            store_kind,
            entry_ids: HashSet::new(),
            is_linear: true,
            entry_index: HashMap::new(),
            cached_message_count: 0,
            cached_name: None,
            autosave_queue: AutosaveQueue::new(),
            autosave_durability: AutosaveDurabilityMode::from_env(),
            persisted_entry_count: 0,
            header_dirty: false,
            appends_since_checkpoint: 0,
        }
    }

    /// Open an existing session.
    pub async fn open(path: &str) -> Result<Self> {
        let (session, diagnostics) = Self::open_with_diagnostics(path).await?;
        for warning in diagnostics.warning_lines() {
            eprintln!("{warning}");
        }
        Ok(session)
    }

    /// Open an existing session and return diagnostics about any recovered corruption.
    pub async fn open_with_diagnostics(path: &str) -> Result<(Self, SessionOpenDiagnostics)> {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(crate::Error::SessionNotFound {
                path: path.display().to_string(),
            });
        }

        if path.extension().is_some_and(|ext| ext == "sqlite") {
            #[cfg(feature = "sqlite-sessions")]
            {
                let session = Self::open_sqlite(&path).await?;
                return Ok((session, SessionOpenDiagnostics::default()));
            }

            #[cfg(not(feature = "sqlite-sessions"))]
            {
                return Err(Error::session(
                    "SQLite session files require building with `--features sqlite-sessions`",
                ));
            }
        }

        // Check for V2 sidecar store — enables O(index+tail) resume.
        if session_store_v2::has_v2_sidecar(&path) {
            match Self::open_v2_with_diagnostics(&path).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "V2 sidecar resume failed, falling back to full JSONL parse"
                    );
                }
            }
        }

        Self::open_jsonl_with_diagnostics(&path).await
    }

    /// Open a session from an already-open V2 store with an explicit read mode.
    pub fn open_from_v2(
        store: &SessionStoreV2,
        header: SessionHeader,
        mode: V2OpenMode,
    ) -> Result<(Self, SessionOpenDiagnostics)> {
        let frames = match mode {
            V2OpenMode::Full => store.read_all_entries()?,
            V2OpenMode::ActivePath => match store.head() {
                Some(head) => store.read_active_path(&head.entry_id)?,
                None => Vec::new(),
            },
            V2OpenMode::Tail(count) => store.read_tail_entries(count)?,
        };

        let mut diagnostics = SessionOpenDiagnostics::default();
        let mut entries = Vec::with_capacity(frames.len());
        for frame in &frames {
            match session_store_v2::frame_to_session_entry(frame) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    diagnostics.skipped_entries.push(SessionOpenSkippedEntry {
                        line_number: usize::try_from(frame.entry_seq).unwrap_or(0),
                        error: e.to_string(),
                    });
                }
            }
        }

        let finalized = finalize_loaded_entries(&mut entries);
        for orphan in &finalized.orphans {
            diagnostics
                .orphaned_parent_links
                .push(SessionOpenOrphanedParentLink {
                    entry_id: orphan.0.clone(),
                    missing_parent_id: orphan.1.clone(),
                });
        }

        let entry_count = entries.len();
        Ok((
            Self {
                header,
                entries,
                path: None,
                leaf_id: finalized.leaf_id,
                session_dir: None,
                store_kind: SessionStoreKind::Jsonl,
                entry_ids: finalized.entry_ids,
                is_linear: finalized.is_linear,
                entry_index: finalized.entry_index,
                cached_message_count: finalized.message_count,
                cached_name: finalized.name,
                autosave_queue: AutosaveQueue::new(),
                autosave_durability: AutosaveDurabilityMode::from_env(),
                persisted_entry_count: entry_count,
                header_dirty: false,
                appends_since_checkpoint: 0,
            },
            diagnostics,
        ))
    }

    /// Open using the V2 sidecar store (async wrapper around blocking read).
    async fn open_v2_with_diagnostics(path: &Path) -> Result<(Self, SessionOpenDiagnostics)> {
        let path_buf = path.to_path_buf();
        let (tx, rx) = oneshot::channel();

        thread::spawn(move || {
            let res = crate::session::open_from_v2_store_blocking(path_buf);
            let cx = AgentCx::for_request();
            let _ = tx.send(cx.cx(), res);
        });

        let cx = AgentCx::for_request();
        rx.recv(cx.cx())
            .await
            .map_err(|_| crate::Error::session("V2 open task cancelled"))?
    }

    async fn open_jsonl_with_diagnostics(path: &Path) -> Result<(Self, SessionOpenDiagnostics)> {
        let path_buf = path.to_path_buf();
        let (tx, rx) = oneshot::channel();

        thread::spawn(move || {
            let res = open_jsonl_blocking(path_buf);
            let cx = AgentCx::for_request();
            let _ = tx.send(cx.cx(), res);
        });

        let cx = AgentCx::for_request();
        rx.recv(cx.cx())
            .await
            .map_err(|_| crate::Error::session("Open task cancelled"))?
    }

    #[cfg(feature = "sqlite-sessions")]
    async fn open_sqlite(path: &Path) -> Result<Self> {
        let (header, mut entries) = crate::session_sqlite::load_session(path).await?;
        let finalized = finalize_loaded_entries(&mut entries);
        let entry_count = entries.len();

        Ok(Self {
            header,
            entries,
            path: Some(path.to_path_buf()),
            leaf_id: finalized.leaf_id,
            session_dir: None,
            store_kind: SessionStoreKind::Sqlite,
            entry_ids: finalized.entry_ids,
            is_linear: finalized.is_linear,
            entry_index: finalized.entry_index,
            cached_message_count: finalized.message_count,
            cached_name: finalized.name,
            autosave_queue: AutosaveQueue::new(),
            autosave_durability: AutosaveDurabilityMode::from_env(),
            persisted_entry_count: entry_count,
            header_dirty: false,
            appends_since_checkpoint: 0,
        })
    }

    /// Continue the most recent session.
    pub async fn continue_recent_in_dir(
        override_dir: Option<&Path>,
        config: &Config,
    ) -> Result<Self> {
        let store_kind = SessionStoreKind::from_config(config);
        let base_dir = override_dir.map_or_else(Config::sessions_dir, PathBuf::from);
        let cwd = std::env::current_dir()?;
        let cwd_display = cwd.display().to_string();
        let encoded_cwd = encode_cwd(&cwd);
        let project_session_dir = base_dir.join(&encoded_cwd);

        if !project_session_dir.exists() {
            return Ok(Self::create_with_dir_and_store(Some(base_dir), store_kind));
        }

        // Prefer the session index for fast lookup.
        let index = SessionIndex::for_sessions_root(&base_dir);
        let mut indexed_sessions: Vec<SessionPickEntry> = index
            .list_sessions(Some(&cwd_display))
            .map(|list| {
                list.into_iter()
                    .filter_map(SessionPickEntry::from_meta)
                    .collect()
            })
            .unwrap_or_default();

        if indexed_sessions.is_empty() && index.reindex_all().is_ok() {
            indexed_sessions = index
                .list_sessions(Some(&cwd_display))
                .map(|list| {
                    list.into_iter()
                        .filter_map(SessionPickEntry::from_meta)
                        .collect()
                })
                .unwrap_or_default();
        }

        let scanned = scan_sessions_on_disk(&project_session_dir, indexed_sessions.clone()).await?;

        let mut by_path: HashMap<PathBuf, SessionPickEntry> = HashMap::new();
        for entry in indexed_sessions.into_iter().chain(scanned.into_iter()) {
            by_path
                .entry(entry.path.clone())
                .and_modify(|existing| {
                    if entry.last_modified_ms > existing.last_modified_ms {
                        *existing = entry.clone();
                    }
                })
                .or_insert(entry);
        }

        let mut candidates = by_path.into_values().collect::<Vec<_>>();
        candidates.sort_by_key(|entry| std::cmp::Reverse(entry.last_modified_ms));

        for entry in &candidates {
            match Self::open(entry.path.to_string_lossy().as_ref()).await {
                Ok(mut session) => {
                    session.session_dir = Some(base_dir.clone());
                    return Ok(session);
                }
                Err(err) => {
                    tracing::warn!(
                        path = %entry.path.display(),
                        error = %err,
                        "Skipping unreadable session candidate while continuing"
                    );
                }
            }
        }

        Ok(Self::create_with_dir_and_store(Some(base_dir), store_kind))
    }

    /// Save the session to disk.
    pub async fn save(&mut self) -> Result<()> {
        let ticket = self
            .autosave_queue
            .begin_flush(AutosaveFlushTrigger::Manual);
        let result = self.save_inner().await;
        if let Some(ticket) = ticket {
            self.autosave_queue.finish_flush(ticket, result.is_ok());
        }
        result
    }

    /// Flush queued autosave mutations using the requested trigger.
    ///
    /// This is the write-behind entry point: no-op when there are no pending
    /// mutations, and one persistence operation for all coalesced mutations when
    /// pending work exists.
    pub async fn flush_autosave(&mut self, trigger: AutosaveFlushTrigger) -> Result<()> {
        let Some(ticket) = self.autosave_queue.begin_flush(trigger) else {
            return Ok(());
        };
        let result = self.save_inner().await;
        self.autosave_queue.finish_flush(ticket, result.is_ok());
        result
    }

    /// Final shutdown flush respecting the configured durability mode.
    pub async fn flush_autosave_on_shutdown(&mut self) -> Result<()> {
        if !self.autosave_durability.should_flush_on_shutdown() {
            return Ok(());
        }
        let result = self.flush_autosave(AutosaveFlushTrigger::Shutdown).await;
        if result.is_err() && self.autosave_durability.best_effort_on_shutdown() {
            if let Err(err) = &result {
                tracing::warn!(error = %err, "best-effort autosave flush failed during shutdown");
            }
            return Ok(());
        }
        result
    }

    /// Current autosave queue and lifecycle counters for observability.
    pub const fn autosave_metrics(&self) -> AutosaveQueueMetrics {
        self.autosave_queue.metrics()
    }

    pub const fn autosave_durability_mode(&self) -> AutosaveDurabilityMode {
        self.autosave_durability
    }

    pub const fn set_autosave_durability_mode(&mut self, mode: AutosaveDurabilityMode) {
        self.autosave_durability = mode;
    }

    #[cfg(test)]
    fn set_autosave_queue_limit_for_test(&mut self, max_pending_mutations: usize) {
        self.autosave_queue = AutosaveQueue::with_limit(max_pending_mutations);
    }

    #[cfg(test)]
    const fn set_autosave_durability_for_test(&mut self, mode: AutosaveDurabilityMode) {
        self.autosave_durability = mode;
    }

    /// Returns `true` when a full rewrite is required instead of incremental append.
    fn should_full_rewrite(&self) -> bool {
        // First save — no file exists yet.
        if self.persisted_entry_count == 0 {
            return true;
        }
        // Header was modified since last save.
        if self.header_dirty {
            return true;
        }
        // Periodic checkpoint to clean up accumulated partial writes.
        if self.appends_since_checkpoint >= compaction_checkpoint_interval() {
            return true;
        }
        // Defensive: if persisted count somehow exceeds entries, force full rewrite.
        if self.persisted_entry_count > self.entries.len() {
            return true;
        }
        // Any new entry is a Compaction (dead entries before marker need rewriting).
        self.entries[self.persisted_entry_count..]
            .iter()
            .any(|e| matches!(e, SessionEntry::Compaction(_)))
    }

    /// Save the session to disk.
    #[allow(clippy::too_many_lines)]
    async fn save_inner(&mut self) -> Result<()> {
        self.ensure_entry_ids();

        let store_kind = match self
            .path
            .as_ref()
            .and_then(|path| path.extension().and_then(|ext| ext.to_str()))
        {
            Some("jsonl") => SessionStoreKind::Jsonl,
            Some("sqlite") => {
                #[cfg(feature = "sqlite-sessions")]
                {
                    SessionStoreKind::Sqlite
                }

                #[cfg(not(feature = "sqlite-sessions"))]
                {
                    return Err(Error::session(
                        "SQLite session files require building with `--features sqlite-sessions`",
                    ));
                }
            }
            _ => self.store_kind,
        };

        if self.path.is_none() {
            // Create a new path
            let base_dir = self
                .session_dir
                .clone()
                .unwrap_or_else(Config::sessions_dir);
            let cwd = std::env::current_dir()?;
            let encoded_cwd = encode_cwd(&cwd);
            let project_session_dir = base_dir.join(&encoded_cwd);

            asupersync::fs::create_dir_all(&project_session_dir).await?;

            let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.3fZ");
            // Robust against malformed/legacy session ids: keep a short, filename-safe suffix.
            let short_id = {
                let prefix: String = self
                    .header
                    .id
                    .chars()
                    .take(8)
                    .map(|ch| {
                        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                            ch
                        } else {
                            '_'
                        }
                    })
                    .collect();
                if prefix.trim_matches('_').is_empty() {
                    "session".to_string()
                } else {
                    prefix
                }
            };
            let filename = format!("{}_{}.{}", timestamp, short_id, store_kind.extension());
            self.path = Some(project_session_dir.join(filename));
        }

        let session_dir_clone = self.session_dir.clone();
        let path = self.path.clone().unwrap();
        let path_clone = path.clone();

        match store_kind {
            SessionStoreKind::Jsonl => {
                let sessions_root = session_dir_clone.unwrap_or_else(Config::sessions_dir);
                // Gap C: use incrementally maintained stats instead of O(n) scan.
                let message_count = self.cached_message_count;
                let session_name = self.cached_name.clone();

                if self.should_full_rewrite() {
                    // === Full rewrite path (first save, header change, compaction, checkpoint) ===
                    type JsonlSaveResult =
                        std::result::Result<Vec<SessionEntry>, (Error, Vec<SessionEntry>)>;
                    let (tx, rx) = oneshot::channel::<JsonlSaveResult>();

                    let header_snapshot = self.header.clone();
                    let entries_to_save = std::mem::take(&mut self.entries);

                    let path_for_thread = path_clone.clone();
                    thread::spawn(move || {
                        let entries = entries_to_save;
                        let res = || -> Result<()> {
                            let parent = path_for_thread.parent().unwrap_or_else(|| Path::new("."));
                            let temp_file = tempfile::NamedTempFile::new_in(parent)?;
                            {
                                let mut writer =
                                    std::io::BufWriter::with_capacity(1 << 20, temp_file.as_file());
                                serde_json::to_writer(&mut writer, &header_snapshot)?;
                                writer.write_all(b"\n")?;
                                for entry in &entries {
                                    serde_json::to_writer(&mut writer, entry)?;
                                    writer.write_all(b"\n")?;
                                }
                                writer.flush()?;
                            }
                            temp_file
                                .persist(&path_for_thread)
                                .map_err(|e| crate::Error::Io(Box::new(e.error)))?;

                            enqueue_session_index_snapshot_update(
                                sessions_root.clone(),
                                path_for_thread.clone(),
                                header_snapshot.clone(),
                                message_count,
                                session_name.clone(),
                            );
                            Ok(())
                        }();
                        let cx = AgentCx::for_request();
                        let _ = tx.send(
                            cx.cx(),
                            match res {
                                Ok(()) => Ok(entries),
                                Err(err) => Err((err, entries)),
                            },
                        );
                    });

                    let cx = AgentCx::for_request();
                    let result = rx
                        .recv(cx.cx())
                        .await
                        .map_err(|_| crate::Error::session("Save task cancelled"))?;

                    match result {
                        Ok(entries) => {
                            self.entries = entries;
                            self.rebuild_all_caches();
                            self.persisted_entry_count = self.entries.len();
                            self.header_dirty = false;
                            self.appends_since_checkpoint = 0;
                            Ok(())
                        }
                        Err((err, entries)) => {
                            self.entries = entries;
                            self.rebuild_all_caches();
                            Err(err)
                        }
                    }?;
                } else {
                    // === Incremental append path ===
                    let new_start = self.persisted_entry_count;
                    if new_start < self.entries.len() {
                        // Pre-serialize new entries on the main thread (typically 1-3 entries).
                        let mut serialized_bytes = Vec::new();
                        for entry in &self.entries[new_start..] {
                            let mut line = serde_json::to_vec(entry)?;
                            line.push(b'\n');
                            serialized_bytes.push(line);
                        }
                        let new_count = self.entries.len();

                        let (tx, rx) = oneshot::channel::<Result<()>>();
                        let header_snapshot = self.header.clone();

                        let path_for_thread = path_clone.clone();
                        thread::spawn(move || {
                            let res = || -> Result<()> {
                                let file = std::fs::OpenOptions::new()
                                    .append(true)
                                    .open(&path_for_thread)
                                    .map_err(|e| crate::Error::Io(Box::new(e)))?;
                                let mut writer = std::io::BufWriter::new(file);
                                for chunk in &serialized_bytes {
                                    writer.write_all(chunk)?;
                                }
                                writer.flush()?;

                                enqueue_session_index_snapshot_update(
                                    sessions_root.clone(),
                                    path_for_thread.clone(),
                                    header_snapshot.clone(),
                                    message_count,
                                    session_name.clone(),
                                );
                                Ok(())
                            }();
                            let cx = AgentCx::for_request();
                            let _ = tx.send(cx.cx(), res);
                        });

                        let cx = AgentCx::for_request();
                        let result = rx
                            .recv(cx.cx())
                            .await
                            .map_err(|_| crate::Error::session("Append task cancelled"))?;

                        if result.is_ok() {
                            self.persisted_entry_count = new_count;
                            self.appends_since_checkpoint += 1;
                        }
                        result?;
                    }
                    // No new entries → no-op, nothing to write.
                }
            }
            #[cfg(feature = "sqlite-sessions")]
            SessionStoreKind::Sqlite => {
                let message_count = self.cached_message_count;
                let session_name = self.cached_name.clone();

                if self.should_full_rewrite() {
                    // === Full rewrite path (first save, header change, compaction, checkpoint) ===
                    crate::session_sqlite::save_session(&path_clone, &self.header, &self.entries)
                        .await?;
                    self.persisted_entry_count = self.entries.len();
                    self.header_dirty = false;
                    self.appends_since_checkpoint = 0;
                } else {
                    // === Incremental append path ===
                    let new_start = self.persisted_entry_count;
                    if new_start < self.entries.len() {
                        crate::session_sqlite::append_entries(
                            &path_clone,
                            &self.entries[new_start..],
                            new_start,
                            message_count,
                            session_name.as_deref(),
                        )
                        .await?;
                        self.persisted_entry_count = self.entries.len();
                        self.appends_since_checkpoint += 1;
                    }
                    // No new entries → no-op, nothing to write.
                }

                let sessions_root = session_dir_clone.unwrap_or_else(Config::sessions_dir);
                enqueue_session_index_snapshot_update(
                    sessions_root,
                    path_clone.clone(),
                    self.header.clone(),
                    message_count,
                    session_name,
                );
            }
        }
        Ok(())
    }

    const fn enqueue_autosave_mutation(&mut self, kind: AutosaveMutationKind) {
        self.autosave_queue.enqueue_mutation(kind);
    }

    /// Append a session message entry.
    pub fn append_message(&mut self, message: SessionMessage) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::Message(MessageEntry { base, message });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.cached_message_count += 1;
        self.enqueue_autosave_mutation(AutosaveMutationKind::Message);
        id
    }

    /// Append a message from the model message types.
    pub fn append_model_message(&mut self, message: Message) -> String {
        self.append_message(SessionMessage::from(message))
    }

    pub fn append_model_change(&mut self, provider: String, model_id: String) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::ModelChange(ModelChangeEntry {
            base,
            provider,
            model_id,
        });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
        id
    }

    pub fn append_thinking_level_change(&mut self, thinking_level: String) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::ThinkingLevelChange(ThinkingLevelChangeEntry {
            base,
            thinking_level,
        });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
        id
    }

    pub fn append_session_info(&mut self, name: Option<String>) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        if name.is_some() {
            self.cached_name.clone_from(&name);
        }
        let entry = SessionEntry::SessionInfo(SessionInfoEntry { base, name });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
        id
    }

    /// Append a custom entry (extension state, etc).
    pub fn append_custom_entry(
        &mut self,
        custom_type: String,
        data: Option<serde_json::Value>,
    ) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::Custom(CustomEntry {
            base,
            custom_type,
            data,
        });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
        id
    }

    pub fn append_bash_execution(
        &mut self,
        command: String,
        output: String,
        exit_code: i32,
        cancelled: bool,
        truncated: bool,
        full_output_path: Option<String>,
    ) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::Message(MessageEntry {
            base,
            message: SessionMessage::BashExecution {
                command,
                output,
                exit_code,
                cancelled: Some(cancelled),
                truncated: Some(truncated),
                full_output_path,
                timestamp: Some(chrono::Utc::now().timestamp_millis()),
                extra: HashMap::new(),
            },
        });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.cached_message_count += 1;
        self.enqueue_autosave_mutation(AutosaveMutationKind::Message);
        id
    }

    /// Get the current session name from the cached value (Gap C).
    pub fn get_name(&self) -> Option<String> {
        self.cached_name.clone()
    }

    /// Set the session name by appending a `SessionInfo` entry.
    pub fn set_name(&mut self, name: &str) -> String {
        self.append_session_info(Some(name.to_string()))
    }

    pub fn append_compaction(
        &mut self,
        summary: String,
        first_kept_entry_id: String,
        tokens_before: u64,
        details: Option<Value>,
        from_hook: Option<bool>,
    ) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::Compaction(CompactionEntry {
            base,
            summary,
            first_kept_entry_id,
            tokens_before,
            details,
            from_hook,
        });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
        id
    }

    pub fn append_branch_summary(
        &mut self,
        from_id: String,
        summary: String,
        details: Option<Value>,
        from_hook: Option<bool>,
    ) -> String {
        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::BranchSummary(BranchSummaryEntry {
            base,
            from_id,
            summary,
            details,
            from_hook,
        });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
        id
    }

    pub fn ensure_entry_ids(&mut self) {
        ensure_entry_ids(&mut self.entries);
        self.rebuild_all_caches();
    }

    /// Rebuild all derived caches from `self.entries`.
    ///
    /// Called after bulk mutations (save round-trip, ensure_entry_ids) where
    /// incremental maintenance is impractical.
    fn rebuild_all_caches(&mut self) {
        let finalized = finalize_loaded_entries(&mut self.entries);
        self.entry_ids = finalized.entry_ids;
        self.entry_index = finalized.entry_index;
        self.cached_message_count = finalized.message_count;
        self.cached_name = finalized.name;
        // is_linear requires BOTH: no branching in the entry tree AND the
        // current leaf_id pointing at the last entry.  If the user navigated
        // to a mid-chain entry before saving, the leaf differs from the tip
        // and the fast path would return wrong results.
        self.is_linear = finalized.is_linear && self.leaf_id == finalized.leaf_id;
    }

    /// Convert session entries to model messages (for provider context).
    pub fn to_messages(&self) -> Vec<Message> {
        let mut messages = Vec::new();
        for entry in &self.entries {
            if let SessionEntry::Message(msg_entry) = entry {
                if let Some(message) = session_message_to_model(&msg_entry.message) {
                    messages.push(message);
                }
            }
        }
        messages
    }

    /// Render the session as a standalone HTML document.
    pub fn to_html(&self) -> String {
        let mut html = String::new();
        html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
        html.push_str("<title>Pi Session</title>");
        html.push_str("<style>");
        html.push_str(
            "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:24px;background:#0b0c10;color:#e6e6e6;}
            h1{margin:0 0 8px 0;}
            .meta{color:#9aa0a6;margin-bottom:24px;font-size:14px;}
            .msg{padding:16px 18px;margin:12px 0;border-radius:8px;background:#14161b;}
            .msg.user{border-left:4px solid #4fc3f7;}
            .msg.assistant{border-left:4px solid #81c784;}
            .msg.tool{border-left:4px solid #ffb74d;}
            .msg.system{border-left:4px solid #ef9a9a;}
            .role{font-weight:600;margin-bottom:8px;}
            pre{white-space:pre-wrap;background:#0f1115;padding:12px;border-radius:6px;overflow:auto;}
            .thinking summary{cursor:pointer;}
            img{max-width:100%;height:auto;border-radius:6px;margin-top:8px;}
            .note{color:#9aa0a6;font-size:13px;margin:6px 0;}
            ",
        );
        html.push_str("</style></head><body>");

        let _ = write!(
            html,
            "<h1>Pi Session</h1><div class=\"meta\">Session {} • {} • cwd: {}</div>",
            escape_html(&self.header.id),
            escape_html(&self.header.timestamp),
            escape_html(&self.header.cwd)
        );

        for entry in &self.entries {
            match entry {
                SessionEntry::Message(message) => {
                    html.push_str(&render_session_message(&message.message));
                }
                SessionEntry::ModelChange(change) => {
                    let _ = write!(
                        html,
                        "<div class=\"msg system\"><div class=\"role\">Model</div><div class=\"note\">{} / {}</div></div>",
                        escape_html(&change.provider),
                        escape_html(&change.model_id)
                    );
                }
                SessionEntry::ThinkingLevelChange(change) => {
                    let _ = write!(
                        html,
                        "<div class=\"msg system\"><div class=\"role\">Thinking</div><div class=\"note\">{}</div></div>",
                        escape_html(&change.thinking_level)
                    );
                }
                SessionEntry::Compaction(compaction) => {
                    let _ = write!(
                        html,
                        "<div class=\"msg system\"><div class=\"role\">Compaction</div><pre>{}</pre></div>",
                        escape_html(&compaction.summary)
                    );
                }
                SessionEntry::BranchSummary(summary) => {
                    let _ = write!(
                        html,
                        "<div class=\"msg system\"><div class=\"role\">Branch Summary</div><pre>{}</pre></div>",
                        escape_html(&summary.summary)
                    );
                }
                SessionEntry::SessionInfo(info) => {
                    if let Some(name) = &info.name {
                        let _ = write!(
                            html,
                            "<div class=\"msg system\"><div class=\"role\">Session Name</div><div class=\"note\">{}</div></div>",
                            escape_html(name)
                        );
                    }
                }
                SessionEntry::Custom(custom) => {
                    let _ = write!(
                        html,
                        "<div class=\"msg system\"><div class=\"role\">{}</div></div>",
                        escape_html(&custom.custom_type)
                    );
                }
                SessionEntry::Label(_) => {}
            }
        }

        html.push_str("</body></html>");
        html
    }

    /// Update header model info.
    pub fn set_model_header(
        &mut self,
        provider: Option<String>,
        model_id: Option<String>,
        thinking_level: Option<String>,
    ) {
        let changed = provider.is_some() || model_id.is_some() || thinking_level.is_some();
        if provider.is_some() {
            self.header.provider = provider;
        }
        if model_id.is_some() {
            self.header.model_id = model_id;
        }
        if thinking_level.is_some() {
            self.header.thinking_level = thinking_level;
        }
        if changed {
            self.header_dirty = true;
            self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
        }
    }

    pub fn set_branched_from(&mut self, path: Option<String>) {
        self.header.parent_session = path;
        self.header_dirty = true;
        self.enqueue_autosave_mutation(AutosaveMutationKind::Metadata);
    }

    /// Plan a `/fork` from a user message entry ID.
    ///
    /// Returns the entries to copy into a new session (path to the parent of the selected
    /// user message), the new leaf id, and the selected user message text for editor pre-fill.
    pub fn plan_fork_from_user_message(&self, entry_id: &str) -> Result<ForkPlan> {
        let entry = self
            .get_entry(entry_id)
            .ok_or_else(|| Error::session(format!("Fork target not found: {entry_id}")))?;

        let SessionEntry::Message(message_entry) = entry else {
            return Err(Error::session(format!(
                "Fork target is not a message entry: {entry_id}"
            )));
        };

        let SessionMessage::User { content, .. } = &message_entry.message else {
            return Err(Error::session(format!(
                "Fork target is not a user message: {entry_id}"
            )));
        };

        let selected_text = user_content_to_text(content);
        let leaf_id = message_entry.base.parent_id.clone();

        let entries = if let Some(ref leaf_id) = leaf_id {
            let path_ids = self.get_path_to_entry(leaf_id);
            let mut entries = Vec::new();
            for path_id in path_ids {
                let entry = self.get_entry(&path_id).ok_or_else(|| {
                    Error::session(format!("Failed to build fork: missing entry {path_id}"))
                })?;
                entries.push(entry.clone());
            }
            entries
        } else {
            Vec::new()
        };

        Ok(ForkPlan {
            entries,
            leaf_id,
            selected_text,
        })
    }

    fn next_entry_id(&self) -> String {
        let use_entry_id_cache = session_entry_id_cache_enabled();
        for _ in 0..100 {
            let candidate = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
            let exists = if use_entry_id_cache {
                self.entry_ids.contains(&candidate)
            } else {
                self.entries
                    .iter()
                    .any(|entry| entry.base_id().is_some_and(|id| id == candidate.as_str()))
            };
            if !exists {
                return candidate;
            }
        }

        // Extremely unlikely fallback: recover by rebuilding the set and retrying.
        if use_entry_id_cache {
            generate_entry_id(&self.entry_ids)
        } else {
            let existing = entry_id_set(&self.entries);
            generate_entry_id(&existing)
        }
    }

    // ========================================================================
    // Tree Navigation
    // ========================================================================

    /// Build a map from entry ID to its parent ID.
    fn build_parent_map(&self) -> HashMap<String, Option<String>> {
        self.entries
            .iter()
            .filter_map(|e| {
                e.base_id()
                    .map(|id| (id.clone(), e.base().parent_id.clone()))
            })
            .collect()
    }

    /// Build a map from parent ID to children IDs.
    fn build_children_map(&self) -> HashMap<Option<String>, Vec<String>> {
        let mut children: HashMap<Option<String>, Vec<String>> = HashMap::new();
        for entry in &self.entries {
            if let Some(id) = entry.base_id() {
                children
                    .entry(entry.base().parent_id.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
        children
    }

    /// Get the path from an entry back to the root (inclusive).
    /// Returns entry IDs in order from root to the specified entry.
    pub fn get_path_to_entry(&self, entry_id: &str) -> Vec<String> {
        let parent_map = self.build_parent_map();
        let mut path = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut current = Some(entry_id.to_string());

        while let Some(id) = current {
            if !visited.insert(id.clone()) {
                break; // cycle detected
            }
            path.push(id.clone());
            current = parent_map.get(&id).and_then(Clone::clone);
        }

        path.reverse();
        path
    }

    /// Get direct children of an entry.
    pub fn get_children(&self, entry_id: Option<&str>) -> Vec<String> {
        let children_map = self.build_children_map();
        let key = entry_id.map(String::from);
        children_map.get(&key).cloned().unwrap_or_default()
    }

    /// List all leaf nodes (entries with no children).
    pub fn list_leaves(&self) -> Vec<String> {
        let children_map = self.build_children_map();
        self.entries
            .iter()
            .filter_map(|e| {
                let id = e.base_id()?;
                // An entry is a leaf if it has no children
                if children_map
                    .get(&Some(id.clone()))
                    .is_none_or(Vec::is_empty)
                {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Navigate to a specific entry, making it the current leaf.
    /// Returns true if the entry exists.
    pub fn navigate_to(&mut self, entry_id: &str) -> bool {
        // Gap B: O(1) existence check via entry_index.
        let exists = self.entry_index.contains_key(entry_id);
        if exists {
            // Gap A: navigating away from the tip breaks linearity.
            let is_tip = self
                .entries
                .last()
                .and_then(|e| e.base_id())
                .is_some_and(|id| id == entry_id);
            if !is_tip {
                self.is_linear = false;
            }
            self.leaf_id = Some(entry_id.to_string());
            true
        } else {
            false
        }
    }

    /// Reset the leaf pointer to root (before any entries).
    ///
    /// After calling this, the next appended entry will become a new root entry
    /// (`parent_id = None`). This is used by interactive `/tree` navigation when
    /// re-editing the first user message.
    pub fn reset_leaf(&mut self) {
        self.leaf_id = None;
        self.is_linear = false;
    }

    /// Create a new branch starting from a specific entry.
    /// Sets the leaf_id to the specified entry so new entries branch from there.
    /// Returns true if the entry exists.
    pub fn create_branch_from(&mut self, entry_id: &str) -> bool {
        self.navigate_to(entry_id)
    }

    /// Get the entry at a specific ID (Gap B: O(1) via `entry_index`).
    pub fn get_entry(&self, entry_id: &str) -> Option<&SessionEntry> {
        self.entry_index
            .get(entry_id)
            .and_then(|&idx| self.entries.get(idx))
    }

    /// Get the entry at a specific ID, mutable (Gap B: O(1) via `entry_index`).
    pub fn get_entry_mut(&mut self, entry_id: &str) -> Option<&mut SessionEntry> {
        self.entry_index
            .get(entry_id)
            .copied()
            .and_then(|idx| self.entries.get_mut(idx))
    }

    /// Entries along the current leaf path, in chronological order.
    ///
    /// Gap A: when `is_linear` is true (the 99% case — no branching has
    /// occurred), this returns all entries directly without building a
    /// parent map or tracing the path.
    pub fn entries_for_current_path(&self) -> Vec<&SessionEntry> {
        let Some(leaf_id) = &self.leaf_id else {
            return Vec::new();
        };

        // Fast path: linear session — all entries are on the current path.
        if self.is_linear {
            return self.entries.iter().collect();
        }

        let path = self.get_path_to_entry(leaf_id);
        let path_set: HashSet<&str> = path.iter().map(String::as_str).collect();

        self.entries
            .iter()
            .filter(|entry| {
                entry
                    .base_id()
                    .is_some_and(|id| path_set.contains(id.as_str()))
            })
            .collect()
    }

    /// Convert session entries along the current path to model messages.
    /// This follows parent_id links from leaf_id back to root.
    pub fn to_messages_for_current_path(&self) -> Vec<Message> {
        let path_entries = self.entries_for_current_path();

        // If the current path contains a compaction entry, omit older messages
        // and insert the compaction summary before the kept region.
        let last_compaction = path_entries.iter().rev().find_map(|entry| match entry {
            SessionEntry::Compaction(compaction) => Some(compaction),
            _ => None,
        });

        if let Some(compaction) = last_compaction {
            let mut messages = Vec::new();

            let summary_message = SessionMessage::CompactionSummary {
                summary: compaction.summary.clone(),
                tokens_before: compaction.tokens_before,
            };
            if let Some(message) = session_message_to_model(&summary_message) {
                messages.push(message);
            }

            // Find the index of the compaction entry so we can fall back to
            // including everything after it if first_kept_entry_id is orphaned.
            let compaction_idx = path_entries.iter().position(
                |e| matches!(e, SessionEntry::Compaction(c) if std::ptr::eq(c, compaction)),
            );

            let has_kept_entry = path_entries.iter().any(|e| {
                e.base_id()
                    .is_some_and(|id| id == &compaction.first_kept_entry_id)
            });

            let mut keep = false;
            let mut past_compaction = false;
            for (idx, entry) in path_entries.iter().enumerate() {
                // Track when we pass the compaction entry itself.
                if compaction_idx == Some(idx) {
                    past_compaction = true;
                }

                if !keep {
                    if has_kept_entry {
                        // Normal path: skip until we find the first kept entry.
                        if entry
                            .base_id()
                            .is_some_and(|id| id == &compaction.first_kept_entry_id)
                        {
                            keep = true;
                        } else {
                            continue;
                        }
                    } else if past_compaction {
                        // Fallback: first_kept_entry_id is orphaned (session corruption).
                        // Include all entries after the compaction entry to avoid data loss.
                        tracing::warn!(
                            first_kept_entry_id = %compaction.first_kept_entry_id,
                            "Compaction references missing entry; including all post-compaction entries"
                        );
                        keep = true;
                    } else {
                        continue;
                    }
                }

                match entry {
                    SessionEntry::Message(msg_entry) => {
                        if let Some(message) = session_message_to_model(&msg_entry.message) {
                            messages.push(message);
                        }
                    }
                    SessionEntry::BranchSummary(summary) => {
                        let summary_message = SessionMessage::BranchSummary {
                            summary: summary.summary.clone(),
                            from_id: summary.from_id.clone(),
                        };
                        if let Some(message) = session_message_to_model(&summary_message) {
                            messages.push(message);
                        }
                    }
                    _ => {}
                }
            }

            return messages;
        }

        let mut messages = Vec::new();
        for entry in path_entries {
            match entry {
                SessionEntry::Message(msg_entry) => {
                    if let Some(message) = session_message_to_model(&msg_entry.message) {
                        messages.push(message);
                    }
                }
                SessionEntry::BranchSummary(summary) => {
                    let summary_message = SessionMessage::BranchSummary {
                        summary: summary.summary.clone(),
                        from_id: summary.from_id.clone(),
                    };
                    if let Some(message) = session_message_to_model(&summary_message) {
                        messages.push(message);
                    }
                }
                _ => {}
            }
        }
        messages
    }

    /// Find the nearest ancestor that is a fork point (has multiple children)
    /// and return its children (sibling branch roots). Each sibling is represented
    /// by its branch-root entry ID plus the leaf ID reachable from that root.
    ///
    /// Returns `(fork_point_id, sibling_leaves)` where each sibling leaf is
    /// a leaf entry ID reachable through the fork point's children. The current
    /// leaf is included in the list.
    pub fn sibling_branches(&self) -> Option<(Option<String>, Vec<SiblingBranch>)> {
        let children_map = self.build_children_map();
        let leaf_id = self.leaf_id.as_ref()?;
        let path = self.get_path_to_entry(leaf_id);
        if path.is_empty() {
            return None;
        }

        // Walk backwards from current leaf's path to find the nearest fork point.
        // A fork point is any entry whose parent has >1 children, OR None (root)
        // with >1 root entries.
        // We check each entry's parent to see if the parent has multiple children.
        for (idx, entry_id) in path.iter().enumerate().rev() {
            let parent_of_entry = self
                .get_entry(entry_id)
                .and_then(|e| e.base().parent_id.clone());

            let siblings_at_parent = children_map
                .get(&parent_of_entry)
                .cloned()
                .unwrap_or_default();

            if siblings_at_parent.len() > 1 {
                // This is a fork point. Collect all leaves reachable from each sibling.
                let mut branches = Vec::new();
                for sibling_root in &siblings_at_parent {
                    let leaf = Self::deepest_leaf_from(&children_map, sibling_root);
                    let preview = self.entry_preview(&leaf);
                    let msg_count = self.count_messages_on_path(&leaf);
                    let is_current = path[idx..].contains(sibling_root);
                    branches.push(SiblingBranch {
                        root_id: sibling_root.clone(),
                        leaf_id: leaf,
                        preview,
                        message_count: msg_count,
                        is_current,
                    });
                }
                return Some((parent_of_entry, branches));
            }
        }

        None
    }

    /// Follow the first child chain to reach the deepest leaf from a starting entry.
    fn deepest_leaf_from(
        children_map: &HashMap<Option<String>, Vec<String>>,
        start_id: &str,
    ) -> String {
        let mut current = start_id.to_string();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                tracing::warn!("Cycle detected in session tree at entry: {current}");
                return current;
            }
            let children = children_map.get(&Some(current.clone()));
            match children.and_then(|c| c.first()) {
                Some(child) => current.clone_from(child),
                None => return current,
            }
        }
    }

    /// Get a short preview string for an entry (first user message text on
    /// the path from root to the given leaf).
    fn entry_preview(&self, leaf_id: &str) -> String {
        let path = self.get_path_to_entry(leaf_id);
        for id in &path {
            if let Some(SessionEntry::Message(msg)) = self.get_entry(id) {
                if let SessionMessage::User { content, .. } = &msg.message {
                    let text = user_content_to_text(content);
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        return if trimmed.chars().count() > 60 {
                            let truncated: String = trimmed.chars().take(57).collect();
                            format!("{truncated}...")
                        } else {
                            trimmed.to_string()
                        };
                    }
                }
            }
        }
        String::from("(empty)")
    }

    /// Count message entries along the path to a leaf.
    fn count_messages_on_path(&self, leaf_id: &str) -> usize {
        let path = self.get_path_to_entry(leaf_id);
        let path_set: HashSet<&str> = path.iter().map(String::as_str).collect();
        self.entries
            .iter()
            .filter(|e| {
                matches!(e, SessionEntry::Message(_))
                    && e.base_id().is_some_and(|id| path_set.contains(id.as_str()))
            })
            .count()
    }

    /// Get a summary of branches in this session.
    pub fn branch_summary(&self) -> BranchInfo {
        let leaves = self.list_leaves();
        let children_map = self.build_children_map();

        // Find branch points (entries with multiple children)
        let branch_points: Vec<String> = self
            .entries
            .iter()
            .filter_map(|e| {
                let id = e.base_id()?;
                let children = children_map.get(&Some(id.clone()))?;
                if children.len() > 1 {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        BranchInfo {
            total_entries: self.entries.len(),
            leaf_count: leaves.len(),
            branch_point_count: branch_points.len(),
            current_leaf: self.leaf_id.clone(),
            leaves,
            branch_points,
        }
    }

    /// Add a label to an entry.
    pub fn add_label(&mut self, target_id: &str, label: Option<String>) -> Option<String> {
        // Verify target exists
        self.get_entry(target_id)?;

        let id = self.next_entry_id();
        let base = EntryBase::new(self.leaf_id.clone(), id.clone());
        let entry = SessionEntry::Label(LabelEntry {
            base,
            target_id: target_id.to_string(),
            label,
        });
        self.leaf_id = Some(id.clone());
        self.entries.push(entry);
        self.entry_index.insert(id.clone(), self.entries.len() - 1);
        self.entry_ids.insert(id.clone());
        self.enqueue_autosave_mutation(AutosaveMutationKind::Label);
        Some(id)
    }
}

/// Summary of branches in a session.
#[derive(Debug, Clone)]
pub struct BranchInfo {
    pub total_entries: usize,
    pub leaf_count: usize,
    pub branch_point_count: usize,
    pub current_leaf: Option<String>,
    pub leaves: Vec<String>,
    pub branch_points: Vec<String>,
}

/// A sibling branch at a fork point.
#[derive(Debug, Clone)]
pub struct SiblingBranch {
    /// Entry ID of the branch root (child of the fork point).
    pub root_id: String,
    /// Leaf entry ID reachable from this branch root.
    pub leaf_id: String,
    /// Short preview of the first user message on this branch.
    pub preview: String,
    /// Number of message entries along the path.
    pub message_count: usize,
    /// Whether the current session leaf is on this branch.
    pub is_current: bool,
}

#[derive(Debug, Clone)]
struct SessionPickEntry {
    path: PathBuf,
    id: String,
    timestamp: String,
    message_count: u64,
    name: Option<String>,
    last_modified_ms: i64,
    size_bytes: u64,
}

impl SessionPickEntry {
    fn from_meta(meta: crate::session_index::SessionMeta) -> Option<Self> {
        let path = PathBuf::from(meta.path);
        if !path.exists() {
            return None;
        }
        Some(Self {
            path,
            id: meta.id,
            timestamp: meta.timestamp,
            message_count: meta.message_count,
            name: meta.name,
            last_modified_ms: meta.last_modified_ms,
            size_bytes: meta.size_bytes,
        })
    }
}

const fn can_reuse_known_entry(
    known_entry: &SessionPickEntry,
    disk_ms: i64,
    disk_size: u64,
) -> bool {
    known_entry.last_modified_ms == disk_ms && known_entry.size_bytes == disk_size
}

async fn scan_sessions_on_disk(
    project_session_dir: &Path,
    known: Vec<SessionPickEntry>,
) -> Result<Vec<SessionPickEntry>> {
    let path_buf = project_session_dir.to_path_buf();
    let (tx, rx) = oneshot::channel();

    thread::Builder::new()
        .name("session-scan".to_string())
        .spawn(move || {
            let res = (|| -> Result<Vec<SessionPickEntry>> {
                let mut entries = Vec::new();
                let dir_entries = std::fs::read_dir(&path_buf)
                    .map_err(|e| Error::session(format!("Failed to read sessions: {e}")))?;

                let known_map: HashMap<PathBuf, SessionPickEntry> =
                    known.into_iter().map(|e| (e.path.clone(), e)).collect();

                for entry in dir_entries {
                    let entry =
                        entry.map_err(|e| Error::session(format!("Read dir entry: {e}")))?;
                    let path = entry.path();
                    if is_session_file_path(&path) {
                        // Optimization: if we already have this file indexed and both mtime and
                        // size match, reuse indexed metadata to avoid a full parse.
                        if let Ok(metadata) = std::fs::metadata(&path) {
                            let disk_size = metadata.len();
                            if let Ok(modified) = metadata.modified() {
                                #[allow(clippy::cast_possible_truncation)]
                                let disk_ms = modified
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis()
                                    as i64;

                                if let Some(known_entry) = known_map.get(&path) {
                                    if can_reuse_known_entry(known_entry, disk_ms, disk_size) {
                                        entries.push(known_entry.clone());
                                        continue;
                                    }
                                }
                            }
                        }

                        if let Ok(meta) = load_session_meta(&path) {
                            entries.push(meta);
                        }
                    }
                }
                Ok(entries)
            })();
            let cx = AgentCx::for_request();
            let _ = tx.send(cx.cx(), res);
        })
        .map_err(|e| Error::session(format!("Failed to spawn session scan thread: {e}")))?;

    let cx = AgentCx::for_request();
    rx.recv(cx.cx())
        .await
        .map_err(|_| Error::session("Scan task cancelled"))?
}

fn is_session_file_path(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("jsonl") => true,
        #[cfg(feature = "sqlite-sessions")]
        Some("sqlite") => true,
        _ => false,
    }
}

fn load_session_meta(path: &Path) -> Result<SessionPickEntry> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("jsonl") => load_session_meta_jsonl(path),
        #[cfg(feature = "sqlite-sessions")]
        Some("sqlite") => load_session_meta_sqlite(path),
        _ => Err(Error::session(format!(
            "Unsupported session file extension: {}",
            path.display()
        ))),
    }
}

#[derive(Deserialize)]
struct PartialEntry {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    name: Option<String>,
}

fn load_session_meta_jsonl(path: &Path) -> Result<SessionPickEntry> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::session(format!("Failed to read session: {e}")))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let header_line = lines
        .next()
        .ok_or_else(|| Error::session("Empty session file"))?
        .map_err(|e| Error::session(format!("Failed to read header: {e}")))?;

    let header: SessionHeader =
        serde_json::from_str(&header_line).map_err(|e| Error::session(format!("{e}")))?;

    let mut message_count = 0u64;
    let mut name = None;

    for line_content in lines.map_while(std::result::Result::ok) {
        if let Ok(entry) = serde_json::from_str::<PartialEntry>(&line_content) {
            match entry.r#type.as_str() {
                "message" => message_count += 1,
                "session_info" => {
                    if entry.name.is_some() {
                        name = entry.name;
                    }
                }
                _ => {}
            }
        }
    }

    let metadata = std::fs::metadata(path)
        .map_err(|e| Error::session(format!("Failed to stat session: {e}")))?;
    let size_bytes = metadata.len();
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    #[allow(clippy::cast_possible_truncation)]
    let last_modified_ms = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64; // i64::MAX ms = ~292 million years, so truncation is safe

    Ok(SessionPickEntry {
        path: path.to_path_buf(),
        id: header.id,
        timestamp: header.timestamp,
        message_count,
        name,
        last_modified_ms,
        size_bytes,
    })
}

#[cfg(feature = "sqlite-sessions")]
fn load_session_meta_sqlite(path: &Path) -> Result<SessionPickEntry> {
    let meta = futures::executor::block_on(async {
        crate::session_sqlite::load_session_meta(path).await
    })?;
    let header = meta.header;

    let metadata = std::fs::metadata(path)
        .map_err(|e| Error::session(format!("Failed to stat session: {e}")))?;
    let size_bytes = metadata.len();
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    #[allow(clippy::cast_possible_truncation)]
    let last_modified_ms = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64; // i64::MAX ms = ~292 million years, so truncation is safe

    Ok(SessionPickEntry {
        path: path.to_path_buf(),
        id: header.id,
        timestamp: header.timestamp,
        message_count: meta.message_count,
        name: meta.name,
        last_modified_ms,
        size_bytes,
    })
}

// ============================================================================
// Session Header
// ============================================================================

/// Session file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHeader {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
    pub id: String,
    pub timestamp: String,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "branchedFrom",
        alias = "parentSession"
    )]
    pub parent_session: Option<String>,
}

impl SessionHeader {
    pub fn new() -> Self {
        let now = chrono::Utc::now();
        Self {
            r#type: "session".to_string(),
            version: Some(SESSION_VERSION),
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            provider: None,
            model_id: None,
            thinking_level: None,
            parent_session: None,
        }
    }
}

impl Default for SessionHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Session Entries
// ============================================================================

/// A session entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEntry {
    Message(MessageEntry),
    ModelChange(ModelChangeEntry),
    ThinkingLevelChange(ThinkingLevelChangeEntry),
    Compaction(CompactionEntry),
    BranchSummary(BranchSummaryEntry),
    Label(LabelEntry),
    SessionInfo(SessionInfoEntry),
    Custom(CustomEntry),
}

impl SessionEntry {
    pub const fn base(&self) -> &EntryBase {
        match self {
            Self::Message(e) => &e.base,
            Self::ModelChange(e) => &e.base,
            Self::ThinkingLevelChange(e) => &e.base,
            Self::Compaction(e) => &e.base,
            Self::BranchSummary(e) => &e.base,
            Self::Label(e) => &e.base,
            Self::SessionInfo(e) => &e.base,
            Self::Custom(e) => &e.base,
        }
    }

    pub const fn base_mut(&mut self) -> &mut EntryBase {
        match self {
            Self::Message(e) => &mut e.base,
            Self::ModelChange(e) => &mut e.base,
            Self::ThinkingLevelChange(e) => &mut e.base,
            Self::Compaction(e) => &mut e.base,
            Self::BranchSummary(e) => &mut e.base,
            Self::Label(e) => &mut e.base,
            Self::SessionInfo(e) => &mut e.base,
            Self::Custom(e) => &mut e.base,
        }
    }

    pub const fn base_id(&self) -> Option<&String> {
        self.base().id.as_ref()
    }
}

/// Base entry fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryBase {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub timestamp: String,
}

impl EntryBase {
    pub fn new(parent_id: Option<String>, id: String) -> Self {
        Self {
            id: Some(id),
            parent_id,
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }
    }
}

/// Message entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    pub message: SessionMessage,
}

/// Session message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "role",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SessionMessage {
    User {
        content: UserContent,
        #[serde(skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    Assistant {
        #[serde(flatten)]
        message: AssistantMessage,
    },
    ToolResult {
        tool_call_id: String,
        tool_name: String,
        content: Vec<ContentBlock>,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<Value>,
        #[serde(default)]
        is_error: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    Custom {
        custom_type: String,
        content: String,
        #[serde(default)]
        display: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
    },
    BashExecution {
        command: String,
        output: String,
        exit_code: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        cancelled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        truncated: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        full_output_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timestamp: Option<i64>,
        #[serde(flatten)]
        extra: HashMap<String, Value>,
    },
    BranchSummary {
        summary: String,
        from_id: String,
    },
    CompactionSummary {
        summary: String,
        tokens_before: u64,
    },
}

impl From<Message> for SessionMessage {
    fn from(message: Message) -> Self {
        match message {
            Message::User(user) => Self::User {
                content: user.content,
                timestamp: Some(user.timestamp),
            },
            Message::Assistant(assistant) => Self::Assistant {
                message: Arc::try_unwrap(assistant).unwrap_or_else(|a| (*a).clone()),
            },
            Message::ToolResult(result) => Self::ToolResult {
                tool_call_id: result.tool_call_id,
                tool_name: result.tool_name,
                content: result.content,
                details: result.details,
                is_error: result.is_error,
                timestamp: Some(result.timestamp),
            },
            Message::Custom(custom) => Self::Custom {
                custom_type: custom.custom_type,
                content: custom.content,
                display: custom.display,
                details: custom.details,
                timestamp: Some(custom.timestamp),
            },
        }
    }
}

/// Model change entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelChangeEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    pub provider: String,
    pub model_id: String,
}

/// Thinking level change entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThinkingLevelChangeEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    pub thinking_level: String,
}

/// Compaction entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactionEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    pub summary: String,
    pub first_kept_entry_id: String,
    pub tokens_before: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_hook: Option<bool>,
}

/// Branch summary entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchSummaryEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    pub from_id: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_hook: Option<bool>,
}

/// Label entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Session info entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfoEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Custom entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomEntry {
    #[serde(flatten)]
    pub base: EntryBase,
    pub custom_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ============================================================================
// Utilities
// ============================================================================

/// Encode a working directory path for use in session directory names.
pub fn encode_cwd(path: &std::path::Path) -> String {
    let s = path.display().to_string();
    let s = s.trim_start_matches(['/', '\\']);
    let s = s.replace(['/', '\\', ':'], "-");
    format!("--{s}--")
}

pub(crate) fn session_message_to_model(message: &SessionMessage) -> Option<Message> {
    match message {
        SessionMessage::User { content, timestamp } => Some(Message::User(UserMessage {
            content: content.clone(),
            timestamp: timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
        })),
        SessionMessage::Assistant { message } => Some(Message::assistant(message.clone())),
        SessionMessage::ToolResult {
            tool_call_id,
            tool_name,
            content,
            details,
            is_error,
            timestamp,
        } => Some(Message::ToolResult(ToolResultMessage {
            tool_call_id: tool_call_id.clone(),
            tool_name: tool_name.clone(),
            content: content.clone(),
            details: details.clone(),
            is_error: *is_error,
            timestamp: timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
        })),
        SessionMessage::Custom {
            custom_type,
            content,
            display,
            details,
            timestamp,
        } => Some(Message::Custom(crate::model::CustomMessage {
            content: content.clone(),
            custom_type: custom_type.clone(),
            display: *display,
            details: details.clone(),
            timestamp: timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
        })),
        SessionMessage::BashExecution {
            command,
            output,
            exit_code,
            cancelled,
            truncated,
            full_output_path,
            timestamp,
            extra,
        } => {
            if extra
                .get("excludeFromContext")
                .and_then(Value::as_bool)
                .is_some_and(|v| v)
            {
                return None;
            }
            let text = bash_execution_to_text(
                command,
                output,
                *exit_code,
                cancelled.unwrap_or(false),
                truncated.unwrap_or(false),
                full_output_path.as_deref(),
            );
            Some(Message::User(UserMessage {
                content: UserContent::Blocks(vec![ContentBlock::Text(TextContent::new(text))]),
                timestamp: timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
            }))
        }
        SessionMessage::BranchSummary { summary, .. } => Some(Message::User(UserMessage {
            content: UserContent::Blocks(vec![ContentBlock::Text(TextContent::new(format!(
                "{BRANCH_SUMMARY_PREFIX}{summary}{BRANCH_SUMMARY_SUFFIX}"
            )))]),
            timestamp: chrono::Utc::now().timestamp_millis(),
        })),
        SessionMessage::CompactionSummary { summary, .. } => Some(Message::User(UserMessage {
            content: UserContent::Blocks(vec![ContentBlock::Text(TextContent::new(format!(
                "{COMPACTION_SUMMARY_PREFIX}{summary}{COMPACTION_SUMMARY_SUFFIX}"
            )))]),
            timestamp: chrono::Utc::now().timestamp_millis(),
        })),
    }
}

const COMPACTION_SUMMARY_PREFIX: &str = "The conversation history before this point was compacted into the following summary:\n\n<summary>\n";
const COMPACTION_SUMMARY_SUFFIX: &str = "\n</summary>";

const BRANCH_SUMMARY_PREFIX: &str =
    "The following is a summary of a branch that this conversation came back from:\n\n<summary>\n";
const BRANCH_SUMMARY_SUFFIX: &str = "</summary>";

pub(crate) fn bash_execution_to_text(
    command: &str,
    output: &str,
    exit_code: i32,
    cancelled: bool,
    truncated: bool,
    full_output_path: Option<&str>,
) -> String {
    let mut text = format!("Ran `{command}`\n");
    if output.is_empty() {
        text.push_str("(no output)");
    } else {
        text.push_str("```\n");
        text.push_str(output);
        if !output.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("```");
    }

    if cancelled {
        text.push_str("\n\n(command cancelled)");
    } else if exit_code != 0 {
        let _ = write!(text, "\n\nCommand exited with code {exit_code}");
    }

    if truncated {
        if let Some(path) = full_output_path {
            let _ = write!(text, "\n\n[Output truncated. Full output: {path}]");
        }
    }

    text
}

fn render_session_message(message: &SessionMessage) -> String {
    match message {
        SessionMessage::User { content, .. } => {
            let mut html = String::new();
            html.push_str("<div class=\"msg user\"><div class=\"role\">User</div>");
            html.push_str(&render_user_content(content));
            html.push_str("</div>");
            html
        }
        SessionMessage::Assistant { message } => {
            let mut html = String::new();
            html.push_str("<div class=\"msg assistant\"><div class=\"role\">Assistant</div>");
            html.push_str(&render_blocks(&message.content));
            html.push_str("</div>");
            html
        }
        SessionMessage::ToolResult {
            tool_name,
            content,
            is_error,
            details,
            ..
        } => {
            let mut html = String::new();
            let role = if *is_error { "Tool Error" } else { "Tool" };
            let _ = write!(
                html,
                "<div class=\"msg tool\"><div class=\"role\">{}: {}</div>",
                role,
                escape_html(tool_name)
            );
            html.push_str(&render_blocks(content));
            if let Some(details) = details {
                let details_str =
                    serde_json::to_string_pretty(details).unwrap_or_else(|_| details.to_string());
                let _ = write!(html, "<pre>{}</pre>", escape_html(&details_str));
            }
            html.push_str("</div>");
            html
        }
        SessionMessage::Custom {
            custom_type,
            content,
            ..
        } => {
            let mut html = String::new();
            let _ = write!(
                html,
                "<div class=\"msg system\"><div class=\"role\">{}</div><pre>{}</pre></div>",
                escape_html(custom_type),
                escape_html(content)
            );
            html
        }
        SessionMessage::BashExecution {
            command,
            output,
            exit_code,
            ..
        } => {
            let mut html = String::new();
            let _ = write!(
                html,
                "<div class=\"msg tool\"><div class=\"role\">Bash (exit {exit_code})</div><pre>{}</pre><pre>{}</pre></div>",
                escape_html(command),
                escape_html(output)
            );
            html
        }
        SessionMessage::BranchSummary { summary, .. } => {
            format!(
                "<div class=\"msg system\"><div class=\"role\">Branch Summary</div><pre>{}</pre></div>",
                escape_html(summary)
            )
        }
        SessionMessage::CompactionSummary { summary, .. } => {
            format!(
                "<div class=\"msg system\"><div class=\"role\">Compaction</div><pre>{}</pre></div>",
                escape_html(summary)
            )
        }
    }
}

fn render_user_content(content: &UserContent) -> String {
    match content {
        UserContent::Text(text) => format!("<pre>{}</pre>", escape_html(text)),
        UserContent::Blocks(blocks) => render_blocks(blocks),
    }
}

fn render_blocks(blocks: &[ContentBlock]) -> String {
    let mut html = String::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text) => {
                let _ = write!(html, "<pre>{}</pre>", escape_html(&text.text));
            }
            ContentBlock::Thinking(thinking) => {
                let _ = write!(
                    html,
                    "<details class=\"thinking\"><summary>Thinking</summary><pre>{}</pre></details>",
                    escape_html(&thinking.thinking)
                );
            }
            ContentBlock::Image(image) => {
                let _ = write!(
                    html,
                    "<img src=\"data:{};base64,{}\" alt=\"image\"/>",
                    escape_html(&image.mime_type),
                    escape_html(&image.data)
                );
            }
            ContentBlock::ToolCall(tool_call) => {
                let args = serde_json::to_string_pretty(&tool_call.arguments)
                    .unwrap_or_else(|_| tool_call.arguments.to_string());
                let _ = write!(
                    html,
                    "<div class=\"note\">Tool call: {}</div><pre>{}</pre>",
                    escape_html(&tool_call.name),
                    escape_html(&args)
                );
            }
        }
    }
    html
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn user_content_to_text(content: &UserContent) -> String {
    match content {
        UserContent::Text(text) => text.clone(),
        UserContent::Blocks(blocks) => content_blocks_to_text(blocks),
    }
}

fn content_blocks_to_text(blocks: &[ContentBlock]) -> String {
    let mut output = String::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text_block) => push_line(&mut output, &text_block.text),
            ContentBlock::Image(image) => {
                push_line(&mut output, &format!("[image: {}]", image.mime_type));
            }
            ContentBlock::Thinking(thinking_block) => {
                push_line(&mut output, &thinking_block.thinking);
            }
            ContentBlock::ToolCall(call) => {
                push_line(&mut output, &format!("[tool call: {}]", call.name));
            }
        }
    }
    output
}

fn push_line(out: &mut String, line: &str) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(line);
}

fn entry_id_set(entries: &[SessionEntry]) -> HashSet<String> {
    entries
        .iter()
        .filter_map(|e| e.base_id().cloned())
        .collect()
}

fn session_entry_stats(entries: &[SessionEntry]) -> (u64, Option<String>) {
    let mut message_count = 0u64;
    let mut name = None;
    for entry in entries {
        match entry {
            SessionEntry::Message(_) => message_count += 1,
            SessionEntry::SessionInfo(info) => {
                if info.name.is_some() {
                    name.clone_from(&info.name);
                }
            }
            _ => {}
        }
    }
    (message_count, name)
}

/// Minimum entry count to activate parallel deserialization (Gap E).
const PARALLEL_THRESHOLD: usize = 512;

/// Parse a JSONL session file on the current (blocking) thread.
///
/// Combines Gap E (parallel deserialization) and Gap F (single-pass
/// finalization) for the fastest possible open path.
#[allow(clippy::too_many_lines)]
fn open_jsonl_blocking(path_buf: PathBuf) -> Result<(Session, SessionOpenDiagnostics)> {
    type ChunkResult = (Vec<SessionEntry>, Vec<SessionOpenSkippedEntry>);

    // Read the entire file into memory for parallel parsing (Gap E).
    let contents = std::fs::read_to_string(&path_buf).map_err(|e| crate::Error::Io(Box::new(e)))?;
    let all_lines: Vec<&str> = contents.lines().collect();

    if all_lines.is_empty() {
        return Err(crate::Error::session("Empty session file"));
    }

    // Parse header (first line)
    let header: SessionHeader = serde_json::from_str(all_lines[0])
        .map_err(|e| crate::Error::session(format!("Invalid header: {e}")))?;

    let entry_lines = &all_lines[1..];
    let mut diagnostics = SessionOpenDiagnostics::default();

    // Gap E: parallel deserialization for large sessions.
    // Below the threshold, sequential is faster (no thread overhead).
    let num_threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));

    let mut entries: Vec<SessionEntry> =
        if entry_lines.len() >= PARALLEL_THRESHOLD && num_threads > 1 {
            let chunk_size = (entry_lines.len() / num_threads).max(64);

            let chunk_results: Vec<ChunkResult> = std::thread::scope(|s| {
                entry_lines
                    .chunks(chunk_size)
                    .enumerate()
                    .map(|(chunk_idx, chunk)| {
                        let base_offset = chunk_idx * chunk_size;
                        s.spawn(move || {
                            let mut ok = Vec::with_capacity(chunk.len());
                            let mut skip = Vec::new();
                            for (j, line) in chunk.iter().enumerate() {
                                match serde_json::from_str::<SessionEntry>(line) {
                                    Ok(entry) => ok.push(entry),
                                    Err(e) => {
                                        skip.push(SessionOpenSkippedEntry {
                                            line_number: base_offset + j + 2,
                                            error: e.to_string(),
                                        });
                                    }
                                }
                            }
                            (ok, skip)
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .collect()
            });

            let total: usize = chunk_results.iter().map(|(v, _)| v.len()).sum();
            let mut merged = Vec::with_capacity(total);
            for (chunk_entries, chunk_skipped) in chunk_results {
                merged.extend(chunk_entries);
                diagnostics.skipped_entries.extend(chunk_skipped);
            }
            merged
        } else {
            // Sequential path for small files.
            let mut entries = Vec::with_capacity(entry_lines.len());
            for (i, line) in entry_lines.iter().enumerate() {
                match serde_json::from_str::<SessionEntry>(line) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        diagnostics.skipped_entries.push(SessionOpenSkippedEntry {
                            line_number: i + 2,
                            error: e.to_string(),
                        });
                    }
                }
            }
            entries
        };

    // --- Single-pass load finalization (Gap F) ---
    let finalized = finalize_loaded_entries(&mut entries);
    for orphan in &finalized.orphans {
        diagnostics
            .orphaned_parent_links
            .push(SessionOpenOrphanedParentLink {
                entry_id: orphan.0.clone(),
                missing_parent_id: orphan.1.clone(),
            });
    }

    let entry_count = entries.len();

    Ok((
        Session {
            header,
            entries,
            path: Some(path_buf),
            leaf_id: finalized.leaf_id,
            session_dir: None,
            store_kind: SessionStoreKind::Jsonl,
            entry_ids: finalized.entry_ids,
            is_linear: finalized.is_linear,
            entry_index: finalized.entry_index,
            cached_message_count: finalized.message_count,
            cached_name: finalized.name,
            autosave_queue: AutosaveQueue::new(),
            autosave_durability: AutosaveDurabilityMode::from_env(),
            persisted_entry_count: entry_count,
            header_dirty: false,
            appends_since_checkpoint: 0,
        },
        diagnostics,
    ))
}

/// Open a session from its V2 sidecar store.
///
/// Reads the JSONL header (first line) for `SessionHeader`, then loads
/// entries from the V2 segment store via its offset index — O(index + tail)
/// instead of the O(n) full-file parse that `open_jsonl_blocking` performs.
#[allow(clippy::too_many_lines)]
fn open_from_v2_store_blocking(jsonl_path: PathBuf) -> Result<(Session, SessionOpenDiagnostics)> {
    // 1. Read JSONL header (first line only).
    let file = std::fs::File::open(&jsonl_path).map_err(|e| crate::Error::Io(Box::new(e)))?;
    let mut reader = BufReader::new(file);
    let mut header_line = String::new();
    reader
        .read_line(&mut header_line)
        .map_err(|e| crate::Error::Io(Box::new(e)))?;
    let header: SessionHeader = serde_json::from_str(header_line.trim())
        .map_err(|e| crate::Error::session(format!("Invalid header in JSONL: {e}")))?;

    // 2. Open V2 sidecar store.
    let v2_root = session_store_v2::v2_sidecar_path(&jsonl_path);
    let store = SessionStoreV2::create(&v2_root, 64 * 1024 * 1024)?;

    // 3. Load from store in full mode.
    let (mut session, diagnostics) = Session::open_from_v2(&store, header, V2OpenMode::Full)?;
    session.path = Some(jsonl_path);
    Ok((session, diagnostics))
}

/// Create a V2 sidecar store from an existing JSONL session file.
///
/// This is the migration path: parse the full JSONL once and write each entry
/// into the V2 segmented store with offset index. Subsequent opens can then
/// use `open_from_v2_store_blocking` for O(index+tail) resume.
pub fn create_v2_sidecar_from_jsonl(jsonl_path: &Path) -> Result<SessionStoreV2> {
    let contents =
        std::fs::read_to_string(jsonl_path).map_err(|e| crate::Error::Io(Box::new(e)))?;
    let mut lines = contents.lines();

    // Skip header line.
    let _header_line = lines
        .next()
        .ok_or_else(|| crate::Error::session("Empty JSONL session file"))?;

    let v2_root = session_store_v2::v2_sidecar_path(jsonl_path);
    let mut store = SessionStoreV2::create(&v2_root, 64 * 1024 * 1024)?;

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let entry: SessionEntry = serde_json::from_str(line)
            .map_err(|e| crate::Error::session(format!("Bad JSONL entry: {e}")))?;
        let (entry_id, parent_entry_id, entry_type, payload) =
            session_store_v2::session_entry_to_frame_args(&entry)?;
        store.append_entry(entry_id, parent_entry_id, entry_type, payload)?;
    }

    Ok(store)
}

/// Result of single-pass load finalization (Gap F).
///
/// Replaces the previous multi-pass approach (`ensure_entry_ids` +
/// `entry_id_set` + orphan detection + stats) with a single O(n) scan
/// that produces all required caches at once.
struct LoadFinalization {
    leaf_id: Option<String>,
    entry_ids: HashSet<String>,
    entry_index: HashMap<String, usize>,
    message_count: u64,
    name: Option<String>,
    is_linear: bool,
    orphans: Vec<(String, String)>,
}

/// Single-pass finalization of loaded entries.
///
/// 1. Assigns IDs to entries missing them (`ensure_entry_ids` work).
/// 2. Builds `entry_ids` set and `entry_index` map.
/// 3. Detects orphaned parent links.
/// 4. Computes `session_entry_stats` (message count + name).
/// 5. Determines `is_linear` (no branching, leaf == last entry).
fn finalize_loaded_entries(entries: &mut [SessionEntry]) -> LoadFinalization {
    // First pass: assign missing IDs (same logic as `ensure_entry_ids`).
    let mut entry_ids: HashSet<String> = entries
        .iter()
        .filter_map(|e| e.base_id().cloned())
        .collect();
    for entry in entries.iter_mut() {
        if entry.base().id.is_none() {
            let id = generate_entry_id(&entry_ids);
            entry.base_mut().id = Some(id.clone());
            entry_ids.insert(id);
        }
    }

    // Second (main) pass: build all caches in one scan.
    let mut entry_index = HashMap::with_capacity(entries.len());
    let mut message_count = 0u64;
    let mut name: Option<String> = None;
    let mut leaf_id: Option<String> = None;
    let mut orphans = Vec::new();
    // Track parent_ids seen as children's parent to detect branching.
    let mut parent_id_child_count: HashMap<Option<&str>, u32> = HashMap::new();
    let mut has_branching = false;

    for (idx, entry) in entries.iter().enumerate() {
        let Some(id) = entry.base_id() else {
            continue;
        };
        entry_index.insert(id.clone(), idx);
        leaf_id = Some(id.clone());

        // Orphan detection.
        if let Some(parent_id) = entry.base().parent_id.as_ref() {
            if !entry_ids.contains(parent_id) {
                orphans.push((id.clone(), parent_id.clone()));
            }
        }

        // Branch detection: if any parent_id has >1 child, it's branched.
        if !has_branching {
            let parent_key = entry.base().parent_id.as_deref();
            let count = parent_id_child_count.entry(parent_key).or_insert(0);
            *count += 1;
            if *count > 1 {
                has_branching = true;
            }
        }

        // Stats.
        match entry {
            SessionEntry::Message(_) => message_count += 1,
            SessionEntry::SessionInfo(info) => {
                if info.name.is_some() {
                    name.clone_from(&info.name);
                }
            }
            _ => {}
        }
    }

    // is_linear: no branching AND the leaf is the last entry's ID
    // (i.e., we're at the tip of a single chain).
    let is_linear = !has_branching;

    LoadFinalization {
        leaf_id,
        entry_ids,
        entry_index,
        message_count,
        name,
        is_linear,
        orphans,
    }
}

fn parse_env_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn session_entry_id_cache_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("PI_SESSION_ENTRY_ID_CACHE").map_or(true, |value| parse_env_bool(&value))
    })
}

fn ensure_entry_ids(entries: &mut [SessionEntry]) {
    let mut existing = entry_id_set(entries);
    for entry in entries.iter_mut() {
        if entry.base().id.is_none() {
            let id = generate_entry_id(&existing);
            entry.base_mut().id = Some(id.clone());
            existing.insert(id);
        }
    }
}

/// Generate a unique entry ID (8 hex characters), falling back to UUID on collision.
fn generate_entry_id(existing: &HashSet<String>) -> String {
    for _ in 0..100 {
        let uuid = uuid::Uuid::new_v4();
        let id = uuid.simple().to_string()[..8].to_string();
        if !existing.contains(&id) {
            return id;
        }
    }
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cost, StopReason, Usage};
    use asupersync::runtime::RuntimeBuilder;
    use clap::Parser;
    use std::future::Future;

    fn make_test_message(text: &str) -> SessionMessage {
        SessionMessage::User {
            content: UserContent::Text(text.to_string()),
            timestamp: Some(0),
        }
    }

    fn run_async<T>(future: impl Future<Output = T>) -> T {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        runtime.block_on(future)
    }

    #[test]
    fn test_session_handle_mutations_defer_persistence_side_effects() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.set_autosave_durability_for_test(AutosaveDurabilityMode::Throughput);
        // Point at a directory path so an eager save would fail with an IO error.
        session.path = Some(temp_dir.path().to_path_buf());
        let handle = SessionHandle(Arc::new(Mutex::new(session)));

        run_async(async { handle.set_name("deferred-save".to_string()).await })
            .expect("set_name should not trigger immediate save");
        run_async(async { handle.append_message(make_test_message("hello")).await })
            .expect("append_message should not trigger immediate save");
        run_async(async {
            handle
                .append_custom_entry(
                    "marker".to_string(),
                    Some(serde_json::json!({ "value": 42 })),
                )
                .await
        })
        .expect("append_custom_entry should not trigger immediate save");
        run_async(async {
            handle
                .set_model("prov".to_string(), "model".to_string())
                .await
        })
        .expect("set_model should not trigger immediate save");
        run_async(async { handle.set_thinking_level("high".to_string()).await })
            .expect("set_thinking_level should not trigger immediate save");

        let branch = run_async(async { handle.get_branch().await });
        let message_id = branch
            .iter()
            .find_map(|entry| {
                if entry.get("type").and_then(Value::as_str) == Some("message") {
                    entry
                        .get("id")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                } else {
                    None
                }
            })
            .expect("message entry id in branch");
        run_async(async {
            handle
                .set_label(message_id, Some("hot-path".to_string()))
                .await
        })
        .expect("set_label should not trigger immediate save");

        let state = run_async(async { handle.get_state().await });
        assert_eq!(
            state.get("sessionName").and_then(Value::as_str),
            Some("deferred-save")
        );
        assert_eq!(
            state.get("thinkingLevel").and_then(Value::as_str),
            Some("high")
        );
        assert_eq!(
            state.get("durabilityMode").and_then(Value::as_str),
            Some("throughput")
        );
        assert_eq!(state.get("messageCount").and_then(Value::as_u64), Some(1));

        let (provider, model_id) = run_async(async { handle.get_model().await });
        assert_eq!(provider.as_deref(), Some("prov"));
        assert_eq!(model_id.as_deref(), Some("model"));
    }

    #[test]
    fn test_autosave_queue_coalesces_mutations_per_flush() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.path = Some(temp_dir.path().join("autosave-coalesce.jsonl"));

        session.append_message(make_test_message("one"));
        session.append_custom_entry("marker".to_string(), None);
        session.append_message(make_test_message("two"));

        let before = session.autosave_metrics();
        assert_eq!(before.pending_mutations, 3);
        assert!(before.coalesced_mutations >= 2);
        assert_eq!(before.flush_succeeded, 0);

        run_async(async { session.flush_autosave(AutosaveFlushTrigger::Periodic).await })
            .expect("periodic flush");

        let after = session.autosave_metrics();
        assert_eq!(after.pending_mutations, 0);
        assert_eq!(after.flush_started, 1);
        assert_eq!(after.flush_succeeded, 1);
        assert_eq!(after.last_flush_batch_size, 3);
        assert_eq!(
            after.last_flush_trigger,
            Some(AutosaveFlushTrigger::Periodic)
        );
    }

    #[test]
    fn test_autosave_queue_backpressure_is_bounded() {
        let mut session = Session::create();
        session.set_autosave_queue_limit_for_test(2);

        for i in 0..5 {
            session.append_message(make_test_message(&format!("message-{i}")));
        }

        let metrics = session.autosave_metrics();
        assert_eq!(metrics.max_pending_mutations, 2);
        assert_eq!(metrics.pending_mutations, 2);
        assert_eq!(metrics.backpressure_events, 3);
        assert!(metrics.coalesced_mutations >= 4);
    }

    #[test]
    fn test_autosave_shutdown_flush_semantics_follow_durability_mode() {
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let mut strict = Session::create();
        // Point at a directory path so strict shutdown flush attempts fail.
        strict.path = Some(temp_dir.path().to_path_buf());
        strict.set_autosave_durability_for_test(AutosaveDurabilityMode::Strict);
        strict.append_message(make_test_message("strict"));

        run_async(async { strict.flush_autosave_on_shutdown().await })
            .expect_err("strict mode should propagate shutdown flush failure");
        let strict_metrics = strict.autosave_metrics();
        assert_eq!(strict_metrics.flush_failed, 1);
        assert!(strict_metrics.pending_mutations > 0);

        let mut throughput = Session::create();
        throughput.path = Some(temp_dir.path().to_path_buf());
        throughput.set_autosave_durability_for_test(AutosaveDurabilityMode::Throughput);
        throughput.append_message(make_test_message("throughput"));

        run_async(async { throughput.flush_autosave_on_shutdown().await })
            .expect("throughput mode skips shutdown flush");
        let throughput_metrics = throughput.autosave_metrics();
        assert_eq!(throughput_metrics.flush_started, 0);
        assert_eq!(throughput_metrics.pending_mutations, 1);
    }

    #[test]
    fn test_session_new_prefers_cli_durability_mode_over_config() {
        let cli =
            crate::cli::Cli::parse_from(["pi", "--no-session", "--session-durability", "strict"]);
        let config: Config =
            serde_json::from_str(r#"{ "sessionDurability": "throughput" }"#).expect("config parse");
        let session =
            run_async(async { Session::new(&cli, &config).await }).expect("create session");
        assert_eq!(
            session.autosave_durability_mode(),
            AutosaveDurabilityMode::Strict
        );
    }

    #[test]
    fn test_session_new_uses_config_durability_mode_when_cli_unset() {
        let cli = crate::cli::Cli::parse_from(["pi", "--no-session"]);
        let config: Config =
            serde_json::from_str(r#"{ "sessionDurability": "throughput" }"#).expect("config parse");
        let session =
            run_async(async { Session::new(&cli, &config).await }).expect("create session");
        assert_eq!(
            session.autosave_durability_mode(),
            AutosaveDurabilityMode::Throughput
        );
    }

    #[test]
    fn test_resolve_autosave_durability_mode_precedence() {
        assert_eq!(
            resolve_autosave_durability_mode(Some("strict"), Some("throughput"), Some("balanced")),
            AutosaveDurabilityMode::Strict
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, Some("throughput"), Some("strict")),
            AutosaveDurabilityMode::Throughput
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, None, Some("strict")),
            AutosaveDurabilityMode::Strict
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, None, None),
            AutosaveDurabilityMode::Balanced
        );
    }

    #[test]
    fn test_resolve_autosave_durability_mode_ignores_invalid_values() {
        assert_eq!(
            resolve_autosave_durability_mode(Some("bad"), Some("throughput"), Some("strict")),
            AutosaveDurabilityMode::Throughput
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, Some("bad"), Some("strict")),
            AutosaveDurabilityMode::Strict
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, None, Some("bad")),
            AutosaveDurabilityMode::Balanced
        );
    }

    #[test]
    fn test_get_share_viewer_url_matches_legacy() {
        assert_eq!(
            build_share_viewer_url(None, "gist-123"),
            "https://buildwithpi.ai/session/#gist-123"
        );
        assert_eq!(
            build_share_viewer_url(Some("https://example.com/session/"), "gist-123"),
            "https://example.com/session/#gist-123"
        );
        assert_eq!(
            build_share_viewer_url(Some("https://example.com/session"), "gist-123"),
            "https://example.com/session#gist-123"
        );
        // Legacy JS uses `process.env.PI_SHARE_VIEWER_URL || DEFAULT`, so empty-string should
        // fall back to default.
        assert_eq!(
            build_share_viewer_url(Some(""), "gist-123"),
            "https://buildwithpi.ai/session/#gist-123"
        );
    }

    #[test]
    fn test_session_linear_history() {
        let mut session = Session::in_memory();

        let id1 = session.append_message(make_test_message("Hello"));
        let id2 = session.append_message(make_test_message("World"));
        let id3 = session.append_message(make_test_message("Test"));

        // Check leaf is the last entry
        assert_eq!(session.leaf_id.as_deref(), Some(id3.as_str()));

        // Check path from last entry
        let path = session.get_path_to_entry(&id3);
        assert_eq!(path, vec![id1.as_str(), id2.as_str(), id3.as_str()]);

        // Check only one leaf
        let leaves = session.list_leaves();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], id3);
    }

    #[test]
    fn test_session_branching() {
        let mut session = Session::in_memory();

        // Create linear history: A -> B -> C
        let id_a = session.append_message(make_test_message("A"));
        let id_b = session.append_message(make_test_message("B"));
        let id_c = session.append_message(make_test_message("C"));

        // Now branch from B: A -> B -> D
        assert!(session.create_branch_from(&id_b));
        let id_d = session.append_message(make_test_message("D"));

        // Should have 2 leaves: C and D
        let leaves = session.list_leaves();
        assert_eq!(leaves.len(), 2);
        assert!(leaves.contains(&id_c));
        assert!(leaves.contains(&id_d));

        // Path to D should be A -> B -> D
        let path_to_d = session.get_path_to_entry(&id_d);
        assert_eq!(path_to_d, vec![id_a.as_str(), id_b.as_str(), id_d.as_str()]);

        // Path to C should be A -> B -> C
        let path_to_c = session.get_path_to_entry(&id_c);
        assert_eq!(path_to_c, vec![id_a.as_str(), id_b.as_str(), id_c.as_str()]);
    }

    #[test]
    fn test_session_navigation() {
        let mut session = Session::in_memory();

        let id1 = session.append_message(make_test_message("First"));
        let id2 = session.append_message(make_test_message("Second"));

        // Navigate to first entry
        assert!(session.navigate_to(&id1));
        assert_eq!(session.leaf_id.as_deref(), Some(id1.as_str()));

        // Navigate to non-existent entry
        assert!(!session.navigate_to("nonexistent"));
        // leaf_id unchanged
        assert_eq!(session.leaf_id.as_deref(), Some(id1.as_str()));

        // Navigate back to second
        assert!(session.navigate_to(&id2));
        assert_eq!(session.leaf_id.as_deref(), Some(id2.as_str()));
    }

    #[test]
    fn test_session_get_children() {
        let mut session = Session::in_memory();

        // A -> B -> C
        //   -> D
        let id_a = session.append_message(make_test_message("A"));
        let id_b = session.append_message(make_test_message("B"));
        let _id_c = session.append_message(make_test_message("C"));

        // Branch from A
        session.create_branch_from(&id_a);
        let id_d = session.append_message(make_test_message("D"));

        // A should have 2 children: B and D
        let children_a = session.get_children(Some(&id_a));
        assert_eq!(children_a.len(), 2);
        assert!(children_a.contains(&id_b));
        assert!(children_a.contains(&id_d));

        // Root (None) should have 1 child: A
        let root_children = session.get_children(None);
        assert_eq!(root_children.len(), 1);
        assert_eq!(root_children[0], id_a);
    }

    #[test]
    fn test_branch_summary() {
        let mut session = Session::in_memory();

        // Linear: A -> B
        let id_a = session.append_message(make_test_message("A"));
        let id_b = session.append_message(make_test_message("B"));

        let info = session.branch_summary();
        assert_eq!(info.total_entries, 2);
        assert_eq!(info.leaf_count, 1);
        assert_eq!(info.branch_point_count, 0);

        // Create branch: A -> B, A -> C
        session.create_branch_from(&id_a);
        let _id_c = session.append_message(make_test_message("C"));

        let info = session.branch_summary();
        assert_eq!(info.total_entries, 3);
        assert_eq!(info.leaf_count, 2);
        assert_eq!(info.branch_point_count, 1);
        assert!(info.branch_points.contains(&id_a));
        assert!(info.leaves.contains(&id_b));
    }

    #[test]
    fn test_session_jsonl_serialization() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        session.header.provider = Some("anthropic".to_string());
        session.header.model_id = Some("claude-test".to_string());
        session.header.thinking_level = Some("medium".to_string());

        let user_id = session.append_message(make_test_message("Hello"));
        let assistant = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("Hi!"))],
            api: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-test".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        };
        session.append_message(SessionMessage::Assistant { message: assistant });
        session.append_model_change("anthropic".to_string(), "claude-test".to_string());
        session.append_thinking_level_change("high".to_string());
        session.append_compaction("summary".to_string(), user_id.clone(), 123, None, None);
        session.append_branch_summary(user_id, "branch".to_string(), None, None);
        session.append_session_info(Some("my-session".to_string()));

        run_async(async { session.save().await }).unwrap();

        let path = session.path.clone().unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        let mut lines = contents.lines();

        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["type"], "session");
        assert_eq!(header["version"], SESSION_VERSION);

        let mut types = Vec::new();
        for line in lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            let entry_type = value["type"].as_str().unwrap_or_default().to_string();
            types.push(entry_type);
        }

        assert!(types.contains(&"message".to_string()));
        assert!(types.contains(&"model_change".to_string()));
        assert!(types.contains(&"thinking_level_change".to_string()));
        assert!(types.contains(&"compaction".to_string()));
        assert!(types.contains(&"branch_summary".to_string()));
        assert!(types.contains(&"session_info".to_string()));
    }

    #[test]
    fn test_save_handles_short_or_empty_session_id() {
        let temp = tempfile::tempdir().unwrap();

        let mut short_id_session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        short_id_session.header.id = "x".to_string();
        run_async(async { short_id_session.save().await }).expect("save with short id");
        let short_name = short_id_session
            .path
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .expect("short id filename");
        assert!(short_name.contains("_x."));

        let mut empty_id_session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        empty_id_session.header.id.clear();
        run_async(async { empty_id_session.save().await }).expect("save with empty id");
        let empty_name = empty_id_session
            .path
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .expect("empty id filename");
        assert!(empty_name.contains("_session."));

        let mut unsafe_id_session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        unsafe_id_session.header.id = "../etc/passwd".to_string();
        run_async(async { unsafe_id_session.save().await }).expect("save with unsafe id");
        let unsafe_path = unsafe_id_session.path.as_ref().expect("unsafe id path");
        let unsafe_name = unsafe_path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("unsafe id filename");
        assert!(unsafe_name.contains("____etc_p."));
        let expected_dir = temp
            .path()
            .join(encode_cwd(&std::env::current_dir().unwrap()));
        assert_eq!(
            unsafe_path.parent().expect("unsafe id parent"),
            expected_dir.as_path()
        );
    }

    #[test]
    fn test_open_with_diagnostics_skips_corrupted_last_entry_and_recovers_leaf() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        let first_id = session.append_message(make_test_message("Hello"));
        let second_id = session.append_message(make_test_message("World"));
        assert_eq!(session.leaf_id.as_deref(), Some(second_id.as_str()));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().expect("session path set");

        let mut lines = std::fs::read_to_string(&path)
            .expect("read session")
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(lines.len() >= 3, "expected header + 2 entries");

        let corrupted_line_number = lines.len(); // 1-based
        let last_index = lines.len() - 1;
        lines[last_index] = "{ this is not json }".to_string();

        let corrupted_path = temp.path().join("corrupted.jsonl");
        std::fs::write(&corrupted_path, format!("{}\n", lines.join("\n")))
            .expect("write corrupted session");

        let (loaded, diagnostics) = run_async(async {
            Session::open_with_diagnostics(corrupted_path.to_string_lossy().as_ref()).await
        })
        .expect("open corrupted session");

        assert_eq!(diagnostics.skipped_entries.len(), 1);
        assert_eq!(
            diagnostics.skipped_entries[0].line_number,
            corrupted_line_number
        );

        let warnings = diagnostics.warning_lines();
        assert_eq!(warnings.len(), 2, "expected per-line warning + summary");
        assert!(
            warnings[0].starts_with(&format!(
                "Warning: Skipping corrupted entry at line {corrupted_line_number} in session file:"
            )),
            "unexpected warning: {}",
            warnings[0]
        );
        assert_eq!(
            warnings[1],
            "Warning: Skipped 1 corrupted entries while loading session"
        );

        assert_eq!(
            loaded.entries.len(),
            session.entries.len() - 1,
            "expected last entry to be dropped"
        );
        assert_eq!(loaded.leaf_id.as_deref(), Some(first_id.as_str()));
    }

    #[test]
    fn test_save_and_open_round_trip_preserves_compaction_and_branch_summary() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        let root_id = session.append_message(make_test_message("Hello"));
        session.append_compaction("compacted".to_string(), root_id.clone(), 123, None, None);
        session.append_branch_summary(root_id, "branch summary".to_string(), None, None);

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().expect("session path set");

        let loaded = run_async(async { Session::open(path.to_string_lossy().as_ref()).await })
            .expect("reopen session");

        assert!(loaded.entries.iter().any(|entry| {
            matches!(entry, SessionEntry::Compaction(compaction) if compaction.summary == "compacted" && compaction.tokens_before == 123)
        }));
        assert!(loaded.entries.iter().any(|entry| {
            matches!(entry, SessionEntry::BranchSummary(summary) if summary.summary == "branch summary")
        }));

        let html = loaded.to_html();
        assert!(html.contains("compacted"));
        assert!(html.contains("branch summary"));
    }

    #[test]
    fn test_concurrent_saves_do_not_corrupt_session_file_unit() {
        let temp = tempfile::tempdir().unwrap();
        let base_dir = temp.path().join("sessions");

        let mut session = Session::create_with_dir(Some(base_dir));
        session.append_message(make_test_message("Hello"));

        run_async(async { session.save().await }).expect("initial save");
        let path = session.path.clone().expect("session path set");

        let path1 = path.clone();
        let path2 = path.clone();

        let t1 = std::thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("build runtime");
            runtime.block_on(async move {
                let mut s = Session::open(path1.to_string_lossy().as_ref())
                    .await
                    .expect("open session");
                s.append_message(make_test_message("From thread 1"));
                s.save().await
            })
        });

        let t2 = std::thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("build runtime");
            runtime.block_on(async move {
                let mut s = Session::open(path2.to_string_lossy().as_ref())
                    .await
                    .expect("open session");
                s.append_message(make_test_message("From thread 2"));
                s.save().await
            })
        });

        let r1 = t1.join().expect("thread 1 join");
        let r2 = t2.join().expect("thread 2 join");
        assert!(
            r1.is_ok() || r2.is_ok(),
            "Expected at least one save to succeed: r1={r1:?} r2={r2:?}"
        );

        let loaded = run_async(async { Session::open(path.to_string_lossy().as_ref()).await })
            .expect("open after concurrent saves");
        assert!(!loaded.entries.is_empty());
    }

    #[test]
    fn test_to_messages_for_current_path() {
        let mut session = Session::in_memory();

        // Tree structure:
        // A -> B -> C
        //       \-> D  (D branches from B)
        let _id_a = session.append_message(make_test_message("A"));
        let id_b = session.append_message(make_test_message("B"));
        let _id_c = session.append_message(make_test_message("C"));

        // Navigate to B and add D
        session.create_branch_from(&id_b);
        let id_d = session.append_message(make_test_message("D"));

        // Current path should be A -> B -> D
        session.navigate_to(&id_d);
        let messages = session.to_messages_for_current_path();
        assert_eq!(messages.len(), 3);

        // Verify content
        if let Message::User(user) = &messages[0] {
            if let UserContent::Text(text) = &user.content {
                assert_eq!(text, "A");
            }
        }
        if let Message::User(user) = &messages[2] {
            if let UserContent::Text(text) = &user.content {
                assert_eq!(text, "D");
            }
        }
    }

    #[test]
    fn test_reset_leaf_produces_empty_current_path() {
        let mut session = Session::in_memory();

        let _id_a = session.append_message(make_test_message("A"));
        let _id_b = session.append_message(make_test_message("B"));

        session.reset_leaf();
        assert!(session.entries_for_current_path().is_empty());
        assert!(session.to_messages_for_current_path().is_empty());

        // After reset, the next entry becomes a new root.
        let id_root = session.append_message(make_test_message("Root"));
        let entry = session.get_entry(&id_root).expect("entry");
        assert!(entry.base().parent_id.is_none());
    }

    #[test]
    fn test_encode_cwd() {
        let path = std::path::Path::new("/home/user/project");
        let encoded = encode_cwd(path);
        assert!(encoded.starts_with("--"));
        assert!(encoded.ends_with("--"));
        assert!(encoded.contains("home-user-project"));
    }

    // ======================================================================
    // Session creation and header validation
    // ======================================================================

    #[test]
    fn test_session_header_defaults() {
        let header = SessionHeader::new();
        assert_eq!(header.r#type, "session");
        assert_eq!(header.version, Some(SESSION_VERSION));
        assert!(!header.id.is_empty());
        assert!(!header.timestamp.is_empty());
        assert!(header.provider.is_none());
        assert!(header.model_id.is_none());
        assert!(header.thinking_level.is_none());
        assert!(header.parent_session.is_none());
    }

    #[test]
    fn test_session_create_produces_unique_ids() {
        let s1 = Session::create();
        let s2 = Session::create();
        assert_ne!(s1.header.id, s2.header.id);
    }

    #[test]
    fn test_in_memory_session_has_no_path() {
        let session = Session::in_memory();
        assert!(session.path.is_none());
        assert!(session.leaf_id.is_none());
        assert!(session.entries.is_empty());
    }

    #[test]
    fn test_create_with_dir_stores_session_dir() {
        let temp = tempfile::tempdir().unwrap();
        let session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        assert_eq!(session.session_dir, Some(temp.path().to_path_buf()));
    }

    // ======================================================================
    // Message types: tool result, bash execution, custom
    // ======================================================================

    #[test]
    fn test_append_tool_result_message() {
        let mut session = Session::in_memory();
        let user_id = session.append_message(make_test_message("Hello"));

        let tool_msg = SessionMessage::ToolResult {
            tool_call_id: "call_123".to_string(),
            tool_name: "read".to_string(),
            content: vec![ContentBlock::Text(TextContent::new("file contents"))],
            details: None,
            is_error: false,
            timestamp: Some(1000),
        };
        let tool_id = session.append_message(tool_msg);

        // Verify parent linking
        let entry = session.get_entry(&tool_id).unwrap();
        assert_eq!(entry.base().parent_id.as_deref(), Some(user_id.as_str()));

        // Verify it converts to model message
        let messages = session.to_messages();
        assert_eq!(messages.len(), 2);
        assert!(matches!(&messages[1], Message::ToolResult(tr) if tr.tool_call_id == "call_123"));
    }

    #[test]
    fn test_append_tool_result_error() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("Hello"));

        let tool_msg = SessionMessage::ToolResult {
            tool_call_id: "call_err".to_string(),
            tool_name: "bash".to_string(),
            content: vec![ContentBlock::Text(TextContent::new("command not found"))],
            details: None,
            is_error: true,
            timestamp: Some(2000),
        };
        let tool_id = session.append_message(tool_msg);

        let entry = session.get_entry(&tool_id).unwrap();
        if let SessionEntry::Message(msg) = entry {
            if let SessionMessage::ToolResult { is_error, .. } = &msg.message {
                assert!(is_error);
            } else {
                panic!("expected ToolResult");
            }
        }
    }

    #[test]
    fn test_append_bash_execution() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("run something"));

        let bash_id = session.append_bash_execution(
            "echo hello".to_string(),
            "hello\n".to_string(),
            0,
            false,
            false,
            None,
        );

        let entry = session.get_entry(&bash_id).unwrap();
        if let SessionEntry::Message(msg) = entry {
            if let SessionMessage::BashExecution {
                command, exit_code, ..
            } = &msg.message
            {
                assert_eq!(command, "echo hello");
                assert_eq!(*exit_code, 0);
            } else {
                panic!("expected BashExecution");
            }
        }

        // BashExecution converts to User message for model context
        let messages = session.to_messages();
        assert_eq!(messages.len(), 2);
        assert!(matches!(&messages[1], Message::User(_)));
    }

    #[test]
    fn test_bash_execution_exclude_from_context() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("run something"));

        let id = session.next_entry_id();
        let base = EntryBase::new(session.leaf_id.clone(), id.clone());
        let mut extra = HashMap::new();
        extra.insert("excludeFromContext".to_string(), serde_json::json!(true));
        let entry = SessionEntry::Message(MessageEntry {
            base,
            message: SessionMessage::BashExecution {
                command: "secret".to_string(),
                output: "hidden".to_string(),
                exit_code: 0,
                cancelled: None,
                truncated: None,
                full_output_path: None,
                timestamp: Some(0),
                extra,
            },
        });
        session.leaf_id = Some(id);
        session.entries.push(entry);
        session.entry_ids = entry_id_set(&session.entries);

        // The excluded bash execution should not appear in model messages
        let messages = session.to_messages();
        assert_eq!(messages.len(), 1); // only the user message
    }

    #[test]
    fn test_append_custom_message() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("Hello"));

        let custom_msg = SessionMessage::Custom {
            custom_type: "extension_state".to_string(),
            content: "some state".to_string(),
            display: false,
            details: Some(serde_json::json!({"key": "value"})),
            timestamp: Some(0),
        };
        let custom_id = session.append_message(custom_msg);

        let entry = session.get_entry(&custom_id).unwrap();
        if let SessionEntry::Message(msg) = entry {
            if let SessionMessage::Custom {
                custom_type,
                display,
                ..
            } = &msg.message
            {
                assert_eq!(custom_type, "extension_state");
                assert!(!display);
            } else {
                panic!("expected Custom");
            }
        }
    }

    #[test]
    fn test_append_custom_entry() {
        let mut session = Session::in_memory();
        let root_id = session.append_message(make_test_message("Hello"));

        let custom_id =
            session.append_custom_entry("my_type".to_string(), Some(serde_json::json!(42)));

        let entry = session.get_entry(&custom_id).unwrap();
        if let SessionEntry::Custom(custom) = entry {
            assert_eq!(custom.custom_type, "my_type");
            assert_eq!(custom.data, Some(serde_json::json!(42)));
            assert_eq!(custom.base.parent_id.as_deref(), Some(root_id.as_str()));
        } else {
            panic!("expected Custom entry");
        }
    }

    // ======================================================================
    // Parent linking / tree structure
    // ======================================================================

    #[test]
    fn test_parent_linking_chain() {
        let mut session = Session::in_memory();

        let id1 = session.append_message(make_test_message("A"));
        let id2 = session.append_message(make_test_message("B"));
        let id3 = session.append_message(make_test_message("C"));

        // First entry has no parent
        let e1 = session.get_entry(&id1).unwrap();
        assert!(e1.base().parent_id.is_none());

        // Second entry's parent is first
        let e2 = session.get_entry(&id2).unwrap();
        assert_eq!(e2.base().parent_id.as_deref(), Some(id1.as_str()));

        // Third entry's parent is second
        let e3 = session.get_entry(&id3).unwrap();
        assert_eq!(e3.base().parent_id.as_deref(), Some(id2.as_str()));
    }

    #[test]
    fn test_model_change_updates_leaf() {
        let mut session = Session::in_memory();

        let msg_id = session.append_message(make_test_message("Hello"));
        let change_id = session.append_model_change("openai".to_string(), "gpt-4".to_string());

        assert_eq!(session.leaf_id.as_deref(), Some(change_id.as_str()));

        let entry = session.get_entry(&change_id).unwrap();
        assert_eq!(entry.base().parent_id.as_deref(), Some(msg_id.as_str()));

        if let SessionEntry::ModelChange(mc) = entry {
            assert_eq!(mc.provider, "openai");
            assert_eq!(mc.model_id, "gpt-4");
        } else {
            panic!("expected ModelChange");
        }
    }

    #[test]
    fn test_thinking_level_change_updates_leaf() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("Hello"));

        let change_id = session.append_thinking_level_change("high".to_string());
        assert_eq!(session.leaf_id.as_deref(), Some(change_id.as_str()));

        let entry = session.get_entry(&change_id).unwrap();
        if let SessionEntry::ThinkingLevelChange(tlc) = entry {
            assert_eq!(tlc.thinking_level, "high");
        } else {
            panic!("expected ThinkingLevelChange");
        }
    }

    // ======================================================================
    // Session name get/set
    // ======================================================================

    #[test]
    fn test_get_name_returns_latest() {
        let mut session = Session::in_memory();

        assert!(session.get_name().is_none());

        session.set_name("first");
        assert_eq!(session.get_name().as_deref(), Some("first"));

        session.set_name("second");
        assert_eq!(session.get_name().as_deref(), Some("second"));
    }

    #[test]
    fn test_set_name_returns_entry_id() {
        let mut session = Session::in_memory();
        let id = session.set_name("test-name");
        assert!(!id.is_empty());
        let entry = session.get_entry(&id).unwrap();
        assert!(matches!(entry, SessionEntry::SessionInfo(_)));
    }

    // ======================================================================
    // Label
    // ======================================================================

    #[test]
    fn test_add_label_to_existing_entry() {
        let mut session = Session::in_memory();
        let msg_id = session.append_message(make_test_message("Hello"));

        let label_id = session.add_label(&msg_id, Some("important".to_string()));
        assert!(label_id.is_some());

        let entry = session.get_entry(&label_id.unwrap()).unwrap();
        if let SessionEntry::Label(label) = entry {
            assert_eq!(label.target_id, msg_id);
            assert_eq!(label.label.as_deref(), Some("important"));
        } else {
            panic!("expected Label entry");
        }
    }

    #[test]
    fn test_add_label_to_nonexistent_entry_returns_none() {
        let mut session = Session::in_memory();
        let result = session.add_label("nonexistent", Some("label".to_string()));
        assert!(result.is_none());
    }

    // ======================================================================
    // JSONL round-trip (save + reload)
    // ======================================================================

    #[test]
    fn test_round_trip_preserves_all_message_types() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        // Append diverse message types
        session.append_message(make_test_message("user text"));

        let assistant = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("response"))],
            api: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-test".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        };
        session.append_message(SessionMessage::Assistant { message: assistant });

        session.append_message(SessionMessage::ToolResult {
            tool_call_id: "call_1".to_string(),
            tool_name: "read".to_string(),
            content: vec![ContentBlock::Text(TextContent::new("result"))],
            details: None,
            is_error: false,
            timestamp: Some(100),
        });

        session.append_bash_execution("ls".to_string(), "files".to_string(), 0, false, false, None);

        session.append_custom_entry(
            "ext_data".to_string(),
            Some(serde_json::json!({"foo": "bar"})),
        );

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.entries.len(), session.entries.len());
        assert_eq!(loaded.header.id, session.header.id);
        assert_eq!(loaded.header.version, Some(SESSION_VERSION));

        // Verify specific entry types survived the round-trip
        let has_tool_result = loaded.entries.iter().any(|e| {
            matches!(
                e,
                SessionEntry::Message(m) if matches!(
                    &m.message,
                    SessionMessage::ToolResult { tool_name, .. } if tool_name == "read"
                )
            )
        });
        assert!(has_tool_result, "tool result should survive round-trip");

        let has_bash = loaded.entries.iter().any(|e| {
            matches!(
                e,
                SessionEntry::Message(m) if matches!(
                    &m.message,
                    SessionMessage::BashExecution { command, .. } if command == "ls"
                )
            )
        });
        assert!(has_bash, "bash execution should survive round-trip");

        let has_custom = loaded.entries.iter().any(|e| {
            matches!(
                e,
                SessionEntry::Custom(c) if c.custom_type == "ext_data"
            )
        });
        assert!(has_custom, "custom entry should survive round-trip");
    }

    #[test]
    fn test_round_trip_preserves_leaf_id() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        let _id1 = session.append_message(make_test_message("A"));
        let id2 = session.append_message(make_test_message("B"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.leaf_id.as_deref(), Some(id2.as_str()));
    }

    #[test]
    fn test_round_trip_preserves_header_fields() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        session.header.provider = Some("anthropic".to_string());
        session.header.model_id = Some("claude-opus".to_string());
        session.header.thinking_level = Some("high".to_string());
        session.header.parent_session = Some("/old/session.jsonl".to_string());

        session.append_message(make_test_message("Hello"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.header.provider.as_deref(), Some("anthropic"));
        assert_eq!(loaded.header.model_id.as_deref(), Some("claude-opus"));
        assert_eq!(loaded.header.thinking_level.as_deref(), Some("high"));
        assert_eq!(
            loaded.header.parent_session.as_deref(),
            Some("/old/session.jsonl")
        );
    }

    #[test]
    fn test_empty_session_save_and_reload() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert!(loaded.entries.is_empty());
        assert!(loaded.leaf_id.is_none());
        assert_eq!(loaded.header.id, session.header.id);
    }

    // ======================================================================
    // Corrupted JSONL recovery
    // ======================================================================

    #[test]
    fn test_corrupted_middle_entry_preserves_surrounding_entries() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        let id1 = session.append_message(make_test_message("First"));
        let id2 = session.append_message(make_test_message("Second"));
        let id3 = session.append_message(make_test_message("Third"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        // Corrupt the middle entry (line 3, 1-indexed: header=1, first=2, second=3)
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert!(lines.len() >= 4);
        lines[2] = "GARBAGE JSON".to_string();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let (loaded, diagnostics) = run_async(async {
            Session::open_with_diagnostics(path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        let diag = serde_json::json!({
            "fixture_id": "session-corrupted-middle-entry-replay-integrity",
            "path": path.display().to_string(),
            "seed": "deterministic-static",
            "env": {
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            },
            "expected": {
                "skipped_entries": 1,
                "orphaned_parent_links": 1,
            },
            "actual": {
                "skipped_entries": diagnostics.skipped_entries.len(),
                "orphaned_parent_links": diagnostics.orphaned_parent_links.len(),
                "leaf_id": loaded.leaf_id,
            },
        })
        .to_string();

        assert_eq!(diagnostics.skipped_entries.len(), 1, "{diag}");
        assert_eq!(diagnostics.skipped_entries[0].line_number, 3, "{diag}");
        assert_eq!(diagnostics.orphaned_parent_links.len(), 1, "{diag}");
        assert_eq!(diagnostics.orphaned_parent_links[0].entry_id, id3, "{diag}");
        assert_eq!(
            diagnostics.orphaned_parent_links[0].missing_parent_id, id2,
            "{diag}"
        );
        assert!(
            diagnostics.warning_lines().iter().any(|line| {
                line.contains("references missing parent")
                    && line.contains(diagnostics.orphaned_parent_links[0].entry_id.as_str())
            }),
            "{diag}"
        );

        // First and third entries should survive
        assert_eq!(loaded.entries.len(), 2, "{diag}");
        assert!(loaded.get_entry(&id1).is_some(), "{diag}");
        assert!(loaded.get_entry(&id3).is_some(), "{diag}");
    }

    #[test]
    fn test_multiple_corrupted_entries_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        session.append_message(make_test_message("A"));
        session.append_message(make_test_message("B"));
        session.append_message(make_test_message("C"));
        session.append_message(make_test_message("D"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        // Corrupt entries B (line 3) and D (line 5)
        lines[2] = "BAD".to_string();
        lines[4] = "ALSO BAD".to_string();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let (loaded, diagnostics) = run_async(async {
            Session::open_with_diagnostics(path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        assert_eq!(diagnostics.skipped_entries.len(), 2);
        assert_eq!(loaded.entries.len(), 2); // A and C survive
    }

    #[test]
    fn test_corrupted_header_fails_to_open() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bad_header.jsonl");
        std::fs::write(&path, "NOT A VALID HEADER\n{\"type\":\"message\"}\n").unwrap();

        let result = run_async(async {
            Session::open_with_diagnostics(path.to_string_lossy().as_ref()).await
        });
        assert!(
            result.is_err(),
            "corrupted header should cause open failure"
        );
    }

    // ======================================================================
    // Branching and navigation
    // ======================================================================

    #[test]
    fn test_create_branch_from_nonexistent_returns_false() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("A"));
        assert!(!session.create_branch_from("nonexistent"));
    }

    #[test]
    fn test_deep_branching() {
        let mut session = Session::in_memory();

        // Create A -> B -> C
        let id_a = session.append_message(make_test_message("A"));
        let id_b = session.append_message(make_test_message("B"));
        let _id_c = session.append_message(make_test_message("C"));

        // Branch from A: A -> D
        session.create_branch_from(&id_a);
        let _id_d = session.append_message(make_test_message("D"));

        // Branch from B: A -> B -> E
        session.create_branch_from(&id_b);
        let id_e = session.append_message(make_test_message("E"));

        // Should have 3 leaves: C, D, E
        let leaves = session.list_leaves();
        assert_eq!(leaves.len(), 3);

        // Path to E is A -> B -> E
        let path = session.get_path_to_entry(&id_e);
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], id_a);
        assert_eq!(path[1], id_b);
        assert_eq!(path[2], id_e);
    }

    #[test]
    fn test_sibling_branches_at_fork() {
        let mut session = Session::in_memory();

        // Create A -> B -> C
        let id_a = session.append_message(make_test_message("A"));
        let _id_b = session.append_message(make_test_message("B"));
        let _id_c = session.append_message(make_test_message("C"));

        // Branch from A: A -> D
        session.create_branch_from(&id_a);
        let id_d = session.append_message(make_test_message("D"));

        // Navigate to D to make it current
        session.navigate_to(&id_d);

        let siblings = session.sibling_branches();
        assert!(siblings.is_some());
        let (fork_point, branches) = siblings.unwrap();
        assert!(fork_point.is_none() || fork_point.as_deref() == Some(id_a.as_str()));
        assert_eq!(branches.len(), 2);

        // One should be current, one not
        let current_count = branches.iter().filter(|b| b.is_current).count();
        assert_eq!(current_count, 1);
    }

    #[test]
    fn test_sibling_branches_no_fork() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("A"));
        session.append_message(make_test_message("B"));

        // No fork points, so sibling_branches returns None
        assert!(session.sibling_branches().is_none());
    }

    // ======================================================================
    // Plan fork
    // ======================================================================

    #[test]
    fn test_plan_fork_from_user_message() {
        let mut session = Session::in_memory();

        let _id_a = session.append_message(make_test_message("First question"));
        let assistant = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("Answer"))],
            api: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            model: "test".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        };
        let _id_b = session.append_message(SessionMessage::Assistant { message: assistant });
        let id_c = session.append_message(make_test_message("Second question"));

        // Fork from the second user message
        let plan = session.plan_fork_from_user_message(&id_c).unwrap();
        assert_eq!(plan.selected_text, "Second question");
        // Entries should be the path up to (but not including) the forked message
        assert_eq!(plan.entries.len(), 2); // A and B
    }

    #[test]
    fn test_plan_fork_from_root_message() {
        let mut session = Session::in_memory();
        let id_a = session.append_message(make_test_message("Root question"));

        let plan = session.plan_fork_from_user_message(&id_a).unwrap();
        assert_eq!(plan.selected_text, "Root question");
        assert!(plan.entries.is_empty()); // No entries before root
        assert!(plan.leaf_id.is_none());
    }

    #[test]
    fn test_plan_fork_from_nonexistent_fails() {
        let session = Session::in_memory();
        assert!(session.plan_fork_from_user_message("nonexistent").is_err());
    }

    #[test]
    fn test_plan_fork_from_assistant_message_fails() {
        let mut session = Session::in_memory();
        session.append_message(make_test_message("Q"));
        let assistant = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("A"))],
            api: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            model: "test".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        };
        let asst_id = session.append_message(SessionMessage::Assistant { message: assistant });

        assert!(session.plan_fork_from_user_message(&asst_id).is_err());
    }

    // ======================================================================
    // Compaction in message context
    // ======================================================================

    #[test]
    fn test_compaction_truncates_model_context() {
        let mut session = Session::in_memory();

        let _id_a = session.append_message(make_test_message("old message A"));
        let _id_b = session.append_message(make_test_message("old message B"));
        let id_c = session.append_message(make_test_message("kept message C"));

        // Compact: keep from id_c onwards
        session.append_compaction(
            "Summary of old messages".to_string(),
            id_c,
            5000,
            None,
            None,
        );

        let id_d = session.append_message(make_test_message("new message D"));

        // Ensure we're at the right leaf
        session.navigate_to(&id_d);

        let messages = session.to_messages_for_current_path();
        // Should have: compaction summary + kept message C + new message D
        // (old messages A and B should be omitted)
        assert!(messages.len() <= 4); // compaction summary + C + compaction entry + D

        // Verify old messages are not in context
        let all_text: String = messages
            .iter()
            .filter_map(|m| match m {
                Message::User(u) => match &u.content {
                    UserContent::Text(t) => Some(t.clone()),
                    UserContent::Blocks(blocks) => {
                        let texts: Vec<String> = blocks
                            .iter()
                            .filter_map(|b| {
                                if let ContentBlock::Text(t) = b {
                                    Some(t.text.clone())
                                } else {
                                    None
                                }
                            })
                            .collect();
                        Some(texts.join(" "))
                    }
                },
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" ");

        assert!(
            !all_text.contains("old message A"),
            "compacted message A should not appear in context"
        );
        assert!(
            !all_text.contains("old message B"),
            "compacted message B should not appear in context"
        );
        assert!(
            all_text.contains("kept message C") || all_text.contains("new message D"),
            "kept messages should appear in context"
        );
    }

    // ======================================================================
    // Large session handling
    // ======================================================================

    #[test]
    fn test_large_session_append_and_path() {
        let mut session = Session::in_memory();

        let mut last_id = String::new();
        for i in 0..500 {
            last_id = session.append_message(make_test_message(&format!("msg-{i}")));
        }

        assert_eq!(session.entries.len(), 500);
        assert_eq!(session.leaf_id.as_deref(), Some(last_id.as_str()));

        // Path from root to leaf should include all 500 entries
        let path = session.get_path_to_entry(&last_id);
        assert_eq!(path.len(), 500);

        // Entries for current path should also be 500
        let current = session.entries_for_current_path();
        assert_eq!(current.len(), 500);
    }

    #[test]
    fn test_large_session_save_and_reload() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        for i in 0..200 {
            session.append_message(make_test_message(&format!("message {i}")));
        }

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.entries.len(), 200);
        assert_eq!(loaded.header.id, session.header.id);
    }

    // ======================================================================
    // Entry ID generation
    // ======================================================================

    #[test]
    fn test_ensure_entry_ids_fills_missing() {
        let mut entries = vec![
            SessionEntry::Message(MessageEntry {
                base: EntryBase {
                    id: None,
                    parent_id: None,
                    timestamp: "2025-01-01T00:00:00.000Z".to_string(),
                },
                message: SessionMessage::User {
                    content: UserContent::Text("test".to_string()),
                    timestamp: Some(0),
                },
            }),
            SessionEntry::Message(MessageEntry {
                base: EntryBase {
                    id: Some("existing".to_string()),
                    parent_id: None,
                    timestamp: "2025-01-01T00:00:00.000Z".to_string(),
                },
                message: SessionMessage::User {
                    content: UserContent::Text("test2".to_string()),
                    timestamp: Some(0),
                },
            }),
        ];

        ensure_entry_ids(&mut entries);

        // First entry should now have an ID
        assert!(entries[0].base().id.is_some());
        // Second entry should keep its existing ID
        assert_eq!(entries[1].base().id.as_deref(), Some("existing"));
        // IDs should be unique
        assert_ne!(entries[0].base().id, entries[1].base().id);
    }

    #[test]
    fn test_generate_entry_id_produces_8_char_hex() {
        let existing = HashSet::new();
        let id = generate_entry_id(&existing);
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ======================================================================
    // set_model_header / set_branched_from
    // ======================================================================

    #[test]
    fn test_set_model_header() {
        let mut session = Session::in_memory();
        session.set_model_header(
            Some("anthropic".to_string()),
            Some("claude-opus".to_string()),
            Some("high".to_string()),
        );
        assert_eq!(session.header.provider.as_deref(), Some("anthropic"));
        assert_eq!(session.header.model_id.as_deref(), Some("claude-opus"));
        assert_eq!(session.header.thinking_level.as_deref(), Some("high"));
    }

    #[test]
    fn test_set_branched_from() {
        let mut session = Session::in_memory();
        assert!(session.header.parent_session.is_none());

        session.set_branched_from(Some("/path/to/parent.jsonl".to_string()));
        assert_eq!(
            session.header.parent_session.as_deref(),
            Some("/path/to/parent.jsonl")
        );
    }

    // ======================================================================
    // to_html rendering
    // ======================================================================

    #[test]
    fn test_to_html_contains_all_message_types() {
        let mut session = Session::in_memory();

        session.append_message(make_test_message("user question"));

        let assistant = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("assistant answer"))],
            api: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            model: "test".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        };
        session.append_message(SessionMessage::Assistant { message: assistant });
        session.append_model_change("anthropic".to_string(), "claude-test".to_string());
        session.set_name("test-session-html");

        let html = session.to_html();
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("user question"));
        assert!(html.contains("assistant answer"));
        assert!(html.contains("anthropic"));
        assert!(html.contains("test-session-html"));
    }

    // ======================================================================
    // to_messages conversion
    // ======================================================================

    #[test]
    fn test_to_messages_includes_all_message_entries() {
        let mut session = Session::in_memory();

        session.append_message(make_test_message("Q1"));
        let assistant = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new("A1"))],
            api: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            model: "test".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        };
        session.append_message(SessionMessage::Assistant { message: assistant });
        session.append_message(SessionMessage::ToolResult {
            tool_call_id: "c1".to_string(),
            tool_name: "edit".to_string(),
            content: vec![ContentBlock::Text(TextContent::new("edited"))],
            details: None,
            is_error: false,
            timestamp: Some(0),
        });

        // Non-message entries should NOT appear in to_messages()
        session.append_model_change("openai".to_string(), "gpt-4".to_string());
        session.append_session_info(Some("name".to_string()));

        let messages = session.to_messages();
        assert_eq!(messages.len(), 3); // user + assistant + tool_result
    }

    // ======================================================================
    // JSONL format validation
    // ======================================================================

    #[test]
    fn test_jsonl_header_is_first_line() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        session.append_message(make_test_message("test"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let contents = std::fs::read_to_string(path).unwrap();
        let first_line = contents.lines().next().unwrap();
        let header: serde_json::Value = serde_json::from_str(first_line).unwrap();

        assert_eq!(header["type"], "session");
        assert_eq!(header["version"], SESSION_VERSION);
        assert!(!header["id"].as_str().unwrap().is_empty());
        assert!(!header["timestamp"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_jsonl_entries_have_camelcase_fields() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        session.append_message(make_test_message("test"));
        session.append_model_change("provider".to_string(), "model".to_string());

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let contents = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();

        // Check message entry (line 2)
        let msg_value: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert!(msg_value.get("parentId").is_some() || msg_value.get("id").is_some());

        // Check model change entry (line 3)
        let mc_value: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert!(mc_value.get("modelId").is_some());
    }

    // ======================================================================
    // Session open errors
    // ======================================================================

    #[test]
    fn test_open_nonexistent_file_returns_error() {
        let result =
            run_async(async { Session::open("/tmp/nonexistent_session_12345.jsonl").await });
        assert!(result.is_err());
    }

    #[test]
    fn test_open_empty_file_returns_error() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("empty.jsonl");
        std::fs::write(&path, "").unwrap();

        let result = run_async(async { Session::open(path.to_string_lossy().as_ref()).await });
        assert!(result.is_err());
    }

    // ======================================================================
    // get_entry / get_entry_mut
    // ======================================================================

    #[test]
    fn test_get_entry_returns_correct_entry() {
        let mut session = Session::in_memory();
        let id = session.append_message(make_test_message("Hello"));

        let entry = session.get_entry(&id);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().base().id.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn test_get_entry_mut_allows_modification() {
        let mut session = Session::in_memory();
        let id = session.append_message(make_test_message("Original"));

        let entry = session.get_entry_mut(&id).unwrap();
        if let SessionEntry::Message(msg) = entry {
            msg.message = SessionMessage::User {
                content: UserContent::Text("Modified".to_string()),
                timestamp: Some(0),
            };
        }

        // Verify modification persisted
        let entry = session.get_entry(&id).unwrap();
        if let SessionEntry::Message(msg) = entry {
            if let SessionMessage::User { content, .. } = &msg.message {
                match content {
                    UserContent::Text(t) => assert_eq!(t, "Modified"),
                    UserContent::Blocks(_) => panic!("expected Text content"),
                }
            } else {
                panic!("expected user message");
            }
        }
    }

    #[test]
    fn test_get_entry_nonexistent_returns_none() {
        let session = Session::in_memory();
        assert!(session.get_entry("nonexistent").is_none());
    }

    // ======================================================================
    // Branching round-trip (save with branches, reload, verify)
    // ======================================================================

    #[test]
    fn test_branching_round_trip_preserves_tree_structure() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        // Create: A -> B -> C, then branch from A: A -> D
        let id_a = session.append_message(make_test_message("A"));
        let id_b = session.append_message(make_test_message("B"));
        let id_c = session.append_message(make_test_message("C"));

        session.create_branch_from(&id_a);
        let id_d = session.append_message(make_test_message("D"));

        // Verify pre-save state
        let leaves = session.list_leaves();
        assert_eq!(leaves.len(), 2);

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        // Verify tree structure survived round-trip
        assert_eq!(loaded.entries.len(), 4);
        let loaded_leaves = loaded.list_leaves();
        assert_eq!(loaded_leaves.len(), 2);
        assert!(loaded_leaves.contains(&id_c));
        assert!(loaded_leaves.contains(&id_d));

        // Verify parent linking
        let path_to_c = loaded.get_path_to_entry(&id_c);
        assert_eq!(path_to_c, vec![id_a.as_str(), id_b.as_str(), id_c.as_str()]);

        let path_to_d = loaded.get_path_to_entry(&id_d);
        assert_eq!(path_to_d, vec![id_a.as_str(), id_d.as_str()]);
    }

    // ======================================================================
    // Session directory resolution from CWD
    // ======================================================================

    #[test]
    fn test_encode_cwd_strips_leading_separators() {
        let path = std::path::Path::new("/home/user/my-project");
        let encoded = encode_cwd(path);
        assert_eq!(encoded, "--home-user-my-project--");
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_encode_cwd_handles_deeply_nested_path() {
        let path = std::path::Path::new("/a/b/c/d/e/f");
        let encoded = encode_cwd(path);
        assert_eq!(encoded, "--a-b-c-d-e-f--");
    }

    #[test]
    fn test_save_creates_project_session_dir_from_cwd() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        session.append_message(make_test_message("test"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        // The saved path should be inside a CWD-encoded subdirectory
        let parent = path.parent().unwrap();
        let dir_name = parent.file_name().unwrap().to_string_lossy();
        assert!(
            dir_name.starts_with("--"),
            "session dir should start with --"
        );
        assert!(dir_name.ends_with("--"), "session dir should end with --");

        // The file should have .jsonl extension
        assert_eq!(path.extension().unwrap(), "jsonl");
    }

    #[test]
    fn test_can_reuse_known_entry_requires_matching_mtime_and_size() {
        let known_entry = SessionPickEntry {
            path: PathBuf::from("session.jsonl"),
            id: "session-id".to_string(),
            timestamp: "2026-01-01T00:00:00.000Z".to_string(),
            message_count: 4,
            name: Some("cached".to_string()),
            last_modified_ms: 1234,
            size_bytes: 4096,
        };

        assert!(can_reuse_known_entry(&known_entry, 1234, 4096));
        assert!(!can_reuse_known_entry(&known_entry, 1235, 4096));
        assert!(!can_reuse_known_entry(&known_entry, 1234, 4097));
    }

    #[test]
    fn test_scan_sessions_on_disk_ignores_stale_known_entry_when_size_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        session.append_message(make_test_message("first"));
        session.append_message(make_test_message("second"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().expect("session path");
        let metadata = std::fs::metadata(&path).expect("session metadata");
        let disk_size = metadata.len();
        #[allow(clippy::cast_possible_truncation)]
        let disk_ms = metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let stale_known_entry = SessionPickEntry {
            path: path.clone(),
            id: session.header.id.clone(),
            timestamp: session.header.timestamp.clone(),
            message_count: 999,
            name: Some("stale".to_string()),
            last_modified_ms: disk_ms,
            size_bytes: disk_size.saturating_add(1),
        };

        let session_dir = path.parent().expect("session parent").to_path_buf();
        let scanned =
            run_async(async { scan_sessions_on_disk(&session_dir, vec![stale_known_entry]).await })
                .expect("scan sessions");
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].path, path);
        assert_eq!(scanned[0].message_count, 2);
        assert_eq!(scanned[0].size_bytes, disk_size);
    }

    // ======================================================================
    // All entries corrupted (only header valid)
    // ======================================================================

    #[test]
    fn test_all_entries_corrupted_produces_empty_session() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        session.append_message(make_test_message("A"));
        session.append_message(make_test_message("B"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        // Corrupt all entry lines (keep header at index 0)
        for (i, line) in lines.iter_mut().enumerate().skip(1) {
            *line = format!("GARBAGE_{i}");
        }
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let (loaded, diagnostics) = run_async(async {
            Session::open_with_diagnostics(path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        assert_eq!(diagnostics.skipped_entries.len(), 2);
        assert!(loaded.entries.is_empty());
        assert!(loaded.leaf_id.is_none());
        // Header should still be valid
        assert_eq!(loaded.header.id, session.header.id);
    }

    // ======================================================================
    // Unicode and special character content
    // ======================================================================

    #[test]
    fn test_unicode_content_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        let unicode_texts = [
            "Hello \u{1F600} World",    // emoji
            "\u{4F60}\u{597D}",         // Chinese
            "\u{0410}\u{0411}\u{0412}", // Cyrillic
            "caf\u{00E9}",              // accented
            "tab\there\nnewline",       // control chars
            "\"quoted\" and \\escaped", // JSON special chars
        ];

        for text in &unicode_texts {
            session.append_message(make_test_message(text));
        }

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.entries.len(), unicode_texts.len());

        for (i, entry) in loaded.entries.iter().enumerate() {
            if let SessionEntry::Message(msg) = entry {
                if let SessionMessage::User { content, .. } = &msg.message {
                    match content {
                        UserContent::Text(t) => assert_eq!(t, unicode_texts[i]),
                        UserContent::Blocks(_) => panic!("expected Text content at index {i}"),
                    }
                }
            }
        }
    }

    // ======================================================================
    // Multiple compactions
    // ======================================================================

    #[test]
    fn test_multiple_compactions_latest_wins() {
        let mut session = Session::in_memory();

        let _id_a = session.append_message(make_test_message("old A"));
        let _id_b = session.append_message(make_test_message("old B"));
        let id_c = session.append_message(make_test_message("kept C"));

        // First compaction: keep from C
        session.append_compaction("Summary 1".to_string(), id_c, 1000, None, None);

        let _id_d = session.append_message(make_test_message("new D"));
        let id_e = session.append_message(make_test_message("new E"));

        // Second compaction: keep from E
        session.append_compaction("Summary 2".to_string(), id_e, 2000, None, None);

        let id_f = session.append_message(make_test_message("newest F"));

        session.navigate_to(&id_f);
        let messages = session.to_messages_for_current_path();

        // Old messages A, B should definitely not appear
        let all_text: String = messages
            .iter()
            .filter_map(|m| match m {
                Message::User(u) => match &u.content {
                    UserContent::Text(t) => Some(t.clone()),
                    UserContent::Blocks(_) => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" ");

        assert!(!all_text.contains("old A"), "A should be compacted away");
        assert!(!all_text.contains("old B"), "B should be compacted away");
    }

    // ======================================================================
    // Session with only metadata entries (no messages)
    // ======================================================================

    #[test]
    fn test_session_with_only_metadata_entries() {
        let mut session = Session::in_memory();

        session.append_model_change("anthropic".to_string(), "claude-opus".to_string());
        session.append_thinking_level_change("high".to_string());
        session.set_name("metadata-only");

        // to_messages should return empty (no actual messages)
        let messages = session.to_messages();
        assert!(messages.is_empty());

        // entries_for_current_path should still return the metadata entries
        let entries = session.entries_for_current_path();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_metadata_only_session_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        session.append_model_change("openai".to_string(), "gpt-4o".to_string());
        session.append_thinking_level_change("medium".to_string());

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.entries.len(), 2);
        assert!(
            loaded
                .entries
                .iter()
                .any(|e| matches!(e, SessionEntry::ModelChange(_)))
        );
        assert!(
            loaded
                .entries
                .iter()
                .any(|e| matches!(e, SessionEntry::ThinkingLevelChange(_)))
        );
    }

    // ======================================================================
    // Session name round-trip persistence
    // ======================================================================

    #[test]
    fn test_session_name_survives_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        session.append_message(make_test_message("Hello"));
        session.set_name("my-important-session");

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.get_name().as_deref(), Some("my-important-session"));
    }

    // ======================================================================
    // Trailing newline / whitespace in JSONL
    // ======================================================================

    #[test]
    fn test_trailing_whitespace_in_jsonl_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));
        session.append_message(make_test_message("test"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        // Append extra blank lines at the end
        let mut contents = std::fs::read_to_string(&path).unwrap();
        contents.push_str("\n\n\n");
        std::fs::write(&path, contents).unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.entries.len(), 1);
    }

    // ======================================================================
    // Branching after compaction
    // ======================================================================

    #[test]
    fn test_branching_after_compaction() {
        let mut session = Session::in_memory();

        let _id_a = session.append_message(make_test_message("old A"));
        let id_b = session.append_message(make_test_message("kept B"));

        session.append_compaction("Compacted".to_string(), id_b.clone(), 500, None, None);

        let id_c = session.append_message(make_test_message("C after compaction"));

        // Branch from B (the compaction keep-point)
        session.create_branch_from(&id_b);
        let id_d = session.append_message(make_test_message("D branch after compaction"));

        let leaves = session.list_leaves();
        assert_eq!(leaves.len(), 2);
        assert!(leaves.contains(&id_c));
        assert!(leaves.contains(&id_d));
    }

    // ======================================================================
    // Assistant message with tool calls round-trip
    // ======================================================================

    #[test]
    fn test_assistant_with_tool_calls_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::create_with_dir(Some(temp.path().to_path_buf()));

        session.append_message(make_test_message("read my file"));

        let assistant = AssistantMessage {
            content: vec![
                ContentBlock::Text(TextContent::new("Let me read that for you.")),
                ContentBlock::ToolCall(crate::model::ToolCall {
                    id: "call_abc".to_string(),
                    name: "read".to_string(),
                    arguments: serde_json::json!({"path": "src/main.rs"}),
                    thought_signature: None,
                }),
            ],
            api: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-test".to_string(),
            usage: Usage {
                input: 100,
                output: 50,
                cache_read: 0,
                cache_write: 0,
                total_tokens: 150,
                cost: Cost::default(),
            },
            stop_reason: StopReason::ToolUse,
            error_message: None,
            timestamp: 12345,
        };
        session.append_message(SessionMessage::Assistant { message: assistant });

        session.append_message(SessionMessage::ToolResult {
            tool_call_id: "call_abc".to_string(),
            tool_name: "read".to_string(),
            content: vec![ContentBlock::Text(TextContent::new("fn main() {}"))],
            details: Some(serde_json::json!({"lines": 1, "truncated": false})),
            is_error: false,
            timestamp: Some(12346),
        });

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.entries.len(), 3);

        // Verify tool call content survived
        let has_tool_call = loaded.entries.iter().any(|e| {
            if let SessionEntry::Message(msg) = e {
                if let SessionMessage::Assistant { message } = &msg.message {
                    return message
                        .content
                        .iter()
                        .any(|c| matches!(c, ContentBlock::ToolCall(tc) if tc.id == "call_abc"));
                }
            }
            false
        });
        assert!(has_tool_call, "tool call should survive round-trip");

        // Verify tool result details survived
        let has_details = loaded.entries.iter().any(|e| {
            if let SessionEntry::Message(msg) = e {
                if let SessionMessage::ToolResult { details, .. } = &msg.message {
                    return details.is_some();
                }
            }
            false
        });
        assert!(has_details, "tool result details should survive round-trip");
    }

    // ======================================================================
    // FUZZ-P1.4: Proptest coverage for Session JSONL parsing
    // ======================================================================

    mod proptest_session {
        use super::*;
        use proptest::prelude::*;
        use serde_json::json;

        /// Generate a random valid timestamp string.
        fn timestamp_strategy() -> impl Strategy<Value = String> {
            (
                2020u32..2030,
                1u32..13,
                1u32..29,
                0u32..24,
                0u32..60,
                0u32..60,
            )
                .prop_map(|(y, mo, d, h, mi, s)| {
                    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000Z")
                })
        }

        /// Generate a random entry ID (8 hex chars).
        fn entry_id_strategy() -> impl Strategy<Value = String> {
            "[0-9a-f]{8}"
        }

        /// Generate an arbitrary JSON value of bounded depth/size.
        fn bounded_json_value(max_depth: u32) -> BoxedStrategy<serde_json::Value> {
            if max_depth == 0 {
                prop_oneof![
                    Just(json!(null)),
                    any::<bool>().prop_map(|b| json!(b)),
                    any::<i64>().prop_map(|n| json!(n)),
                    "[a-zA-Z0-9 ]{0,32}".prop_map(|s| json!(s)),
                ]
                .boxed()
            } else {
                prop_oneof![
                    Just(json!(null)),
                    any::<bool>().prop_map(|b| json!(b)),
                    any::<i64>().prop_map(|n| json!(n)),
                    "[a-zA-Z0-9 ]{0,32}".prop_map(|s| json!(s)),
                    prop::collection::vec(bounded_json_value(max_depth - 1), 0..4)
                        .prop_map(serde_json::Value::Array),
                ]
                .boxed()
            }
        }

        /// Generate a valid `SessionEntry` JSON object for one of the known types.
        #[allow(clippy::too_many_lines)]
        fn valid_session_entry_json() -> impl Strategy<Value = serde_json::Value> {
            let ts = timestamp_strategy();
            let eid = entry_id_strategy();
            let parent = prop::option::of(entry_id_strategy());

            (ts, eid, parent, 0u8..8).prop_flat_map(|(ts, eid, parent, variant)| {
                let base = json!({
                    "id": eid,
                    "parentId": parent,
                    "timestamp": ts,
                });

                match variant {
                    0 => {
                        // Message - User
                        "[a-zA-Z0-9 ]{1,64}"
                            .prop_map(move |text| {
                                let mut v = base.clone();
                                v["type"] = json!("message");
                                v["message"] = json!({
                                    "role": "user",
                                    "content": text,
                                });
                                v
                            })
                            .boxed()
                    }
                    1 => {
                        // Message - Assistant
                        "[a-zA-Z0-9 ]{1,64}"
                            .prop_map(move |text| {
                                let mut v = base.clone();
                                v["type"] = json!("message");
                                v["message"] = json!({
                                    "role": "assistant",
                                    "content": [{"type": "text", "text": text}],
                                    "api": "anthropic",
                                    "provider": "anthropic",
                                    "model": "test-model",
                                    "usage": {
                                        "input": 10,
                                        "output": 5,
                                        "cacheRead": 0,
                                        "cacheWrite": 0,
                                        "totalTokens": 15,
                                        "cost": {"input": 0.0, "output": 0.0, "total": 0.0}
                                    },
                                    "stopReason": "end_turn",
                                    "timestamp": 12345,
                                });
                                v
                            })
                            .boxed()
                    }
                    2 => {
                        // ModelChange
                        ("[a-z]{3,8}", "[a-z0-9-]{5,20}")
                            .prop_map(move |(provider, model)| {
                                let mut v = base.clone();
                                v["type"] = json!("model_change");
                                v["provider"] = json!(provider);
                                v["modelId"] = json!(model);
                                v
                            })
                            .boxed()
                    }
                    3 => {
                        // ThinkingLevelChange
                        prop_oneof![
                            Just("off".to_string()),
                            Just("low".to_string()),
                            Just("medium".to_string()),
                            Just("high".to_string()),
                        ]
                        .prop_map(move |level| {
                            let mut v = base.clone();
                            v["type"] = json!("thinking_level_change");
                            v["thinkingLevel"] = json!(level);
                            v
                        })
                        .boxed()
                    }
                    4 => {
                        // Compaction
                        ("[a-zA-Z0-9 ]{1,32}", entry_id_strategy(), 100u64..100_000)
                            .prop_map(move |(summary, kept_id, tokens)| {
                                let mut v = base.clone();
                                v["type"] = json!("compaction");
                                v["summary"] = json!(summary);
                                v["firstKeptEntryId"] = json!(kept_id);
                                v["tokensBefore"] = json!(tokens);
                                v
                            })
                            .boxed()
                    }
                    5 => {
                        // Label
                        (entry_id_strategy(), prop::option::of("[a-zA-Z0-9 ]{1,16}"))
                            .prop_map(move |(target, label)| {
                                let mut v = base.clone();
                                v["type"] = json!("label");
                                v["targetId"] = json!(target);
                                if let Some(l) = label {
                                    v["label"] = json!(l);
                                }
                                v
                            })
                            .boxed()
                    }
                    6 => {
                        // SessionInfo
                        prop::option::of("[a-zA-Z0-9 ]{1,32}")
                            .prop_map(move |name| {
                                let mut v = base.clone();
                                v["type"] = json!("session_info");
                                if let Some(n) = name {
                                    v["name"] = json!(n);
                                }
                                v
                            })
                            .boxed()
                    }
                    _ => {
                        // Custom
                        ("[a-z_]{3,12}", bounded_json_value(2))
                            .prop_map(move |(custom_type, data)| {
                                let mut v = base.clone();
                                v["type"] = json!("custom");
                                v["customType"] = json!(custom_type);
                                v["data"] = data;
                                v
                            })
                            .boxed()
                    }
                }
            })
        }

        /// Generate a corrupted JSON line (valid JSON but wrong shape for `SessionEntry`).
        fn corrupted_entry_json() -> impl Strategy<Value = String> {
            prop_oneof![
                // Missing "type" field
                Just(r#"{"id":"aaaaaaaa","timestamp":"2024-01-01T00:00:00.000Z"}"#.to_string()),
                // Unknown type
                Just(r#"{"type":"unknown_type","id":"bbbbbbbb","timestamp":"2024-01-01T00:00:00.000Z"}"#.to_string()),
                // Empty object
                Just(r"{}".to_string()),
                // Array instead of object
                Just(r"[1,2,3]".to_string()),
                // Scalar values
                Just(r"42".to_string()),
                Just(r#""just a string""#.to_string()),
                Just(r"null".to_string()),
                Just(r"true".to_string()),
                // Truncated JSON (simulating crash)
                Just(r#"{"type":"message","id":"cccccccc","timestamp":"2024-01-01T"#.to_string()),
                // Valid JSON with wrong field types
                Just(r#"{"type":"message","id":12345,"timestamp":"2024-01-01T00:00:00.000Z"}"#.to_string()),
            ]
        }

        /// Build a complete JSONL file string from header + entries.
        fn build_jsonl(header: &str, entry_lines: &[String]) -> String {
            let mut lines = vec![header.to_string()];
            lines.extend(entry_lines.iter().cloned());
            lines.join("\n")
        }

        // ------------------------------------------------------------------
        // Proptest 1: SessionEntry deserialization never panics
        // ------------------------------------------------------------------
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 256,
                max_shrink_iters: 200,
                .. ProptestConfig::default()
            })]

            #[test]
            fn session_entry_deser_never_panics(
                entry_json in valid_session_entry_json()
            ) {
                let json_str = entry_json.to_string();
                // Must not panic — Ok or Err is fine
                let _ = serde_json::from_str::<SessionEntry>(&json_str);
            }
        }

        // ------------------------------------------------------------------
        // Proptest 2: Corrupted/malformed input never panics
        // ------------------------------------------------------------------
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 256,
                max_shrink_iters: 200,
                .. ProptestConfig::default()
            })]

            #[test]
            fn corrupted_entry_deser_never_panics(
                line in corrupted_entry_json()
            ) {
                let _ = serde_json::from_str::<SessionEntry>(&line);
            }

            #[test]
            fn arbitrary_bytes_deser_never_panics(
                raw in prop::collection::vec(any::<u8>(), 0..512)
            ) {
                // Even random bytes must not panic serde
                if let Ok(s) = String::from_utf8(raw) {
                    let _ = serde_json::from_str::<SessionEntry>(&s);
                }
            }
        }

        // ------------------------------------------------------------------
        // Proptest 3: Valid entries round-trip through serialization
        // ------------------------------------------------------------------
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 256,
                max_shrink_iters: 200,
                .. ProptestConfig::default()
            })]

            #[test]
            fn valid_entry_round_trip(
                entry_json in valid_session_entry_json()
            ) {
                let json_str = entry_json.to_string();
                if let Ok(entry) = serde_json::from_str::<SessionEntry>(&json_str) {
                    // Serialize back
                    let reserialized = serde_json::to_string(&entry).unwrap();
                    // Deserialize again
                    let re_entry = serde_json::from_str::<SessionEntry>(&reserialized).unwrap();
                    // Both should have the same entry ID
                    assert_eq!(entry.base_id(), re_entry.base_id());
                    // Both should have the same type tag
                    assert_eq!(
                        std::mem::discriminant(&entry),
                        std::mem::discriminant(&re_entry)
                    );
                }
            }
        }

        // ------------------------------------------------------------------
        // Proptest 4: Full JSONL load with mixed valid/invalid lines
        //             recovers valid entries and reports diagnostics
        // ------------------------------------------------------------------
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 128,
                max_shrink_iters: 100,
                .. ProptestConfig::default()
            })]

            #[test]
            fn jsonl_corrupted_recovery(
                valid_entries in prop::collection::vec(valid_session_entry_json(), 1..8),
                corrupted_lines in prop::collection::vec(corrupted_entry_json(), 0..5),
                interleave_seed in any::<u64>(),
            ) {
                let header_json = json!({
                    "type": "session",
                    "version": 3,
                    "id": "testid01",
                    "timestamp": "2024-01-01T00:00:00.000Z",
                    "cwd": "/tmp/test"
                }).to_string();

                // Interleave valid and corrupted lines deterministically
                let valid_strs: Vec<String> = valid_entries.iter().map(ToString::to_string).collect();
                let total = valid_strs.len() + corrupted_lines.len();
                let mut all_lines: Vec<(bool, String)> = Vec::with_capacity(total);
                for s in &valid_strs {
                    all_lines.push((true, s.clone()));
                }
                for s in &corrupted_lines {
                    all_lines.push((false, s.clone()));
                }

                // Deterministic shuffle based on seed
                let mut seed = interleave_seed;
                for i in (1..all_lines.len()).rev() {
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    let j = (seed >> 33) as usize % (i + 1);
                    all_lines.swap(i, j);
                }

                let entry_lines: Vec<String> = all_lines.iter().map(|(_, s)| s.clone()).collect();
                let content = build_jsonl(&header_json, &entry_lines);

                // Write to temp file and load
                let temp_dir = tempfile::tempdir().unwrap();
                let file_path = temp_dir.path().join("test_session.jsonl");
                std::fs::write(&file_path, &content).unwrap();

                let (session, diagnostics) = run_async(async {
                    Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
                }).unwrap();

                // Invariant: parsed + skipped == total lines (all non-empty)
                let total_parsed = session.entries.len();
                assert_eq!(
                    total_parsed + diagnostics.skipped_entries.len(),
                    total,
                    "parsed ({total_parsed}) + skipped ({}) should equal total lines ({total})",
                    diagnostics.skipped_entries.len()
                );
            }
        }

        // ------------------------------------------------------------------
        // Proptest 5: Orphaned parent links are detected
        // ------------------------------------------------------------------
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 128,
                max_shrink_iters: 100,
                .. ProptestConfig::default()
            })]

            #[test]
            fn orphaned_parent_links_detected(
                n_entries in 2usize..10,
                orphan_idx in 0usize..8,
            ) {
                let orphan_idx = orphan_idx % n_entries;
                let header_json = json!({
                    "type": "session",
                    "version": 3,
                    "id": "testid01",
                    "timestamp": "2024-01-01T00:00:00.000Z",
                    "cwd": "/tmp/test"
                }).to_string();

                let mut entry_lines = Vec::new();
                let mut prev_id: Option<String> = None;

                for i in 0..n_entries {
                    let eid = format!("{i:08x}");
                    let parent = if i == orphan_idx {
                        // Point to a nonexistent parent
                        Some("deadbeef".to_string())
                    } else {
                        prev_id.clone()
                    };

                    let entry = json!({
                        "type": "message",
                        "id": eid,
                        "parentId": parent,
                        "timestamp": "2024-01-01T00:00:00.000Z",
                        "message": {
                            "role": "user",
                            "content": format!("msg {i}"),
                        }
                    });
                    entry_lines.push(entry.to_string());
                    prev_id = Some(eid);
                }

                let content = build_jsonl(&header_json, &entry_lines);
                let temp_dir = tempfile::tempdir().unwrap();
                let file_path = temp_dir.path().join("orphan_test.jsonl");
                std::fs::write(&file_path, &content).unwrap();

                let (_session, diagnostics) = run_async(async {
                    Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
                }).unwrap();

                // The orphaned entry should be detected
                let has_orphan = diagnostics.orphaned_parent_links.iter().any(|o| {
                    o.missing_parent_id == "deadbeef"
                });
                assert!(
                    has_orphan,
                    "orphaned parent link to 'deadbeef' should be detected"
                );
            }
        }

        // ------------------------------------------------------------------
        // Proptest 6: ensure_entry_ids assigns IDs to entries without them
        // ------------------------------------------------------------------
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 128,
                max_shrink_iters: 100,
                .. ProptestConfig::default()
            })]

            #[test]
            fn ensure_entry_ids_fills_gaps(
                n_total in 1usize..20,
                missing_mask in prop::collection::vec(any::<bool>(), 1..20),
            ) {
                let n = n_total.min(missing_mask.len());
                let mut entries: Vec<SessionEntry> = (0..n).map(|i| {
                    let id = if missing_mask[i] {
                        None
                    } else {
                        Some(format!("{i:08x}"))
                    };
                    SessionEntry::Message(MessageEntry {
                        base: EntryBase {
                            id,
                            parent_id: None,
                            timestamp: "2024-01-01T00:00:00.000Z".to_string(),
                        },
                        message: SessionMessage::User {
                            content: UserContent::Text(format!("msg {i}")),
                            timestamp: Some(0),
                        },
                    })
                }).collect();

                ensure_entry_ids(&mut entries);

                // All entries must have IDs after the call
                for entry in &entries {
                    assert!(
                        entry.base_id().is_some(),
                        "all entries must have IDs after ensure_entry_ids"
                    );
                }

                // All IDs must be unique
                let ids: Vec<&String> = entries.iter().filter_map(|e| e.base_id()).collect();
                let unique: std::collections::HashSet<&String> = ids.iter().copied().collect();
                assert_eq!(
                    ids.len(),
                    unique.len(),
                    "all entry IDs must be unique"
                );
            }
        }

        // ------------------------------------------------------------------
        // Proptest 7: SessionHeader deserialization with boundary values
        // ------------------------------------------------------------------
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 256,
                max_shrink_iters: 200,
                .. ProptestConfig::default()
            })]

            #[test]
            fn session_header_deser_never_panics(
                version in prop::option::of(0u8..255),
                id in "[a-zA-Z0-9-]{0,64}",
                ts in timestamp_strategy(),
                cwd in "(/[a-zA-Z0-9_]{1,8}){0,5}",
                provider in prop::option::of("[a-z]{2,10}"),
                model_id in prop::option::of("[a-z0-9-]{2,20}"),
                thinking_level in prop::option::of("[a-z]{2,8}"),
            ) {
                let mut obj = json!({
                    "type": "session",
                    "id": id,
                    "timestamp": ts,
                    "cwd": cwd,
                });
                if let Some(v) = version {
                    obj["version"] = json!(v);
                }
                if let Some(p) = &provider {
                    obj["provider"] = json!(p);
                }
                if let Some(m) = &model_id {
                    obj["modelId"] = json!(m);
                }
                if let Some(t) = &thinking_level {
                    obj["thinkingLevel"] = json!(t);
                }
                let json_str = obj.to_string();
                let _ = serde_json::from_str::<SessionHeader>(&json_str);
            }
        }

        // ------------------------------------------------------------------
        // Proptest 8: Edge-case JSONL files
        // ------------------------------------------------------------------

        #[test]
        fn empty_file_returns_error() {
            let temp_dir = tempfile::tempdir().unwrap();
            let file_path = temp_dir.path().join("empty.jsonl");
            std::fs::write(&file_path, "").unwrap();

            let result = run_async(async {
                Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
            });
            assert!(result.is_err(), "empty file should return error");
        }

        #[test]
        fn header_only_file_produces_empty_session() {
            let header = json!({
                "type": "session",
                "version": 3,
                "id": "testid01",
                "timestamp": "2024-01-01T00:00:00.000Z",
                "cwd": "/tmp/test"
            })
            .to_string();

            let temp_dir = tempfile::tempdir().unwrap();
            let file_path = temp_dir.path().join("header_only.jsonl");
            std::fs::write(&file_path, &header).unwrap();

            let (session, diagnostics) = run_async(async {
                Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
            })
            .unwrap();

            assert!(
                session.entries.is_empty(),
                "header-only file should have no entries"
            );
            assert!(diagnostics.skipped_entries.is_empty(), "no lines to skip");
        }

        #[test]
        fn file_with_only_invalid_lines_has_diagnostics() {
            let header = json!({
                "type": "session",
                "version": 3,
                "id": "testid01",
                "timestamp": "2024-01-01T00:00:00.000Z",
                "cwd": "/tmp/test"
            })
            .to_string();

            let content = format!(
                "{}\n{}\n{}\n{}",
                header,
                r#"{"bad":"json","no":"type"}"#,
                r"not json at all",
                r#"{"type":"nonexistent_type","id":"aaa","timestamp":"2024-01-01T00:00:00.000Z"}"#,
            );

            let temp_dir = tempfile::tempdir().unwrap();
            let file_path = temp_dir.path().join("all_invalid.jsonl");
            std::fs::write(&file_path, &content).unwrap();

            let (session, diagnostics) = run_async(async {
                Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
            })
            .unwrap();

            assert!(
                session.entries.is_empty(),
                "all-invalid file should have no entries"
            );
            assert_eq!(
                diagnostics.skipped_entries.len(),
                3,
                "should have 3 skipped entries"
            );
        }

        #[test]
        fn duplicate_entry_ids_are_loaded_without_panic() {
            let header = json!({
                "type": "session",
                "version": 3,
                "id": "testid01",
                "timestamp": "2024-01-01T00:00:00.000Z",
                "cwd": "/tmp/test"
            })
            .to_string();

            let entry1 = json!({
                "type": "message",
                "id": "deadbeef",
                "timestamp": "2024-01-01T00:00:00.000Z",
                "message": {"role": "user", "content": "first"}
            })
            .to_string();

            let entry2 = json!({
                "type": "message",
                "id": "deadbeef",
                "timestamp": "2024-01-01T00:00:01.000Z",
                "message": {"role": "user", "content": "second (duplicate id)"}
            })
            .to_string();

            let content = format!("{header}\n{entry1}\n{entry2}");

            let temp_dir = tempfile::tempdir().unwrap();
            let file_path = temp_dir.path().join("dup_ids.jsonl");
            std::fs::write(&file_path, &content).unwrap();

            // Must not panic
            let (session, _diagnostics) = run_async(async {
                Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
            })
            .unwrap();

            assert_eq!(session.entries.len(), 2, "both entries should be loaded");
        }
    }

    // ------------------------------------------------------------------
    // Incremental append tests
    // ------------------------------------------------------------------

    #[test]
    fn test_incremental_append_writes_only_new_entries() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        // First save: full rewrite (persisted_entry_count == 0).
        session.append_message(make_test_message("msg A"));
        session.append_message(make_test_message("msg B"));
        run_async(async { session.save().await }).unwrap();

        assert_eq!(session.persisted_entry_count, 2);
        assert_eq!(session.appends_since_checkpoint, 0);

        let path = session.path.clone().unwrap();
        let lines_after_first = std::fs::read_to_string(&path).unwrap().lines().count();
        // 1 header + 2 entries = 3 lines
        assert_eq!(lines_after_first, 3);

        // Add more entries and save again (incremental append).
        session.append_message(make_test_message("msg C"));
        run_async(async { session.save().await }).unwrap();

        assert_eq!(session.persisted_entry_count, 3);
        assert_eq!(session.appends_since_checkpoint, 1);

        let lines_after_second = std::fs::read_to_string(&path).unwrap().lines().count();
        // 1 header + 3 entries = 4 lines
        assert_eq!(lines_after_second, 4);
    }

    #[test]
    fn test_header_change_forces_full_rewrite() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();
        assert_eq!(session.persisted_entry_count, 1);
        assert!(!session.header_dirty);

        // Modify header.
        session.set_model_header(Some("new-provider".to_string()), None, None);
        assert!(session.header_dirty);

        session.append_message(make_test_message("msg B"));
        run_async(async { session.save().await }).unwrap();

        // Full rewrite resets all counters.
        assert_eq!(session.persisted_entry_count, 2);
        assert!(!session.header_dirty);
        assert_eq!(session.appends_since_checkpoint, 0);

        // Verify header on disk has the new provider.
        let path = session.path.clone().unwrap();
        let first_line = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        let header: serde_json::Value = serde_json::from_str(&first_line).unwrap();
        assert_eq!(header["provider"], "new-provider");
    }

    #[test]
    fn test_compaction_entry_forces_full_rewrite() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        let id_a = session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();
        assert_eq!(session.persisted_entry_count, 1);

        // Append a compaction entry — should force full rewrite.
        session.append_compaction("summary".to_string(), id_a, 100, None, None);
        session.append_message(make_test_message("msg B"));

        run_async(async { session.save().await }).unwrap();

        // Full rewrite: counters reset.
        assert_eq!(session.persisted_entry_count, 3);
        assert_eq!(session.appends_since_checkpoint, 0);
    }

    #[test]
    fn test_checkpoint_interval_forces_full_rewrite() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        // First save (full rewrite).
        session.append_message(make_test_message("initial"));
        run_async(async { session.save().await }).unwrap();

        // Simulate many incremental appends by setting the counter near threshold.
        let interval = compaction_checkpoint_interval();
        session.appends_since_checkpoint = interval;

        // Next save should trigger full rewrite due to checkpoint.
        session.append_message(make_test_message("triggers checkpoint"));
        run_async(async { session.save().await }).unwrap();

        // Full rewrite resets counters.
        assert_eq!(session.appends_since_checkpoint, 0);
        assert_eq!(session.persisted_entry_count, 2);
    }

    #[test]
    fn test_incremental_append_load_round_trip() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        // First save.
        session.append_message(make_test_message("msg A"));
        session.append_message(make_test_message("msg B"));
        run_async(async { session.save().await }).unwrap();

        // Incremental append.
        session.append_message(make_test_message("msg C"));
        run_async(async { session.save().await }).unwrap();

        let path = session.path.clone().unwrap();

        // Reload and verify all entries present.
        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.entries.len(), 3);
        // Verify the entry content by checking that we have messages A, B, C.
        let texts: Vec<&str> = loaded
            .entries
            .iter()
            .filter_map(|e| match e {
                SessionEntry::Message(m) => match &m.message {
                    SessionMessage::User {
                        content: UserContent::Text(t),
                        ..
                    } => Some(t.as_str()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec!["msg A", "msg B", "msg C"]);
    }

    #[test]
    fn test_persisted_entry_count_set_on_open() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        session.append_message(make_test_message("msg B"));
        session.append_message(make_test_message("msg C"));
        run_async(async { session.save().await }).unwrap();

        let path = session.path.clone().unwrap();
        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();

        assert_eq!(loaded.persisted_entry_count, 3);
        assert!(!loaded.header_dirty);
        assert_eq!(loaded.appends_since_checkpoint, 0);
    }

    #[test]
    fn test_no_new_entries_is_noop() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();

        let path = session.path.clone().unwrap();
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Sleep briefly to ensure mtime would change if file was written.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Save again with no changes.
        run_async(async { session.save().await }).unwrap();

        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "file should not be modified on no-op save"
        );
        assert_eq!(session.persisted_entry_count, 1);
    }

    #[test]
    fn test_incremental_append_caches_stay_valid() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();

        // After full rewrite, caches rebuilt.
        assert_eq!(session.entry_index.len(), 1);

        // Incremental append: add more entries.
        let id_b = session.append_message(make_test_message("msg B"));
        let id_c = session.append_message(make_test_message("msg C"));
        run_async(async { session.save().await }).unwrap();

        // Caches should still be valid (not rebuilt, but maintained incrementally).
        assert_eq!(session.entry_index.len(), 3);
        assert!(session.entry_index.contains_key(&id_b));
        assert!(session.entry_index.contains_key(&id_c));
        assert_eq!(session.cached_message_count, 3);
    }

    #[test]
    fn test_set_branched_from_marks_header_dirty() {
        let mut session = Session::create();
        assert!(!session.header_dirty);

        session.set_branched_from(Some("/some/path".to_string()));
        assert!(session.header_dirty);
    }

    // ====================================================================
    // Crash-consistency and recovery tests (bd-3ar8v.2.7)
    // ====================================================================

    /// Helper: build a valid JSONL session file string with header + N entries.
    fn build_crash_test_session_file(num_entries: usize) -> String {
        let header = serde_json::json!({
            "type": "session",
            "version": 3,
            "id": "crash-test",
            "timestamp": "2024-06-01T00:00:00.000Z",
            "cwd": "/tmp/test"
        });
        let mut lines = vec![serde_json::to_string(&header).unwrap()];
        for i in 0..num_entries {
            let entry = serde_json::json!({
                "type": "message",
                "id": format!("entry-{i}"),
                "timestamp": "2024-06-01T00:00:00.000Z",
                "message": {"role": "user", "content": format!("message {i}")}
            });
            lines.push(serde_json::to_string(&entry).unwrap());
        }
        lines.join("\n")
    }

    #[test]
    fn crash_empty_file_returns_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("empty.jsonl");
        std::fs::write(&file_path, "").unwrap();

        let result = run_async(async {
            Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
        });
        assert!(result.is_err(), "empty file should fail to open");
    }

    #[test]
    fn crash_corrupted_header_returns_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("bad_header.jsonl");
        std::fs::write(&file_path, "NOT VALID JSON\n").unwrap();

        let result = run_async(async {
            Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
        });
        assert!(result.is_err(), "corrupted header should fail");
    }

    #[test]
    fn crash_header_only_loads_empty() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("header_only.jsonl");
        let header = serde_json::json!({
            "type": "session",
            "version": 3,
            "id": "hdr-only",
            "timestamp": "2024-06-01T00:00:00.000Z",
            "cwd": "/tmp/test"
        });
        std::fs::write(
            &file_path,
            format!("{}\n", serde_json::to_string(&header).unwrap()),
        )
        .unwrap();

        let (session, diagnostics) = run_async(async {
            Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        assert!(session.entries.is_empty());
        assert!(diagnostics.skipped_entries.is_empty());
    }

    #[test]
    fn crash_truncated_last_entry_recovers_preceding() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("truncated.jsonl");

        let mut content = build_crash_test_session_file(3);
        let truncation_point = content.rfind('\n').unwrap();
        content.truncate(truncation_point);
        content.push_str("\n{\"type\":\"message\",\"id\":\"partial");

        std::fs::write(&file_path, &content).unwrap();

        let (session, diagnostics) = run_async(async {
            Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        assert_eq!(session.entries.len(), 2);
        assert_eq!(diagnostics.skipped_entries.len(), 1);
    }

    #[test]
    fn crash_multiple_corrupted_entries_recovers_valid() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("multi_corrupt.jsonl");

        let header = serde_json::json!({
            "type": "session",
            "version": 3,
            "id": "multi-corrupt",
            "timestamp": "2024-06-01T00:00:00.000Z",
            "cwd": "/tmp/test"
        });

        let valid_entry = |id: &str, text: &str| {
            serde_json::json!({
                "type": "message",
                "id": id,
                "timestamp": "2024-06-01T00:00:00.000Z",
                "message": {"role": "user", "content": text}
            })
            .to_string()
        };

        let lines = [
            serde_json::to_string(&header).unwrap(),
            valid_entry("v1", "first"),
            "GARBAGE LINE 1".to_string(),
            valid_entry("v2", "second"),
            "{incomplete json".to_string(),
            valid_entry("v3", "third"),
        ];

        std::fs::write(&file_path, lines.join("\n")).unwrap();

        let (session, diagnostics) = run_async(async {
            Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        assert_eq!(session.entries.len(), 3, "3 valid entries survive");
        assert_eq!(diagnostics.skipped_entries.len(), 2);
    }

    #[test]
    fn crash_incremental_append_survives_partial_write() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        session.append_message(make_test_message("msg B"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        // Simulate crash during append: write truncated entry.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        write!(
            file,
            "\n{{\"type\":\"message\",\"id\":\"crash-entry\",\"timestamp\":\"2024-06-01"
        )
        .unwrap();
        drop(file);

        let (loaded, diagnostics) = run_async(async {
            Session::open_with_diagnostics(path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        assert_eq!(loaded.entries.len(), 2, "original entries recovered");
        assert_eq!(diagnostics.skipped_entries.len(), 1);
    }

    #[test]
    fn crash_full_rewrite_atomic_persist() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("original"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let original_content = std::fs::read_to_string(&path).unwrap();

        session.set_model_header(Some("new-provider".to_string()), None, None);
        session.append_message(make_test_message("second"));
        run_async(async { session.save().await }).unwrap();

        let new_content = std::fs::read_to_string(&path).unwrap();
        assert_ne!(original_content, new_content);

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();
        assert_eq!(loaded.entries.len(), 2);
    }

    #[test]
    fn crash_flush_failure_restores_pending_mutations() {
        let mut queue = AutosaveQueue::with_limit(10);

        queue.enqueue_mutation(AutosaveMutationKind::Message);
        queue.enqueue_mutation(AutosaveMutationKind::Message);
        queue.enqueue_mutation(AutosaveMutationKind::Metadata);
        assert_eq!(queue.pending_mutations, 3);

        let ticket = queue
            .begin_flush(AutosaveFlushTrigger::Periodic)
            .expect("should have ticket");
        assert_eq!(queue.pending_mutations, 0);

        queue.finish_flush(ticket, false);
        assert_eq!(queue.pending_mutations, 3, "mutations restored");
        assert_eq!(queue.flush_failed, 1);
    }

    #[test]
    fn crash_flush_failure_respects_queue_capacity() {
        let mut queue = AutosaveQueue::with_limit(3);

        for _ in 0..3 {
            queue.enqueue_mutation(AutosaveMutationKind::Message);
        }
        let ticket = queue.begin_flush(AutosaveFlushTrigger::Periodic).unwrap();

        queue.enqueue_mutation(AutosaveMutationKind::Message);
        queue.enqueue_mutation(AutosaveMutationKind::Message);
        assert_eq!(queue.pending_mutations, 2);

        queue.finish_flush(ticket, false);
        assert_eq!(queue.pending_mutations, 3, "capped at max");
        assert!(queue.backpressure_events >= 2);
    }

    #[test]
    fn crash_shutdown_strict_propagates_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.path = Some(
            temp_dir
                .path()
                .join("nonexistent_dir")
                .join("session.jsonl"),
        );
        session.set_autosave_durability_for_test(AutosaveDurabilityMode::Strict);
        session.append_message(make_test_message("must save"));
        session
            .autosave_queue
            .enqueue_mutation(AutosaveMutationKind::Message);

        let result = run_async(async { session.flush_autosave_on_shutdown().await });
        assert!(result.is_err(), "strict mode propagates errors");
    }

    #[test]
    fn crash_shutdown_balanced_swallows_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.path = Some(
            temp_dir
                .path()
                .join("nonexistent_dir")
                .join("session.jsonl"),
        );
        session.set_autosave_durability_for_test(AutosaveDurabilityMode::Balanced);
        session.append_message(make_test_message("best effort"));
        session
            .autosave_queue
            .enqueue_mutation(AutosaveMutationKind::Message);

        let result = run_async(async { session.flush_autosave_on_shutdown().await });
        assert!(result.is_ok(), "balanced mode swallows errors");
    }

    #[test]
    fn crash_shutdown_throughput_skips_flush() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.path = Some(
            temp_dir
                .path()
                .join("nonexistent_dir")
                .join("session.jsonl"),
        );
        session.set_autosave_durability_for_test(AutosaveDurabilityMode::Throughput);
        session.append_message(make_test_message("no flush"));
        session
            .autosave_queue
            .enqueue_mutation(AutosaveMutationKind::Message);

        let result = run_async(async { session.flush_autosave_on_shutdown().await });
        assert!(result.is_ok());
        assert!(session.autosave_queue.pending_mutations > 0);
    }

    #[test]
    fn crash_save_reload_preserves_all_entry_types() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        let id_a = session.append_message(make_test_message("msg A"));
        session.append_model_change("provider-x".to_string(), "model-y".to_string());
        session.append_thinking_level_change("high".to_string());
        session.append_compaction("summary".to_string(), id_a, 500, None, None);
        session.append_message(make_test_message("msg B"));

        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();
        assert_eq!(loaded.entries.len(), session.entries.len());
    }

    #[test]
    fn crash_checkpoint_rewrite_cleans_corruption() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("initial"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        for i in 0..5 {
            session.append_message(make_test_message(&format!("msg {i}")));
            run_async(async { session.save().await }).unwrap();
        }

        // Corrupt an appended entry on disk.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        lines[3] = "CORRUPTED_ENTRY".to_string();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        // Force checkpoint: full rewrite replaces corrupted file with clean data.
        session.appends_since_checkpoint = compaction_checkpoint_interval();
        session.append_message(make_test_message("post checkpoint"));
        run_async(async { session.save().await }).unwrap();
        assert_eq!(session.appends_since_checkpoint, 0);

        let (reloaded, diagnostics) = run_async(async {
            Session::open_with_diagnostics(path.to_string_lossy().as_ref()).await
        })
        .unwrap();
        assert!(diagnostics.skipped_entries.is_empty());
        assert_eq!(reloaded.entries.len(), 7);
    }

    #[test]
    fn crash_trailing_newlines_loads_cleanly() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("trailing_nl.jsonl");

        let mut content = build_crash_test_session_file(2);
        content.push_str("\n\n\n");
        std::fs::write(&file_path, &content).unwrap();

        let (session, diagnostics) = run_async(async {
            Session::open_with_diagnostics(file_path.to_string_lossy().as_ref()).await
        })
        .unwrap();

        assert_eq!(session.entries.len(), 2);
        assert!(diagnostics.skipped_entries.is_empty());
    }

    #[test]
    fn crash_noop_save_after_reload_is_idempotent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("hello"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();
        let content_before = std::fs::read_to_string(&path).unwrap();

        let mut loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();
        run_async(async { loaded.save().await }).unwrap();

        let content_after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content_before, content_after);
    }

    #[test]
    fn crash_corrupt_then_continue_operation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        session.append_message(make_test_message("msg B"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        // Corrupt last entry.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        *lines.last_mut().unwrap() = "BROKEN_JSON".to_string();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let (mut recovered, diagnostics) = run_async(async {
            Session::open_with_diagnostics(path.to_string_lossy().as_ref()).await
        })
        .unwrap();
        assert_eq!(diagnostics.skipped_entries.len(), 1);
        assert_eq!(recovered.entries.len(), 1);

        // Continue: add and save.
        recovered.path = Some(path.clone());
        recovered.session_dir = Some(temp_dir.path().to_path_buf());
        recovered.append_message(make_test_message("msg C"));
        run_async(async { recovered.save().await }).unwrap();

        let reloaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();
        assert_eq!(reloaded.entries.len(), 2, "A and C present after recovery");
    }

    #[test]
    fn crash_defensive_rewrite_when_persisted_exceeds_entries() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();

        session.persisted_entry_count = 999;
        assert!(session.should_full_rewrite());

        session.append_message(make_test_message("msg B"));
        run_async(async { session.save().await }).unwrap();
        assert_eq!(session.persisted_entry_count, 2);
        assert_eq!(session.appends_since_checkpoint, 0);
    }

    #[test]
    fn crash_persisted_count_unchanged_on_append_failure() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();
        assert_eq!(session.persisted_entry_count, 1);

        let path = session.path.clone().unwrap();
        session.append_message(make_test_message("msg B"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        #[cfg(not(unix))]
        {
            return;
        }

        let result = run_async(async { session.save().await });

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        assert!(result.is_err());
        assert_eq!(session.persisted_entry_count, 1);

        run_async(async { session.save().await }).unwrap();
        assert_eq!(session.persisted_entry_count, 2);
    }

    #[test]
    fn crash_queue_backpressure_at_limit() {
        let mut queue = AutosaveQueue::with_limit(3);

        queue.enqueue_mutation(AutosaveMutationKind::Message);
        queue.enqueue_mutation(AutosaveMutationKind::Message);
        queue.enqueue_mutation(AutosaveMutationKind::Metadata);
        assert_eq!(queue.pending_mutations, 3);

        queue.enqueue_mutation(AutosaveMutationKind::Label);
        assert_eq!(queue.pending_mutations, 3, "capped");
        assert_eq!(queue.backpressure_events, 1);
    }

    #[test]
    fn crash_flush_failure_with_intervening_mutations() {
        let mut queue = AutosaveQueue::with_limit(8);

        for _ in 0..4 {
            queue.enqueue_mutation(AutosaveMutationKind::Message);
        }
        let ticket = queue.begin_flush(AutosaveFlushTrigger::Periodic).unwrap();

        queue.enqueue_mutation(AutosaveMutationKind::Message);
        queue.enqueue_mutation(AutosaveMutationKind::Metadata);
        assert_eq!(queue.pending_mutations, 2);

        // restore_budget = 8 - 2 = 6, restored = min(4, 6) = 4
        queue.finish_flush(ticket, false);
        assert_eq!(queue.pending_mutations, 6);
        assert_eq!(queue.flush_failed, 1);
    }

    #[test]
    fn crash_queue_metrics_snapshot() {
        let mut queue = AutosaveQueue::with_limit(5);
        queue.enqueue_mutation(AutosaveMutationKind::Message);
        queue.enqueue_mutation(AutosaveMutationKind::Metadata);
        queue.enqueue_mutation(AutosaveMutationKind::Label);

        let metrics = queue.metrics();
        assert_eq!(metrics.pending_mutations, 3);
        assert_eq!(metrics.max_pending_mutations, 5);
        assert_eq!(metrics.coalesced_mutations, 2);
        assert_eq!(metrics.flush_started, 0);
        assert!(metrics.last_flush_duration_ms.is_none());
    }

    #[test]
    fn crash_double_flush_is_noop() {
        let mut queue = AutosaveQueue::with_limit(10);
        queue.enqueue_mutation(AutosaveMutationKind::Message);
        let ticket = queue.begin_flush(AutosaveFlushTrigger::Periodic).unwrap();
        queue.finish_flush(ticket, true);

        assert!(queue.begin_flush(AutosaveFlushTrigger::Manual).is_none());
    }

    #[test]
    fn crash_entries_survive_failed_full_rewrite() {
        // std::mem::take moves entries out during full rewrite.
        // On error they must be restored.
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        session.set_model_header(Some("new-provider".to_string()), None, None);
        session.append_message(make_test_message("msg B"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let parent = path.parent().unwrap();
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        #[cfg(not(unix))]
        {
            return;
        }

        let result = run_async(async { session.save().await });
        assert!(result.is_err());

        assert_eq!(session.entries.len(), 2, "entries restored");
        assert_eq!(session.entry_index.len(), 2);
        assert!(session.header_dirty);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let parent = path.parent().unwrap();
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        run_async(async { session.save().await }).unwrap();
        assert!(!session.header_dirty);
    }

    #[test]
    fn crash_metrics_accumulate_across_failure_recovery() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        let m = session.autosave_metrics();
        assert_eq!(m.flush_succeeded, 1);
        assert_eq!(m.flush_failed, 0);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        #[cfg(not(unix))]
        {
            return;
        }

        session.append_message(make_test_message("msg B"));
        let _ = run_async(async { session.save().await });

        let m = session.autosave_metrics();
        assert_eq!(m.flush_failed, 1);
        assert!(m.pending_mutations > 0);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        run_async(async { session.save().await }).unwrap();

        let m = session.autosave_metrics();
        assert_eq!(m.flush_succeeded, 2);
        assert_eq!(m.flush_failed, 1);
        assert_eq!(m.pending_mutations, 0);
        assert_eq!(m.flush_started, 3);
    }

    #[test]
    fn crash_many_sequential_appends_accumulate() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("initial"));
        run_async(async { session.save().await }).unwrap();

        for i in 0..10 {
            session.append_message(make_test_message(&format!("append-{i}")));
            run_async(async { session.save().await }).unwrap();
        }

        assert_eq!(session.persisted_entry_count, 11);
        assert_eq!(session.appends_since_checkpoint, 10);

        let path = session.path.clone().unwrap();
        let line_count = std::fs::read_to_string(&path).unwrap().lines().count();
        assert_eq!(line_count, 12, "1 header + 11 entries");

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();
        assert_eq!(loaded.entries.len(), 11);
    }

    #[test]
    fn crash_load_unsaved_entry_absent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("saved A"));
        session.append_message(make_test_message("saved B"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        session.append_message(make_test_message("unsaved C"));
        assert_eq!(session.entries.len(), 3);

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();
        assert_eq!(loaded.entries.len(), 2, "unsaved entry absent");
    }

    #[test]
    fn crash_append_retry_after_transient_failure() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut session = Session::create();
        session.session_dir = Some(temp_dir.path().to_path_buf());

        session.append_message(make_test_message("msg A"));
        run_async(async { session.save().await }).unwrap();
        let path = session.path.clone().unwrap();

        session.append_message(make_test_message("msg B"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        #[cfg(not(unix))]
        {
            return;
        }

        let result = run_async(async { session.save().await });
        assert!(result.is_err());
        assert_eq!(session.persisted_entry_count, 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        run_async(async { session.save().await }).unwrap();
        assert_eq!(session.persisted_entry_count, 2);

        let loaded =
            run_async(async { Session::open(path.to_string_lossy().as_ref()).await }).unwrap();
        assert_eq!(loaded.entries.len(), 2);
    }

    #[test]
    fn crash_durability_mode_parsing() {
        assert_eq!(
            AutosaveDurabilityMode::parse("strict"),
            Some(AutosaveDurabilityMode::Strict)
        );
        assert_eq!(
            AutosaveDurabilityMode::parse("BALANCED"),
            Some(AutosaveDurabilityMode::Balanced)
        );
        assert_eq!(
            AutosaveDurabilityMode::parse("  Throughput  "),
            Some(AutosaveDurabilityMode::Throughput)
        );
        assert_eq!(AutosaveDurabilityMode::parse("invalid"), None);
        assert_eq!(AutosaveDurabilityMode::parse(""), None);
    }

    #[test]
    fn crash_durability_resolve_precedence() {
        assert_eq!(
            resolve_autosave_durability_mode(Some("strict"), Some("balanced"), Some("throughput")),
            AutosaveDurabilityMode::Strict
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, Some("throughput"), Some("strict")),
            AutosaveDurabilityMode::Throughput
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, None, Some("strict")),
            AutosaveDurabilityMode::Strict
        );
        assert_eq!(
            resolve_autosave_durability_mode(None, None, None),
            AutosaveDurabilityMode::Balanced
        );
    }
}
