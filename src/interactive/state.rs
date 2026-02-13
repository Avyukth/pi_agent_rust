use std::collections::VecDeque;

use bubbles::list::{DefaultDelegate, Item as ListItem, List};

use crate::agent::QueueMode;
use crate::model::{ContentBlock, Message as ModelMessage};
use crate::models::OAuthConfig;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingLoginKind {
    OAuth,
    ApiKey,
}

#[derive(Debug, Clone)]
pub(super) struct PendingOAuth {
    pub(super) provider: String,
    pub(super) kind: PendingLoginKind,
    pub(super) verifier: String,
    /// OAuth config for extension-registered providers (None for built-in like anthropic).
    pub(super) oauth_config: Option<OAuthConfig>,
}

/// Tool output line count above which blocks auto-collapse.
pub(super) const TOOL_AUTO_COLLAPSE_THRESHOLD: usize = 20;
/// Number of preview lines to show when a tool block is collapsed.
pub(super) const TOOL_COLLAPSE_PREVIEW_LINES: usize = 5;

/// A message in the conversation history.
#[derive(Debug, Clone)]
pub struct ConversationMessage {
    pub role: MessageRole,
    pub content: String,
    pub thinking: Option<String>,
    /// Per-message collapse state for tool outputs.
    pub collapsed: bool,
}

impl ConversationMessage {
    /// Create a non-tool message (never collapsed).
    pub(super) const fn new(role: MessageRole, content: String, thinking: Option<String>) -> Self {
        Self {
            role,
            content,
            thinking,
            collapsed: false,
        }
    }

    /// Create a tool output message with auto-collapse for large outputs.
    pub(super) fn tool(content: String) -> Self {
        let line_count = memchr::memchr_iter(b'\n', content.as_bytes()).count() + 1;
        Self {
            role: MessageRole::Tool,
            content,
            thinking: None,
            collapsed: line_count > TOOL_AUTO_COLLAPSE_THRESHOLD,
        }
    }
}

/// Role of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    User,
    Assistant,
    Tool,
    System,
}

/// State of the agent processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Ready for input.
    Idle,
    /// Processing user request.
    Processing,
    /// Executing a tool.
    ToolRunning,
}

/// Input mode for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Single-line input mode (default).
    SingleLine,
    /// Multi-line input mode (activated with Shift+Enter or \).
    MultiLine,
}

#[derive(Debug, Clone)]
pub enum PendingInput {
    Text(String),
    Content(Vec<ContentBlock>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QueuedMessageKind {
    Steering,
    FollowUp,
}

#[derive(Debug)]
pub(super) struct InteractiveMessageQueue {
    pub(super) steering: VecDeque<String>,
    pub(super) follow_up: VecDeque<String>,
    steering_mode: QueueMode,
    follow_up_mode: QueueMode,
}

impl InteractiveMessageQueue {
    pub(super) const fn new(steering_mode: QueueMode, follow_up_mode: QueueMode) -> Self {
        Self {
            steering: VecDeque::new(),
            follow_up: VecDeque::new(),
            steering_mode,
            follow_up_mode,
        }
    }

    pub(super) const fn set_modes(&mut self, steering_mode: QueueMode, follow_up_mode: QueueMode) {
        self.steering_mode = steering_mode;
        self.follow_up_mode = follow_up_mode;
    }

    pub(super) fn push_steering(&mut self, text: String) {
        self.steering.push_back(text);
    }

    pub(super) fn push_follow_up(&mut self, text: String) {
        self.follow_up.push_back(text);
    }

    pub(super) fn pop_steering(&mut self) -> Vec<String> {
        self.pop_kind(QueuedMessageKind::Steering)
    }

    pub(super) fn pop_follow_up(&mut self) -> Vec<String> {
        self.pop_kind(QueuedMessageKind::FollowUp)
    }

    fn pop_kind(&mut self, kind: QueuedMessageKind) -> Vec<String> {
        let (queue, mode) = match kind {
            QueuedMessageKind::Steering => (&mut self.steering, self.steering_mode),
            QueuedMessageKind::FollowUp => (&mut self.follow_up, self.follow_up_mode),
        };
        match mode {
            QueueMode::All => queue.drain(..).collect(),
            QueueMode::OneAtATime => queue.pop_front().into_iter().collect(),
        }
    }

    pub(super) fn clear_all(&mut self) -> (Vec<String>, Vec<String>) {
        let steering = self.steering.drain(..).collect();
        let follow_up = self.follow_up.drain(..).collect();
        (steering, follow_up)
    }

    pub(super) fn steering_len(&self) -> usize {
        self.steering.len()
    }

    pub(super) fn follow_up_len(&self) -> usize {
        self.follow_up.len()
    }

    pub(super) fn steering_front(&self) -> Option<&String> {
        self.steering.front()
    }

    pub(super) fn follow_up_front(&self) -> Option<&String> {
        self.follow_up.front()
    }
}

#[derive(Debug)]
pub(super) struct InjectedMessageQueue {
    steering: VecDeque<ModelMessage>,
    follow_up: VecDeque<ModelMessage>,
    steering_mode: QueueMode,
    follow_up_mode: QueueMode,
}

impl InjectedMessageQueue {
    pub(super) const fn new(steering_mode: QueueMode, follow_up_mode: QueueMode) -> Self {
        Self {
            steering: VecDeque::new(),
            follow_up: VecDeque::new(),
            steering_mode,
            follow_up_mode,
        }
    }

    fn push_kind(&mut self, kind: QueuedMessageKind, message: ModelMessage) {
        match kind {
            QueuedMessageKind::Steering => self.steering.push_back(message),
            QueuedMessageKind::FollowUp => self.follow_up.push_back(message),
        }
    }

    pub(super) fn push_steering(&mut self, message: ModelMessage) {
        self.push_kind(QueuedMessageKind::Steering, message);
    }

    pub(super) fn push_follow_up(&mut self, message: ModelMessage) {
        self.push_kind(QueuedMessageKind::FollowUp, message);
    }

    fn pop_kind(&mut self, kind: QueuedMessageKind) -> Vec<ModelMessage> {
        let (queue, mode) = match kind {
            QueuedMessageKind::Steering => (&mut self.steering, self.steering_mode),
            QueuedMessageKind::FollowUp => (&mut self.follow_up, self.follow_up_mode),
        };
        match mode {
            QueueMode::All => queue.drain(..).collect(),
            QueueMode::OneAtATime => queue.pop_front().into_iter().collect(),
        }
    }

    pub(super) fn pop_steering(&mut self) -> Vec<ModelMessage> {
        self.pop_kind(QueuedMessageKind::Steering)
    }

    pub(super) fn pop_follow_up(&mut self) -> Vec<ModelMessage> {
        self.pop_kind(QueuedMessageKind::FollowUp)
    }
}

#[derive(Debug, Clone)]
pub(super) struct HistoryItem {
    pub(super) value: String,
}

impl ListItem for HistoryItem {
    fn filter_value(&self) -> &str {
        &self.value
    }
}

#[derive(Clone)]
pub(super) struct HistoryList {
    // We never render the list UI; we use it as a battle-tested cursor+navigation model.
    // The final item is always a sentinel representing "empty input".
    list: List<HistoryItem, DefaultDelegate>,
}

impl HistoryList {
    pub(super) fn new() -> Self {
        let mut list = List::new(
            vec![HistoryItem {
                value: String::new(),
            }],
            DefaultDelegate::new(),
            0,
            0,
        );

        // Keep behavior minimal/predictable for now; this is used as an index model.
        list.filtering_enabled = false;
        list.infinite_scrolling = false;

        // Start at the "empty input" sentinel.
        list.select(0);

        Self { list }
    }

    pub(super) fn entries(&self) -> &[HistoryItem] {
        let items = self.list.items();
        if items.len() <= 1 {
            return &[];
        }
        &items[..items.len().saturating_sub(1)]
    }

    pub(super) fn has_entries(&self) -> bool {
        !self.entries().is_empty()
    }

    pub(super) fn cursor_is_empty(&self) -> bool {
        // Sentinel is always the final item.
        self.list.index() + 1 == self.list.items().len()
    }

    pub(super) fn reset_cursor(&mut self) {
        let last = self.list.items().len().saturating_sub(1);
        self.list.select(last);
    }

    pub(super) fn push(&mut self, value: String) {
        let mut items = self.entries().to_vec();
        items.push(HistoryItem { value });
        items.push(HistoryItem {
            value: String::new(),
        });

        self.list.set_items(items);
        self.reset_cursor();
    }

    pub(super) fn cursor_up(&mut self) {
        self.list.cursor_up();
    }

    pub(super) fn cursor_down(&mut self) {
        self.list.cursor_down();
    }

    pub(super) fn selected_value(&self) -> &str {
        self.list
            .selected_item()
            .map_or("", |item| item.value.as_str())
    }
}

/// Progress metrics emitted by long-running tools (e.g. bash).
#[derive(Debug, Clone)]
pub(super) struct ToolProgress {
    pub(super) started_at: std::time::Instant,
    pub(super) elapsed_ms: u128,
    pub(super) line_count: usize,
    pub(super) byte_count: usize,
    pub(super) timeout_ms: Option<u64>,
}

impl ToolProgress {
    pub(super) fn new() -> Self {
        Self {
            started_at: std::time::Instant::now(),
            elapsed_ms: 0,
            line_count: 0,
            byte_count: 0,
            timeout_ms: None,
        }
    }

    /// Update from a `details.progress` JSON object emitted by tool callbacks.
    pub(super) fn update_from_details(&mut self, details: Option<&Value>) {
        // Always update elapsed from wall clock as fallback.
        self.elapsed_ms = self.started_at.elapsed().as_millis();

        let Some(details) = details else {
            return;
        };
        if let Some(progress) = details.get("progress") {
            if let Some(v) = progress.get("elapsedMs").and_then(Value::as_u64) {
                self.elapsed_ms = u128::from(v);
            }
            if let Some(v) = progress.get("lineCount").and_then(Value::as_u64) {
                #[allow(clippy::cast_possible_truncation)]
                let count = v as usize;
                self.line_count = count;
            }
            if let Some(v) = progress.get("byteCount").and_then(Value::as_u64) {
                #[allow(clippy::cast_possible_truncation)]
                let count = v as usize;
                self.byte_count = count;
            }
            if let Some(v) = progress.get("timeoutMs").and_then(Value::as_u64) {
                self.timeout_ms = Some(v);
            }
        }
    }

    /// Format a compact status string like `"Running bash · 3s · 42 lines"`.
    pub(super) fn format_display(&self, tool_name: &str) -> String {
        let secs = self.elapsed_ms / 1000;
        let mut parts = vec![format!("Running {tool_name}"), format!("{secs}s")];
        if self.line_count > 0 {
            parts.push(format!("{} lines", format_count(self.line_count)));
        } else if self.byte_count > 0 {
            parts.push(format!("{} bytes", format_count(self.byte_count)));
        }
        if let Some(timeout_ms) = self.timeout_ms {
            let timeout_s = timeout_ms / 1000;
            if timeout_s > 0 {
                parts.push(format!("timeout {timeout_s}s"));
            }
        }
        parts.join(" \u{2022} ")
    }
}

/// Format a count with K/M suffix for compact display.
#[allow(clippy::cast_precision_loss)]
pub(super) fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
