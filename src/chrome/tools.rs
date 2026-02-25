//! Chrome browser tool implementations.
//!
//! Observation tools (bd-3mf.7.3):
//! - `ObserveTool`: register a new observer on a tab
//! - `UnobserveTool`: remove an observer by ID
//! - `ObserversTool`: list all active observers (read-only)
//!
//! Navigation tools — Wave 2A (bd-3mf.1):
//! - `NavigateTool`: navigate to URL or back/forward/reload
//! - `TabsCreateTool`: create a new browser tab
//! - `TabsContextTool`: list all tabs (read-only)
//! - `SwitchBrowserTool`: switch active browser
//!
//! Reading tools — Wave 2B (bd-3mf.2):
//! - `ReadPageTool`: read a11y tree from a page (read-only)
//! - `GetPageTextTool`: extract raw text content (read-only)
//! - `FindTool`: search for elements on a page (read-only)
//!
//! Interaction tools — Wave 2C (bd-3mf.3):
//! - `ComputerTool`: 13 sub-actions (click, type, scroll, screenshot, etc.)
//! - `FormInputTool`: set form element value by ref_id
//!
//! Capture + DevTools tools — Wave 2D (bd-3mf.4):
//! - `ScreenshotTool`: capture visible tab as PNG base64
//! - `GifCreatorTool`: Phase 3 stub
//! - `JavascriptTool`: execute arbitrary JS
//! - `ReadConsoleTool`: read console output (read-only)
//! - `ReadNetworkTool`: read network requests (read-only)
//!
//! Window + Shortcuts + Media tools — Wave 2E (bd-3mf.5):
//! - `ResizeWindowTool`: resize browser viewport
//! - `ShortcutsExecuteTool`: dispatch keyboard shortcut
//! - `ShortcutsListTool`: list available shortcuts (read-only)
//! - `UploadImageTool`: upload image to file input

// All Tool trait impls return `&'static str` from name/label/description but the
// trait signature uses `&str` tied to `&self`. Clippy flags this as
// `unnecessary_literal_bound` but the signature is trait-constrained.
#![allow(clippy::unnecessary_literal_bound)]

use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use serde::Deserialize;

use crate::error::Result;
use crate::model::{ContentBlock, TextContent};
use crate::tools::{Tool, ToolOutput, ToolUpdate};

use super::ChromeBridge;
use super::observer::{ObservableEventKind, ObserverRegistry, THROTTLE_FLOOR_MS};

// ============================================================================
// Input Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct ObserveInput {
    /// Unique observer identifier.
    observer_id: String,
    /// Tab ID to observe.
    tab_id: u32,
    /// Event kinds to subscribe to.
    events: Vec<String>,
    /// Throttle interval in milliseconds (clamped to >= 500ms).
    throttle_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UnobserveInput {
    /// Observer ID to remove.
    observer_id: String,
}

// ============================================================================
// ObserveTool
// ============================================================================

/// Register a new live page observer on a tab.
///
/// Creates an observer in the local ObserverRegistry with the specified
/// event subscriptions and throttle interval. The throttle is clamped to
/// a minimum of 500ms (THROTTLE_FLOOR_MS).
pub struct ObserveTool {
    registry: Arc<StdMutex<ObserverRegistry>>,
}

impl ObserveTool {
    pub const fn new(registry: Arc<StdMutex<ObserverRegistry>>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for ObserveTool {
    fn name(&self) -> &str {
        "observe"
    }

    fn label(&self) -> &str {
        "observe"
    }

    fn description(&self) -> &str {
        "Register a live page observer on a browser tab. Subscribes to specified event kinds \
         (console_error, console_warn, network_error, dom_mutation, navigation, load_complete). \
         Events are collected with a configurable throttle interval (minimum 500ms)."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "observer_id": {
                    "type": "string",
                    "description": "Unique identifier for this observer"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Chrome tab ID to observe"
                },
                "events": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "console_error",
                            "console_warn",
                            "network_error",
                            "dom_mutation",
                            "navigation",
                            "load_complete"
                        ]
                    },
                    "description": "Event kinds to subscribe to"
                },
                "throttle_ms": {
                    "type": "integer",
                    "description": "Throttle interval in milliseconds (minimum 500ms, default 500ms)"
                }
            },
            "required": ["observer_id", "tab_id", "events"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: ObserveInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "observe".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        // Validate observer_id is not empty
        if input.observer_id.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: observer_id must not be empty",
                ))],
                details: None,
                is_error: true,
            });
        }

        // Validate events are not empty
        if input.events.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: events must contain at least one event kind",
                ))],
                details: None,
                is_error: true,
            });
        }

        // Parse event kind strings into ObservableEventKind enum values
        let mut event_kinds = Vec::with_capacity(input.events.len());
        for event_str in &input.events {
            match parse_event_kind(event_str) {
                Some(kind) => event_kinds.push(kind),
                None => {
                    return Ok(ToolOutput {
                        content: vec![ContentBlock::Text(TextContent::new(format!(
                            "Error: unknown event kind '{event_str}'. Valid kinds: \
                                 console_error, console_warn, network_error, \
                                 dom_mutation, navigation, load_complete"
                        )))],
                        details: None,
                        is_error: true,
                    });
                }
            }
        }

        // Clamp throttle to floor
        let effective_throttle = input
            .throttle_ms
            .unwrap_or(THROTTLE_FLOOR_MS)
            .max(THROTTLE_FLOOR_MS);

        // Register in ObserverRegistry
        let mut registry = self
            .registry
            .lock()
            .expect("observer registry mutex poisoned");
        if let Err(e) = registry.observe(
            input.observer_id.clone(),
            input.tab_id,
            event_kinds.clone(),
            effective_throttle,
        ) {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(format!("Error: {e}")))],
                details: None,
                is_error: true,
            });
        }
        drop(registry);

        let event_names: Vec<&str> = event_kinds.iter().map(|k| event_kind_str(*k)).collect();
        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent::new(format!(
                "Observer '{}' registered on tab {} for events [{}] with throttle {}ms",
                input.observer_id,
                input.tab_id,
                event_names.join(", "),
                effective_throttle,
            )))],
            details: Some(serde_json::json!({
                "observer_id": input.observer_id,
                "tab_id": input.tab_id,
                "events": event_names,
                "throttle_ms": effective_throttle,
            })),
            is_error: false,
        })
    }
}

// ============================================================================
// UnobserveTool
// ============================================================================

/// Remove a live page observer by ID.
///
/// Removes the observer from the local ObserverRegistry and returns
/// information about the removed observer.
pub struct UnobserveTool {
    registry: Arc<StdMutex<ObserverRegistry>>,
}

impl UnobserveTool {
    pub const fn new(registry: Arc<StdMutex<ObserverRegistry>>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for UnobserveTool {
    fn name(&self) -> &str {
        "unobserve"
    }

    fn label(&self) -> &str {
        "unobserve"
    }

    fn description(&self) -> &str {
        "Remove a live page observer by its ID. Stops event collection for that observer."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "observer_id": {
                    "type": "string",
                    "description": "ID of the observer to remove"
                }
            },
            "required": ["observer_id"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: UnobserveInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "unobserve".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        if input.observer_id.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: observer_id must not be empty",
                ))],
                details: None,
                is_error: true,
            });
        }

        let mut registry = self
            .registry
            .lock()
            .expect("observer registry mutex poisoned");
        match registry.unobserve(&input.observer_id) {
            Ok(observer) => Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(format!(
                    "Observer '{}' removed (tab {}, {} total events)",
                    observer.id, observer.tab_id, observer.total_events,
                )))],
                details: Some(serde_json::json!({
                    "observer_id": observer.id,
                    "tab_id": observer.tab_id,
                    "total_events": observer.total_events,
                    "removed": true,
                })),
                is_error: false,
            }),
            Err(e) => Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(format!("Error: {e}")))],
                details: None,
                is_error: true,
            }),
        }
    }
}

// ============================================================================
// ObserversTool
// ============================================================================

/// List all active observers with their status.
///
/// Read-only tool that returns information about each active observer
/// including event subscriptions, throttle settings, and event counts.
pub struct ObserversTool {
    registry: Arc<StdMutex<ObserverRegistry>>,
}

impl ObserversTool {
    pub const fn new(registry: Arc<StdMutex<ObserverRegistry>>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Tool for ObserversTool {
    fn name(&self) -> &str {
        "observers"
    }

    fn label(&self) -> &str {
        "observers"
    }

    fn description(&self) -> &str {
        "List all active live page observers with their status, event subscriptions, and counts."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        _input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let observers = self
            .registry
            .lock()
            .expect("observer registry mutex poisoned")
            .list();

        if observers.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new("No active observers."))],
                details: Some(serde_json::json!({
                    "observers": [],
                    "count": 0,
                })),
                is_error: false,
            });
        }

        let mut lines = Vec::with_capacity(observers.len() + 1);
        lines.push(format!("{} active observer(s):", observers.len()));

        for obs in &observers {
            let event_names: Vec<&str> = obs.events.iter().map(|k| event_kind_str(*k)).collect();
            lines.push(format!(
                "  - {} (tab {}, events=[{}], throttle={}ms, pending={}, total={})",
                obs.id,
                obs.tab_id,
                event_names.join(", "),
                obs.throttle_ms,
                obs.pending_count,
                obs.total_events,
            ));
        }

        let details: Vec<serde_json::Value> = observers
            .iter()
            .map(|obs| {
                serde_json::json!({
                    "id": obs.id,
                    "tab_id": obs.tab_id,
                    "events": obs.events.iter().map(|k| event_kind_str(*k)).collect::<Vec<_>>(),
                    "throttle_ms": obs.throttle_ms,
                    "pending_count": obs.pending_count,
                    "total_events": obs.total_events,
                })
            })
            .collect();

        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent::new(lines.join("\n")))],
            details: Some(serde_json::json!({
                "observers": details,
                "count": observers.len(),
            })),
            is_error: false,
        })
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Parse a string into an ObservableEventKind.
fn parse_event_kind(s: &str) -> Option<ObservableEventKind> {
    match s {
        "console_error" => Some(ObservableEventKind::ConsoleError),
        "console_warn" => Some(ObservableEventKind::ConsoleWarn),
        "network_error" => Some(ObservableEventKind::NetworkError),
        "dom_mutation" => Some(ObservableEventKind::DomMutation),
        "navigation" => Some(ObservableEventKind::Navigation),
        "load_complete" => Some(ObservableEventKind::LoadComplete),
        _ => None,
    }
}

/// Convert an ObservableEventKind to its wire string.
const fn event_kind_str(kind: ObservableEventKind) -> &'static str {
    match kind {
        ObservableEventKind::ConsoleError => "console_error",
        ObservableEventKind::ConsoleWarn => "console_warn",
        ObservableEventKind::NetworkError => "network_error",
        ObservableEventKind::DomMutation => "dom_mutation",
        ObservableEventKind::Navigation => "navigation",
        ObservableEventKind::LoadComplete => "load_complete",
    }
}

// ============================================================================
// Browser Tool Input Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct NavigateInput {
    url: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TabsCreateInput {
    url: Option<String>,
    active: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ReadPageInput {
    tab_id: Option<u32>,
    max_depth: Option<u32>,
    max_nodes: Option<u32>,
    filter: Option<String>,
    ref_id: Option<u32>,
    max_chars: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct GetPageTextInput {
    tab_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct FindInput {
    query: String,
    tab_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SwitchBrowserInput {
    browser: Option<String>,
}

// --- Wave 2C: Interaction tools ---

#[derive(Debug, Deserialize)]
struct ComputerInput {
    tab_id: Option<u32>,
    action: String,
    coordinate: Option<Vec<i32>>,
    #[serde(alias = "refId")]
    ref_id: Option<u32>,
    text: Option<String>,
    region: Option<String>,
    duration: Option<u32>,
    scroll_direction: Option<String>,
    scroll_amount: Option<u32>,
    repeat: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct FormInputInput {
    tab_id: Option<u32>,
    #[serde(alias = "refId")]
    ref_id: u32,
    value: String,
}

// --- Wave 2D: Capture + DevTools tools ---

#[derive(Debug, Deserialize)]
struct ScreenshotInput {
    selector: Option<String>,
    tab_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct GifCreatorInput {
    duration_ms: Option<u32>,
    tab_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct JavascriptInput {
    code: String,
    tab_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ReadConsoleInput {
    pattern: Option<String>,
    tab_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ReadNetworkInput {
    pattern: Option<String>,
    tab_id: Option<u32>,
}

// --- Wave 2E: Window + Shortcuts + Media tools ---

#[derive(Debug, Deserialize)]
struct ResizeWindowInput {
    width: u32,
    height: u32,
    tab_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ShortcutsExecuteInput {
    shortcut: String,
}

#[derive(Debug, Deserialize)]
struct UploadImageInput {
    file_path: String,
    selector: String,
    tab_id: Option<u32>,
}

// ============================================================================
// Bridge Request Helper
// ============================================================================

/// Send a tool request through the ChromeBridge and return the response as ToolOutput.
///
/// Returns a "not connected" error if the bridge is disconnected or the request
/// method is not yet wired (pending bd-18m.2.1 native host relay completion).
fn bridge_not_connected_error(tool_name: &str) -> ToolOutput {
    ToolOutput {
        content: vec![ContentBlock::Text(TextContent::new(format!(
            "Error: browser tools not available — ChromeBridge is not connected. \
             Use --setup-chrome and ensure the Chrome extension is running. (tool: {tool_name})"
        )))],
        details: None,
        is_error: true,
    }
}

// ============================================================================
// NavigateTool — Wave 2A
// ============================================================================

/// Navigate to a URL or perform back/forward/reload.
///
/// When `url` is provided, navigates the active tab to that URL.
/// When `action` is provided ("back", "forward", "reload"), performs that action.
pub struct NavigateTool {
    bridge: Arc<ChromeBridge>,
}

impl NavigateTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for NavigateTool {
    fn name(&self) -> &str {
        "navigate"
    }

    fn label(&self) -> &str {
        "navigate"
    }

    fn description(&self) -> &str {
        "Navigate to a URL or perform browser navigation (back, forward, reload). \
         Provide `url` to navigate to a page, or `action` for history navigation."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to navigate to"
                },
                "action": {
                    "type": "string",
                    "enum": ["back", "forward", "reload"],
                    "description": "Navigation action (alternative to url)"
                }
            }
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: NavigateInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "navigate".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        // Must provide either url or action
        if input.url.is_none() && input.action.is_none() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: must provide either 'url' or 'action' (back/forward/reload)",
                ))],
                details: None,
                is_error: true,
            });
        }

        // Validate action if provided
        if let Some(ref action) = input.action {
            match action.as_str() {
                "back" | "forward" | "reload" => {}
                other => {
                    return Ok(ToolOutput {
                        content: vec![ContentBlock::Text(TextContent::new(format!(
                            "Error: invalid action '{other}'. Must be one of: back, forward, reload"
                        )))],
                        details: None,
                        is_error: true,
                    });
                }
            }
        }

        // Validate URL if provided
        if let Some(ref url) = input.url {
            if url.is_empty() {
                return Ok(ToolOutput {
                    content: vec![ContentBlock::Text(TextContent::new(
                        "Error: url must not be empty",
                    ))],
                    details: None,
                    is_error: true,
                });
            }
        }

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("navigate"))
    }
}

// ============================================================================
// TabsCreateTool — Wave 2A
// ============================================================================

/// Create a new browser tab.
///
/// Optionally navigates the new tab to a URL and controls whether it becomes active.
pub struct TabsCreateTool {
    bridge: Arc<ChromeBridge>,
}

impl TabsCreateTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for TabsCreateTool {
    fn name(&self) -> &str {
        "tabs_create"
    }

    fn label(&self) -> &str {
        "tabs_create"
    }

    fn description(&self) -> &str {
        "Create a new browser tab. Optionally specify a URL and whether the tab should be active."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to open in the new tab"
                },
                "active": {
                    "type": "boolean",
                    "description": "Whether the new tab should be active (focused)"
                }
            }
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: TabsCreateInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "tabs_create".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("tabs_create"))
    }
}

// ============================================================================
// TabsContextTool — Wave 2A
// ============================================================================

/// List all browser tabs in Pi's tab group.
///
/// Returns an array of tab information including IDs, URLs, and titles.
/// This is a read-only tool that does not modify browser state.
pub struct TabsContextTool {
    bridge: Arc<ChromeBridge>,
}

impl TabsContextTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for TabsContextTool {
    fn name(&self) -> &str {
        "tabs_context"
    }

    fn label(&self) -> &str {
        "tabs_context"
    }

    fn description(&self) -> &str {
        "List all browser tabs with their IDs, URLs, and titles. Use this to discover available \
         tabs before interacting with them."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        _input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("tabs_context"))
    }
}

// ============================================================================
// SwitchBrowserTool — Wave 2A
// ============================================================================

/// Switch to a different browser.
///
/// Phase 3 placeholder — currently returns a not-implemented error.
pub struct SwitchBrowserTool {
    bridge: Arc<ChromeBridge>,
}

impl SwitchBrowserTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for SwitchBrowserTool {
    fn name(&self) -> &str {
        "switch_browser"
    }

    fn label(&self) -> &str {
        "switch_browser"
    }

    fn description(&self) -> &str {
        "Switch to a different browser. Currently supports Chrome only."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "browser": {
                    "type": "string",
                    "description": "Browser name to switch to"
                }
            }
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: SwitchBrowserInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "switch_browser".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent::new(
                "Error: switch_browser is not yet implemented (Phase 3)",
            ))],
            details: None,
            is_error: true,
        })
    }
}

// ============================================================================
// ReadPageTool — Wave 2B
// ============================================================================

/// Read the accessibility tree from a browser tab.
///
/// Returns a structured a11y tree with element roles, names, text content,
/// and reference IDs for interactive elements. This is the primary tool
/// the agent uses to "see" page content.
pub struct ReadPageTool {
    bridge: Arc<ChromeBridge>,
}

impl ReadPageTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ReadPageTool {
    fn name(&self) -> &str {
        "read_page"
    }

    fn label(&self) -> &str {
        "read_page"
    }

    fn description(&self) -> &str {
        "Read the accessibility tree from a browser tab. Returns element roles, names, \
         text content, and reference IDs for interactive elements. Use filter/ref_id \
         to narrow the scope, max_chars to limit output size."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID to read (defaults to active tab)"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum tree depth to traverse (default 15)"
                },
                "max_nodes": {
                    "type": "integer",
                    "description": "Maximum number of nodes to include"
                },
                "filter": {
                    "type": "string",
                    "description": "CSS selector to narrow the tree root"
                },
                "ref_id": {
                    "type": "integer",
                    "description": "Focus on a specific element reference subtree"
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Limit output character count"
                }
            }
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: ReadPageInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "read_page".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("read_page"))
    }
}

// ============================================================================
// GetPageTextTool — Wave 2B
// ============================================================================

/// Extract raw text content from a browser tab.
///
/// Returns the innerText of the page, which is useful for simple text extraction
/// without the full a11y tree structure.
pub struct GetPageTextTool {
    bridge: Arc<ChromeBridge>,
}

impl GetPageTextTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for GetPageTextTool {
    fn name(&self) -> &str {
        "get_page_text"
    }

    fn label(&self) -> &str {
        "get_page_text"
    }

    fn description(&self) -> &str {
        "Extract raw text content (innerText) from a browser tab. Simpler than read_page \
         when you only need the text without accessibility tree structure."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID to read (defaults to active tab)"
                }
            }
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: GetPageTextInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "get_page_text".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("get_page_text"))
    }
}

// ============================================================================
// FindTool — Wave 2B
// ============================================================================

/// Search for elements on a page by text or CSS selector.
///
/// Returns matching elements with their reference IDs, which can be used
/// with interaction tools (click, form_input, etc.).
pub struct FindTool {
    bridge: Arc<ChromeBridge>,
}

impl FindTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for FindTool {
    fn name(&self) -> &str {
        "find"
    }

    fn label(&self) -> &str {
        "find"
    }

    fn description(&self) -> &str {
        "Search for elements on a page by text content or CSS selector. Returns matching \
         elements with reference IDs for subsequent interaction."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Text to search for or CSS selector"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID to search in (defaults to active tab)"
                }
            },
            "required": ["query"]
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: FindInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "find".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        if input.query.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: query must not be empty",
                ))],
                details: None,
                is_error: true,
            });
        }

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("find"))
    }
}

// ============================================================================
// ComputerTool — Wave 2C
// ============================================================================

/// Valid ComputerTool actions.
const COMPUTER_ACTIONS: &[&str] = &[
    "left_click",
    "right_click",
    "double_click",
    "triple_click",
    "type",
    "key",
    "scroll",
    "scroll_to",
    "hover",
    "left_click_drag",
    "screenshot",
    "zoom",
    "wait",
];

/// Actions that require a coordinate [x, y].
const COORDINATE_ACTIONS: &[&str] = &[
    "left_click",
    "right_click",
    "double_click",
    "triple_click",
    "hover",
    "left_click_drag",
    "scroll_to",
];

/// Actions that require text input.
const TEXT_ACTIONS: &[&str] = &["type", "key"];

/// Interact with the browser page via mouse, keyboard, or screen actions.
///
/// Supports 13 sub-actions: click variants, type/key, scroll, hover, drag,
/// screenshot, zoom, and wait. Each action has specific parameter requirements.
pub struct ComputerTool {
    bridge: Arc<ChromeBridge>,
}

impl ComputerTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ComputerTool {
    fn name(&self) -> &str {
        "computer"
    }

    fn label(&self) -> &str {
        "computer"
    }

    fn description(&self) -> &str {
        "Interact with the browser page. Actions: left_click, right_click, double_click, \
         triple_click, type, key, scroll, scroll_to, hover, left_click_drag, screenshot, \
         zoom, wait. Click/hover actions require coordinate [x,y] or refId. Type/key \
         actions require text."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                },
                "action": {
                    "type": "string",
                    "enum": COMPUTER_ACTIONS,
                    "description": "Action to perform"
                },
                "coordinate": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "minItems": 2,
                    "maxItems": 2,
                    "description": "Target [x, y] coordinate for click/hover/drag actions"
                },
                "refId": {
                    "type": "integer",
                    "description": "Element reference ID (alternative to coordinate)"
                },
                "text": {
                    "type": "string",
                    "description": "Text to type or key combo to press"
                },
                "region": {
                    "type": "string",
                    "description": "Region for zoom action"
                },
                "duration": {
                    "type": "integer",
                    "description": "Duration in ms for wait/zoom actions"
                },
                "scroll_direction": {
                    "type": "string",
                    "enum": ["up", "down", "left", "right"],
                    "description": "Direction for scroll action"
                },
                "scroll_amount": {
                    "type": "integer",
                    "description": "Scroll amount in pixels"
                },
                "repeat": {
                    "type": "integer",
                    "description": "Number of times to repeat the action"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: ComputerInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "computer".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        // Validate action
        if !COMPUTER_ACTIONS.contains(&input.action.as_str()) {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(format!(
                    "Error: invalid action '{}'. Must be one of: {}",
                    input.action,
                    COMPUTER_ACTIONS.join(", ")
                )))],
                details: None,
                is_error: true,
            });
        }

        // Validate coordinate requirement
        if COORDINATE_ACTIONS.contains(&input.action.as_str())
            && input.coordinate.is_none()
            && input.ref_id.is_none()
        {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(format!(
                    "Error: action '{}' requires 'coordinate' [x,y] or 'refId'",
                    input.action
                )))],
                details: None,
                is_error: true,
            });
        }

        // Validate coordinate format (must be [x, y])
        if let Some(ref coord) = input.coordinate {
            if coord.len() != 2 {
                return Ok(ToolOutput {
                    content: vec![ContentBlock::Text(TextContent::new(
                        "Error: coordinate must be [x, y] (exactly 2 integers)",
                    ))],
                    details: None,
                    is_error: true,
                });
            }
        }

        // Validate text requirement
        if TEXT_ACTIONS.contains(&input.action.as_str()) && input.text.is_none() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(format!(
                    "Error: action '{}' requires 'text'",
                    input.action
                )))],
                details: None,
                is_error: true,
            });
        }

        // Validate scroll direction
        if input.action == "scroll" {
            if let Some(ref dir) = input.scroll_direction {
                match dir.as_str() {
                    "up" | "down" | "left" | "right" => {}
                    other => {
                        return Ok(ToolOutput {
                            content: vec![ContentBlock::Text(TextContent::new(format!(
                                "Error: invalid scroll_direction '{other}'. \
                                 Must be: up, down, left, right"
                            )))],
                            details: None,
                            is_error: true,
                        });
                    }
                }
            }
        }

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("computer"))
    }
}

// ============================================================================
// FormInputTool — Wave 2C
// ============================================================================

/// Set a form element's value by reference ID.
///
/// Uses the ref_id from read_page/find results to target a specific form element.
pub struct FormInputTool {
    bridge: Arc<ChromeBridge>,
}

impl FormInputTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for FormInputTool {
    fn name(&self) -> &str {
        "form_input"
    }

    fn label(&self) -> &str {
        "form_input"
    }

    fn description(&self) -> &str {
        "Set the value of a form element (input, textarea, select) by its reference ID. \
         Use read_page or find first to discover the ref_id."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                },
                "refId": {
                    "type": "integer",
                    "description": "Element reference ID from read_page/find"
                },
                "value": {
                    "type": "string",
                    "description": "Value to set on the form element"
                }
            },
            "required": ["refId", "value"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: FormInputInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "form_input".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("form_input"))
    }
}

// ============================================================================
// ScreenshotTool — Wave 2D
// ============================================================================

/// Capture a screenshot of the visible browser tab.
///
/// Returns a PNG base64-encoded image. Optionally crop to a CSS selector region.
pub struct ScreenshotTool {
    bridge: Arc<ChromeBridge>,
}

impl ScreenshotTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ScreenshotTool {
    fn name(&self) -> &str {
        "screenshot"
    }

    fn label(&self) -> &str {
        "screenshot"
    }

    fn description(&self) -> &str {
        "Capture a screenshot of the visible browser tab as PNG base64. \
         Optionally specify a CSS selector to crop to a specific element."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "description": "CSS selector to crop the screenshot to"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                }
            }
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: ScreenshotInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "screenshot".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("screenshot"))
    }
}

// ============================================================================
// GifCreatorTool — Wave 2D (Phase 3 stub)
// ============================================================================

/// Record a GIF of the browser tab.
///
/// Phase 3 placeholder — returns a "not yet available" error.
pub struct GifCreatorTool {
    bridge: Arc<ChromeBridge>,
}

impl GifCreatorTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for GifCreatorTool {
    fn name(&self) -> &str {
        "gif_creator"
    }

    fn label(&self) -> &str {
        "gif_creator"
    }

    fn description(&self) -> &str {
        "Record a GIF of the browser tab (not yet available — Phase 3)."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "duration_ms": {
                    "type": "integer",
                    "description": "Recording duration in milliseconds"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                }
            }
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: GifCreatorInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "gif_creator".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent::new(
                "Error: GIF encoding is not yet available (Phase 3)",
            ))],
            details: None,
            is_error: true,
        })
    }
}

// ============================================================================
// JavascriptTool — Wave 2D
// ============================================================================

/// Execute arbitrary JavaScript in a browser tab.
///
/// Uses chrome.scripting.executeScript. Non-idempotent — arbitrary JS can
/// have side effects.
pub struct JavascriptTool {
    bridge: Arc<ChromeBridge>,
}

impl JavascriptTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for JavascriptTool {
    fn name(&self) -> &str {
        "javascript"
    }

    fn label(&self) -> &str {
        "javascript"
    }

    fn description(&self) -> &str {
        "Execute JavaScript code in a browser tab. Returns the evaluation result. \
         Use for custom page interactions, data extraction, or DOM manipulation."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "JavaScript code to execute"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                }
            },
            "required": ["code"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: JavascriptInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "javascript".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        if input.code.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: code must not be empty",
                ))],
                details: None,
                is_error: true,
            });
        }

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("javascript"))
    }
}

// ============================================================================
// ReadConsoleTool — Wave 2D
// ============================================================================

/// Read console output from a browser tab.
///
/// Returns console messages optionally filtered by a regex pattern. Read-only.
pub struct ReadConsoleTool {
    bridge: Arc<ChromeBridge>,
}

impl ReadConsoleTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ReadConsoleTool {
    fn name(&self) -> &str {
        "read_console_messages"
    }

    fn label(&self) -> &str {
        "read_console_messages"
    }

    fn description(&self) -> &str {
        "Read console output from a browser tab. Optionally filter by a regex pattern. \
         Useful for debugging and verifying application behavior."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to filter console messages"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                }
            }
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: ReadConsoleInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "read_console_messages".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("read_console_messages"))
    }
}

// ============================================================================
// ReadNetworkTool — Wave 2D
// ============================================================================

/// Read network request metadata from a browser tab.
///
/// Returns XHR/Fetch request info optionally filtered by URL regex. Read-only.
pub struct ReadNetworkTool {
    bridge: Arc<ChromeBridge>,
}

impl ReadNetworkTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ReadNetworkTool {
    fn name(&self) -> &str {
        "read_network_requests"
    }

    fn label(&self) -> &str {
        "read_network_requests"
    }

    fn description(&self) -> &str {
        "Read network request metadata (XHR/Fetch) from a browser tab. Optionally filter \
         by a URL regex pattern. Returns method, URL, status, and timing info."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to filter by request URL"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                }
            }
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _input: ReadNetworkInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "read_network_requests".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("read_network_requests"))
    }
}

// ============================================================================
// ResizeWindowTool — Wave 2E
// ============================================================================

/// Resize the browser viewport.
///
/// Sets the browser window dimensions to the specified width and height.
pub struct ResizeWindowTool {
    bridge: Arc<ChromeBridge>,
}

impl ResizeWindowTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ResizeWindowTool {
    fn name(&self) -> &str {
        "resize_window"
    }

    fn label(&self) -> &str {
        "resize_window"
    }

    fn description(&self) -> &str {
        "Resize the browser viewport to specified dimensions."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "width": {
                    "type": "integer",
                    "description": "Viewport width in pixels",
                    "minimum": 100
                },
                "height": {
                    "type": "integer",
                    "description": "Viewport height in pixels",
                    "minimum": 100
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                }
            },
            "required": ["width", "height"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: ResizeWindowInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "resize_window".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        if input.width < 100 || input.height < 100 {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: width and height must be at least 100 pixels",
                ))],
                details: None,
                is_error: true,
            });
        }

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("resize_window"))
    }
}

// ============================================================================
// ShortcutsExecuteTool — Wave 2E
// ============================================================================

/// Dispatch a keyboard shortcut.
///
/// Sends a key combination to the active page via content script injection.
pub struct ShortcutsExecuteTool {
    bridge: Arc<ChromeBridge>,
}

impl ShortcutsExecuteTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ShortcutsExecuteTool {
    fn name(&self) -> &str {
        "shortcuts_execute"
    }

    fn label(&self) -> &str {
        "shortcuts_execute"
    }

    fn description(&self) -> &str {
        "Execute a keyboard shortcut in the browser. Specify the key combination \
         (e.g. 'Ctrl+C', 'Alt+Tab', 'Enter')."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "shortcut": {
                    "type": "string",
                    "description": "Key combination to execute (e.g. 'Ctrl+C', 'Enter')"
                }
            },
            "required": ["shortcut"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: ShortcutsExecuteInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "shortcuts_execute".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        if input.shortcut.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: shortcut must not be empty",
                ))],
                details: None,
                is_error: true,
            });
        }

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("shortcuts_execute"))
    }
}

// ============================================================================
// ShortcutsListTool — Wave 2E
// ============================================================================

/// List available keyboard shortcuts.
///
/// Returns the list of shortcuts registered via chrome.commands. Read-only.
pub struct ShortcutsListTool {
    bridge: Arc<ChromeBridge>,
}

impl ShortcutsListTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for ShortcutsListTool {
    fn name(&self) -> &str {
        "shortcuts_list"
    }

    fn label(&self) -> &str {
        "shortcuts_list"
    }

    fn description(&self) -> &str {
        "List available browser keyboard shortcuts registered via chrome.commands."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        _input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("shortcuts_list"))
    }
}

// ============================================================================
// UploadImageTool — Wave 2E
// ============================================================================

/// Upload an image to a file input element.
///
/// Creates a DataTransfer with the image file and dispatches it to the
/// targeted file input element via CSS selector.
pub struct UploadImageTool {
    bridge: Arc<ChromeBridge>,
}

impl UploadImageTool {
    pub const fn new(bridge: Arc<ChromeBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for UploadImageTool {
    fn name(&self) -> &str {
        "upload_image"
    }

    fn label(&self) -> &str {
        "upload_image"
    }

    fn description(&self) -> &str {
        "Upload an image to a file input element. Specify the file path and a CSS \
         selector targeting the file input."
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the image file to upload"
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector targeting the file input element"
                },
                "tab_id": {
                    "type": "integer",
                    "description": "Tab ID (defaults to active tab)"
                }
            },
            "required": ["file_path", "selector"]
        })
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        input: serde_json::Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        let input: UploadImageInput =
            serde_json::from_value(input).map_err(|e| crate::error::Error::Tool {
                tool: "upload_image".to_string(),
                message: format!("invalid parameters: {e}"),
            })?;

        if input.file_path.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: file_path must not be empty",
                ))],
                details: None,
                is_error: true,
            });
        }

        if input.selector.is_empty() {
            return Ok(ToolOutput {
                content: vec![ContentBlock::Text(TextContent::new(
                    "Error: selector must not be empty",
                ))],
                details: None,
                is_error: true,
            });
        }

        let _ = &self.bridge;
        // TODO(bd-18m.2.1): Send request via ChromeBridge once native host relay is complete
        Ok(bridge_not_connected_error("upload_image"))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> Arc<StdMutex<ObserverRegistry>> {
        Arc::new(StdMutex::new(ObserverRegistry::new()))
    }

    fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build")
            .block_on(future)
    }

    /// Extract text from the first content block of a ToolOutput.
    fn first_text(output: &ToolOutput) -> &str {
        match &output.content[0] {
            ContentBlock::Text(tc) => &tc.text,
            other => panic!("expected Text content block, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // ObserveTool tests
    // -----------------------------------------------------------------------

    #[test]
    fn observe_basic_registration() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-1",
                        "tab_id": 42,
                        "events": ["console_error", "network_error"],
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(!result.is_error, "should succeed");
            assert!(first_text(&result).contains("obs-1"));

            let reg = registry.lock().unwrap();
            assert_eq!(reg.len(), 1);
            let obs = reg.get("obs-1").expect("observer registered");
            assert_eq!(obs.tab_id, 42);
            assert_eq!(obs.events.len(), 2);
        });
    }

    #[test]
    fn observe_throttle_clamped_to_floor() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            // Request 100ms throttle — should be clamped to 500ms
            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-fast",
                        "tab_id": 1,
                        "events": ["console_error"],
                        "throttle_ms": 100,
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(!result.is_error);
            let details = result.details.unwrap();
            assert_eq!(details["throttle_ms"], THROTTLE_FLOOR_MS);

            let reg = registry.lock().unwrap();
            assert_eq!(
                reg.get("obs-fast").unwrap().throttle_ms,
                THROTTLE_FLOOR_MS,
                "throttle must be clamped to floor"
            );
        });
    }

    #[test]
    fn observe_throttle_above_floor_passes_through() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-slow",
                        "tab_id": 1,
                        "events": ["dom_mutation"],
                        "throttle_ms": 2000,
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(!result.is_error);
            let details = result.details.unwrap();
            assert_eq!(details["throttle_ms"], 2000);
        });
    }

    #[test]
    fn observe_default_throttle_is_floor() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-default",
                        "tab_id": 1,
                        "events": ["navigation"],
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(!result.is_error);
            let details = result.details.unwrap();
            assert_eq!(
                details["throttle_ms"], THROTTLE_FLOOR_MS,
                "omitted throttle should default to THROTTLE_FLOOR_MS"
            );
        });
    }

    #[test]
    fn observe_empty_observer_id_rejected() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "",
                        "tab_id": 1,
                        "events": ["console_error"],
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error, "empty observer_id should be rejected");
        });
    }

    #[test]
    fn observe_empty_events_rejected() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-1",
                        "tab_id": 1,
                        "events": [],
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error, "empty events array should be rejected");
        });
    }

    #[test]
    fn observe_unknown_event_kind_rejected() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-1",
                        "tab_id": 1,
                        "events": ["console_error", "bogus_event"],
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error, "unknown event kind should be rejected");
            assert!(first_text(&result).contains("bogus_event"));
        });
    }

    #[test]
    fn observe_duplicate_observer_id_rejected() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let r1 = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-dup",
                        "tab_id": 1,
                        "events": ["console_error"],
                    }),
                    None,
                )
                .await
                .expect("execute");
            assert!(!r1.is_error);

            let r2 = tool
                .execute(
                    "call-2",
                    serde_json::json!({
                        "observer_id": "obs-dup",
                        "tab_id": 2,
                        "events": ["console_warn"],
                    }),
                    None,
                )
                .await
                .expect("execute");
            assert!(r2.is_error, "duplicate observer_id should be rejected");
        });
    }

    #[test]
    fn observe_limit_reached() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            // Register MAX_OBSERVERS observers
            for i in 0..super::super::observer::MAX_OBSERVERS {
                let result = tool
                    .execute(
                        &format!("call-{i}"),
                        serde_json::json!({
                            "observer_id": format!("obs-{i}"),
                            "tab_id": i as u32,
                            "events": ["console_error"],
                        }),
                        None,
                    )
                    .await
                    .expect("execute");
                assert!(!result.is_error, "observer {i} should succeed");
            }

            // One more should fail
            let result = tool
                .execute(
                    "call-overflow",
                    serde_json::json!({
                        "observer_id": "obs-overflow",
                        "tab_id": 99,
                        "events": ["console_error"],
                    }),
                    None,
                )
                .await
                .expect("execute");
            assert!(result.is_error, "should fail at limit");
            assert!(first_text(&result).contains("limit"));
        });
    }

    #[test]
    fn observe_all_six_event_kinds() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserveTool::new(registry.clone());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-all",
                        "tab_id": 1,
                        "events": [
                            "console_error",
                            "console_warn",
                            "network_error",
                            "dom_mutation",
                            "navigation",
                            "load_complete"
                        ],
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(!result.is_error);
            let reg = registry.lock().unwrap();
            assert_eq!(reg.get("obs-all").unwrap().events.len(), 6);
        });
    }

    // -----------------------------------------------------------------------
    // UnobserveTool tests
    // -----------------------------------------------------------------------

    #[test]
    fn unobserve_removes_observer() {
        run_async(async {
            let registry = make_registry();
            let observe_tool = ObserveTool::new(registry.clone());
            let unobserve_tool = UnobserveTool::new(registry.clone());

            // Register first
            observe_tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "observer_id": "obs-rm",
                        "tab_id": 1,
                        "events": ["console_error"],
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert_eq!(registry.lock().unwrap().len(), 1);

            // Remove
            let result = unobserve_tool
                .execute(
                    "call-2",
                    serde_json::json!({ "observer_id": "obs-rm" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(!result.is_error);
            assert!(first_text(&result).contains("removed"));
            assert_eq!(registry.lock().unwrap().len(), 0);
        });
    }

    #[test]
    fn unobserve_nonexistent_fails() {
        run_async(async {
            let registry = make_registry();
            let tool = UnobserveTool::new(registry);

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "observer_id": "ghost" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not found"));
        });
    }

    #[test]
    fn unobserve_empty_id_rejected() {
        run_async(async {
            let registry = make_registry();
            let tool = UnobserveTool::new(registry);

            let result = tool
                .execute("call-1", serde_json::json!({ "observer_id": "" }), None)
                .await
                .expect("execute");

            assert!(result.is_error, "empty observer_id should be rejected");
        });
    }

    // -----------------------------------------------------------------------
    // ObserversTool tests
    // -----------------------------------------------------------------------

    #[test]
    fn observers_empty_list() {
        run_async(async {
            let registry = make_registry();
            let tool = ObserversTool::new(registry);

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(!result.is_error);
            assert!(first_text(&result).contains("No active"));
            let details = result.details.unwrap();
            assert_eq!(details["count"], 0);
        });
    }

    #[test]
    fn observers_lists_registered() {
        run_async(async {
            let registry = make_registry();
            let observe_tool = ObserveTool::new(registry.clone());
            let list_tool = ObserversTool::new(registry.clone());

            // Register two observers
            observe_tool
                .execute(
                    "c1",
                    serde_json::json!({
                        "observer_id": "obs-a",
                        "tab_id": 10,
                        "events": ["console_error", "network_error"],
                    }),
                    None,
                )
                .await
                .unwrap();
            observe_tool
                .execute(
                    "c2",
                    serde_json::json!({
                        "observer_id": "obs-b",
                        "tab_id": 20,
                        "events": ["dom_mutation"],
                        "throttle_ms": 1000,
                    }),
                    None,
                )
                .await
                .unwrap();

            let result = list_tool
                .execute("c3", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(!result.is_error);
            let text = first_text(&result);
            assert!(text.contains("2 active observer(s)"));
            assert!(text.contains("obs-a"));
            assert!(text.contains("obs-b"));

            let details = result.details.unwrap();
            assert_eq!(details["count"], 2);
        });
    }

    #[test]
    fn observers_tool_is_read_only() {
        let registry = make_registry();
        let tool = ObserversTool::new(registry);
        assert!(tool.is_read_only(), "observers tool must be read-only");
    }

    // -----------------------------------------------------------------------
    // Helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_event_kind_all_valid() {
        assert_eq!(
            parse_event_kind("console_error"),
            Some(ObservableEventKind::ConsoleError)
        );
        assert_eq!(
            parse_event_kind("console_warn"),
            Some(ObservableEventKind::ConsoleWarn)
        );
        assert_eq!(
            parse_event_kind("network_error"),
            Some(ObservableEventKind::NetworkError)
        );
        assert_eq!(
            parse_event_kind("dom_mutation"),
            Some(ObservableEventKind::DomMutation)
        );
        assert_eq!(
            parse_event_kind("navigation"),
            Some(ObservableEventKind::Navigation)
        );
        assert_eq!(
            parse_event_kind("load_complete"),
            Some(ObservableEventKind::LoadComplete)
        );
    }

    #[test]
    fn parse_event_kind_invalid() {
        assert_eq!(parse_event_kind("bogus"), None);
        assert_eq!(parse_event_kind(""), None);
        assert_eq!(parse_event_kind("CONSOLE_ERROR"), None);
    }

    #[test]
    fn event_kind_str_roundtrip() {
        let kinds = [
            ObservableEventKind::ConsoleError,
            ObservableEventKind::ConsoleWarn,
            ObservableEventKind::NetworkError,
            ObservableEventKind::DomMutation,
            ObservableEventKind::Navigation,
            ObservableEventKind::LoadComplete,
        ];
        for kind in &kinds {
            let s = event_kind_str(*kind);
            let parsed = parse_event_kind(s).expect("roundtrip should succeed");
            assert_eq!(&parsed, kind);
        }
    }

    // -----------------------------------------------------------------------
    // Browser tool helpers
    // -----------------------------------------------------------------------

    fn make_bridge() -> Arc<ChromeBridge> {
        Arc::new(ChromeBridge::new(Default::default()))
    }

    // -----------------------------------------------------------------------
    // NavigateTool tests — Wave 2A
    // -----------------------------------------------------------------------

    #[test]
    fn navigate_rejects_empty_params() {
        run_async(async {
            let tool = NavigateTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(result.is_error, "must provide url or action");
            assert!(first_text(&result).contains("url"));
        });
    }

    #[test]
    fn navigate_rejects_invalid_action() {
        run_async(async {
            let tool = NavigateTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "action": "sideways" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("sideways"));
        });
    }

    #[test]
    fn navigate_rejects_empty_url() {
        run_async(async {
            let tool = NavigateTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "url": "" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("empty"));
        });
    }

    #[test]
    fn navigate_accepts_valid_url() {
        run_async(async {
            let tool = NavigateTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "url": "https://example.com" }),
                    None,
                )
                .await
                .expect("execute");

            // Should return "not connected" since bridge is disconnected
            assert!(result.is_error);
            assert!(
                first_text(&result).contains("not connected")
                    || first_text(&result).contains("not available")
            );
        });
    }

    #[test]
    fn navigate_accepts_valid_action() {
        run_async(async {
            let tool = NavigateTool::new(make_bridge());

            for action in &["back", "forward", "reload"] {
                let result = tool
                    .execute("call-1", serde_json::json!({ "action": action }), None)
                    .await
                    .expect("execute");

                // Should reach bridge call (not parameter validation error)
                assert!(result.is_error);
                assert!(
                    first_text(&result).contains("not available"),
                    "action '{action}' should pass validation"
                );
            }
        });
    }

    #[test]
    fn navigate_tool_metadata() {
        let tool = NavigateTool::new(make_bridge());
        assert_eq!(tool.name(), "navigate");
        assert!(!tool.is_read_only());
    }

    // -----------------------------------------------------------------------
    // TabsCreateTool tests — Wave 2A
    // -----------------------------------------------------------------------

    #[test]
    fn tabs_create_accepts_empty_params() {
        run_async(async {
            let tool = TabsCreateTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            // All params optional — should reach bridge call
            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn tabs_create_accepts_url_and_active() {
        run_async(async {
            let tool = TabsCreateTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "url": "https://example.com", "active": true }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn tabs_create_tool_metadata() {
        let tool = TabsCreateTool::new(make_bridge());
        assert_eq!(tool.name(), "tabs_create");
        assert!(!tool.is_read_only());
    }

    // -----------------------------------------------------------------------
    // TabsContextTool tests — Wave 2A
    // -----------------------------------------------------------------------

    #[test]
    fn tabs_context_is_read_only() {
        let tool = TabsContextTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "tabs_context");
    }

    #[test]
    fn tabs_context_accepts_empty_params() {
        run_async(async {
            let tool = TabsContextTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // SwitchBrowserTool tests — Wave 2A
    // -----------------------------------------------------------------------

    #[test]
    fn switch_browser_returns_not_implemented() {
        run_async(async {
            let tool = SwitchBrowserTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "browser": "firefox" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not yet implemented"));
        });
    }

    #[test]
    fn switch_browser_tool_metadata() {
        let tool = SwitchBrowserTool::new(make_bridge());
        assert_eq!(tool.name(), "switch_browser");
        assert!(!tool.is_read_only());
    }

    // -----------------------------------------------------------------------
    // ReadPageTool tests — Wave 2B
    // -----------------------------------------------------------------------

    #[test]
    fn read_page_is_read_only() {
        let tool = ReadPageTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "read_page");
    }

    #[test]
    fn read_page_accepts_empty_params() {
        run_async(async {
            let tool = ReadPageTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            // All params optional — should reach bridge call
            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn read_page_accepts_full_params() {
        run_async(async {
            let tool = ReadPageTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "tab_id": 42,
                        "max_depth": 10,
                        "max_nodes": 500,
                        "filter": "main",
                        "ref_id": 7,
                        "max_chars": 10000,
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn read_page_rejects_invalid_types() {
        run_async(async {
            let tool = ReadPageTool::new(make_bridge());

            let result = tool.execute(
                "call-1",
                serde_json::json!({ "tab_id": "not-a-number" }),
                None,
            );

            // Should return Error::Tool for deserialization failure
            let err = result.await;
            assert!(err.is_err(), "string tab_id should fail deserialization");
        });
    }

    // -----------------------------------------------------------------------
    // GetPageTextTool tests — Wave 2B
    // -----------------------------------------------------------------------

    #[test]
    fn get_page_text_is_read_only() {
        let tool = GetPageTextTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "get_page_text");
    }

    #[test]
    fn get_page_text_accepts_empty_params() {
        run_async(async {
            let tool = GetPageTextTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn get_page_text_accepts_tab_id() {
        run_async(async {
            let tool = GetPageTextTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "tab_id": 42 }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // FindTool tests — Wave 2B
    // -----------------------------------------------------------------------

    #[test]
    fn find_is_read_only() {
        let tool = FindTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "find");
    }

    #[test]
    fn find_rejects_empty_query() {
        run_async(async {
            let tool = FindTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "query": "" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("empty"));
        });
    }

    #[test]
    fn find_rejects_missing_query() {
        run_async(async {
            let tool = FindTool::new(make_bridge());

            let result = tool.execute("call-1", serde_json::json!({}), None);

            let err = result.await;
            assert!(err.is_err(), "missing required 'query' should fail");
        });
    }

    #[test]
    fn find_accepts_valid_query() {
        run_async(async {
            let tool = FindTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "query": "Submit", "tab_id": 42 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // ComputerTool tests — Wave 2C
    // -----------------------------------------------------------------------

    #[test]
    fn computer_tool_metadata() {
        let tool = ComputerTool::new(make_bridge());
        assert_eq!(tool.name(), "computer");
        assert!(!tool.is_read_only());
    }

    #[test]
    fn computer_rejects_invalid_action() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "action": "explode" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("explode"));
        });
    }

    #[test]
    fn computer_click_requires_coordinate_or_ref_id() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "left_click" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("coordinate"));
        });
    }

    #[test]
    fn computer_click_accepts_coordinate() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "left_click", "coordinate": [100, 200] }),
                    None,
                )
                .await
                .expect("execute");

            // Passes validation, reaches bridge
            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn computer_click_accepts_ref_id() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "left_click", "refId": 42 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn computer_rejects_bad_coordinate_length() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "left_click", "coordinate": [100] }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("[x, y]"));
        });
    }

    #[test]
    fn computer_type_requires_text() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "action": "type" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("text"));
        });
    }

    #[test]
    fn computer_type_accepts_text() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "type", "text": "hello" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn computer_key_requires_text() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "action": "key" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("text"));
        });
    }

    #[test]
    fn computer_scroll_rejects_invalid_direction() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "scroll", "scroll_direction": "diagonal" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("diagonal"));
        });
    }

    #[test]
    fn computer_scroll_accepts_valid_direction() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            for dir in &["up", "down", "left", "right"] {
                let result = tool
                    .execute(
                        "call-1",
                        serde_json::json!({ "action": "scroll", "scroll_direction": dir }),
                        None,
                    )
                    .await
                    .expect("execute");

                assert!(result.is_error);
                assert!(
                    first_text(&result).contains("not available"),
                    "scroll_direction '{dir}' should pass validation"
                );
            }
        });
    }

    #[test]
    fn computer_screenshot_action_passes_validation() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "screenshot" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn computer_wait_action_passes_validation() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "action": "wait", "duration": 1000 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn computer_all_13_actions_recognized() {
        run_async(async {
            let tool = ComputerTool::new(make_bridge());

            for action in COMPUTER_ACTIONS {
                // Build minimum valid input for each action
                let mut input = serde_json::json!({ "action": action });
                if COORDINATE_ACTIONS.contains(action) {
                    input["coordinate"] = serde_json::json!([100, 200]);
                }
                if TEXT_ACTIONS.contains(action) {
                    input["text"] = serde_json::json!("test");
                }

                let result = tool.execute("call-1", input, None).await.expect("execute");

                // Should reach bridge (not validation error)
                assert!(
                    first_text(&result).contains("not available"),
                    "action '{action}' should pass validation and reach bridge"
                );
            }
        });
    }

    // -----------------------------------------------------------------------
    // FormInputTool tests — Wave 2C
    // -----------------------------------------------------------------------

    #[test]
    fn form_input_tool_metadata() {
        let tool = FormInputTool::new(make_bridge());
        assert_eq!(tool.name(), "form_input");
        assert!(!tool.is_read_only());
    }

    #[test]
    fn form_input_rejects_missing_required() {
        run_async(async {
            let tool = FormInputTool::new(make_bridge());

            // Missing both required fields
            let result = tool.execute("call-1", serde_json::json!({}), None);
            assert!(result.await.is_err());

            // Missing value
            let result = tool.execute("call-1", serde_json::json!({ "refId": 42 }), None);
            assert!(result.await.is_err());

            // Missing refId
            let result = tool.execute("call-1", serde_json::json!({ "value": "hello" }), None);
            assert!(result.await.is_err());
        });
    }

    #[test]
    fn form_input_accepts_valid_params() {
        run_async(async {
            let tool = FormInputTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "refId": 42, "value": "test@example.com" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn form_input_accepts_tab_id() {
        run_async(async {
            let tool = FormInputTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "refId": 7, "value": "x", "tab_id": 99 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // ScreenshotTool tests — Wave 2D
    // -----------------------------------------------------------------------

    #[test]
    fn screenshot_is_read_only() {
        let tool = ScreenshotTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "screenshot");
    }

    #[test]
    fn screenshot_accepts_empty_params() {
        run_async(async {
            let tool = ScreenshotTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn screenshot_accepts_selector() {
        run_async(async {
            let tool = ScreenshotTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "selector": "#main", "tab_id": 42 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // GifCreatorTool tests — Wave 2D
    // -----------------------------------------------------------------------

    #[test]
    fn gif_creator_is_read_only() {
        let tool = GifCreatorTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "gif_creator");
    }

    #[test]
    fn gif_creator_returns_phase3_stub() {
        run_async(async {
            let tool = GifCreatorTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "duration_ms": 3000 }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("Phase 3"));
        });
    }

    // -----------------------------------------------------------------------
    // JavascriptTool tests — Wave 2D
    // -----------------------------------------------------------------------

    #[test]
    fn javascript_tool_metadata() {
        let tool = JavascriptTool::new(make_bridge());
        assert_eq!(tool.name(), "javascript");
        assert!(!tool.is_read_only());
    }

    #[test]
    fn javascript_rejects_empty_code() {
        run_async(async {
            let tool = JavascriptTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "code": "" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("empty"));
        });
    }

    #[test]
    fn javascript_rejects_missing_code() {
        run_async(async {
            let tool = JavascriptTool::new(make_bridge());

            let result = tool.execute("call-1", serde_json::json!({}), None);
            assert!(result.await.is_err());
        });
    }

    #[test]
    fn javascript_accepts_valid_code() {
        run_async(async {
            let tool = JavascriptTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "code": "document.title", "tab_id": 42 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // ReadConsoleTool tests — Wave 2D
    // -----------------------------------------------------------------------

    #[test]
    fn read_console_is_read_only() {
        let tool = ReadConsoleTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "read_console_messages");
    }

    #[test]
    fn read_console_accepts_empty_params() {
        run_async(async {
            let tool = ReadConsoleTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn read_console_accepts_pattern() {
        run_async(async {
            let tool = ReadConsoleTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "pattern": "\\[ERROR\\]", "tab_id": 42 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // ReadNetworkTool tests — Wave 2D
    // -----------------------------------------------------------------------

    #[test]
    fn read_network_is_read_only() {
        let tool = ReadNetworkTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "read_network_requests");
    }

    #[test]
    fn read_network_accepts_empty_params() {
        run_async(async {
            let tool = ReadNetworkTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    #[test]
    fn read_network_accepts_pattern() {
        run_async(async {
            let tool = ReadNetworkTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "pattern": "/api/.*", "tab_id": 42 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // ResizeWindowTool tests — Wave 2E
    // -----------------------------------------------------------------------

    #[test]
    fn resize_window_tool_metadata() {
        let tool = ResizeWindowTool::new(make_bridge());
        assert_eq!(tool.name(), "resize_window");
        assert!(!tool.is_read_only());
    }

    #[test]
    fn resize_window_rejects_missing_dimensions() {
        run_async(async {
            let tool = ResizeWindowTool::new(make_bridge());

            let result = tool.execute("call-1", serde_json::json!({}), None);
            assert!(result.await.is_err());
        });
    }

    #[test]
    fn resize_window_rejects_too_small() {
        run_async(async {
            let tool = ResizeWindowTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "width": 50, "height": 50 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("100"));
        });
    }

    #[test]
    fn resize_window_accepts_valid_dimensions() {
        run_async(async {
            let tool = ResizeWindowTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "width": 1024, "height": 768 }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // ShortcutsExecuteTool tests — Wave 2E
    // -----------------------------------------------------------------------

    #[test]
    fn shortcuts_execute_tool_metadata() {
        let tool = ShortcutsExecuteTool::new(make_bridge());
        assert_eq!(tool.name(), "shortcuts_execute");
        assert!(!tool.is_read_only());
    }

    #[test]
    fn shortcuts_execute_rejects_empty() {
        run_async(async {
            let tool = ShortcutsExecuteTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "shortcut": "" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("empty"));
        });
    }

    #[test]
    fn shortcuts_execute_rejects_missing() {
        run_async(async {
            let tool = ShortcutsExecuteTool::new(make_bridge());

            let result = tool.execute("call-1", serde_json::json!({}), None);
            assert!(result.await.is_err());
        });
    }

    #[test]
    fn shortcuts_execute_accepts_valid() {
        run_async(async {
            let tool = ShortcutsExecuteTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({ "shortcut": "Ctrl+C" }), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // ShortcutsListTool tests — Wave 2E
    // -----------------------------------------------------------------------

    #[test]
    fn shortcuts_list_is_read_only() {
        let tool = ShortcutsListTool::new(make_bridge());
        assert!(tool.is_read_only());
        assert_eq!(tool.name(), "shortcuts_list");
    }

    #[test]
    fn shortcuts_list_accepts_empty_params() {
        run_async(async {
            let tool = ShortcutsListTool::new(make_bridge());

            let result = tool
                .execute("call-1", serde_json::json!({}), None)
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // UploadImageTool tests — Wave 2E
    // -----------------------------------------------------------------------

    #[test]
    fn upload_image_tool_metadata() {
        let tool = UploadImageTool::new(make_bridge());
        assert_eq!(tool.name(), "upload_image");
        assert!(!tool.is_read_only());
    }

    #[test]
    fn upload_image_rejects_missing_required() {
        run_async(async {
            let tool = UploadImageTool::new(make_bridge());

            let result = tool.execute("call-1", serde_json::json!({}), None);
            assert!(result.await.is_err());
        });
    }

    #[test]
    fn upload_image_rejects_empty_file_path() {
        run_async(async {
            let tool = UploadImageTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "file_path": "", "selector": "input[type=file]" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("file_path"));
        });
    }

    #[test]
    fn upload_image_rejects_empty_selector() {
        run_async(async {
            let tool = UploadImageTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({ "file_path": "/tmp/img.png", "selector": "" }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("selector"));
        });
    }

    #[test]
    fn upload_image_accepts_valid_params() {
        run_async(async {
            let tool = UploadImageTool::new(make_bridge());

            let result = tool
                .execute(
                    "call-1",
                    serde_json::json!({
                        "file_path": "/tmp/screenshot.png",
                        "selector": "input[type=file]",
                        "tab_id": 42,
                    }),
                    None,
                )
                .await
                .expect("execute");

            assert!(result.is_error);
            assert!(first_text(&result).contains("not available"));
        });
    }

    // -----------------------------------------------------------------------
    // Tool count verification
    // -----------------------------------------------------------------------

    #[test]
    fn all_browser_tool_names_unique() {
        let bridge = make_bridge();
        let registry = make_registry();

        let tools: Vec<Box<dyn Tool>> = vec![
            // Observation (3)
            Box::new(ObserveTool::new(registry.clone())),
            Box::new(UnobserveTool::new(registry.clone())),
            Box::new(ObserversTool::new(registry)),
            // Navigation — Wave 2A (4)
            Box::new(NavigateTool::new(bridge.clone())),
            Box::new(TabsCreateTool::new(bridge.clone())),
            Box::new(TabsContextTool::new(bridge.clone())),
            Box::new(SwitchBrowserTool::new(bridge.clone())),
            // Reading — Wave 2B (3)
            Box::new(ReadPageTool::new(bridge.clone())),
            Box::new(GetPageTextTool::new(bridge.clone())),
            Box::new(FindTool::new(bridge.clone())),
            // Interaction — Wave 2C (2)
            Box::new(ComputerTool::new(bridge.clone())),
            Box::new(FormInputTool::new(bridge.clone())),
            // Capture/DevTools — Wave 2D (5)
            Box::new(ScreenshotTool::new(bridge.clone())),
            Box::new(GifCreatorTool::new(bridge.clone())),
            Box::new(JavascriptTool::new(bridge.clone())),
            Box::new(ReadConsoleTool::new(bridge.clone())),
            Box::new(ReadNetworkTool::new(bridge.clone())),
            // Window/Shortcuts/Media — Wave 2E (4)
            Box::new(ResizeWindowTool::new(bridge.clone())),
            Box::new(ShortcutsExecuteTool::new(bridge.clone())),
            Box::new(ShortcutsListTool::new(bridge.clone())),
            Box::new(UploadImageTool::new(bridge)),
        ];

        assert_eq!(tools.len(), 21, "should have 21 browser tools total");

        let mut names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
        let original_count = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), original_count, "all tool names must be unique");
    }
}
