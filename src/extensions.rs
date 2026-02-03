//! Extension protocol, policy, and runtime scaffolding.
//!
//! This module defines the versioned extension protocol and provides
//! validation utilities plus a minimal WASM host scaffold.

use crate::agent::AgentEvent;
use crate::error::{Error, Result};
use crate::session::SessionMessage;
use asupersync::Cx;
use asupersync::channel::{mpsc, oneshot};
use asupersync::time::{timeout, wall_now};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "1.0";
pub const LOG_SCHEMA_VERSION: &str = "pi.ext.log.v1";

// ============================================================================
// Policy
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionPolicyMode {
    Strict,
    Prompt,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionPolicy {
    pub mode: ExtensionPolicyMode,
    pub max_memory_mb: u32,
    pub default_caps: Vec<String>,
    pub deny_caps: Vec<String>,
}

impl Default for ExtensionPolicy {
    fn default() -> Self {
        Self {
            mode: ExtensionPolicyMode::Prompt,
            max_memory_mb: 256,
            default_caps: vec!["read".to_string(), "write".to_string(), "http".to_string()],
            deny_caps: vec!["exec".to_string(), "env".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Prompt,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub decision: PolicyDecision,
    pub capability: String,
    pub reason: String,
}

impl ExtensionPolicy {
    pub fn evaluate(&self, capability: &str) -> PolicyCheck {
        let normalized = capability.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return PolicyCheck {
                decision: PolicyDecision::Deny,
                capability: String::new(),
                reason: "empty_capability".to_string(),
            };
        }

        if self
            .deny_caps
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case(&normalized))
        {
            return PolicyCheck {
                decision: PolicyDecision::Deny,
                capability: normalized,
                reason: "deny_caps".to_string(),
            };
        }

        let in_default_caps = self
            .default_caps
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case(&normalized));

        match self.mode {
            ExtensionPolicyMode::Strict => PolicyCheck {
                decision: if in_default_caps {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny
                },
                capability: normalized,
                reason: if in_default_caps {
                    "default_caps".to_string()
                } else {
                    "not_in_default_caps".to_string()
                },
            },
            ExtensionPolicyMode::Prompt => PolicyCheck {
                decision: if in_default_caps {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Prompt
                },
                capability: normalized,
                reason: if in_default_caps {
                    "default_caps".to_string()
                } else {
                    "prompt_required".to_string()
                },
            },
            ExtensionPolicyMode::Permissive => PolicyCheck {
                decision: PolicyDecision::Allow,
                capability: normalized,
                reason: "permissive".to_string(),
            },
        }
    }
}

pub fn required_capability_for_host_call(name: &str, input: &Value) -> Option<String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "tool" => input
            .get("name")
            .and_then(Value::as_str)
            .map(|tool| tool_capability(tool).to_string()),
        "exec" => Some("exec".to_string()),
        "http" => Some("http".to_string()),
        "session" => Some("session".to_string()),
        "ui" => Some("ui".to_string()),
        "log" => Some("log".to_string()),
        _ => None,
    }
}

fn tool_capability(tool_name: &str) -> &'static str {
    match tool_name.trim().to_ascii_lowercase().as_str() {
        "read" | "grep" | "find" | "ls" => "read",
        "write" | "edit" => "write",
        "bash" => "exec",
        _ => "tool",
    }
}

// ============================================================================
// Protocol (v1)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionMessage {
    pub id: String,
    pub version: String,
    #[serde(flatten)]
    pub body: ExtensionBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ExtensionBody {
    Register(RegisterPayload),
    ToolCall(ToolCallPayload),
    ToolResult(ToolResultPayload),
    SlashCommand(SlashCommandPayload),
    SlashResult(SlashResultPayload),
    EventHook(EventHookPayload),
    HostCall(HostCallPayload),
    HostResult(HostResultPayload),
    Log(Box<LogPayload>),
    Error(ErrorPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub name: String,
    pub version: String,
    pub api_version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub slash_commands: Vec<Value>,
    #[serde(default)]
    pub event_hooks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallPayload {
    pub call_id: String,
    pub name: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultPayload {
    pub call_id: String,
    pub output: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallPayload {
    pub call_id: String,
    pub name: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResultPayload {
    pub call_id: String,
    pub output: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashCommandPayload {
    pub name: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashResultPayload {
    pub output: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventHookPayload {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPayload {
    pub schema: String,
    pub ts: String,
    pub level: LogLevel,
    pub event: String,
    pub message: String,
    pub correlation: LogCorrelation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<LogSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogCorrelation {
    pub extension_id: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slash_command_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub component: LogComponent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogComponent {
    Capture,
    Harness,
    Runtime,
    Extension,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

// ============================================================================
// Extension UI + Session Bridge
// ============================================================================

/// Extension UI request payload (host -> UI surface).
#[derive(Debug, Clone)]
pub struct ExtensionUiRequest {
    pub id: String,
    pub method: String,
    pub payload: Value,
    pub timeout_ms: Option<u64>,
}

impl ExtensionUiRequest {
    pub fn new(id: impl Into<String>, method: impl Into<String>, payload: Value) -> Self {
        Self {
            id: id.into(),
            method: method.into(),
            payload,
            timeout_ms: None,
        }
    }

    pub fn expects_response(&self) -> bool {
        matches!(
            self.method.as_str(),
            "select" | "confirm" | "input" | "editor"
        )
    }

    pub fn effective_timeout_ms(&self) -> Option<u64> {
        self.timeout_ms.or_else(|| {
            self.payload
                .get("timeout")
                .and_then(serde_json::Value::as_u64)
        })
    }

    pub fn to_rpc_event(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "type".to_string(),
            Value::String("extension_ui_request".to_string()),
        );
        map.insert("id".to_string(), Value::String(self.id.clone()));
        map.insert("method".to_string(), Value::String(self.method.clone()));

        match &self.payload {
            Value::Object(obj) => {
                for (key, value) in obj {
                    map.insert(key.clone(), value.clone());
                }
            }
            other => {
                map.insert("payload".to_string(), other.clone());
            }
        }

        Value::Object(map)
    }
}

/// Extension UI response payload (UI surface -> host).
#[derive(Debug, Clone)]
pub struct ExtensionUiResponse {
    pub id: String,
    pub value: Option<Value>,
    pub cancelled: bool,
}

/// Minimal session access for extensions (hostcalls).
#[async_trait]
pub trait ExtensionSession: Send + Sync {
    async fn get_state(&self) -> Value;
    async fn get_messages(&self) -> Vec<SessionMessage>;
    async fn set_name(&self, name: String) -> Result<()>;
}

impl ExtensionMessage {
    pub fn parse_and_validate(json: &str) -> Result<Self> {
        let msg: Self = serde_json::from_str(json)?;
        msg.validate()?;
        Ok(msg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(Error::validation("Extension message id is empty"));
        }
        if self.version != PROTOCOL_VERSION {
            return Err(Error::validation(format!(
                "Unsupported extension protocol version: {}",
                self.version
            )));
        }

        match &self.body {
            ExtensionBody::Register(payload) => validate_register(payload),
            ExtensionBody::ToolCall(payload) => validate_tool_call(payload),
            ExtensionBody::ToolResult(payload) => validate_tool_result(payload),
            ExtensionBody::SlashCommand(payload) => validate_slash_command(payload),
            ExtensionBody::SlashResult(_) => Ok(()),
            ExtensionBody::EventHook(payload) => validate_event_hook(payload),
            ExtensionBody::HostCall(payload) => validate_host_call(payload),
            ExtensionBody::HostResult(payload) => validate_host_result(payload),
            ExtensionBody::Log(payload) => validate_log(payload),
            ExtensionBody::Error(payload) => validate_error(payload),
        }
    }
}

fn validate_register(payload: &RegisterPayload) -> Result<()> {
    if payload.name.trim().is_empty() {
        return Err(Error::validation("Extension name is empty"));
    }
    if payload.version.trim().is_empty() {
        return Err(Error::validation("Extension version is empty"));
    }
    if payload.api_version.trim().is_empty() {
        return Err(Error::validation("Extension api_version is empty"));
    }
    Ok(())
}

fn validate_tool_call(payload: &ToolCallPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Tool call_id is empty"));
    }
    if payload.name.trim().is_empty() {
        return Err(Error::validation("Tool name is empty"));
    }
    Ok(())
}

fn validate_tool_result(payload: &ToolResultPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Tool result call_id is empty"));
    }
    Ok(())
}

fn validate_host_call(payload: &HostCallPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Host call_id is empty"));
    }
    if payload.name.trim().is_empty() {
        return Err(Error::validation("Host call name is empty"));
    }
    Ok(())
}

fn validate_host_result(payload: &HostResultPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Host result call_id is empty"));
    }
    Ok(())
}

fn validate_slash_command(payload: &SlashCommandPayload) -> Result<()> {
    if payload.name.trim().is_empty() {
        return Err(Error::validation("Slash command name is empty"));
    }
    Ok(())
}

fn validate_event_hook(payload: &EventHookPayload) -> Result<()> {
    if payload.event.trim().is_empty() {
        return Err(Error::validation("Event hook name is empty"));
    }
    Ok(())
}

fn validate_log(payload: &LogPayload) -> Result<()> {
    if payload.schema != LOG_SCHEMA_VERSION {
        return Err(Error::validation(format!(
            "Unsupported log schema: {}",
            payload.schema
        )));
    }
    if payload.ts.trim().is_empty() {
        return Err(Error::validation("Log timestamp is empty"));
    }
    if payload.event.trim().is_empty() {
        return Err(Error::validation("Log event is empty"));
    }
    if payload.message.trim().is_empty() {
        return Err(Error::validation("Log message is empty"));
    }
    if payload.correlation.extension_id.trim().is_empty() {
        return Err(Error::validation("Log correlation extension_id is empty"));
    }
    if payload.correlation.scenario_id.trim().is_empty() {
        return Err(Error::validation("Log correlation scenario_id is empty"));
    }
    Ok(())
}

fn validate_error(payload: &ErrorPayload) -> Result<()> {
    if payload.code.trim().is_empty() {
        return Err(Error::validation("Error code is empty"));
    }
    if payload.message.trim().is_empty() {
        return Err(Error::validation("Error message is empty"));
    }
    Ok(())
}

// ============================================================================
// WASM Host Scaffold (minimal)
// ============================================================================

#[derive(Debug, Clone)]
pub struct WasmExtension {
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WasmExtensionHost {
    policy: ExtensionPolicy,
}

impl WasmExtensionHost {
    pub const fn new(policy: ExtensionPolicy) -> Self {
        Self { policy }
    }

    pub const fn policy(&self) -> &ExtensionPolicy {
        &self.policy
    }

    pub fn load_from_path(&self, path: &Path) -> Result<WasmExtension> {
        if !path.exists() {
            return Err(Error::validation(format!(
                "Extension artifact not found: {}",
                path.display()
            )));
        }
        Ok(WasmExtension {
            path: path.to_path_buf(),
        })
    }

    pub fn instantiate(&self, _extension: &WasmExtension) -> Result<()> {
        Err(Error::validation(
            "WASM host not enabled yet. Scaffold only.",
        ))
    }
}

// ============================================================================
// Extension Event System
// ============================================================================

/// Timeout for extension events in milliseconds.
pub const EXTENSION_EVENT_TIMEOUT_MS: u64 = 5000;

/// Event names for the extension lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionEventName {
    /// Input from the user.
    Input,
    /// Before the agent starts processing.
    BeforeAgentStart,
    /// Agent started processing.
    AgentStart,
    /// Agent ended processing.
    AgentEnd,
    /// Session before switch.
    SessionBeforeSwitch,
    /// Session switched.
    SessionSwitch,
    /// Session before fork.
    SessionBeforeFork,
    /// Session forked.
    SessionFork,
    /// Session before compact.
    SessionBeforeCompact,
    /// Session compacted.
    SessionCompact,
}

impl std::fmt::Display for ExtensionEventName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Input => "input",
            Self::BeforeAgentStart => "before_agent_start",
            Self::AgentStart => "agent_start",
            Self::AgentEnd => "agent_end",
            Self::SessionBeforeSwitch => "session_before_switch",
            Self::SessionSwitch => "session_switch",
            Self::SessionBeforeFork => "session_before_fork",
            Self::SessionFork => "session_fork",
            Self::SessionBeforeCompact => "session_before_compact",
            Self::SessionCompact => "session_compact",
        };
        write!(f, "{name}")
    }
}

/// Extension manager for handling loaded extensions.
#[derive(Clone)]
pub struct ExtensionManager {
    inner: Arc<Mutex<ExtensionManagerInner>>,
}

#[derive(Default)]
struct ExtensionManagerInner {
    extensions: Vec<RegisterPayload>,
    ui_sender: Option<mpsc::Sender<ExtensionUiRequest>>,
    pending_ui: HashMap<String, oneshot::Sender<ExtensionUiResponse>>,
    session: Option<Arc<dyn ExtensionSession>>,
}

impl std::fmt::Debug for ExtensionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionManager").finish_non_exhaustive()
    }
}

impl Default for ExtensionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionManager {
    /// Create a new extension manager.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExtensionManagerInner::default())),
        }
    }

    pub fn set_ui_sender(&self, sender: mpsc::Sender<ExtensionUiRequest>) {
        let mut guard = self.inner.lock().unwrap();
        guard.ui_sender = Some(sender);
    }

    pub fn set_session(&self, session: Arc<dyn ExtensionSession>) {
        let mut guard = self.inner.lock().unwrap();
        guard.session = Some(session);
    }

    pub fn register(&self, payload: RegisterPayload) {
        let mut guard = self.inner.lock().unwrap();
        guard.extensions.push(payload);
    }

    pub fn has_command(&self, name: &str) -> bool {
        let needle = normalize_command(name);
        let guard = self.inner.lock().unwrap();
        guard
            .extensions
            .iter()
            .flat_map(|ext| ext.slash_commands.iter())
            .filter_map(extract_slash_command_name)
            .any(|cmd| normalize_command(&cmd) == needle)
    }

    pub fn list_commands(&self) -> Vec<Value> {
        let guard = self.inner.lock().unwrap();
        let mut commands = Vec::new();

        for ext in &guard.extensions {
            for cmd in &ext.slash_commands {
                let Some(name) = extract_slash_command_name(cmd) else {
                    continue;
                };
                let description = cmd.get("description").and_then(Value::as_str);
                commands.push(json!({
                    "name": name,
                    "description": description,
                    "source": "extension",
                }));
            }
        }

        drop(guard);
        commands
    }

    pub async fn request_ui(
        &self,
        mut request: ExtensionUiRequest,
    ) -> Result<Option<ExtensionUiResponse>> {
        let cx = Cx::for_request();
        if request.id.trim().is_empty() {
            request.id = Uuid::new_v4().to_string();
        }

        let (ui_sender, expects_response) = {
            let guard = self.inner.lock().unwrap();
            (guard.ui_sender.clone(), request.expects_response())
        };

        let Some(ui_sender) = ui_sender else {
            return Err(Error::extension("Extension UI sender not configured"));
        };

        if !expects_response {
            ui_sender
                .send(&cx, request)
                .await
                .map_err(|_| Error::extension("Extension UI channel closed"))?;
            return Ok(None);
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.inner.lock().unwrap();
            guard.pending_ui.insert(request.id.clone(), tx);
        }

        if ui_sender.send(&cx, request.clone()).await.is_err() {
            self.inner.lock().unwrap().pending_ui.remove(&request.id);
            return Err(Error::extension("Extension UI channel closed"));
        }

        let response = if let Some(timeout_ms) = request.effective_timeout_ms() {
            match timeout(wall_now(), Duration::from_millis(timeout_ms), rx.recv(&cx)).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(_)) => Err(Error::extension("Extension UI response dropped")),
                Err(_) => Err(Error::extension("Extension UI request timed out")),
            }
        } else {
            rx.recv(&cx)
                .await
                .map_err(|_| Error::extension("Extension UI response dropped"))
        };

        match response {
            Ok(resp) => Ok(Some(resp)),
            Err(err) => {
                self.inner.lock().unwrap().pending_ui.remove(&request.id);
                Err(err)
            }
        }
    }

    pub fn respond_ui(&self, response: ExtensionUiResponse) -> bool {
        let cx = Cx::for_request();
        let tx = {
            let mut guard = self.inner.lock().unwrap();
            guard.pending_ui.remove(&response.id)
        };
        tx.is_some_and(|sender| sender.send(&cx, response).is_ok())
    }

    /// Dispatch an event to all registered extensions.
    pub async fn dispatch_event(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
    ) -> Result<()> {
        let _ = (event, data); // Stub - extension runtime not yet implemented
        Ok(())
    }

    /// Dispatch a cancellable event to all registered extensions.
    pub async fn dispatch_cancellable_event(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
        _timeout_ms: u64,
    ) -> Result<bool> {
        let _ = (event, data); // Stub - extension runtime not yet implemented
        Ok(false) // Not cancelled
    }
}

/// Extract extension event information from an agent event.
pub const fn extension_event_from_agent(
    event: &AgentEvent,
) -> Option<(ExtensionEventName, Option<Value>)> {
    match event {
        AgentEvent::AgentStart => Some((ExtensionEventName::AgentStart, None)),
        AgentEvent::AgentEnd { .. } => Some((ExtensionEventName::AgentEnd, None)),
        _ => None,
    }
}

fn extract_slash_command_name(value: &Value) -> Option<String> {
    value
        .get("name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn normalize_command(name: &str) -> String {
    name.trim_start_matches('/').trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::Validator;

    fn compiled_extension_protocol_schema() -> Validator {
        let schema_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("docs/schema/extension_protocol.json");
        let raw = std::fs::read_to_string(&schema_path).unwrap_or_else(|err| {
            panic!(
                "Failed to read extension protocol schema {}: {err}",
                schema_path.display()
            )
        });
        let schema: Value = serde_json::from_str(&raw).unwrap_or_else(|err| {
            panic!(
                "Failed to parse extension protocol schema {}: {err}",
                schema_path.display()
            )
        });

        jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to compile JSON schema {}: {err}",
                    schema_path.display()
                )
            })
    }

    #[allow(clippy::too_many_lines)]
    fn sample_protocol_messages() -> Vec<(&'static str, ExtensionMessage)> {
        vec![
            (
                "register",
                ExtensionMessage {
                    id: "msg-register".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::Register(RegisterPayload {
                        name: "demo".to_string(),
                        version: "0.1.0".to_string(),
                        api_version: "1.0".to_string(),
                        capabilities: vec!["read".to_string()],
                        tools: Vec::new(),
                        slash_commands: Vec::new(),
                        event_hooks: Vec::new(),
                    }),
                },
            ),
            (
                "tool_call",
                ExtensionMessage {
                    id: "msg-tool-call".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::ToolCall(ToolCallPayload {
                        call_id: "call-1".to_string(),
                        name: "read".to_string(),
                        input: json!({ "path": "README.md" }),
                        context: None,
                    }),
                },
            ),
            (
                "tool_result",
                ExtensionMessage {
                    id: "msg-tool-result".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::ToolResult(ToolResultPayload {
                        call_id: "call-1".to_string(),
                        output: json!({ "ok": true }),
                        is_error: false,
                    }),
                },
            ),
            (
                "slash_command",
                ExtensionMessage {
                    id: "msg-slash-command".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::SlashCommand(SlashCommandPayload {
                        name: "/hello".to_string(),
                        args: vec!["world".to_string()],
                        input: None,
                    }),
                },
            ),
            (
                "slash_result",
                ExtensionMessage {
                    id: "msg-slash-result".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::SlashResult(SlashResultPayload {
                        output: json!({ "text": "ok" }),
                        is_error: false,
                    }),
                },
            ),
            (
                "event_hook",
                ExtensionMessage {
                    id: "msg-event-hook".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::EventHook(EventHookPayload {
                        event: "agent_start".to_string(),
                        data: Some(json!({ "note": "hello" })),
                    }),
                },
            ),
            (
                "host_call",
                ExtensionMessage {
                    id: "msg-host-call".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::HostCall(HostCallPayload {
                        call_id: "host-1".to_string(),
                        name: "tool".to_string(),
                        input: json!({ "name": "read", "input": { "path": "README.md" } }),
                        timeout_ms: Some(2500),
                        context: None,
                    }),
                },
            ),
            (
                "host_result",
                ExtensionMessage {
                    id: "msg-host-result".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::HostResult(HostResultPayload {
                        call_id: "host-1".to_string(),
                        output: json!({ "content": [] }),
                        is_error: false,
                    }),
                },
            ),
            (
                "log",
                ExtensionMessage {
                    id: "msg-log".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::Log(Box::new(LogPayload {
                        schema: LOG_SCHEMA_VERSION.to_string(),
                        ts: "2026-02-03T03:01:02.123Z".to_string(),
                        level: LogLevel::Info,
                        event: "tool_call.start".to_string(),
                        message: "tool call dispatched".to_string(),
                        correlation: LogCorrelation {
                            extension_id: "ext.demo".to_string(),
                            scenario_id: "scn-001".to_string(),
                            session_id: None,
                            run_id: None,
                            artifact_id: None,
                            tool_call_id: None,
                            slash_command_id: None,
                            event_id: None,
                            host_call_id: None,
                            rpc_id: None,
                            trace_id: None,
                            span_id: None,
                        },
                        source: None,
                        data: None,
                    })),
                },
            ),
            (
                "error",
                ExtensionMessage {
                    id: "msg-error".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::Error(ErrorPayload {
                        code: "E_DEMO".to_string(),
                        message: "Something went wrong".to_string(),
                        details: Some(json!({ "hint": "check config" })),
                    }),
                },
            ),
        ]
    }

    #[test]
    fn parse_register_message() {
        let json = r#"
        {
          "id": "msg-1",
          "version": "1.0",
          "type": "register",
          "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capabilities": ["read"]
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::Register(_)));
    }

    #[test]
    fn reject_invalid_version() {
        let json = r#"
        {
          "id": "msg-2",
          "version": "2.0",
          "type": "log",
          "payload": {
            "schema": "pi.ext.log.v1",
            "ts": "2026-02-03T03:01:02.123Z",
            "level": "info",
            "event": "tool_call.start",
            "message": "hi",
            "correlation": {
              "extension_id": "ext.demo",
              "scenario_id": "scn-001"
            }
          }
        }
        "#;
        let err = ExtensionMessage::parse_and_validate(json).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Unsupported extension protocol version"));
    }

    #[test]
    fn parse_host_call_message() {
        let json = r#"
        {
          "id": "msg-3",
          "version": "1.0",
          "type": "host_call",
          "payload": {
            "call_id": "call-1",
            "name": "tool",
            "input": { "name": "read", "input": { "path": "README.md" } },
            "timeout_ms": 1000
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::HostCall(_)));
    }

    #[test]
    fn parse_log_message() {
        let json = r#"
        {
          "id": "msg-4",
          "version": "1.0",
          "type": "log",
          "payload": {
            "schema": "pi.ext.log.v1",
            "ts": "2026-02-03T03:01:02.123Z",
            "level": "info",
            "event": "tool_call.start",
            "message": "tool call dispatched",
            "correlation": {
              "extension_id": "ext.demo",
              "scenario_id": "scn-001"
            }
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::Log(_)));
    }

    #[test]
    fn extension_ui_rpc_event_format() {
        let request = ExtensionUiRequest::new(
            "req-1",
            "notify",
            json!({ "title": "Hello", "message": "World" }),
        );
        let event = request.to_rpc_event();
        assert_eq!(event["type"], "extension_ui_request");
        assert_eq!(event["id"], "req-1");
        assert_eq!(event["method"], "notify");
        assert_eq!(event["title"], "Hello");
        assert_eq!(event["message"], "World");
    }

    #[test]
    fn extension_ui_request_roundtrip() {
        let manager = ExtensionManager::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let handle = runtime.handle();

        runtime.block_on(async move {
            let (ui_tx, ui_rx) = mpsc::channel(16);
            manager.set_ui_sender(ui_tx);

            let responder = manager.clone();
            handle.spawn(async move {
                let cx = Cx::for_request();
                if let Ok(req) = ui_rx.recv(&cx).await {
                    responder.respond_ui(ExtensionUiResponse {
                        id: req.id,
                        value: Some(json!(true)),
                        cancelled: false,
                    });
                }
            });

            let request = ExtensionUiRequest::new("", "confirm", json!({ "title": "Confirm" }));
            let response = manager.request_ui(request).await.unwrap();
            assert_eq!(response.unwrap().value, Some(json!(true)));
        });
    }

    #[test]
    fn extension_protocol_schema_accepts_all_variants() {
        let schema = compiled_extension_protocol_schema();
        for (label, message) in sample_protocol_messages() {
            let instance =
                serde_json::to_value(&message).unwrap_or_else(|err| panic!("{label}: {err}"));

            if !schema.is_valid(&instance) {
                let errs = schema
                    .iter_errors(&instance)
                    .map(|err| err.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                panic!("{label}: schema validation failed:\n{errs}");
            }

            let json =
                serde_json::to_string(&message).unwrap_or_else(|err| panic!("{label}: {err}"));
            let parsed = ExtensionMessage::parse_and_validate(&json)
                .unwrap_or_else(|err| panic!("{label}: parse_and_validate failed: {err}"));
            let parsed_json =
                serde_json::to_value(&parsed).unwrap_or_else(|err| panic!("{label}: {err}"));
            assert_eq!(
                instance, parsed_json,
                "{label}: JSON changed after roundtrip"
            );
        }
    }

    #[test]
    fn extension_protocol_schema_rejects_missing_required_fields() {
        let schema = compiled_extension_protocol_schema();

        let (_, message) = sample_protocol_messages()
            .into_iter()
            .find(|(label, _)| *label == "register")
            .expect("register sample");
        let mut instance = serde_json::to_value(&message).expect("serialize");

        // Missing "id"
        instance
            .as_object_mut()
            .expect("object")
            .remove("id")
            .expect("id present");
        assert!(
            schema.validate(&instance).is_err(),
            "schema should reject missing id"
        );
    }

    #[test]
    fn parse_and_validate_rejects_unknown_type() {
        let json = r#"
        {
          "id": "msg-unknown",
          "version": "1.0",
          "type": "not_a_real_type",
          "payload": { "x": 1 }
        }
        "#;
        assert!(ExtensionMessage::parse_and_validate(json).is_err());
    }
}
