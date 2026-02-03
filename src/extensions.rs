//! Extension protocol, policy, and runtime scaffolding.
//!
//! This module defines the versioned extension protocol and provides
//! validation utilities plus a minimal WASM host scaffold.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const PROTOCOL_VERSION: &str = "1.0";

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
    Log(LogPayload),
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
    #[serde(default)]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultPayload {
    pub call_id: String,
    pub output: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashCommandPayload {
    pub name: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
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
    #[serde(default)]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPayload {
    pub level: LogLevel,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
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
    #[serde(default)]
    pub details: Option<Value>,
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
    if payload.message.trim().is_empty() {
        return Err(Error::validation("Log message is empty"));
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

#[cfg(test)]
mod tests {
    use super::*;

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
          "payload": { "level": "info", "message": "hi" }
        }
        "#;
        let err = ExtensionMessage::parse_and_validate(json).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Unsupported extension protocol version"));
    }
}
