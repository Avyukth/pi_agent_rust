//! Opt-in Chromium automation through the native Chrome DevTools Protocol.
//!
//! Production calls attach to a running browser (by default on loopback port
//! 9222). They never fall back to simulated results. Deterministic fixtures must
//! explicitly select `with_mock(true)` or `PI_BROWSER_MOCK=1`.

use crate::error::{Error, Result};
use crate::model::{ContentBlock, TextContent};
use crate::tools::{Tool, ToolEffects, ToolOutput, ToolUpdate};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod cdp;
mod interaction;
mod mock;
mod policy;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserTabInfo {
    pub name: String,
    pub url: String,
    pub title: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserElementRef {
    pub ref_id: String,
    pub tag: String,
    pub role: String,
    pub text: String,
    pub selector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserSnapshot {
    pub url: String,
    pub title: String,
    pub elements: Vec<BrowserElementRef>,
    pub summary: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BrowserSettings {
    #[serde(alias = "enableBrowser")]
    pub enable_browser: Option<bool>,
    #[serde(alias = "executablePath")]
    pub executable_path: Option<String>,
    #[serde(alias = "remoteDebuggingPort")]
    pub remote_debugging_port: Option<u16>,
    pub headless: Option<bool>,
    #[serde(alias = "userAgent")]
    pub user_agent: Option<String>,
    #[serde(alias = "domainAllowlist")]
    pub domain_allowlist: Option<Vec<String>>,
}

pub struct BrowserTool {
    cwd: PathBuf,
    mock_mode: Option<bool>,
    mock_state: Mutex<mock::State>,
    /// Behind an `Arc` so the CDP path can take an `OwnedMutexGuard`.
    /// `asupersync::sync::MutexGuard` is NOT `Send`, and this guard is held
    /// across awaits inside a `Tool::execute` future, which must be.
    live_state: Arc<asupersync::sync::Mutex<cdp::Session>>,
    cdp_endpoint: Option<String>,
    domain_allowlist: Option<Vec<String>>,
}

impl BrowserTool {
    pub fn new(cwd: &Path) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            mock_mode: None,
            mock_state: Mutex::new(mock::State::default()),
            live_state: Arc::new(asupersync::sync::Mutex::new(cdp::Session::default())),
            cdp_endpoint: None,
            domain_allowlist: None,
        }
    }

    #[must_use]
    pub const fn with_mock(mut self, mock: bool) -> Self {
        self.mock_mode = Some(mock);
        self
    }

    /// Attach to an explicitly selected loopback CDP HTTP endpoint.
    /// Takes precedence over `PI_BROWSER_CDP_URL` and the port-9222 default.
    #[must_use]
    pub fn with_cdp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.cdp_endpoint = Some(endpoint.into());
        self
    }

    #[must_use]
    pub fn with_domain_allowlist(mut self, allowlist: Option<Vec<String>>) -> Self {
        self.domain_allowlist = allowlist;
        self
    }

    fn is_mock(&self) -> bool {
        self.mock_mode
            .unwrap_or_else(|| std::env::var("PI_BROWSER_MOCK").is_ok_and(|v| v == "1"))
    }
}

fn output(text: impl Into<String>, details: Value) -> ToolOutput {
    ToolOutput {
        content: vec![ContentBlock::Text(TextContent {
            text: text.into(),
            text_signature: None,
        })],
        details: Some(details),
        is_error: false,
    }
}

fn required<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::tool("browser", format!("missing required {name} parameter")))
}

#[async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl Tool for BrowserTool {
    fn name(&self) -> &str {
        "browser"
    }

    fn label(&self) -> &str {
        "Browser"
    }

    fn description(&self) -> &str {
        "Chromium automation over a loopback CDP endpoint (PI_BROWSER_CDP_URL, default \
         http://127.0.0.1:9222). Supports named tabs, navigation, JavaScript, page snapshots, \
         input actions and PNG screenshots. A running remote-debugging browser is required; \
         connection failures are errors, never simulated successes."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "required": ["action"],
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["open", "goto", "close", "list_tabs", "snapshot", "ax_tree",
                             "evaluate", "click", "type", "fill", "press", "scroll", "wait_for", "screenshot"],
                    "description": "Browser automation action"
                },
                "tab": {"type": "string", "description": "Tab name or target ID; default: active tab"},
                "url": {"type": "string", "description": "HTTP(S) URL or about:blank for open/goto"},
                "script": {"type": "string", "description": "JavaScript expression for evaluate"},
                "selector": {"type": "string", "description": "CSS selector or snapshot element ref, e.g. @e1"},
                "text": {"type": "string", "description": "Text for type/fill"},
                "key": {"type": "string", "description": "Key for press, e.g. Enter, Tab, ArrowDown"},
                "output_path": {"type": "string", "description": "Destination path for a real PNG screenshot"},
                "delta_x": {"type": "number", "description": "Horizontal scroll delta in CSS pixels"},
                "delta_y": {"type": "number", "description": "Vertical scroll delta in CSS pixels; default 600"},
                "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 120000,
                               "description": "Whole-operation deadline, including connection and lock wait"}
            }
        })
    }

    fn effects(&self) -> ToolEffects {
        ToolEffects::write()
    }

    async fn execute(
        &self,
        _tool_call_id: &str,
        args: Value,
        _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
    ) -> Result<ToolOutput> {
        required(&args, "action")?;
        if self.is_mock() {
            return self
                .mock_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .execute(&self.cwd, self.domain_allowlist.as_deref(), &args);
        }
        cdp::execute(
            &self.live_state,
            self.cdp_endpoint.as_deref(),
            &self.cwd,
            self.domain_allowlist.as_deref(),
            &args,
        )
        .await
    }
}
