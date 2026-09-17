//! Native, bounded CDP transport. A connection belongs to one tool operation;
//! cancellation drops it instead of reusing a possibly partially written frame.

use super::{BrowserTabInfo, output, policy, required};
use crate::agent_cx::AgentCx;
use crate::error::{Error, Result};
use crate::tools::ToolOutput;
use asupersync::net::TcpStream;
use asupersync::net::websocket::{Message, WebSocket, WebSocketConfig};
use base64::Engine as _;
use futures::future::{Either, select};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_EVENTS: usize = 8192;
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:9222";

#[derive(Default)]
pub(super) struct Session {
    tabs: BTreeMap<String, String>,
    active: Option<String>,
    endpoint: Option<String>,
}

pub(super) async fn execute(
    state: &asupersync::sync::Mutex<Session>,
    endpoint_override: Option<&str>,
    cwd: &Path,
    allowlist: Option<&[String]>,
    args: &Value,
) -> Result<ToolOutput> {
    let action = required(args, "action")?;
    match action {
        "open" | "goto" => policy::check_navigation(required(args, "url")?, allowlist)?,
        "evaluate" => { required(args, "script")?; }
        "close" | "list_tabs" | "screenshot" => {}
        "snapshot" | "ax_tree" | "click" | "type" | "fill" | "press" | "scroll" | "wait_for" => {
            return Err(Error::tool("browser", format!("{action} is not yet implemented by the native CDP backend")));
        }
        _ => return Err(Error::tool("browser", format!("unknown action: {action}"))),
    }
    let timeout_ms = match args.get("timeout_ms") {
        None => 30_000,
        Some(value) => value.as_u64().filter(|n| (1..=120_000).contains(n))
            .ok_or_else(|| Error::tool("browser", "timeout_ms must be an integer in 1..=120000"))?,
    };
    if let Some(tab) = args.get("tab")
        && tab.as_str().is_none_or(|s| s.is_empty() || s.len() > 256)
    {
        return Err(Error::tool("browser", "tab must be a nonempty string of at most 256 bytes"));
    }
    if let Some(script) = args.get("script").and_then(Value::as_str)
        && script.len() > 64 * 1024
    {
        return Err(Error::tool("browser", "script exceeds the 64 KiB limit"));
    }
    let endpoint_text = endpoint_override.map(str::to_owned)
        .or_else(|| std::env::var("PI_BROWSER_CDP_URL").ok())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
    let endpoint = policy::endpoint(&endpoint_text, false)?;
    let owner = AgentCx::for_current_or_request();
    let caps = owner.capabilities();
    if !caps.io || !caps.time || !caps.entropy {
        return Err(Error::tool("browser", "CDP requires I/O, timer and entropy capabilities"));
    }
    owner.checkpoint().map_err(|_| Error::tool("browser", "browser operation cancelled"))?;
    let operation = async {
        let mut state = state.lock(owner.cx()).await
            .map_err(|e| Error::tool("browser", format!("browser session lock: {e}")))?;
        if state.endpoint.as_deref() != Some(endpoint.as_str()) {
            state.tabs.clear();
            state.active = None;
            state.endpoint = Some(endpoint.to_string());
        }
        let mut cdp = Cdp::connect(&owner, &endpoint).await?;
        state.execute(&owner, &mut cdp, cwd, allowlist, args).await
    };
    // Register owner cancellation even while the peer is silent or the lock is
    // occupied. No detached task, polling thread or unbounded receive is needed.
    let cancelled = async {
        let (sender, mut receiver) = asupersync::channel::oneshot::channel::<()>();
        let _ = receiver.recv(owner.cx()).await;
        drop(sender);
    };
    let watchdog = async {
        let time = owner.time();
        match select(Box::pin(time.sleep(Duration::from_millis(timeout_ms))), Box::pin(cancelled)).await {
            Either::Left(_) => "browser operation timed out; remote side effects may already have occurred",
            Either::Right(_) => "browser operation cancelled; remote side effects may already have occurred",
        }
    };
    match select(Box::pin(operation), Box::pin(watchdog)).await {
        Either::Left((result, _)) => result,
        Either::Right((message, pending)) => {
            drop(pending);
            Err(Error::tool("browser", message))
        }
    }
}

pub(super) struct Cdp {
    socket: WebSocket<TcpStream>,
    next_id: u64,
    session_id: Option<String>,
    loaded: BTreeSet<(String, String)>,
}

impl Cdp {
    async fn connect(owner: &AgentCx, endpoint: &url::Url) -> Result<Self> {
        let client = owner.http().client();
        let response = client.get(&format!("{}json/version", endpoint.as_str()))
            .timeout(Duration::from_secs(5)).send().await
            .map_err(|e| Error::tool("browser", format!("cannot attach to Chromium at {endpoint}: {e}. Start Chromium with --remote-debugging-port={} and a dedicated --user-data-dir, or set PI_BROWSER_CDP_URL", endpoint.port_or_known_default().unwrap_or(9222))))?;
        if response.status() != 200 {
            return Err(Error::tool("browser", format!("CDP discovery returned HTTP {}", response.status())));
        }
        let version: Value = serde_json::from_slice(&response.bytes_limited(64 * 1024).await?)
            .map_err(|e| Error::tool("browser", format!("invalid CDP discovery JSON: {e}")))?;
        let advertised = required(&version, "webSocketDebuggerUrl")?;
        let mut websocket = policy::endpoint(advertised, true)?;
        if websocket.port_or_known_default() != endpoint.port_or_known_default() {
            return Err(Error::tool("browser", "CDP discovery changed the endpoint port"));
        }
        websocket.set_host(endpoint.host_str()).map_err(|_| Error::tool("browser", "invalid CDP host"))?;
        let config = WebSocketConfig::default()
            .max_frame_size(MAX_MESSAGE_BYTES)
            .max_message_size(MAX_MESSAGE_BYTES)
            .connect_timeout(Some(Duration::from_secs(5)));
        let socket = WebSocket::connect_with_config(owner.cx(), websocket.as_str(), config).await
            .map_err(|e| Error::tool("browser", format!("CDP WebSocket connection failed: {e}")))?;
        Ok(Self { socket, next_id: 0, session_id: None, loaded: BTreeSet::new() })
    }

    async fn receive(&mut self, owner: &AgentCx) -> Result<Value> {
        loop {
            match self.socket.recv(owner.cx()).await
                .map_err(|e| Error::tool("browser", format!("CDP receive failed: {e}")))?
            {
                Some(Message::Text(text)) => {
                    let value: Value = serde_json::from_str(&text)
                        .map_err(|e| Error::tool("browser", format!("invalid CDP JSON: {e}")))?;
                    if !value.is_object() { return Err(Error::tool("browser", "CDP message must be an object")); }
                    if value["method"] == "Page.lifecycleEvent"
                        && matches!(value["params"]["name"].as_str(), Some("DOMContentLoaded" | "load"))
                        && let (Some(frame), Some(loader)) = (value["params"]["frameId"].as_str(), value["params"]["loaderId"].as_str())
                    {
                        if self.loaded.len() >= 256 { self.loaded.clear(); }
                        self.loaded.insert((frame.into(), loader.into()));
                    }
                    if value["method"] == "Inspector.targetCrashed" {
                        return Err(Error::tool("browser", "browser target crashed"));
                    }
                    return Ok(value);
                }
                Some(Message::Ping(_) | Message::Pong(_)) => {}
                Some(Message::Binary(_)) => return Err(Error::tool("browser", "unexpected binary CDP message")),
                Some(Message::Close(_)) | None => return Err(Error::tool("browser", "CDP connection closed before the command completed")),
            }
        }
    }

    async fn call(&mut self, owner: &AgentCx, method: &str, params: Value, page: bool) -> Result<Value> {
        self.next_id = self.next_id.checked_add(1).ok_or_else(|| Error::tool("browser", "CDP request ID exhausted"))?;
        let id = self.next_id;
        let mut request = json!({"id": id, "method": method, "params": params});
        if page {
            request["sessionId"] = json!(self.session_id.as_ref().ok_or_else(|| Error::tool("browser", "no attached page"))?);
        }
        self.socket.send(owner.cx(), Message::text(request.to_string())).await
            .map_err(|e| Error::tool("browser", format!("CDP send failed: {e}")))?;
        for _ in 0..MAX_EVENTS {
            let response = self.receive(owner).await?;
            if response["id"].as_u64() == Some(id) {
                if let Some(error) = response.get("error") {
                    return Err(Error::tool("browser", format!("{method} failed: {error}")));
                }
                return response.get("result").filter(|v| v.is_object()).cloned()
                    .ok_or_else(|| Error::tool("browser", format!("{method} response is missing its result")));
            }
        }
        Err(Error::tool("browser", "too many CDP events without a command response"))
    }

    pub(super) async fn command(&mut self, owner: &AgentCx, method: &str, params: Value) -> Result<Value> {
        self.call(owner, method, params, true).await
    }

    pub(super) async fn evaluate(&mut self, owner: &AgentCx, expression: &str) -> Result<Value> {
        let response = self.command(owner, "Runtime.evaluate", json!({
            "expression": expression, "returnByValue": true, "awaitPromise": true,
            "timeout": 25_000, "allowUnsafeEvalBlockedByCSP": false
        })).await?;
        evaluation_value(&response)
    }

    async fn navigate(&mut self, owner: &AgentCx, url: &str) -> Result<()> {
        self.command(owner, "Page.enable", json!({})).await?;
        self.command(owner, "Page.setLifecycleEventsEnabled", json!({"enabled": true})).await?;
        let navigation = self.command(owner, "Page.navigate", json!({"url": url})).await?;
        if let Some(error) = navigation.get("errorText").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Err(Error::tool("browser", format!("navigation failed: {error}")));
        }
        if navigation["isDownload"] == true {
            return Err(Error::tool("browser", "navigation started a download, not a loaded page"));
        }
        if let Some(loader) = navigation.get("loaderId").and_then(Value::as_str) {
            let frame = required(&navigation, "frameId")?;
            let key = (frame.to_owned(), loader.to_owned());
            for _ in 0..MAX_EVENTS {
                if self.loaded.contains(&key) { return Ok(()); }
                self.receive(owner).await?;
            }
            return Err(Error::tool("browser", "navigation did not reach DOMContentLoaded"));
        }
        // A same-document navigation has no new loader and no load event.
        Ok(())
    }
}

fn evaluation_value(response: &Value) -> Result<Value> {
    if let Some(exception) = response.get("exceptionDetails") {
        return Err(Error::tool("browser", format!("JavaScript exception: {exception}")));
    }
    let result = response.get("result").filter(|v| v.is_object())
        .ok_or_else(|| Error::tool("browser", "Runtime.evaluate returned no remote object"))?;
    if let Some(value) = result.get("value") { return Ok(value.clone()); }
    if let Some(value) = result.get("unserializableValue") {
        return Ok(json!({"type": result["type"], "unserializableValue": value}));
    }
    if result["type"] == "undefined" { return Ok(json!({"type": "undefined"})); }
    Err(Error::tool("browser", "JavaScript result cannot be represented by value"))
}

impl Session {
    #[allow(clippy::too_many_lines)]
    async fn execute(&mut self, owner: &AgentCx, cdp: &mut Cdp, cwd: &Path, allowlist: Option<&[String]>, args: &Value) -> Result<ToolOutput> {
        let action = required(args, "action")?;
        let response = cdp.call(owner, "Target.getTargets", json!({}), false).await?;
        let targets = response.get("targetInfos").and_then(Value::as_array)
            .ok_or_else(|| Error::tool("browser", "Target.getTargets returned no targets"))?;
        let pages: BTreeMap<String, Value> = targets.iter().filter(|v| v["type"] == "page")
            .filter_map(|v| v["targetId"].as_str().map(|id| (id.to_owned(), v.clone()))).collect();
        self.tabs.retain(|_, id| pages.contains_key(id));
        if self.active.as_ref().is_some_and(|name| !self.tabs.contains_key(name)) { self.active = None; }
        let tab = args.get("tab").and_then(Value::as_str).or(self.active.as_deref()).unwrap_or("default").to_owned();
        if action == "list_tabs" {
            let tabs: Vec<_> = pages.iter().map(|(id, info)| {
                let name = self.tabs.iter().find(|(_, target)| *target == id).map_or(id, |(name, _)| name);
                BrowserTabInfo {
                    name: name.clone(), url: info["url"].as_str().unwrap_or_default().into(),
                    title: info["title"].as_str().unwrap_or_default().into(), is_active: self.active.as_ref() == Some(name),
                }
            }).collect();
            let lines = tabs.iter().map(|t| format!("- [{}] \"{}\" -> {}", t.name, t.title, t.url)).collect::<Vec<_>>().join("\n");
            return Ok(output(format!("Active browser tabs ({}):\n{lines}", tabs.len()), json!({"tabs": tabs, "backend": "cdp"})));
        }
        let existing = self.tabs.get(&tab).cloned().or_else(|| pages.contains_key(&tab).then(|| tab.clone()));
        let target = if action == "open" && existing.is_none() {
            // Create a blank target first: validate and attach before navigation.
            let created = cdp.call(owner, "Target.createTarget", json!({"url": "about:blank"}), false).await?;
            let id = required(&created, "targetId")?.to_owned();
            self.tabs.insert(tab.clone(), id.clone());
            id
        } else {
            existing.ok_or_else(|| Error::tool("browser", format!("cannot {action} nonexistent tab {tab}; use open or select a target from list_tabs")))?
        };
        if action == "close" {
            let response = cdp.call(owner, "Target.closeTarget", json!({"targetId": target}), false).await?;
            if response["success"] != true { return Err(Error::tool("browser", "Chromium refused to close the target")); }
            self.tabs.retain(|_, id| id != &target);
            if self.active.as_ref() == Some(&tab) { self.active = self.tabs.keys().next().cloned(); }
            return Ok(output(format!("Closed tab {tab}"), json!({"closed_tab": tab, "remaining_count": self.tabs.len(), "backend": "cdp"})));
        }
        if !matches!(action, "open" | "goto") {
            let current = pages.get(&target).and_then(|v| v["url"].as_str()).ok_or_else(|| Error::tool("browser", "target has no current URL"))?;
            policy::check_navigation(current, allowlist)?;
        }
        let attached = cdp.call(owner, "Target.attachToTarget", json!({"targetId": target, "flatten": true}), false).await?;
        cdp.session_id = Some(required(&attached, "sessionId")?.to_owned());
        self.tabs.insert(tab.clone(), target);
        self.active = Some(tab.clone());
        match action {
            "open" | "goto" => {
                let url = required(args, "url")?;
                cdp.navigate(owner, url).await?;
                let info = cdp.evaluate(owner, "({url: location.href, title: document.title})").await?;
                let final_url = required(&info, "url")?;
                policy::check_navigation(final_url, allowlist)?;
                let title = required(&info, "title")?;
                Ok(output(format!("Navigated tab {tab} to {final_url} (Title: \"{title}\")"), json!({"tab": tab, "url": final_url, "title": title, "loaded": true, "backend": "cdp"})))
            }
            "evaluate" => {
                let value = cdp.evaluate(owner, required(args, "script")?).await?;
                Ok(output(format!("Evaluation result: {value}"), json!({"result": value, "backend": "cdp"})))
            }
            "screenshot" => {
                let response = cdp.command(owner, "Page.captureScreenshot", json!({"format": "png", "fromSurface": true})).await?;
                let bytes = base64::engine::general_purpose::STANDARD.decode(required(&response, "data")?)
                    .map_err(|e| Error::tool("browser", format!("invalid screenshot base64: {e}")))?;
                if bytes.len() < 24 || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                    return Err(Error::tool("browser", "Chromium did not return a PNG screenshot"));
                }
                let path = match args.get("output_path") {
                    None => PathBuf::from(format!("screenshots/browser_{}.png", uuid::Uuid::new_v4().simple())),
                    Some(value) => PathBuf::from(value.as_str().filter(|s| !s.is_empty()).ok_or_else(|| Error::tool("browser", "output_path must be a nonempty string"))?),
                };
                let path = if path.is_absolute() { path } else { cwd.join(path) };
                if let Some(parent) = path.parent() { owner.fs().create_dir_all(parent).await?; }
                owner.fs().write(&path, &bytes).await?;
                Ok(output(format!("Captured tab {tab} screenshot to {}\nSize: {} bytes", path.display(), bytes.len()),
                    json!({"tab": tab, "saved_path": path.display().to_string(), "size_bytes": bytes.len(), "backend": "cdp"})))
            }
            _ => Err(Error::tool("browser", format!("unsupported CDP action: {action}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn javascript_exceptions_and_unserializable_values_are_not_fake_successes() {
        assert!(evaluation_value(&json!({"exceptionDetails": {"text": "Uncaught"}, "result": {"type": "object"}})).is_err());
        assert!(evaluation_value(&json!({})).is_err());
        assert_eq!(evaluation_value(&json!({"result": {"type": "number", "value": 42}})).unwrap(), json!(42));
        assert_eq!(evaluation_value(&json!({"result": {"type": "number", "unserializableValue": "NaN"}})).unwrap()["unserializableValue"], "NaN");
        assert_eq!(evaluation_value(&json!({"result": {"type": "undefined"}})).unwrap()["type"], "undefined");
    }
}
