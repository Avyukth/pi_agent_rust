//! Explicit fixture backend. No production call is allowed to reach this module.

use super::{BrowserElementRef, BrowserSnapshot, BrowserTabInfo, output, policy, required};
use crate::error::{Error, Result};
use crate::tools::ToolOutput;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D, 0x49, 0x48, 0x44, 0x52, 0, 0, 0,
    1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1F, 0x15, 0xC4, 0x89, 0, 0, 0, 0x0A, 0x49, 0x44, 0x41, 0x54,
    0x78, 0x9C, 0x63, 0, 1, 0, 0, 5, 0, 1, 0x0D, 0x0A, 0x2D, 0xB4, 0, 0, 0, 0, 0x49, 0x45, 0x4E,
    0x44, 0xAE, 0x42, 0x60, 0x82,
];

pub(super) struct State {
    tabs: BTreeMap<String, BrowserTabInfo>,
    active: String,
}

impl Default for State {
    fn default() -> Self {
        let tab = BrowserTabInfo {
            name: "default".into(),
            url: "about:blank".into(),
            title: "Blank Tab".into(),
            is_active: true,
        };
        Self {
            tabs: BTreeMap::from([("default".into(), tab)]),
            active: "default".into(),
        }
    }
}

impl State {
    #[allow(clippy::too_many_lines)]
    pub(super) fn execute(
        &mut self,
        cwd: &Path,
        allowlist: Option<&[String]>,
        args: &Value,
    ) -> Result<ToolOutput> {
        let action = required(args, "action")?;
        let tab = args
            .get("tab")
            .and_then(Value::as_str)
            .unwrap_or(&self.active)
            .to_owned();
        match action {
            "open" | "goto" => {
                let url = required(args, "url")?;
                policy::check_navigation(url, allowlist)?;
                let title = args.get("title").and_then(Value::as_str).map_or_else(
                    || {
                        if matches!(url, "https://example.com" | "http://example.com") {
                            "Example Domain".to_owned()
                        } else {
                            format!("Page ({url})")
                        }
                    },
                    str::to_owned,
                );
                for info in self.tabs.values_mut() {
                    info.is_active = false;
                }
                self.tabs.insert(
                    tab.clone(),
                    BrowserTabInfo {
                        name: tab.clone(),
                        url: url.into(),
                        title: title.clone(),
                        is_active: true,
                    },
                );
                self.active.clone_from(&tab);
                Ok(output(
                    format!("Navigated tab {tab} to {url} (Title: \"{title}\")"),
                    json!({"tab": tab, "url": url, "title": title, "status": 200}),
                ))
            }
            "close" => {
                if self.tabs.remove(&tab).is_none() {
                    return Err(Error::tool(
                        "browser",
                        format!("cannot close nonexistent tab {tab}"),
                    ));
                }
                if self.active == tab {
                    self.active = self
                        .tabs
                        .keys()
                        .next()
                        .cloned()
                        .unwrap_or_else(|| "default".into());
                }
                for info in self.tabs.values_mut() {
                    info.is_active = info.name == self.active;
                }
                Ok(output(
                    format!("Closed tab {tab}. Remaining tabs: {}", self.tabs.len()),
                    json!({"closed_tab": tab, "remaining_count": self.tabs.len()}),
                ))
            }
            "list_tabs" => {
                let tabs: Vec<_> = self.tabs.values().cloned().collect();
                let lines = tabs
                    .iter()
                    .map(|t| format!("- [{}] \"{}\" -> {}", t.name, t.title, t.url))
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(output(
                    format!("Active browser tabs ({}):\n{lines}", tabs.len()),
                    json!({"tabs": tabs}),
                ))
            }
            "snapshot" | "ax_tree" => {
                let info = self
                    .tabs
                    .get(&tab)
                    .ok_or_else(|| Error::tool("browser", "unknown tab"))?;
                let elements = vec![
                    BrowserElementRef {
                        ref_id: "@e1".into(),
                        tag: "h1".into(),
                        role: "heading".into(),
                        text: info.title.clone(),
                        selector: "h1.main-title".into(),
                    },
                    BrowserElementRef {
                        ref_id: "@e2".into(),
                        tag: "input".into(),
                        role: "textbox".into(),
                        text: String::new(),
                        selector: "input#search-query".into(),
                    },
                    BrowserElementRef {
                        ref_id: "@e3".into(),
                        tag: "button".into(),
                        role: "button".into(),
                        text: "Submit".into(),
                        selector: "button#submit-btn".into(),
                    },
                ];
                let summary = format!(
                    "Page Snapshot for [{tab}] \"{}\":\n{}",
                    info.title,
                    elements
                        .iter()
                        .map(|e| format!(
                            "- [{}] <{}> (role: {}) \"{}\" ({})",
                            e.ref_id, e.tag, e.role, e.text, e.selector
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                let snapshot = BrowserSnapshot {
                    url: info.url.clone(),
                    title: info.title.clone(),
                    elements,
                    summary: summary.clone(),
                };
                Ok(output(summary, json!({"snapshot": snapshot})))
            }
            "evaluate" => {
                let script = required(args, "script")?;
                let result = if script.contains("document.title") {
                    json!("Example Page Title")
                } else if script.contains("1 + 1") {
                    json!(2)
                } else {
                    json!({"result": "evaluated", "code": script})
                };
                Ok(output(
                    format!("Evaluation result: {result}"),
                    json!({"result": result}),
                ))
            }
            "click" => {
                let selector = required(args, "selector")?;
                Ok(output(
                    format!("Clicked element {selector} in tab {tab}"),
                    json!({"action": action, "selector": selector, "tab": tab}),
                ))
            }
            "type" | "fill" => {
                let selector = required(args, "selector")?;
                let count = required(args, "text")?.chars().count();
                Ok(output(
                    format!("Entered text into {selector} in tab {tab} ({count} chars)"),
                    json!({"action": action, "selector": selector, "char_count": count}),
                ))
            }
            "press" => {
                let key = required(args, "key")?;
                Ok(output(
                    format!("Dispatched keypress {key} in tab {tab}"),
                    json!({"action": action, "key": key, "tab": tab}),
                ))
            }
            "scroll" => Ok(output(
                format!("Scrolled tab {tab} viewport"),
                json!({"action": action, "tab": tab}),
            )),
            "wait_for" => {
                let selector = required(args, "selector")?;
                let timeout = args
                    .get("timeout_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(5000);
                Ok(output(
                    format!("Selector {selector} appeared within {timeout}ms in tab {tab}"),
                    json!({"selector": selector, "timeout_ms": timeout, "found": true}),
                ))
            }
            "screenshot" => {
                let path = args.get("output_path").and_then(Value::as_str).map_or_else(
                    || {
                        PathBuf::from(format!(
                            "screenshots/browser_{}.png",
                            uuid::Uuid::new_v4().simple()
                        ))
                    },
                    PathBuf::from,
                );
                let path = if path.is_absolute() {
                    path
                } else {
                    cwd.join(path)
                };
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, PNG)?;
                Ok(output(
                    format!(
                        "Captured tab {tab} screenshot to {}\nSize: {} bytes",
                        path.display(),
                        PNG.len()
                    ),
                    json!({"tab": tab, "saved_path": path.display().to_string(), "size_bytes": PNG.len()}),
                ))
            }
            _ => Err(Error::tool("browser", format!("unknown action: {action}"))),
        }
    }
}
