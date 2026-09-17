//! Explicit deterministic fixtures. This module is never a native-error fallback.

use super::{AxNode, ComputerTool, DisplayInfo, WindowInfo, error, native, output};
use crate::error::Result;
use crate::tools::ToolOutput;
use serde_json::{Value, json};

pub(super) const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52, 0, 0, 0,
    1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0a, 0x49, 0x44, 0x41, 0x54,
    0x78, 0x9c, 0x63, 0, 1, 0, 0, 5, 0, 1, 0x0d, 0x0a, 0x2d, 0xb4, 0, 0, 0, 0, 0x49, 0x45, 0x4e,
    0x44, 0xae, 0x42, 0x60, 0x82,
];

#[allow(
    clippy::too_many_lines,
    reason = "Keep deterministic action fixtures together in one dispatch table"
)]
pub(super) fn execute(tool: &ComputerTool, args: &Value) -> Result<ToolOutput> {
    let action = args["action"].as_str().expect("validated action");
    match action {
        "list_displays" => {
            let displays = vec![
                DisplayInfo {
                    id: 1,
                    name: "Built-in Retina Display".into(),
                    width: 2560,
                    height: 1600,
                    is_primary: true,
                    scale_factor: 2,
                },
                DisplayInfo {
                    id: 2,
                    name: "External 4K Monitor".into(),
                    width: 3840,
                    height: 2160,
                    is_primary: false,
                    scale_factor: 2,
                },
            ];
            Ok(output(
                "Found 2 display(s): Built-in Retina Display; External 4K Monitor (mock)".into(),
                json!({"displays":displays}),
                true,
            ))
        }
        "list_windows" => {
            let windows = vec![
                WindowInfo {
                    id: 101,
                    title: "Pi Agent Terminal".into(),
                    app_name: "Ghostty".into(),
                    x: 100,
                    y: 100,
                    width: 1200,
                    height: 800,
                    is_minimized: false,
                    is_focused: true,
                },
                WindowInfo {
                    id: 102,
                    title: "Cargo.toml - pi_agent_rust".into(),
                    app_name: "Visual Studio Code".into(),
                    x: 400,
                    y: 200,
                    width: 1400,
                    height: 900,
                    is_minimized: false,
                    is_focused: false,
                },
            ];
            Ok(output(
                "Found 2 window(s): Pi Agent Terminal; Cargo.toml - pi_agent_rust (mock)".into(),
                json!({"windows":windows}),
                true,
            ))
        }
        "screenshot" => native::publish(&native::destination(&tool.cwd, args)?, args, PNG, true),
        "clipboard_read" => {
            let value = tool
                .clipboard_buffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            Ok(output(
                format!(
                    "Clipboard content ({} chars):\n{value}",
                    value.chars().count()
                ),
                json!({"char_count":value.chars().count(),"text":value}),
                true,
            ))
        }
        "clipboard_write" => {
            let value = args["text"].as_str().expect("validated text");
            *tool
                .clipboard_buffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = value.to_string();
            Ok(output(
                format!(
                    "Copied {} characters to clipboard (mock)",
                    value.chars().count()
                ),
                json!({"char_count":value.chars().count()}),
                true,
            ))
        }
        "ax_tree" => {
            let window = args.get("window_id").and_then(Value::as_u64).unwrap_or(101);
            let root = AxNode {
                role: "AXApplication".into(),
                title: Some("Terminal".into()),
                value: None,
                enabled: true,
                focused: true,
                children: vec![AxNode {
                    role: "AXTextArea".into(),
                    title: None,
                    value: None,
                    enabled: true,
                    focused: true,
                    children: vec![],
                }],
            };
            Ok(output(
                format!(
                    "Accessibility tree for window {window}:\n{}",
                    serde_json::to_string_pretty(&root)?
                ),
                json!({"window_id":window,"root":root}),
                true,
            ))
        }
        "key_type" => {
            let value = args["text"].as_str().expect("validated text");
            Ok(output(
                format!("Typed text ({} characters, mock)", value.chars().count()),
                json!({"action":action,"char_count":value.chars().count()}),
                true,
            ))
        }
        "key_press" => Ok(output(
            "Pressed key (mock)".into(),
            json!({"action":action,"key":args["key"]}),
            true,
        )),
        "mouse_move" | "mouse_click" | "mouse_drag" => Ok(output(
            format!("Desktop {action} (mock)"),
            json!({
                "action":action,"x":args.get("x"),"y":args.get("y"),"button":args.get("button").and_then(Value::as_str).unwrap_or("left")
            }),
            true,
        )),
        "scroll" | "focus_window" => Ok(output(
            format!("Desktop {action} (mock)"),
            json!({"action":action}),
            true,
        )),
        _ => Err(error("unknown action")),
    }
}
