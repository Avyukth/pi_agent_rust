//! Live smoke test for the Chrome bridge: discovery -> socket auth -> extension tool ops.
//!
//! Requires a running browser with the Pi extension loaded and the native host
//! registered (`pi --setup-chrome`). Usage:
//!   cargo run --example chrome_e2e_smoke -- <url>

use asupersync::runtime::RuntimeBuilder;
use pi::chrome::{ChromeBridge, ChromeBridgeConfig};
use serde_json::json;

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "data:text/html,<h1 id=t>pi-e2e-ok</h1>".to_string());
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build");
    let code = runtime.block_on(async move {
        let bridge = ChromeBridge::new(ChromeBridgeConfig::new("e2e-session", "e2e-client"));
        match bridge.discover_hosts() {
            Ok(records) => eprintln!("[e2e] discovered {} host(s)", records.len()),
            Err(err) => {
                eprintln!("[e2e] FAIL discover: {err}");
                return 1;
            }
        }
        if let Err(err) = bridge.connect().await {
            eprintln!("[e2e] FAIL connect: {err}");
            return 1;
        }
        eprintln!("[e2e] connected: {:?}", bridge.status());

        let steps = [
            ("tabs_context", json!({})),
            ("tabs_create", json!({ "url": url })),
            ("tabs_context", json!({})),
            ("get_page_text", json!({})),
            ("find", json!({ "query": "submit button" })),
            ("read_page", json!({ "max_nodes": 50 })),
            (
                "javascript_tool",
                json!({ "code": "document.querySelector('#t').textContent" }),
            ),
            (
                "javascript_tool",
                json!({ "code": "fetch(location.href).then(r => r.status)" }),
            ),
            (
                "javascript_tool",
                json!({ "code": "document.title + '|' + location.href" }),
            ),
        ];
        let mut failures = 0;
        for (op, payload) in steps {
            match bridge.send_request(op, payload).await {
                Ok(resp) => {
                    let text = serde_json::to_string(&resp).unwrap_or_default();
                    let ok = text.contains("\"ok\":true");
                    if !ok {
                        failures += 1;
                    }
                    let preview: String = text.chars().take(400).collect();
                    eprintln!("[e2e] {op}: ok={ok} {preview}");
                }
                Err(err) => {
                    failures += 1;
                    eprintln!("[e2e] {op}: FAIL {err}");
                }
            }
        }
        i32::from(failures > 0)
    });
    std::process::exit(code);
}
