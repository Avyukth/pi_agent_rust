//! Chrome tool registry integration tests (bd-3mf.8).
//!
//! Verifies:
//! - All 21 browser tools register with unique names
//! - Tool schemas are valid JSON objects with required fields
//! - S1 safety invariant: browser tools NOT registered without `--chrome` flag
//! - Combined registry (builtin + browser) has correct total count
//!
//! Run:
//! ```bash
//! cargo test --test chrome_tools
//! ```

mod common;

use pi::chrome::observer::ObserverRegistry;
use pi::chrome::tools::*;
use pi::chrome::{ChromeBridge, ChromeBridgeConfig};
use pi::tools::Tool;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn make_bridge() -> Arc<ChromeBridge> {
    let config = ChromeBridgeConfig::default();
    Arc::new(ChromeBridge::new(config))
}

fn make_registry() -> Arc<Mutex<ObserverRegistry>> {
    Arc::new(Mutex::new(ObserverRegistry::new()))
}

fn all_browser_tools() -> Vec<Box<dyn Tool>> {
    let bridge = make_bridge();
    let registry = make_registry();

    vec![
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
    ]
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

/// bd-3mf.8: Verify combined tool count = builtin (7) + browser (21).
///
/// Note: Chrome's `find` (element search) shares the name with builtin `find`
/// (file search). When both are registered, the browser version shadows the
/// builtin. Combined unique count = 27 (7 + 21 - 1 overlap).
#[test]
fn test_tool_registry_with_browser_tools() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let builtin = pi::sdk::create_all_tools(tmp.path());
    let browser = all_browser_tools();

    assert_eq!(builtin.len(), 7, "should have 7 builtin tools");
    assert_eq!(browser.len(), 21, "should have 21 browser tools");

    // Browser tools alone must have unique names
    let browser_names: HashSet<&str> = browser.iter().map(|t| t.name()).collect();
    assert_eq!(browser_names.len(), 21, "all 21 browser tool names must be unique");

    // Combined: "find" is shared between builtin (file search) and chrome (element search)
    let mut all_names: HashSet<String> = HashSet::new();
    for tool in builtin.iter().chain(browser.iter()) {
        all_names.insert(tool.name().to_string());
    }

    // Expect 27 unique = 7 + 21 - 1 overlap ("find")
    assert_eq!(all_names.len(), 27, "combined unique tools should be 27 (find overlaps)");
}

/// bd-3mf.8 / S1: Browser-exclusive tools must NOT be in the builtin registry.
///
/// Note: "find" exists in both (file search builtin, element search browser),
/// so it's excluded from this assertion.
#[test]
fn test_tool_not_registered_without_chrome_flag() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let builtin = pi::sdk::create_all_tools(tmp.path());

    let builtin_names: HashSet<&str> = builtin.iter().map(|t| t.name()).collect();
    let browser = all_browser_tools();

    // Known shared names (different implementations, same name)
    let shared_names: HashSet<&str> = ["find"].into_iter().collect();

    // Browser-exclusive tools should NOT appear in builtin
    for tool in &browser {
        if shared_names.contains(tool.name()) {
            continue; // skip shared names
        }
        assert!(
            !builtin_names.contains(tool.name()),
            "browser-exclusive tool '{}' should NOT be in builtin registry (S1 violation)",
            tool.name()
        );
    }
}

/// All browser tool names are non-empty and ASCII-kebab or snake_case.
#[test]
fn test_browser_tool_names_valid() {
    for tool in &all_browser_tools() {
        let name = tool.name();
        assert!(!name.is_empty(), "tool name must not be empty");
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "tool name '{}' has invalid characters",
            name,
        );
    }
}

/// All browser tool descriptions are non-empty.
#[test]
fn test_browser_tool_descriptions_nonempty() {
    for tool in &all_browser_tools() {
        assert!(
            !tool.description().is_empty(),
            "tool '{}' has empty description",
            tool.name()
        );
    }
}

/// All browser tool parameter schemas are valid JSON objects with "type": "object".
#[test]
fn test_browser_tool_schemas_valid_objects() {
    for tool in &all_browser_tools() {
        let params = tool.parameters();
        let obj = params.as_object().unwrap_or_else(|| {
            panic!(
                "tool '{}' parameters must be a JSON object, got: {}",
                tool.name(),
                params
            )
        });

        // Must have "type": "object"
        let type_val = obj.get("type").unwrap_or_else(|| {
            panic!("tool '{}' schema missing 'type' field", tool.name())
        });
        assert_eq!(
            type_val, "object",
            "tool '{}' schema type should be 'object'",
            tool.name()
        );
    }
}

/// All browser tool labels are non-empty and distinct from names where appropriate.
#[test]
fn test_browser_tool_labels_nonempty() {
    for tool in &all_browser_tools() {
        assert!(
            !tool.label().is_empty(),
            "tool '{}' has empty label",
            tool.name()
        );
    }
}

/// Verify read-only tools are correctly marked.
#[test]
fn test_browser_tool_readonly_markers() {
    let readonly_expected: HashSet<&str> = [
        "tabs_context", "read_page", "get_page_text", "find",
        "read_console_messages", "read_network_requests",
        "shortcuts_list", "observers",
    ]
    .into_iter()
    .collect();

    for tool in &all_browser_tools() {
        if readonly_expected.contains(tool.name()) {
            assert!(
                tool.is_read_only(),
                "tool '{}' should be marked read-only",
                tool.name()
            );
        }
    }
}

/// Observation tools (3) have correct metadata.
#[test]
fn test_observation_tools_metadata() {
    let registry = make_registry();

    let observe = ObserveTool::new(registry.clone());
    let unobserve = UnobserveTool::new(registry.clone());
    let observers = ObserversTool::new(registry);

    assert_eq!(observe.name(), "observe");
    assert_eq!(unobserve.name(), "unobserve");
    assert_eq!(observers.name(), "observers");

    // Observers is read-only, observe/unobserve are not
    assert!(observers.is_read_only());
    assert!(!observe.is_read_only());
    assert!(!unobserve.is_read_only());
}
