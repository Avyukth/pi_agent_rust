//! Extension conformance harness utilities (normalization + diff triage).
//!
//! This is the first building block for the planned `tests/ext_conformance/` suite
//! described in `CONFORMANCE.md` and `EXTENSIONS.md`.
//!
//! The core idea:
//! - Extension logs (JSONL) must be comparable across runs.
//! - We normalize known non-deterministic fields (timestamps, pids, run/session IDs, etc.).
//! - We canonicalize JSON key ordering for stable diffs.
//! - Diffs are grouped by `event` and correlation IDs to speed triage.
#![forbid(unsafe_code)]

use regex::Regex;
use serde_json::{Value, json};
use similar::ChangeTag;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::sync::OnceLock;

const PLACEHOLDER_TS: &str = "<ts>";
const PLACEHOLDER_HOST: &str = "<host>";
const PLACEHOLDER_SESSION_ID: &str = "<session_id>";
const PLACEHOLDER_RUN_ID: &str = "<run_id>";
const PLACEHOLDER_ARTIFACT_ID: &str = "<artifact_id>";
const PLACEHOLDER_TRACE_ID: &str = "<trace_id>";
const PLACEHOLDER_SPAN_ID: &str = "<span_id>";

static ANSI_REGEX: OnceLock<Regex> = OnceLock::new();

fn ansi_regex() -> &'static Regex {
    ANSI_REGEX.get_or_init(|| Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").expect("ansi regex"))
}

fn normalize_ext_log_line(mut value: Value, cwd: &Path) -> Value {
    normalize_known_dynamic_fields(&mut value);
    normalize_strings_in_value(&mut value, cwd);
    canonicalize_json_keys(&value)
}

fn normalize_known_dynamic_fields(value: &mut Value) {
    // Top-level: ts
    if let Some(ts) = value.get_mut("ts") {
        if ts.is_string() {
            *ts = Value::String(PLACEHOLDER_TS.to_string());
        }
    }

    // correlation: replace known dynamic identifiers
    if let Some(correlation) = value.get_mut("correlation").and_then(Value::as_object_mut) {
        replace_string_field(correlation, "session_id", PLACEHOLDER_SESSION_ID);
        replace_string_field(correlation, "run_id", PLACEHOLDER_RUN_ID);
        replace_string_field(correlation, "artifact_id", PLACEHOLDER_ARTIFACT_ID);
        replace_string_field(correlation, "trace_id", PLACEHOLDER_TRACE_ID);
        replace_string_field(correlation, "span_id", PLACEHOLDER_SPAN_ID);
    }

    // source: host + pid
    if let Some(source) = value.get_mut("source").and_then(Value::as_object_mut) {
        replace_string_field(source, "host", PLACEHOLDER_HOST);
        if let Some(pid) = source.get_mut("pid") {
            if pid.is_number() {
                *pid = Value::Number(0.into());
            }
        }
    }
}

fn replace_string_field(object: &mut serde_json::Map<String, Value>, key: &str, replacement: &str) {
    if let Some(value) = object.get_mut(key) {
        if value.is_string() {
            *value = Value::String(replacement.to_string());
        }
    }
}

fn normalize_strings_in_value(value: &mut Value, cwd: &Path) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(s) => {
            *s = normalize_string(s, cwd);
        }
        Value::Array(items) => {
            for item in items {
                normalize_strings_in_value(item, cwd);
            }
        }
        Value::Object(map) => {
            for (_key, item) in map.iter_mut() {
                normalize_strings_in_value(item, cwd);
            }
        }
    }
}

fn normalize_string(input: &str, cwd: &Path) -> String {
    // 1) Strip ANSI escape sequences (keeps plain text).
    // Covers CSI sequences like: ESC[31m, ESC[0m, ESC[2K, etc.
    let without_ansi = ansi_regex().replace_all(input, "");

    // 2) Normalize absolute paths under cwd to "<cwd>/...".
    let cwd = cwd.display().to_string();
    let cwd_backslashes = cwd.replace('/', "\\");
    let mut out = without_ansi.to_string();
    if !cwd.is_empty() {
        out = out.replace(&cwd, "<cwd>");
        out = out.replace(&cwd_backslashes, "<cwd>");
    }
    out
}

fn canonicalize_json_keys(value: &Value) -> Value {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json_keys).collect()),
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(value) = map.get(&key) {
                    out.insert(key, canonicalize_json_keys(value));
                }
            }
            Value::Object(out)
        }
    }
}

fn diff_key(value: &Value) -> String {
    let event = value
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    let correlation = value.get("correlation").and_then(Value::as_object);
    let (kind, id) = correlation
        .and_then(|corr| {
            preferred_correlation_id(corr, "tool_call_id", "tool_call_id")
                .or_else(|| preferred_correlation_id(corr, "slash_command_id", "slash_command_id"))
                .or_else(|| preferred_correlation_id(corr, "event_id", "event_id"))
                .or_else(|| preferred_correlation_id(corr, "host_call_id", "host_call_id"))
                .or_else(|| preferred_correlation_id(corr, "rpc_id", "rpc_id"))
                .or_else(|| preferred_correlation_id(corr, "scenario_id", "scenario_id"))
        })
        .unwrap_or(("id", "<missing>"));
    format!("{event}::{kind}:{id}")
}

fn preferred_correlation_id<'a>(
    corr: &'a serde_json::Map<String, Value>,
    key: &'static str,
    kind: &'static str,
) -> Option<(&'static str, &'a str)> {
    let id = corr.get(key).and_then(Value::as_str)?;
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    Some((kind, id))
}

fn diff_normalized_jsonl(
    expected_jsonl: &str,
    actual_jsonl: &str,
    cwd: &Path,
) -> Result<(), String> {
    let expected = parse_and_normalize_jsonl(expected_jsonl, cwd)?;
    let actual = parse_and_normalize_jsonl(actual_jsonl, cwd)?;

    let expected_groups = group_by_diff_key(&expected);
    let actual_groups = group_by_diff_key(&actual);

    let mut keys = BTreeSet::new();
    keys.extend(expected_groups.keys().cloned());
    keys.extend(actual_groups.keys().cloned());

    let mut problems = String::new();
    for key in keys {
        let expected_items = expected_groups.get(&key).cloned().unwrap_or_default();
        let actual_items = actual_groups.get(&key).cloned().unwrap_or_default();
        if expected_items == actual_items {
            continue;
        }

        let expected_text = render_group(&expected_items)?;
        let actual_text = render_group(&actual_items)?;
        let group_diff = render_text_diff(&expected_text, &actual_text);

        let _ = writeln!(problems, "\n=== DIFF GROUP: {key} ===");
        problems.push_str(&group_diff);
        problems.push('\n');
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

fn parse_and_normalize_jsonl(input: &str, cwd: &Path) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: Value = serde_json::from_str(line)
            .map_err(|err| format!("line {idx}: JSON parse error: {err}"))?;
        out.push(normalize_ext_log_line(parsed, cwd));
    }
    Ok(out)
}

fn group_by_diff_key(values: &[Value]) -> BTreeMap<String, Vec<Value>> {
    let mut groups: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for value in values {
        groups
            .entry(diff_key(value))
            .or_default()
            .push(value.clone());
    }
    groups
}

fn render_group(values: &[Value]) -> Result<String, String> {
    // Always render arrays so count/order differences are visible.
    serde_json::to_string_pretty(values).map_err(|err| err.to_string())
}

fn render_text_diff(expected: &str, actual: &str) -> String {
    let diff = similar::TextDiff::from_lines(expected, actual);
    let mut out = String::new();
    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        out.push_str(sign);
        out.push_str(change.value());
    }
    out
}

#[test]
fn normalizes_dynamic_fields_paths_and_ansi() {
    let cwd = Path::new("/tmp/pi_ext_conformance");
    let original = json!({
        "schema": "pi.ext.log.v1",
        "ts": "2026-02-03T03:01:02.123Z",
        "level": "info",
        "event": "tool_call.start",
        "message": format!("opened {} \u{1b}[31mERR\u{1b}[0m", cwd.join("file.txt").display()),
        "correlation": {
            "extension_id": "ext.demo",
            "scenario_id": "scn-001",
            "session_id": "sess-abc123",
            "run_id": "run-20260203-0001",
            "artifact_id": "sha256:deadbeef",
            "trace_id": "trace-xyz",
            "span_id": "span-123"
        },
        "source": { "component": "runtime", "host": "host.name", "pid": 4242 },
        "data": {
            "path": cwd.join("dir/sub/file.rs").display().to_string(),
            "note": "\u{1b}[1mBold\u{1b}[0m"
        }
    });

    let normalized = normalize_ext_log_line(original, cwd);

    assert_eq!(normalized["ts"], PLACEHOLDER_TS);
    assert_eq!(
        normalized["correlation"]["session_id"],
        PLACEHOLDER_SESSION_ID
    );
    assert_eq!(normalized["correlation"]["run_id"], PLACEHOLDER_RUN_ID);
    assert_eq!(
        normalized["correlation"]["artifact_id"],
        PLACEHOLDER_ARTIFACT_ID
    );
    assert_eq!(normalized["correlation"]["trace_id"], PLACEHOLDER_TRACE_ID);
    assert_eq!(normalized["correlation"]["span_id"], PLACEHOLDER_SPAN_ID);
    assert_eq!(normalized["source"]["host"], PLACEHOLDER_HOST);
    assert_eq!(normalized["source"]["pid"], 0);

    let msg = normalized["message"].as_str().unwrap_or_default();
    assert!(msg.contains("<cwd>/file.txt"));
    assert!(!msg.contains(&cwd.display().to_string()));
    assert!(!msg.contains("\u{1b}["));
    assert!(msg.contains("ERR"));

    let path = normalized["data"]["path"].as_str().unwrap_or_default();
    assert!(path.contains("<cwd>/dir/sub/file.rs"));
    assert!(!path.contains(&cwd.display().to_string()));

    assert_eq!(normalized["data"]["note"], "Bold");
}

#[test]
fn diff_key_prefers_most_specific_correlation_id() {
    let value = json!({
        "event": "tool_call.start",
        "correlation": {
            "scenario_id": "scn-001",
            "tool_call_id": "tool-42"
        }
    });

    assert_eq!(diff_key(&value), "tool_call.start::tool_call_id:tool-42");
}

#[test]
fn diff_normalized_jsonl_treats_dynamic_fields_as_equal() {
    let cwd = Path::new("/tmp/pi_ext_conformance");
    let expected = r#"
{"schema":"pi.ext.log.v1","ts":"2026-02-03T03:01:02.123Z","level":"info","event":"tool_call.start","message":"opened /tmp/pi_ext_conformance/file.txt","correlation":{"extension_id":"ext.demo","scenario_id":"scn-001","session_id":"sess-a","run_id":"run-a"},"source":{"component":"runtime","host":"a","pid":1}}
"#;
    let actual = r#"
{"schema":"pi.ext.log.v1","ts":"2026-02-03T03:01:02.999Z","level":"info","event":"tool_call.start","message":"opened /tmp/pi_ext_conformance/file.txt","correlation":{"extension_id":"ext.demo","scenario_id":"scn-001","session_id":"sess-b","run_id":"run-b"},"source":{"component":"runtime","host":"b","pid":9999}}
"#;

    diff_normalized_jsonl(expected, actual, cwd).unwrap();
}
