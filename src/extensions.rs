//! Extension protocol, policy, and runtime scaffolding.
//!
//! This module defines the versioned extension protocol and provides
//! validation utilities plus a minimal WASM host scaffold.

use crate::agent::AgentEvent;
use crate::connectors::Connector;
use crate::connectors::http::HttpConnector;
use crate::error::{Error, Result};
use crate::extension_events::{ToolCallEventResult, ToolResultEventResult};
use crate::extensions_js::{
    ExtensionRepairEvent, ExtensionToolDef, HostcallKind, HostcallRequest, PiJsRuntime,
    PiJsRuntimeConfig, js_to_json, json_to_js,
};
use crate::permissions::{PermissionStore, PersistedDecision};
use crate::scheduler::HostcallOutcome;
use crate::session::SessionMessage;
use crate::tools::ToolRegistry;
use asupersync::channel::{mpsc, oneshot};
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "wasm-host")]
use asupersync::sync::Mutex as AsyncMutex;
use asupersync::time::{sleep, timeout, wall_now};
use asupersync::{Budget, Cx};
use async_trait::async_trait;
use base64::Engine as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest as _;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;

/// Canonicalize a path, stripping the `\\?\` verbatim prefix on Windows.
///
/// `std::fs::canonicalize` on Windows returns extended-length paths (`\\?\C:\...`)
/// which break QuickJS module resolution and JS string interpolation. This helper
/// strips that prefix so paths remain compatible with downstream consumers.
pub fn safe_canonicalize(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    strip_unc_prefix(canonical)
}

/// Strip the `\\?\` or `//?/` verbatim prefix from a path on Windows. No-op on Unix.
#[allow(clippy::missing_const_for_fn)]
pub fn strip_unc_prefix(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(stripped);
        }
        // fd normalises separators to `/`, producing `//?/` instead of `\\?\`.
        if let Some(stripped) = s.strip_prefix("//?/") {
            return PathBuf::from(stripped);
        }
    }
    path
}

fn hostcall_params_hash(method: &str, params: &Value) -> String {
    fn canonicalize_json(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                let mut out = serde_json::Map::new();
                for key in keys {
                    if let Some(value) = map.get(&key) {
                        out.insert(key, canonicalize_json(value));
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
            other => other.clone(),
        }
    }

    let canonical = canonicalize_json(&json!({ "method": method, "params": params }));
    let encoded = serde_json::to_string(&canonical).expect("serialize canonical hostcall params");
    let mut hasher = sha2::Sha256::new();
    hasher.update(encoded.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hostcall_params_shape_hash(method: &str, params: &Value) -> String {
    fn shape_only(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                let mut out = serde_json::Map::new();
                for key in keys {
                    if let Some(value) = map.get(&key) {
                        out.insert(key, shape_only(value));
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(shape_only).collect()),
            Value::String(_) => Value::String("string".to_string()),
            Value::Number(_) => Value::String("number".to_string()),
            Value::Bool(_) => Value::String("bool".to_string()),
            Value::Null => Value::String("null".to_string()),
        }
    }

    let canonical = json!({
        "method": method,
        "params_shape": shape_only(params),
    });
    let encoded = serde_json::to_string(&canonical).unwrap_or_default();
    let mut hasher = sha2::Sha256::new();
    hasher.update(encoded.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub const PROTOCOL_VERSION: &str = "1.0";
pub const LOG_SCHEMA_VERSION: &str = "pi.ext.log.v1";
pub const COMPAT_LEDGER_SCHEMA_VERSION: &str = "pi.ext.compat_ledger.v1";
pub const RUNTIME_RISK_LEDGER_SCHEMA_VERSION: &str = "pi.ext.runtime_risk_ledger.v1";
pub const RUNTIME_RISK_REPLAY_SCHEMA_VERSION: &str = "pi.ext.runtime_risk_replay.v1";
pub const RUNTIME_RISK_CALIBRATION_SCHEMA_VERSION: &str = "pi.ext.runtime_risk_calibration.v1";
pub const RUNTIME_HOSTCALL_TELEMETRY_SCHEMA_VERSION: &str = "pi.ext.hostcall_telemetry.v1";
pub const RUNTIME_HOSTCALL_FEATURE_SCHEMA_VERSION: &str = "pi.ext.hostcall_feature_vector.v1";
pub const RUNTIME_HOSTCALL_FEATURE_BUDGET_US: u64 = 250;
pub const RUNTIME_RISK_EXPLANATION_SCHEMA_VERSION: &str = "pi.ext.runtime_risk_explanation.v1";
pub const RUNTIME_RISK_EXPLANATION_TERM_BUDGET: usize = 12;
pub const RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS: u64 = 2;
pub const RUNTIME_RISK_BASELINE_SCHEMA_VERSION: &str = "pi.ext.runtime_risk_baseline.v1";
const RUNTIME_HOSTCALL_SEQUENCE_WINDOW: usize = 64;
const CAPABILITY_MANIFEST_SCHEMA_V1: &str = "pi.ext.cap.v1";
const CAPABILITY_MANIFEST_SCHEMA_V2: &str = "pi.ext.cap.v2";

fn runtime_risk_explanation_schema_default() -> String {
    RUNTIME_RISK_EXPLANATION_SCHEMA_VERSION.to_string()
}

// ============================================================================
// Compatibility Scanner (bd-3bs)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatEvidence {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
}

impl CompatEvidence {
    #[must_use]
    pub const fn new(file: String, line: usize, column: usize, snippet: String) -> Self {
        Self {
            file,
            line,
            column,
            snippet,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatCapabilityEvidence {
    pub capability: String,
    pub reason: String,
    pub evidence: Vec<CompatEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatRewriteEvidence {
    pub from: String,
    pub to: String,
    pub evidence: Vec<CompatEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatIssueEvidence {
    pub rule: String,
    pub message: String,
    pub evidence: Vec<CompatEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatLedger {
    pub schema: String,
    pub capabilities: Vec<CompatCapabilityEvidence>,
    pub rewrites: Vec<CompatRewriteEvidence>,
    pub forbidden: Vec<CompatIssueEvidence>,
    pub flagged: Vec<CompatIssueEvidence>,
}

impl CompatLedger {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema: COMPAT_LEDGER_SCHEMA_VERSION.to_string(),
            capabilities: Vec::new(),
            rewrites: Vec::new(),
            forbidden: Vec::new(),
            flagged: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
            && self.rewrites.is_empty()
            && self.forbidden.is_empty()
            && self.flagged.is_empty()
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[derive(Debug, Clone)]
pub struct CompatibilityScanner {
    root: PathBuf,
}

const MARKER_IMPORT: u16 = 1 << 0;
const MARKER_REQUIRE: u16 = 1 << 1;
const MARKER_PI: u16 = 1 << 2;
const MARKER_PROCESS_ENV: u16 = 1 << 3;
const MARKER_PROCESS: u16 = 1 << 4;
const MARKER_FUNCTION: u16 = 1 << 5;
const MARKER_EVAL: u16 = 1 << 6;
const MARKER_BINDING: u16 = 1 << 7;
const MARKER_DLOPEN: u16 = 1 << 8;

impl CompatibilityScanner {
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn scan_path(&self, path: &Path) -> Result<CompatLedger> {
        let files = collect_js_like_files(path)?;
        Ok(self.scan_files(&files))
    }

    pub fn scan_root(&self) -> Result<CompatLedger> {
        self.scan_path(&self.root)
    }

    fn scan_files(&self, files: &[PathBuf]) -> CompatLedger {
        let mut caps: BTreeMap<(String, String, String), Vec<CompatEvidence>> = BTreeMap::new();
        let mut rewrites: BTreeMap<(String, String), Vec<CompatEvidence>> = BTreeMap::new();
        let mut forbidden: BTreeMap<(String, String, String), Vec<CompatEvidence>> =
            BTreeMap::new();
        let mut flagged: BTreeMap<(String, String, String), Vec<CompatEvidence>> = BTreeMap::new();

        for path in files {
            self.scan_file(path, &mut caps, &mut rewrites, &mut forbidden, &mut flagged);
        }

        let capabilities = caps
            .into_iter()
            .map(|((capability, reason, remediation), mut evidence)| {
                sort_evidence(&mut evidence);
                CompatCapabilityEvidence {
                    capability,
                    reason,
                    evidence,
                    remediation: if remediation.is_empty() {
                        None
                    } else {
                        Some(remediation)
                    },
                }
            })
            .collect();

        let rewrites = rewrites
            .into_iter()
            .map(|((from, to), mut evidence)| {
                sort_evidence(&mut evidence);
                CompatRewriteEvidence { from, to, evidence }
            })
            .collect();

        let forbidden = forbidden
            .into_iter()
            .map(|((rule, message, remediation), mut evidence)| {
                sort_evidence(&mut evidence);
                CompatIssueEvidence {
                    rule,
                    message,
                    evidence,
                    remediation: if remediation.is_empty() {
                        None
                    } else {
                        Some(remediation)
                    },
                }
            })
            .collect();

        let flagged = flagged
            .into_iter()
            .map(|((rule, message, remediation), mut evidence)| {
                sort_evidence(&mut evidence);
                CompatIssueEvidence {
                    rule,
                    message,
                    evidence,
                    remediation: if remediation.is_empty() {
                        None
                    } else {
                        Some(remediation)
                    },
                }
            })
            .collect();

        CompatLedger {
            schema: COMPAT_LEDGER_SCHEMA_VERSION.to_string(),
            capabilities,
            rewrites,
            forbidden,
            flagged,
        }
    }

    fn scan_file(
        &self,
        path: &Path,
        caps: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
        rewrites: &mut BTreeMap<(String, String), Vec<CompatEvidence>>,
        forbidden: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
        flagged: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
    ) {
        const LONG_LINE_COMMENT_BYPASS_LEN: usize = 4096;

        let Ok(content) = fs::read_to_string(path) else {
            return;
        };

        let rel = relative_posix(&self.root, path);
        let mut in_block_comment = false;

        for (idx, raw_line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let maybe_contains_comment = in_block_comment
                || (raw_line.as_bytes().contains(&b'/')
                    && (raw_line.contains("//") || raw_line.contains("/*")));
            let stripped = if maybe_contains_comment {
                Cow::Owned(strip_js_comments(raw_line, &mut in_block_comment))
            } else {
                Cow::Borrowed(raw_line)
            };
            let trimmed = stripped.trim_end();
            let raw_trimmed = raw_line.trim_end();

            // Comment stripping is line-oriented and intentionally lightweight. For very long
            // minified lines, regex literals can confuse comment stripping and truncate the line
            // before later import/require calls. For those cases, prefer raw text to avoid
            // dropping capability evidence from bundled artifacts.
            let scan_text = if raw_trimmed.len() >= LONG_LINE_COMMENT_BYPASS_LEN
                && trimmed.len() < raw_trimmed.len()
            {
                raw_trimmed
            } else {
                trimmed
            };

            if scan_text.is_empty() {
                continue;
            }

            let markers = Self::detect_scan_markers(scan_text);
            if markers & (MARKER_IMPORT | MARKER_REQUIRE) != 0 {
                Self::scan_imports_in_line(
                    &rel, line_no, scan_text, caps, rewrites, forbidden, flagged,
                );
            }

            if markers & (MARKER_PI | MARKER_PROCESS_ENV) != 0 {
                Self::scan_pi_apis_in_line(&rel, line_no, scan_text, caps);
            }

            if markers & (MARKER_FUNCTION | MARKER_EVAL) != 0 {
                Self::scan_flagged_apis_in_line(&rel, line_no, scan_text, flagged);
            }

            if (markers & MARKER_PROCESS) != 0 && (markers & (MARKER_BINDING | MARKER_DLOPEN) != 0)
            {
                Self::scan_forbidden_patterns_in_line(&rel, line_no, scan_text, forbidden);
            }
        }
    }

    #[must_use]
    fn detect_scan_markers(text: &str) -> u16 {
        let bytes = text.as_bytes();
        let mut markers = 0_u16;
        let mut idx = 0;

        while idx < bytes.len() {
            match bytes[idx] {
                b'i' if bytes[idx..].starts_with(b"import") => markers |= MARKER_IMPORT,
                b'r' if bytes[idx..].starts_with(b"require") => markers |= MARKER_REQUIRE,
                b'p' => {
                    if bytes[idx..].starts_with(b"pi") {
                        markers |= MARKER_PI;
                    }
                    if bytes[idx..].starts_with(b"process") {
                        markers |= MARKER_PROCESS;
                        if bytes[idx..].starts_with(b"process.env") {
                            markers |= MARKER_PROCESS_ENV;
                        }
                    }
                }
                b'F' if bytes[idx..].starts_with(b"Function") => markers |= MARKER_FUNCTION,
                b'e' if bytes[idx..].starts_with(b"eval") => markers |= MARKER_EVAL,
                b'b' if bytes[idx..].starts_with(b"binding") => markers |= MARKER_BINDING,
                b'd' if bytes[idx..].starts_with(b"dlopen") => markers |= MARKER_DLOPEN,
                _ => {}
            }

            if (markers & (MARKER_IMPORT | MARKER_REQUIRE) != 0)
                && (markers & (MARKER_PI | MARKER_PROCESS_ENV) != 0)
                && (markers & (MARKER_FUNCTION | MARKER_EVAL) != 0)
                && (markers & MARKER_PROCESS != 0)
                && (markers & (MARKER_BINDING | MARKER_DLOPEN) != 0)
            {
                break;
            }
            idx += 1;
        }

        markers
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_imports_in_line(
        file: &str,
        line: usize,
        text: &str,
        caps: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
        rewrites: &mut BTreeMap<(String, String), Vec<CompatEvidence>>,
        forbidden: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
        flagged: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
    ) {
        for (specifier, column) in extract_import_specifiers(text) {
            let evidence = CompatEvidence::new(file.to_string(), line, column, text.to_string());
            Self::classify_import(&specifier, evidence, caps, rewrites, forbidden, flagged);
        }

        for (specifier, column) in extract_require_specifiers(text) {
            let evidence = CompatEvidence::new(file.to_string(), line, column, text.to_string());
            Self::classify_import(&specifier, evidence, caps, rewrites, forbidden, flagged);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_import(
        specifier: &str,
        evidence: CompatEvidence,
        caps: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
        rewrites: &mut BTreeMap<(String, String), Vec<CompatEvidence>>,
        forbidden: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
        flagged: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
    ) {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return;
        }

        let normalized = specifier.strip_prefix("node:").unwrap_or(specifier);
        let module_root = normalized.split('/').next().unwrap_or(normalized);

        if let Some(forbidden_reason) = forbidden_builtin_reason(module_root) {
            forbidden
                .entry((
                    "forbidden_import".to_string(),
                    format!("import of forbidden builtin `{specifier}`"),
                    forbidden_reason.to_string(),
                ))
                .or_default()
                .push(evidence);
            return;
        }

        if let Some((to, inferred_caps, hint)) = rewrite_target_and_caps(normalized) {
            rewrites
                .entry((specifier.to_string(), to.to_string()))
                .or_default()
                .push(evidence.clone());

            for cap in inferred_caps {
                caps.entry((
                    cap.to_string(),
                    format!("import:{normalized}"),
                    hint.to_string(),
                ))
                .or_default()
                .push(evidence.clone());
            }
            return;
        }

        if looks_like_node_builtin(module_root) {
            flagged
                .entry((
                    "unsupported_import".to_string(),
                    format!("import of unsupported builtin `{specifier}`"),
                    "No extc rewrite contract entry; replace with pi APIs or add a generic rewrite rule."
                        .to_string(),
                ))
                .or_default()
                .push(evidence);
        }
    }

    fn scan_pi_apis_in_line(
        file: &str,
        line: usize,
        text: &str,
        caps: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
    ) {
        for (cap, reason, column) in extract_pi_capabilities(text) {
            let evidence = CompatEvidence::new(file.to_string(), line, column, text.to_string());
            caps.entry((cap, reason, String::new()))
                .or_default()
                .push(evidence);
        }

        if let Some(column) = find_substring_column(text, "process.env") {
            let evidence = CompatEvidence::new(file.to_string(), line, column, text.to_string());
            caps.entry((
                "env".to_string(),
                "process.env".to_string(),
                "Declare `env` capability (scoped) or avoid reading host env vars.".to_string(),
            ))
            .or_default()
            .push(evidence);
        }
    }

    fn scan_flagged_apis_in_line(
        file: &str,
        line: usize,
        text: &str,
        flagged: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
    ) {
        if text.contains("Function") {
            if let Some(column) = find_regex_column(text, new_function_regex()) {
                let evidence =
                    CompatEvidence::new(file.to_string(), line, column, text.to_string());
                flagged
                    .entry((
                        "flagged_api".to_string(),
                        "new Function(...)".to_string(),
                        "Avoid dynamic code generation when possible; prefer static bundling. If required, ensure the function body is a literal and keep it minimal."
                            .to_string(),
                    ))
                    .or_default()
                    .push(evidence);
            }
        }

        if text.contains("eval") {
            if let Some(column) = find_regex_column(text, eval_regex()) {
                let evidence =
                    CompatEvidence::new(file.to_string(), line, column, text.to_string());
                flagged
                    .entry((
                        "flagged_api".to_string(),
                        "eval(...)".to_string(),
                        "Avoid eval; prefer parsing/dispatch on structured data. If unavoidable, keep the evaluated string literal and log evidence."
                            .to_string(),
                    ))
                    .or_default()
                    .push(evidence);
            }
        }
    }

    fn scan_forbidden_patterns_in_line(
        file: &str,
        line: usize,
        text: &str,
        forbidden: &mut BTreeMap<(String, String, String), Vec<CompatEvidence>>,
    ) {
        if text.contains("process") {
            if text.contains("binding") {
                if let Some(column) = find_regex_column(text, binding_regex()) {
                    let evidence =
                        CompatEvidence::new(file.to_string(), line, column, text.to_string());
                    forbidden
                        .entry((
                            "forbidden_api".to_string(),
                            "process.binding(...)".to_string(),
                            "Native module access is forbidden; remove this usage.".to_string(),
                        ))
                        .or_default()
                        .push(evidence);
                }
            }

            if text.contains("dlopen") {
                if let Some(column) = find_regex_column(text, dlopen_regex()) {
                    let evidence =
                        CompatEvidence::new(file.to_string(), line, column, text.to_string());
                    forbidden
                        .entry((
                            "forbidden_api".to_string(),
                            "process.dlopen(...)".to_string(),
                            "Native addon loading is forbidden; remove this usage.".to_string(),
                        ))
                        .or_default()
                        .push(evidence);
                }
            }
        }
    }
}

fn collect_js_like_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        if is_js_like(path) {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    collect_js_like_files_recursive(path, &mut out)?;
    // Paths are all rooted under `path`, so sorting by the full `PathBuf`
    // yields the same deterministic order as sorting by relative string keys
    // without per-entry key allocation.
    out.sort_unstable();
    Ok(out)
}

fn collect_js_like_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut stack = vec![dir.to_path_buf()];

    while let Some(current_dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current_dir) else {
            continue; // Skip unreadable directories
        };

        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();

            if file_type.is_dir() {
                if should_ignore_dir(&path) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() && is_js_like(&path) {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn should_ignore_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(name, "node_modules" | "target" | "dist" | ".git")
}

fn is_js_like(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(ext, "ts" | "js" | "tsx" | "jsx" | "mts" | "cts")
}

fn relative_posix(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn sort_evidence(evidence: &mut [CompatEvidence]) {
    evidence.sort_by(|left, right| {
        (&left.file, left.line, left.column, &left.snippet).cmp(&(
            &right.file,
            right.line,
            right.column,
            &right.snippet,
        ))
    });
}

fn find_substring_column(haystack: &str, needle: &str) -> Option<usize> {
    haystack.find(needle).map(|idx| idx + 1)
}

fn find_regex_column(haystack: &str, regex: &Regex) -> Option<usize> {
    regex.find(haystack).map(|m| m.start() + 1)
}

fn import_from_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^\s*import(?:\s+type)?\s+[^;]*?\s+from\s+["']([^"']+)["']"#)
            .expect("import from regex")
    })
}

fn import_side_effect_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\s*import\s+["']([^"']+)["']"#).expect("import regex"))
}

fn import_dynamic_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bimport\s*\(\s*["']([^"']+)["']\s*\)"#).expect("import()"))
}

fn require_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\brequire\s*\(\s*["']([^"']+)["']\s*\)"#).expect("require"))
}

fn new_function_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bnew\s+Function\s*\(").expect("new Function"))
}

fn eval_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\beval\s*\(").expect("eval"))
}

fn pi_tool_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bpi\.tool\s*\(\s*["']([^"']+)["']"#).expect("pi.tool"))
}

fn pi_exec_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpi\.exec\s*\(").expect("pi.exec"))
}

fn pi_http_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpi\.http\s*\(").expect("pi.http"))
}

fn pi_log_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpi\.log\s*\(").expect("pi.log"))
}

fn pi_session_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpi\.session\.").expect("pi.session"))
}

fn pi_ui_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bpi\.ui\.").expect("pi.ui"))
}

fn binding_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"process\s*\.\s*binding\s*\(").expect("binding regex"))
}

fn dlopen_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"process\s*\.\s*dlopen\s*\(").expect("dlopen regex"))
}

const fn is_js_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn parse_top_level_import_specifier(line: &str) -> Option<(String, usize)> {
    let trimmed = line.trim_start();
    let leading_ws = line.len().saturating_sub(trimmed.len());
    let bytes = trimmed.as_bytes();

    if !trimmed.starts_with("import") {
        return None;
    }

    let mut idx = "import".len();
    if bytes.get(idx).is_some_and(|b| is_js_ident_continue(*b)) {
        return None;
    }

    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    if idx >= bytes.len() {
        return None;
    }

    // Optional `import type ...`.
    if trimmed[idx..].starts_with("type") {
        let after_type = idx + "type".len();
        if bytes
            .get(after_type)
            .is_some_and(|b| is_js_ident_continue(*b))
        {
            // Not a standalone `type` keyword.
        } else {
            let mut k = after_type;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k > after_type {
                idx = k;
            }
        }
    }

    if idx >= bytes.len() {
        return None;
    }

    // Side-effect import: `import "pkg"`.
    if matches!(bytes[idx], b'"' | b'\'') {
        let quote = bytes[idx];
        let start = idx + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end] != quote {
            end += 1;
        }
        if end < bytes.len() {
            let spec = trimmed[start..end].to_string();
            return Some((spec, leading_ws + start + 1));
        }
        return None;
    }

    // Standard import: `import ... from "pkg"`.
    let mut search_from = idx;
    while let Some(rel) = trimmed[search_from..].find("from") {
        let from_idx = search_from + rel;
        let after_from = from_idx + "from".len();
        let before_ok = from_idx == 0 || !is_js_ident_continue(bytes[from_idx - 1]);
        let after_ok = after_from >= bytes.len() || !is_js_ident_continue(bytes[after_from]);
        if before_ok && after_ok {
            let mut k = after_from;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < bytes.len() && matches!(bytes[k], b'"' | b'\'') {
                let quote = bytes[k];
                let start = k + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != quote {
                    end += 1;
                }
                if end < bytes.len() {
                    let spec = trimmed[start..end].to_string();
                    return Some((spec, leading_ws + start + 1));
                }
                return None;
            }
        }
        search_from = after_from;
    }

    None
}

fn extract_import_specifiers(line: &str) -> Vec<(String, usize)> {
    if !line.contains("import") {
        return Vec::new();
    }

    let mut out = Vec::new();

    let top_level = parse_top_level_import_specifier(line);
    if let Some((specifier, column)) = &top_level {
        out.push((specifier.clone(), *column));
    } else {
        if let Some(caps) = import_from_regex().captures(line) {
            if let Some(m) = caps.get(1) {
                out.push((m.as_str().to_string(), m.start() + 1));
            }
        }

        if let Some(caps) = import_side_effect_regex().captures(line) {
            if let Some(m) = caps.get(1) {
                out.push((m.as_str().to_string(), m.start() + 1));
            }
        }
    }

    if line.contains('(') {
        for caps in import_dynamic_regex().captures_iter(line) {
            if let Some(m) = caps.get(1) {
                let candidate = (m.as_str().to_string(), m.start() + 1);
                if !out.contains(&candidate) {
                    out.push(candidate);
                }
            }
        }
    }

    out
}

fn extract_require_specifiers(line: &str) -> Vec<(String, usize)> {
    if !line.contains("require") {
        return Vec::new();
    }

    if !line.contains('(') {
        return Vec::new();
    }

    let mut out = Vec::new();
    for caps in require_regex().captures_iter(line) {
        if let Some(m) = caps.get(1) {
            out.push((m.as_str().to_string(), m.start() + 1));
        }
    }

    out
}

fn extract_pi_capabilities(line: &str) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();

    if !line.contains("pi") {
        return out;
    }

    if line.contains("pi.tool") {
        for caps in pi_tool_regex().captures_iter(line) {
            let Some(tool) = caps.get(1) else { continue };
            let tool_name = tool.as_str().trim().to_ascii_lowercase();
            let (capability, reason) = match tool_name.as_str() {
                "read" | "grep" | "find" | "ls" => ("read", format!("pi.tool({tool_name})")),
                "write" | "edit" => ("write", format!("pi.tool({tool_name})")),
                "bash" => ("exec", "pi.tool(bash)".to_string()),
                _ => ("tool", format!("pi.tool({tool_name})")),
            };
            out.push((capability.to_string(), reason, tool.start() + 1));
        }
    }

    if line.contains("pi.exec") {
        if let Some(column) = find_regex_column(line, pi_exec_regex()) {
            out.push(("exec".to_string(), "pi.exec".to_string(), column));
        }
    }

    if line.contains("pi.http") {
        if let Some(column) = find_regex_column(line, pi_http_regex()) {
            out.push(("http".to_string(), "pi.http".to_string(), column));
        }
    }

    if line.contains("pi.log") {
        if let Some(column) = find_regex_column(line, pi_log_regex()) {
            out.push(("log".to_string(), "pi.log".to_string(), column));
        }
    }

    if line.contains("pi.session") {
        if let Some(column) = find_regex_column(line, pi_session_regex()) {
            out.push(("session".to_string(), "pi.session.*".to_string(), column));
        }
    }

    if line.contains("pi.ui") {
        if let Some(column) = find_regex_column(line, pi_ui_regex()) {
            out.push(("ui".to_string(), "pi.ui.*".to_string(), column));
        }
    }

    out
}

fn forbidden_builtin_reason(module_root: &str) -> Option<&'static str> {
    match module_root {
        "vm" => Some("Arbitrary code execution; use hostcalls only."),
        "worker_threads" | "cluster" => Some("Unsupported concurrency model; use PiJS scheduler."),
        "dgram" => Some("Raw UDP sockets are not supported."),
        "net" | "tls" => Some("Raw sockets bypass HTTP policy; use fetch/pi.http."),
        "inspector" => Some("Debugger access is not allowed."),
        "perf_hooks" => Some("Timing oracle; use host-provided timing APIs if needed."),
        "v8" => Some("Engine internals are not allowed."),
        "repl" => Some("Interactive eval is not allowed."),
        _ => None,
    }
}

fn rewrite_target_and_caps(
    normalized: &str,
) -> Option<(&'static str, Vec<&'static str>, &'static str)> {
    match normalized {
        "fs" | "node:fs" => Some((
            "pi:node/fs",
            vec!["read", "write"],
            "Extc rewrites to `pi:node/fs`; declare `read`/`write` capabilities or use `pi.tool(...)` directly.",
        )),
        "fs/promises" | "node:fs/promises" => Some((
            "pi:node/fs_promises",
            vec!["read", "write"],
            "Extc rewrites to `pi:node/fs_promises`; declare `read`/`write` capabilities or use `pi.tool(...)` directly.",
        )),
        "path" | "node:path" => Some((
            "pi:node/path",
            Vec::new(),
            "Extc rewrites to `pi:node/path` (pure).",
        )),
        "os" | "node:os" => Some((
            "pi:node/os",
            vec!["env"],
            "Extc rewrites to `pi:node/os`; declare `env` capability (scoped) when reading host-derived values.",
        )),
        "url" | "node:url" => Some((
            "pi:node/url",
            Vec::new(),
            "Extc rewrites to `pi:node/url` (pure).",
        )),
        "crypto" | "node:crypto" => Some((
            "pi:node/crypto",
            Vec::new(),
            "Extc rewrites to `pi:node/crypto` (pure).",
        )),
        "child_process" | "node:child_process" => Some((
            "pi:node/child_process",
            vec!["exec"],
            "Extc rewrites to `pi:node/child_process`; declare `exec` or use `pi.exec(...)`.",
        )),
        "module" | "node:module" => Some((
            "pi:node/module",
            Vec::new(),
            "Extc rewrites to `pi:node/module`.",
        )),
        _ => None,
    }
}

fn looks_like_node_builtin(module_root: &str) -> bool {
    // Heuristic: common Node builtin module names. If it matches, we treat it as a builtin.
    // This keeps the scanner conservative without needing a full Node builtin registry.
    matches!(
        module_root,
        "assert"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "dns"
            | "domain"
            | "events"
            | "fs"
            | "http"
            | "https"
            | "inspector"
            | "module"
            | "net"
            | "os"
            | "path"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "repl"
            | "stream"
            | "string_decoder"
            | "sys"
            | "timers"
            | "tls"
            | "tty"
            | "url"
            | "util"
            | "v8"
            | "vm"
            | "worker_threads"
            | "zlib"
    )
}

/// Strip single-line (`//`) and block (`/* ... */`) JS comments from a line,
/// respecting string literals (double/single/backtick).
///
/// `in_block_comment` carries block-comment state across lines.
fn strip_js_comments(line: &str, in_block_comment: &mut bool) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if *in_block_comment {
            if ch == '*' && matches!(chars.peek(), Some('/')) {
                chars.next();
                *in_block_comment = false;
            }
            continue;
        }

        if escaped {
            result.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && (in_single_quote || in_double_quote || in_template) {
            result.push(ch);
            escaped = true;
            continue;
        }

        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            }
            result.push(ch);
            continue;
        }

        if in_double_quote {
            if ch == '"' {
                in_double_quote = false;
            }
            result.push(ch);
            continue;
        }

        if in_template {
            if ch == '`' {
                in_template = false;
            }
            result.push(ch);
            continue;
        }

        match ch {
            '/' if matches!(chars.peek(), Some('/')) => break,
            '/' if matches!(chars.peek(), Some('*')) => {
                chars.next();
                *in_block_comment = true;
            }
            '\'' => {
                in_single_quote = true;
                result.push(ch);
            }
            '"' => {
                in_double_quote = true;
                result.push(ch);
            }
            '`' => {
                in_template = true;
                result.push(ch);
            }
            _ => result.push(ch),
        }
    }

    result
}

#[cfg(test)]
mod compatibility_scanner_comment_tests {
    use super::{CompatibilityScanner, strip_js_comments};
    use std::fs;

    #[test]
    fn strip_js_comments_keeps_comment_markers_inside_strings() {
        let mut in_block_comment = false;
        let line = r#"const code = "import('fs') // not a comment"; // real comment"#;
        let stripped = strip_js_comments(line, &mut in_block_comment);
        assert_eq!(
            stripped.trim(),
            r#"const code = "import('fs') // not a comment";"#
        );
        assert!(!in_block_comment);
    }

    #[test]
    fn compatibility_scanner_ignores_commented_patterns() {
        let temp = tempfile::tempdir().expect("tempdir");
        let entry = temp.path().join("commented.js");
        fs::write(
            &entry,
            r#"
// import fs from "fs";
// pi.exec("echo should-not-count");
/* process.binding("fs");
   eval("bad");
*/
"#,
        )
        .expect("write test file");

        let scanner = CompatibilityScanner::new(temp.path().to_path_buf());
        let ledger = scanner.scan_path(&entry).expect("scan");

        assert!(ledger.capabilities.is_empty());
        assert!(ledger.rewrites.is_empty());
        assert!(ledger.forbidden.is_empty());
        assert!(ledger.flagged.is_empty());
    }

    #[test]
    fn compatibility_scanner_still_reports_live_code_with_nearby_comments() {
        let temp = tempfile::tempdir().expect("tempdir");
        let entry = temp.path().join("mixed.js");
        fs::write(
            &entry,
            r#"
/* import child_process from "child_process"; */
import fs from "fs"; // real import
pi.exec("echo hello");
"#,
        )
        .expect("write test file");

        let scanner = CompatibilityScanner::new(temp.path().to_path_buf());
        let ledger = scanner.scan_path(&entry).expect("scan");

        assert_eq!(
            ledger.rewrites.len(),
            1,
            "live fs import should be rewritten"
        );
        assert!(
            ledger
                .rewrites
                .iter()
                .any(|rewrite| rewrite.from == "fs" && rewrite.to == "pi:node/fs")
        );
        assert!(
            ledger
                .capabilities
                .iter()
                .any(|cap| cap.capability == "read")
        );
        assert!(
            ledger
                .capabilities
                .iter()
                .any(|cap| cap.capability == "write")
        );
        assert!(
            ledger
                .capabilities
                .iter()
                .any(|cap| cap.capability == "exec")
        );
        assert!(ledger.forbidden.is_empty());
        assert!(ledger.flagged.is_empty());
    }

    #[test]
    fn compatibility_scanner_keeps_late_requires_in_minified_lines() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let sample =
            repo_root.join("tests/ext_conformance/artifacts/doom-overlay/doom/build/doom.js");
        let sample_content = fs::read_to_string(&sample).expect("read minified sample bundle");

        let temp = tempfile::tempdir().expect("tempdir");
        let entry = temp.path().join("bundle.js");
        fs::write(&entry, sample_content).expect("write bundle sample");

        let scanner = CompatibilityScanner::new(temp.path().to_path_buf());
        let ledger = scanner.scan_path(&entry).expect("scan");

        assert!(
            ledger
                .capabilities
                .iter()
                .any(|cap| cap.capability == "exec" && cap.reason == "import:child_process"),
            "minified bundle should still infer exec capability from child_process require"
        );
    }
}

// ============================================================================
// Policy
// ============================================================================

// ---------------------------------------------------------------------------
// Capability taxonomy
// ---------------------------------------------------------------------------

/// Enumeration of all recognised extension capabilities.
///
/// Each variant maps 1-to-1 with a string token used in policy configuration
/// (e.g. `"read"`, `"exec"`). The canonical string is the
/// `#[serde(rename_all = "snake_case")]` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read files and directories.
    Read,
    /// Write / create / delete files and directories.
    Write,
    /// Outbound HTTP requests.
    Http,
    /// Subscribe to and emit lifecycle events.
    Events,
    /// Access session state (messages, model, labels, etc.).
    Session,
    /// UI operations (status, widgets, notifications).
    Ui,
    /// Execute shell commands (dangerous).
    Exec,
    /// Read environment variables (dangerous — may leak secrets).
    Env,
    /// Generic tool invocation.
    Tool,
    /// Logging (always allowed, included for completeness).
    Log,
}

/// All known capabilities in definition order.
pub const ALL_CAPABILITIES: &[Capability] = &[
    Capability::Read,
    Capability::Write,
    Capability::Http,
    Capability::Events,
    Capability::Session,
    Capability::Ui,
    Capability::Exec,
    Capability::Env,
    Capability::Tool,
    Capability::Log,
];

impl Capability {
    /// Parse a string token into a [`Capability`], case-insensitive.
    /// Returns `None` for unrecognised tokens.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "http" => Some(Self::Http),
            "events" => Some(Self::Events),
            "session" => Some(Self::Session),
            "ui" => Some(Self::Ui),
            "exec" => Some(Self::Exec),
            "env" => Some(Self::Env),
            "tool" => Some(Self::Tool),
            "log" => Some(Self::Log),
            _ => None,
        }
    }

    /// Canonical string token (matches serde rename).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Http => "http",
            Self::Events => "events",
            Self::Session => "session",
            Self::Ui => "ui",
            Self::Exec => "exec",
            Self::Env => "env",
            Self::Tool => "tool",
            Self::Log => "log",
        }
    }

    /// Whether this capability is classified as *dangerous*.
    ///
    /// Dangerous capabilities default to Deny in Strict/Prompt modes and
    /// require explicit opt-in or user confirmation.
    pub const fn is_dangerous(self) -> bool {
        matches!(self, Self::Exec | Self::Env)
    }

    /// List of all dangerous capabilities.
    pub const fn dangerous_list() -> &'static [Self] {
        &[Self::Exec, Self::Env]
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Policy profile presets
// ---------------------------------------------------------------------------

/// Named policy profiles providing curated defaults.
///
/// Profiles are convenience constructors for [`ExtensionPolicy`] — once
/// constructed the policy is fully mutable and can be further customised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    /// Safe defaults: only non-dangerous capabilities allowed, dangerous
    /// denied. Mode = Strict.
    Safe,
    /// Standard defaults (current production behaviour): non-dangerous
    /// allowed, dangerous prompt. Mode = Prompt.
    Standard,
    /// Everything allowed, nothing denied. Mode = Permissive.
    Permissive,
}

impl PolicyProfile {
    /// Expand this profile into a concrete [`ExtensionPolicy`].
    pub fn to_policy(self) -> ExtensionPolicy {
        match self {
            Self::Safe => ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "http".to_string(),
                    "events".to_string(),
                    "session".to_string(),
                ],
                deny_caps: vec!["exec".to_string(), "env".to_string()],
                per_extension: HashMap::new(),
                exec_mediation: ExecMediationPolicy::strict(),
                secret_broker: SecretBrokerPolicy::default(),
            },
            Self::Standard => ExtensionPolicy::default(),
            Self::Permissive => ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                per_extension: HashMap::new(),
                exec_mediation: ExecMediationPolicy::permissive(),
                secret_broker: SecretBrokerPolicy::default(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Per-extension overrides
// ---------------------------------------------------------------------------

/// Per-extension policy override.
///
/// When present for an extension ID, these fields take precedence over the
/// global policy fields at the corresponding layer in the precedence chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionOverride {
    /// Mode override for this extension. `None` inherits the global mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ExtensionPolicyMode>,
    /// Additional capabilities to allow for this extension (merged with
    /// global `default_caps`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Additional capabilities to deny for this extension (merged with
    /// global `deny_caps`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Per-extension resource quota overrides (SEC-4.1).
    /// `None` inherits the global quota defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<ExtensionQuotaConfig>,
}

// ---------------------------------------------------------------------------
// Core policy types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionPolicyMode {
    Strict,
    Prompt,
    Permissive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RepairPolicyMode {
    Off,
    Suggest,
    AutoSafe,
    AutoStrict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionPolicy {
    pub mode: ExtensionPolicyMode,
    pub max_memory_mb: u32,
    pub default_caps: Vec<String>,
    pub deny_caps: Vec<String>,
    /// Per-extension overrides keyed by extension ID.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub per_extension: HashMap<String, ExtensionOverride>,
    /// Exec mediation policy (SEC-4.3). Controls command-level allow/deny
    /// after capability-level exec is granted.
    #[serde(default)]
    pub exec_mediation: ExecMediationPolicy,
    /// Secret broker policy (SEC-4.3). Controls redaction of secret env vars
    /// and prevents raw disclosure when policy forbids it.
    #[serde(default)]
    pub secret_broker: SecretBrokerPolicy,
}

impl Default for ExtensionPolicy {
    fn default() -> Self {
        Self {
            mode: ExtensionPolicyMode::Prompt,
            max_memory_mb: 256,
            default_caps: vec![
                "read".to_string(),
                "write".to_string(),
                "http".to_string(),
                "events".to_string(),
                "session".to_string(),
            ],
            deny_caps: vec!["exec".to_string(), "env".to_string()],
            per_extension: HashMap::new(),
            exec_mediation: ExecMediationPolicy::default(),
            secret_broker: SecretBrokerPolicy::default(),
        }
    }
}

/// Deterministic runtime risk-controller settings for extension hostcalls.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeRiskConfig {
    /// Master switch for runtime risk decisions.
    pub enabled: bool,
    /// Type-I error budget for sequential detection (0 < alpha < 1).
    pub alpha: f64,
    /// Sliding-window size for residual/drift checks.
    pub window_size: usize,
    /// Max in-memory entries retained in the risk evidence ledger.
    pub ledger_limit: usize,
    /// Max decision budget per hostcall (ms) before fallback action.
    pub decision_timeout_ms: u64,
    /// If true, controller failures/timeouts fail closed.
    pub fail_closed: bool,
}

impl Default for RuntimeRiskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            alpha: 0.01,
            window_size: 128,
            ledger_limit: 2048,
            decision_timeout_ms: 50,
            fail_closed: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-extension resource quota engine (SEC-4.1 / bd-b1d7o)
// ---------------------------------------------------------------------------

/// Configurable per-extension resource quotas. When a quota is `None`, the
/// corresponding limit is not enforced. All values are per-extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionQuotaConfig {
    /// Maximum hostcalls permitted per 1-second sliding window.
    pub max_hostcalls_per_second: Option<u32>,
    /// Maximum hostcalls permitted per 60-second sliding window.
    pub max_hostcalls_per_minute: Option<u32>,
    /// Maximum total hostcalls before the extension is throttled.
    pub max_hostcalls_total: Option<u64>,
    /// Maximum concurrent subprocesses spawned via exec hostcalls.
    pub max_subprocesses: Option<u32>,
    /// Maximum cumulative bytes written via fs/write hostcalls.
    pub max_write_bytes: Option<u64>,
    /// Maximum cumulative HTTP requests issued via http hostcalls.
    pub max_http_requests: Option<u64>,
}

impl Default for ExtensionQuotaConfig {
    fn default() -> Self {
        Self::for_mode(ExtensionPolicyMode::Prompt)
    }
}

impl ExtensionQuotaConfig {
    /// Create quota defaults appropriate for a given policy mode.
    ///
    /// - **Strict**: restrictive burst/rate limits and low subprocess fan-out.
    /// - **Prompt**: moderate defaults (original baseline).
    /// - **Permissive**: relaxed limits for trusted extensions.
    #[must_use]
    pub const fn for_mode(mode: ExtensionPolicyMode) -> Self {
        match mode {
            ExtensionPolicyMode::Strict => Self {
                max_hostcalls_per_second: Some(20),
                max_hostcalls_per_minute: Some(500),
                max_hostcalls_total: Some(5_000),
                max_subprocesses: Some(4),
                max_write_bytes: Some(50 * 1024 * 1024), // 50 MB
                max_http_requests: Some(200),
            },
            ExtensionPolicyMode::Prompt => Self {
                max_hostcalls_per_second: Some(100),
                max_hostcalls_per_minute: Some(2_000),
                max_hostcalls_total: None,
                max_subprocesses: Some(8),
                max_write_bytes: None,
                max_http_requests: None,
            },
            ExtensionPolicyMode::Permissive => Self {
                max_hostcalls_per_second: Some(500),
                max_hostcalls_per_minute: Some(10_000),
                max_hostcalls_total: None,
                max_subprocesses: Some(32),
                max_write_bytes: None,
                max_http_requests: None,
            },
        }
    }
}

/// Mutable per-extension quota counters, reset semantics:
/// - `hostcall_timestamps_ms` is a sliding window (entries expire by time).
/// - `hostcalls_total` and cumulative counters are monotonic (session-lifetime).
/// - `active_subprocesses` increments on spawn, decrements on exit.
#[derive(Debug, Clone, Default)]
struct ExtensionQuotaState {
    hostcall_timestamps_ms: VecDeque<i64>,
    hostcalls_total: u64,
    active_subprocesses: u32,
    write_bytes_total: u64,
    http_requests_total: u64,
}

/// Telemetry event emitted when a quota limit is breached.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaBreachEvent {
    /// Unix epoch milliseconds when the breach was detected.
    pub ts_ms: i64,
    /// Extension that triggered the breach.
    pub extension_id: String,
    /// Capability being requested (e.g. "exec", "http", "write").
    pub capability: String,
    /// Human-readable reason for the breach.
    pub reason: String,
    /// Source of the quota config: "per_extension" or "global".
    pub quota_config_source: String,
}

/// Result of a quota check before dispatching a hostcall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaCheckResult {
    /// Within quota — proceed.
    Allowed,
    /// Quota exceeded — deny with reason.
    Exceeded { reason: String },
}

/// Check per-extension quotas. Returns [`QuotaCheckResult::Exceeded`] if any
/// configured limit is breached. Called in the dispatch chokepoint before
/// the runtime risk evaluation.
fn check_extension_quota(
    config: &ExtensionQuotaConfig,
    state: &mut ExtensionQuotaState,
    now_ms: i64,
    capability: &str,
) -> QuotaCheckResult {
    // 1. Prune expired timestamps (older than 60s).
    let horizon_60s = now_ms.saturating_sub(60_000);
    while state
        .hostcall_timestamps_ms
        .front()
        .is_some_and(|&ts| ts < horizon_60s)
    {
        state.hostcall_timestamps_ms.pop_front();
    }

    // 2. Record this call.
    state.hostcall_timestamps_ms.push_back(now_ms);
    state.hostcalls_total += 1;

    // 3. Per-second burst check.
    if let Some(max_per_sec) = config.max_hostcalls_per_second {
        let horizon_1s = now_ms.saturating_sub(1_000);
        let count_1s = state
            .hostcall_timestamps_ms
            .iter()
            .rev()
            .take_while(|&&ts| ts >= horizon_1s)
            .count();
        if count_1s > max_per_sec as usize {
            return QuotaCheckResult::Exceeded {
                reason: format!("hostcall rate {count_1s}/s exceeds limit {max_per_sec}/s"),
            };
        }
    }

    // 4. Per-minute rate check.
    if let Some(max_per_min) = config.max_hostcalls_per_minute {
        let count_60s = state.hostcall_timestamps_ms.len();
        if count_60s > max_per_min as usize {
            return QuotaCheckResult::Exceeded {
                reason: format!("hostcall rate {count_60s}/60s exceeds limit {max_per_min}/60s"),
            };
        }
    }

    // 5. Total hostcall budget.
    if let Some(max_total) = config.max_hostcalls_total {
        if state.hostcalls_total > max_total {
            return QuotaCheckResult::Exceeded {
                reason: format!(
                    "total hostcalls {} exceeds limit {max_total}",
                    state.hostcalls_total
                ),
            };
        }
    }

    // 6. Subprocess fan-out (only relevant for exec capability).
    if capability == "exec" {
        if let Some(max_sub) = config.max_subprocesses {
            if state.active_subprocesses >= max_sub {
                return QuotaCheckResult::Exceeded {
                    reason: format!(
                        "active subprocesses {} reaches limit {max_sub}",
                        state.active_subprocesses
                    ),
                };
            }
        }
    }

    // 7. HTTP request budget.
    if capability == "http" {
        if let Some(max_http) = config.max_http_requests {
            if state.http_requests_total >= max_http {
                return QuotaCheckResult::Exceeded {
                    reason: format!(
                        "HTTP requests {} exceeds limit {max_http}",
                        state.http_requests_total
                    ),
                };
            }
            state.http_requests_total += 1;
        }
    }

    // 8. Write bytes budget (tracked externally via record_write_bytes).
    if capability == "write" {
        if let Some(max_wb) = config.max_write_bytes {
            if state.write_bytes_total >= max_wb {
                return QuotaCheckResult::Exceeded {
                    reason: format!(
                        "write bytes {} exceeds limit {max_wb}",
                        state.write_bytes_total
                    ),
                };
            }
        }
    }

    QuotaCheckResult::Allowed
}

// ---------------------------------------------------------------------------
// Exec mediation and secret broker (SEC-4.3 / bd-zh0hj)
// ---------------------------------------------------------------------------

/// Classification of dangerous command patterns for exec mediation.
///
/// Each variant represents a class of commands that pose a security risk when
/// executed by an extension. The classifier is deterministic: given the same
/// command string, the same classification is always returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DangerousCommandClass {
    /// Recursive deletion targeting root or broad paths (`rm -rf /`).
    RecursiveDelete,
    /// Device-level writes (`dd`, `mkfs`, `fdisk`).
    DeviceWrite,
    /// Fork bomb or process exhaustion patterns.
    ForkBomb,
    /// Pipe to shell execution (`curl | sh`, `wget | bash`).
    PipeToShell,
    /// System shutdown or reboot commands.
    SystemShutdown,
    /// Broad permission changes (`chmod 777`, `chmod -R 777`).
    PermissionEscalation,
    /// Killing critical system processes (`kill -9 1`, `pkill init`).
    ProcessTermination,
    /// Modifying /etc/passwd, /etc/shadow, or sudoers.
    CredentialFileModification,
    /// Disk wipe or overwrite patterns (`shred`, `wipefs`).
    DiskWipe,
    /// Network exfiltration via raw sockets or reverse shells.
    ReverseShell,
}

impl DangerousCommandClass {
    /// Human-readable label for incident logging.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RecursiveDelete => "recursive_delete",
            Self::DeviceWrite => "device_write",
            Self::ForkBomb => "fork_bomb",
            Self::PipeToShell => "pipe_to_shell",
            Self::SystemShutdown => "system_shutdown",
            Self::PermissionEscalation => "permission_escalation",
            Self::ProcessTermination => "process_termination",
            Self::CredentialFileModification => "credential_file_modification",
            Self::DiskWipe => "disk_wipe",
            Self::ReverseShell => "reverse_shell",
        }
    }

    /// Risk tier for this command class (used for policy decisions).
    #[must_use]
    pub const fn risk_tier(self) -> ExecRiskTier {
        match self {
            Self::RecursiveDelete
            | Self::DeviceWrite
            | Self::ForkBomb
            | Self::DiskWipe
            | Self::ReverseShell => ExecRiskTier::Critical,
            Self::PipeToShell
            | Self::SystemShutdown
            | Self::PermissionEscalation
            | Self::ProcessTermination
            | Self::CredentialFileModification => ExecRiskTier::High,
        }
    }
}

/// Risk tier for exec command classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecRiskTier {
    /// Low risk — normal commands.
    Low,
    /// Medium risk — commands that could be misused.
    Medium,
    /// High risk — commands with significant destructive potential.
    High,
    /// Critical risk — commands that could cause irreversible damage.
    Critical,
}

/// Policy configuration for exec mediation (SEC-4.3).
///
/// Controls which commands are allowed/denied based on pattern matching
/// and dangerous command classification. Evaluated after capability-level
/// policy and quota checks but before the actual command is spawned.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecMediationPolicy {
    /// When true, exec mediation is active and commands are classified.
    pub enabled: bool,
    /// Minimum risk tier that triggers a deny (default: Critical).
    /// Commands at or above this tier are blocked.
    pub deny_threshold: ExecRiskTier,
    /// Explicit command prefixes to deny (case-insensitive substring match).
    /// These are checked before the built-in classifier.
    #[serde(default)]
    pub deny_patterns: Vec<String>,
    /// Explicit command prefixes to allow even if classified as dangerous.
    /// Use sparingly — allows overriding the classifier for specific tools.
    #[serde(default)]
    pub allow_patterns: Vec<String>,
    /// When true, commands classified as dangerous are logged even if allowed.
    pub audit_all_classified: bool,
}

impl Default for ExecMediationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_threshold: ExecRiskTier::Critical,
            deny_patterns: Vec::new(),
            allow_patterns: Vec::new(),
            audit_all_classified: true,
        }
    }
}

impl ExecMediationPolicy {
    /// Strict preset: blocks High and above.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            enabled: true,
            deny_threshold: ExecRiskTier::High,
            deny_patterns: Vec::new(),
            allow_patterns: Vec::new(),
            audit_all_classified: true,
        }
    }

    /// Permissive preset: only blocks Critical.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            enabled: true,
            deny_threshold: ExecRiskTier::Critical,
            deny_patterns: Vec::new(),
            allow_patterns: Vec::new(),
            audit_all_classified: false,
        }
    }

    /// Disabled preset: no exec mediation.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            deny_threshold: ExecRiskTier::Critical,
            deny_patterns: Vec::new(),
            allow_patterns: Vec::new(),
            audit_all_classified: false,
        }
    }
}

/// Result of exec mediation evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecMediationResult {
    /// Command is allowed to proceed.
    Allow,
    /// Command is allowed but was classified as potentially dangerous.
    AllowWithAudit {
        class: DangerousCommandClass,
        reason: String,
    },
    /// Command is denied.
    Deny {
        class: Option<DangerousCommandClass>,
        reason: String,
    },
}

/// Classify a command string into dangerous command classes.
///
/// Returns all matching classifications. A command may match multiple
/// classes (e.g., a reverse shell that also pipes to shell).
/// The classifier is deterministic and case-insensitive.
#[must_use]
pub fn classify_dangerous_command(cmd: &str, args: &[String]) -> Vec<DangerousCommandClass> {
    let mut classes = Vec::new();
    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", args.join(" "))
    };
    let lower = full_cmd.to_ascii_lowercase();

    // --- Critical tier ---

    // Recursive delete targeting root or broad paths.
    if classify_recursive_delete(&lower) {
        classes.push(DangerousCommandClass::RecursiveDelete);
    }

    // Device-level writes.
    if classify_device_write(&lower) {
        classes.push(DangerousCommandClass::DeviceWrite);
    }

    // Fork bomb patterns.
    if classify_fork_bomb(&lower) {
        classes.push(DangerousCommandClass::ForkBomb);
    }

    // Disk wipe.
    if classify_disk_wipe(&lower) {
        classes.push(DangerousCommandClass::DiskWipe);
    }

    // Reverse shell.
    if classify_reverse_shell(&lower) {
        classes.push(DangerousCommandClass::ReverseShell);
    }

    // --- High tier ---

    // Pipe to shell.
    if classify_pipe_to_shell(&lower) {
        classes.push(DangerousCommandClass::PipeToShell);
    }

    // System shutdown.
    if classify_system_shutdown(&lower) {
        classes.push(DangerousCommandClass::SystemShutdown);
    }

    // Permission escalation.
    if classify_permission_escalation(&lower) {
        classes.push(DangerousCommandClass::PermissionEscalation);
    }

    // Process termination of critical processes.
    if classify_process_termination(&lower) {
        classes.push(DangerousCommandClass::ProcessTermination);
    }

    // Credential file modification.
    if classify_credential_file_modification(&lower) {
        classes.push(DangerousCommandClass::CredentialFileModification);
    }

    classes
}

fn classify_recursive_delete(lower: &str) -> bool {
    // rm -rf / or rm -rf /* or rm -rf ~
    if !lower.contains("rm") {
        return false;
    }
    let has_rf = lower.contains("-rf") || lower.contains("-fr") || lower.contains("--recursive");
    if !has_rf {
        return false;
    }
    // Target root, home, or wildcard
    let dangerous_targets = [" /", " /*", " ~/", " ~/*", " --no-preserve-root"];
    dangerous_targets.iter().any(|t| lower.contains(t))
}

fn classify_device_write(lower: &str) -> bool {
    // dd writing to devices, mkfs, fdisk
    let dd_to_dev = lower.contains("dd ") && lower.contains("of=/dev/");
    let mkfs = lower.starts_with("mkfs") || lower.contains(" mkfs") || lower.contains(";mkfs");
    let fdisk = lower.starts_with("fdisk") || lower.contains(" fdisk") || lower.contains(";fdisk");
    dd_to_dev || mkfs || fdisk
}

fn classify_fork_bomb(lower: &str) -> bool {
    // Classic bash fork bomb: :(){ :|:& };:
    // Also: while true; do ... & done
    lower.contains(":(){ :|:&")
        || lower.contains(":(){ :|: &")
        || (lower.contains("while true") && lower.contains("& done"))
        || (lower.contains("fork") && lower.contains("while") && lower.contains('&'))
}

fn classify_disk_wipe(lower: &str) -> bool {
    let shred = lower.starts_with("shred") || lower.contains(" shred ") || lower.contains(";shred");
    let wipefs =
        lower.starts_with("wipefs") || lower.contains(" wipefs") || lower.contains(";wipefs");
    let dd_zero = lower.contains("dd ") && lower.contains("if=/dev/zero");
    let dd_urandom = lower.contains("dd ") && lower.contains("if=/dev/urandom");
    shred || wipefs || dd_zero || dd_urandom
}

fn classify_reverse_shell(lower: &str) -> bool {
    // Common reverse shell patterns
    let bash_rev = lower.contains("/dev/tcp/") && lower.contains("bash");
    let nc_rev = (lower.contains("nc ") || lower.contains("ncat ") || lower.contains("netcat "))
        && lower.contains("-e ");
    let python_rev = lower.contains("socket") && lower.contains("connect") && lower.contains("sh");
    bash_rev || nc_rev || python_rev
}

fn classify_pipe_to_shell(lower: &str) -> bool {
    // curl/wget piped to sh/bash
    let has_download = lower.contains("curl ") || lower.contains("wget ");
    let has_pipe_to_shell = lower.contains("| sh")
        || lower.contains("| bash")
        || lower.contains("|sh")
        || lower.contains("|bash")
        || lower.contains("| /bin/sh")
        || lower.contains("| /bin/bash");
    has_download && has_pipe_to_shell
}

fn classify_system_shutdown(lower: &str) -> bool {
    lower.starts_with("shutdown")
        || lower.contains(" shutdown")
        || lower.contains(";shutdown")
        || lower.starts_with("reboot")
        || lower.contains(" reboot")
        || lower.contains(";reboot")
        || lower.starts_with("halt")
        || lower.contains(" halt")
        || lower.contains(";halt")
        || lower.starts_with("poweroff")
        || lower.contains(" poweroff")
        || lower.contains(";poweroff")
        || lower.starts_with("init 0")
        || lower.contains(" init 0")
        || lower.starts_with("init 6")
        || lower.contains(" init 6")
}

fn classify_permission_escalation(lower: &str) -> bool {
    // chmod 777, chmod -R 777, chown root
    let chmod_broad = lower.contains("chmod")
        && (lower.contains("777") || lower.contains("a+rwx") || lower.contains("o+w"));
    let chmod_suid = lower.contains("chmod") && (lower.contains("+s") || lower.contains("4755"));
    chmod_broad || chmod_suid
}

fn classify_process_termination(lower: &str) -> bool {
    // kill -9 1, pkill init, killall
    let kill_pid1 = lower.contains("kill") && (lower.contains(" 1 ") || lower.ends_with(" 1"));
    let kill_9 = lower.contains("kill -9") || lower.contains("kill -kill");
    let pkill_critical = lower.contains("pkill")
        && (lower.contains("init") || lower.contains("systemd") || lower.contains("sshd"));
    let killall = lower.starts_with("killall") || lower.contains(" killall");
    // Only flag kill of PID 1 or critical processes
    (kill_pid1 && kill_9) || pkill_critical || killall
}

fn classify_credential_file_modification(lower: &str) -> bool {
    let cred_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
    ];
    let write_cmds = ["tee ", "cat >", "echo >", "sed -i", "cp ", "mv "];
    cred_files
        .iter()
        .any(|f| lower.contains(f) && write_cmds.iter().any(|w| lower.contains(w)))
}

/// Evaluate exec mediation policy for a command.
///
/// Called after capability-level policy allows exec, but before spawning.
/// Returns [`ExecMediationResult`] indicating whether the command should
/// proceed, be audited, or be denied.
#[must_use]
pub fn evaluate_exec_mediation(
    policy: &ExecMediationPolicy,
    cmd: &str,
    args: &[String],
) -> ExecMediationResult {
    if !policy.enabled {
        return ExecMediationResult::Allow;
    }

    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", args.join(" "))
    };
    let lower = full_cmd.to_ascii_lowercase();

    // 1. Check explicit allow patterns (highest precedence override).
    for pattern in &policy.allow_patterns {
        if lower.contains(&pattern.to_ascii_lowercase()) {
            return ExecMediationResult::Allow;
        }
    }

    // 2. Check explicit deny patterns.
    for pattern in &policy.deny_patterns {
        if lower.contains(&pattern.to_ascii_lowercase()) {
            return ExecMediationResult::Deny {
                class: None,
                reason: format!("Command matches deny pattern: {pattern}"),
            };
        }
    }

    // 3. Classify via built-in rules.
    let classes = classify_dangerous_command(cmd, args);
    if classes.is_empty() {
        return ExecMediationResult::Allow;
    }

    // Find the highest-risk classification.
    let worst = classes
        .iter()
        .max_by_key(|c| c.risk_tier())
        .copied()
        .expect("classes is non-empty");

    if worst.risk_tier() >= policy.deny_threshold {
        ExecMediationResult::Deny {
            class: Some(worst),
            reason: format!(
                "Command classified as {} ({})",
                worst.label(),
                worst.risk_tier().label()
            ),
        }
    } else if policy.audit_all_classified {
        ExecMediationResult::AllowWithAudit {
            class: worst,
            reason: format!(
                "Command classified as {} ({}) — below deny threshold",
                worst.label(),
                worst.risk_tier().label()
            ),
        }
    } else {
        ExecMediationResult::Allow
    }
}

impl ExecRiskTier {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

// ---------------------------------------------------------------------------
// Secret broker (SEC-4.3 / bd-zh0hj)
// ---------------------------------------------------------------------------

/// Patterns used to identify environment variables likely to contain secrets.
///
/// The broker uses suffix and prefix matching to catch common naming
/// conventions for API keys, tokens, passwords, and credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretBrokerPolicy {
    /// When true, the secret broker is active.
    pub enabled: bool,
    /// Env var name suffixes that indicate a secret (case-insensitive).
    pub secret_suffixes: Vec<String>,
    /// Env var name prefixes that indicate a secret (case-insensitive).
    pub secret_prefixes: Vec<String>,
    /// Exact env var names that are always treated as secrets (case-insensitive).
    pub secret_exact: Vec<String>,
    /// Env vars on this list are never redacted, even if they match a pattern.
    pub disclosure_allowlist: Vec<String>,
    /// The replacement string used in place of secret values.
    pub redaction_placeholder: String,
}

impl Default for SecretBrokerPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            secret_suffixes: vec![
                "_KEY".to_string(),
                "_SECRET".to_string(),
                "_TOKEN".to_string(),
                "_PASSWORD".to_string(),
                "_PASSWD".to_string(),
                "_CREDENTIAL".to_string(),
                "_CREDENTIALS".to_string(),
                "_AUTH".to_string(),
                "_API_KEY".to_string(),
                "_PRIVATE_KEY".to_string(),
            ],
            secret_prefixes: vec![
                "SECRET_".to_string(),
                "AUTH_".to_string(),
                "CREDENTIAL_".to_string(),
            ],
            secret_exact: vec![
                "ANTHROPIC_API_KEY".to_string(),
                "OPENAI_API_KEY".to_string(),
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "AWS_SESSION_TOKEN".to_string(),
                "GITHUB_TOKEN".to_string(),
                "GOOGLE_API_KEY".to_string(),
                "AZURE_CLIENT_SECRET".to_string(),
                "DATABASE_URL".to_string(),
                "REDIS_URL".to_string(),
                "PRIVATE_KEY".to_string(),
                "NPM_TOKEN".to_string(),
                "DOCKER_PASSWORD".to_string(),
                "SLACK_TOKEN".to_string(),
                "STRIPE_SECRET_KEY".to_string(),
                "TWILIO_AUTH_TOKEN".to_string(),
                "SENDGRID_API_KEY".to_string(),
            ],
            disclosure_allowlist: Vec::new(),
            redaction_placeholder: "[REDACTED]".to_string(),
        }
    }
}

impl SecretBrokerPolicy {
    /// Returns `true` if the given env var name matches a known secret pattern.
    #[must_use]
    pub fn is_secret(&self, name: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // Check disclosure allowlist first (overrides everything).
        if self
            .disclosure_allowlist
            .iter()
            .any(|a| a.eq_ignore_ascii_case(name))
        {
            return false;
        }

        let upper = name.to_ascii_uppercase();

        // Exact match.
        if self
            .secret_exact
            .iter()
            .any(|e| e.eq_ignore_ascii_case(name))
        {
            return true;
        }

        // Suffix match.
        if self
            .secret_suffixes
            .iter()
            .any(|s| upper.ends_with(&s.to_ascii_uppercase()))
        {
            return true;
        }

        // Prefix match.
        self.secret_prefixes
            .iter()
            .any(|p| upper.starts_with(&p.to_ascii_uppercase()))
    }

    /// Redact a value if the env var name is a secret.
    ///
    /// Returns the original value if not a secret, or the redaction
    /// placeholder if it is.
    #[must_use]
    pub fn maybe_redact<'a>(&'a self, name: &str, value: &'a str) -> &'a str {
        if self.is_secret(name) {
            &self.redaction_placeholder
        } else {
            value
        }
    }
}

/// Redact secrets in a command string for safe logging.
///
/// Scans for patterns like `KEY=value` and replaces the value portion
/// for any key that matches the secret broker policy. Also redacts
/// inline `-p password` style arguments.
#[must_use]
pub fn redact_command_for_logging(policy: &SecretBrokerPolicy, cmd: &str) -> String {
    if !policy.enabled {
        return cmd.to_string();
    }
    let mut result = cmd.to_string();

    // Redact KEY=VALUE patterns in env-style assignments.
    // Matches: SOME_KEY=somevalue or SOME_KEY="somevalue"
    for part in cmd.split_whitespace() {
        if let Some(eq_pos) = part.find('=') {
            let key = &part[..eq_pos];
            if policy.is_secret(key) {
                let replacement = format!("{key}={}", policy.redaction_placeholder);
                result = result.replace(part, &replacement);
            }
        }
    }

    result
}

/// Telemetry entry for exec mediation decisions.
#[derive(Debug, Clone, Serialize)]
pub struct ExecMediationLedgerEntry {
    /// Unix epoch milliseconds.
    pub ts_ms: i64,
    /// Extension that requested exec.
    pub extension_id: Option<String>,
    /// Hash of the command (never log raw command).
    pub command_hash: String,
    /// Dangerous command class if classified.
    pub command_class: Option<String>,
    /// Risk tier of the classification.
    pub risk_tier: Option<String>,
    /// Mediation decision.
    pub decision: String,
    /// Human-readable reason.
    pub reason: String,
}

/// Telemetry entry for secret broker decisions.
#[derive(Debug, Clone, Serialize)]
pub struct SecretBrokerLedgerEntry {
    /// Unix epoch milliseconds.
    pub ts_ms: i64,
    /// Extension requesting env access.
    pub extension_id: Option<String>,
    /// Hash of the env var name (never log raw name for denied vars).
    pub name_hash: String,
    /// Whether the value was redacted.
    pub redacted: bool,
    /// Reason for redaction or disclosure.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRiskStateLabelValue {
    SafeFast,
    Suspicious,
    Unsafe,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRiskActionValue {
    Allow,
    Harden,
    Deny,
    Terminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskPosteriorEvidence {
    pub safe_fast: f64,
    pub suspicious: f64,
    #[serde(rename = "unsafe")]
    pub unsafe_: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskExpectedLossEvidence {
    pub allow: f64,
    pub harden: f64,
    pub deny: f64,
    pub terminate: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRiskExplanationLevelValue {
    Compact,
    #[default]
    Standard,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskExplanationContributor {
    pub code: String,
    pub signed_impact: f64,
    pub magnitude: f64,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeRiskExplanationBudgetState {
    pub time_budget_ms: u64,
    pub elapsed_ms: u64,
    pub term_budget: usize,
    pub terms_emitted: usize,
    pub exhausted: bool,
    pub fallback_mode: bool,
}

impl Default for RuntimeRiskExplanationBudgetState {
    fn default() -> Self {
        Self {
            time_budget_ms: RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
            elapsed_ms: 0,
            term_budget: RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            terms_emitted: 0,
            exhausted: false,
            fallback_mode: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskLedgerArtifactEntry {
    pub ts_ms: i64,
    pub extension_id: String,
    pub call_id: String,
    pub capability: String,
    pub method: String,
    pub params_hash: String,
    pub policy_reason: String,
    pub risk_score: f64,
    pub posterior: RuntimeRiskPosteriorEvidence,
    pub expected_loss: RuntimeRiskExpectedLossEvidence,
    pub selected_action: RuntimeRiskActionValue,
    pub derived_state: RuntimeRiskStateLabelValue,
    pub triggers: Vec<String>,
    pub fallback_reason: Option<String>,
    pub e_process: f64,
    pub e_threshold: f64,
    pub conformal_residual: f64,
    pub conformal_quantile: f64,
    pub drift_detected: bool,
    pub outcome_error_code: Option<String>,
    #[serde(default = "runtime_risk_explanation_schema_default")]
    pub explanation_schema: String,
    #[serde(default)]
    pub explanation_level: RuntimeRiskExplanationLevelValue,
    #[serde(default)]
    pub explanation_summary: String,
    #[serde(default)]
    pub top_contributors: Vec<RuntimeRiskExplanationContributor>,
    #[serde(default)]
    pub budget_state: RuntimeRiskExplanationBudgetState,
    pub ledger_hash: String,
    pub prev_ledger_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskLedgerArtifact {
    pub schema: String,
    pub generated_at_ms: i64,
    pub entry_count: usize,
    pub head_ledger_hash: Option<String>,
    pub tail_ledger_hash: Option<String>,
    pub data_hash: String,
    pub entries: Vec<RuntimeRiskLedgerArtifactEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeRiskLedgerIntegrityError {
    pub index: usize,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeRiskLedgerVerificationReport {
    pub schema: String,
    pub entry_count: usize,
    pub head_ledger_hash: Option<String>,
    pub tail_ledger_hash: Option<String>,
    pub artifact_data_hash: String,
    pub computed_data_hash: String,
    pub valid: bool,
    pub errors: Vec<RuntimeRiskLedgerIntegrityError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskReplayStep {
    pub index: usize,
    pub call_id: String,
    pub extension_id: String,
    pub capability: String,
    pub method: String,
    pub policy_reason: String,
    pub selected_action: RuntimeRiskActionValue,
    pub derived_state: RuntimeRiskStateLabelValue,
    pub risk_score: f64,
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub explanation_level: RuntimeRiskExplanationLevelValue,
    #[serde(default)]
    pub explanation_summary: String,
    #[serde(default)]
    pub top_contributors: Vec<RuntimeRiskExplanationContributor>,
    #[serde(default)]
    pub budget_state: RuntimeRiskExplanationBudgetState,
    pub fallback_reason: Option<String>,
    pub drift_detected: bool,
    pub e_process: f64,
    pub e_threshold: f64,
    pub conformal_residual: f64,
    pub conformal_quantile: f64,
    pub ledger_hash: String,
    pub prev_ledger_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskReplayArtifact {
    pub schema: String,
    pub source_schema: String,
    pub source_data_hash: String,
    pub entry_count: usize,
    pub tail_ledger_hash: Option<String>,
    pub steps: Vec<RuntimeRiskReplayStep>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRiskCalibrationObjective {
    MinExpectedLoss,
    MinFalsePositives,
    #[default]
    BalancedAccuracy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskThresholdCalibration {
    pub threshold: f64,
    pub objective_score: f64,
    pub expected_loss: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RuntimeRiskCalibrationConfig {
    pub objective: RuntimeRiskCalibrationObjective,
    pub baseline_threshold: f64,
    pub threshold_grid: Vec<f64>,
    pub false_positive_weight: f64,
    pub false_negative_weight: f64,
}

impl Default for RuntimeRiskCalibrationConfig {
    fn default() -> Self {
        let threshold_grid = (1..=19).map(|step| f64::from(step) * 0.05_f64).collect();
        Self {
            objective: RuntimeRiskCalibrationObjective::BalancedAccuracy,
            baseline_threshold: 0.65,
            threshold_grid,
            false_positive_weight: 1.0,
            false_negative_weight: 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskCalibrationReport {
    pub schema: String,
    pub source_schema: String,
    pub source_data_hash: String,
    pub objective: RuntimeRiskCalibrationObjective,
    pub baseline_threshold: f64,
    pub recommended_threshold: f64,
    pub recommended_delta: f64,
    pub baseline: RuntimeRiskThresholdCalibration,
    pub recommended: RuntimeRiskThresholdCalibration,
    pub candidates: Vec<RuntimeRiskThresholdCalibration>,
}

// ============================================================================
// Baseline Modeling (bd-153pv)
// ============================================================================

/// Per-capability robust statistics from approved traces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineCapabilityProfile {
    /// Capability name (e.g. "log", "exec", "http").
    pub capability: String,
    /// Number of observations.
    pub sample_count: usize,
    /// Median of risk scores.
    pub risk_score_median: f64,
    /// Median Absolute Deviation of risk scores.
    pub risk_score_mad: f64,
    /// 5th percentile of risk scores.
    pub risk_score_p5: f64,
    /// 95th percentile of risk scores.
    pub risk_score_p95: f64,
    /// Median error rate across calls.
    pub error_rate_median: f64,
    /// Median burst density (1s window).
    pub burst_density_1s_median: f64,
    /// Median burst density (10s window).
    pub burst_density_10s_median: f64,
}

/// Markov transition matrix over risk state labels.
///
/// States: `SafeFast`=0, `Suspicious`=1, `Unsafe`=2.
/// `counts[i][j]` = number of observed transitions from state `i` to state `j`.
/// `probabilities[i][j]` = smoothed transition probability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineMarkovTransitionMatrix {
    /// Raw transition counts `[from][to]`, 3x3.
    pub counts: [[u64; 3]; 3],
    /// Smoothed probabilities `[from][to]`, 3x3. Rows sum to 1.0.
    pub probabilities: [[f64; 3]; 3],
    /// Dirichlet smoothing prior per cell (default: 1.0).
    pub smoothing_prior: f64,
    /// Total transitions observed.
    pub total_transitions: u64,
    /// Stationary distribution `[SafeFast, Suspicious, Unsafe]`.
    pub stationary_distribution: [f64; 3],
}

/// Single drift anomaly detected when comparing live features to baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineDriftAnomaly {
    /// Which metric deviated (e.g. "risk_score", "error_rate", "burst_density_1s").
    pub metric: String,
    /// Observed value.
    pub observed: f64,
    /// Baseline median for this metric.
    pub baseline_median: f64,
    /// Baseline MAD for this metric.
    pub baseline_mad: f64,
    /// Number of MAD units from median (z-score analog).
    pub deviation_mads: f64,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Result of comparing live features against a baseline model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineDriftReport {
    /// Extension ID this report pertains to.
    pub extension_id: String,
    /// Capability being evaluated.
    pub capability: String,
    /// Whether any anomaly exceeded the threshold.
    pub drift_detected: bool,
    /// Individual anomalies found.
    pub anomalies: Vec<BaselineDriftAnomaly>,
    /// Markov transition anomaly score (KL divergence from baseline).
    pub transition_divergence: f64,
    /// Whether transition pattern is anomalous (KL > threshold).
    pub transition_anomalous: bool,
}

/// Complete baseline model for an extension, built from approved traces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRiskBaselineModel {
    /// Schema version.
    pub schema: String,
    /// Extension ID this baseline covers.
    pub extension_id: String,
    /// Timestamp when baseline was generated (ms since epoch).
    pub generated_at_ms: i64,
    /// Source data hash from the ledger used to build this baseline.
    pub source_data_hash: String,
    /// Number of ledger entries used to build the baseline.
    pub source_entry_count: usize,
    /// Per-capability robust statistics.
    pub capability_profiles: Vec<BaselineCapabilityProfile>,
    /// Markov transition matrix over risk states.
    pub transition_matrix: BaselineMarkovTransitionMatrix,
    /// MAD deviation threshold for flagging anomalies (default: 3.0).
    pub anomaly_threshold_mads: f64,
    /// KL divergence threshold for transition anomalies (default: 0.5).
    pub transition_divergence_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct RuntimeHostcallSequenceContext {
    pub sequence_id: u64,
    pub previous_capability: Option<String>,
    pub previous_method: Option<String>,
    pub previous_resource_target_class: Option<String>,
    pub burst_count_1s: u32,
    pub burst_count_10s: u32,
    pub recent_error_count: u32,
    pub recent_window_count: u32,
    pub prior_failure_streak: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RuntimeHostcallFeatureVector {
    pub schema: String,
    pub base_score: f64,
    pub recent_mean_score: f64,
    pub recent_error_rate: f64,
    pub burst_density_1s: f64,
    pub burst_density_10s: f64,
    pub prior_failure_streak_norm: f64,
    pub dangerous_capability: f64,
    pub timeout_requested: f64,
    pub policy_prompt_bias: f64,
}

impl Default for RuntimeHostcallFeatureVector {
    fn default() -> Self {
        Self {
            schema: RUNTIME_HOSTCALL_FEATURE_SCHEMA_VERSION.to_string(),
            base_score: 0.0,
            recent_mean_score: 0.0,
            recent_error_rate: 0.0,
            burst_density_1s: 0.0,
            burst_density_10s: 0.0,
            prior_failure_streak_norm: 0.0,
            dangerous_capability: 0.0,
            timeout_requested: 0.0,
            policy_prompt_bias: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RuntimeHostcallTelemetryEvent {
    pub schema: String,
    pub ts_ms: i64,
    pub extension_id: String,
    pub call_id: String,
    pub capability: String,
    pub method: String,
    pub params_hash: String,
    pub args_shape_hash: String,
    pub resource_target_class: String,
    pub policy_reason: String,
    pub policy_profile: String,
    pub risk_score: f64,
    pub timeout_ms: Option<u64>,
    pub latency_ms: u64,
    pub outcome: String,
    pub outcome_error_code: Option<String>,
    pub selected_action: RuntimeRiskActionValue,
    pub reason_codes: Vec<String>,
    pub explanation_level: RuntimeRiskExplanationLevelValue,
    pub explanation_summary: String,
    pub top_contributors: Vec<RuntimeRiskExplanationContributor>,
    pub budget_state: RuntimeRiskExplanationBudgetState,
    pub sequence: RuntimeHostcallSequenceContext,
    pub features: RuntimeHostcallFeatureVector,
    pub extraction_latency_us: u64,
    pub extraction_budget_us: u64,
    pub extraction_budget_exceeded: bool,
    pub redaction_summary: String,
}

impl Default for RuntimeHostcallTelemetryEvent {
    fn default() -> Self {
        Self {
            schema: RUNTIME_HOSTCALL_TELEMETRY_SCHEMA_VERSION.to_string(),
            ts_ms: 0,
            extension_id: String::new(),
            call_id: String::new(),
            capability: String::new(),
            method: String::new(),
            params_hash: String::new(),
            args_shape_hash: String::new(),
            resource_target_class: "unknown".to_string(),
            policy_reason: String::new(),
            policy_profile: String::new(),
            risk_score: 0.0,
            timeout_ms: None,
            latency_ms: 0,
            outcome: "success".to_string(),
            outcome_error_code: None,
            selected_action: RuntimeRiskActionValue::Allow,
            reason_codes: Vec::new(),
            explanation_level: RuntimeRiskExplanationLevelValue::Standard,
            explanation_summary: "no explanation generated".to_string(),
            top_contributors: Vec::new(),
            budget_state: RuntimeRiskExplanationBudgetState::default(),
            sequence: RuntimeHostcallSequenceContext::default(),
            features: RuntimeHostcallFeatureVector::default(),
            extraction_latency_us: 0,
            extraction_budget_us: RUNTIME_HOSTCALL_FEATURE_BUDGET_US,
            extraction_budget_exceeded: false,
            redaction_summary: "params redacted via hash-only telemetry".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RuntimeHostcallTelemetryArtifact {
    pub schema: String,
    pub generated_at_ms: i64,
    pub entry_count: usize,
    pub entries: Vec<RuntimeHostcallTelemetryEvent>,
}

impl Default for RuntimeHostcallTelemetryArtifact {
    fn default() -> Self {
        Self {
            schema: RUNTIME_HOSTCALL_TELEMETRY_SCHEMA_VERSION.to_string(),
            generated_at_ms: 0,
            entry_count: 0,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RuntimeRiskStateLabel {
    SafeFast,
    Suspicious,
    Unsafe,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RuntimeRiskAction {
    Allow,
    Harden,
    Deny,
    Terminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeRiskPosterior {
    safe_fast: f64,
    suspicious: f64,
    unsafe_: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeRiskExpectedLoss {
    allow: f64,
    harden: f64,
    deny: f64,
    terminate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeRiskLedgerEntry {
    ts_ms: i64,
    extension_id: String,
    call_id: String,
    capability: String,
    method: String,
    params_hash: String,
    policy_reason: String,
    risk_score: f64,
    posterior: RuntimeRiskPosterior,
    expected_loss: RuntimeRiskExpectedLoss,
    selected_action: RuntimeRiskAction,
    derived_state: RuntimeRiskStateLabel,
    triggers: Vec<String>,
    fallback_reason: Option<String>,
    e_process: f64,
    e_threshold: f64,
    conformal_residual: f64,
    conformal_quantile: f64,
    drift_detected: bool,
    outcome_error_code: Option<String>,
    explanation_schema: String,
    explanation_level: RuntimeRiskExplanationLevelValue,
    explanation_summary: String,
    top_contributors: Vec<RuntimeRiskExplanationContributor>,
    budget_state: RuntimeRiskExplanationBudgetState,
    ledger_hash: String,
    prev_ledger_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct RuntimeRiskDecision {
    action: RuntimeRiskAction,
    reason: String,
    capability: String,
    method: String,
    params_hash: String,
    args_shape_hash: String,
    resource_target_class: String,
    policy_profile: String,
    timeout_ms: Option<u64>,
    risk_score: f64,
    posterior: RuntimeRiskPosterior,
    expected_loss: RuntimeRiskExpectedLoss,
    e_process: f64,
    e_threshold: f64,
    conformal_residual: f64,
    conformal_quantile: f64,
    drift_detected: bool,
    triggers: Vec<String>,
    explanation_schema: String,
    explanation_level: RuntimeRiskExplanationLevelValue,
    explanation_summary: String,
    top_contributors: Vec<RuntimeRiskExplanationContributor>,
    budget_state: RuntimeRiskExplanationBudgetState,
    fallback_reason: Option<String>,
    elapsed_ms: u64,
    state_label: RuntimeRiskStateLabel,
    sequence_context: RuntimeHostcallSequenceContext,
    features: RuntimeHostcallFeatureVector,
    feature_extraction_latency_us: u64,
    feature_budget_exceeded: bool,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeRiskCallMetadata<'a> {
    args_shape_hash: &'a str,
    resource_target_class: &'a str,
    timeout_ms: Option<u64>,
    policy_profile: &'a str,
}

#[derive(Debug, Clone)]
struct RuntimeRiskState {
    alpha_safe: f64,
    alpha_suspicious: f64,
    alpha_unsafe: f64,
    log_e_process: f64,
    recent_scores: VecDeque<f64>,
    recent_call_timestamps_ms: VecDeque<i64>,
    recent_outcome_errors: VecDeque<bool>,
    residual_window: VecDeque<f64>,
    previous_residual_quantile: f64,
    consecutive_unsafe: u32,
    consecutive_failures: u32,
    quarantined: bool,
    last_decision: Option<RuntimeRiskAction>,
    last_capability: Option<String>,
    last_method: Option<String>,
    last_resource_target_class: Option<String>,
    sequence_counter: u64,
}

impl Default for RuntimeRiskState {
    fn default() -> Self {
        Self {
            alpha_safe: 8.0,
            alpha_suspicious: 1.5,
            alpha_unsafe: 0.5,
            log_e_process: 0.0,
            recent_scores: VecDeque::new(),
            recent_call_timestamps_ms: VecDeque::new(),
            recent_outcome_errors: VecDeque::new(),
            residual_window: VecDeque::new(),
            previous_residual_quantile: 0.0,
            consecutive_unsafe: 0,
            consecutive_failures: 0,
            quarantined: false,
            last_decision: None,
            last_capability: None,
            last_method: None,
            last_resource_target_class: None,
            sequence_counter: 0,
        }
    }
}

impl From<RuntimeRiskStateLabel> for RuntimeRiskStateLabelValue {
    fn from(value: RuntimeRiskStateLabel) -> Self {
        match value {
            RuntimeRiskStateLabel::SafeFast => Self::SafeFast,
            RuntimeRiskStateLabel::Suspicious => Self::Suspicious,
            RuntimeRiskStateLabel::Unsafe => Self::Unsafe,
        }
    }
}

impl From<RuntimeRiskStateLabelValue> for RuntimeRiskStateLabel {
    fn from(value: RuntimeRiskStateLabelValue) -> Self {
        match value {
            RuntimeRiskStateLabelValue::SafeFast => Self::SafeFast,
            RuntimeRiskStateLabelValue::Suspicious => Self::Suspicious,
            RuntimeRiskStateLabelValue::Unsafe => Self::Unsafe,
        }
    }
}

impl From<RuntimeRiskAction> for RuntimeRiskActionValue {
    fn from(value: RuntimeRiskAction) -> Self {
        match value {
            RuntimeRiskAction::Allow => Self::Allow,
            RuntimeRiskAction::Harden => Self::Harden,
            RuntimeRiskAction::Deny => Self::Deny,
            RuntimeRiskAction::Terminate => Self::Terminate,
        }
    }
}

impl From<RuntimeRiskActionValue> for RuntimeRiskAction {
    fn from(value: RuntimeRiskActionValue) -> Self {
        match value {
            RuntimeRiskActionValue::Allow => Self::Allow,
            RuntimeRiskActionValue::Harden => Self::Harden,
            RuntimeRiskActionValue::Deny => Self::Deny,
            RuntimeRiskActionValue::Terminate => Self::Terminate,
        }
    }
}

impl From<&RuntimeRiskPosterior> for RuntimeRiskPosteriorEvidence {
    fn from(value: &RuntimeRiskPosterior) -> Self {
        Self {
            safe_fast: value.safe_fast,
            suspicious: value.suspicious,
            unsafe_: value.unsafe_,
        }
    }
}

impl From<&RuntimeRiskExpectedLoss> for RuntimeRiskExpectedLossEvidence {
    fn from(value: &RuntimeRiskExpectedLoss) -> Self {
        Self {
            allow: value.allow,
            harden: value.harden,
            deny: value.deny,
            terminate: value.terminate,
        }
    }
}

impl From<&RuntimeRiskLedgerEntry> for RuntimeRiskLedgerArtifactEntry {
    fn from(value: &RuntimeRiskLedgerEntry) -> Self {
        Self {
            ts_ms: value.ts_ms,
            extension_id: value.extension_id.clone(),
            call_id: value.call_id.clone(),
            capability: value.capability.clone(),
            method: value.method.clone(),
            params_hash: value.params_hash.clone(),
            policy_reason: value.policy_reason.clone(),
            risk_score: value.risk_score,
            posterior: RuntimeRiskPosteriorEvidence::from(&value.posterior),
            expected_loss: RuntimeRiskExpectedLossEvidence::from(&value.expected_loss),
            selected_action: RuntimeRiskActionValue::from(value.selected_action),
            derived_state: RuntimeRiskStateLabelValue::from(value.derived_state),
            triggers: value.triggers.clone(),
            fallback_reason: value.fallback_reason.clone(),
            e_process: value.e_process,
            e_threshold: value.e_threshold,
            conformal_residual: value.conformal_residual,
            conformal_quantile: value.conformal_quantile,
            drift_detected: value.drift_detected,
            outcome_error_code: value.outcome_error_code.clone(),
            explanation_schema: value.explanation_schema.clone(),
            explanation_level: value.explanation_level,
            explanation_summary: value.explanation_summary.clone(),
            top_contributors: value.top_contributors.clone(),
            budget_state: value.budget_state.clone(),
            ledger_hash: value.ledger_hash.clone(),
            prev_ledger_hash: value.prev_ledger_hash.clone(),
        }
    }
}

impl From<&RuntimeRiskLedgerArtifactEntry> for RuntimeRiskLedgerEntry {
    fn from(value: &RuntimeRiskLedgerArtifactEntry) -> Self {
        Self {
            ts_ms: value.ts_ms,
            extension_id: value.extension_id.clone(),
            call_id: value.call_id.clone(),
            capability: value.capability.clone(),
            method: value.method.clone(),
            params_hash: value.params_hash.clone(),
            policy_reason: value.policy_reason.clone(),
            risk_score: value.risk_score,
            posterior: RuntimeRiskPosterior {
                safe_fast: value.posterior.safe_fast,
                suspicious: value.posterior.suspicious,
                unsafe_: value.posterior.unsafe_,
            },
            expected_loss: RuntimeRiskExpectedLoss {
                allow: value.expected_loss.allow,
                harden: value.expected_loss.harden,
                deny: value.expected_loss.deny,
                terminate: value.expected_loss.terminate,
            },
            selected_action: RuntimeRiskAction::from(value.selected_action),
            derived_state: RuntimeRiskStateLabel::from(value.derived_state),
            triggers: value.triggers.clone(),
            fallback_reason: value.fallback_reason.clone(),
            e_process: value.e_process,
            e_threshold: value.e_threshold,
            conformal_residual: value.conformal_residual,
            conformal_quantile: value.conformal_quantile,
            drift_detected: value.drift_detected,
            outcome_error_code: value.outcome_error_code.clone(),
            explanation_schema: value.explanation_schema.clone(),
            explanation_level: value.explanation_level,
            explanation_summary: value.explanation_summary.clone(),
            top_contributors: value.top_contributors.clone(),
            budget_state: value.budget_state.clone(),
            ledger_hash: value.ledger_hash.clone(),
            prev_ledger_hash: value.prev_ledger_hash.clone(),
        }
    }
}

fn runtime_risk_now_ms() -> i64 {
    i64::try_from(wall_now().as_millis()).unwrap_or(i64::MAX)
}

#[allow(clippy::missing_const_for_fn)]
fn runtime_risk_clamp01(value: f64) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

fn runtime_risk_is_dangerous(capability: &str) -> bool {
    matches!(capability, "exec" | "env" | "http")
}

fn runtime_risk_base_score(capability: &str, method: &str, policy_reason: &str) -> f64 {
    let capability_score = match capability {
        "exec" => 0.95,
        "env" => 0.85,
        "http" => 0.70,
        "write" => 0.45,
        "tool" => 0.50,
        "session" => 0.35,
        "events" => 0.30,
        "ui" => 0.20,
        "read" => 0.15,
        _ => 0.25,
    };

    let method_bonus = match method {
        "exec" => 0.20,
        "http" => 0.12,
        "tool" => 0.08,
        _ => 0.0,
    };

    let policy_bonus = if policy_reason.starts_with("prompt_user_") {
        0.15
    } else if policy_reason.starts_with("prompt_cache_") {
        0.08
    } else {
        0.0
    };

    runtime_risk_clamp01(capability_score + method_bonus + policy_bonus)
}

fn runtime_hostcall_policy_profile(mode: ExtensionPolicyMode) -> String {
    match mode {
        ExtensionPolicyMode::Strict => "strict".to_string(),
        ExtensionPolicyMode::Prompt => "balanced".to_string(),
        ExtensionPolicyMode::Permissive => "permissive".to_string(),
    }
}

fn runtime_hostcall_count_recent(window: &VecDeque<i64>, now_ms: i64, horizon_ms: i64) -> u32 {
    let count = window
        .iter()
        .rev()
        .take_while(|ts| now_ms.saturating_sub(**ts) <= horizon_ms)
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn runtime_hostcall_sequence_context(
    state: &RuntimeRiskState,
    now_ms: i64,
) -> RuntimeHostcallSequenceContext {
    let recent_error_count = state
        .recent_outcome_errors
        .iter()
        .filter(|value| **value)
        .count();
    RuntimeHostcallSequenceContext {
        sequence_id: state.sequence_counter.saturating_add(1),
        previous_capability: state.last_capability.clone(),
        previous_method: state.last_method.clone(),
        previous_resource_target_class: state.last_resource_target_class.clone(),
        burst_count_1s: runtime_hostcall_count_recent(
            &state.recent_call_timestamps_ms,
            now_ms,
            1_000,
        ),
        burst_count_10s: runtime_hostcall_count_recent(
            &state.recent_call_timestamps_ms,
            now_ms,
            10_000,
        ),
        recent_error_count: u32::try_from(recent_error_count).unwrap_or(u32::MAX),
        recent_window_count: u32::try_from(state.recent_outcome_errors.len()).unwrap_or(u32::MAX),
        prior_failure_streak: state.consecutive_failures,
    }
}

fn runtime_hostcall_extract_features(
    base_score: f64,
    recent_mean_score: f64,
    sequence: &RuntimeHostcallSequenceContext,
    capability: &str,
    policy_reason: &str,
    timeout_ms: Option<u64>,
) -> RuntimeHostcallFeatureVector {
    let recent_error_rate = if sequence.recent_window_count == 0 {
        0.0
    } else {
        f64::from(sequence.recent_error_count) / f64::from(sequence.recent_window_count)
    };

    RuntimeHostcallFeatureVector {
        schema: RUNTIME_HOSTCALL_FEATURE_SCHEMA_VERSION.to_string(),
        base_score: runtime_risk_clamp01(base_score),
        recent_mean_score: runtime_risk_clamp01(recent_mean_score),
        recent_error_rate: runtime_risk_clamp01(recent_error_rate),
        burst_density_1s: runtime_risk_clamp01(f64::from(sequence.burst_count_1s) / 8.0),
        burst_density_10s: runtime_risk_clamp01(f64::from(sequence.burst_count_10s) / 24.0),
        prior_failure_streak_norm: runtime_risk_clamp01(
            f64::from(sequence.prior_failure_streak) / 8.0,
        ),
        dangerous_capability: if runtime_risk_is_dangerous(capability) {
            1.0
        } else {
            0.0
        },
        timeout_requested: if timeout_ms.unwrap_or(0) > 0 {
            1.0
        } else {
            0.0
        },
        policy_prompt_bias: if policy_reason.starts_with("prompt_") {
            1.0
        } else {
            0.0
        },
    }
}

fn runtime_hostcall_is_private_ip(host: &str) -> Option<bool> {
    let parsed = host.parse::<IpAddr>().ok()?;
    Some(match parsed {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_loopback(),
    })
}

fn runtime_hostcall_resource_target_class(method: &str, params: &Value) -> String {
    match method {
        "http" => {
            let Some(url_raw) = params.get("url").and_then(Value::as_str) else {
                return "network.unknown".to_string();
            };
            let parsed = Url::parse(url_raw).ok();
            let Some(url) = parsed else {
                return "network.unknown".to_string();
            };
            let Some(host) = url.host_str() else {
                return "network.unknown".to_string();
            };
            if host.eq_ignore_ascii_case("localhost") {
                return "network.loopback".to_string();
            }
            if let Some(is_private) = runtime_hostcall_is_private_ip(host) {
                if is_private {
                    return "network.private".to_string();
                }
                return "network.public".to_string();
            }
            "network.public".to_string()
        }
        "exec" => "subprocess.exec".to_string(),
        "tool" => {
            let tool_name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match tool_name {
                "read" | "write" | "edit" | "grep" | "find" | "ls" => "filesystem.tool".to_string(),
                "bash" => "subprocess.tool".to_string(),
                _ => "tool.unknown".to_string(),
            }
        }
        "session" => "session.state".to_string(),
        "ui" => "ui.interaction".to_string(),
        "events" => "event.bus".to_string(),
        "log" => "telemetry.log".to_string(),
        _ => "unknown".to_string(),
    }
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn runtime_risk_quantile(mut values: Vec<f64>, q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q = runtime_risk_clamp01(q);
    let idx = ((values.len() - 1) as f64 * q).round() as usize;
    values[idx.min(values.len() - 1)]
}

fn runtime_risk_compute_ledger_hash(
    entry: &RuntimeRiskLedgerEntry,
    prev_hash: Option<&str>,
) -> String {
    let mut canonical = entry.clone();
    canonical.ledger_hash.clear();
    canonical.prev_ledger_hash = prev_hash.map(ToString::to_string);

    let mut hasher = sha2::Sha256::new();
    if let Some(prev) = prev_hash {
        hasher.update(prev.as_bytes());
    }
    let payload = serde_json::to_string(&canonical).unwrap_or_default();
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn runtime_risk_compute_ledger_hash_artifact(
    entry: &RuntimeRiskLedgerArtifactEntry,
    prev_hash: Option<&str>,
) -> String {
    let internal = RuntimeRiskLedgerEntry::from(entry);
    runtime_risk_compute_ledger_hash(&internal, prev_hash)
}

pub fn runtime_risk_ledger_data_hash(entries: &[RuntimeRiskLedgerArtifactEntry]) -> String {
    let mut hasher = sha2::Sha256::new();
    for entry in entries {
        hasher.update(entry.ledger_hash.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

pub fn verify_runtime_risk_ledger_artifact(
    artifact: &RuntimeRiskLedgerArtifact,
) -> RuntimeRiskLedgerVerificationReport {
    let mut errors = Vec::new();
    if artifact.schema != RUNTIME_RISK_LEDGER_SCHEMA_VERSION {
        errors.push(RuntimeRiskLedgerIntegrityError {
            index: 0,
            code: "schema_mismatch".to_string(),
            message: format!(
                "expected schema {}, got {}",
                RUNTIME_RISK_LEDGER_SCHEMA_VERSION, artifact.schema
            ),
        });
    }

    if artifact.entry_count != artifact.entries.len() {
        errors.push(RuntimeRiskLedgerIntegrityError {
            index: artifact.entries.len(),
            code: "entry_count_mismatch".to_string(),
            message: format!(
                "entry_count={}, actual={}",
                artifact.entry_count,
                artifact.entries.len()
            ),
        });
    }

    let head_ledger_hash = artifact
        .entries
        .first()
        .map(|entry| entry.ledger_hash.clone());
    let tail_ledger_hash = artifact
        .entries
        .last()
        .map(|entry| entry.ledger_hash.clone());

    if artifact.head_ledger_hash != head_ledger_hash {
        errors.push(RuntimeRiskLedgerIntegrityError {
            index: 0,
            code: "head_hash_mismatch".to_string(),
            message: "head_ledger_hash does not match first entry".to_string(),
        });
    }

    if artifact.tail_ledger_hash != tail_ledger_hash {
        errors.push(RuntimeRiskLedgerIntegrityError {
            index: artifact.entries.len(),
            code: "tail_hash_mismatch".to_string(),
            message: "tail_ledger_hash does not match last entry".to_string(),
        });
    }

    let mut expected_prev_hash = artifact
        .entries
        .first()
        .and_then(|entry| entry.prev_ledger_hash.clone());

    for (idx, entry) in artifact.entries.iter().enumerate() {
        if entry.prev_ledger_hash != expected_prev_hash {
            errors.push(RuntimeRiskLedgerIntegrityError {
                index: idx,
                code: "prev_hash_mismatch".to_string(),
                message: format!(
                    "expected prev {:?}, got {:?}",
                    expected_prev_hash, entry.prev_ledger_hash
                ),
            });
        }

        let expected_hash =
            runtime_risk_compute_ledger_hash_artifact(entry, expected_prev_hash.as_deref());
        if entry.ledger_hash != expected_hash {
            errors.push(RuntimeRiskLedgerIntegrityError {
                index: idx,
                code: "hash_mismatch".to_string(),
                message: format!("expected {}, got {}", expected_hash, entry.ledger_hash),
            });
        }

        expected_prev_hash = Some(entry.ledger_hash.clone());
    }

    let computed_data_hash = runtime_risk_ledger_data_hash(&artifact.entries);
    if artifact.data_hash != computed_data_hash {
        errors.push(RuntimeRiskLedgerIntegrityError {
            index: artifact.entries.len(),
            code: "data_hash_mismatch".to_string(),
            message: format!(
                "expected {}, got {}",
                computed_data_hash, artifact.data_hash
            ),
        });
    }

    RuntimeRiskLedgerVerificationReport {
        schema: RUNTIME_RISK_LEDGER_SCHEMA_VERSION.to_string(),
        entry_count: artifact.entries.len(),
        head_ledger_hash,
        tail_ledger_hash,
        artifact_data_hash: artifact.data_hash.clone(),
        computed_data_hash,
        valid: errors.is_empty(),
        errors,
    }
}

pub fn replay_runtime_risk_ledger_artifact(
    artifact: &RuntimeRiskLedgerArtifact,
) -> Result<RuntimeRiskReplayArtifact> {
    let verification = verify_runtime_risk_ledger_artifact(artifact);
    if !verification.valid {
        let summary = verification
            .errors
            .iter()
            .take(3)
            .map(|err| format!("[{}] {}: {}", err.index, err.code, err.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::validation(format!(
            "runtime risk ledger integrity verification failed: {summary}"
        )));
    }

    let steps = artifact
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| RuntimeRiskReplayStep {
            index,
            call_id: entry.call_id.clone(),
            extension_id: entry.extension_id.clone(),
            capability: entry.capability.clone(),
            method: entry.method.clone(),
            policy_reason: entry.policy_reason.clone(),
            selected_action: entry.selected_action,
            derived_state: entry.derived_state,
            risk_score: entry.risk_score,
            reason_codes: entry.triggers.clone(),
            explanation_level: entry.explanation_level,
            explanation_summary: entry.explanation_summary.clone(),
            top_contributors: entry.top_contributors.clone(),
            budget_state: entry.budget_state.clone(),
            fallback_reason: entry.fallback_reason.clone(),
            drift_detected: entry.drift_detected,
            e_process: entry.e_process,
            e_threshold: entry.e_threshold,
            conformal_residual: entry.conformal_residual,
            conformal_quantile: entry.conformal_quantile,
            ledger_hash: entry.ledger_hash.clone(),
            prev_ledger_hash: entry.prev_ledger_hash.clone(),
        })
        .collect();

    Ok(RuntimeRiskReplayArtifact {
        schema: RUNTIME_RISK_REPLAY_SCHEMA_VERSION.to_string(),
        source_schema: artifact.schema.clone(),
        source_data_hash: artifact.data_hash.clone(),
        entry_count: artifact.entries.len(),
        tail_ledger_hash: artifact.tail_ledger_hash.clone(),
        steps,
    })
}

fn runtime_risk_calibration_threshold_grid(config: &RuntimeRiskCalibrationConfig) -> Vec<f64> {
    let mut thresholds = if config.threshold_grid.is_empty() {
        RuntimeRiskCalibrationConfig::default().threshold_grid
    } else {
        config.threshold_grid.clone()
    };
    for threshold in &mut thresholds {
        *threshold = runtime_risk_clamp01(*threshold);
    }
    thresholds.sort_by(f64::total_cmp);
    thresholds.dedup_by(|left, right| left.total_cmp(right).is_eq());
    if thresholds.is_empty() {
        thresholds.push(runtime_risk_clamp01(config.baseline_threshold));
    }
    thresholds
}

const fn runtime_risk_calibration_is_positive(entry: &RuntimeRiskLedgerArtifactEntry) -> bool {
    entry.outcome_error_code.is_some()
        || matches!(
            entry.selected_action,
            RuntimeRiskActionValue::Deny | RuntimeRiskActionValue::Terminate
        )
        || matches!(entry.derived_state, RuntimeRiskStateLabelValue::Unsafe)
}

fn runtime_risk_calibration_candidate(
    entries: &[RuntimeRiskLedgerArtifactEntry],
    threshold: f64,
    config: &RuntimeRiskCalibrationConfig,
) -> RuntimeRiskThresholdCalibration {
    let threshold = runtime_risk_clamp01(threshold);
    let fp_weight = config.false_positive_weight.max(0.0);
    let fn_weight = config.false_negative_weight.max(0.0);
    let mut true_positive = 0.0_f64;
    let mut false_positive = 0.0_f64;
    let mut true_negative = 0.0_f64;
    let mut false_negative = 0.0_f64;

    for entry in entries {
        let actual_positive = runtime_risk_calibration_is_positive(entry);
        let predicted_positive = entry.risk_score >= threshold;
        match (actual_positive, predicted_positive) {
            (true, true) => true_positive += 1.0,
            (false, true) => false_positive += 1.0,
            (false, false) => true_negative += 1.0,
            (true, false) => false_negative += 1.0,
        }
    }

    let positives = true_positive + false_negative;
    let negatives = true_negative + false_positive;
    let false_positive_rate = if negatives == 0.0 {
        0.0
    } else {
        false_positive / negatives
    };
    let false_negative_rate = if positives == 0.0 {
        0.0
    } else {
        false_negative / positives
    };

    let false_negative_cost = false_negative * 12.0 * fn_weight;
    let false_positive_cost = false_positive * 3.0 * fp_weight;
    let true_positive_cost = true_positive;
    let true_negative_cost = true_negative * 0.2;
    let expected_loss =
        false_negative_cost + false_positive_cost + true_positive_cost + true_negative_cost;

    let objective_score = match config.objective {
        RuntimeRiskCalibrationObjective::MinExpectedLoss => expected_loss,
        RuntimeRiskCalibrationObjective::MinFalsePositives => {
            (false_positive_rate * fp_weight) + (false_negative_rate * fn_weight * 0.25)
        }
        RuntimeRiskCalibrationObjective::BalancedAccuracy => {
            (false_positive_rate * fp_weight) + (false_negative_rate * fn_weight)
        }
    };

    RuntimeRiskThresholdCalibration {
        threshold,
        objective_score,
        expected_loss,
        false_positive_rate,
        false_negative_rate,
    }
}

pub fn calibrate_runtime_risk_from_ledger(
    artifact: &RuntimeRiskLedgerArtifact,
    config: &RuntimeRiskCalibrationConfig,
) -> Result<RuntimeRiskCalibrationReport> {
    let verification = verify_runtime_risk_ledger_artifact(artifact);
    if !verification.valid {
        return Err(Error::validation(
            "runtime risk ledger failed integrity verification".to_string(),
        ));
    }
    if artifact.entries.is_empty() {
        return Err(Error::validation(
            "runtime risk ledger calibration requires at least one entry".to_string(),
        ));
    }

    let baseline_threshold = runtime_risk_clamp01(config.baseline_threshold);
    let baseline =
        runtime_risk_calibration_candidate(&artifact.entries, baseline_threshold, config);
    let mut candidates = runtime_risk_calibration_threshold_grid(config)
        .into_iter()
        .map(|threshold| runtime_risk_calibration_candidate(&artifact.entries, threshold, config))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.threshold.total_cmp(&right.threshold));

    let mut recommended = candidates
        .first()
        .cloned()
        .unwrap_or_else(|| baseline.clone());
    for candidate in candidates.iter().skip(1) {
        let better_score = candidate
            .objective_score
            .total_cmp(&recommended.objective_score)
            .is_lt();
        let equal_score = candidate
            .objective_score
            .total_cmp(&recommended.objective_score)
            .is_eq();
        let candidate_distance = (candidate.threshold - baseline_threshold).abs();
        let recommended_distance = (recommended.threshold - baseline_threshold).abs();
        let better_distance = candidate_distance.total_cmp(&recommended_distance).is_lt();
        let equal_distance = candidate_distance.total_cmp(&recommended_distance).is_eq();
        let better_threshold = candidate
            .threshold
            .total_cmp(&recommended.threshold)
            .is_lt();

        if better_score
            || (equal_score && (better_distance || (equal_distance && better_threshold)))
        {
            recommended = candidate.clone();
        }
    }

    Ok(RuntimeRiskCalibrationReport {
        schema: RUNTIME_RISK_CALIBRATION_SCHEMA_VERSION.to_string(),
        source_schema: artifact.schema.clone(),
        source_data_hash: artifact.data_hash.clone(),
        objective: config.objective,
        baseline_threshold,
        recommended_threshold: recommended.threshold,
        recommended_delta: recommended.threshold - baseline_threshold,
        baseline,
        recommended,
        candidates,
    })
}

// ============================================================================
// Baseline Model Builder (bd-153pv)
// ============================================================================

/// Compute the median of a sorted slice. Returns 0.0 for empty slices.
fn baseline_median(sorted: &[f64]) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        // Use midpoint arithmetic to avoid overflow lint
        let a = sorted[mid - 1];
        let b = sorted[mid];
        a + (b - a) / 2.0
    } else {
        sorted[mid]
    }
}

/// Compute the Median Absolute Deviation of a sorted slice.
/// MAD = median(|x_i - median(x)|).
fn baseline_mad(sorted: &[f64]) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let med = baseline_median(sorted);
    let mut deviations: Vec<f64> = sorted.iter().map(|x| (x - med).abs()).collect();
    deviations.sort_by(f64::total_cmp);
    baseline_median(&deviations)
}

/// Map a `RuntimeRiskStateLabelValue` to a 0-indexed state for the Markov matrix.
const fn state_label_to_index(label: RuntimeRiskStateLabelValue) -> usize {
    match label {
        RuntimeRiskStateLabelValue::SafeFast => 0,
        RuntimeRiskStateLabelValue::Suspicious => 1,
        RuntimeRiskStateLabelValue::Unsafe => 2,
    }
}

/// Build a Markov transition matrix from a sequence of state labels.
/// Uses Dirichlet smoothing (additive prior) for sparse data.
#[allow(clippy::cast_precision_loss)]
fn build_markov_transition_matrix(
    states: &[RuntimeRiskStateLabelValue],
    smoothing_prior: f64,
) -> BaselineMarkovTransitionMatrix {
    let mut counts = [[0u64; 3]; 3];
    let mut total_transitions = 0u64;
    for window in states.windows(2) {
        let from = state_label_to_index(window[0]);
        let to = state_label_to_index(window[1]);
        counts[from][to] += 1;
        total_transitions += 1;
    }

    // Smooth and normalize
    let mut probabilities = [[0.0f64; 3]; 3];
    for (i, row) in counts.iter().enumerate() {
        let row_sum: f64 = row.iter().map(|&c| c as f64).sum::<f64>();
        let row_total = 3.0f64.mul_add(smoothing_prior, row_sum);
        for (j, &count) in row.iter().enumerate() {
            probabilities[i][j] = (count as f64 + smoothing_prior) / row_total;
        }
    }

    // Compute stationary distribution via power iteration.
    let stationary = markov_stationary_distribution(&probabilities);

    BaselineMarkovTransitionMatrix {
        counts,
        probabilities,
        smoothing_prior,
        total_transitions,
        stationary_distribution: stationary,
    }
}

/// Compute stationary distribution of a 3x3 transition matrix via power iteration.
fn markov_stationary_distribution(prob: &[[f64; 3]; 3]) -> [f64; 3] {
    let mut pi = [1.0 / 3.0; 3];
    for _ in 0..200 {
        let mut next = [0.0f64; 3];
        for (j, next_j) in next.iter_mut().enumerate() {
            for (i, pi_i) in pi.iter().enumerate() {
                *next_j += pi_i * prob[i][j];
            }
        }
        // Normalize
        let sum: f64 = next.iter().sum();
        if sum > 0.0 {
            for v in &mut next {
                *v /= sum;
            }
        }
        pi = next;
    }
    pi
}

/// Compute KL divergence D_KL(p || q) for two discrete distributions.
/// Returns 0.0 if distributions are identical. Uses floor of 1e-12 for q to
/// avoid log(0).
fn kl_divergence(p: &[f64; 3], q: &[f64; 3]) -> f64 {
    let mut kl = 0.0f64;
    for (i, &p_i) in p.iter().enumerate() {
        if p_i > 0.0 {
            let q_i = q[i].max(1e-12);
            kl += p_i * (p_i / q_i).ln();
        }
    }
    kl.max(0.0)
}

/// Build a per-capability profile from ledger entries for a single capability.
fn build_capability_profile(
    capability: &str,
    entries: &[&RuntimeRiskLedgerArtifactEntry],
) -> BaselineCapabilityProfile {
    let mut risk_scores: Vec<f64> = entries.iter().map(|e| e.risk_score).collect();
    risk_scores.sort_by(f64::total_cmp);

    let median = baseline_median(&risk_scores);
    let mad = baseline_mad(&risk_scores);
    let p5 = runtime_risk_quantile(risk_scores.clone(), 0.05);
    let p95 = runtime_risk_quantile(risk_scores, 0.95);

    // Compute error rate from outcome_error_code presence
    let error_count = entries
        .iter()
        .filter(|e| e.outcome_error_code.is_some())
        .count();
    #[allow(clippy::cast_precision_loss)]
    let error_rate = if entries.is_empty() {
        0.0
    } else {
        error_count as f64 / entries.len() as f64
    };

    // burst_density is harder to compute from ledger entries (no feature vector),
    // but we can estimate from timestamp clustering
    let mut timestamps: Vec<i64> = entries.iter().map(|e| e.ts_ms).collect();
    timestamps.sort_unstable();
    let burst_1s_median = estimate_burst_density(&timestamps, 1000);
    let burst_10s_median = estimate_burst_density(&timestamps, 10_000);

    BaselineCapabilityProfile {
        capability: capability.to_string(),
        sample_count: entries.len(),
        risk_score_median: median,
        risk_score_mad: mad,
        risk_score_p5: p5,
        risk_score_p95: p95,
        error_rate_median: error_rate,
        burst_density_1s_median: burst_1s_median,
        burst_density_10s_median: burst_10s_median,
    }
}

/// Estimate median burst density for a set of sorted timestamps within a given
/// window size (in ms). Returns 0.0 if there are fewer than 2 timestamps.
fn estimate_burst_density(sorted_timestamps: &[i64], window_ms: i64) -> f64 {
    if sorted_timestamps.len() < 2 {
        return 0.0;
    }
    let mut densities = Vec::with_capacity(sorted_timestamps.len());
    for (i, &ts) in sorted_timestamps.iter().enumerate() {
        let count = sorted_timestamps[i..]
            .iter()
            .take_while(|&&t| t - ts <= window_ms)
            .count();
        // Normalize: 8 for 1s, 24 for 10s (same as feature extraction)
        let normalizer = if window_ms <= 1000 { 8.0 } else { 24.0 };
        #[allow(clippy::cast_precision_loss)]
        densities.push(runtime_risk_clamp01(count as f64 / normalizer));
    }
    densities.sort_by(f64::total_cmp);
    baseline_median(&densities)
}

/// Build a complete baseline model from a runtime risk ledger artifact.
///
/// The baseline captures per-capability robust statistics (median/MAD/quantiles)
/// and a Markov transition matrix over risk state labels, both of which can be
/// used by the online scorer for drift detection.
pub fn build_baseline_from_ledger(
    artifact: &RuntimeRiskLedgerArtifact,
    extension_id: &str,
) -> Result<RuntimeRiskBaselineModel> {
    build_baseline_from_ledger_with_options(artifact, extension_id, 3.0, 0.5, 1.0)
}

/// Build a baseline model with customizable thresholds.
pub fn build_baseline_from_ledger_with_options(
    artifact: &RuntimeRiskLedgerArtifact,
    extension_id: &str,
    anomaly_threshold_mads: f64,
    transition_divergence_threshold: f64,
    smoothing_prior: f64,
) -> Result<RuntimeRiskBaselineModel> {
    let verification = verify_runtime_risk_ledger_artifact(artifact);
    if !verification.valid {
        return Err(Error::validation(
            "cannot build baseline from invalid ledger".to_string(),
        ));
    }
    if artifact.entries.is_empty() {
        return Err(Error::validation(
            "baseline requires at least one ledger entry".to_string(),
        ));
    }

    // Filter to this extension only
    let ext_entries: Vec<&RuntimeRiskLedgerArtifactEntry> = artifact
        .entries
        .iter()
        .filter(|e| e.extension_id == extension_id)
        .collect();

    if ext_entries.is_empty() {
        return Err(Error::validation(format!(
            "no ledger entries found for extension '{extension_id}'"
        )));
    }

    // Group by capability
    let mut by_capability: std::collections::BTreeMap<
        String,
        Vec<&RuntimeRiskLedgerArtifactEntry>,
    > = std::collections::BTreeMap::new();
    for entry in &ext_entries {
        by_capability
            .entry(entry.capability.clone())
            .or_default()
            .push(entry);
    }

    let capability_profiles: Vec<BaselineCapabilityProfile> = by_capability
        .iter()
        .map(|(cap, entries)| build_capability_profile(cap, entries))
        .collect();

    // Build Markov transition matrix from state sequence
    let states: Vec<RuntimeRiskStateLabelValue> =
        ext_entries.iter().map(|e| e.derived_state).collect();
    let transition_matrix = build_markov_transition_matrix(&states, smoothing_prior);

    Ok(RuntimeRiskBaselineModel {
        schema: RUNTIME_RISK_BASELINE_SCHEMA_VERSION.to_string(),
        extension_id: extension_id.to_string(),
        generated_at_ms: runtime_risk_now_ms(),
        source_data_hash: artifact.data_hash.clone(),
        source_entry_count: ext_entries.len(),
        capability_profiles,
        transition_matrix,
        anomaly_threshold_mads,
        transition_divergence_threshold,
    })
}

/// Detect drift in live features compared to a baseline model.
///
/// Returns a drift report with individual anomalies (metrics exceeding the MAD
/// threshold) and Markov transition divergence.
#[allow(clippy::too_many_arguments)]
pub fn detect_baseline_drift(
    baseline: &RuntimeRiskBaselineModel,
    extension_id: &str,
    capability: &str,
    live_risk_score: f64,
    live_error_rate: f64,
    live_burst_1s: f64,
    live_burst_10s: f64,
    recent_states: &[RuntimeRiskStateLabelValue],
) -> BaselineDriftReport {
    let profile = baseline
        .capability_profiles
        .iter()
        .find(|p| p.capability == capability);

    let mut anomalies = Vec::new();
    let mut drift_detected = false;

    if let Some(prof) = profile {
        // Check risk score deviation
        let mad_threshold = baseline.anomaly_threshold_mads;

        let check_metric = |metric: &str,
                            observed: f64,
                            median: f64,
                            mad: f64,
                            anomalies: &mut Vec<BaselineDriftAnomaly>|
         -> bool {
            // Use a floor of 0.01 for MAD to avoid infinite deviation on constant data
            let effective_mad = mad.max(0.01);
            let deviation = (observed - median).abs() / effective_mad;
            if deviation > mad_threshold {
                anomalies.push(BaselineDriftAnomaly {
                    metric: metric.to_string(),
                    observed,
                    baseline_median: median,
                    baseline_mad: mad,
                    deviation_mads: deviation,
                    explanation: format!(
                        "{metric} = {observed:.4} is {deviation:.1} MADs from baseline median \
                         {median:.4} (MAD={mad:.4})"
                    ),
                });
                true
            } else {
                false
            }
        };

        drift_detected |= check_metric(
            "risk_score",
            live_risk_score,
            prof.risk_score_median,
            prof.risk_score_mad,
            &mut anomalies,
        );
        drift_detected |= check_metric(
            "error_rate",
            live_error_rate,
            prof.error_rate_median,
            prof.error_rate_median.max(0.01), // Use median as proxy MAD when no explicit MAD
            &mut anomalies,
        );
        drift_detected |= check_metric(
            "burst_density_1s",
            live_burst_1s,
            prof.burst_density_1s_median,
            prof.burst_density_1s_median.max(0.01),
            &mut anomalies,
        );
        drift_detected |= check_metric(
            "burst_density_10s",
            live_burst_10s,
            prof.burst_density_10s_median,
            prof.burst_density_10s_median.max(0.01),
            &mut anomalies,
        );
    }

    // Check Markov transition divergence
    let mut transition_divergence = 0.0;
    let mut transition_anomalous = false;
    if recent_states.len() >= 2 {
        // Build observed transition matrix from recent states
        let observed_matrix = build_markov_transition_matrix(recent_states, 0.5);
        // Compare stationary distributions via KL divergence
        transition_divergence = kl_divergence(
            &observed_matrix.stationary_distribution,
            &baseline.transition_matrix.stationary_distribution,
        );
        if transition_divergence > baseline.transition_divergence_threshold {
            transition_anomalous = true;
            drift_detected = true;
        }
    }

    BaselineDriftReport {
        extension_id: extension_id.to_string(),
        capability: capability.to_string(),
        drift_detected,
        anomalies,
        transition_divergence,
        transition_anomalous,
    }
}

fn runtime_risk_choose_action(
    posterior: &RuntimeRiskPosterior,
    e_process_breach: bool,
    drift_detected: bool,
) -> (
    RuntimeRiskAction,
    RuntimeRiskExpectedLoss,
    Vec<String>,
    RuntimeRiskStateLabel,
) {
    // Asymmetric loss matrix:
    // - false allow on unsafe is very costly
    // - denying known-safe calls has meaningful UX/compat cost
    let allow_loss = 120.0f64.mul_add(posterior.unsafe_, 8.0 * posterior.suspicious);
    let harden_loss = 35.0f64.mul_add(
        posterior.unsafe_,
        3.0f64.mul_add(posterior.safe_fast, 2.0 * posterior.suspicious),
    );
    let deny_loss = 2.0f64.mul_add(
        posterior.unsafe_,
        20.0f64.mul_add(posterior.safe_fast, 4.0 * posterior.suspicious),
    );
    let terminate_loss = 1.0f64.mul_add(
        posterior.unsafe_,
        35.0f64.mul_add(posterior.safe_fast, 8.0 * posterior.suspicious),
    );

    let expected = RuntimeRiskExpectedLoss {
        allow: allow_loss,
        harden: harden_loss,
        deny: deny_loss,
        terminate: terminate_loss,
    };

    let mut best = RuntimeRiskAction::Allow;
    let mut best_loss = allow_loss;
    if harden_loss < best_loss {
        best = RuntimeRiskAction::Harden;
        best_loss = harden_loss;
    }
    if deny_loss < best_loss {
        best = RuntimeRiskAction::Deny;
        best_loss = deny_loss;
    }
    if terminate_loss < best_loss {
        best = RuntimeRiskAction::Terminate;
    }

    let mut triggers = Vec::new();
    if e_process_breach {
        triggers.push("e_process_breach".to_string());
        if matches!(best, RuntimeRiskAction::Allow) {
            best = RuntimeRiskAction::Harden;
        }
    }
    if drift_detected {
        triggers.push("drift_detected".to_string());
        if matches!(best, RuntimeRiskAction::Allow) {
            best = RuntimeRiskAction::Harden;
        }
    }

    let state_label = if posterior.unsafe_ >= 0.55 {
        RuntimeRiskStateLabel::Unsafe
    } else if posterior.suspicious >= 0.40 {
        RuntimeRiskStateLabel::Suspicious
    } else {
        RuntimeRiskStateLabel::SafeFast
    };

    (best, expected, triggers, state_label)
}

const fn runtime_risk_action_code(action: RuntimeRiskAction) -> &'static str {
    match action {
        RuntimeRiskAction::Allow => "allow",
        RuntimeRiskAction::Harden => "harden",
        RuntimeRiskAction::Deny => "deny",
        RuntimeRiskAction::Terminate => "terminate",
    }
}

const fn runtime_risk_selected_expected_loss(
    action: RuntimeRiskAction,
    expected_loss: &RuntimeRiskExpectedLoss,
) -> f64 {
    match action {
        RuntimeRiskAction::Allow => expected_loss.allow,
        RuntimeRiskAction::Harden => expected_loss.harden,
        RuntimeRiskAction::Deny => expected_loss.deny,
        RuntimeRiskAction::Terminate => expected_loss.terminate,
    }
}

const fn runtime_risk_default_explanation_level(
    action: RuntimeRiskAction,
    triggers: &[String],
    fallback_reason: Option<&str>,
) -> RuntimeRiskExplanationLevelValue {
    if fallback_reason.is_some()
        || matches!(
            action,
            RuntimeRiskAction::Deny | RuntimeRiskAction::Terminate
        )
    {
        RuntimeRiskExplanationLevelValue::Full
    } else if matches!(action, RuntimeRiskAction::Harden) || !triggers.is_empty() {
        RuntimeRiskExplanationLevelValue::Standard
    } else {
        RuntimeRiskExplanationLevelValue::Compact
    }
}

fn runtime_risk_sort_contributors(contributors: &mut [RuntimeRiskExplanationContributor]) {
    contributors.sort_by(|left, right| {
        right
            .magnitude
            .total_cmp(&left.magnitude)
            .then_with(|| left.code.cmp(&right.code))
    });
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn runtime_risk_build_explanation(
    action: RuntimeRiskAction,
    risk_score: f64,
    posterior: &RuntimeRiskPosterior,
    expected_loss: &RuntimeRiskExpectedLoss,
    features: &RuntimeHostcallFeatureVector,
    triggers: &[String],
    fallback_reason: Option<&str>,
    term_budget: usize,
    time_budget_ms: u64,
) -> (
    RuntimeRiskExplanationLevelValue,
    String,
    Vec<RuntimeRiskExplanationContributor>,
    RuntimeRiskExplanationBudgetState,
) {
    let started = Instant::now();
    let normalized_term_budget = term_budget.max(1);
    let mut level = runtime_risk_default_explanation_level(action, triggers, fallback_reason);
    let mut contributors = vec![
        RuntimeRiskExplanationContributor {
            code: "feature_base_score".to_string(),
            signed_impact: 0.65 * features.base_score,
            magnitude: (0.65 * features.base_score).abs(),
            rationale: "base capability/method risk contribution".to_string(),
        },
        RuntimeRiskExplanationContributor {
            code: "feature_recent_mean_score".to_string(),
            signed_impact: 0.35 * features.recent_mean_score,
            magnitude: (0.35 * features.recent_mean_score).abs(),
            rationale: "recent moving-average risk contribution".to_string(),
        },
        RuntimeRiskExplanationContributor {
            code: "feature_recent_error_rate".to_string(),
            signed_impact: 0.12 * features.recent_error_rate,
            magnitude: (0.12 * features.recent_error_rate).abs(),
            rationale: "recent hostcall failure-rate contribution".to_string(),
        },
        RuntimeRiskExplanationContributor {
            code: "feature_burst_density_1s".to_string(),
            signed_impact: 0.08 * features.burst_density_1s,
            magnitude: (0.08 * features.burst_density_1s).abs(),
            rationale: "short-horizon call burst density contribution".to_string(),
        },
        RuntimeRiskExplanationContributor {
            code: "feature_prior_failure_streak".to_string(),
            signed_impact: 0.05 * features.prior_failure_streak_norm,
            magnitude: (0.05 * features.prior_failure_streak_norm).abs(),
            rationale: "prior failure streak contribution".to_string(),
        },
        RuntimeRiskExplanationContributor {
            code: "posterior_unsafe".to_string(),
            signed_impact: posterior.unsafe_,
            magnitude: posterior.unsafe_.abs(),
            rationale: "posterior probability of unsafe behavior".to_string(),
        },
        RuntimeRiskExplanationContributor {
            code: "posterior_suspicious".to_string(),
            signed_impact: 0.5 * posterior.suspicious,
            magnitude: (0.5 * posterior.suspicious).abs(),
            rationale: "posterior probability of suspicious behavior".to_string(),
        },
    ];

    let selected_loss = runtime_risk_selected_expected_loss(action, expected_loss);
    let loss_delta_vs_allow = expected_loss.allow - selected_loss;
    contributors.push(RuntimeRiskExplanationContributor {
        code: "expected_loss_delta_vs_allow".to_string(),
        signed_impact: loss_delta_vs_allow,
        magnitude: loss_delta_vs_allow.abs(),
        rationale: "expected-loss improvement versus allow action".to_string(),
    });

    for trigger in triggers {
        contributors.push(RuntimeRiskExplanationContributor {
            code: format!("trigger_{trigger}"),
            signed_impact: 0.1,
            magnitude: 0.1,
            rationale: format!("trigger `{trigger}` tightened action selection"),
        });
    }

    if let Some(reason) = fallback_reason {
        contributors.push(RuntimeRiskExplanationContributor {
            code: format!("fallback_{reason}"),
            signed_impact: 0.25,
            magnitude: 0.25,
            rationale: format!("fallback reason `{reason}` constrained decision output"),
        });
    }

    runtime_risk_sort_contributors(&mut contributors);

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let budget_exhausted_by_terms = contributors.len() > normalized_term_budget;
    let budget_exhausted_by_time = elapsed_ms > time_budget_ms;
    let exhausted = budget_exhausted_by_terms || budget_exhausted_by_time;
    let mut fallback_mode = false;

    if exhausted {
        level = RuntimeRiskExplanationLevelValue::Compact;
        fallback_mode = true;
        let action_code = runtime_risk_action_code(action);
        contributors = vec![
            RuntimeRiskExplanationContributor {
                code: format!("action_{action_code}"),
                signed_impact: 1.0,
                magnitude: 1.0,
                rationale: "conservative fallback preserves deterministic selected action"
                    .to_string(),
            },
            RuntimeRiskExplanationContributor {
                code: "budget_exhausted".to_string(),
                signed_impact: 1.0,
                magnitude: 0.95,
                rationale: "explanation budget exhausted; omitted speculative contributor terms"
                    .to_string(),
            },
        ];
    }

    let mut trigger_labels = triggers.to_vec();
    trigger_labels.sort();
    let trigger_summary = if trigger_labels.is_empty() {
        "none".to_string()
    } else {
        trigger_labels.join("|")
    };
    let action_code = runtime_risk_action_code(action);
    let summary = if fallback_mode {
        format!("action={action_code} score={risk_score:.3} conservative_explanation_fallback=true")
    } else {
        format!(
            "action={action_code} score={risk_score:.3} unsafe={:.3} suspicious={:.3} triggers={trigger_summary}",
            posterior.unsafe_, posterior.suspicious
        )
    };

    let terms_emitted = contributors.len();
    (
        level,
        summary,
        contributors,
        RuntimeRiskExplanationBudgetState {
            time_budget_ms,
            elapsed_ms,
            term_budget: normalized_term_budget,
            terms_emitted,
            exhausted,
            fallback_mode,
        },
    )
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

// ---------------------------------------------------------------------------
// Precedence chain
// ---------------------------------------------------------------------------
//
// Policy evaluation follows a strict precedence order. Each layer either
// produces a terminal decision (Allow / Deny) or defers to the next layer.
//
//   1. **Per-extension deny** — if the capability is in the extension
//      override's `deny` list → Deny ("extension_deny").
//   2. **Global deny_caps** — if the capability is in the global `deny_caps`
//      list → Deny ("deny_caps").
//   3. **Per-extension allow** — if the capability is in the extension
//      override's `allow` list → Allow ("extension_allow").
//   4. **Global default_caps** — if the capability is in `default_caps`
//      → Allow ("default_caps").
//   5. **Mode fallback** — Strict → Deny, Prompt → Prompt, Permissive →
//      Allow.
//
// The effective mode is the per-extension override mode if set, otherwise
// the global mode.

impl ExtensionPolicy {
    /// Evaluate policy for a capability without extension context.
    ///
    /// Equivalent to `evaluate_for(capability, None)`.
    pub fn evaluate(&self, capability: &str) -> PolicyCheck {
        self.evaluate_for(capability, None)
    }

    /// Evaluate policy for a capability with optional extension context.
    ///
    /// Applies the full precedence chain documented above.
    #[allow(clippy::too_many_lines)]
    pub fn evaluate_for(&self, capability: &str, extension_id: Option<&str>) -> PolicyCheck {
        let normalized = capability.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return PolicyCheck {
                decision: PolicyDecision::Deny,
                capability: String::new(),
                reason: "empty_capability".to_string(),
            };
        }

        let ext_override = extension_id.and_then(|id| self.per_extension.get(id));

        // Layer 1: per-extension deny.
        if let Some(ovr) = ext_override {
            if ovr
                .deny
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(&normalized))
            {
                return PolicyCheck {
                    decision: PolicyDecision::Deny,
                    capability: normalized,
                    reason: "extension_deny".to_string(),
                };
            }
        }

        // Layer 2: global deny_caps.
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

        // Layer 3: per-extension allow.
        if let Some(ovr) = ext_override {
            if ovr
                .allow
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(&normalized))
            {
                return PolicyCheck {
                    decision: PolicyDecision::Allow,
                    capability: normalized,
                    reason: "extension_allow".to_string(),
                };
            }
        }

        // Layer 4: global default_caps.
        let in_default_caps = self
            .default_caps
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case(&normalized));

        // Layer 5: mode fallback (use per-extension mode if set).
        let effective_mode = ext_override.and_then(|ovr| ovr.mode).unwrap_or(self.mode);

        match effective_mode {
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

    /// Check whether a specific extension has any overrides configured.
    pub fn has_override(&self, extension_id: &str) -> bool {
        self.per_extension.contains_key(extension_id)
    }

    /// Create a policy from a named profile.
    pub fn from_profile(profile: PolicyProfile) -> Self {
        profile.to_policy()
    }
}

pub(crate) fn required_capability_for_host_call_static(
    call: &HostCallPayload,
) -> Option<&'static str> {
    let method = call.method.trim();
    if method.is_empty() {
        return None;
    }

    if method.eq_ignore_ascii_case("fs") {
        let op = call
            .params
            .get("op")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        let op = FsOp::parse(op)?;
        return Some(op.required_capability());
    }

    if method.eq_ignore_ascii_case("tool") {
        let tool_name = call
            .params
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)?;
        if tool_name.is_empty() {
            return None;
        }

        if tool_name.eq_ignore_ascii_case("read")
            || tool_name.eq_ignore_ascii_case("grep")
            || tool_name.eq_ignore_ascii_case("find")
            || tool_name.eq_ignore_ascii_case("ls")
        {
            return Some("read");
        }
        if tool_name.eq_ignore_ascii_case("write") || tool_name.eq_ignore_ascii_case("edit") {
            return Some("write");
        }
        if tool_name.eq_ignore_ascii_case("bash") {
            return Some("exec");
        }
        return Some("tool");
    }

    if method.eq_ignore_ascii_case("exec") {
        Some("exec")
    } else if method.eq_ignore_ascii_case("env") {
        Some("env")
    } else if method.eq_ignore_ascii_case("http") {
        Some("http")
    } else if method.eq_ignore_ascii_case("session") {
        Some("session")
    } else if method.eq_ignore_ascii_case("ui") {
        Some("ui")
    } else if method.eq_ignore_ascii_case("events") {
        Some("events")
    } else if method.eq_ignore_ascii_case("log") {
        Some("log")
    } else {
        None
    }
}

pub fn required_capability_for_host_call(call: &HostCallPayload) -> Option<String> {
    required_capability_for_host_call_static(call).map(str::to_string)
}

// ============================================================================
// Connectors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    Read,
    Write,
    List,
    Stat,
    Mkdir,
    Delete,
}

impl FsOp {
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("read") {
            Some(Self::Read)
        } else if value.eq_ignore_ascii_case("write") {
            Some(Self::Write)
        } else if value.eq_ignore_ascii_case("list") || value.eq_ignore_ascii_case("readdir") {
            Some(Self::List)
        } else if value.eq_ignore_ascii_case("stat") {
            Some(Self::Stat)
        } else if value.eq_ignore_ascii_case("mkdir") {
            Some(Self::Mkdir)
        } else if value.eq_ignore_ascii_case("delete")
            || value.eq_ignore_ascii_case("remove")
            || value.eq_ignore_ascii_case("rm")
        {
            Some(Self::Delete)
        } else {
            None
        }
    }

    const fn required_capability(self) -> &'static str {
        match self {
            Self::Read | Self::List | Self::Stat => "read",
            Self::Write | Self::Mkdir | Self::Delete => "write",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FsScopes {
    read_declared: bool,
    write_declared: bool,
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
}

impl FsScopes {
    pub fn least_privilege_for_cwd(cwd: &Path) -> Result<Self> {
        let root = canonicalize_root(cwd)?;
        Ok(Self {
            // Least-privilege default for unknown/new extensions: read-only project access.
            read_declared: true,
            write_declared: false,
            read_roots: vec![root],
            write_roots: Vec::new(),
        })
    }

    pub fn for_cwd(cwd: &Path) -> Result<Self> {
        let root = canonicalize_root(cwd)?;
        Ok(Self {
            read_declared: true,
            write_declared: true,
            read_roots: vec![root.clone()],
            write_roots: vec![root],
        })
    }

    pub fn from_manifest(manifest: Option<&CapabilityManifest>, cwd: &Path) -> Result<Self> {
        let Some(manifest) = manifest else {
            return Self::least_privilege_for_cwd(cwd);
        };

        let mut read_declared = false;
        let mut write_declared = false;
        let mut read_roots = Vec::new();
        let mut write_roots = Vec::new();

        for req in &manifest.capabilities {
            let cap = req.capability.trim().to_ascii_lowercase();
            if cap != "read" && cap != "write" {
                continue;
            }
            if cap == "read" {
                read_declared = true;
            } else {
                write_declared = true;
            }
            let Some(scope) = &req.scope else {
                continue;
            };
            let Some(paths) = &scope.paths else {
                continue;
            };

            for raw in paths {
                let root = resolve_scoped_root(raw, cwd)?;
                if cap == "read" {
                    read_roots.push(root);
                } else {
                    write_roots.push(root);
                }
            }
        }

        let fallback = canonicalize_root(cwd)?;
        if read_declared && read_roots.is_empty() {
            read_roots.push(fallback.clone());
        }
        if write_declared && write_roots.is_empty() {
            write_roots.push(fallback);
        }

        Ok(Self {
            read_declared,
            write_declared,
            read_roots,
            write_roots,
        })
    }

    fn roots_for_capability(&self, capability: &str) -> &[PathBuf] {
        if capability.eq_ignore_ascii_case("read") {
            if self.read_declared {
                &self.read_roots
            } else {
                &[]
            }
        } else if self.write_declared {
            &self.write_roots
        } else {
            &[]
        }
    }
}

#[derive(Debug, Clone)]
pub struct FsConnector {
    cwd: PathBuf,
    policy: ExtensionPolicy,
    scopes: FsScopes,
}

impl FsConnector {
    pub fn new(cwd: impl AsRef<Path>, policy: ExtensionPolicy, scopes: FsScopes) -> Result<Self> {
        let cwd = canonicalize_root(cwd.as_ref())?;
        Ok(Self {
            cwd,
            policy,
            scopes,
        })
    }

    pub fn handle_host_call(&self, call: &HostCallPayload) -> HostResultPayload {
        if !call.method.trim().eq_ignore_ascii_case("fs") {
            return HostResultPayload {
                call_id: call.call_id.clone(),
                output: json!({}),
                is_error: true,
                error: Some(HostCallError {
                    code: HostCallErrorCode::InvalidRequest,
                    message: "Unsupported hostcall method for FsConnector".to_string(),
                    details: Some(json!({ "method": call.method })),
                    retryable: None,
                }),
                chunk: None,
            };
        }

        let result = self.handle_fs_params(&call.params);
        match result {
            Ok(output) => HostResultPayload {
                call_id: call.call_id.clone(),
                output,
                is_error: false,
                error: None,
                chunk: None,
            },
            Err(error) => HostResultPayload {
                call_id: call.call_id.clone(),
                output: json!({}),
                is_error: true,
                error: Some(error),
                chunk: None,
            },
        }
    }

    fn handle_fs_params(&self, params: &Value) -> std::result::Result<Value, HostCallError> {
        let op = params
            .get("op")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        let op = FsOp::parse(op).ok_or_else(|| HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Invalid fs op".to_string(),
            details: Some(json!({ "op": op })),
            retryable: None,
        })?;

        let capability = op.required_capability();
        let policy_check = self.policy.evaluate(capability);
        if policy_check.decision != PolicyDecision::Allow {
            return Err(HostCallError {
                code: HostCallErrorCode::Denied,
                message: "Capability denied by policy".to_string(),
                details: Some(json!({
                    "capability": policy_check.capability,
                    "decision": format!("{:?}", policy_check.decision),
                    "reason": policy_check.reason,
                })),
                retryable: None,
            });
        }

        let roots = self.scopes.roots_for_capability(capability);
        if roots.is_empty() {
            return Err(HostCallError {
                code: HostCallErrorCode::Denied,
                message: format!("No allowed roots configured for '{capability}'"),
                details: Some(json!({
                    "capability": capability,
                    "hint": "Declare capability_manifest scope.paths for this capability."
                })),
                retryable: None,
            });
        }

        let path_str = params
            .get("path")
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or_else(|| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "Missing fs path".to_string(),
                details: None,
                retryable: None,
            })?;

        let target = resolve_target_path(&self.cwd, path_str)?;

        let canonical_target = match op {
            FsOp::Read | FsOp::List | FsOp::Stat | FsOp::Delete => canonicalize_existing(&target),
            FsOp::Write | FsOp::Mkdir => canonicalize_for_create(&target),
        }?;

        let matched_root = roots.iter().find(|root| canonical_target.starts_with(root));

        if matched_root.is_none() {
            let root_hashes = roots.iter().map(|root| hash_path(root)).collect::<Vec<_>>();
            tracing::warn!(
                event = "ext.fs.denied",
                op = ?op,
                capability = capability,
                path_hash = %hash_path(&canonical_target),
                scope_roots = ?root_hashes,
                "Denied fs operation outside allowlist",
            );
            return Err(HostCallError {
                code: HostCallErrorCode::Denied,
                message: "Path outside allowed scope; update capability_manifest scope.paths"
                    .to_string(),
                details: Some(json!({
                    "capability": capability,
                    "path_hash": hash_path(&canonical_target),
                    "scope_roots": root_hashes,
                    "hint": "Add an allowed path to capability_manifest scope.paths."
                })),
                retryable: None,
            });
        }

        let matched_root_hash = matched_root.map(|root| hash_path(root)).unwrap_or_default();
        tracing::info!(
            event = "ext.fs.call",
            op = ?op,
            capability = capability,
            path_hash = %hash_path(&canonical_target),
            scope_root = %matched_root_hash,
            "Executing fs operation",
        );

        match op {
            FsOp::Read => fs_op_read(params, &canonical_target),
            FsOp::Write => fs_op_write(params, &canonical_target),
            FsOp::List => fs_op_list(&canonical_target),
            FsOp::Stat => fs_op_stat(params, &canonical_target),
            FsOp::Mkdir => fs_op_mkdir(&canonical_target),
            FsOp::Delete => fs_op_delete(params, &canonical_target),
        }
    }
}

fn resolve_target_path(cwd: &Path, raw: &str) -> std::result::Result<PathBuf, HostCallError> {
    if raw.is_empty() {
        return Err(HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Path is empty".to_string(),
            details: None,
            retryable: None,
        });
    }

    let path = Path::new(raw);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    })
}

fn canonicalize_root(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path)
        .map(strip_unc_prefix)
        .map_err(|err| Error::extension(format!("canonicalize: {err}")))
}

fn resolve_scoped_root(raw: &str, cwd: &Path) -> Result<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::validation("Capability scope path is empty"));
    }

    let path = Path::new(raw);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    canonicalize_root(&resolved)
}

fn canonicalize_existing(path: &Path) -> std::result::Result<PathBuf, HostCallError> {
    std::fs::canonicalize(path)
        .map(strip_unc_prefix)
        .map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("canonicalize: {err}"),
            details: Some(json!({ "path": path.display().to_string() })),
            retryable: None,
        })
}

fn canonicalize_for_create(path: &Path) -> std::result::Result<PathBuf, HostCallError> {
    // For non-existing paths, canonicalize the nearest existing ancestor and re-append suffix.
    let mut ancestor = path.to_path_buf();
    while !ancestor.exists() {
        ancestor = ancestor
            .parent()
            .ok_or_else(|| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "Path has no existing ancestor".to_string(),
                details: Some(json!({ "path": path.display().to_string() })),
                retryable: None,
            })?
            .to_path_buf();
    }

    let canonical_ancestor = std::fs::canonicalize(&ancestor)
        .map(strip_unc_prefix)
        .map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("canonicalize: {err}"),
            details: Some(json!({ "path": ancestor.display().to_string() })),
            retryable: None,
        })?;

    let suffix = path.strip_prefix(&ancestor).map_err(|_| HostCallError {
        code: HostCallErrorCode::Internal,
        message: "Failed to compute path suffix".to_string(),
        details: Some(json!({
            "path": path.display().to_string(),
            "ancestor": ancestor.display().to_string(),
        })),
        retryable: None,
    })?;

    let mut normalized_parts: Vec<std::ffi::OsString> = Vec::new();
    let mut up_levels: usize = 0;
    for component in suffix.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => normalized_parts.push(part.to_os_string()),
            std::path::Component::ParentDir => {
                if normalized_parts.pop().is_none() {
                    up_levels = up_levels.saturating_add(1);
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(HostCallError {
                    code: HostCallErrorCode::InvalidRequest,
                    message: "Invalid path suffix".to_string(),
                    details: Some(json!({
                        "path": path.display().to_string(),
                        "ancestor": ancestor.display().to_string(),
                    })),
                    retryable: None,
                });
            }
        }
    }

    let mut base = canonical_ancestor;
    for _ in 0..up_levels {
        base = base
            .parent()
            .ok_or_else(|| HostCallError {
                code: HostCallErrorCode::Denied,
                message: "Path escapes filesystem root".to_string(),
                details: Some(json!({
                    "path": path.display().to_string(),
                    "ancestor": ancestor.display().to_string(),
                })),
                retryable: None,
            })?
            .to_path_buf();
    }

    let mut normalized_suffix = PathBuf::new();
    for part in normalized_parts {
        normalized_suffix.push(part);
    }

    Ok(base.join(normalized_suffix))
}

fn hash_path(path: &Path) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}")
}

fn fs_op_read(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let encoding = params
        .get("encoding")
        .and_then(Value::as_str)
        .map_or("utf8", str::trim);

    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > crate::tools::READ_TOOL_MAX_BYTES {
            return Err(HostCallError {
                code: HostCallErrorCode::Io,
                message: format!(
                    "File is too large ({} bytes). Max allowed is {} bytes.",
                    meta.len(),
                    crate::tools::READ_TOOL_MAX_BYTES
                ),
                details: None,
                retryable: None,
            });
        }
    }

    let bytes = fs::read(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("read: {err}"),
        details: None,
        retryable: None,
    })?;

    match encoding.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => {
            let text = String::from_utf8(bytes).map_err(|_| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "File is not valid UTF-8; use base64 encoding".to_string(),
                details: Some(json!({ "encoding": "base64" })),
                retryable: None,
            })?;
            Ok(json!({ "encoding": "utf8", "text": text }))
        }
        "base64" => {
            let data = base64::engine::general_purpose::STANDARD.encode(bytes);
            Ok(json!({ "encoding": "base64", "data": data }))
        }
        other => Err(HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Invalid encoding".to_string(),
            details: Some(json!({ "encoding": other })),
            retryable: None,
        }),
    }
}

fn fs_op_write(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let encoding = params
        .get("encoding")
        .and_then(Value::as_str)
        .map_or("utf8", str::trim);

    let data = params
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Missing write data".to_string(),
            details: None,
            retryable: None,
        })?;

    let bytes = match encoding.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => data.as_bytes().to_vec(),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|err| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: format!("Invalid base64: {err}"),
                details: None,
                retryable: None,
            })?,
        other => {
            return Err(HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "Invalid encoding".to_string(),
                details: Some(json!({ "encoding": other })),
                retryable: None,
            });
        }
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("mkdir parent: {err}"),
            details: None,
            retryable: None,
        })?;
    }

    fs::write(path, &bytes).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("write: {err}"),
        details: None,
        retryable: None,
    })?;

    Ok(json!({ "bytes_written": bytes.len() }))
}

fn fs_op_list(path: &Path) -> std::result::Result<Value, HostCallError> {
    let read_dir = fs::read_dir(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("read_dir: {err}"),
        details: None,
        retryable: None,
    })?;

    let mut entries = Vec::new();
    for entry in read_dir {
        if entries.len() >= crate::tools::LS_SCAN_HARD_LIMIT {
            return Err(HostCallError {
                code: HostCallErrorCode::Io,
                message: format!(
                    "Directory scan limit reached ({} entries).",
                    crate::tools::LS_SCAN_HARD_LIMIT
                ),
                details: None,
                retryable: None,
            });
        }

        let entry = entry.map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("read_dir entry: {err}"),
            details: None,
            retryable: None,
        })?;
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = fs::symlink_metadata(entry.path()).map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("metadata: {err}"),
            details: None,
            retryable: None,
        })?;
        let kind = if meta.file_type().is_symlink() {
            "symlink"
        } else if meta.is_dir() {
            "dir"
        } else if meta.is_file() {
            "file"
        } else {
            "other"
        };
        entries.push(json!({ "name": name, "kind": kind }));
    }

    Ok(json!({ "entries": entries }))
}

fn fs_op_stat(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let follow = params
        .get("follow_symlinks")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let meta = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    }
    .map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("stat: {err}"),
        details: None,
        retryable: None,
    })?;

    Ok(json!({
        "is_file": meta.is_file(),
        "is_dir": meta.is_dir(),
        "len": meta.len(),
    }))
}

fn fs_op_mkdir(path: &Path) -> std::result::Result<Value, HostCallError> {
    fs::create_dir_all(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("mkdir: {err}"),
        details: None,
        retryable: None,
    })?;
    Ok(json!({ "created": true }))
}

fn fs_op_delete(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let recursive = params
        .get("recursive")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let meta = fs::symlink_metadata(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("stat: {err}"),
        details: None,
        retryable: None,
    })?;

    if meta.is_dir() && !meta.file_type().is_symlink() {
        if recursive {
            fs::remove_dir_all(path)
        } else {
            fs::remove_dir(path)
        }
        .map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("remove_dir: {err}"),
            details: None,
            retryable: None,
        })?;
        return Ok(json!({ "deleted": true, "kind": "dir" }));
    }

    fs::remove_file(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("remove_file: {err}"),
        details: None,
        retryable: None,
    })?;

    Ok(json!({ "deleted": true, "kind": "file" }))
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_manifest: Option<CapabilityManifest>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub slash_commands: Vec<Value>,
    #[serde(default)]
    pub shortcuts: Vec<Value>,
    #[serde(default)]
    pub flags: Vec<Value>,
    #[serde(default)]
    pub event_hooks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub schema: String,
    pub capabilities: Vec<CapabilityRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirement {
    pub capability: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intents: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connector_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostcall_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<CapabilityScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CapabilityProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProvenance {
    pub source: String,
    pub integrity: CapabilityIntegrityAttestation,
    pub publisher: CapabilityPublisherAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityIntegrityAttestation {
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPublisherAttestation {
    pub id: String,
    pub verification: String,
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
    pub capability: String,
    pub method: String,
    pub params: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostCallErrorCode {
    Timeout,
    Denied,
    Io,
    InvalidRequest,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallError {
    pub code: HostCallErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStreamChunk {
    pub index: u64,
    pub is_last: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backpressure: Option<HostStreamBackpressure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStreamBackpressure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResultPayload {
    pub call_id: String,
    pub output: Value,
    pub is_error: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<HostCallError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk: Option<HostStreamChunk>,
}

// ============================================================================
// Shared Hostcall Dispatch (bd-1uy.1.3)
// ============================================================================

/// Context for the shared hostcall dispatcher.
///
/// Carries the runtime resources needed to dispatch any hostcall, regardless of
/// whether it originated from a JS extension, WASM component, or protocol message.
pub struct HostCallContext<'a> {
    /// Runtime origin identifier (e.g. `"js"`, `"wasm"`, `"protocol"`).
    pub runtime_name: &'a str,
    /// Extension that initiated the call (for policy + logging).
    pub extension_id: Option<&'a str>,
    /// Built-in tool registry.
    pub tools: &'a ToolRegistry,
    /// HTTP connector for outbound requests.
    pub http: &'a HttpConnector,
    /// Extension manager for session/ui/events dispatch.
    pub manager: Option<ExtensionManager>,
    /// Policy governing capability access.
    pub policy: &'a ExtensionPolicy,
    /// Optional JS runtime for exec streaming.
    pub js_runtime: Option<&'a PiJsRuntime>,
    /// Test interceptor (if any).
    pub interceptor: Option<&'a dyn HostcallInterceptor>,
}

/// Convert a [`HostcallRequest`] (JS-origin) into the canonical [`HostCallPayload`].
///
/// The canonical params shapes are:
/// - `tool`:  `{ "name": <tool_name>, "input": <payload> }`
/// - `exec`:  `{ "cmd": <string>, ...payload_fields }`
/// - `http`:  payload passthrough
/// - `session/ui/events`:  `{ "op": <string>, ...payload_fields }`
pub fn hostcall_request_to_payload(request: &HostcallRequest) -> HostCallPayload {
    let method = request.method().to_string();
    let capability = request.required_capability();
    let params = request.params_for_hash();
    let timeout_ms = js_hostcall_timeout_ms(request);

    HostCallPayload {
        call_id: request.call_id.clone(),
        capability,
        method,
        params,
        timeout_ms,
        cancel_token: None,
        context: None,
    }
}

/// Convert a [`HostResultPayload`] into the JS-facing [`HostcallOutcome`].
pub fn host_result_to_outcome(result: HostResultPayload) -> HostcallOutcome {
    if let Some(chunk_info) = result.chunk {
        return HostcallOutcome::StreamChunk {
            sequence: chunk_info.index,
            chunk: result.output,
            is_final: chunk_info.is_last,
        };
    }
    if result.is_error {
        let code = result
            .error
            .as_ref()
            .map_or("internal", |e| host_call_error_code_str(e.code));
        let message = result
            .error
            .as_ref()
            .map_or_else(|| "Unknown error".to_string(), |e| e.message.clone());
        HostcallOutcome::Error {
            code: code.to_string(),
            message,
        }
    } else {
        HostcallOutcome::Success(result.output)
    }
}

/// Convert a [`HostcallOutcome`] into a [`HostResultPayload`].
pub fn outcome_to_host_result(call_id: &str, outcome: &HostcallOutcome) -> HostResultPayload {
    match outcome {
        HostcallOutcome::Success(output) => HostResultPayload {
            call_id: call_id.to_string(),
            output: output.clone(),
            is_error: false,
            error: None,
            chunk: None,
        },
        HostcallOutcome::Error { code, message } => HostResultPayload {
            call_id: call_id.to_string(),
            output: json!({}),
            is_error: true,
            error: Some(HostCallError {
                code: parse_error_code(code),
                message: message.clone(),
                details: None,
                retryable: None,
            }),
            chunk: None,
        },
        HostcallOutcome::StreamChunk {
            sequence,
            chunk,
            is_final,
        } => HostResultPayload {
            call_id: call_id.to_string(),
            output: chunk.clone(),
            is_error: false,
            error: None,
            chunk: Some(HostStreamChunk {
                index: *sequence,
                is_last: *is_final,
                backpressure: None,
            }),
        },
    }
}

/// Map a string error code to the taxonomy enum, defaulting to `Internal`.
fn parse_error_code(code: &str) -> HostCallErrorCode {
    match code {
        "timeout" => HostCallErrorCode::Timeout,
        "denied" => HostCallErrorCode::Denied,
        "io" => HostCallErrorCode::Io,
        "invalid_request" => HostCallErrorCode::InvalidRequest,
        _ => HostCallErrorCode::Internal,
    }
}

/// Convert a taxonomy error code to its string representation.
const fn host_call_error_code_str(code: HostCallErrorCode) -> &'static str {
    match code {
        HostCallErrorCode::Timeout => "timeout",
        HostCallErrorCode::Denied => "denied",
        HostCallErrorCode::Io => "io",
        HostCallErrorCode::InvalidRequest => "invalid_request",
        HostCallErrorCode::Internal => "internal",
    }
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
    /// Extension that initiated this UI request (for provenance display).
    pub extension_id: Option<String>,
}

impl ExtensionUiRequest {
    pub fn new(id: impl Into<String>, method: impl Into<String>, payload: Value) -> Self {
        Self {
            id: id.into(),
            method: method.into(),
            payload,
            timeout_ms: None,
            extension_id: None,
        }
    }

    /// Set the extension ID for provenance tracking.
    #[must_use]
    pub fn with_extension_id(mut self, ext_id: Option<String>) -> Self {
        self.extension_id = ext_id;
        self
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
    async fn get_entries(&self) -> Vec<Value>;
    async fn get_branch(&self) -> Vec<Value>;
    async fn set_name(&self, name: String) -> Result<()>;
    async fn append_message(&self, message: SessionMessage) -> Result<()>;
    async fn append_custom_entry(&self, custom_type: String, data: Option<Value>) -> Result<()>;
    async fn set_model(&self, provider: String, model_id: String) -> Result<()>;
    async fn get_model(&self) -> (Option<String>, Option<String>);
    async fn set_thinking_level(&self, level: String) -> Result<()>;
    async fn get_thinking_level(&self) -> Option<String>;
    async fn set_label(&self, target_id: String, label: Option<String>) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionDeliverAs {
    Steer,
    FollowUp,
    NextTurn,
}

impl ExtensionDeliverAs {
    fn parse(value: Option<&str>) -> Option<Self> {
        let value = value?.trim();
        if value.is_empty() {
            return None;
        }
        match value {
            "steer" => Some(Self::Steer),
            "followUp" | "follow_up" | "follow-up" => Some(Self::FollowUp),
            "nextTurn" | "next_turn" | "next-turn" => Some(Self::NextTurn),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtensionSendMessage {
    pub extension_id: Option<String>,
    pub custom_type: String,
    pub content: String,
    pub display: bool,
    pub details: Option<Value>,
    pub deliver_as: Option<ExtensionDeliverAs>,
    pub trigger_turn: bool,
}

#[derive(Debug, Clone)]
pub struct ExtensionSendUserMessage {
    pub extension_id: Option<String>,
    pub text: String,
    pub deliver_as: Option<ExtensionDeliverAs>,
}

#[async_trait]
pub trait ExtensionHostActions: Send + Sync {
    async fn send_message(&self, message: ExtensionSendMessage) -> Result<()>;
    async fn send_user_message(&self, message: ExtensionSendUserMessage) -> Result<()>;
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

    if let Some(manifest) = &payload.capability_manifest {
        validate_capability_manifest(manifest)?;
    }
    Ok(())
}

fn capability_manifest_sha256_digest_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-fA-F0-9]{64}$").expect("regex"))
}

fn is_known_v2_capability(value: &str) -> bool {
    matches!(
        value,
        "read" | "write" | "exec" | "env" | "http" | "session" | "events" | "ui" | "log" | "tool"
    )
}

fn is_known_v2_intent(value: &str) -> bool {
    matches!(
        value,
        "file_read"
            | "file_write"
            | "process_exec"
            | "environment_access"
            | "network_egress"
            | "session_state_access"
            | "event_stream_access"
            | "ui_interaction"
            | "telemetry_logging"
    )
}

fn is_known_v2_connector_class(value: &str) -> bool {
    matches!(
        value,
        "tool" | "fs" | "exec" | "env" | "http" | "session" | "events" | "ui" | "log"
    )
}

fn is_known_v2_hostcall_class(value: &str) -> bool {
    matches!(
        value,
        "tool"
            | "exec"
            | "env"
            | "http"
            | "session"
            | "events"
            | "ui"
            | "log"
            | "fs.read"
            | "fs.write"
            | "fs.list"
            | "fs.stat"
            | "fs.mkdir"
            | "fs.delete"
    )
}

fn is_known_v2_risk_tier(value: &str) -> bool {
    matches!(value, "low" | "medium" | "high" | "critical")
}

fn is_known_v2_provenance_source(value: &str) -> bool {
    matches!(value, "npm" | "github" | "registry" | "local" | "builtin")
}

fn is_known_v2_publisher_verification(value: &str) -> bool {
    matches!(
        value,
        "unsigned" | "self_attested" | "key_attested" | "registry_attested"
    )
}

#[allow(clippy::too_many_lines)]
fn validate_capability_manifest(manifest: &CapabilityManifest) -> Result<()> {
    match manifest.schema.as_str() {
        CAPABILITY_MANIFEST_SCHEMA_V1 => {
            for (idx, req) in manifest.capabilities.iter().enumerate() {
                if req.capability.trim().is_empty() {
                    return Err(Error::validation(format!(
                        "Capability manifest v1 entry {idx} includes empty capability"
                    )));
                }
                if !req.intents.is_empty()
                    || !req.connector_classes.is_empty()
                    || !req.hostcall_classes.is_empty()
                    || req.risk_tier.is_some()
                    || req.provenance.is_some()
                    || req
                        .scope
                        .as_ref()
                        .is_some_and(|scope| scope.allowed_tools.is_some())
                {
                    return Err(Error::validation(format!(
                        "Capability manifest v1 entry {idx} contains v2-only fields"
                    )));
                }
            }
            Ok(())
        }
        CAPABILITY_MANIFEST_SCHEMA_V2 => {
            for (idx, req) in manifest.capabilities.iter().enumerate() {
                let capability = req.capability.trim();
                if capability.is_empty() {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} includes empty capability"
                    )));
                }
                if !is_known_v2_capability(capability) {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} has unsupported capability '{capability}'"
                    )));
                }
                if !req.methods.is_empty() {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} must not include legacy methods"
                    )));
                }
                if req.intents.is_empty() {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} must include at least one intent"
                    )));
                }
                for intent in &req.intents {
                    let intent = intent.trim();
                    if intent.is_empty() || !is_known_v2_intent(intent) {
                        return Err(Error::validation(format!(
                            "Capability manifest v2 entry {idx} has unsupported intent '{intent}'"
                        )));
                    }
                }
                if req.connector_classes.is_empty() {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} must include at least one connector class"
                    )));
                }
                for class_name in &req.connector_classes {
                    let class_name = class_name.trim();
                    if class_name.is_empty() || !is_known_v2_connector_class(class_name) {
                        return Err(Error::validation(format!(
                            "Capability manifest v2 entry {idx} has unsupported connector class '{class_name}'"
                        )));
                    }
                }
                if req.hostcall_classes.is_empty() {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} must include at least one hostcall class"
                    )));
                }
                for class_name in &req.hostcall_classes {
                    let class_name = class_name.trim();
                    if class_name.is_empty() || !is_known_v2_hostcall_class(class_name) {
                        return Err(Error::validation(format!(
                            "Capability manifest v2 entry {idx} has unsupported hostcall class '{class_name}'"
                        )));
                    }
                }
                if let Some(risk_tier) = req.risk_tier.as_deref() {
                    let risk_tier = risk_tier.trim();
                    if risk_tier.is_empty() || !is_known_v2_risk_tier(risk_tier) {
                        return Err(Error::validation(format!(
                            "Capability manifest v2 entry {idx} has unsupported risk_tier '{risk_tier}'"
                        )));
                    }
                }
                let Some(provenance) = req.provenance.as_ref() else {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} is missing provenance"
                    )));
                };
                let source = provenance.source.trim();
                if source.is_empty() || !is_known_v2_provenance_source(source) {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} has unsupported provenance source '{source}'"
                    )));
                }
                let algorithm = provenance.integrity.algorithm.trim();
                if algorithm != "sha256" {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} has unsupported integrity algorithm '{algorithm}'"
                    )));
                }
                let digest = provenance.integrity.digest.trim();
                if !capability_manifest_sha256_digest_regex().is_match(digest) {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} has invalid integrity digest"
                    )));
                }
                let publisher_id = provenance.publisher.id.trim();
                if publisher_id.is_empty() {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} has empty publisher id"
                    )));
                }
                let verification = provenance.publisher.verification.trim();
                if verification.is_empty() || !is_known_v2_publisher_verification(verification) {
                    return Err(Error::validation(format!(
                        "Capability manifest v2 entry {idx} has unsupported publisher verification '{verification}'"
                    )));
                }
            }
            Ok(())
        }
        _ => Err(Error::validation(format!(
            "Unsupported capability manifest schema: {}",
            manifest.schema
        ))),
    }
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

    if !payload.params.is_object() {
        return Err(Error::validation("Host call params must be an object"));
    }

    let declared_capability = payload.capability.trim().to_ascii_lowercase();
    if declared_capability.is_empty() {
        return Err(Error::validation("Host call capability is empty"));
    }

    if payload.method.trim().is_empty() {
        return Err(Error::validation("Host call method is empty"));
    }

    let required = required_capability_for_host_call_static(payload).ok_or_else(|| {
        Error::validation(format!(
            "Unknown or invalid host call method: {}",
            payload.method
        ))
    })?;

    if declared_capability != required {
        return Err(Error::validation(format!(
            "Host call capability mismatch: declared {declared_capability}, required {required}"
        )));
    }
    Ok(())
}

fn validate_host_result(payload: &HostResultPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Host result call_id is empty"));
    }
    if !payload.output.is_object() {
        return Err(Error::validation("Host result output must be an object"));
    }
    if payload.is_error {
        if payload.error.is_none() {
            return Err(Error::validation(
                "Host result marked is_error=true but error payload is missing",
            ));
        }
    } else if payload.error.is_some() {
        return Err(Error::validation(
            "Host result includes error payload but is_error=false",
        ));
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

#[cfg(feature = "wasm-host")]
#[derive(Debug, Clone)]
pub struct WasmExtension {
    pub path: PathBuf,
}

#[cfg(feature = "wasm-host")]
#[allow(clippy::trait_duplication_in_bounds)]
mod wasm_host {
    use super::*;

    use crate::connectors::http::{HttpConnector, HttpConnectorConfig};
    use std::collections::BTreeSet;
    use wasmtime::component::{Component, Linker};

    wasmtime::component::bindgen!({
        path: "docs/wit/extension.wit",
        world: "pi-extension",
        async: true,
    });

    use self::pi::extension::host;

    pub(super) struct HostState {
        policy: ExtensionPolicy,
        cwd: PathBuf,
        tools: Arc<crate::tools::ToolRegistry>,
        manager: Option<ExtensionManagerHandle>,
        http: HttpConnector,
        fs: FsConnector,
        env_allowlist: BTreeSet<String>,
        manifest_schema: Option<String>,
        manifest_requirements: Vec<CapabilityRequirement>,
        extension_id: Option<String>,
    }

    impl HostState {
        pub(super) fn new(policy: ExtensionPolicy, cwd: PathBuf) -> Result<Self> {
            let tools = Arc::new(crate::tools::ToolRegistry::new(
                &["read", "bash", "edit", "write", "grep", "find", "ls"],
                &cwd,
                None,
            ));
            Self::new_with_tools(policy, cwd, tools, None)
        }

        pub(super) fn new_with_tools(
            policy: ExtensionPolicy,
            cwd: PathBuf,
            tools: Arc<crate::tools::ToolRegistry>,
            manager: Option<ExtensionManagerHandle>,
        ) -> Result<Self> {
            let scopes = FsScopes::least_privilege_for_cwd(&cwd)?;
            let fs = FsConnector::new(&cwd, policy.clone(), scopes)?;
            Ok(Self {
                policy,
                cwd,
                tools,
                manager,
                http: HttpConnector::new(HttpConnectorConfig {
                    enforce_allowlist: true,
                    ..Default::default()
                }),
                fs,
                env_allowlist: BTreeSet::new(),
                manifest_schema: None,
                manifest_requirements: Vec::new(),
                extension_id: None,
            })
        }

        fn env_allowlist_from_manifest(manifest: Option<&CapabilityManifest>) -> BTreeSet<String> {
            let Some(manifest) = manifest else {
                return BTreeSet::new();
            };

            let mut out = BTreeSet::new();
            for req in &manifest.capabilities {
                if !req.capability.trim().eq_ignore_ascii_case("env") {
                    continue;
                }
                let Some(scope) = req.scope.as_ref() else {
                    continue;
                };
                let Some(env) = scope.env.as_ref() else {
                    continue;
                };
                for key in env {
                    let key = key.trim();
                    if !key.is_empty() {
                        out.insert(key.to_string());
                    }
                }
            }
            out
        }

        fn http_allowlist_from_manifest(manifest: Option<&CapabilityManifest>) -> Vec<String> {
            let Some(manifest) = manifest else {
                return Vec::new();
            };

            let mut out = Vec::new();
            for req in &manifest.capabilities {
                if !req.capability.trim().eq_ignore_ascii_case("http") {
                    continue;
                }
                let Some(scope) = req.scope.as_ref() else {
                    continue;
                };
                let Some(hosts) = scope.hosts.as_ref() else {
                    continue;
                };
                for host in hosts {
                    let host = host.trim();
                    if !host.is_empty() {
                        out.push(host.to_string());
                    }
                }
            }
            out
        }

        pub fn apply_registration(&mut self, registration: &RegisterPayload) -> Result<()> {
            if !registration.name.trim().is_empty() {
                self.extension_id = Some(registration.name.trim().to_string());
            }

            let manifest = registration.capability_manifest.as_ref();
            self.manifest_schema = manifest.map(|value| value.schema.clone());
            self.manifest_requirements =
                manifest.map_or_else(Vec::new, |value| value.capabilities.clone());

            self.env_allowlist = Self::env_allowlist_from_manifest(manifest);

            let fs_scopes = FsScopes::from_manifest(manifest, &self.cwd)?;
            self.fs = FsConnector::new(&self.cwd, self.policy.clone(), fs_scopes)?;

            let http_allowlist = Self::http_allowlist_from_manifest(manifest);
            self.http = HttpConnector::new(HttpConnectorConfig {
                allowlist: http_allowlist,
                enforce_allowlist: true,
                ..Default::default()
            });

            Ok(())
        }

        fn manager(&self) -> Option<ExtensionManager> {
            self.manager
                .as_ref()
                .and_then(ExtensionManagerHandle::upgrade)
        }

        fn hostcall_op(params: &Value) -> Option<String> {
            params
                .get("op")
                .or_else(|| params.get("method"))
                .or_else(|| params.get("name"))
                .and_then(Value::as_str)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        }

        fn matches_manifest_class(classes: &[String], class_name: &str) -> bool {
            classes
                .iter()
                .any(|value| value.trim().eq_ignore_ascii_case(class_name))
        }

        fn connector_class_for_call(call: &HostCallPayload) -> Option<&'static str> {
            let method = call.method.trim();
            if method.eq_ignore_ascii_case("tool") {
                Some("tool")
            } else if method.eq_ignore_ascii_case("fs") {
                Some("fs")
            } else if method.eq_ignore_ascii_case("exec") {
                Some("exec")
            } else if method.eq_ignore_ascii_case("env") {
                Some("env")
            } else if method.eq_ignore_ascii_case("http") {
                Some("http")
            } else if method.eq_ignore_ascii_case("session") {
                Some("session")
            } else if method.eq_ignore_ascii_case("events") {
                Some("events")
            } else if method.eq_ignore_ascii_case("ui") {
                Some("ui")
            } else if method.eq_ignore_ascii_case("log") {
                Some("log")
            } else {
                None
            }
        }

        fn hostcall_class_for_call(call: &HostCallPayload) -> Option<String> {
            let method = call.method.trim();
            if method.eq_ignore_ascii_case("fs") {
                let op = call
                    .params
                    .get("op")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or_default();
                let op = FsOp::parse(op)?;
                let suffix = match op {
                    FsOp::Read => "read",
                    FsOp::Write => "write",
                    FsOp::List => "list",
                    FsOp::Stat => "stat",
                    FsOp::Mkdir => "mkdir",
                    FsOp::Delete => "delete",
                };
                return Some(format!("fs.{suffix}"));
            }

            if method.is_empty() {
                None
            } else {
                Some(method.to_ascii_lowercase())
            }
        }

        fn enforce_manifest_classes(
            &self,
            required: &str,
            call: &HostCallPayload,
        ) -> std::result::Result<(), String> {
            if self.manifest_schema.as_deref() != Some(CAPABILITY_MANIFEST_SCHEMA_V2) {
                return Ok(());
            }

            let Some(connector_class) = Self::connector_class_for_call(call) else {
                return Ok(());
            };
            let Some(hostcall_class) = Self::hostcall_class_for_call(call) else {
                // Let downstream call parsing return the canonical invalid-request error.
                return Ok(());
            };

            let matching_requirements = self
                .manifest_requirements
                .iter()
                .filter(|req| req.capability.trim().eq_ignore_ascii_case(required))
                .collect::<Vec<_>>();

            if matching_requirements.is_empty() {
                return Err(Self::host_error_json(
                    HostCallErrorCode::Denied,
                    format!("Capability '{required}' not declared in capability manifest"),
                    Some(json!({
                        "capability": required,
                        "connector_class": connector_class,
                        "hostcall_class": hostcall_class,
                        "hint": "Declare this capability in capability_manifest.v2 before use."
                    })),
                    None,
                ));
            }

            let allowed = matching_requirements.iter().any(|req| {
                Self::matches_manifest_class(&req.connector_classes, connector_class)
                    && Self::matches_manifest_class(&req.hostcall_classes, &hostcall_class)
            });
            if allowed {
                return Ok(());
            }

            let allowed_connector_classes = matching_requirements
                .iter()
                .flat_map(|req| req.connector_classes.iter())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let allowed_hostcall_classes = matching_requirements
                .iter()
                .flat_map(|req| req.hostcall_classes.iter())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();

            Err(Self::host_error_json(
                HostCallErrorCode::Denied,
                format!(
                    "Capability scope mismatch: connector class '{connector_class}' / hostcall class '{hostcall_class}' is not allowed for capability '{required}'"
                ),
                Some(json!({
                    "capability": required,
                    "connector_class": connector_class,
                    "hostcall_class": hostcall_class,
                    "allowed_connector_classes": allowed_connector_classes,
                    "allowed_hostcall_classes": allowed_hostcall_classes,
                    "hint": "Update capability_manifest scope: connector_classes and hostcall_classes must include this call."
                })),
                None,
            ))
        }

        fn host_error_json(
            code: HostCallErrorCode,
            message: impl Into<String>,
            details: Option<Value>,
            retryable: Option<bool>,
        ) -> String {
            let payload = HostCallError {
                code,
                message: message.into(),
                details,
                retryable,
            };
            serde_json::to_string(&payload).unwrap_or_else(|_| {
                format!(
                    "{{\"code\":\"internal\",\"message\":\"failed to serialize error: {}\"}}",
                    payload.message
                )
            })
        }

        fn hostcall_outcome_code(code: &str) -> HostCallErrorCode {
            match code {
                "timeout" => HostCallErrorCode::Timeout,
                "denied" => HostCallErrorCode::Denied,
                "io" => HostCallErrorCode::Io,
                "invalid_request" => HostCallErrorCode::InvalidRequest,
                _ => HostCallErrorCode::Internal,
            }
        }

        fn hostcall_outcome_to_result(
            outcome: HostcallOutcome,
        ) -> std::result::Result<String, String> {
            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => serde_json::json!({
                    "sequence": sequence,
                    "chunk": chunk,
                    "isFinal": is_final,
                }),
                HostcallOutcome::Error { code, message } => {
                    return Err(Self::host_error_json(
                        Self::hostcall_outcome_code(&code),
                        message,
                        None,
                        None,
                    ));
                }
            };

            serde_json::to_string(&value).map_err(|err| {
                Self::host_error_json(
                    HostCallErrorCode::Internal,
                    format!("Failed to serialize hostcall output: {err}"),
                    None,
                    None,
                )
            })
        }

        async fn resolve_policy_decision(
            &self,
            required: &str,
        ) -> (PolicyDecision, String, String) {
            const UNKNOWN_EXTENSION_ID: &str = "<unknown>";
            let PolicyCheck {
                decision,
                capability,
                reason,
            } = self.policy.evaluate(required);

            if decision != PolicyDecision::Prompt {
                return (decision, reason, capability);
            }

            let Some(manager) = self.manager() else {
                return (
                    PolicyDecision::Deny,
                    "prompt_required_no_manager".to_string(),
                    capability,
                );
            };

            if let Some(extension_id) = self.extension_id.as_deref() {
                if let Some(allow) =
                    manager.cached_policy_prompt_decision(extension_id, &capability)
                {
                    let decision = if allow {
                        PolicyDecision::Allow
                    } else {
                        PolicyDecision::Deny
                    };
                    let reason = if allow {
                        "prompt_cache_allow".to_string()
                    } else {
                        "prompt_cache_deny".to_string()
                    };
                    return (decision, reason, capability);
                }
            }

            let prompt_extension_id = self.extension_id.as_deref().unwrap_or(UNKNOWN_EXTENSION_ID);
            let allow = prompt_capability_once(&manager, prompt_extension_id, &capability).await;
            if let Some(extension_id) = self.extension_id.as_deref() {
                manager.cache_policy_prompt_decision(extension_id, &capability, allow);
            }
            let decision = if allow {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny
            };
            let reason = if allow {
                "prompt_user_allow".to_string()
            } else {
                "prompt_user_deny".to_string()
            };
            (decision, reason, capability)
        }

        async fn dispatch_tool(
            &self,
            call: &HostCallPayload,
        ) -> std::result::Result<String, String> {
            let params = &call.params;
            let call_timeout_ms = call.timeout_ms.filter(|ms| *ms > 0);
            let tool_name = params
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .ok_or_else(|| {
                    Self::host_error_json(
                        HostCallErrorCode::InvalidRequest,
                        "Missing tool name",
                        None,
                        None,
                    )
                })?;
            let mut input = params
                .get("input")
                .cloned()
                .unwrap_or_else(|| Value::Object(serde_json::Map::default()));

            if tool_name.eq_ignore_ascii_case("bash") && input.get("timeout").is_none() {
                if let Some(timeout_ms) = call_timeout_ms {
                    let timeout_secs = timeout_ms.div_ceil(1000);
                    if let Some(obj) = input.as_object_mut() {
                        obj.insert("timeout".to_string(), json!(timeout_secs));
                    }
                }
            }

            let tool = self.tools.get(tool_name).ok_or_else(|| {
                Self::host_error_json(
                    HostCallErrorCode::InvalidRequest,
                    format!("Unknown tool: {tool_name}"),
                    Some(json!({ "tool": tool_name })),
                    None,
                )
            })?;

            let execute = tool.execute(&call.call_id, input, None);
            let output = if let Some(timeout_ms) = call_timeout_ms {
                match timeout(
                    wall_now(),
                    Duration::from_millis(timeout_ms),
                    Box::pin(execute),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        return Err(Self::host_error_json(
                            HostCallErrorCode::Timeout,
                            format!("Tool execution timed out after {timeout_ms}ms"),
                            Some(json!({ "tool": tool_name, "timeout_ms": timeout_ms })),
                            Some(true),
                        ));
                    }
                }
            } else {
                execute.await
            }
            .map_err(|err| match &err {
                Error::Validation(_) => Self::host_error_json(
                    HostCallErrorCode::InvalidRequest,
                    err.to_string(),
                    Some(json!({ "tool": tool_name })),
                    None,
                ),
                Error::Tool { .. } | Error::Io(_) => Self::host_error_json(
                    HostCallErrorCode::Io,
                    err.to_string(),
                    Some(json!({ "tool": tool_name })),
                    None,
                ),
                Error::Aborted => Self::host_error_json(
                    HostCallErrorCode::Timeout,
                    "Tool execution aborted",
                    Some(json!({ "tool": tool_name })),
                    Some(true),
                ),
                _ => Self::host_error_json(
                    HostCallErrorCode::Internal,
                    err.to_string(),
                    Some(json!({ "tool": tool_name })),
                    None,
                ),
            })?;

            serde_json::to_string(&output).map_err(|err| {
                Self::host_error_json(
                    HostCallErrorCode::Internal,
                    format!("Failed to serialize tool output: {err}"),
                    Some(json!({ "tool": tool_name })),
                    None,
                )
            })
        }

        async fn dispatch_http(
            &self,
            call: &HostCallPayload,
        ) -> std::result::Result<String, String> {
            let connector_call = crate::connectors::HostCallPayload {
                call_id: call.call_id.clone(),
                capability: call.capability.clone(),
                method: call.method.clone(),
                params: call.params.clone(),
                timeout_ms: call.timeout_ms,
                cancel_token: call.cancel_token.clone(),
                context: call.context.clone(),
            };

            let result = self.http.dispatch(&connector_call).await.map_err(|err| {
                Self::host_error_json(HostCallErrorCode::Internal, err.to_string(), None, None)
            })?;

            if result.is_error {
                let error = result.error.as_ref().map_or_else(
                    || {
                        Self::host_error_json(
                            HostCallErrorCode::Internal,
                            "HTTP connector returned is_error=true but no error payload",
                            None,
                            None,
                        )
                    },
                    |payload| {
                        Self::host_error_json(
                            payload.code,
                            payload.message.clone(),
                            payload.details.clone(),
                            payload.retryable,
                        )
                    },
                );
                return Err(error);
            }

            serde_json::to_string(&result.output).map_err(|err| {
                Self::host_error_json(
                    HostCallErrorCode::Internal,
                    format!("Failed to serialize HTTP output: {err}"),
                    None,
                    None,
                )
            })
        }

        async fn dispatch_exec(
            &self,
            call: &HostCallPayload,
        ) -> std::result::Result<String, String> {
            // Minimal: map exec -> bash tool (same sandbox semantics).
            let mut params = call.params.clone();
            if params.get("command").is_none() {
                let cmd = params
                    .get("cmd")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                let args_str = params.get("args").and_then(Value::as_array).map(|args| {
                    args.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                });
                if let (Some(cmd), Some(args_str)) = (cmd, args_str) {
                    let command = format!("{cmd} {args_str}");
                    if let Some(obj) = params.as_object_mut() {
                        obj.insert("command".to_string(), Value::String(command));
                        obj.remove("cmd");
                        obj.remove("args");
                    } else {
                        params = json!({ "command": command });
                    }
                }
            }

            let bash_call = HostCallPayload {
                call_id: call.call_id.clone(),
                capability: call.capability.clone(),
                method: "tool".to_string(),
                params: json!({ "name": "bash", "input": params }),
                timeout_ms: call.timeout_ms,
                cancel_token: call.cancel_token.clone(),
                context: call.context.clone(),
            };

            self.dispatch_tool(&bash_call).await
        }

        async fn dispatch_fs(&self, call: &HostCallPayload) -> std::result::Result<String, String> {
            let result = self.fs.handle_host_call(call);

            if result.is_error {
                let error = result.error.as_ref().map_or_else(
                    || {
                        Self::host_error_json(
                            HostCallErrorCode::Internal,
                            "FS connector returned is_error=true but no error payload",
                            None,
                            None,
                        )
                    },
                    |payload| {
                        Self::host_error_json(
                            payload.code,
                            payload.message.clone(),
                            payload.details.clone(),
                            payload.retryable,
                        )
                    },
                );
                return Err(error);
            }

            serde_json::to_string(&result.output).map_err(|err| {
                Self::host_error_json(
                    HostCallErrorCode::Internal,
                    format!("Failed to serialize fs output: {err}"),
                    None,
                    None,
                )
            })
        }

        fn sha256_hex(input: &str) -> String {
            let mut hasher = sha2::Sha256::new();
            hasher.update(input.as_bytes());
            let digest = hasher.finalize();
            format!("{digest:x}")
        }

        fn canonicalize_json(value: &Value) -> Value {
            match value {
                Value::Object(map) => {
                    let mut keys = map.keys().cloned().collect::<Vec<_>>();
                    keys.sort();
                    let mut out = serde_json::Map::new();
                    for key in keys {
                        if let Some(value) = map.get(&key) {
                            out.insert(key, Self::canonicalize_json(value));
                        }
                    }
                    Value::Object(out)
                }
                Value::Array(items) => {
                    Value::Array(items.iter().map(Self::canonicalize_json).collect())
                }
                other => other.clone(),
            }
        }

        fn hostcall_params_hash(method: &str, params: &Value) -> String {
            let canonical = Self::canonicalize_json(&json!({ "method": method, "params": params }));
            let encoded = serde_json::to_string(&canonical)
                .unwrap_or_else(|_| "{\"error\":\"canonical_hostcall_failed\"}".to_string());
            Self::sha256_hex(&encoded)
        }

        async fn dispatch_env(
            &self,
            call: &HostCallPayload,
        ) -> std::result::Result<String, String> {
            let params = &call.params;
            let mut names = Vec::new();

            if let Some(name) = params.get("name").and_then(Value::as_str) {
                let name = name.trim();
                if !name.is_empty() {
                    names.push(name.to_string());
                }
            } else if let Some(items) = params.get("names").and_then(Value::as_array) {
                for item in items {
                    if let Some(name) = item.as_str() {
                        let name = name.trim();
                        if !name.is_empty() {
                            names.push(name.to_string());
                        }
                    }
                }
            }

            if names.is_empty() {
                return Err(Self::host_error_json(
                    HostCallErrorCode::InvalidRequest,
                    "Missing env var name(s)",
                    None,
                    None,
                ));
            }

            if self.env_allowlist.is_empty() {
                return Err(Self::host_error_json(
                    HostCallErrorCode::Denied,
                    "Env access not configured (no allowlist)",
                    Some(json!({ "capability": "env" })),
                    None,
                ));
            }

            let mut denied_hashes = Vec::new();
            for name in &names {
                if !self.env_allowlist.contains(name) {
                    denied_hashes.push(Self::sha256_hex(name));
                }
            }

            if !denied_hashes.is_empty() {
                return Err(Self::host_error_json(
                    HostCallErrorCode::Denied,
                    "Env var not allowed by scope",
                    Some(json!({ "denied_hashes": denied_hashes })),
                    None,
                ));
            }

            let mut values = serde_json::Map::new();
            let broker = &self.policy;
            for name in names {
                match std::env::var_os(&name) {
                    None => {
                        values.insert(name, Value::Null);
                    }
                    Some(value) => match value.into_string() {
                        Ok(value) => {
                            // SEC-4.3: Apply secret broker redaction.
                            let final_value = broker.secret_broker.maybe_redact(&name, &value);
                            if final_value != value {
                                tracing::info!(
                                    event = "secret_broker.redact",
                                    name_hash = %Self::sha256_hex(&name),
                                    "Secret broker redacted env var value"
                                );
                            }
                            values.insert(name, Value::String(final_value.to_string()));
                        }
                        Err(_) => {
                            return Err(Self::host_error_json(
                                HostCallErrorCode::Io,
                                "Env var value is not valid UTF-8",
                                Some(json!({ "name_hash": Self::sha256_hex(&name) })),
                                None,
                            ));
                        }
                    },
                }
            }

            let output = json!({ "values": Value::Object(values) });
            serde_json::to_string(&output).map_err(|err| {
                Self::host_error_json(
                    HostCallErrorCode::Internal,
                    format!("Failed to serialize env output: {err}"),
                    None,
                    None,
                )
            })
        }
    }

    impl host::Host for HostState {
        #[allow(clippy::too_many_lines)]
        async fn call(
            &mut self,
            name: String,
            input_json: String,
        ) -> std::result::Result<String, String> {
            let payload: HostCallPayload = match serde_json::from_str(&input_json) {
                Ok(value) => value,
                Err(err) => {
                    return Err(Self::host_error_json(
                        HostCallErrorCode::InvalidRequest,
                        format!("Invalid host_call JSON: {err}"),
                        None,
                        None,
                    ));
                }
            };

            if !name.trim().is_empty() && !payload.method.eq_ignore_ascii_case(name.trim()) {
                return Err(Self::host_error_json(
                    HostCallErrorCode::InvalidRequest,
                    "host.call name must match host_call.method",
                    Some(json!({ "name": name, "method": payload.method })),
                    None,
                ));
            }

            let Some(required) = required_capability_for_host_call_static(&payload) else {
                return Err(Self::host_error_json(
                    HostCallErrorCode::InvalidRequest,
                    format!("Unknown host_call method: {}", payload.method),
                    Some(json!({ "method": payload.method })),
                    None,
                ));
            };

            if !payload.capability.trim().eq_ignore_ascii_case(required) {
                return Err(Self::host_error_json(
                    HostCallErrorCode::InvalidRequest,
                    "Capability mismatch: declared capability does not match derived capability",
                    Some(json!({
                        "declared": payload.capability,
                        "required": required,
                        "method": payload.method,
                    })),
                    None,
                ));
            }
            self.enforce_manifest_classes(required, &payload)?;

            let call_timeout_ms = payload.timeout_ms.filter(|ms| *ms > 0);
            let params_hash = Self::hostcall_params_hash(&payload.method, &payload.params);
            let started_at = Instant::now();

            tracing::info!(
                event = "host_call.start",
                runtime = "wasm",
                call_id = %payload.call_id,
                extension_id = ?self.extension_id.as_deref(),
                capability = %required,
                method = %payload.method,
                params_hash = %params_hash,
                timeout_ms = call_timeout_ms,
                "Hostcall start"
            );

            let (decision, reason, capability) = self.resolve_policy_decision(required).await;
            if decision == PolicyDecision::Allow {
                tracing::info!(
                    event = "policy.decision",
                    runtime = "wasm",
                    call_id = %payload.call_id,
                    extension_id = ?self.extension_id.as_deref(),
                    capability = %capability,
                    decision = ?decision,
                    reason = %reason,
                    params_hash = %params_hash,
                    "Hostcall allowed by policy"
                );
            } else {
                tracing::warn!(
                    event = "policy.decision",
                    runtime = "wasm",
                    call_id = %payload.call_id,
                    extension_id = ?self.extension_id.as_deref(),
                    capability = %capability,
                    decision = ?decision,
                    reason = %reason,
                    params_hash = %params_hash,
                    "Hostcall denied by policy"
                );
            }

            let method = payload.method.trim().to_ascii_lowercase();
            let outcome = if decision == PolicyDecision::Allow {
                let dispatch = async {
                    match method.as_str() {
                        "tool" => self.dispatch_tool(&payload).await,
                        "http" => self.dispatch_http(&payload).await,
                        "exec" => self.dispatch_exec(&payload).await,
                        "fs" => self.dispatch_fs(&payload).await,
                        "env" => self.dispatch_env(&payload).await,
                        "session" | "ui" | "events" => {
                            let op = Self::hostcall_op(&payload.params).ok_or_else(|| {
                                Self::host_error_json(
                                    HostCallErrorCode::InvalidRequest,
                                    format!("Missing host_call op for {method}"),
                                    Some(json!({ "method": method })),
                                    None,
                                )
                            })?;
                            let manager = self.manager().ok_or_else(|| {
                                Self::host_error_json(
                                    HostCallErrorCode::Denied,
                                    "No extension manager configured for host_call",
                                    Some(json!({ "method": method })),
                                    None,
                                )
                            })?;
                            let outcome = match method.as_str() {
                                "session" => {
                                    dispatch_hostcall_session(
                                        &payload.call_id,
                                        &manager,
                                        &op,
                                        payload.params.clone(),
                                    )
                                    .await
                                }
                                "ui" => {
                                    dispatch_hostcall_ui(
                                        &payload.call_id,
                                        &manager,
                                        &op,
                                        payload.params.clone(),
                                        self.extension_id.as_deref(),
                                    )
                                    .await
                                }
                                "events" => {
                                    dispatch_hostcall_events(
                                        &payload.call_id,
                                        &manager,
                                        self.tools.as_ref(),
                                        &op,
                                        payload.params.clone(),
                                    )
                                    .await
                                }
                                _ => HostcallOutcome::Error {
                                    code: "invalid_request".to_string(),
                                    message: format!("Unsupported host_call method: {method}"),
                                },
                            };
                            Self::hostcall_outcome_to_result(outcome)
                        }
                        _ => Err(Self::host_error_json(
                            HostCallErrorCode::InvalidRequest,
                            format!("Unsupported host_call method: {method}"),
                            Some(json!({ "method": method })),
                            None,
                        )),
                    }
                };

                match call_timeout_ms {
                    Some(timeout_ms) => timeout(
                        wall_now(),
                        Duration::from_millis(timeout_ms),
                        Box::pin(dispatch),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        Err(Self::host_error_json(
                            HostCallErrorCode::Timeout,
                            format!("Hostcall timed out after {timeout_ms}ms"),
                            Some(json!({ "capability": required, "method": method })),
                            Some(true),
                        ))
                    }),
                    None => dispatch.await,
                }
            } else {
                Err(Self::host_error_json(
                    HostCallErrorCode::Denied,
                    format!("Capability '{capability}' denied by policy ({reason})"),
                    Some(json!({
                        "capability": capability,
                        "decision": format!("{:?}", decision),
                        "reason": reason,
                    })),
                    None,
                ))
            };

            let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            let (is_error, error_code) = match &outcome {
                Ok(_) => (false, None),
                Err(err_json) => (
                    true,
                    serde_json::from_str::<HostCallError>(err_json)
                        .ok()
                        .map(|err| err.code),
                ),
            };

            if is_error {
                tracing::warn!(
                    event = "host_call.end",
                    runtime = "wasm",
                    call_id = %payload.call_id,
                    extension_id = ?self.extension_id.as_deref(),
                    capability = %required,
                    method = %payload.method,
                    params_hash = %params_hash,
                    duration_ms,
                    error_code = ?error_code,
                    "Hostcall end (error)"
                );
            } else {
                tracing::info!(
                    event = "host_call.end",
                    runtime = "wasm",
                    call_id = %payload.call_id,
                    extension_id = ?self.extension_id.as_deref(),
                    capability = %required,
                    method = %payload.method,
                    params_hash = %params_hash,
                    duration_ms,
                    "Hostcall end (success)"
                );
            }

            outcome
        }
    }

    pub struct Instance {
        store: wasmtime::Store<HostState>,
        bindings: PiExtension,
    }

    impl Instance {
        pub(super) async fn instantiate(
            engine: &wasmtime::Engine,
            path: &Path,
            state: HostState,
        ) -> Result<Self> {
            let component = Component::from_file(engine, path).map_err(|err| {
                Error::extension(format!(
                    "Failed to load WASM component {}: {err}",
                    path.display()
                ))
            })?;

            let mut linker = Linker::<HostState>::new(engine);
            host::add_to_linker(&mut linker, |data| data).map_err(|err| {
                Error::extension(format!("Failed to link WASM host imports: {err}"))
            })?;

            let mut store = wasmtime::Store::new(engine, state);
            let bindings = PiExtension::instantiate_async(&mut store, &component, &linker)
                .await
                .map_err(|err| {
                    Error::extension(format!("Failed to instantiate WASM extension: {err}"))
                })?;

            Ok(Self { store, bindings })
        }

        pub async fn init(&mut self, manifest_json: &str) -> Result<String> {
            let result = self
                .bindings
                .interface0
                .call_init(&mut self.store, manifest_json)
                .await
                .map_err(|err| Error::extension(format!("WASM init failed: {err}")))?;

            let registration_json = result.map_err(Error::extension)?;
            let registration: RegisterPayload =
                serde_json::from_str(&registration_json).map_err(|err| {
                    Error::extension(format!(
                        "WASM init returned invalid registration payload: {err}"
                    ))
                })?;
            validate_register(&registration)?;
            self.store.data_mut().apply_registration(&registration)?;

            Ok(registration_json)
        }

        pub async fn handle_tool(&mut self, name: &str, input_json: &str) -> Result<String> {
            let result = self
                .bindings
                .interface0
                .call_handle_tool(&mut self.store, name, input_json)
                .await
                .map_err(|err| Error::extension(format!("WASM handle-tool failed: {err}")))?;

            result.map_err(Error::extension)
        }

        pub async fn handle_slash(
            &mut self,
            command: &str,
            args: &[String],
            input_json: &str,
        ) -> Result<String> {
            let result = self
                .bindings
                .interface0
                .call_handle_slash(&mut self.store, command, args, input_json)
                .await
                .map_err(|err| Error::extension(format!("WASM handle-slash failed: {err}")))?;

            result.map_err(Error::extension)
        }

        pub async fn handle_event(&mut self, event_json: &str) -> Result<String> {
            let result = self
                .bindings
                .interface0
                .call_handle_event(&mut self.store, event_json)
                .await
                .map_err(|err| Error::extension(format!("WASM handle-event failed: {err}")))?;

            result.map_err(Error::extension)
        }

        pub async fn shutdown(&mut self) -> Result<()> {
            self.bindings
                .interface0
                .call_shutdown(&mut self.store)
                .await
                .map_err(|err| Error::extension(format!("WASM shutdown failed: {err}")))?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::connectors::http::HttpConnectorConfig;
        use crate::model::ContentBlock;
        use crate::tools::{Tool, ToolOutput, ToolRegistry, ToolUpdate};
        use asupersync::runtime::RuntimeBuilder;
        use asupersync::time::{sleep, wall_now};
        use async_trait::async_trait;
        use serde_json::json;
        use std::collections::BTreeMap;
        use std::future::Future;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;
        use tempfile::tempdir;

        fn run_async<T, Fut>(future: Fut) -> T
        where
            Fut: Future<Output = T>,
        {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("build asupersync runtime");
            runtime.block_on(future)
        }

        fn permissive_policy() -> ExtensionPolicy {
            ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                ..Default::default()
            }
        }

        fn strict_policy(default_caps: &[&str], deny_caps: &[&str]) -> ExtensionPolicy {
            ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: default_caps.iter().map(|cap| (*cap).to_string()).collect(),
                deny_caps: deny_caps.iter().map(|cap| (*cap).to_string()).collect(),
                ..Default::default()
            }
        }

        fn registration_payload() -> RegisterPayload {
            RegisterPayload {
                name: "ext.test".to_string(),
                version: "0.1.0".to_string(),
                api_version: PROTOCOL_VERSION.to_string(),
                capabilities: Vec::new(),
                capability_manifest: Some(CapabilityManifest {
                    schema: "pi.ext.cap.v1".to_string(),
                    capabilities: vec![
                        CapabilityRequirement {
                            capability: "env".to_string(),
                            methods: vec!["env".to_string()],
                            intents: Vec::new(),
                            connector_classes: Vec::new(),
                            hostcall_classes: Vec::new(),
                            risk_tier: None,
                            scope: Some(CapabilityScope {
                                env: Some(vec!["PI_TEST_ENV".to_string()]),
                                paths: None,
                                hosts: None,
                                allowed_tools: None,
                            }),
                            provenance: None,
                        },
                        CapabilityRequirement {
                            capability: "read".to_string(),
                            methods: vec!["fs".to_string()],
                            intents: Vec::new(),
                            connector_classes: Vec::new(),
                            hostcall_classes: Vec::new(),
                            risk_tier: None,
                            scope: Some(CapabilityScope {
                                paths: Some(vec![".".to_string()]),
                                hosts: None,
                                env: None,
                                allowed_tools: None,
                            }),
                            provenance: None,
                        },
                    ],
                }),
                tools: Vec::new(),
                slash_commands: Vec::new(),
                shortcuts: Vec::new(),
                flags: Vec::new(),
                event_hooks: Vec::new(),
            }
        }

        fn registration_payload_with_write_scope() -> RegisterPayload {
            let mut payload = registration_payload();
            let CapabilityManifest { capabilities, .. } = payload
                .capability_manifest
                .get_or_insert_with(|| CapabilityManifest {
                    schema: "pi.ext.cap.v1".to_string(),
                    capabilities: Vec::new(),
                });
            capabilities.push(CapabilityRequirement {
                capability: "write".to_string(),
                methods: vec!["fs".to_string()],
                intents: Vec::new(),
                connector_classes: Vec::new(),
                hostcall_classes: Vec::new(),
                risk_tier: None,
                scope: Some(CapabilityScope {
                    paths: Some(vec![".".to_string()]),
                    hosts: None,
                    env: None,
                    allowed_tools: None,
                }),
                provenance: None,
            });
            payload
        }

        fn registration_payload_v2_read_fs_scope() -> RegisterPayload {
            RegisterPayload {
                name: "ext.test".to_string(),
                version: "0.2.0".to_string(),
                api_version: PROTOCOL_VERSION.to_string(),
                capabilities: Vec::new(),
                capability_manifest: Some(CapabilityManifest {
                    schema: CAPABILITY_MANIFEST_SCHEMA_V2.to_string(),
                    capabilities: vec![CapabilityRequirement {
                        capability: "read".to_string(),
                        methods: Vec::new(),
                        intents: vec!["file_read".to_string()],
                        connector_classes: vec!["fs".to_string()],
                        hostcall_classes: vec!["fs.read".to_string()],
                        risk_tier: Some("low".to_string()),
                        scope: Some(CapabilityScope {
                            paths: Some(vec![".".to_string()]),
                            hosts: None,
                            env: None,
                            allowed_tools: None,
                        }),
                        provenance: Some(CapabilityProvenance {
                            source: "local".to_string(),
                            integrity: CapabilityIntegrityAttestation {
                                algorithm: "sha256".to_string(),
                                digest:
                                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                        .to_string(),
                            },
                            publisher: CapabilityPublisherAttestation {
                                id: "publisher.local.test".to_string(),
                                verification: "unsigned".to_string(),
                            },
                        }),
                    }],
                }),
                tools: Vec::new(),
                slash_commands: Vec::new(),
                shortcuts: Vec::new(),
                flags: Vec::new(),
                event_hooks: Vec::new(),
            }
        }

        #[derive(Debug, Clone)]
        struct CapturedEvent {
            level: tracing::Level,
            fields: BTreeMap<String, String>,
        }

        #[derive(Clone, Default)]
        struct CaptureLayer {
            events: Arc<Mutex<Vec<CapturedEvent>>>,
        }

        impl CaptureLayer {
            fn snapshot(&self) -> Vec<CapturedEvent> {
                self.events
                    .lock()
                    .expect("events mutex")
                    .iter()
                    .cloned()
                    .collect()
            }
        }

        struct FieldVisitor<'a> {
            fields: &'a mut BTreeMap<String, String>,
        }

        impl tracing::field::Visit for FieldVisitor<'_> {
            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }

            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.fields
                    .insert(field.name().to_string(), format!("{value:?}"));
            }
        }

        impl<S> tracing_subscriber::Layer<S> for CaptureLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let mut fields = BTreeMap::new();
                let mut visitor = FieldVisitor {
                    fields: &mut fields,
                };
                event.record(&mut visitor);
                self.events
                    .lock()
                    .expect("events mutex")
                    .push(CapturedEvent {
                        level: *event.metadata().level(),
                        fields,
                    });
            }
        }

        fn capture_tracing_events<T>(f: impl FnOnce() -> T) -> (T, Vec<CapturedEvent>) {
            use tracing_subscriber::layer::SubscriberExt as _;

            let capture = CaptureLayer::default();
            let subscriber = tracing_subscriber::registry().with(capture.clone());
            let result = tracing::subscriber::with_default(subscriber, f);
            (result, capture.snapshot())
        }

        fn find_policy_decisions<'a>(
            events: &'a [CapturedEvent],
            call_id: &str,
        ) -> Vec<&'a CapturedEvent> {
            events
                .iter()
                .filter(|event| {
                    event
                        .fields
                        .get("event")
                        .is_some_and(|value| value == "policy.decision")
                        && event
                            .fields
                            .get("call_id")
                            .is_some_and(|value| value == call_id)
                })
                .collect()
        }

        fn assert_policy_decision_logged(
            events: &[CapturedEvent],
            call_id: &str,
            capability: &str,
            decision: &str,
        ) {
            let matching = find_policy_decisions(events, call_id);
            assert!(
                !matching.is_empty(),
                "expected policy.decision log for call_id={call_id}; got events: {events:#?}"
            );
            assert!(
                matching.iter().any(|event| {
                    event
                        .fields
                        .get("capability")
                        .is_some_and(|value| value == capability)
                        && event
                            .fields
                            .get("decision")
                            .is_some_and(|value| value == decision)
                        && event
                            .fields
                            .get("extension_id")
                            .is_some_and(|value| value.contains("ext.test"))
                }),
                "expected policy.decision with capability={capability} decision={decision} extension_id=ext.test; got: {matching:#?}"
            );
        }

        #[derive(Debug)]
        struct SleepTool;

        #[async_trait]
        impl Tool for SleepTool {
            fn name(&self) -> &'static str {
                "sleep"
            }

            fn label(&self) -> &'static str {
                "sleep"
            }

            fn description(&self) -> &'static str {
                "sleep tool"
            }

            fn parameters(&self) -> Value {
                json!({ "type": "object" })
            }

            async fn execute(
                &self,
                _tool_call_id: &str,
                _input: Value,
                _on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>,
            ) -> Result<ToolOutput> {
                sleep(wall_now(), Duration::from_millis(200)).await;
                Ok(ToolOutput {
                    content: vec![],
                    details: None,
                    is_error: false,
                })
            }
        }

        #[test]
        fn wasm_host_env_requires_allowlist() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");

            let allowed_call = HostCallPayload {
                call_id: "call-env-1".to_string(),
                capability: "env".to_string(),
                method: "env".to_string(),
                params: json!({ "name": "PI_TEST_ENV" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let allowed_json = serde_json::to_string(&allowed_call).expect("serialize hostcall");
            let allowed_out = run_async(async {
                host::Host::call(&mut state, "env".to_string(), allowed_json).await
            })
            .expect("env hostcall ok");

            let out: Value = serde_json::from_str(&allowed_out).expect("parse env output");
            let values = out
                .get("values")
                .and_then(Value::as_object)
                .expect("values object");
            assert!(values.get("PI_TEST_ENV").is_some());

            let denied_call = HostCallPayload {
                call_id: "call-env-2".to_string(),
                capability: "env".to_string(),
                method: "env".to_string(),
                params: json!({ "name": "NOT_ALLOWED_ENV" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let denied_json = serde_json::to_string(&denied_call).expect("serialize hostcall");
            let err_json = run_async(async {
                host::Host::call(&mut state, "env".to_string(), denied_json).await
            })
            .expect_err("env hostcall denied");
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Denied);
        }

        #[test]
        fn wasm_host_env_denied_by_policy_even_when_allowlisted() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(ExtensionPolicy::default(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-env-policy-deny".to_string(),
                capability: "env".to_string(),
                method: "env".to_string(),
                params: json!({ "name": "PI_TEST_ENV" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let ((outcome, ()), events) = capture_tracing_events(|| {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                let outcome = run_async(async {
                    host::Host::call(&mut state, "env".to_string(), json).await
                });
                (outcome, ())
            });

            let err_json = outcome.expect_err("env hostcall denied by policy");
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert_policy_decision_logged(&events, &call.call_id, "env", "Deny");
        }

        #[test]
        fn wasm_host_fs_respects_manifest_scopes() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();
            std::fs::write(dir.path().join("file.txt"), "hello").expect("write file");

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");

            let read_call = HostCallPayload {
                call_id: "call-fs-read".to_string(),
                capability: "read".to_string(),
                method: "fs".to_string(),
                params: json!({ "op": "read", "path": "file.txt" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let read_json = serde_json::to_string(&read_call).expect("serialize hostcall");
            let read_out = run_async(async {
                host::Host::call(&mut state, "fs".to_string(), read_json).await
            })
            .expect("fs read ok");
            let out: Value = serde_json::from_str(&read_out).expect("parse fs output");
            assert_eq!(out.get("text").and_then(Value::as_str), Some("hello"));

            let write_call = HostCallPayload {
                call_id: "call-fs-write".to_string(),
                capability: "write".to_string(),
                method: "fs".to_string(),
                params: json!({ "op": "write", "path": "out.txt", "encoding": "utf8", "data": "hi" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let write_json = serde_json::to_string(&write_call).expect("serialize hostcall");
            let err_json = run_async(async {
                host::Host::call(&mut state, "fs".to_string(), write_json).await
            })
            .expect_err("fs write denied");
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Denied);
        }

        #[test]
        fn wasm_host_v2_manifest_denies_connector_class_mismatch() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();
            std::fs::write(dir.path().join("file.txt"), "hello").expect("write file");

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload_v2_read_fs_scope())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-v2-connector-class-deny".to_string(),
                capability: "read".to_string(),
                method: "tool".to_string(),
                params: json!({ "name": "read", "input": { "file_path": "file.txt" } }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let err_json = {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                run_async(async { host::Host::call(&mut state, "tool".to_string(), json).await })
                    .expect_err("tool read should be denied by connector class scope")
            };
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("connector class"),
                "expected connector class guidance, got: {}",
                err.message
            );
        }

        #[test]
        fn wasm_host_v2_manifest_denies_hostcall_class_mismatch() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();
            std::fs::write(dir.path().join("file.txt"), "hello").expect("write file");

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload_v2_read_fs_scope())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-v2-hostcall-class-deny".to_string(),
                capability: "read".to_string(),
                method: "fs".to_string(),
                params: json!({ "op": "list", "path": "." }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let err_json = {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                run_async(async { host::Host::call(&mut state, "fs".to_string(), json).await })
                    .expect_err("fs.list should be denied when only fs.read is allowed")
            };
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("hostcall class"),
                "expected hostcall class guidance, got: {}",
                err.message
            );
        }

        #[test]
        fn wasm_host_v2_manifest_allows_matching_connector_and_hostcall_classes() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();
            std::fs::write(dir.path().join("file.txt"), "hello").expect("write file");

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload_v2_read_fs_scope())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-v2-hostcall-class-allow".to_string(),
                capability: "read".to_string(),
                method: "fs".to_string(),
                params: json!({ "op": "read", "path": "file.txt" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let out_json = {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                run_async(async { host::Host::call(&mut state, "fs".to_string(), json).await })
                    .expect("fs.read should be allowed by matching v2 scope classes")
            };
            let out: Value = serde_json::from_str(&out_json).expect("parse fs output");
            assert_eq!(out.get("text").and_then(Value::as_str), Some("hello"));
        }

        #[test]
        fn wasm_host_fs_defaults_to_read_only_without_manifest() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();
            std::fs::write(dir.path().join("file.txt"), "hello").expect("write file");

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");

            let read_call = HostCallPayload {
                call_id: "call-fs-read-default".to_string(),
                capability: "read".to_string(),
                method: "fs".to_string(),
                params: json!({ "op": "read", "path": "file.txt" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };
            let read_json = serde_json::to_string(&read_call).expect("serialize hostcall");
            let read_out = run_async(async {
                host::Host::call(&mut state, "fs".to_string(), read_json).await
            })
            .expect("fs read ok");
            let out: Value = serde_json::from_str(&read_out).expect("parse fs output");
            assert_eq!(out.get("text").and_then(Value::as_str), Some("hello"));

            let write_call = HostCallPayload {
                call_id: "call-fs-write-default".to_string(),
                capability: "write".to_string(),
                method: "fs".to_string(),
                params: json!({
                    "op": "write",
                    "path": "out.txt",
                    "encoding": "utf8",
                    "data": "hi"
                }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };
            let write_json = serde_json::to_string(&write_call).expect("serialize hostcall");
            let err_json = run_async(async {
                host::Host::call(&mut state, "fs".to_string(), write_json).await
            })
            .expect_err("fs write denied by least-privilege default");
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("scope.paths"),
                "expected scope guidance, got: {}",
                err.message
            );
        }

        #[test]
        fn wasm_host_fs_write_succeeds_with_write_scope_and_logs_policy() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload_with_write_scope())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-fs-write-ok".to_string(),
                capability: "write".to_string(),
                method: "fs".to_string(),
                params: json!({ "op": "write", "path": "out.txt", "encoding": "utf8", "data": "hi" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let ((out, ()), events) = capture_tracing_events(|| {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                let out =
                    run_async(async { host::Host::call(&mut state, "fs".to_string(), json).await })
                        .expect("fs write ok");
                (out, ())
            });

            let out: Value = serde_json::from_str(&out).expect("parse fs output");
            assert_eq!(out.get("bytes_written").and_then(Value::as_u64), Some(2));
            assert_eq!(
                std::fs::read_to_string(dir.path().join("out.txt")).expect("read out.txt"),
                "hi"
            );
            assert_policy_decision_logged(&events, &call.call_id, "write", "Allow");
        }

        #[test]
        fn wasm_host_tool_call_times_out_and_returns_timeout_error() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state.tools = Arc::new(ToolRegistry::from_tools(vec![Box::new(SleepTool)]));
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-tool-timeout".to_string(),
                capability: "tool".to_string(),
                method: "tool".to_string(),
                params: json!({ "name": "sleep", "input": {} }),
                timeout_ms: Some(50),
                cancel_token: None,
                context: None,
            };

            let ((outcome, ()), events) = capture_tracing_events(|| {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                let outcome = run_async(async {
                    host::Host::call(&mut state, "tool".to_string(), json).await
                });
                (outcome, ())
            });

            let err_json = outcome.expect_err("tool hostcall timeout");
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Timeout);
            assert_policy_decision_logged(&events, &call.call_id, "tool", "Allow");
        }

        #[test]
        fn wasm_host_exec_denied_by_default_policy_and_logs_decision() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(ExtensionPolicy::default(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-exec-deny".to_string(),
                capability: "exec".to_string(),
                method: "exec".to_string(),
                params: json!({ "command": "echo hi" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let ((outcome, ()), events) = capture_tracing_events(|| {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                let outcome = run_async(async {
                    host::Host::call(&mut state, "exec".to_string(), json).await
                });
                (outcome, ())
            });

            let err_json = outcome.expect_err("exec denied");
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error json");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert_policy_decision_logged(&events, &call.call_id, "exec", "Deny");
        }

        #[test]
        fn wasm_host_exec_succeeds_when_policy_allows() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(permissive_policy(), cwd).expect("host state");
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-exec-ok".to_string(),
                capability: "exec".to_string(),
                method: "exec".to_string(),
                params: json!({ "command": "echo hello" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            let out_json = {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                run_async(async { host::Host::call(&mut state, "exec".to_string(), json).await })
                    .expect("exec ok")
            };

            let output: ToolOutput = serde_json::from_str(&out_json).expect("parse tool output");
            assert!(!output.is_error);
            let text = output
                .content
                .iter()
                .filter_map(|block| match block {
                    ContentBlock::Text(text) => Some(text.text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("hello"));
        }

        #[test]
        fn wasm_host_http_get_succeeds_against_local_server_when_configured() {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let addr = listener.local_addr().expect("local addr");

            let join = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = stream.write_all(response);
            });

            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(strict_policy(&["http"], &[]), cwd).expect("host state");
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");
            state.http = HttpConnector::new(HttpConnectorConfig {
                require_tls: false,
                allowlist: vec!["127.0.0.1".to_string()],
                ..Default::default()
            });

            let url = format!("http://127.0.0.1:{}/", addr.port());
            let call = HostCallPayload {
                call_id: "call-http-ok".to_string(),
                capability: "http".to_string(),
                method: "http".to_string(),
                params: json!({ "url": url, "method": "GET" }),
                timeout_ms: Some(2000),
                cancel_token: None,
                context: None,
            };

            let out_json = {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                run_async(async { host::Host::call(&mut state, "http".to_string(), json).await })
                    .expect("http ok")
            };

            let out: Value = serde_json::from_str(&out_json).expect("parse http output");
            assert_eq!(out.get("status").and_then(Value::as_u64), Some(200));
            assert_eq!(out.get("body").and_then(Value::as_str), Some("ok"));

            join.join().expect("server thread join");
        }

        #[test]
        fn wasm_host_http_denied_by_default_without_http_allowlist_scope() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut state = HostState::new(strict_policy(&["http"], &[]), cwd).expect("host state");
            state
                .apply_registration(&registration_payload())
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-http-deny-default".to_string(),
                capability: "http".to_string(),
                method: "http".to_string(),
                params: json!({ "url": "https://example.com", "method": "GET" }),
                timeout_ms: Some(500),
                cancel_token: None,
                context: None,
            };

            let err_json = {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                run_async(async { host::Host::call(&mut state, "http".to_string(), json).await })
                    .expect_err("http should be denied without scoped allowlist")
            };
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("allowlist"),
                "expected allowlist guidance, got: {}",
                err.message
            );
        }

        #[test]
        fn wasm_host_http_denied_when_http_capability_has_no_hosts_scope() {
            let dir = tempdir().expect("tempdir");
            let cwd = dir.path().to_path_buf();

            let mut payload = registration_payload();
            payload
                .capability_manifest
                .as_mut()
                .expect("capability manifest")
                .capabilities
                .push(CapabilityRequirement {
                    capability: "http".to_string(),
                    methods: vec!["http".to_string()],
                    intents: Vec::new(),
                    connector_classes: Vec::new(),
                    hostcall_classes: Vec::new(),
                    risk_tier: None,
                    scope: None,
                    provenance: None,
                });

            let mut state = HostState::new(strict_policy(&["http"], &[]), cwd).expect("host state");
            state
                .apply_registration(&payload)
                .expect("apply registration");

            let call = HostCallPayload {
                call_id: "call-http-deny-empty-scope".to_string(),
                capability: "http".to_string(),
                method: "http".to_string(),
                params: json!({ "url": "https://example.com", "method": "GET" }),
                timeout_ms: Some(500),
                cancel_token: None,
                context: None,
            };

            let err_json = {
                let json = serde_json::to_string(&call).expect("serialize hostcall");
                run_async(async { host::Host::call(&mut state, "http".to_string(), json).await })
                    .expect_err("http should be denied when hosts scope is omitted")
            };
            let err: HostCallError = serde_json::from_str(&err_json).expect("parse error");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("allowlist"),
                "expected allowlist guidance, got: {}",
                err.message
            );
        }
    }
}

#[cfg(feature = "wasm-host")]
pub struct WasmExtensionHost {
    policy: ExtensionPolicy,
    cwd: PathBuf,
    engine: wasmtime::Engine,
}

#[cfg(feature = "wasm-host")]
impl WasmExtensionHost {
    pub fn new(cwd: &Path, policy: ExtensionPolicy) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.async_support(true);

        let engine = wasmtime::Engine::new(&config)
            .map_err(|err| Error::extension(format!("Failed to create WASM engine: {err}")))?;

        Ok(Self {
            policy,
            cwd: cwd.to_path_buf(),
            engine,
        })
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

    pub async fn instantiate(&self, extension: &WasmExtension) -> Result<wasm_host::Instance> {
        wasm_host::Instance::instantiate(
            &self.engine,
            &extension.path,
            wasm_host::HostState::new(self.policy.clone(), self.cwd.clone())?,
        )
        .await
    }

    async fn instantiate_with(
        &self,
        extension: &WasmExtension,
        tools: Arc<ToolRegistry>,
        manager: Option<ExtensionManagerHandle>,
    ) -> Result<wasm_host::Instance> {
        wasm_host::Instance::instantiate(
            &self.engine,
            &extension.path,
            wasm_host::HostState::new_with_tools(
                self.policy.clone(),
                self.cwd.clone(),
                tools,
                manager,
            )?,
        )
        .await
    }
}

// ============================================================================
// Extension Event System
// ============================================================================

/// Default cancellation budget for extension event handlers (ms).
pub const EXTENSION_EVENT_TIMEOUT_MS: u64 = 5_000;

/// Default cancellation budget for extension tool execution (ms).
pub const EXTENSION_TOOL_BUDGET_MS: u64 = 30_000;

/// Default cancellation budget for extension command execution (ms).
pub const EXTENSION_COMMAND_BUDGET_MS: u64 = 30_000;

/// Default cancellation budget for extension shortcut execution (ms).
pub const EXTENSION_SHORTCUT_BUDGET_MS: u64 = 30_000;

/// Default cancellation budget for UI dialog operations (ms).
pub const EXTENSION_UI_BUDGET_MS: u64 = 1_000;

/// Default cancellation budget for provider stream operations (ms).
pub const EXTENSION_PROVIDER_BUDGET_MS: u64 = 120_000;

/// Default cancellation budget for extension queries (get tools, pump, flags) (ms).
pub const EXTENSION_QUERY_BUDGET_MS: u64 = 10_000;

/// Default cancellation budget for extension loading (ms).
pub const EXTENSION_LOAD_BUDGET_MS: u64 = 60_000;

/// Create a [`Cx`] with a deadline budget derived from `timeout_ms`.
///
/// The returned context will cancel any async operation that exceeds the
/// deadline, integrating with asupersync's structured concurrency protocol.
fn cx_with_deadline(timeout_ms: u64) -> Cx {
    let budget = Budget {
        deadline: Some(wall_now() + Duration::from_millis(timeout_ms)),
        ..Budget::INFINITE
    };
    Cx::for_request_with_budget(budget)
}

/// Event names for the extension lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionEventName {
    /// Agent startup (once per session).
    Startup,
    /// Input from the user.
    Input,
    /// Before the agent starts processing.
    BeforeAgentStart,
    /// Agent started processing.
    AgentStart,
    /// Agent ended processing.
    AgentEnd,
    /// Turn lifecycle start.
    TurnStart,
    /// Turn lifecycle end.
    TurnEnd,
    /// Message lifecycle start.
    MessageStart,
    /// Message lifecycle update (assistant streaming).
    MessageUpdate,
    /// Message lifecycle end.
    MessageEnd,
    /// Tool execution start.
    ToolExecutionStart,
    /// Tool execution update.
    ToolExecutionUpdate,
    /// Tool execution end.
    ToolExecutionEnd,
    /// Tool call (pre-exec; can block).
    ToolCall,
    /// Tool result (post-exec; can modify).
    ToolResult,
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
            Self::Startup => "startup",
            Self::Input => "input",
            Self::BeforeAgentStart => "before_agent_start",
            Self::AgentStart => "agent_start",
            Self::AgentEnd => "agent_end",
            Self::TurnStart => "turn_start",
            Self::TurnEnd => "turn_end",
            Self::MessageStart => "message_start",
            Self::MessageUpdate => "message_update",
            Self::MessageEnd => "message_end",
            Self::ToolExecutionStart => "tool_execution_start",
            Self::ToolExecutionUpdate => "tool_execution_update",
            Self::ToolExecutionEnd => "tool_execution_end",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
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

// ============================================================================
// Extension Manifest + Load Specs
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionRuntime {
    Js,
    Wasm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionManifest {
    pub schema: String,
    pub extension_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub api_version: String,
    pub runtime: ExtensionRuntime,
    pub entrypoint: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_manifest: Option<CapabilityManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ExtensionManifest {
    fn normalize(
        mut self,
        package_name: Option<String>,
        package_version: Option<String>,
    ) -> Result<Self> {
        if self.name.trim().is_empty() {
            if let Some(name) = package_name {
                self.name = name;
            }
        }

        if self.version.trim().is_empty() {
            if let Some(version) = package_version {
                self.version = version;
            }
        }

        if self.api_version.trim().is_empty() {
            self.api_version = PROTOCOL_VERSION.to_string();
        }

        validate_extension_manifest(&self)?;
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct ExtensionManifestSource {
    pub manifest: ExtensionManifest,
    pub manifest_json: String,
    pub root: PathBuf,
    pub manifest_path: PathBuf,
}

impl ExtensionManifestSource {
    pub fn entry_path(&self) -> PathBuf {
        self.root.join(self.manifest.entrypoint.trim())
    }
}

#[derive(Debug, Clone)]
pub enum ExtensionLoadSpec {
    Js(JsExtensionLoadSpec),
    #[cfg(feature = "wasm-host")]
    Wasm(WasmExtensionLoadSpec),
}

#[cfg(feature = "wasm-host")]
#[derive(Debug, Clone)]
pub struct WasmExtensionLoadSpec {
    pub manifest: ExtensionManifest,
    pub manifest_json: String,
    pub root: PathBuf,
    pub entry_path: PathBuf,
}

fn extension_id_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,63}$").expect("regex"))
}

fn validate_extension_manifest(manifest: &ExtensionManifest) -> Result<()> {
    if manifest.schema != "pi.ext.manifest.v1" {
        return Err(Error::validation(format!(
            "Unsupported extension manifest schema: {}",
            manifest.schema
        )));
    }

    let extension_id = manifest.extension_id.trim();
    if extension_id.is_empty() {
        return Err(Error::validation(
            "Extension manifest extension_id is empty",
        ));
    }
    if !extension_id_regex().is_match(extension_id) {
        return Err(Error::validation(format!(
            "Invalid extension_id '{extension_id}'"
        )));
    }

    if manifest.name.trim().is_empty() {
        return Err(Error::validation("Extension manifest name is empty"));
    }
    if manifest.version.trim().is_empty() {
        return Err(Error::validation("Extension manifest version is empty"));
    }
    if manifest.api_version.trim().is_empty() {
        return Err(Error::validation("Extension manifest api_version is empty"));
    }
    if manifest.entrypoint.trim().is_empty() {
        return Err(Error::validation("Extension manifest entrypoint is empty"));
    }
    let entry_path = Path::new(manifest.entrypoint.trim());
    if entry_path.is_absolute()
        || entry_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(Error::validation(format!(
            "Extension manifest entrypoint must be a relative path inside the extension root: {}",
            manifest.entrypoint
        )));
    }

    if let Some(capability_manifest) = &manifest.capability_manifest {
        validate_capability_manifest(capability_manifest)?;
    }

    Ok(())
}

fn read_package_json_meta(root: &Path) -> Option<(Option<String>, Option<String>, Option<Value>)> {
    let package_json = root.join("package.json");
    if !package_json.exists() {
        return None;
    }
    let raw = fs::read_to_string(package_json).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    let name = json.get("name").and_then(Value::as_str).map(str::to_string);
    let version = json
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    let pi = json.get("pi").cloned();
    Some((name, version, pi))
}

fn parse_extension_manifest_value(
    value: Value,
    package_name: Option<String>,
    package_version: Option<String>,
) -> Result<ExtensionManifest> {
    let manifest: ExtensionManifest = serde_json::from_value(value)
        .map_err(|err| Error::validation(format!("Invalid extension manifest: {err}")))?;
    manifest.normalize(package_name, package_version)
}

pub fn load_extension_manifest(root: &Path) -> Result<Option<ExtensionManifestSource>> {
    let (package_name, package_version, package_pi) =
        read_package_json_meta(root).unwrap_or((None, None, None));

    let extension_json = root.join("extension.json");
    if extension_json.exists() {
        let raw = fs::read_to_string(&extension_json).map_err(|err| {
            Error::validation(format!(
                "Failed to read extension manifest {}: {err}",
                extension_json.display()
            ))
        })?;
        let value: Value = serde_json::from_str(&raw).map_err(|err| {
            Error::validation(format!(
                "Failed to parse extension manifest {}: {err}",
                extension_json.display()
            ))
        })?;
        let manifest = parse_extension_manifest_value(value, package_name, package_version)?;
        let manifest_json = serde_json::to_string(&manifest)
            .map_err(|err| Error::validation(format!("Serialize manifest: {err}")))?;
        return Ok(Some(ExtensionManifestSource {
            manifest,
            manifest_json,
            root: root.to_path_buf(),
            manifest_path: extension_json,
        }));
    }

    if let Some(pi) = package_pi {
        if pi.get("schema").and_then(Value::as_str) == Some("pi.ext.manifest.v1") {
            let manifest = parse_extension_manifest_value(pi, package_name, package_version)?;
            let manifest_json = serde_json::to_string(&manifest)
                .map_err(|err| Error::validation(format!("Serialize manifest: {err}")))?;
            let manifest_path = root.join("package.json");
            return Ok(Some(ExtensionManifestSource {
                manifest,
                manifest_json,
                root: root.to_path_buf(),
                manifest_path,
            }));
        }
    }

    Ok(None)
}

fn resolve_extension_index(root: &Path) -> Option<PathBuf> {
    let index_ts = root.join("index.ts");
    if index_ts.exists() {
        return Some(index_ts);
    }
    let index_js = root.join("index.js");
    if index_js.exists() {
        return Some(index_js);
    }
    None
}

impl ExtensionManifestSource {
    fn to_load_spec(&self) -> Result<ExtensionLoadSpec> {
        let entry_path = self.entry_path();
        if !entry_path.exists() {
            return Err(Error::validation(format!(
                "Extension entrypoint not found: {}",
                entry_path.display()
            )));
        }

        match self.manifest.runtime {
            ExtensionRuntime::Js => Ok(ExtensionLoadSpec::Js(JsExtensionLoadSpec::from_manifest(
                &self.manifest,
                &self.root,
            )?)),
            ExtensionRuntime::Wasm => {
                #[cfg(feature = "wasm-host")]
                {
                    Ok(ExtensionLoadSpec::Wasm(WasmExtensionLoadSpec {
                        manifest: self.manifest.clone(),
                        manifest_json: self.manifest_json.clone(),
                        root: self.root.clone(),
                        entry_path,
                    }))
                }
                #[cfg(not(feature = "wasm-host"))]
                {
                    Err(Error::validation(
                        "WASM extensions require the `wasm-host` feature".to_string(),
                    ))
                }
            }
        }
    }
}

pub fn resolve_extension_load_spec(entry: &Path) -> Result<ExtensionLoadSpec> {
    if entry.is_dir() {
        if let Some(source) = load_extension_manifest(entry)? {
            return source.to_load_spec();
        }
        if let Some(index) = resolve_extension_index(entry) {
            return Ok(ExtensionLoadSpec::Js(JsExtensionLoadSpec::from_entry_path(
                index,
            )?));
        }
        return Err(Error::validation(format!(
            "Extension directory has no manifest or entrypoint: {}",
            entry.display()
        )));
    }

    if entry.is_file() {
        if entry
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s == "extension.json")
        {
            let root = entry.parent().unwrap_or(entry);
            if let Some(source) = load_extension_manifest(root)? {
                return source.to_load_spec();
            }
        }

        if let Some(ext) = entry.extension().and_then(|s| s.to_str()) {
            match ext {
                "wasm" => {
                    #[cfg(feature = "wasm-host")]
                    {
                        if let Some(source) =
                            load_extension_manifest(entry.parent().unwrap_or(entry))?
                        {
                            let spec = source.to_load_spec()?;
                            if let ExtensionLoadSpec::Wasm(wasm_spec) = spec {
                                if wasm_spec.entry_path != entry {
                                    return Err(Error::validation(format!(
                                        "WASM entrypoint mismatch: manifest entrypoint is {}, but got {}",
                                        wasm_spec.entry_path.display(),
                                        entry.display()
                                    )));
                                }
                                return Ok(ExtensionLoadSpec::Wasm(wasm_spec));
                            }
                            return Err(Error::validation(format!(
                                "Extension manifest runtime is not wasm for {}",
                                entry.display()
                            )));
                        }
                        return Err(Error::validation(format!(
                            "WASM extension requires extension.json or package.json#pi manifest: {}",
                            entry.display()
                        )));
                    }
                    #[cfg(not(feature = "wasm-host"))]
                    {
                        return Err(Error::validation(
                            "WASM extensions require the `wasm-host` feature".to_string(),
                        ));
                    }
                }
                "js" | "ts" | "mjs" | "cjs" => {
                    return Ok(ExtensionLoadSpec::Js(JsExtensionLoadSpec::from_entry_path(
                        entry,
                    )?));
                }
                _ => {}
            }
        }
    }

    Err(Error::validation(format!(
        "Unsupported extension entry: {}",
        entry.display()
    )))
}

// ============================================================================
// JS Extension Runtime (QuickJS via PiJsRuntime)
// ============================================================================

#[derive(Debug, Clone)]
pub struct JsExtensionLoadSpec {
    pub extension_id: String,
    pub entry_path: PathBuf,
    pub name: String,
    pub version: String,
    pub api_version: String,
}

impl JsExtensionLoadSpec {
    pub fn from_entry_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::validation(format!(
                "Extension entry does not exist: {}",
                path.display()
            )));
        }

        let entry_path = safe_canonicalize(path);

        let file_stem = entry_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if file_stem.is_empty() {
            return Err(Error::validation(format!(
                "Extension entry has no filename: {}",
                entry_path.display()
            )));
        }

        let extension_id = if file_stem == "index" {
            entry_path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .trim()
                .to_string()
        } else {
            file_stem
        };

        if extension_id.is_empty() {
            return Err(Error::validation(format!(
                "Could not derive extension id from entry path: {}",
                entry_path.display()
            )));
        }

        let mut name = extension_id.clone();
        let mut version = "0.0.0".to_string();

        if let Some(parent) = entry_path.parent() {
            let manifest_path = parent.join("package.json");
            if manifest_path.exists() {
                if let Ok(raw) = fs::read_to_string(&manifest_path) {
                    if let Ok(json) = serde_json::from_str::<Value>(&raw) {
                        if let Some(manifest_name) = json.get("name").and_then(Value::as_str) {
                            if !manifest_name.trim().is_empty() {
                                name = manifest_name.trim().to_string();
                            }
                        }
                        if let Some(manifest_version) = json.get("version").and_then(Value::as_str)
                        {
                            if !manifest_version.trim().is_empty() {
                                version = manifest_version.trim().to_string();
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            extension_id,
            entry_path,
            name,
            version,
            api_version: PROTOCOL_VERSION.to_string(),
        })
    }

    pub fn from_manifest(manifest: &ExtensionManifest, root: &Path) -> Result<Self> {
        let entry_path = root.join(manifest.entrypoint.trim());
        if !entry_path.exists() {
            return Err(Error::validation(format!(
                "Extension entry does not exist: {}",
                entry_path.display()
            )));
        }

        let entry_path = safe_canonicalize(&entry_path);

        if manifest.extension_id.trim().is_empty() {
            return Err(Error::validation(
                "Extension manifest extension_id is empty".to_string(),
            ));
        }

        Ok(Self {
            extension_id: manifest.extension_id.clone(),
            entry_path,
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            api_version: manifest.api_version.clone(),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct JsExtensionSnapshot {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    api_version: String,
    #[serde(default)]
    tools: Vec<Value>,
    #[serde(default)]
    slash_commands: Vec<Value>,
    #[serde(default)]
    shortcuts: Vec<Value>,
    #[serde(default)]
    providers: Vec<Value>,
    #[serde(default)]
    flags: Vec<Value>,
    #[serde(default)]
    event_hooks: Vec<String>,
    #[serde(default)]
    active_tools: Option<Vec<String>>,
}

#[cfg(feature = "wasm-host")]
#[derive(Clone)]
pub struct WasmExtensionHandle {
    instance: Arc<AsyncMutex<wasm_host::Instance>>,
    registration: RegisterPayload,
    tool_defs: Vec<ExtensionToolDef>,
}

#[cfg(feature = "wasm-host")]
impl WasmExtensionHandle {
    fn new(instance: wasm_host::Instance, registration: RegisterPayload) -> Self {
        let tool_defs = parse_extension_tool_defs(&registration.tools);
        Self {
            instance: Arc::new(AsyncMutex::new(instance)),
            registration,
            tool_defs,
        }
    }

    pub fn tool_defs(&self) -> &[ExtensionToolDef] {
        &self.tool_defs
    }

    pub fn event_hooks(&self) -> &[String] {
        &self.registration.event_hooks
    }

    pub const fn registration(&self) -> &RegisterPayload {
        &self.registration
    }

    pub async fn handle_tool(&self, name: &str, input: &Value) -> Result<String> {
        let input_json = serde_json::to_string(input)
            .map_err(|err| Error::extension(format!("Serialize tool input: {err}")))?;
        let cx = Cx::for_request();
        let mut instance = self
            .instance
            .lock(&cx)
            .await
            .map_err(|err| Error::extension(format!("Lock wasm instance: {err}")))?;
        instance.handle_tool(name, &input_json).await
    }

    pub async fn handle_slash(
        &self,
        command: &str,
        args: &[String],
        input: &Value,
    ) -> Result<String> {
        let input_json = serde_json::to_string(input)
            .map_err(|err| Error::extension(format!("Serialize slash input: {err}")))?;
        let cx = Cx::for_request();
        let mut instance = self
            .instance
            .lock(&cx)
            .await
            .map_err(|err| Error::extension(format!("Lock wasm instance: {err}")))?;
        instance.handle_slash(command, args, &input_json).await
    }

    pub async fn handle_event_value(
        &self,
        event: &Value,
        timeout_ms: u64,
    ) -> Result<Option<Value>> {
        let event_json = serde_json::to_string(event)
            .map_err(|err| Error::extension(format!("Serialize event: {err}")))?;
        let cx = Cx::for_request();
        let fut = async {
            let mut instance = self
                .instance
                .lock(&cx)
                .await
                .map_err(|err| Error::extension(format!("Lock wasm instance: {err}")))?;
            instance.handle_event(&event_json).await
        };

        let response_json = if timeout_ms > 0 {
            match timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut)).await {
                Ok(value) => value?,
                Err(_) => {
                    return Err(Error::extension(format!(
                        "WASM event timed out after {timeout_ms}ms"
                    )));
                }
            }
        } else {
            fut.await?
        };

        if response_json.trim().is_empty() {
            return Ok(None);
        }

        let value: Value = serde_json::from_str(&response_json)
            .map_err(|err| Error::extension(format!("Parse event response: {err}")))?;
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }
}

fn parse_extension_tool_defs(tools: &[Value]) -> Vec<ExtensionToolDef> {
    let mut defs = Vec::new();
    for value in tools {
        match serde_json::from_value::<ExtensionToolDef>(value.clone()) {
            Ok(def) => defs.push(def),
            Err(err) => {
                tracing::warn!(error = %err, "Invalid extension tool definition; ignoring");
            }
        }
    }
    defs
}

/// Trait allowing tests to intercept hostcalls before they reach real dispatch.
/// Return `Some(outcome)` to short-circuit, or `None` to fall through to real dispatch.
pub trait HostcallInterceptor: Send + Sync {
    fn intercept(&self, request: &HostcallRequest) -> Option<HostcallOutcome>;
}

#[derive(Clone)]
struct JsRuntimeHost {
    tools: Arc<ToolRegistry>,
    /// Weak reference to avoid Arc cycle with the runtime thread.
    /// The thread holds a `JsRuntimeHost` which would otherwise prevent
    /// `ExtensionManager` from being dropped (and the channel from closing).
    manager_ref: Weak<Mutex<ExtensionManagerInner>>,
    http: Arc<HttpConnector>,
    policy: ExtensionPolicy,
    interceptor: Option<Arc<dyn HostcallInterceptor>>,
}

impl JsRuntimeHost {
    /// Upgrade the weak manager reference.  Returns `None` if the
    /// `ExtensionManager` has already been dropped (shutdown in progress).
    fn manager(&self) -> Option<ExtensionManager> {
        self.manager_ref
            .upgrade()
            .map(|inner| ExtensionManager { inner })
    }
}

#[derive(Debug)]
enum JsRuntimeCommand {
    LoadExtensions {
        specs: Vec<JsExtensionLoadSpec>,
        reply: oneshot::Sender<Result<Vec<JsExtensionSnapshot>>>,
    },
    GetRegisteredTools {
        reply: oneshot::Sender<Result<Vec<ExtensionToolDef>>>,
    },
    PumpOnce {
        reply: oneshot::Sender<Result<bool>>,
    },
    DispatchEvent {
        event_name: String,
        event_payload: Value,
        ctx_payload: Value,
        timeout_ms: u64,
        reply: oneshot::Sender<Result<Value>>,
    },
    ExecuteTool {
        tool_name: String,
        tool_call_id: String,
        input: Value,
        ctx_payload: Value,
        timeout_ms: u64,
        reply: oneshot::Sender<Result<Value>>,
    },
    ExecuteCommand {
        command_name: String,
        args: String,
        ctx_payload: Value,
        timeout_ms: u64,
        reply: oneshot::Sender<Result<Value>>,
    },
    ExecuteShortcut {
        key_id: String,
        ctx_payload: Value,
        timeout_ms: u64,
        reply: oneshot::Sender<Result<Value>>,
    },
    ProviderStreamSimpleStart {
        provider_id: String,
        model: Value,
        context: Value,
        options: Value,
        timeout_ms: u64,
        reply: oneshot::Sender<Result<String>>,
    },
    ProviderStreamSimpleNext {
        stream_id: String,
        timeout_ms: u64,
        reply: oneshot::Sender<Result<Option<Value>>>,
    },
    ProviderStreamSimpleCancel {
        stream_id: String,
        timeout_ms: u64,
        reply: Option<oneshot::Sender<Result<()>>>,
    },
    SetFlagValue {
        extension_id: String,
        flag_name: String,
        value: Value,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Drain accumulated auto-repair events from the runtime.
    DrainRepairEvents {
        reply: oneshot::Sender<Vec<ExtensionRepairEvent>>,
    },
    /// Request the runtime thread to shut down gracefully.
    Shutdown,
}

/// Handle to the JS extension runtime thread.
///
/// Cloning shares the same underlying runtime. Call [`shutdown`](Self::shutdown)
/// to request a graceful exit; the runtime thread will finish the current
/// command, break out of the event loop, and signal completion via
/// `exit_signal`.
pub struct JsExtensionRuntimeHandle {
    sender: mpsc::Sender<JsRuntimeCommand>,
    /// Receives `()` when the runtime thread exits its event loop.
    /// Wrapped in `Arc<Mutex<Option<_>>>` so only the first `shutdown()`
    /// caller actually awaits the signal.
    exit_signal: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

impl Clone for JsExtensionRuntimeHandle {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            exit_signal: Arc::clone(&self.exit_signal),
        }
    }
}

impl JsExtensionRuntimeHandle {
    #[allow(clippy::too_many_lines)]
    pub async fn start(
        config: PiJsRuntimeConfig,
        tools: Arc<ToolRegistry>,
        manager: ExtensionManager,
    ) -> Result<Self> {
        Self::start_inner(config, tools, manager, None, None).await
    }

    /// Like [`start`](Self::start) but uses a specific [`ExtensionPolicy`].
    pub async fn start_with_policy(
        config: PiJsRuntimeConfig,
        tools: Arc<ToolRegistry>,
        manager: ExtensionManager,
        policy: ExtensionPolicy,
    ) -> Result<Self> {
        Self::start_inner(config, tools, manager, None, Some(policy)).await
    }

    /// Like [`start`](Self::start) but installs a [`HostcallInterceptor`] that
    /// can short-circuit hostcalls before they reach real dispatch handlers.
    /// Used by conformance tests to provide deterministic exec/http/ui stubs.
    pub async fn start_with_interceptor(
        config: PiJsRuntimeConfig,
        tools: Arc<ToolRegistry>,
        manager: ExtensionManager,
        interceptor: Arc<dyn HostcallInterceptor>,
    ) -> Result<Self> {
        Self::start_inner(config, tools, manager, Some(interceptor), None).await
    }

    #[allow(clippy::too_many_lines)]
    async fn start_inner(
        config: PiJsRuntimeConfig,
        tools: Arc<ToolRegistry>,
        manager: ExtensionManager,
        interceptor: Option<Arc<dyn HostcallInterceptor>>,
        policy: Option<ExtensionPolicy>,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel(32);
        let (init_tx, init_rx) = oneshot::channel();
        let (exit_tx, exit_rx) = oneshot::channel();
        let host = JsRuntimeHost {
            tools,
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(HttpConnector::with_defaults()),
            policy: policy.unwrap_or_default(),
            interceptor,
        };

        thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("extension runtime build");
            runtime.block_on(async move {
                let cx = Cx::for_request();
                let init =
                    PiJsRuntime::with_clock_and_config(crate::scheduler::WallClock, config).await;
                let js_runtime = match init {
                    Ok(runtime) => {
                        let _ = init_tx.send(&cx, Ok(()));
                        runtime
                    }
                    Err(err) => {
                        let _ = init_tx.send(&cx, Err(err));
                        return;
                    }
                };

                while let Ok(cmd) = rx.recv(&cx).await {
                    match cmd {
                        JsRuntimeCommand::Shutdown => break,
                        JsRuntimeCommand::LoadExtensions { specs, reply } => {
                            let result = load_all_extensions(&js_runtime, &host, &specs).await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::GetRegisteredTools { reply } => {
                            let result = js_runtime.get_registered_tools().await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::PumpOnce { reply } => {
                            let result = pump_js_runtime_once(&js_runtime, &host).await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::DispatchEvent {
                            event_name,
                            event_payload,
                            ctx_payload,
                            timeout_ms,
                            reply,
                        } => {
                            let result = dispatch_extension_event(
                                &js_runtime,
                                &host,
                                &event_name,
                                event_payload,
                                ctx_payload,
                                timeout_ms,
                            )
                            .await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::ExecuteTool {
                            tool_name,
                            tool_call_id,
                            input,
                            ctx_payload,
                            timeout_ms,
                            reply,
                        } => {
                            let result = execute_extension_tool(
                                &js_runtime,
                                &host,
                                &tool_name,
                                &tool_call_id,
                                input,
                                ctx_payload,
                                timeout_ms,
                            )
                            .await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::ExecuteCommand {
                            command_name,
                            args,
                            ctx_payload,
                            timeout_ms,
                            reply,
                        } => {
                            let result = execute_extension_command(
                                &js_runtime,
                                &host,
                                &command_name,
                                &args,
                                ctx_payload,
                                timeout_ms,
                            )
                            .await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::ExecuteShortcut {
                            key_id,
                            ctx_payload,
                            timeout_ms,
                            reply,
                        } => {
                            let result = execute_extension_shortcut(
                                &js_runtime,
                                &host,
                                &key_id,
                                ctx_payload,
                                timeout_ms,
                            )
                            .await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::ProviderStreamSimpleStart {
                            provider_id,
                            model,
                            context,
                            options,
                            timeout_ms,
                            reply,
                        } => {
                            let result = start_extension_provider_stream_simple(
                                &js_runtime,
                                &host,
                                &provider_id,
                                model,
                                context,
                                options,
                                timeout_ms,
                            )
                            .await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::ProviderStreamSimpleNext {
                            stream_id,
                            timeout_ms,
                            reply,
                        } => {
                            let result = next_extension_provider_stream_simple(
                                &js_runtime,
                                &host,
                                &stream_id,
                                timeout_ms,
                            )
                            .await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::ProviderStreamSimpleCancel {
                            stream_id,
                            timeout_ms,
                            reply,
                        } => {
                            let result = cancel_extension_provider_stream_simple(
                                &js_runtime,
                                &host,
                                &stream_id,
                                timeout_ms,
                            )
                            .await;
                            if let Some(reply) = reply {
                                let _ = reply.send(&cx, result);
                            }
                        }
                        JsRuntimeCommand::SetFlagValue {
                            extension_id,
                            flag_name,
                            value,
                            reply,
                        } => {
                            let result = js_runtime
                                .with_ctx(|ctx| {
                                    let global = ctx.globals();
                                    let set_fn: rquickjs::Function<'_> =
                                        global.get("__pi_set_flag_value")?;
                                    let _: rquickjs::Value<'_> = set_fn.call((
                                        extension_id.as_str(),
                                        flag_name.as_str(),
                                        json_to_js(&ctx, &value)?,
                                    ))?;
                                    Ok(())
                                })
                                .await;
                            let _ = reply.send(&cx, result);
                        }
                        JsRuntimeCommand::DrainRepairEvents { reply } => {
                            let events = js_runtime.drain_repair_events();
                            let _ = reply.send(&cx, events);
                        }
                    }
                }
                // Signal that the runtime thread has exited its event loop.
                let _ = exit_tx.send(&cx, ());
                tracing::info!(
                    event = "extension_runtime.exit",
                    "JS extension runtime thread exiting"
                );
            });
        });

        let cx = Cx::for_request();
        init_rx
            .recv(&cx)
            .await
            .map_err(|_| Error::extension("JS extension runtime init cancelled"))??;

        Ok(Self {
            sender: tx,
            exit_signal: Arc::new(Mutex::new(Some(exit_rx))),
        })
    }

    /// Request the JS runtime thread to shut down gracefully.
    ///
    /// Sends a `Shutdown` command and waits up to `budget` for the thread
    /// to exit its event loop.  Returns `true` if the runtime exited
    /// within the budget.
    pub async fn shutdown(&self, budget: Duration) -> bool {
        let cx = Cx::for_request();
        let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);

        // Send shutdown command (ignore error if channel already closed).
        let _ = self.sender.send(&cx, JsRuntimeCommand::Shutdown).await;

        // Take the exit signal — only the first caller can await it.
        let exit_rx = {
            let Ok(mut guard) = self.exit_signal.lock() else {
                return false;
            };
            guard.take()
        };

        let Some(rx) = exit_rx else {
            // Already shut down or another caller is waiting.
            return true;
        };

        match timeout(wall_now(), budget, rx.recv(&cx)).await {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                // Sender dropped without explicit ack: runtime is gone, so cleanup is
                // complete, but log for postmortem visibility.
                tracing::warn!(
                    event = "extension_runtime.shutdown_exit_signal_dropped",
                    budget_ms,
                    error = %err,
                    "JS extension runtime exit signal channel closed before ack"
                );
                true
            }
            Err(_) => {
                tracing::warn!(
                    event = "extension_runtime.shutdown_timeout",
                    budget_ms,
                    "JS extension runtime did not exit within cleanup budget"
                );
                false
            }
        }
    }

    async fn load_extensions_snapshots(
        &self,
        specs: Vec<JsExtensionLoadSpec>,
    ) -> Result<Vec<JsExtensionSnapshot>> {
        let timeout_ms = EXTENSION_LOAD_BUDGET_MS;
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::LoadExtensions {
            specs,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime load timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn get_registered_tools(&self) -> Result<Vec<ExtensionToolDef>> {
        let timeout_ms = EXTENSION_QUERY_BUDGET_MS;
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::GetRegisteredTools { reply: reply_tx };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime tools query timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn pump_once(&self) -> Result<bool> {
        let timeout_ms = EXTENSION_QUERY_BUDGET_MS;
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::PumpOnce { reply: reply_tx };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime pump timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn dispatch_event(
        &self,
        event_name: String,
        event_payload: Value,
        ctx_payload: Value,
        timeout_ms: u64,
    ) -> Result<Value> {
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::DispatchEvent {
            event_name,
            event_payload,
            ctx_payload,
            timeout_ms,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime event timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn execute_tool(
        &self,
        tool_name: String,
        tool_call_id: String,
        input: Value,
        ctx_payload: Value,
        timeout_ms: u64,
    ) -> Result<Value> {
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::ExecuteTool {
            tool_name,
            tool_call_id,
            input,
            ctx_payload,
            timeout_ms,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime tool timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn execute_command(
        &self,
        command_name: String,
        args: String,
        ctx_payload: Value,
        timeout_ms: u64,
    ) -> Result<Value> {
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::ExecuteCommand {
            command_name,
            args,
            ctx_payload,
            timeout_ms,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime command timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn execute_shortcut(
        &self,
        key_id: String,
        ctx_payload: Value,
        timeout_ms: u64,
    ) -> Result<Value> {
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::ExecuteShortcut {
            key_id,
            ctx_payload,
            timeout_ms,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime shortcut timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn set_flag_value(
        &self,
        extension_id: String,
        flag_name: String,
        value: Value,
    ) -> Result<()> {
        let timeout_ms = EXTENSION_QUERY_BUDGET_MS;
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::SetFlagValue {
            extension_id,
            flag_name,
            value,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime flag update timed out after {timeout_ms}ms"
                )))
            })
    }

    /// Drain all accumulated auto-repair events from the JS runtime.
    pub async fn drain_repair_events(&self) -> Vec<ExtensionRepairEvent> {
        let cx = cx_with_deadline(EXTENSION_QUERY_BUDGET_MS);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::DrainRepairEvents { reply: reply_tx };
        let Ok(()) = self.sender.send(&cx, command).await else {
            return Vec::new();
        };
        reply_rx.recv(&cx).await.unwrap_or_default()
    }

    pub async fn provider_stream_simple_start(
        &self,
        provider_id: String,
        model: Value,
        context: Value,
        options: Value,
        timeout_ms: u64,
    ) -> Result<String> {
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::ProviderStreamSimpleStart {
            provider_id,
            model,
            context,
            options,
            timeout_ms,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime provider stream start timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn provider_stream_simple_next(
        &self,
        stream_id: String,
        timeout_ms: u64,
    ) -> Result<Option<Value>> {
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::ProviderStreamSimpleNext {
            stream_id,
            timeout_ms,
            reply: reply_tx,
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime provider stream next timed out after {timeout_ms}ms"
                )))
            })
    }

    pub async fn provider_stream_simple_cancel(
        &self,
        stream_id: String,
        timeout_ms: u64,
    ) -> Result<()> {
        let cx = cx_with_deadline(timeout_ms);
        let (reply_tx, reply_rx) = oneshot::channel();
        let command = JsRuntimeCommand::ProviderStreamSimpleCancel {
            stream_id,
            timeout_ms,
            reply: Some(reply_tx),
        };
        let fut = async move {
            self.sender
                .send(&cx, command)
                .await
                .map_err(|_| Error::extension("JS extension runtime channel closed"))?;
            reply_rx
                .recv(&cx)
                .await
                .map_err(|_| Error::extension("JS extension runtime task cancelled"))?
        };

        timeout(wall_now(), Duration::from_millis(timeout_ms), Box::pin(fut))
            .await
            .unwrap_or_else(|_| {
                Err(Error::extension(format!(
                    "JS extension runtime provider stream cancel timed out after {timeout_ms}ms"
                )))
            })
    }

    pub fn provider_stream_simple_cancel_best_effort(&self, stream_id: String) {
        let timeout_ms = 5000;
        if self
            .sender
            .try_send(JsRuntimeCommand::ProviderStreamSimpleCancel {
                stream_id: stream_id.clone(),
                timeout_ms,
                reply: None,
            })
            .is_ok()
        {
            return;
        }

        // Fall back to an async send if the command channel is full.
        let sender = self.sender.clone();
        let _ = std::thread::Builder::new()
            .name("pi-js-stream-cancel".to_owned())
            .spawn(move || {
                let Ok(runtime) = asupersync::runtime::RuntimeBuilder::current_thread().build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let cx = Cx::for_request();
                    let _ = sender
                        .send(
                            &cx,
                            JsRuntimeCommand::ProviderStreamSimpleCancel {
                                stream_id,
                                timeout_ms,
                                reply: None,
                            },
                        )
                        .await;
                });
            });
    }
}

#[allow(clippy::future_not_send)]
async fn load_all_extensions(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    specs: &[JsExtensionLoadSpec],
) -> Result<Vec<JsExtensionSnapshot>> {
    for spec in specs {
        load_one_extension(runtime, host, spec).await?;
    }
    snapshot_extensions(runtime).await
}

#[allow(clippy::future_not_send)]
async fn load_one_extension(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    spec: &JsExtensionLoadSpec,
) -> Result<()> {
    // Register the extension's root directory so `readFileSync` can access
    // bundled assets (HTML templates, markdown docs, etc.) within the
    // extension's own directory tree, and so the resolver can detect
    // monorepo escape patterns (Pattern 3).
    if let Some(ext_dir) = spec.entry_path.parent() {
        if let Ok(canonical) = std::fs::canonicalize(ext_dir).map(strip_unc_prefix) {
            runtime.add_extension_root_with_id(canonical, Some(spec.extension_id.as_str()));
        }
    }

    // QuickJS module resolver requires forward-slash paths.
    let entry_specifier = spec.entry_path.display().to_string().replace('\\', "/");
    let meta = json!({
        "name": spec.name,
        "version": spec.version,
        "apiVersion": spec.api_version,
    });
    let task_id = format!("task-load-{}", Uuid::new_v4());

    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let load_fn: rquickjs::Function<'_> = global.get("__pi_load_extension")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let meta_value = json_to_js(&ctx, &meta)?;
            let promise: rquickjs::Value<'_> =
                load_fn.call((spec.extension_id.clone(), entry_specifier, meta_value))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    let _ = await_js_task(runtime, host, &task_id, Duration::from_secs(10)).await?;
    Ok(())
}

#[allow(clippy::future_not_send)]
async fn snapshot_extensions(runtime: &PiJsRuntime) -> Result<Vec<JsExtensionSnapshot>> {
    let json = runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let snapshot_fn: rquickjs::Function<'_> = global.get("__pi_snapshot_extensions")?;
            let value: rquickjs::Value<'_> = snapshot_fn.call(())?;
            js_to_json(&value)
        })
        .await?;

    let snapshots: Vec<JsExtensionSnapshot> =
        serde_json::from_value(json).map_err(|err| Error::extension(err.to_string()))?;
    Ok(snapshots)
}

#[allow(clippy::future_not_send)]
async fn dispatch_extension_event(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    event_name: &str,
    event_payload: Value,
    ctx_payload: Value,
    timeout_ms: u64,
) -> Result<Value> {
    let task_id = format!("task-event-{}", Uuid::new_v4());
    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let dispatch_fn: rquickjs::Function<'_> =
                global.get("__pi_dispatch_extension_event")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let event_js = json_to_js(&ctx, &event_payload)?;
            let ctx_js = json_to_js(&ctx, &ctx_payload)?;
            let promise: rquickjs::Value<'_> =
                dispatch_fn.call((event_name.to_string(), event_js, ctx_js))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    await_js_task(runtime, host, &task_id, Duration::from_millis(timeout_ms)).await
}

#[allow(clippy::future_not_send)]
async fn execute_extension_tool(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    tool_name: &str,
    tool_call_id: &str,
    input: Value,
    ctx_payload: Value,
    timeout_ms: u64,
) -> Result<Value> {
    let started_at = Instant::now();
    tracing::info!(
        event = "ext.tool.start",
        tool_name = %tool_name,
        tool_call_id = %tool_call_id,
        timeout_ms,
        "Extension tool execution start"
    );
    let task_id = format!("task-tool-{}", Uuid::new_v4());
    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let exec_fn: rquickjs::Function<'_> = global.get("__pi_execute_tool")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let input_js = json_to_js(&ctx, &input)?;
            let ctx_js = json_to_js(&ctx, &ctx_payload)?;
            let promise: rquickjs::Value<'_> = exec_fn.call((
                tool_name.to_string(),
                tool_call_id.to_string(),
                input_js,
                ctx_js,
            ))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    let result = await_js_task(runtime, host, &task_id, Duration::from_millis(timeout_ms)).await;
    let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let is_err = result.is_err();
    tracing::info!(
        event = "ext.tool.end",
        tool_name = %tool_name,
        tool_call_id = %tool_call_id,
        duration_ms,
        is_error = is_err,
        "Extension tool execution end"
    );
    result
}

#[allow(clippy::future_not_send)]
async fn execute_extension_command(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    command_name: &str,
    args: &str,
    ctx_payload: Value,
    timeout_ms: u64,
) -> Result<Value> {
    let started_at = Instant::now();
    tracing::info!(
        event = "ext.command.start",
        command = %command_name,
        timeout_ms,
        "Extension command execution start"
    );
    let task_id = format!("task-cmd-{}", Uuid::new_v4());
    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let exec_fn: rquickjs::Function<'_> = global.get("__pi_execute_command")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let ctx_js = json_to_js(&ctx, &ctx_payload)?;
            let promise: rquickjs::Value<'_> =
                exec_fn.call((command_name.to_string(), args.to_string(), ctx_js))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    let result = await_js_task(runtime, host, &task_id, Duration::from_millis(timeout_ms)).await;
    let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let is_err = result.is_err();
    tracing::info!(
        event = "ext.command.end",
        command = %command_name,
        duration_ms,
        is_error = is_err,
        "Extension command execution end"
    );
    result
}

#[allow(clippy::future_not_send)]
async fn execute_extension_shortcut(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    key_id: &str,
    ctx_payload: Value,
    timeout_ms: u64,
) -> Result<Value> {
    let started_at = Instant::now();
    tracing::info!(
        event = "ext.shortcut.start",
        key_id = %key_id,
        timeout_ms,
        "Extension shortcut execution start"
    );
    let task_id = format!("task-shortcut-{}", Uuid::new_v4());
    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let exec_fn: rquickjs::Function<'_> = global.get("__pi_execute_shortcut")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let ctx_js = json_to_js(&ctx, &ctx_payload)?;
            let promise: rquickjs::Value<'_> = exec_fn.call((key_id.to_string(), ctx_js))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    let result = await_js_task(runtime, host, &task_id, Duration::from_millis(timeout_ms)).await;
    let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let is_err = result.is_err();
    tracing::info!(
        event = "ext.shortcut.end",
        key_id = %key_id,
        duration_ms,
        is_error = is_err,
        "Extension shortcut execution end"
    );
    result
}

#[derive(Debug, Deserialize)]
struct JsProviderStreamNext {
    done: bool,
    #[serde(default)]
    value: Option<Value>,
}

#[allow(clippy::future_not_send)]
async fn start_extension_provider_stream_simple(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    provider_id: &str,
    model: Value,
    context: Value,
    options: Value,
    timeout_ms: u64,
) -> Result<String> {
    let task_id = format!("task-provider-stream-start-{}", Uuid::new_v4());
    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let start_fn: rquickjs::Function<'_> =
                global.get("__pi_provider_stream_simple_start")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let model_js = json_to_js(&ctx, &model)?;
            let context_js = json_to_js(&ctx, &context)?;
            let options_js = json_to_js(&ctx, &options)?;
            let promise: rquickjs::Value<'_> =
                start_fn.call((provider_id.to_string(), model_js, context_js, options_js))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    let value = await_js_task(runtime, host, &task_id, Duration::from_millis(timeout_ms)).await?;
    value
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| Error::extension("provider stream start: expected stream id".to_string()))
}

#[allow(clippy::future_not_send)]
async fn next_extension_provider_stream_simple(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    stream_id: &str,
    timeout_ms: u64,
) -> Result<Option<Value>> {
    let task_id = format!("task-provider-stream-next-{}", Uuid::new_v4());
    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let next_fn: rquickjs::Function<'_> = global.get("__pi_provider_stream_simple_next")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let promise: rquickjs::Value<'_> = next_fn.call((stream_id.to_string(),))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    let value = await_js_task(runtime, host, &task_id, Duration::from_millis(timeout_ms)).await?;
    let result: JsProviderStreamNext = serde_json::from_value(value)
        .map_err(|err| Error::extension(format!("provider stream next: {err}")))?;
    if result.done {
        return Ok(None);
    }
    let Some(value) = result.value else {
        return Err(Error::extension(
            "provider stream next: missing value".to_string(),
        ));
    };
    Ok(Some(value))
}

#[allow(clippy::future_not_send)]
async fn cancel_extension_provider_stream_simple(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    stream_id: &str,
    timeout_ms: u64,
) -> Result<()> {
    let task_id = format!("task-provider-stream-cancel-{}", Uuid::new_v4());
    runtime
        .with_ctx(|ctx| {
            let global = ctx.globals();
            let cancel_fn: rquickjs::Function<'_> =
                global.get("__pi_provider_stream_simple_cancel")?;
            let task_start: rquickjs::Function<'_> = global.get("__pi_task_start")?;
            let promise: rquickjs::Value<'_> = cancel_fn.call((stream_id.to_string(),))?;
            let _task: String = task_start.call((task_id.clone(), promise))?;
            Ok(())
        })
        .await?;

    let _ = await_js_task(runtime, host, &task_id, Duration::from_millis(timeout_ms)).await?;
    Ok(())
}

#[allow(clippy::future_not_send)]
async fn pump_js_runtime_once(runtime: &PiJsRuntime, host: &JsRuntimeHost) -> Result<bool> {
    fn drain_requests(runtime: &PiJsRuntime) -> std::collections::VecDeque<HostcallRequest> {
        runtime.drain_hostcall_requests()
    }

    async fn dispatch_requests(
        runtime: &PiJsRuntime,
        host: &JsRuntimeHost,
        mut pending: std::collections::VecDeque<HostcallRequest>,
    ) {
        while let Some(req) = pending.pop_front() {
            let call_id = req.call_id.clone();
            if !runtime.is_hostcall_pending(&call_id) {
                tracing::debug!(
                    event = "pijs.hostcall.skip_cancelled",
                    call_id = %call_id,
                    "Skipping hostcall dispatch because call is no longer pending"
                );
                continue;
            }
            let outcome = dispatch_hostcall_with_runtime(Some(runtime), host, req).await;
            runtime.complete_hostcall(call_id, outcome);
        }
    }

    // Process any hostcalls already queued before we advance the event loop.
    dispatch_requests(runtime, host, drain_requests(runtime)).await;

    // Advance the event loop (may schedule hostcalls while running a task's microtasks).
    let _ = runtime.tick().await?;
    let _ = runtime.drain_microtasks().await?;

    // Process hostcalls scheduled during the tick/microtask phase. Without this, fire-and-forget
    // calls (e.g. `pi.sendMessage()` without `await`) can be lost when a JS task resolves quickly.
    let after_tick = drain_requests(runtime);
    let has_after_tick = !after_tick.is_empty();
    dispatch_requests(runtime, host, after_tick).await;

    // If we dispatched any hostcalls, run another tick so their completions are delivered and
    // microtasks reach a fixpoint before the caller observes the outcome.
    if has_after_tick {
        let _ = runtime.tick().await?;
        let _ = runtime.drain_microtasks().await?;
    }

    Ok(runtime.has_pending())
}

#[derive(Debug, Deserialize)]
struct JsTaskState {
    status: String,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    error: Option<JsTaskError>,
}

#[derive(Debug, Deserialize)]
struct JsTaskError {
    #[serde(default)]
    code: Option<String>,
    message: String,
    #[serde(default)]
    stack: Option<String>,
}

fn js_hostcall_timeout_ms(request: &HostcallRequest) -> Option<u64> {
    fn timeout_value(value: &Value) -> Option<u64> {
        value
            .get("timeout")
            .and_then(Value::as_u64)
            .or_else(|| value.get("timeoutMs").and_then(Value::as_u64))
            .or_else(|| value.get("timeout_ms").and_then(Value::as_u64))
            .filter(|ms| *ms > 0)
    }

    match request.kind {
        HostcallKind::Exec { .. } => request
            .payload
            .get("options")
            .and_then(timeout_value)
            .or_else(|| timeout_value(&request.payload)),
        HostcallKind::Http => timeout_value(&request.payload),
        _ => None,
    }
}

async fn prompt_capability_once(
    manager: &ExtensionManager,
    extension_id: &str,
    capability: &str,
) -> bool {
    let title = format!("Allow extension capability: {capability}");
    let message = format!("Extension {extension_id} requests capability '{capability}'. Allow?");
    let payload = json!({
        "title": title,
        "message": message,
        "extension_id": extension_id,
        "capability": capability,
    });
    let request = ExtensionUiRequest::new("", "confirm", payload);

    match manager.request_ui(request).await {
        Ok(Some(response)) => {
            response
                .value
                .as_ref()
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && !response.cancelled
        }
        Ok(None) | Err(_) => false,
    }
}

// NOTE: Superseded by resolve_shared_policy_prompt in dispatch_host_call_shared (bd-1uy.1.3).
#[allow(dead_code, clippy::future_not_send)]
async fn resolve_js_hostcall_policy_decision(
    host: &JsRuntimeHost,
    extension_id: Option<&str>,
    required: &str,
) -> (PolicyDecision, String, String) {
    const UNKNOWN_EXTENSION_ID: &str = "<unknown>";
    let PolicyCheck {
        mut decision,
        capability,
        mut reason,
    } = host.policy.evaluate(required);

    if decision != PolicyDecision::Prompt {
        return (decision, reason, capability);
    }

    if let Some(extension_id) = extension_id {
        if let Some(allow) = host
            .manager()
            .and_then(|m| m.cached_policy_prompt_decision(extension_id, &capability))
        {
            decision = if allow {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny
            };
            reason = if allow {
                "prompt_cache_allow".to_string()
            } else {
                "prompt_cache_deny".to_string()
            };
            return (decision, reason, capability);
        }
    }

    let prompt_extension_id = extension_id.unwrap_or(UNKNOWN_EXTENSION_ID);
    let Some(manager) = host.manager() else {
        return (PolicyDecision::Deny, "shutdown".to_string(), capability);
    };
    let allow = prompt_capability_once(&manager, prompt_extension_id, &capability).await;
    if let Some(extension_id) = extension_id {
        manager.cache_policy_prompt_decision(extension_id, &capability, allow);
    }
    decision = if allow {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny
    };
    reason = if allow {
        "prompt_user_allow".to_string()
    } else {
        "prompt_user_deny".to_string()
    };
    (decision, reason, capability)
}

fn log_hostcall_start(
    runtime: &str,
    call_id: &str,
    extension_id: Option<&str>,
    required: &str,
    method: &str,
    params_hash: &str,
    call_timeout_ms: Option<u64>,
) {
    tracing::info!(
        event = "host_call.start",
        runtime = runtime,
        call_id = %call_id,
        extension_id = ?extension_id,
        capability = %required,
        method = %method,
        params_hash = %params_hash,
        timeout_ms = call_timeout_ms,
        "Hostcall start"
    );
}

fn log_policy_decision(
    runtime: &str,
    call_id: &str,
    extension_id: Option<&str>,
    capability: &str,
    decision: &PolicyDecision,
    reason: &str,
    params_hash: &str,
) {
    if *decision == PolicyDecision::Allow {
        tracing::info!(
            event = "policy.decision",
            runtime = runtime,
            call_id = %call_id,
            extension_id = ?extension_id,
            capability = %capability,
            decision = ?decision,
            reason = %reason,
            params_hash = %params_hash,
            "Hostcall allowed by policy"
        );
    } else {
        tracing::warn!(
            event = "policy.decision",
            runtime = runtime,
            call_id = %call_id,
            extension_id = ?extension_id,
            capability = %capability,
            decision = ?decision,
            reason = %reason,
            params_hash = %params_hash,
            "Hostcall denied by policy"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn log_hostcall_end(
    runtime: &str,
    call_id: &str,
    extension_id: Option<&str>,
    required: &str,
    method: &str,
    params_hash: &str,
    duration_ms: u64,
    outcome: &HostcallOutcome,
) {
    let (is_error, error_code) = match outcome {
        HostcallOutcome::Success(_) | HostcallOutcome::StreamChunk { .. } => (false, None),
        HostcallOutcome::Error { code, .. } => (true, Some(code.as_str())),
    };

    if is_error {
        tracing::warn!(
            event = "host_call.end",
            runtime = runtime,
            call_id = %call_id,
            extension_id = ?extension_id,
            capability = %required,
            method = %method,
            params_hash = %params_hash,
            duration_ms,
            error_code = error_code,
            "Hostcall end (error)"
        );
    } else {
        tracing::info!(
            event = "host_call.end",
            runtime = runtime,
            call_id = %call_id,
            extension_id = ?extension_id,
            capability = %required,
            method = %method,
            params_hash = %params_hash,
            duration_ms,
            "Hostcall end (success)"
        );
    }
}

// ============================================================================
// Shared Hostcall Dispatcher (bd-1uy.1.3)
// ============================================================================

/// Dispatch a hostcall through the unified ABI surface.
///
/// This is the **single source of truth** for hostcall execution, usable by
/// JS extensions, WASM components, and protocol-based runtimes alike.
///
/// 1. Resolves the required capability from the payload.
/// 2. Evaluates policy (allow / deny / prompt).
/// 3. Routes to the appropriate type-specific handler.
/// 4. Returns a taxonomy-compliant [`HostResultPayload`].
#[allow(clippy::future_not_send)]
#[allow(clippy::too_many_lines)]
pub async fn dispatch_host_call_shared(
    ctx: &HostCallContext<'_>,
    call: HostCallPayload,
) -> HostResultPayload {
    if let Err(err) = validate_host_call(&call) {
        return outcome_to_host_result(
            &call.call_id,
            &HostcallOutcome::Error {
                code: "invalid_request".to_string(),
                message: err.to_string(),
            },
        );
    }

    let call_id = call.call_id.clone();
    let method = call.method.clone();
    let capability = required_capability_for_host_call_static(&call).unwrap_or("internal");
    let params_hash = hostcall_params_hash(&method, &call.params);
    let args_shape_hash = hostcall_params_shape_hash(&method, &call.params);
    let resource_target_class = runtime_hostcall_resource_target_class(&method, &call.params);
    let policy_profile = runtime_hostcall_policy_profile(ctx.policy.mode);
    let started_at = Instant::now();

    log_hostcall_start(
        ctx.runtime_name,
        &call_id,
        ctx.extension_id,
        capability,
        &method,
        &params_hash,
        call.timeout_ms,
    );

    // Policy check (per-extension overrides applied via extension_id).
    let policy_check = ctx.policy.evaluate_for(capability, ctx.extension_id);
    let (decision, reason) = match policy_check.decision {
        PolicyDecision::Allow => (PolicyDecision::Allow, policy_check.reason),
        PolicyDecision::Deny => (PolicyDecision::Deny, policy_check.reason),
        PolicyDecision::Prompt => {
            // Check prompt cache, then prompt the user.
            resolve_shared_policy_prompt(ctx, capability).await
        }
    };

    log_policy_decision(
        ctx.runtime_name,
        &call_id,
        ctx.extension_id,
        capability,
        &decision,
        &reason,
        &params_hash,
    );

    // SEC-4.1: Per-extension quota check (after policy, before risk eval).
    if decision == PolicyDecision::Allow {
        if let Some(manager) = ctx.manager.as_ref() {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            let quota_result =
                manager.check_quota(ctx.extension_id, capability, now_ms, ctx.policy);
            if let QuotaCheckResult::Exceeded { reason: ref qr } = quota_result {
                tracing::warn!(
                    event = "ext.quota.exceeded",
                    extension_id = ?ctx.extension_id,
                    capability,
                    method = %method,
                    reason = %qr,
                );
                let outcome = HostcallOutcome::Error {
                    code: "quota_exceeded".to_string(),
                    message: format!("Quota exceeded for extension: {qr}"),
                };
                let duration_ms =
                    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
                log_hostcall_end(
                    ctx.runtime_name,
                    &call_id,
                    ctx.extension_id,
                    capability,
                    &method,
                    &params_hash,
                    duration_ms,
                    &outcome,
                );
                return outcome_to_host_result(&call_id, &outcome);
            }
        }
    }

    // SEC-4.1: track whether we need subprocess lifecycle recording.
    let is_exec = capability == "exec";

    let mut runtime_risk_decision = None;
    let outcome = if decision == PolicyDecision::Allow {
        if let Some(manager) = ctx.manager.as_ref() {
            runtime_risk_decision = manager.evaluate_runtime_risk(
                ctx.extension_id,
                &call_id,
                capability,
                &method,
                &params_hash,
                RuntimeRiskCallMetadata {
                    args_shape_hash: &args_shape_hash,
                    resource_target_class: &resource_target_class,
                    timeout_ms: call.timeout_ms,
                    policy_profile: &policy_profile,
                },
                &reason,
            );
        }

        let will_dispatch = match runtime_risk_decision
            .as_ref()
            .map_or(RuntimeRiskAction::Allow, |d| d.action)
        {
            RuntimeRiskAction::Allow => true,
            RuntimeRiskAction::Harden => !runtime_risk_is_dangerous(capability),
            RuntimeRiskAction::Deny | RuntimeRiskAction::Terminate => false,
        };

        // SEC-4.1: record subprocess spawn before exec dispatch.
        if is_exec && will_dispatch {
            if let (Some(manager), Some(ext_id)) = (ctx.manager.as_ref(), ctx.extension_id) {
                manager.record_subprocess_spawn(ext_id);
            }
        }

        let dispatched = match runtime_risk_decision
            .as_ref()
            .map_or(RuntimeRiskAction::Allow, |d| d.action)
        {
            RuntimeRiskAction::Allow => dispatch_shared_allowed(ctx, &call).await,
            RuntimeRiskAction::Harden => {
                if runtime_risk_is_dangerous(capability) {
                    HostcallOutcome::Error {
                        code: "denied".to_string(),
                        message: format!(
                            "Capability '{capability}' denied by runtime risk hardening"
                        ),
                    }
                } else {
                    dispatch_shared_allowed(ctx, &call).await
                }
            }
            RuntimeRiskAction::Deny => HostcallOutcome::Error {
                code: "denied".to_string(),
                message: format!("Capability '{capability}' denied by runtime risk controller"),
            },
            RuntimeRiskAction::Terminate => HostcallOutcome::Error {
                code: "denied".to_string(),
                message: "Extension quarantined by runtime risk controller".to_string(),
            },
        };

        // SEC-4.1: record subprocess exit after exec dispatch completes.
        if is_exec && will_dispatch {
            if let (Some(manager), Some(ext_id)) = (ctx.manager.as_ref(), ctx.extension_id) {
                manager.record_subprocess_exit(ext_id);
            }
        }

        dispatched
    } else {
        HostcallOutcome::Error {
            code: "denied".to_string(),
            message: format!("Capability '{capability}' denied by policy ({reason})"),
        }
    };

    let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    log_hostcall_end(
        ctx.runtime_name,
        &call_id,
        ctx.extension_id,
        capability,
        &method,
        &params_hash,
        duration_ms,
        &outcome,
    );

    if let (Some(manager), Some(risk_decision)) =
        (ctx.manager.as_ref(), runtime_risk_decision.as_ref())
    {
        let outcome_error_code = match &outcome {
            HostcallOutcome::Error { code, .. } => Some(code.as_str()),
            _ => None,
        };
        manager.record_runtime_risk_outcome(
            ctx.extension_id,
            &call_id,
            &reason,
            risk_decision,
            outcome_error_code,
            duration_ms,
        );
    }

    outcome_to_host_result(&call_id, &outcome)
}

// ============================================================================
// Protocol Adapter: ExtensionMessage host_call -> host_result (bd-1uy.1.2)
// ============================================================================

/// Handle an incoming [`ExtensionMessage`] of type `host_call` by dispatching
/// through the shared hostcall ABI and returning `host_result` messages.
///
/// This is a thin wrapper around [`dispatch_host_call_shared`] with no bespoke
/// policy, timeout, or logging logic.
///
/// Returns a `Vec<ExtensionMessage>` for streaming-readiness: the initial
/// implementation always returns exactly one message.
///
/// If the message is not a `host_call`, or fails validation, a single
/// `host_result` with `invalid_request` is returned (never panics).
#[allow(clippy::future_not_send)]
pub async fn handle_extension_message(
    ctx: &HostCallContext<'_>,
    msg: ExtensionMessage,
) -> Vec<ExtensionMessage> {
    // Validate the incoming message.
    if let Err(err) = msg.validate() {
        let call_id = match &msg.body {
            ExtensionBody::HostCall(payload) => payload.call_id.clone(),
            _ => String::new(),
        };
        return vec![make_host_result_message(
            &call_id,
            HostResultPayload {
                call_id: call_id.clone(),
                output: json!({}),
                is_error: true,
                error: Some(HostCallError {
                    code: HostCallErrorCode::InvalidRequest,
                    message: format!("Message validation failed: {err}"),
                    details: None,
                    retryable: None,
                }),
                chunk: None,
            },
        )];
    }

    // Extract the `HostCallPayload`.
    let payload = match msg.body {
        ExtensionBody::HostCall(payload) => payload,
        other => {
            let type_name = extension_body_type_name(&other);
            return vec![make_host_result_message(
                "",
                HostResultPayload {
                    call_id: String::new(),
                    output: json!({}),
                    is_error: true,
                    error: Some(HostCallError {
                        code: HostCallErrorCode::InvalidRequest,
                        message: format!(
                            "handle_extension_message expects host_call, got {type_name}"
                        ),
                        details: None,
                        retryable: None,
                    }),
                    chunk: None,
                },
            )];
        }
    };

    let call_id = payload.call_id.clone();

    // Dispatch through the shared ABI surface.
    let result = dispatch_host_call_shared(ctx, payload).await;

    vec![make_host_result_message(&call_id, result)]
}

/// Build an [`ExtensionMessage`] wrapping a [`HostResultPayload`].
fn make_host_result_message(call_id: &str, result: HostResultPayload) -> ExtensionMessage {
    ExtensionMessage {
        id: format!("host_result:{call_id}"),
        version: PROTOCOL_VERSION.to_string(),
        body: ExtensionBody::HostResult(result),
    }
}

/// Return the serde tag name for an [`ExtensionBody`] variant.
const fn extension_body_type_name(body: &ExtensionBody) -> &'static str {
    match body {
        ExtensionBody::Register(_) => "register",
        ExtensionBody::ToolCall(_) => "tool_call",
        ExtensionBody::ToolResult(_) => "tool_result",
        ExtensionBody::SlashCommand(_) => "slash_command",
        ExtensionBody::SlashResult(_) => "slash_result",
        ExtensionBody::EventHook(_) => "event_hook",
        ExtensionBody::HostCall(_) => "host_call",
        ExtensionBody::HostResult(_) => "host_result",
        ExtensionBody::Log(_) => "log",
        ExtensionBody::Error(_) => "error",
    }
}

/// Resolve a policy `Prompt` decision using the extension manager cache + UI.
#[allow(clippy::future_not_send)]
async fn resolve_shared_policy_prompt(
    ctx: &HostCallContext<'_>,
    capability: &str,
) -> (PolicyDecision, String) {
    // Check prompt cache.
    if let Some(ext_id) = ctx.extension_id {
        if let Some(allow) = ctx
            .manager
            .as_ref()
            .and_then(|m| m.cached_policy_prompt_decision(ext_id, capability))
        {
            let decision = if allow {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Deny
            };
            let reason = if allow {
                "prompt_cache_allow"
            } else {
                "prompt_cache_deny"
            };
            return (decision, reason.to_string());
        }
    }

    // Prompt the user via UI.
    let Some(ref manager) = ctx.manager else {
        return (PolicyDecision::Deny, "shutdown".to_string());
    };

    let prompt_ext_id = ctx.extension_id.unwrap_or("<unknown>");
    let allow = prompt_capability_once(manager, prompt_ext_id, capability).await;

    if let Some(ext_id) = ctx.extension_id {
        manager.cache_policy_prompt_decision(ext_id, capability, allow);
    }

    let decision = if allow {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny
    };
    let reason = if allow {
        "prompt_user_allow"
    } else {
        "prompt_user_deny"
    };
    (decision, reason.to_string())
}

/// Route an allowed hostcall to the appropriate handler based on method.
///
/// Converts the canonical [`HostCallPayload`] params back into the format
/// expected by the type-specific dispatch functions.
#[allow(clippy::future_not_send, clippy::too_many_lines)]
async fn dispatch_shared_allowed(
    ctx: &HostCallContext<'_>,
    call: &HostCallPayload,
) -> HostcallOutcome {
    match call.method.as_str() {
        "tool" => {
            let name = call
                .params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let input = call.params.get("input").cloned().unwrap_or(Value::Null);
            dispatch_hostcall_tool(ctx.tools, &call.call_id, name, input).await
        }
        "exec" => {
            let cmd = call
                .params
                .get("cmd")
                .and_then(Value::as_str)
                .unwrap_or_default();
            // Extract args for mediation classification.
            let args: Vec<String> = call
                .params
                .get("args")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default();

            // SEC-4.3: Exec mediation — classify and gate dangerous commands.
            let mediation = evaluate_exec_mediation(&ctx.policy.exec_mediation, cmd, &args);
            match &mediation {
                ExecMediationResult::Deny { class, reason } => {
                    tracing::warn!(
                        event = "exec.mediation.deny",
                        extension_id = ?ctx.extension_id,
                        command_class = ?class.map(DangerousCommandClass::label),
                        reason = %reason,
                        "Exec command denied by mediation policy"
                    );
                    return HostcallOutcome::Error {
                        code: "denied".to_string(),
                        message: format!("Exec denied by mediation policy: {reason}"),
                    };
                }
                ExecMediationResult::AllowWithAudit { class, reason } => {
                    tracing::info!(
                        event = "exec.mediation.audit",
                        extension_id = ?ctx.extension_id,
                        command_class = class.label(),
                        reason = %reason,
                        "Exec command allowed with audit"
                    );
                }
                ExecMediationResult::Allow => {}
            }

            // Reconstruct exec payload: everything except "cmd".
            let payload = if let Value::Object(map) = &call.params {
                let mut out = map.clone();
                out.remove("cmd");
                Value::Object(out)
            } else {
                Value::Null
            };
            dispatch_hostcall_exec(ctx.js_runtime, &call.call_id, cmd, payload).await
        }
        "http" => dispatch_hostcall_http(&call.call_id, ctx.http, call.params.clone()).await,
        "session" => {
            let op = call
                .params
                .get("op")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let Some(op) = op else {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "host_call session requires non-empty params.op".to_string(),
                };
            };
            let Some(ref manager) = ctx.manager else {
                return HostcallOutcome::Error {
                    code: "denied".to_string(),
                    message: "Extension manager is shutting down".to_string(),
                };
            };
            // Reconstruct session payload: everything except "op".
            let payload = if let Value::Object(map) = &call.params {
                let mut out = map.clone();
                out.remove("op");
                Value::Object(out)
            } else {
                Value::Null
            };
            dispatch_hostcall_session(&call.call_id, manager, op, payload).await
        }
        "ui" => {
            let op = call
                .params
                .get("op")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let Some(op) = op else {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "host_call ui requires non-empty params.op".to_string(),
                };
            };
            let Some(ref manager) = ctx.manager else {
                return HostcallOutcome::Error {
                    code: "denied".to_string(),
                    message: "Extension manager is shutting down".to_string(),
                };
            };
            // Reconstruct ui payload: everything except "op".
            let payload = if let Value::Object(map) = &call.params {
                let mut out = map.clone();
                out.remove("op");
                Value::Object(out)
            } else {
                Value::Null
            };
            dispatch_hostcall_ui(&call.call_id, manager, op, payload, ctx.extension_id).await
        }
        "events" => {
            let op = call
                .params
                .get("op")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let Some(op) = op else {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "host_call events requires non-empty params.op".to_string(),
                };
            };
            let Some(ref manager) = ctx.manager else {
                return HostcallOutcome::Error {
                    code: "denied".to_string(),
                    message: "Extension manager is shutting down".to_string(),
                };
            };
            // Reconstruct events payload: everything except "op".
            let payload = if let Value::Object(map) = &call.params {
                let mut out = map.clone();
                out.remove("op");
                Value::Object(out)
            } else {
                Value::Null
            };
            dispatch_hostcall_events(&call.call_id, manager, ctx.tools, op, payload).await
        }
        "log" => dispatch_hostcall_log(&call.call_id, ctx.extension_id, call.params.clone()).await,
        _ => HostcallOutcome::Error {
            code: "invalid_request".to_string(),
            message: format!("Unsupported hostcall method: {}", call.method),
        },
    }
}

#[allow(clippy::future_not_send)]
async fn dispatch_hostcall(host: &JsRuntimeHost, request: HostcallRequest) -> HostcallOutcome {
    dispatch_hostcall_with_runtime(None, host, request).await
}

/// Dispatch a JS hostcall through the shared ABI surface (bd-1uy.1.3).
///
/// All JS-origin hostcalls now route through [`dispatch_host_call_shared`],
/// which enforces the canonical [`HostCallPayload`] representation,
/// taxonomy-only error codes, and deterministic params hashing.
///
/// The test interceptor is checked *before* entering the shared path since
/// it operates on the JS-specific [`HostcallRequest`] type.
#[allow(clippy::future_not_send)]
async fn dispatch_hostcall_with_runtime(
    runtime: Option<&PiJsRuntime>,
    host: &JsRuntimeHost,
    request: HostcallRequest,
) -> HostcallOutcome {
    // Test interceptor check (short-circuits before the shared ABI path).
    if let Some(ref interceptor) = host.interceptor {
        if let Some(outcome) = interceptor.intercept(&request) {
            return outcome;
        }
    }

    // Convert JS request to canonical payload.
    let canonical = hostcall_request_to_payload(&request);

    // Build the shared dispatch context from the JsRuntimeHost.
    let ctx = HostCallContext {
        runtime_name: "js",
        extension_id: request.extension_id.as_deref(),
        tools: &host.tools,
        http: &host.http,
        manager: host.manager(),
        policy: &host.policy,
        js_runtime: runtime,
        interceptor: None, // already checked above
    };

    // Dispatch through the shared ABI and convert back to JS outcome.
    let result = dispatch_host_call_shared(&ctx, canonical).await;
    host_result_to_outcome(result)
}

#[allow(clippy::future_not_send)]
async fn dispatch_hostcall_tool(
    tools: &ToolRegistry,
    call_id: &str,
    name: &str,
    payload: Value,
) -> HostcallOutcome {
    let Some(tool) = tools.get(name) else {
        return HostcallOutcome::Error {
            code: "invalid_request".to_string(),
            message: format!("Unknown tool: {name}"),
        };
    };

    match tool.execute(call_id, payload, None).await {
        Ok(output) => match serde_json::to_value(output) {
            Ok(value) => HostcallOutcome::Success(value),
            Err(err) => HostcallOutcome::Error {
                code: "internal".to_string(),
                message: format!("Serialize tool output: {err}"),
            },
        },
        Err(err) => HostcallOutcome::Error {
            code: "io".to_string(),
            message: err.to_string(),
        },
    }
}

#[allow(clippy::future_not_send, clippy::too_many_lines)]
async fn dispatch_hostcall_exec(
    runtime: Option<&PiJsRuntime>,
    call_id: &str,
    cmd: &str,
    payload: Value,
) -> HostcallOutcome {
    use std::io::{BufRead as _, Read as _};
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};

    enum ExecStreamFrame {
        Stdout(String),
        Stderr(String),
        Final { code: i32, killed: bool },
        Error(String),
    }

    fn pump_stream<R: std::io::Read>(
        reader: R,
        tx: &SyncSender<ExecStreamFrame>,
        stdout: bool,
    ) -> std::result::Result<(), String> {
        let mut reader = std::io::BufReader::new(reader);
        loop {
            let mut buf = Vec::new();
            let read = reader
                .read_until(b'\n', &mut buf)
                .map_err(|err| err.to_string())?;
            if read == 0 {
                break;
            }

            let text = String::from_utf8_lossy(&buf).to_string();
            let frame = if stdout {
                ExecStreamFrame::Stdout(text)
            } else {
                ExecStreamFrame::Stderr(text)
            };
            if tx.send(frame).is_err() {
                break;
            }
        }
        Ok(())
    }

    #[allow(clippy::unnecessary_lazy_evaluations)] // lazy eval needed on unix for signal()
    fn exit_status_code(status: std::process::ExitStatus) -> i32 {
        status.code().unwrap_or_else(|| {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt as _;
                status.signal().map_or(-1, |signal| -signal)
            }
            #[cfg(not(unix))]
            {
                -1
            }
        })
    }

    let args_value = payload.get("args").cloned().unwrap_or(Value::Null);
    let args_array = match args_value {
        Value::Null => Vec::new(),
        Value::Array(items) => items,
        _ => {
            return HostcallOutcome::Error {
                code: "invalid_request".to_string(),
                message: "exec args must be an array".to_string(),
            };
        }
    };

    let args = args_array
        .iter()
        .map(|v| {
            v.as_str()
                .map_or_else(|| v.to_string(), ToString::to_string)
        })
        .collect::<Vec<_>>();

    let options = payload.get("options").cloned().unwrap_or_else(|| json!({}));
    let cwd = options
        .get("cwd")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let timeout_ms = options
        .get("timeout")
        .and_then(Value::as_u64)
        .or_else(|| options.get("timeoutMs").and_then(Value::as_u64))
        .or_else(|| options.get("timeout_ms").and_then(Value::as_u64))
        .filter(|ms| *ms > 0);
    let stream = options
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if stream {
        if let Some(runtime) = runtime {
            if !runtime.is_hostcall_pending(call_id) {
                return HostcallOutcome::Error {
                    code: "timeout".to_string(),
                    message: "exec stream cancelled".to_string(),
                };
            }

            let cmd = cmd.to_string();
            let (tx, rx) = mpsc::sync_channel::<ExecStreamFrame>(256);
            let cancel = Arc::new(AtomicBool::new(false));
            let cancel_worker = Arc::clone(&cancel);
            let call_id_for_error = call_id.to_string();

            thread::spawn(move || {
                let result = (|| -> std::result::Result<(), String> {
                    let mut command = Command::new(&cmd);
                    command
                        .args(&args)
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());

                    if let Some(cwd) = cwd.as_ref() {
                        command.current_dir(cwd);
                    }

                    let mut child = command.spawn().map_err(|err| err.to_string())?;
                    let pid = child.id();

                    let stdout = child.stdout.take().ok_or("Missing stdout pipe")?;
                    let stderr = child.stderr.take().ok_or("Missing stderr pipe")?;

                    let stdout_tx = tx.clone();
                    let stderr_tx = tx.clone();
                    let stdout_handle =
                        thread::spawn(move || pump_stream(stdout, &stdout_tx, true));
                    let stderr_handle =
                        thread::spawn(move || pump_stream(stderr, &stderr_tx, false));

                    let start = Instant::now();
                    let mut killed = false;
                    let status = loop {
                        if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
                            break status;
                        }

                        if cancel_worker.load(AtomicOrdering::SeqCst) {
                            killed = true;
                            crate::tools::kill_process_tree(Some(pid));
                            let _ = child.kill();
                            break child.wait().map_err(|err| err.to_string())?;
                        }

                        if let Some(timeout_ms) = timeout_ms {
                            if start.elapsed() >= Duration::from_millis(timeout_ms) {
                                killed = true;
                                crate::tools::kill_process_tree(Some(pid));
                                let _ = child.kill();
                                break child.wait().map_err(|err| err.to_string())?;
                            }
                        }

                        thread::sleep(Duration::from_millis(10));
                    };

                    let stdout_result = stdout_handle
                        .join()
                        .map_err(|_| "stdout reader thread panicked".to_string())?;
                    if let Err(err) = stdout_result {
                        return Err(format!("Read stdout: {err}"));
                    }

                    let stderr_result = stderr_handle
                        .join()
                        .map_err(|_| "stderr reader thread panicked".to_string())?;
                    if let Err(err) = stderr_result {
                        return Err(format!("Read stderr: {err}"));
                    }

                    let code = exit_status_code(status);
                    let _ = tx.send(ExecStreamFrame::Final { code, killed });
                    Ok(())
                })();

                if let Err(err) = result {
                    if tx.send(ExecStreamFrame::Error(err)).is_err() {
                        tracing::trace!(
                            call_id = %call_id_for_error,
                            "Exec hostcall stream result dropped before completion"
                        );
                    }
                }
            });

            let mut sequence = 0_u64;
            loop {
                if !runtime.is_hostcall_pending(call_id) {
                    cancel.store(true, AtomicOrdering::SeqCst);
                    return HostcallOutcome::Error {
                        code: "timeout".to_string(),
                        message: "exec stream cancelled".to_string(),
                    };
                }

                match rx.recv_timeout(Duration::from_millis(25)) {
                    Ok(ExecStreamFrame::Stdout(chunk)) => {
                        runtime.complete_hostcall(
                            call_id.to_string(),
                            HostcallOutcome::StreamChunk {
                                sequence,
                                chunk: json!({ "stdout": chunk }),
                                is_final: false,
                            },
                        );
                        sequence = sequence.saturating_add(1);
                    }
                    Ok(ExecStreamFrame::Stderr(chunk)) => {
                        runtime.complete_hostcall(
                            call_id.to_string(),
                            HostcallOutcome::StreamChunk {
                                sequence,
                                chunk: json!({ "stderr": chunk }),
                                is_final: false,
                            },
                        );
                        sequence = sequence.saturating_add(1);
                    }
                    Ok(ExecStreamFrame::Final { code, killed }) => {
                        return HostcallOutcome::StreamChunk {
                            sequence,
                            chunk: json!({
                                "code": code,
                                "killed": killed,
                            }),
                            is_final: true,
                        };
                    }
                    Ok(ExecStreamFrame::Error(message)) => {
                        return HostcallOutcome::Error {
                            code: "io".to_string(),
                            message,
                        };
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        return HostcallOutcome::Error {
                            code: "internal".to_string(),
                            message: "exec stream channel closed".to_string(),
                        };
                    }
                }
            }
        }
    }

    let cmd = cmd.to_string();
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        let result: std::result::Result<Value, String> = (|| {
            let mut command = Command::new(&cmd);
            command
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            if let Some(cwd) = cwd.as_ref() {
                command.current_dir(cwd);
            }

            let mut child = command.spawn().map_err(|err| err.to_string())?;
            let pid = child.id();

            let mut stdout = child.stdout.take().ok_or("Missing stdout pipe")?;
            let mut stderr = child.stderr.take().ok_or("Missing stderr pipe")?;

            let stdout_handle = thread::spawn(move || -> std::result::Result<Vec<u8>, String> {
                let mut buf = Vec::new();
                stdout
                    .read_to_end(&mut buf)
                    .map_err(|err| err.to_string())?;
                Ok(buf)
            });
            let stderr_handle = thread::spawn(move || -> std::result::Result<Vec<u8>, String> {
                let mut buf = Vec::new();
                stderr
                    .read_to_end(&mut buf)
                    .map_err(|err| err.to_string())?;
                Ok(buf)
            });

            let start = Instant::now();
            let mut killed = false;
            let status = loop {
                if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
                    break status;
                }

                if let Some(timeout_ms) = timeout_ms {
                    if start.elapsed() >= Duration::from_millis(timeout_ms) {
                        killed = true;
                        crate::tools::kill_process_tree(Some(pid));
                        let _ = child.kill();
                        break child.wait().map_err(|err| err.to_string())?;
                    }
                }

                thread::sleep(Duration::from_millis(10));
            };

            let stdout_bytes = stdout_handle
                .join()
                .map_err(|_| "stdout reader thread panicked".to_string())?
                .map_err(|err| format!("Read stdout: {err}"))?;
            let stderr_bytes = stderr_handle
                .join()
                .map_err(|_| "stderr reader thread panicked".to_string())?
                .map_err(|err| format!("Read stderr: {err}"))?;

            let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
            let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
            let code = exit_status_code(status);

            Ok(json!({
                "stdout": stdout,
                "stderr": stderr,
                "code": code,
                "killed": killed,
            }))
        })();

        let cx = Cx::for_request();
        let _ = tx.send(&cx, result);
    });

    let cx = Cx::for_request();
    match rx.recv(&cx).await {
        Ok(Ok(value)) => HostcallOutcome::Success(value),
        Ok(Err(err)) => HostcallOutcome::Error {
            code: "io".to_string(),
            message: err,
        },
        Err(_) => HostcallOutcome::Error {
            code: "internal".to_string(),
            message: "exec task cancelled".to_string(),
        },
    }
}

#[allow(clippy::future_not_send)]
async fn dispatch_hostcall_http(
    call_id: &str,
    connector: &HttpConnector,
    payload: Value,
) -> HostcallOutcome {
    let call = crate::connectors::HostCallPayload {
        call_id: call_id.to_string(),
        capability: "http".to_string(),
        method: "http".to_string(),
        params: payload,
        timeout_ms: None,
        cancel_token: None,
        context: None,
    };

    match connector.dispatch(&call).await {
        Ok(result) => {
            if result.is_error {
                let message = result.error.as_ref().map_or_else(
                    || "HTTP connector error".to_string(),
                    |err| err.message.clone(),
                );
                let code = result
                    .error
                    .as_ref()
                    .map_or("internal", |err| hostcall_code_to_str(err.code));
                HostcallOutcome::Error {
                    code: code.to_string(),
                    message,
                }
            } else {
                HostcallOutcome::Success(result.output)
            }
        }
        Err(err) => HostcallOutcome::Error {
            code: "internal".to_string(),
            message: err.to_string(),
        },
    }
}

const fn hostcall_code_to_str(code: HostCallErrorCode) -> &'static str {
    match code {
        HostCallErrorCode::Timeout => "timeout",
        HostCallErrorCode::Denied => "denied",
        HostCallErrorCode::Io => "io",
        HostCallErrorCode::InvalidRequest => "invalid_request",
        HostCallErrorCode::Internal => "internal",
    }
}

#[allow(clippy::future_not_send)]
#[allow(clippy::too_many_lines)]
async fn dispatch_hostcall_session(
    _call_id: &str,
    manager: &ExtensionManager,
    op: &str,
    payload: Value,
) -> HostcallOutcome {
    let Some(session) = manager.session_handle() else {
        return HostcallOutcome::Error {
            code: "denied".to_string(),
            message: "No session configured".to_string(),
        };
    };

    let op_norm = op.trim().to_ascii_lowercase();
    let result = match op_norm.as_str() {
        "get_state" | "getstate" => Ok(session.get_state().await),
        "get_messages" | "getmessages" => serde_json::to_value(session.get_messages().await)
            .map_err(|err| Error::extension(format!("Serialize messages: {err}"))),
        "get_entries" | "getentries" => serde_json::to_value(session.get_entries().await)
            .map_err(|err| Error::extension(format!("Serialize entries: {err}"))),
        "get_branch" | "getbranch" => serde_json::to_value(session.get_branch().await)
            .map_err(|err| Error::extension(format!("Serialize branch: {err}"))),
        "get_file" | "getfile" => {
            let state = session.get_state().await;
            let file = state
                .get("sessionFile")
                .or_else(|| state.get("session_file"))
                .cloned()
                .unwrap_or(Value::Null);
            Ok(file)
        }
        "get_name" | "getname" => {
            let state = session.get_state().await;
            let name = state
                .get("sessionName")
                .or_else(|| state.get("session_name"))
                .cloned()
                .unwrap_or(Value::Null);
            Ok(name)
        }
        "set_name" | "setname" => {
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            session.set_name(name).await.map(|()| Value::Null)
        }
        "set_model" | "setmodel" => {
            let provider = payload
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let model_id = payload
                .get("modelId")
                .and_then(Value::as_str)
                .or_else(|| payload.get("model_id").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            if provider.is_empty() || model_id.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "setModel: provider and modelId are required".to_string(),
                };
            }
            session
                .set_model(provider, model_id)
                .await
                .map(|()| Value::Bool(true))
        }
        "get_model" | "getmodel" => {
            let (provider, model_id) = session.get_model().await;
            Ok(serde_json::json!({
                "provider": provider,
                "modelId": model_id,
            }))
        }
        "set_thinking_level" | "setthinkinglevel" => {
            let level = payload
                .get("level")
                .and_then(Value::as_str)
                .or_else(|| payload.get("thinkingLevel").and_then(Value::as_str))
                .or_else(|| payload.get("thinking_level").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            if level.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "setThinkingLevel: level is required".to_string(),
                };
            }
            session
                .set_thinking_level(level)
                .await
                .map(|()| Value::Null)
        }
        "get_thinking_level" | "getthinkinglevel" => {
            let level = session.get_thinking_level().await;
            Ok(level.map_or(Value::Null, Value::String))
        }
        "append_message" | "appendmessage" => {
            let message_value = payload.get("message").cloned().unwrap_or(payload);
            match serde_json::from_value(message_value) {
                Ok(message) => session.append_message(message).await.map(|()| Value::Null),
                Err(err) => Err(Error::validation(format!("Parse message: {err}"))),
            }
        }
        "append_entry" | "appendentry" => {
            let custom_type = payload
                .get("customType")
                .and_then(Value::as_str)
                .or_else(|| payload.get("custom_type").and_then(Value::as_str))
                .or_else(|| payload.get("customtype").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            let data = payload.get("data").cloned();
            session
                .append_custom_entry(custom_type, data)
                .await
                .map(|()| Value::Null)
        }
        "set_label" | "setlabel" => {
            let target_id = payload
                .get("targetId")
                .and_then(Value::as_str)
                .or_else(|| payload.get("target_id").and_then(Value::as_str))
                .or_else(|| payload.get("entryId").and_then(Value::as_str))
                .or_else(|| payload.get("entry_id").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            if target_id.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "setLabel: targetId is required".to_string(),
                };
            }
            let label = payload
                .get("label")
                .and_then(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            session
                .set_label(target_id, label)
                .await
                .map(|()| Value::Null)
        }
        _ => Err(Error::validation(format!("Unknown session op: {op}"))),
    };

    match result {
        Ok(value) => HostcallOutcome::Success(value),
        Err(err) => {
            let code = err.hostcall_error_code().to_string();
            HostcallOutcome::Error {
                code,
                message: err.to_string(),
            }
        }
    }
}

#[allow(clippy::future_not_send)]
async fn dispatch_hostcall_ui(
    call_id: &str,
    manager: &ExtensionManager,
    op: &str,
    payload: Value,
    extension_id: Option<&str>,
) -> HostcallOutcome {
    let op = op.trim();
    if op.is_empty() {
        return HostcallOutcome::Error {
            code: "invalid_request".to_string(),
            message: "host_call ui requires non-empty op".to_string(),
        };
    }

    let request = ExtensionUiRequest {
        id: call_id.to_string(),
        method: op.to_string(),
        payload,
        timeout_ms: None,
        extension_id: extension_id.map(ToString::to_string),
    };

    match manager.request_ui(request).await {
        Ok(Some(response)) => HostcallOutcome::Success(ui_response_value_for_op(op, &response)),
        Ok(None) => HostcallOutcome::Success(Value::Null),
        Err(err) => HostcallOutcome::Error {
            code: classify_ui_hostcall_error(&err).to_string(),
            message: err.to_string(),
        },
    }
}

pub(crate) fn ui_response_value_for_op(op: &str, response: &ExtensionUiResponse) -> Value {
    if response.cancelled {
        return match op {
            // Deterministic defaults: confirm cancellation/timeout resolves false.
            "confirm" => Value::Bool(false),
            _ => Value::Null,
        };
    }
    response.value.clone().unwrap_or(Value::Null)
}

pub(crate) fn classify_ui_hostcall_error(err: &Error) -> &'static str {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("timed out") || lower.contains("cancel") {
        "timeout"
    } else if lower.contains("not configured")
        || lower.contains("channel closed")
        || lower.contains("response dropped")
    {
        "denied"
    } else {
        err.hostcall_error_code()
    }
}

#[allow(clippy::future_not_send, clippy::too_many_lines)]
async fn dispatch_hostcall_log(
    call_id: &str,
    extension_id: Option<&str>,
    payload: Value,
) -> HostcallOutcome {
    let Value::Object(mut entry) = payload else {
        return HostcallOutcome::Error {
            code: "invalid_request".to_string(),
            message: "host_call log requires params object".to_string(),
        };
    };

    entry
        .entry("schema".to_string())
        .or_insert_with(|| Value::String(LOG_SCHEMA_VERSION.to_string()));
    entry.entry("ts".to_string()).or_insert_with(|| {
        Value::String(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    });

    let mut correlation = match entry.remove("correlation") {
        Some(Value::Object(map)) => map,
        Some(_) => {
            return HostcallOutcome::Error {
                code: "invalid_request".to_string(),
                message: "host_call log correlation must be an object".to_string(),
            };
        }
        None => serde_json::Map::new(),
    };

    if !correlation.contains_key("extension_id") {
        let ext = extension_id.unwrap_or("<unknown>");
        correlation.insert("extension_id".to_string(), Value::String(ext.to_string()));
    }
    correlation
        .entry("scenario_id".to_string())
        .or_insert_with(|| Value::String("runtime".to_string()));
    correlation
        .entry("host_call_id".to_string())
        .or_insert_with(|| Value::String(call_id.to_string()));
    entry.insert("correlation".to_string(), Value::Object(correlation));

    let payload = Value::Object(entry);
    let log_entry: LogPayload = match serde_json::from_value(payload) {
        Ok(value) => value,
        Err(err) => {
            return HostcallOutcome::Error {
                code: "invalid_request".to_string(),
                message: format!("host_call log payload is invalid: {err}"),
            };
        }
    };

    if let Err(err) = validate_log(&log_entry) {
        return HostcallOutcome::Error {
            code: "invalid_request".to_string(),
            message: format!("host_call log payload validation failed: {err}"),
        };
    }

    let data = log_entry.data.clone().unwrap_or(Value::Null);
    match log_entry.level {
        LogLevel::Debug => tracing::debug!(
            target: "pijs.ext.log",
            event = %log_entry.event,
            extension_id = %log_entry.correlation.extension_id,
            scenario_id = %log_entry.correlation.scenario_id,
            host_call_id = ?log_entry.correlation.host_call_id,
            data = ?data,
            "{message}",
            message = log_entry.message
        ),
        LogLevel::Info => tracing::info!(
            target: "pijs.ext.log",
            event = %log_entry.event,
            extension_id = %log_entry.correlation.extension_id,
            scenario_id = %log_entry.correlation.scenario_id,
            host_call_id = ?log_entry.correlation.host_call_id,
            data = ?data,
            "{message}",
            message = log_entry.message
        ),
        LogLevel::Warn => tracing::warn!(
            target: "pijs.ext.log",
            event = %log_entry.event,
            extension_id = %log_entry.correlation.extension_id,
            scenario_id = %log_entry.correlation.scenario_id,
            host_call_id = ?log_entry.correlation.host_call_id,
            data = ?data,
            "{message}",
            message = log_entry.message
        ),
        LogLevel::Error => tracing::error!(
            target: "pijs.ext.log",
            event = %log_entry.event,
            extension_id = %log_entry.correlation.extension_id,
            scenario_id = %log_entry.correlation.scenario_id,
            host_call_id = ?log_entry.correlation.host_call_id,
            data = ?data,
            "{message}",
            message = log_entry.message
        ),
    }

    HostcallOutcome::Success(json!({
        "ok": true,
        "schema": log_entry.schema,
        "event": log_entry.event,
    }))
}

#[allow(clippy::future_not_send, clippy::too_many_lines)]
async fn dispatch_hostcall_events(
    _call_id: &str,
    manager: &ExtensionManager,
    tools: &ToolRegistry,
    op: &str,
    payload: Value,
) -> HostcallOutcome {
    let op_norm = op.trim().to_ascii_lowercase();
    match op_norm.as_str() {
        "getactivetools" | "get_active_tools" => {
            let active = manager
                .active_tools()
                .unwrap_or_else(|| tools.tools().iter().map(|t| t.name().to_string()).collect());
            HostcallOutcome::Success(json!({ "tools": active }))
        }
        "getalltools" | "get_all_tools" => {
            let mut result: Vec<Value> = tools
                .tools()
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name(),
                        "description": t.description(),
                    })
                })
                .collect();
            for def in manager.extension_tool_defs() {
                let name = def.get("name").and_then(Value::as_str).unwrap_or_default();
                let description = def
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                result.push(json!({
                    "name": name,
                    "description": description,
                }));
            }
            HostcallOutcome::Success(json!({ "tools": result }))
        }
        "setactivetools" | "set_active_tools" => {
            let tools = payload
                .get("tools")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            manager.set_active_tools(tools);
            HostcallOutcome::Success(Value::Null)
        }
        "appendentry" | "append_entry" => {
            let Some(session) = manager.session_handle() else {
                return HostcallOutcome::Error {
                    code: "denied".to_string(),
                    message: "No session configured".to_string(),
                };
            };
            let custom_type = payload
                .get("customType")
                .and_then(Value::as_str)
                .or_else(|| payload.get("custom_type").and_then(Value::as_str))
                .or_else(|| payload.get("customtype").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            let data = payload.get("data").cloned();
            match session.append_custom_entry(custom_type, data).await {
                Ok(()) => HostcallOutcome::Success(Value::Null),
                Err(err) => HostcallOutcome::Error {
                    code: "io".to_string(),
                    message: err.to_string(),
                },
            }
        }
        "sendmessage" | "send_message" => {
            let Some(actions) = manager.host_actions() else {
                return HostcallOutcome::Error {
                    code: "denied".to_string(),
                    message: "No host actions configured".to_string(),
                };
            };

            let extension_id = payload
                .get("extensionId")
                .and_then(Value::as_str)
                .or_else(|| payload.get("extension_id").and_then(Value::as_str))
                .map(ToString::to_string);

            let message = payload.get("message").cloned().unwrap_or(Value::Null);
            let options = payload.get("options").cloned().unwrap_or(Value::Null);

            let custom_type = message
                .get("customType")
                .and_then(Value::as_str)
                .or_else(|| message.get("custom_type").and_then(Value::as_str))
                .unwrap_or_default()
                .trim()
                .to_string();
            if custom_type.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "sendMessage: message.customType is required".to_string(),
                };
            }

            let display = message
                .get("display")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let details = message.get("details").cloned();

            let content = match message.get("content") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => {
                    serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string())
                }
                None => String::new(),
            };

            let deliver_as = ExtensionDeliverAs::parse(
                options
                    .get("deliverAs")
                    .and_then(Value::as_str)
                    .or_else(|| options.get("deliver_as").and_then(Value::as_str)),
            );
            let trigger_turn = options
                .get("triggerTurn")
                .and_then(Value::as_bool)
                .or_else(|| options.get("trigger_turn").and_then(Value::as_bool))
                .unwrap_or(false);

            let msg = ExtensionSendMessage {
                extension_id,
                custom_type,
                content,
                display,
                details,
                deliver_as,
                trigger_turn,
            };

            match actions.send_message(msg).await {
                Ok(()) => HostcallOutcome::Success(Value::Null),
                Err(err) => HostcallOutcome::Error {
                    code: "io".to_string(),
                    message: err.to_string(),
                },
            }
        }
        "sendusermessage" | "send_user_message" => {
            let Some(actions) = manager.host_actions() else {
                return HostcallOutcome::Error {
                    code: "denied".to_string(),
                    message: "No host actions configured".to_string(),
                };
            };

            let extension_id = payload
                .get("extensionId")
                .and_then(Value::as_str)
                .or_else(|| payload.get("extension_id").and_then(Value::as_str))
                .map(ToString::to_string);

            let text = payload
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if text.is_empty() {
                return HostcallOutcome::Success(Value::Null);
            }

            let options = payload.get("options").cloned().unwrap_or(Value::Null);
            let deliver_as = ExtensionDeliverAs::parse(
                options
                    .get("deliverAs")
                    .and_then(Value::as_str)
                    .or_else(|| options.get("deliver_as").and_then(Value::as_str)),
            );

            let msg = ExtensionSendUserMessage {
                extension_id,
                text,
                deliver_as,
            };

            match actions.send_user_message(msg).await {
                Ok(()) => HostcallOutcome::Success(Value::Null),
                Err(err) => HostcallOutcome::Error {
                    code: "io".to_string(),
                    message: err.to_string(),
                },
            }
        }
        "registercommand" | "register_command" => {
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if name.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "registerCommand: name is required".to_string(),
                };
            }
            let description = payload
                .get("description")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            manager.register_command(&name, description.as_deref());
            HostcallOutcome::Success(Value::Null)
        }
        "registerprovider" | "register_provider" => {
            let id = payload
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if id.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "registerProvider: id is required".to_string(),
                };
            }
            let api = payload
                .get("api")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if api.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "registerProvider: api is required".to_string(),
                };
            }
            // Validate api type.
            match api.as_str() {
                "anthropic-messages"
                | "openai-completions"
                | "openai-responses"
                | "google-generative-ai" => {}
                other => {
                    return HostcallOutcome::Error {
                        code: "invalid_request".to_string(),
                        message: format!(
                            "registerProvider: unsupported api type: {other}. \
                             Supported: anthropic-messages, openai-completions, \
                             openai-responses, google-generative-ai"
                        ),
                    };
                }
            }
            manager.register_provider(payload);
            HostcallOutcome::Success(Value::Null)
        }
        "getmodel" | "get_model" => {
            // Prefer session-authoritative state; fall back to in-memory cache.
            let (provider, model_id) = if let Some(session) = manager.session_handle() {
                session.get_model().await
            } else {
                manager.current_model()
            };
            HostcallOutcome::Success(json!({
                "provider": provider,
                "modelId": model_id,
            }))
        }
        "setmodel" | "set_model" => {
            let provider = payload
                .get("provider")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let model_id = payload
                .get("modelId")
                .and_then(Value::as_str)
                .or_else(|| payload.get("model_id").and_then(Value::as_str))
                .map(ToString::to_string);

            // Update in-memory cache on manager.
            manager.set_current_model(provider.clone(), model_id.clone());

            // Persist via session (creates ModelChangeEntry + updates header).
            if let Some(session) = manager.session_handle() {
                let p = provider.unwrap_or_default();
                let m = model_id.unwrap_or_default();
                if !p.is_empty() && !m.is_empty() {
                    if let Err(err) = session.set_model(p, m).await {
                        return HostcallOutcome::Error {
                            code: "io".to_string(),
                            message: format!("setModel: session update failed: {err}"),
                        };
                    }
                }
            }
            HostcallOutcome::Success(Value::Null)
        }
        "getthinkinglevel" | "get_thinking_level" => {
            // Prefer session-authoritative state; fall back to in-memory cache.
            let level = if let Some(session) = manager.session_handle() {
                session.get_thinking_level().await
            } else {
                manager.current_thinking_level()
            };
            HostcallOutcome::Success(json!({ "thinkingLevel": level }))
        }
        "setthinkinglevel" | "set_thinking_level" => {
            let level = payload
                .get("thinkingLevel")
                .and_then(Value::as_str)
                .or_else(|| payload.get("thinking_level").and_then(Value::as_str))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            // Update in-memory cache on manager.
            manager.set_current_thinking_level(level.clone());

            // Persist via session (creates ThinkingLevelChangeEntry + updates header).
            if let Some(session) = manager.session_handle() {
                if let Some(ref lvl) = level {
                    if let Err(err) = session.set_thinking_level(lvl.clone()).await {
                        return HostcallOutcome::Error {
                            code: "io".to_string(),
                            message: format!("setThinkingLevel: session update failed: {err}"),
                        };
                    }
                }
            }
            HostcallOutcome::Success(Value::Null)
        }
        "registerflag" | "register_flag" => {
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if name.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "registerFlag: name is required".to_string(),
                };
            }
            manager.register_flag(payload);
            HostcallOutcome::Success(Value::Null)
        }
        "getflag" | "get_flag" => {
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if name.is_empty() {
                return HostcallOutcome::Error {
                    code: "invalid_request".to_string(),
                    message: "getFlag: name is required".to_string(),
                };
            }
            let all_flags = manager.list_flags();
            let flag = all_flags
                .iter()
                .find(|f| f.get("name").and_then(Value::as_str).unwrap_or_default() == name);
            flag.map_or(HostcallOutcome::Success(Value::Null), |f| {
                HostcallOutcome::Success(f.clone())
            })
        }
        "listflags" | "list_flags" => {
            let flags = manager.list_flags();
            HostcallOutcome::Success(json!(flags))
        }
        _ => HostcallOutcome::Error {
            code: "invalid_request".to_string(),
            message: format!("Unknown events op: {}", op.trim()),
        },
    }
}

#[allow(clippy::future_not_send)]
async fn await_js_task(
    runtime: &PiJsRuntime,
    host: &JsRuntimeHost,
    task_id: &str,
    timeout: Duration,
) -> Result<Value> {
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::extension(format!(
                "JS task timed out after {}ms",
                timeout.as_millis()
            )));
        }

        let _has_pending = pump_js_runtime_once(runtime, host).await?;

        let state_json = runtime
            .with_ctx(|ctx| {
                let global = ctx.globals();
                let take_fn: rquickjs::Function<'_> = global.get("__pi_task_take")?;
                let value: rquickjs::Value<'_> = take_fn.call((task_id.to_string(),))?;
                js_to_json(&value)
            })
            .await?;

        if state_json.is_null() {
            return Err(Error::extension("JS task state missing".to_string()));
        }

        let state: JsTaskState =
            serde_json::from_value(state_json).map_err(|err| Error::extension(err.to_string()))?;

        match state.status.as_str() {
            "pending" => {
                if !runtime.has_pending() {
                    sleep(wall_now(), Duration::from_millis(1)).await;
                }
            }
            "resolved" => return Ok(state.value.unwrap_or(Value::Null)),
            "rejected" => {
                let err = state.error.unwrap_or_else(|| JsTaskError {
                    code: None,
                    message: "Unknown JS task error".to_string(),
                    stack: None,
                });
                let mut message = err.message;
                if let Some(code) = err.code {
                    message = format!("{code}: {message}");
                }
                if let Some(stack) = err.stack {
                    if !stack.is_empty() {
                        message.push('\n');
                        message.push_str(&stack);
                    }
                }
                return Err(Error::extension(message));
            }
            other => {
                return Err(Error::extension(format!(
                    "Unexpected JS task status: {other}"
                )));
            }
        }

        sleep(wall_now(), Duration::from_millis(0)).await;
    }
}

/// Extension manager for handling loaded extensions.
#[derive(Clone)]
pub struct ExtensionManager {
    inner: Arc<Mutex<ExtensionManagerInner>>,
}

#[cfg(feature = "wasm-host")]
#[derive(Clone, Default)]
pub(crate) struct ExtensionManagerHandle {
    inner: Weak<Mutex<ExtensionManagerInner>>,
}

#[cfg(feature = "wasm-host")]
impl ExtensionManagerHandle {
    fn new(manager: &ExtensionManager) -> Self {
        Self {
            inner: Arc::downgrade(&manager.inner),
        }
    }

    fn upgrade(&self) -> Option<ExtensionManager> {
        self.inner.upgrade().map(|inner| ExtensionManager { inner })
    }
}

#[derive(Default)]
struct ExtensionManagerInner {
    extensions: Vec<RegisterPayload>,
    js_runtime: Option<JsExtensionRuntimeHandle>,
    #[cfg(feature = "wasm-host")]
    wasm_extensions: Vec<WasmExtensionHandle>,
    ui_sender: Option<mpsc::Sender<ExtensionUiRequest>>,
    pending_ui: HashMap<String, oneshot::Sender<ExtensionUiResponse>>,
    session: Option<Arc<dyn ExtensionSession>>,
    active_tools: Option<Vec<String>>,
    providers: Vec<Value>,
    flags: Vec<Value>,
    cwd: Option<String>,
    model_registry_values: HashMap<String, String>,
    current_provider: Option<String>,
    current_model_id: Option<String>,
    current_thinking_level: Option<String>,
    host_actions: Option<Arc<dyn ExtensionHostActions>>,
    policy_prompt_cache: HashMap<String, HashMap<String, PersistedDecision>>,
    /// Persistent store for "Allow Always" / "Deny Always" decisions.
    permission_store: Option<PermissionStore>,
    /// Runtime risk controller configuration and mutable per-extension state.
    runtime_risk_config: RuntimeRiskConfig,
    runtime_risk_states: HashMap<String, RuntimeRiskState>,
    runtime_risk_ledger: VecDeque<RuntimeRiskLedgerEntry>,
    runtime_hostcall_telemetry: VecDeque<RuntimeHostcallTelemetryEvent>,
    runtime_risk_last_hash: Option<String>,
    /// Per-extension resource quota config and mutable counters (SEC-4.1).
    quota_config: ExtensionQuotaConfig,
    quota_states: HashMap<String, ExtensionQuotaState>,
    /// Quota breach telemetry events (SEC-4.1).
    quota_breach_events: VecDeque<QuotaBreachEvent>,
    /// Budget for extension operations (structured concurrency).
    extension_budget: Budget,
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

/// RAII guard for extension lifecycle with structured concurrency guarantees.
///
/// Wraps an [`ExtensionManager`] and ensures that the JS runtime thread is
/// shut down when the region exits.  Provides:
///
/// - **No orphaned tasks**: the runtime thread exits on region close.
/// - **Bounded cleanup**: shutdown is capped by a configurable budget.
/// - **Drop safety**: best-effort shutdown if `shutdown()` was not called.
pub struct ExtensionRegion {
    manager: ExtensionManager,
    cleanup_budget: Duration,
    shutdown_done: std::sync::atomic::AtomicBool,
}

impl ExtensionRegion {
    /// Create a new extension region with the default cleanup budget (5 s).
    pub const fn new(manager: ExtensionManager) -> Self {
        Self {
            manager,
            cleanup_budget: ExtensionManager::DEFAULT_CLEANUP_BUDGET,
            shutdown_done: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a region with a custom cleanup budget.
    pub const fn with_budget(manager: ExtensionManager, budget: Duration) -> Self {
        Self {
            manager,
            cleanup_budget: budget,
            shutdown_done: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Access the inner [`ExtensionManager`].
    pub const fn manager(&self) -> &ExtensionManager {
        &self.manager
    }

    /// Consume the region and return the inner manager (caller takes
    /// responsibility for shutdown).
    pub fn into_inner(mut self) -> ExtensionManager {
        self.shutdown_done
            .store(true, std::sync::atomic::Ordering::Release);
        std::mem::take(&mut self.manager)
    }

    /// Explicitly shut down extensions with the configured budget.
    ///
    /// Returns `true` if the runtime exited cleanly within the budget.
    /// Subsequent calls are no-ops and return `true`.
    pub async fn shutdown(&self) -> bool {
        if self
            .shutdown_done
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return true; // already done
        }
        self.manager.shutdown(self.cleanup_budget).await
    }
}

impl Drop for ExtensionRegion {
    fn drop(&mut self) {
        if self.shutdown_done.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // Best-effort: the Weak reference in JsRuntimeHost will fail to
        // upgrade once the ExtensionManager's Arc refcount drops, causing
        // the runtime thread to observe channel closure and exit.
        tracing::debug!(
            event = "extension_region.drop_without_shutdown",
            "ExtensionRegion dropped without explicit shutdown; \
             runtime thread will exit on Arc release"
        );
    }
}

impl std::fmt::Debug for ExtensionRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionRegion")
            .field("manager", &self.manager)
            .field("cleanup_budget", &self.cleanup_budget)
            .field(
                "shutdown_done",
                &self
                    .shutdown_done
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

fn check_version_constraint(version: &str, range: &str) -> bool {
    let range = range.trim();
    if range == "*" || range.is_empty() {
        return true;
    }

    let parse = |s: &str| -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 3 {
            return None;
        }
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch_str = parts[2].split(['-', '+']).next()?;
        let patch = patch_str.parse().ok()?;
        Some((major, minor, patch))
    };

    let Some((v_major, v_minor, v_patch)) = parse(version) else {
        return false;
    };

    if let Some(rest) = range.strip_prefix('^') {
        let Some((r_major, _, _)) = parse(rest) else {
            return false;
        };
        return v_major == r_major;
    }

    if let Some(rest) = range.strip_prefix('~') {
        let Some((r_major, r_minor, _)) = parse(rest) else {
            return false;
        };
        return v_major == r_major && v_minor == r_minor;
    }

    if let Some(rest) = range.strip_prefix(">=") {
        let Some((r_major, r_minor, r_patch)) = parse(rest) else {
            return false;
        };
        if v_major > r_major {
            return true;
        }
        if v_major < r_major {
            return false;
        }
        if v_minor > r_minor {
            return true;
        }
        if v_minor < r_minor {
            return false;
        }
        return v_patch >= r_patch;
    }

    version == range
}

impl ExtensionManager {
    /// Default cleanup budget for extension shutdown.
    pub const DEFAULT_CLEANUP_BUDGET: Duration = Duration::from_secs(5);

    /// Create a new extension manager.
    ///
    /// Loads persisted permission decisions from disk (if any) and seeds the
    /// in-memory policy prompt cache so that "Allow Always" / "Deny Always"
    /// choices survive across sessions.
    pub fn new() -> Self {
        let mut inner = ExtensionManagerInner::default();
        Self::load_persisted_permissions(&mut inner);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Create a new extension manager with a specific operation budget.
    pub fn with_budget(budget: Budget) -> Self {
        let mut inner = ExtensionManagerInner {
            extension_budget: budget,
            ..Default::default()
        };
        Self::load_persisted_permissions(&mut inner);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Load persisted permission decisions into the inner state.
    fn load_persisted_permissions(inner: &mut ExtensionManagerInner) {
        match PermissionStore::open_default() {
            Ok(store) => {
                // Seed the in-memory cache from persisted decisions.
                inner.policy_prompt_cache = store.to_decision_cache();
                inner.permission_store = Some(store);
            }
            Err(e) => {
                tracing::warn!("Failed to load extension permissions: {e}");
            }
        }
    }

    /// Set the budget for extension operations.
    pub fn set_budget(&self, budget: Budget) {
        let mut guard = self.inner.lock().unwrap();
        guard.extension_budget = budget;
    }

    /// Get the current extension operation budget.
    pub fn budget(&self) -> Budget {
        let guard = self.inner.lock().unwrap();
        guard.extension_budget
    }

    /// Create a `Cx` for extension operations using the configured budget.
    ///
    /// If a budget with constraints is set, returns a budget-constrained Cx.
    /// Otherwise returns a standard request-scoped Cx.
    pub fn extension_cx(&self) -> Cx {
        let budget = self.budget();
        if budget.deadline.is_some() || budget.poll_quota < u32::MAX || budget.cost_quota.is_some()
        {
            Cx::for_request_with_budget(budget)
        } else {
            Cx::for_request()
        }
    }

    /// Compute the effective timeout for an operation, taking the minimum of
    /// the per-operation timeout and the remaining manager-level budget deadline.
    ///
    /// When the manager has a constrained budget (e.g. during shutdown), this
    /// ensures individual operations don't outlast the overall budget.
    fn effective_timeout(&self, operation_timeout_ms: u64) -> u64 {
        let budget = self.budget();
        budget.deadline.map_or(operation_timeout_ms, |deadline| {
            let now = wall_now();
            let remaining_ms = deadline.as_millis().saturating_sub(now.as_millis());
            operation_timeout_ms.min(remaining_ms)
        })
    }

    fn runtime_risk_extension_key(extension_id: Option<&str>) -> String {
        extension_id.unwrap_or("<unknown>").to_string()
    }

    fn runtime_risk_push_ledger(
        guard: &mut ExtensionManagerInner,
        mut entry: RuntimeRiskLedgerEntry,
    ) -> RuntimeRiskLedgerEntry {
        let prev_hash = guard.runtime_risk_last_hash.clone();
        entry.prev_ledger_hash.clone_from(&prev_hash);
        entry.ledger_hash = runtime_risk_compute_ledger_hash(&entry, prev_hash.as_deref());

        guard.runtime_risk_last_hash = Some(entry.ledger_hash.clone());
        guard.runtime_risk_ledger.push_back(entry.clone());
        while guard.runtime_risk_ledger.len() > guard.runtime_risk_config.ledger_limit {
            let _ = guard.runtime_risk_ledger.pop_front();
        }
        entry
    }

    fn runtime_risk_push_telemetry(
        guard: &mut ExtensionManagerInner,
        entry: RuntimeHostcallTelemetryEvent,
    ) {
        guard.runtime_hostcall_telemetry.push_back(entry);
        while guard.runtime_hostcall_telemetry.len() > guard.runtime_risk_config.ledger_limit {
            let _ = guard.runtime_hostcall_telemetry.pop_front();
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn set_runtime_risk_config(&self, config: RuntimeRiskConfig) {
        let mut guard = self.inner.lock().unwrap();
        let clamped = RuntimeRiskConfig {
            enabled: config.enabled,
            alpha: config.alpha.clamp(1.0e-6, 0.5),
            window_size: config.window_size.clamp(8, 4096),
            ledger_limit: config.ledger_limit.clamp(32, 20_000),
            decision_timeout_ms: config.decision_timeout_ms.clamp(1, 2_000),
            fail_closed: config.fail_closed,
        };
        guard.runtime_risk_config = clamped;
    }

    pub fn runtime_risk_config(&self) -> RuntimeRiskConfig {
        self.inner.lock().unwrap().runtime_risk_config.clone()
    }

    // ── SEC-4.1: Per-extension resource quota check ──────────────────────

    /// Check per-extension resource quotas before dispatching a hostcall.
    /// Returns [`QuotaCheckResult::Exceeded`] if any configured limit is breached.
    ///
    /// Quota config resolution: per-extension override (from policy) > global default.
    fn check_quota(
        &self,
        extension_id: Option<&str>,
        capability: &str,
        now_ms: i64,
        policy: &ExtensionPolicy,
    ) -> QuotaCheckResult {
        let Some(ext_id) = extension_id else {
            return QuotaCheckResult::Allowed;
        };
        let Ok(mut guard) = self.inner.lock() else {
            return QuotaCheckResult::Allowed;
        };

        // Resolve quota config: per-extension override > global default.
        let quota_config = policy
            .per_extension
            .get(ext_id)
            .and_then(|ovr| ovr.quota.as_ref())
            .cloned()
            .unwrap_or_else(|| guard.quota_config.clone());

        let state = guard.quota_states.entry(ext_id.to_string()).or_default();

        let result = check_extension_quota(&quota_config, state, now_ms, capability);

        // Record breach telemetry if quota was exceeded.
        if let QuotaCheckResult::Exceeded { ref reason } = result {
            guard.quota_breach_events.push_back(QuotaBreachEvent {
                ts_ms: now_ms,
                extension_id: ext_id.to_string(),
                capability: capability.to_string(),
                reason: reason.clone(),
                quota_config_source: if policy
                    .per_extension
                    .get(ext_id)
                    .and_then(|ovr| ovr.quota.as_ref())
                    .is_some()
                {
                    "per_extension"
                } else {
                    "global"
                }
                .to_string(),
            });
        }

        result
    }

    /// Record subprocess spawn (increments active subprocess counter).
    pub fn record_subprocess_spawn(&self, extension_id: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            let state = guard
                .quota_states
                .entry(extension_id.to_string())
                .or_default();
            state.active_subprocesses += 1;
        }
    }

    /// Record subprocess exit (decrements active subprocess counter).
    pub fn record_subprocess_exit(&self, extension_id: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            let state = guard
                .quota_states
                .entry(extension_id.to_string())
                .or_default();
            state.active_subprocesses = state.active_subprocesses.saturating_sub(1);
        }
    }

    /// Record bytes written by an extension (for write quota tracking).
    pub fn record_write_bytes(&self, extension_id: &str, bytes: u64) {
        if let Ok(mut guard) = self.inner.lock() {
            let state = guard
                .quota_states
                .entry(extension_id.to_string())
                .or_default();
            state.write_bytes_total = state.write_bytes_total.saturating_add(bytes);
        }
    }

    /// Get the current quota state for an extension (for telemetry/inspection).
    pub fn quota_state(&self, extension_id: &str) -> Option<(u64, u32, u64, u64)> {
        let guard = self.inner.lock().ok()?;
        guard.quota_states.get(extension_id).map(|s| {
            (
                s.hostcalls_total,
                s.active_subprocesses,
                s.write_bytes_total,
                s.http_requests_total,
            )
        })
    }

    /// Update the global quota configuration.
    pub fn set_quota_config(&self, config: ExtensionQuotaConfig) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.quota_config = config;
        }
    }

    /// Drain and return all quota breach telemetry events.
    pub fn drain_quota_breach_events(&self) -> Vec<QuotaBreachEvent> {
        self.inner.lock().ok().map_or_else(Vec::new, |mut guard| {
            guard.quota_breach_events.drain(..).collect()
        })
    }

    /// Get the count of recorded quota breach events (for inspection).
    pub fn quota_breach_count(&self) -> usize {
        self.inner
            .lock()
            .ok()
            .map_or(0, |guard| guard.quota_breach_events.len())
    }

    /// Reset quota counters for a specific extension (e.g. on extension reload).
    /// The sliding window timestamps and monotonic counters are cleared.
    pub fn reset_quota_state(&self, extension_id: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.quota_states.remove(extension_id);
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::significant_drop_tightening,
        clippy::cast_precision_loss,
        clippy::suboptimal_flops
    )]
    fn evaluate_runtime_risk(
        &self,
        extension_id: Option<&str>,
        _call_id: &str,
        capability: &str,
        method: &str,
        params_hash: &str,
        meta: RuntimeRiskCallMetadata<'_>,
        policy_reason: &str,
    ) -> Option<RuntimeRiskDecision> {
        let started = Instant::now();
        let mut guard = self.inner.lock().unwrap();
        let config = guard.runtime_risk_config.clone();
        if !config.enabled {
            return None;
        }

        let ext_key = Self::runtime_risk_extension_key(extension_id);
        let state = guard.runtime_risk_states.entry(ext_key).or_default();

        let now_ms = runtime_risk_now_ms();
        let sequence_context = runtime_hostcall_sequence_context(state, now_ms);
        let base = runtime_risk_base_score(capability, method, policy_reason);
        let recent_mean = if state.recent_scores.is_empty() {
            0.0
        } else {
            state.recent_scores.iter().sum::<f64>() / state.recent_scores.len() as f64
        };

        let feature_started = Instant::now();
        let features = runtime_hostcall_extract_features(
            base,
            recent_mean,
            &sequence_context,
            capability,
            policy_reason,
            meta.timeout_ms,
        );
        let feature_extraction_latency_us =
            u64::try_from(feature_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let feature_budget_exceeded =
            feature_extraction_latency_us > RUNTIME_HOSTCALL_FEATURE_BUDGET_US;

        if state.quarantined {
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let mut triggers = vec!["quarantined".to_string()];
            if feature_budget_exceeded {
                triggers.push("feature_budget_exceeded".to_string());
            }
            let posterior = RuntimeRiskPosterior {
                safe_fast: 0.0,
                suspicious: 0.0,
                unsafe_: 1.0,
            };
            let expected_loss = RuntimeRiskExpectedLoss {
                allow: 120.0,
                harden: 35.0,
                deny: 2.0,
                terminate: 1.0,
            };
            let (explanation_level, explanation_summary, top_contributors, budget_state) =
                runtime_risk_build_explanation(
                    RuntimeRiskAction::Terminate,
                    1.0,
                    &posterior,
                    &expected_loss,
                    &features,
                    &triggers,
                    None,
                    RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
                    RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
                );
            return Some(RuntimeRiskDecision {
                action: RuntimeRiskAction::Terminate,
                reason: "quarantined".to_string(),
                capability: capability.to_string(),
                method: method.to_string(),
                params_hash: params_hash.to_string(),
                args_shape_hash: meta.args_shape_hash.to_string(),
                resource_target_class: meta.resource_target_class.to_string(),
                policy_profile: meta.policy_profile.to_string(),
                timeout_ms: meta.timeout_ms,
                risk_score: 1.0,
                posterior,
                expected_loss,
                e_process: f64::INFINITY,
                e_threshold: 1.0 / config.alpha,
                conformal_residual: 1.0,
                conformal_quantile: state.previous_residual_quantile,
                drift_detected: true,
                triggers,
                explanation_schema: RUNTIME_RISK_EXPLANATION_SCHEMA_VERSION.to_string(),
                explanation_level,
                explanation_summary,
                top_contributors,
                budget_state,
                fallback_reason: None,
                elapsed_ms,
                state_label: RuntimeRiskStateLabel::Unsafe,
                sequence_context,
                features,
                feature_extraction_latency_us,
                feature_budget_exceeded,
            });
        }

        let mut risk_score = runtime_risk_clamp01((0.65 * base) + (0.35 * recent_mean));
        risk_score = runtime_risk_clamp01(
            risk_score
                + (0.12 * features.recent_error_rate)
                + (0.08 * features.burst_density_1s)
                + (0.05 * features.prior_failure_streak_norm),
        );
        if runtime_risk_is_dangerous(capability)
            && matches!(state.last_decision, Some(RuntimeRiskAction::Harden))
        {
            risk_score = runtime_risk_clamp01(risk_score + 0.10);
        }

        state.recent_scores.push_back(risk_score);
        while state.recent_scores.len() > config.window_size {
            let _ = state.recent_scores.pop_front();
        }

        // Soft Bayesian evidence update.
        let safe_evidence = (1.0 - risk_score).max(0.05);
        let suspicious_evidence = (risk_score * 0.9).max(0.01);
        let unsafe_evidence = if runtime_risk_is_dangerous(capability) {
            (risk_score * 0.8).max(0.01)
        } else {
            (risk_score * 0.35).max(0.01)
        };

        state.alpha_safe += safe_evidence;
        state.alpha_suspicious += suspicious_evidence;
        state.alpha_unsafe += unsafe_evidence;

        let denom = state.alpha_safe + state.alpha_suspicious + state.alpha_unsafe;
        let posterior = RuntimeRiskPosterior {
            safe_fast: runtime_risk_clamp01(state.alpha_safe / denom),
            suspicious: runtime_risk_clamp01(state.alpha_suspicious / denom),
            unsafe_: runtime_risk_clamp01(state.alpha_unsafe / denom),
        };

        // Anytime-valid sequential evidence (likelihood-ratio style e-process).
        let x = if risk_score >= 0.65 { 1.0 } else { 0.0 };
        let p0: f64 = 0.10;
        let p1: f64 = 0.45;
        let log_lr = if x > 0.5 {
            f64::ln(p1 / p0)
        } else {
            f64::ln((1.0 - p1) / (1.0 - p0))
        };
        state.log_e_process = (state.log_e_process + log_lr).clamp(-120.0, 120.0);
        let e_process = state.log_e_process.exp();
        let e_threshold = 1.0 / config.alpha;
        let e_process_breach = e_process >= e_threshold;

        // BOCPD-lite drift: compare first/second half moving means.
        let mut drift_detected = false;
        if state.recent_scores.len() >= config.window_size / 2 {
            let len = state.recent_scores.len();
            let split = len / 2;
            if split > 0 {
                let first_mean = state.recent_scores.iter().take(split).sum::<f64>() / split as f64;
                let second_mean =
                    state.recent_scores.iter().skip(split).sum::<f64>() / (len - split) as f64;
                drift_detected = (second_mean - first_mean).abs() >= 0.22;
            }
        }

        let conformal_residual = (risk_score - recent_mean).abs();
        let conformal_quantile = if state.residual_window.is_empty() {
            state.previous_residual_quantile
        } else {
            runtime_risk_quantile(
                state.residual_window.iter().copied().collect(),
                1.0 - config.alpha,
            )
        };
        if conformal_quantile > 0.0 && conformal_residual > conformal_quantile * 1.5 {
            drift_detected = true;
        }

        let (mut action, expected_loss, mut triggers, state_label) =
            runtime_risk_choose_action(&posterior, e_process_breach, drift_detected);

        if state.consecutive_unsafe >= 3 && posterior.unsafe_ >= 0.45 {
            action = RuntimeRiskAction::Terminate;
            triggers.push("unsafe_streak".to_string());
        }
        if feature_budget_exceeded {
            triggers.push("feature_budget_exceeded".to_string());
        }

        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut fallback_reason = None;
        if elapsed_ms > config.decision_timeout_ms {
            fallback_reason = Some("decision_timeout".to_string());
            action = if config.fail_closed {
                RuntimeRiskAction::Harden
            } else {
                RuntimeRiskAction::Allow
            };
            triggers.push("decision_timeout".to_string());
        }

        let (explanation_level, explanation_summary, top_contributors, budget_state) =
            runtime_risk_build_explanation(
                action,
                risk_score,
                &posterior,
                &expected_loss,
                &features,
                &triggers,
                fallback_reason.as_deref(),
                RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
                RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
            );

        state.last_decision = Some(action);

        Some(RuntimeRiskDecision {
            action,
            reason: "runtime_risk".to_string(),
            capability: capability.to_string(),
            method: method.to_string(),
            params_hash: params_hash.to_string(),
            args_shape_hash: meta.args_shape_hash.to_string(),
            resource_target_class: meta.resource_target_class.to_string(),
            policy_profile: meta.policy_profile.to_string(),
            timeout_ms: meta.timeout_ms,
            risk_score,
            posterior,
            expected_loss,
            e_process,
            e_threshold,
            conformal_residual,
            conformal_quantile,
            drift_detected,
            triggers,
            explanation_schema: RUNTIME_RISK_EXPLANATION_SCHEMA_VERSION.to_string(),
            explanation_level,
            explanation_summary,
            top_contributors,
            budget_state,
            fallback_reason,
            elapsed_ms,
            state_label,
            sequence_context,
            features,
            feature_extraction_latency_us,
            feature_budget_exceeded,
        })
    }

    #[allow(clippy::too_many_lines, clippy::significant_drop_tightening)]
    fn record_runtime_risk_outcome(
        &self,
        extension_id: Option<&str>,
        call_id: &str,
        policy_reason: &str,
        decision: &RuntimeRiskDecision,
        outcome_error_code: Option<&str>,
        duration_ms: u64,
    ) {
        let mut guard = self.inner.lock().unwrap();
        if !guard.runtime_risk_config.enabled {
            return;
        }
        let window_size = guard.runtime_risk_config.window_size;
        let alpha = guard.runtime_risk_config.alpha;

        let ext_key = Self::runtime_risk_extension_key(extension_id);
        let (telemetry, entry) = {
            let Some(state) = guard.runtime_risk_states.get_mut(&ext_key) else {
                return;
            };

            let realized_risk = if outcome_error_code.is_some() {
                1.0
            } else {
                0.0
            };
            let predicted =
                runtime_risk_clamp01(decision.posterior.suspicious + decision.posterior.unsafe_);
            let residual = (predicted - realized_risk).abs();

            state.residual_window.push_back(residual);
            while state.residual_window.len() > window_size {
                let _ = state.residual_window.pop_front();
            }
            state.previous_residual_quantile =
                runtime_risk_quantile(state.residual_window.iter().copied().collect(), 1.0 - alpha);

            let denied_dangerous = outcome_error_code.is_some_and(|code| code == "denied")
                && runtime_risk_is_dangerous(&decision.capability);
            if decision.posterior.unsafe_ >= 0.55
                || matches!(decision.action, RuntimeRiskAction::Terminate)
                || denied_dangerous
            {
                state.consecutive_unsafe = state.consecutive_unsafe.saturating_add(1);
            } else {
                state.consecutive_unsafe = 0;
            }
            if state.consecutive_unsafe >= 3 {
                state.quarantined = true;
            }

            // Outcome-conditioned Bayesian reinforcement.
            if let Some(code) = outcome_error_code {
                if code == "denied" || code == "timeout" || code == "io" {
                    state.alpha_unsafe += 0.9;
                    state.alpha_suspicious += 0.4;
                } else {
                    state.alpha_suspicious += 0.35;
                }
            } else {
                state.alpha_safe += 0.6;
            }

            let ts_ms = runtime_risk_now_ms();
            let is_error = outcome_error_code.is_some();
            let sequence_window = window_size.max(RUNTIME_HOSTCALL_SEQUENCE_WINDOW);
            state.sequence_counter = state.sequence_counter.saturating_add(1);
            state.recent_call_timestamps_ms.push_back(ts_ms);
            while state.recent_call_timestamps_ms.len() > sequence_window {
                let _ = state.recent_call_timestamps_ms.pop_front();
            }
            state.recent_outcome_errors.push_back(is_error);
            while state.recent_outcome_errors.len() > sequence_window {
                let _ = state.recent_outcome_errors.pop_front();
            }
            state.consecutive_failures = if is_error {
                state.consecutive_failures.saturating_add(1)
            } else {
                0
            };
            state.last_capability = Some(decision.capability.clone());
            state.last_method = Some(decision.method.clone());
            state.last_resource_target_class = Some(decision.resource_target_class.clone());

            let telemetry = RuntimeHostcallTelemetryEvent {
                schema: RUNTIME_HOSTCALL_TELEMETRY_SCHEMA_VERSION.to_string(),
                ts_ms,
                extension_id: ext_key.clone(),
                call_id: call_id.to_string(),
                capability: decision.capability.clone(),
                method: decision.method.clone(),
                params_hash: decision.params_hash.clone(),
                args_shape_hash: decision.args_shape_hash.clone(),
                resource_target_class: decision.resource_target_class.clone(),
                policy_reason: policy_reason.to_string(),
                policy_profile: decision.policy_profile.clone(),
                risk_score: decision.risk_score,
                timeout_ms: decision.timeout_ms,
                latency_ms: duration_ms,
                outcome: if is_error {
                    "error".to_string()
                } else {
                    "success".to_string()
                },
                outcome_error_code: outcome_error_code.map(ToString::to_string),
                selected_action: RuntimeRiskActionValue::from(decision.action),
                reason_codes: decision.triggers.clone(),
                explanation_level: decision.explanation_level,
                explanation_summary: decision.explanation_summary.clone(),
                top_contributors: decision.top_contributors.clone(),
                budget_state: decision.budget_state.clone(),
                sequence: decision.sequence_context.clone(),
                features: decision.features.clone(),
                extraction_latency_us: decision.feature_extraction_latency_us,
                extraction_budget_us: RUNTIME_HOSTCALL_FEATURE_BUDGET_US,
                extraction_budget_exceeded: decision.feature_budget_exceeded,
                redaction_summary: "params redacted via hash-only telemetry".to_string(),
            };

            let entry = RuntimeRiskLedgerEntry {
                ts_ms,
                extension_id: ext_key.clone(),
                call_id: call_id.to_string(),
                capability: decision.capability.clone(),
                method: decision.method.clone(),
                params_hash: decision.params_hash.clone(),
                policy_reason: policy_reason.to_string(),
                risk_score: decision.risk_score,
                posterior: decision.posterior.clone(),
                expected_loss: decision.expected_loss.clone(),
                selected_action: decision.action,
                derived_state: decision.state_label,
                triggers: decision.triggers.clone(),
                fallback_reason: decision.fallback_reason.clone(),
                e_process: decision.e_process,
                e_threshold: decision.e_threshold,
                conformal_residual: residual,
                conformal_quantile: state.previous_residual_quantile,
                drift_detected: decision.drift_detected,
                outcome_error_code: outcome_error_code.map(ToString::to_string),
                explanation_schema: decision.explanation_schema.clone(),
                explanation_level: decision.explanation_level,
                explanation_summary: decision.explanation_summary.clone(),
                top_contributors: decision.top_contributors.clone(),
                budget_state: decision.budget_state.clone(),
                ledger_hash: String::new(),
                prev_ledger_hash: None,
            };
            (telemetry, entry)
        };

        Self::runtime_risk_push_telemetry(&mut guard, telemetry);

        let entry = Self::runtime_risk_push_ledger(&mut guard, entry);
        let top_contributor_codes = entry
            .top_contributors
            .iter()
            .map(|contributor| contributor.code.clone())
            .collect::<Vec<_>>();

        if matches!(
            decision.action,
            RuntimeRiskAction::Deny | RuntimeRiskAction::Terminate | RuntimeRiskAction::Harden
        ) {
            tracing::warn!(
                event = "runtime_risk.decision",
                extension_id = %entry.extension_id,
                call_id = %entry.call_id,
                capability = %entry.capability,
                method = %entry.method,
                selected_action = ?entry.selected_action,
                state = ?entry.derived_state,
                risk_score = entry.risk_score,
                e_process = entry.e_process,
                e_threshold = entry.e_threshold,
                conformal_residual = entry.conformal_residual,
                conformal_quantile = entry.conformal_quantile,
                triggers = ?entry.triggers,
                fallback_reason = ?entry.fallback_reason,
                explanation_level = ?entry.explanation_level,
                explanation_budget_exhausted = entry.budget_state.exhausted,
                explanation_terms = entry.budget_state.terms_emitted,
                top_contributors = ?top_contributor_codes,
                outcome_error_code = ?entry.outcome_error_code,
                ledger_hash = %entry.ledger_hash,
                "Runtime risk controller applied defensive action"
            );
        } else {
            tracing::info!(
                event = "runtime_risk.decision",
                extension_id = %entry.extension_id,
                call_id = %entry.call_id,
                capability = %entry.capability,
                method = %entry.method,
                selected_action = ?entry.selected_action,
                state = ?entry.derived_state,
                risk_score = entry.risk_score,
                e_process = entry.e_process,
                e_threshold = entry.e_threshold,
                conformal_residual = entry.conformal_residual,
                conformal_quantile = entry.conformal_quantile,
                triggers = ?entry.triggers,
                explanation_level = ?entry.explanation_level,
                explanation_budget_exhausted = entry.budget_state.exhausted,
                explanation_terms = entry.budget_state.terms_emitted,
                top_contributors = ?top_contributor_codes,
                ledger_hash = %entry.ledger_hash,
                "Runtime risk controller allowed hostcall"
            );
        }
    }

    pub fn runtime_risk_ledger_artifact(&self) -> RuntimeRiskLedgerArtifact {
        let entries = {
            let guard = self.inner.lock().unwrap();
            guard
                .runtime_risk_ledger
                .iter()
                .map(RuntimeRiskLedgerArtifactEntry::from)
                .collect::<Vec<_>>()
        };
        let head_ledger_hash = entries.first().map(|entry| entry.ledger_hash.clone());
        let tail_ledger_hash = entries.last().map(|entry| entry.ledger_hash.clone());
        let data_hash = runtime_risk_ledger_data_hash(&entries);
        RuntimeRiskLedgerArtifact {
            schema: RUNTIME_RISK_LEDGER_SCHEMA_VERSION.to_string(),
            generated_at_ms: runtime_risk_now_ms(),
            entry_count: entries.len(),
            head_ledger_hash,
            tail_ledger_hash,
            data_hash,
            entries,
        }
    }

    pub fn runtime_hostcall_telemetry_artifact(&self) -> RuntimeHostcallTelemetryArtifact {
        let entries = {
            let guard = self.inner.lock().unwrap();
            guard
                .runtime_hostcall_telemetry
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        RuntimeHostcallTelemetryArtifact {
            schema: RUNTIME_HOSTCALL_TELEMETRY_SCHEMA_VERSION.to_string(),
            generated_at_ms: runtime_risk_now_ms(),
            entry_count: entries.len(),
            entries,
        }
    }

    pub fn runtime_risk_verify_ledger(&self) -> RuntimeRiskLedgerVerificationReport {
        let artifact = self.runtime_risk_ledger_artifact();
        verify_runtime_risk_ledger_artifact(&artifact)
    }

    pub fn runtime_risk_replay_ledger(&self) -> Result<RuntimeRiskReplayArtifact> {
        let artifact = self.runtime_risk_ledger_artifact();
        replay_runtime_risk_ledger_artifact(&artifact)
    }

    pub fn runtime_risk_calibrate_ledger(
        &self,
        config: &RuntimeRiskCalibrationConfig,
    ) -> Result<RuntimeRiskCalibrationReport> {
        let artifact = self.runtime_risk_ledger_artifact();
        calibrate_runtime_risk_from_ledger(&artifact, config)
    }

    /// Build a baseline model for the given extension from the current ledger.
    pub fn build_baseline(&self, extension_id: &str) -> Result<RuntimeRiskBaselineModel> {
        let artifact = self.runtime_risk_ledger_artifact();
        build_baseline_from_ledger(&artifact, extension_id)
    }

    #[cfg(test)]
    fn runtime_risk_ledger_snapshot(&self) -> Vec<RuntimeRiskLedgerEntry> {
        self.inner
            .lock()
            .unwrap()
            .runtime_risk_ledger
            .iter()
            .cloned()
            .collect()
    }

    #[cfg(test)]
    fn runtime_hostcall_telemetry_snapshot(&self) -> Vec<RuntimeHostcallTelemetryEvent> {
        self.inner
            .lock()
            .unwrap()
            .runtime_hostcall_telemetry
            .iter()
            .cloned()
            .collect()
    }

    /// Shut down the extension runtime with a cleanup budget.
    ///
    /// Sends a graceful shutdown to the JS runtime thread and waits up to
    /// `budget` for it to exit.  Returns `true` if the runtime exited
    /// cleanly within the budget.
    pub async fn shutdown(&self, budget: Duration) -> bool {
        let js_runtime = {
            let guard = self.inner.lock().unwrap();
            guard.js_runtime.clone()
        };

        if let Some(runtime) = js_runtime {
            let ok = runtime.shutdown(budget).await;
            // Clear the runtime handle so subsequent calls are no-ops.
            let mut guard = self.inner.lock().unwrap();
            guard.js_runtime = None;
            ok
        } else {
            true
        }
    }

    pub fn set_ui_sender(&self, sender: mpsc::Sender<ExtensionUiRequest>) {
        let mut guard = self.inner.lock().unwrap();
        guard.ui_sender = Some(sender);
    }

    pub fn clear_ui_sender(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.ui_sender = None;
    }

    pub fn set_js_runtime(&self, runtime: JsExtensionRuntimeHandle) {
        let mut guard = self.inner.lock().unwrap();
        guard.js_runtime = Some(runtime);
    }

    pub fn set_cwd(&self, cwd: String) {
        let mut guard = self.inner.lock().unwrap();
        guard.cwd = Some(cwd);
    }

    pub fn set_model_registry_values(&self, values: HashMap<String, String>) {
        let mut guard = self.inner.lock().unwrap();
        guard.model_registry_values = values;
    }

    #[cfg(feature = "wasm-host")]
    fn handle(&self) -> ExtensionManagerHandle {
        ExtensionManagerHandle::new(self)
    }

    pub fn set_host_actions(&self, actions: Arc<dyn ExtensionHostActions>) {
        let mut guard = self.inner.lock().unwrap();
        guard.host_actions = Some(actions);
    }

    pub fn js_runtime(&self) -> Option<JsExtensionRuntimeHandle> {
        let guard = self.inner.lock().unwrap();
        guard.js_runtime.clone()
    }

    fn host_actions(&self) -> Option<Arc<dyn ExtensionHostActions>> {
        let guard = self.inner.lock().unwrap();
        guard.host_actions.clone()
    }

    #[allow(clippy::significant_drop_tightening)]
    pub fn cached_policy_prompt_decision(
        &self,
        extension_id: &str,
        capability: &str,
    ) -> Option<bool> {
        let (decision, extension_version) = {
            let guard = self.inner.lock().unwrap();
            let decision = guard
                .policy_prompt_cache
                .get(extension_id)
                .and_then(|by_cap| by_cap.get(capability))
                .cloned();
            let extension_version = guard
                .extensions
                .iter()
                .find(|e| e.name == extension_id)
                .map(|e| e.version.clone());
            drop(guard);
            (decision, extension_version)
        };
        let dec = decision?;

        if let Some(range) = &dec.version_range {
            if let Some(version) = extension_version {
                if !check_version_constraint(&version, range) {
                    return None;
                }
            } else {
                return None;
            }
        }

        Some(dec.allow)
    }

    pub fn cache_policy_prompt_decision(&self, extension_id: &str, capability: &str, allow: bool) {
        let mut guard = self.inner.lock().unwrap();

        let version_range = guard
            .extensions
            .iter()
            .find(|e| e.name == extension_id)
            .map(|e| format!("^{}", e.version));

        let decision = PersistedDecision {
            capability: capability.to_string(),
            allow,
            decided_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            expires_at: None,
            version_range: version_range.clone(),
        };

        guard
            .policy_prompt_cache
            .entry(extension_id.to_string())
            .or_default()
            .insert(capability.to_string(), decision);

        // Persist to disk so the decision survives across sessions.
        if let Some(ref mut store) = guard.permission_store {
            let res = if let Some(range) = version_range {
                store.record_with_version(extension_id, capability, allow, &range)
            } else {
                store.record(extension_id, capability, allow)
            };
            if let Err(e) = res {
                tracing::warn!("Failed to persist permission decision: {e}");
            }
        }
    }

    /// Revoke all persisted permission decisions for an extension.
    pub fn revoke_extension_permissions(&self, extension_id: &str) {
        let mut guard = self.inner.lock().unwrap();
        guard.policy_prompt_cache.remove(extension_id);
        if let Some(ref mut store) = guard.permission_store {
            if let Err(e) = store.revoke_extension(extension_id) {
                tracing::warn!("Failed to revoke extension permissions: {e}");
            }
        }
    }

    /// Reset all persisted permission decisions.
    pub fn reset_all_permissions(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.policy_prompt_cache.clear();
        if let Some(ref mut store) = guard.permission_store {
            if let Err(e) = store.reset() {
                tracing::warn!("Failed to reset all permissions: {e}");
            }
        }
    }

    /// List all persisted permission decisions.
    pub fn list_permissions(&self) -> HashMap<String, HashMap<String, PersistedDecision>> {
        let guard = self.inner.lock().unwrap();
        guard.policy_prompt_cache.clone()
    }

    pub fn active_tools(&self) -> Option<Vec<String>> {
        let guard = self.inner.lock().unwrap();
        guard.active_tools.clone()
    }

    pub async fn load_js_extensions(&self, specs: Vec<JsExtensionLoadSpec>) -> Result<()> {
        let runtime = self
            .js_runtime()
            .ok_or_else(|| Error::extension("JS extension runtime not configured"))?;

        let snapshots = runtime.load_extensions_snapshots(specs).await?;

        let mut payloads = Vec::new();
        let mut active_tools: Option<Vec<String>> = None;
        let mut all_providers = Vec::new();
        let mut all_flags = Vec::new();
        for snapshot in snapshots {
            let JsExtensionSnapshot {
                id,
                name,
                version,
                api_version,
                tools,
                slash_commands,
                providers,
                shortcuts,
                flags,
                event_hooks,
                active_tools: ext_active_tools,
            } = snapshot;
            all_providers.extend(providers);
            all_flags.extend(flags.clone());
            if let Some(list) = ext_active_tools {
                active_tools = Some(list);
            }
            payloads.push(RegisterPayload {
                name: if name.is_empty() { id } else { name },
                version,
                api_version: if api_version.is_empty() {
                    PROTOCOL_VERSION.to_string()
                } else {
                    api_version
                },
                capabilities: Vec::new(),
                capability_manifest: None,
                tools,
                slash_commands,
                shortcuts,
                flags,
                event_hooks,
            });
        }

        {
            let mut guard = self.inner.lock().unwrap();
            guard.extensions = payloads;
            guard.active_tools = active_tools;
            guard.providers = all_providers;
            guard.flags = all_flags;
            let active_extension_ids = guard
                .extensions
                .iter()
                .map(|ext| ext.name.clone())
                .collect::<std::collections::HashSet<_>>();
            guard
                .runtime_risk_states
                .retain(|ext_id, _| active_extension_ids.contains(ext_id));
        }
        Ok(())
    }

    #[cfg(feature = "wasm-host")]
    pub async fn load_wasm_extensions(
        &self,
        host: &WasmExtensionHost,
        specs: Vec<WasmExtensionLoadSpec>,
        tools: Arc<ToolRegistry>,
    ) -> Result<()> {
        let mut wasm_handles = Vec::new();
        let mut registrations = Vec::new();

        for spec in specs {
            let extension = host.load_from_path(&spec.entry_path)?;
            let mut instance = host
                .instantiate_with(&extension, Arc::clone(&tools), Some(self.handle()))
                .await?;

            let registration_json = instance.init(&spec.manifest_json).await?;
            let mut registration: RegisterPayload = serde_json::from_str(&registration_json)
                .map_err(|err| {
                    Error::extension(format!(
                        "WASM init returned invalid registration payload: {err}"
                    ))
                })?;
            if registration.capability_manifest.is_none() {
                registration
                    .capability_manifest
                    .clone_from(&spec.manifest.capability_manifest);
            }
            validate_register(&registration)?;

            wasm_handles.push(WasmExtensionHandle::new(instance, registration.clone()));
            registrations.push(registration);
        }

        {
            let mut guard = self.inner.lock().unwrap();
            guard.extensions.extend(registrations);
            guard.wasm_extensions.extend(wasm_handles);
        }
        Ok(())
    }

    #[cfg(feature = "wasm-host")]
    pub fn wasm_extensions(&self) -> Vec<WasmExtensionHandle> {
        let guard = self.inner.lock().unwrap();
        guard.wasm_extensions.clone()
    }

    pub fn set_session(&self, session: Arc<dyn ExtensionSession>) {
        let mut guard = self.inner.lock().unwrap();
        guard.session = Some(session);
    }

    pub fn session_handle(&self) -> Option<Arc<dyn ExtensionSession>> {
        let guard = self.inner.lock().unwrap();
        guard.session.clone()
    }

    pub fn set_active_tools(&self, tools: Vec<String>) {
        let mut guard = self.inner.lock().unwrap();
        guard.active_tools = Some(tools);
    }

    pub fn current_model(&self) -> (Option<String>, Option<String>) {
        let guard = self.inner.lock().unwrap();
        (
            guard.current_provider.clone(),
            guard.current_model_id.clone(),
        )
    }

    pub fn set_current_model(&self, provider: Option<String>, model_id: Option<String>) {
        let mut guard = self.inner.lock().unwrap();
        guard.current_provider = provider;
        guard.current_model_id = model_id;
    }

    pub fn current_thinking_level(&self) -> Option<String> {
        let guard = self.inner.lock().unwrap();
        guard.current_thinking_level.clone()
    }

    pub fn set_current_thinking_level(&self, level: Option<String>) {
        let mut guard = self.inner.lock().unwrap();
        guard.current_thinking_level = level;
    }

    /// Collect tool definitions from all registered extensions.
    pub fn extension_tool_defs(&self) -> Vec<Value> {
        let guard = self.inner.lock().unwrap();
        guard
            .extensions
            .iter()
            .flat_map(|ext| ext.tools.iter().cloned())
            .collect()
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

    /// Dynamically register a slash command at runtime (from a hostcall).
    pub fn register_command(&self, name: &str, description: Option<&str>) {
        let mut guard = self.inner.lock().unwrap();
        let entry = json!({
            "name": name,
            "description": description,
        });
        if let Some(ext) = guard.extensions.first_mut() {
            ext.slash_commands.push(entry);
        } else {
            guard.extensions.push(RegisterPayload {
                name: "__dynamic__".to_string(),
                version: "1.0.0".to_string(),
                api_version: PROTOCOL_VERSION.to_string(),
                capabilities: Vec::new(),
                capability_manifest: None,
                tools: Vec::new(),
                slash_commands: vec![entry],
                shortcuts: Vec::new(),
                flags: Vec::new(),
                event_hooks: Vec::new(),
            });
        }
    }

    /// Dynamically register a provider at runtime (from a hostcall).
    pub fn register_provider(&self, payload: Value) {
        let mut guard = self.inner.lock().unwrap();
        guard.providers.push(payload);
    }

    /// Dynamically register a flag at runtime (from a hostcall).
    pub fn register_flag(&self, spec: Value) {
        let mut guard = self.inner.lock().unwrap();
        let name = spec.get("name").and_then(Value::as_str).unwrap_or_default();
        // Deduplicate: replace existing flag with the same name.
        guard
            .flags
            .retain(|f| f.get("name").and_then(Value::as_str).unwrap_or_default() != name);
        guard.flags.push(spec);
    }

    /// Execute an extension slash command via the JS runtime.
    pub async fn execute_command(
        &self,
        command_name: &str,
        args: &str,
        timeout_ms: u64,
    ) -> Result<Value> {
        let timeout_ms = self.effective_timeout(timeout_ms);
        let runtime = self
            .js_runtime()
            .ok_or_else(|| Error::extension("JS extension runtime not configured"))?;
        runtime
            .execute_command(
                command_name.to_string(),
                args.to_string(),
                json!({}),
                timeout_ms,
            )
            .await
    }

    /// Return extension-registered providers as raw JSON specs.
    pub fn extension_providers(&self) -> Vec<Value> {
        let guard = self.inner.lock().unwrap();
        guard.providers.clone()
    }

    /// Return true if an extension provider is backed by a JS `streamSimple` handler.
    pub fn provider_has_stream_simple(&self, provider_id: &str) -> bool {
        let needle = provider_id.trim();
        if needle.is_empty() {
            return false;
        }

        let guard = self.inner.lock().unwrap();
        guard.providers.iter().any(|provider_spec| {
            provider_spec
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id == needle)
                && provider_spec
                    .get("hasStreamSimple")
                    .and_then(Value::as_bool)
                    .or_else(|| provider_spec.get("streamSimple").and_then(Value::as_bool))
                    .unwrap_or(false)
        })
    }

    /// Convert extension-registered providers into model entries suitable for
    /// merging into the `ModelRegistry`.
    #[allow(clippy::too_many_lines)]
    pub fn extension_model_entries(&self) -> Vec<crate::models::ModelEntry> {
        use crate::provider::{InputType, Model, ModelCost};
        use std::collections::HashMap;

        let guard = self.inner.lock().unwrap();
        let mut entries = Vec::new();

        for provider_spec in &guard.providers {
            let provider_id = provider_spec
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if provider_id.is_empty() {
                continue;
            }
            let base_url = provider_spec
                .get("baseUrl")
                .or_else(|| provider_spec.get("base_url"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let api_key_ref = provider_spec
                .get("apiKey")
                .or_else(|| provider_spec.get("api_key"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let api = provider_spec
                .get("api")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();

            // Resolve API key (supports env var names).
            let resolved_key = if api_key_ref.is_empty() {
                None
            } else {
                std::env::var(api_key_ref)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .or_else(|| Some(api_key_ref.to_string()))
            };

            // Extract OAuth config if present.
            let oauth_config = provider_spec
                .get("oauth")
                .and_then(Value::as_object)
                .and_then(|oauth| {
                    let auth_url = oauth.get("authUrl")?.as_str()?.to_string();
                    let token_url = oauth.get("tokenUrl")?.as_str()?.to_string();
                    let client_id = oauth.get("clientId")?.as_str()?.to_string();
                    let scopes = oauth
                        .get("scopes")
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(Value::as_str)
                                .map(ToString::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    let redirect_uri = oauth
                        .get("redirectUri")
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                    Some(crate::models::OAuthConfig {
                        auth_url,
                        token_url,
                        client_id,
                        scopes,
                        redirect_uri,
                    })
                });

            let models = provider_spec
                .get("models")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            for model_spec in &models {
                let model_id = model_spec
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if model_id.is_empty() {
                    continue;
                }
                let model_name = model_spec
                    .get("name")
                    .and_then(Value::as_str)
                    .map_or_else(|| model_id.clone(), ToString::to_string);
                let model_api = model_spec
                    .get("api")
                    .and_then(Value::as_str)
                    .map_or_else(|| api.clone(), ToString::to_string);
                let reasoning = model_spec
                    .get("reasoning")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                #[allow(clippy::cast_possible_truncation)]
                let context_window = model_spec
                    .get("contextWindow")
                    .or_else(|| model_spec.get("context_window"))
                    .and_then(Value::as_u64)
                    .unwrap_or(128_000) as u32;
                #[allow(clippy::cast_possible_truncation)]
                let max_tokens = model_spec
                    .get("maxTokens")
                    .or_else(|| model_spec.get("max_tokens"))
                    .and_then(Value::as_u64)
                    .unwrap_or(16_384) as u32;

                let input = model_spec
                    .get("input")
                    .and_then(Value::as_array)
                    .map_or_else(
                        || vec![InputType::Text],
                        |arr| {
                            arr.iter()
                                .filter_map(Value::as_str)
                                .filter_map(|s| match s {
                                    "text" => Some(InputType::Text),
                                    "image" => Some(InputType::Image),
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                        },
                    );

                entries.push(crate::models::ModelEntry {
                    model: Model {
                        id: model_id,
                        name: model_name,
                        api: model_api,
                        provider: provider_id.clone(),
                        base_url: base_url.clone(),
                        reasoning,
                        input,
                        cost: ModelCost {
                            input: 0.0,
                            output: 0.0,
                            cache_read: 0.0,
                            cache_write: 0.0,
                        },
                        context_window,
                        max_tokens,
                        headers: HashMap::new(),
                    },
                    api_key: resolved_key.clone(),
                    headers: HashMap::new(),
                    auth_header: true,
                    compat: None,
                    oauth_config: oauth_config.clone(),
                });
            }
        }
        drop(guard);
        entries
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

    pub fn has_shortcut(&self, key_id: &str) -> bool {
        let needle = key_id.to_lowercase();
        let guard = self.inner.lock().unwrap();
        guard
            .extensions
            .iter()
            .flat_map(|ext| ext.shortcuts.iter())
            .filter_map(|s| s.get("key_id").and_then(Value::as_str))
            .any(|id| id == needle)
    }

    pub fn list_shortcuts(&self) -> Vec<Value> {
        let guard = self.inner.lock().unwrap();
        let mut shortcuts = Vec::new();

        for ext in &guard.extensions {
            for shortcut in &ext.shortcuts {
                let key_id = shortcut
                    .get("key_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let description = shortcut.get("description").and_then(Value::as_str);
                shortcuts.push(json!({
                    "shortcut": key_id,  // Primary field matching TS oracle output
                    "key_id": key_id,
                    "key": shortcut.get("key"),
                    "description": description,
                    "source": "extension",
                }));
            }
        }

        drop(guard);
        shortcuts
    }

    pub fn list_flags(&self) -> Vec<Value> {
        let guard = self.inner.lock().unwrap();
        let mut flags = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Collect from dynamically registered flags first (higher priority).
        for flag in &guard.flags {
            let name = flag
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !name.is_empty() {
                seen.insert(name.clone());
                let description = flag
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let flag_type = flag.get("type").and_then(Value::as_str).unwrap_or("string");
                flags.push(json!({
                    "name": name,
                    "description": description,
                    "type": flag_type,
                    "default": flag.get("default").cloned(),
                    "source": "extension",
                }));
            }
        }

        // Collect from snapshot-loaded extension payloads (skip duplicates).
        for ext in &guard.extensions {
            for flag in &ext.flags {
                let name = flag
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if !name.is_empty() && seen.insert(name.clone()) {
                    let description = flag
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let flag_type = flag.get("type").and_then(Value::as_str).unwrap_or("string");
                    flags.push(json!({
                        "name": name,
                        "description": description,
                        "type": flag_type,
                        "default": flag.get("default").cloned(),
                        "source": "extension",
                    }));
                }
            }
        }

        drop(guard);
        flags
    }

    /// List all event hook names registered by all loaded extensions.
    pub fn list_event_hooks(&self) -> Vec<String> {
        let guard = self.inner.lock().unwrap();
        let mut hooks = Vec::new();
        for ext in &guard.extensions {
            for hook in &ext.event_hooks {
                if !hooks.contains(hook) {
                    hooks.push(hook.clone());
                }
            }
        }
        drop(guard);
        hooks
    }

    /// Execute an extension shortcut via the JS runtime.
    pub async fn execute_shortcut(
        &self,
        key_id: &str,
        ctx_payload: Value,
        timeout_ms: u64,
    ) -> Result<Value> {
        let timeout_ms = self.effective_timeout(timeout_ms);
        let runtime = self
            .js_runtime()
            .ok_or_else(|| Error::extension("JS extension runtime not configured"))?;
        runtime
            .execute_shortcut(key_id.to_string(), ctx_payload, timeout_ms)
            .await
    }

    /// Set a flag value in the JS runtime for a specific extension.
    pub async fn set_flag_value(
        &self,
        extension_id: &str,
        flag_name: &str,
        value: Value,
    ) -> Result<()> {
        let runtime = self
            .js_runtime()
            .ok_or_else(|| Error::extension("JS extension runtime not configured"))?;
        runtime
            .set_flag_value(extension_id.to_string(), flag_name.to_string(), value)
            .await
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

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_lines)]
    async fn dispatch_event_value(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
        timeout_ms: u64,
    ) -> Result<Option<Value>> {
        let started_at = Instant::now();
        let timeout_ms = self.effective_timeout(timeout_ms);
        let event_name = event.to_string();
        let (runtime, has_ui, session, cwd_override, model_registry_values, has_hook) = {
            let guard = self.inner.lock().unwrap();
            let has_hook = guard
                .extensions
                .iter()
                .any(|ext| ext.event_hooks.iter().any(|hook| hook == &event_name));
            (
                guard.js_runtime.clone(),
                guard.ui_sender.is_some(),
                guard.session.clone(),
                guard.cwd.clone(),
                guard.model_registry_values.clone(),
                has_hook,
            )
        };

        #[cfg(feature = "wasm-host")]
        let (wasm_extensions, has_hook_wasm) = {
            let guard = self.inner.lock().unwrap();
            let has_hook_wasm = guard
                .wasm_extensions
                .iter()
                .any(|ext| ext.event_hooks().iter().any(|hook| hook == &event_name));
            (guard.wasm_extensions.clone(), has_hook_wasm)
        };

        let has_any_hook = {
            #[cfg(feature = "wasm-host")]
            {
                has_hook || has_hook_wasm
            }
            #[cfg(not(feature = "wasm-host"))]
            {
                has_hook
            }
        };

        if !has_any_hook {
            return Ok(None);
        }

        tracing::info!(
            event = "ext.event.start",
            event_name = %event_name,
            timeout_ms,
            "Extension event dispatch start"
        );

        let mut ctx = serde_json::Map::new();
        ctx.insert("hasUI".to_string(), Value::Bool(has_ui));
        if let Some(cwd) = cwd_override.or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|p| p.display().to_string())
        }) {
            ctx.insert("cwd".to_string(), Value::String(cwd));
        }

        if !model_registry_values.is_empty() {
            let mut map = serde_json::Map::new();
            for (key, value) in model_registry_values {
                map.insert(key, Value::String(value));
            }
            ctx.insert("modelRegistry".to_string(), Value::Object(map));
        }

        if let Some(session) = session {
            let state = session.get_state().await;
            let entries = session.get_entries().await;
            let branch = session.get_branch().await;
            let leaf_entry = entries.last().cloned().unwrap_or(Value::Null);
            ctx.insert("sessionState".to_string(), state);
            ctx.insert("sessionEntries".to_string(), Value::Array(entries));
            ctx.insert("sessionBranch".to_string(), Value::Array(branch));
            ctx.insert("sessionLeafEntry".to_string(), leaf_entry);
        }

        let event_payload = match data {
            None => json!({ "type": event_name }),
            Some(Value::Object(mut map)) => {
                map.insert("type".to_string(), Value::String(event_name.clone()));
                Value::Object(map)
            }
            Some(other) => json!({ "type": event_name, "data": other }),
        };

        let ctx_payload = Value::Object(ctx);

        let mut response = None;
        if let Some(runtime) = runtime {
            if has_hook {
                let js_response = runtime
                    .dispatch_event(
                        event_name.clone(),
                        event_payload.clone(),
                        ctx_payload.clone(),
                        timeout_ms,
                    )
                    .await?;
                response = Some(js_response);
            }
        }

        #[cfg(feature = "wasm-host")]
        if has_hook_wasm {
            let mut wasm_payload = event_payload;
            if let Value::Object(map) = &mut wasm_payload {
                map.insert("ctx".to_string(), ctx_payload);
            }
            if let Some(value) = Self::dispatch_wasm_event_value(
                &wasm_extensions,
                &event_name,
                &wasm_payload,
                timeout_ms,
            )
            .await?
            {
                response = Some(value);
            }
        }

        let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        tracing::info!(
            event = "ext.event.end",
            event_name = %event_name,
            duration_ms,
            has_response = response.is_some(),
            "Extension event dispatch end"
        );

        Ok(response)
    }

    #[cfg(feature = "wasm-host")]
    async fn dispatch_wasm_event_value(
        extensions: &[WasmExtensionHandle],
        event_name: &str,
        event_payload: &Value,
        timeout_ms: u64,
    ) -> Result<Option<Value>> {
        let mut response = None;
        for ext in extensions {
            if !ext.event_hooks().iter().any(|hook| hook == event_name) {
                continue;
            }
            if let Some(value) = ext.handle_event_value(event_payload, timeout_ms).await? {
                response = Some(value);
            }
        }
        Ok(response)
    }

    /// Dispatch an event to all registered extensions.
    pub async fn dispatch_event(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
    ) -> Result<()> {
        let _ = self
            .dispatch_event_value(event, data, EXTENSION_EVENT_TIMEOUT_MS)
            .await?;
        Ok(())
    }

    /// Dispatch an event to all registered extensions and return the raw response (if any).
    pub async fn dispatch_event_with_response(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
        timeout_ms: u64,
    ) -> Result<Option<Value>> {
        self.dispatch_event_value(event, data, timeout_ms).await
    }

    /// Dispatch a cancellable event to all registered extensions.
    pub async fn dispatch_cancellable_event(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
        timeout_ms: u64,
    ) -> Result<bool> {
        let Some(response) = self.dispatch_event_value(event, data, timeout_ms).await? else {
            return Ok(false);
        };

        Ok(response.as_bool() == Some(false)
            || response
                .get("cancelled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            || response
                .get("cancel")
                .and_then(Value::as_bool)
                .unwrap_or(false))
    }

    /// Dispatch a `tool_call` event to registered extensions and return the first
    /// blocking response (if any).
    #[allow(clippy::too_many_lines)]
    pub async fn dispatch_tool_call(
        &self,
        tool_call: &crate::model::ToolCall,
        timeout_ms: u64,
    ) -> Result<Option<ToolCallEventResult>> {
        let timeout_ms = self.effective_timeout(timeout_ms);
        let event_name = "tool_call".to_string();
        let (runtime, has_ui, session, cwd_override, model_registry_values, has_hook_js) = {
            let guard = self.inner.lock().unwrap();
            let has_hook = guard
                .extensions
                .iter()
                .any(|ext| ext.event_hooks.iter().any(|hook| hook == &event_name));
            (
                guard.js_runtime.clone(),
                guard.ui_sender.is_some(),
                guard.session.clone(),
                guard.cwd.clone(),
                guard.model_registry_values.clone(),
                has_hook,
            )
        };

        #[cfg(feature = "wasm-host")]
        let (wasm_extensions, has_hook_wasm) = {
            let guard = self.inner.lock().unwrap();
            let has_hook_wasm = guard
                .wasm_extensions
                .iter()
                .any(|ext| ext.event_hooks().iter().any(|hook| hook == &event_name));
            (guard.wasm_extensions.clone(), has_hook_wasm)
        };

        let has_any_hook = {
            #[cfg(feature = "wasm-host")]
            {
                has_hook_js || has_hook_wasm
            }
            #[cfg(not(feature = "wasm-host"))]
            {
                has_hook_js
            }
        };

        if !has_any_hook {
            return Ok(None);
        }

        let mut ctx = serde_json::Map::new();
        ctx.insert("hasUI".to_string(), Value::Bool(has_ui));
        if let Some(cwd) = cwd_override.or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|p| p.display().to_string())
        }) {
            ctx.insert("cwd".to_string(), Value::String(cwd));
        }

        if !model_registry_values.is_empty() {
            let mut map = serde_json::Map::new();
            for (key, value) in model_registry_values {
                map.insert(key, Value::String(value));
            }
            ctx.insert("modelRegistry".to_string(), Value::Object(map));
        }

        if let Some(session) = session {
            let state = session.get_state().await;
            let entries = session.get_entries().await;
            let branch = session.get_branch().await;
            let leaf_entry = entries.last().cloned().unwrap_or(Value::Null);
            ctx.insert("sessionState".to_string(), state);
            ctx.insert("sessionEntries".to_string(), Value::Array(entries));
            ctx.insert("sessionBranch".to_string(), Value::Array(branch));
            ctx.insert("sessionLeafEntry".to_string(), leaf_entry);
        }

        let ctx_payload = Value::Object(ctx);
        let event_payload = json!({
            "type": "tool_call",
            "toolName": tool_call.name.clone(),
            "toolCallId": tool_call.id.clone(),
            "input": tool_call.arguments.clone()
        });

        let mut response: Option<ToolCallEventResult> = None;

        if let Some(runtime) = runtime {
            if has_hook_js {
                let js_response = runtime
                    .dispatch_event(
                        event_name.clone(),
                        event_payload.clone(),
                        ctx_payload.clone(),
                        timeout_ms,
                    )
                    .await?;
                if !js_response.is_null() {
                    let parsed: ToolCallEventResult = serde_json::from_value(js_response)
                        .map_err(|err| Error::extension(err.to_string()))?;
                    if parsed.block {
                        return Ok(Some(parsed));
                    }
                    response = Some(parsed);
                }
            }
        }

        #[cfg(feature = "wasm-host")]
        if has_hook_wasm {
            let mut wasm_payload = event_payload;
            if let Value::Object(map) = &mut wasm_payload {
                map.insert("ctx".to_string(), ctx_payload);
            }
            if let Some(value) = Self::dispatch_wasm_event_value(
                &wasm_extensions,
                &event_name,
                &wasm_payload,
                timeout_ms,
            )
            .await?
            {
                let parsed: ToolCallEventResult = serde_json::from_value(value)
                    .map_err(|err| Error::extension(err.to_string()))?;
                if parsed.block {
                    return Ok(Some(parsed));
                }
                response = response.or(Some(parsed));
            }
        }

        Ok(response)
    }

    /// Dispatch a `tool_result` event to registered extensions and return the
    /// last handler response (if any).
    #[allow(clippy::too_many_lines)]
    pub async fn dispatch_tool_result(
        &self,
        tool_call: &crate::model::ToolCall,
        output: &crate::tools::ToolOutput,
        is_error: bool,
        timeout_ms: u64,
    ) -> Result<Option<ToolResultEventResult>> {
        let timeout_ms = self.effective_timeout(timeout_ms);
        let event_name = "tool_result".to_string();
        let (runtime, has_ui, session, cwd_override, model_registry_values, has_hook_js) = {
            let guard = self.inner.lock().unwrap();
            let has_hook = guard
                .extensions
                .iter()
                .any(|ext| ext.event_hooks.iter().any(|hook| hook == &event_name));
            (
                guard.js_runtime.clone(),
                guard.ui_sender.is_some(),
                guard.session.clone(),
                guard.cwd.clone(),
                guard.model_registry_values.clone(),
                has_hook,
            )
        };

        #[cfg(feature = "wasm-host")]
        let (wasm_extensions, has_hook_wasm) = {
            let guard = self.inner.lock().unwrap();
            let has_hook_wasm = guard
                .wasm_extensions
                .iter()
                .any(|ext| ext.event_hooks().iter().any(|hook| hook == &event_name));
            (guard.wasm_extensions.clone(), has_hook_wasm)
        };

        let has_any_hook = {
            #[cfg(feature = "wasm-host")]
            {
                has_hook_js || has_hook_wasm
            }
            #[cfg(not(feature = "wasm-host"))]
            {
                has_hook_js
            }
        };

        if !has_any_hook {
            return Ok(None);
        }

        let mut ctx = serde_json::Map::new();
        ctx.insert("hasUI".to_string(), Value::Bool(has_ui));
        if let Some(cwd) = cwd_override.or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|p| p.display().to_string())
        }) {
            ctx.insert("cwd".to_string(), Value::String(cwd));
        }

        if !model_registry_values.is_empty() {
            let mut map = serde_json::Map::new();
            for (key, value) in model_registry_values {
                map.insert(key, Value::String(value));
            }
            ctx.insert("modelRegistry".to_string(), Value::Object(map));
        }

        if let Some(session) = session {
            let state = session.get_state().await;
            let entries = session.get_entries().await;
            let branch = session.get_branch().await;
            let leaf_entry = entries.last().cloned().unwrap_or(Value::Null);
            ctx.insert("sessionState".to_string(), state);
            ctx.insert("sessionEntries".to_string(), Value::Array(entries));
            ctx.insert("sessionBranch".to_string(), Value::Array(branch));
            ctx.insert("sessionLeafEntry".to_string(), leaf_entry);
        }

        let ctx_payload = Value::Object(ctx);
        let event_payload = json!({
            "type": "tool_result",
            "toolName": tool_call.name.clone(),
            "toolCallId": tool_call.id.clone(),
            "input": tool_call.arguments.clone(),
            "content": output.content.clone(),
            "details": output.details.clone(),
            "isError": is_error
        });

        let mut response: Option<ToolResultEventResult> = None;

        if let Some(runtime) = runtime {
            if has_hook_js {
                let js_response = runtime
                    .dispatch_event(
                        event_name.clone(),
                        event_payload.clone(),
                        ctx_payload.clone(),
                        timeout_ms,
                    )
                    .await?;
                if !js_response.is_null() {
                    response = Some(
                        serde_json::from_value(js_response)
                            .map_err(|err| Error::extension(err.to_string()))?,
                    );
                }
            }
        }

        #[cfg(feature = "wasm-host")]
        if has_hook_wasm {
            let mut wasm_payload = event_payload;
            if let Value::Object(map) = &mut wasm_payload {
                map.insert("ctx".to_string(), ctx_payload);
            }
            if let Some(value) = Self::dispatch_wasm_event_value(
                &wasm_extensions,
                &event_name,
                &wasm_payload,
                timeout_ms,
            )
            .await?
            {
                response = Some(
                    serde_json::from_value(value)
                        .map_err(|err| Error::extension(err.to_string()))?,
                );
            }
        }

        Ok(response)
    }
}

/// Extract extension event information from an agent event.
pub fn extension_event_from_agent(
    event: &AgentEvent,
) -> Option<(ExtensionEventName, Option<Value>)> {
    let name = match event {
        AgentEvent::AgentStart { .. } => ExtensionEventName::AgentStart,
        AgentEvent::AgentEnd { .. } => ExtensionEventName::AgentEnd,
        AgentEvent::TurnStart { .. } => ExtensionEventName::TurnStart,
        AgentEvent::TurnEnd { .. } => ExtensionEventName::TurnEnd,
        AgentEvent::MessageStart { .. } => ExtensionEventName::MessageStart,
        AgentEvent::MessageUpdate { .. } => ExtensionEventName::MessageUpdate,
        AgentEvent::MessageEnd { .. } => ExtensionEventName::MessageEnd,
        AgentEvent::ToolExecutionStart { .. } => ExtensionEventName::ToolExecutionStart,
        AgentEvent::ToolExecutionUpdate { .. } => ExtensionEventName::ToolExecutionUpdate,
        AgentEvent::ToolExecutionEnd { .. } => ExtensionEventName::ToolExecutionEnd,
    };

    let payload = serde_json::to_value(event).ok();
    Some((name, payload))
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
    use tempfile::tempdir;

    fn compiled_extension_protocol_schema() -> Validator {
        let schema_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("docs/schema/extension_protocol.json");
        let raw = std::fs::read_to_string(&schema_path)
            .map_err(|err| {
                format!(
                    "Failed to read extension protocol schema {}: {err}",
                    schema_path.display()
                )
            })
            .unwrap();
        let schema: Value = serde_json::from_str(&raw)
            .map_err(|err| {
                format!(
                    "Failed to parse extension protocol schema {}: {err}",
                    schema_path.display()
                )
            })
            .unwrap();

        jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|err| {
                format!(
                    "Failed to compile JSON schema {}: {err}",
                    schema_path.display()
                )
            })
            .unwrap()
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
                        capability_manifest: None,
                        tools: Vec::new(),
                        slash_commands: Vec::new(),
                        shortcuts: Vec::new(),
                        flags: Vec::new(),
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
                        capability: "read".to_string(),
                        method: "tool".to_string(),
                        params: json!({ "name": "read", "input": { "path": "README.md" } }),
                        timeout_ms: Some(2500),
                        cancel_token: None,
                        context: None,
                    }),
                },
            ),
            (
                "host_call_cancel",
                ExtensionMessage {
                    id: "msg-host-call-cancel".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::HostCall(HostCallPayload {
                        call_id: "host-2".to_string(),
                        capability: "http".to_string(),
                        method: "http".to_string(),
                        params: json!({ "url": "https://example.com", "method": "GET" }),
                        timeout_ms: Some(1500),
                        cancel_token: Some("cancel-1".to_string()),
                        context: Some(json!({ "trace_id": "trace-1" })),
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
                        error: None,
                        chunk: None,
                    }),
                },
            ),
            (
                "host_result_timeout",
                ExtensionMessage {
                    id: "msg-host-result-timeout".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::HostResult(HostResultPayload {
                        call_id: "host-2".to_string(),
                        output: json!({}),
                        is_error: true,
                        error: Some(HostCallError {
                            code: HostCallErrorCode::Timeout,
                            message: "Timed out".to_string(),
                            details: None,
                            retryable: Some(true),
                        }),
                        chunk: None,
                    }),
                },
            ),
            (
                "host_result_denied",
                ExtensionMessage {
                    id: "msg-host-result-denied".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::HostResult(HostResultPayload {
                        call_id: "host-3".to_string(),
                        output: json!({}),
                        is_error: true,
                        error: Some(HostCallError {
                            code: HostCallErrorCode::Denied,
                            message: "Denied".to_string(),
                            details: Some(json!({ "capability": "exec" })),
                            retryable: None,
                        }),
                        chunk: None,
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
    fn parse_register_message_with_capability_manifest_v2() {
        let json = r#"
        {
          "id": "msg-v2",
          "version": "1.0",
          "type": "register",
          "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capability_manifest": {
              "schema": "pi.ext.cap.v2",
              "capabilities": [
                {
                  "capability": "read",
                  "intents": ["file_read"],
                  "connector_classes": ["fs"],
                  "hostcall_classes": ["fs.read"],
                  "scope": { "paths": ["."] },
                  "provenance": {
                    "source": "local",
                    "integrity": {
                      "algorithm": "sha256",
                      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    },
                    "publisher": {
                      "id": "dev@example",
                      "verification": "self_attested"
                    }
                  }
                }
              ]
            }
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).expect("v2 register should parse");
        let ExtensionBody::Register(payload) = msg.body else {
            panic!("expected register payload");
        };
        let schema = payload
            .capability_manifest
            .expect("capability manifest")
            .schema;
        assert_eq!(schema, CAPABILITY_MANIFEST_SCHEMA_V2);
    }

    #[test]
    fn parse_register_message_rejects_v2_manifest_without_provenance() {
        let json = r#"
        {
          "id": "msg-v2-invalid",
          "version": "1.0",
          "type": "register",
          "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capability_manifest": {
              "schema": "pi.ext.cap.v2",
              "capabilities": [
                {
                  "capability": "read",
                  "intents": ["file_read"],
                  "connector_classes": ["fs"],
                  "hostcall_classes": ["fs.read"]
                }
              ]
            }
          }
        }
        "#;
        let err = ExtensionMessage::parse_and_validate(json).expect_err("must fail closed");
        let msg = format!("{err}");
        assert!(msg.contains("missing provenance"), "{msg}");
    }

    #[test]
    fn parse_register_message_rejects_v2_manifest_unknown_requirement_field() {
        let json = r#"
        {
          "id": "msg-v2-unknown-field",
          "version": "1.0",
          "type": "register",
          "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capability_manifest": {
              "schema": "pi.ext.cap.v2",
              "capabilities": [
                {
                  "capability": "read",
                  "intents": ["file_read"],
                  "connector_classes": ["fs"],
                  "hostcall_classes": ["fs.read"],
                  "provenance": {
                    "source": "local",
                    "integrity": {
                      "algorithm": "sha256",
                      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    },
                    "publisher": {
                      "id": "dev@example",
                      "verification": "self_attested"
                    }
                  },
                  "unexpected_critical": true
                }
              ]
            }
          }
        }
        "#;
        let err = ExtensionMessage::parse_and_validate(json).expect_err("must fail closed");
        let msg = format!("{err}");
        assert!(msg.contains("unknown field"), "{msg}");
        assert!(msg.contains("unexpected_critical"), "{msg}");
    }

    #[test]
    fn parse_register_message_rejects_v2_manifest_unknown_provenance_field() {
        let json = r#"
        {
          "id": "msg-v2-provenance-unknown-field",
          "version": "1.0",
          "type": "register",
          "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capability_manifest": {
              "schema": "pi.ext.cap.v2",
              "capabilities": [
                {
                  "capability": "read",
                  "intents": ["file_read"],
                  "connector_classes": ["fs"],
                  "hostcall_classes": ["fs.read"],
                  "provenance": {
                    "source": "local",
                    "integrity": {
                      "algorithm": "sha256",
                      "digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    },
                    "publisher": {
                      "id": "dev@example",
                      "verification": "self_attested"
                    },
                    "sigstore_bundle": "opaque"
                  }
                }
              ]
            }
          }
        }
        "#;
        let err = ExtensionMessage::parse_and_validate(json).expect_err("must fail closed");
        let msg = format!("{err}");
        assert!(msg.contains("unknown field"), "{msg}");
        assert!(msg.contains("sigstore_bundle"), "{msg}");
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
    fn extension_manifest_rejects_v1_with_v2_only_fields() {
        let manifest = ExtensionManifest {
            schema: "pi.ext.manifest.v1".to_string(),
            extension_id: "ext.test".to_string(),
            name: "ext".to_string(),
            version: "0.1.0".to_string(),
            api_version: PROTOCOL_VERSION.to_string(),
            runtime: ExtensionRuntime::Js,
            entrypoint: "index.js".to_string(),
            capabilities: vec!["read".to_string()],
            capability_manifest: Some(CapabilityManifest {
                schema: CAPABILITY_MANIFEST_SCHEMA_V1.to_string(),
                capabilities: vec![CapabilityRequirement {
                    capability: "read".to_string(),
                    methods: vec!["fs".to_string()],
                    intents: vec!["file_read".to_string()],
                    connector_classes: Vec::new(),
                    hostcall_classes: Vec::new(),
                    risk_tier: None,
                    scope: Some(CapabilityScope {
                        paths: Some(vec![".".to_string()]),
                        hosts: None,
                        env: None,
                        allowed_tools: None,
                    }),
                    provenance: None,
                }],
            }),
            description: None,
        };

        let err = validate_extension_manifest(&manifest).expect_err("v1 must reject v2 fields");
        let msg = format!("{err}");
        assert!(msg.contains("v2-only fields"), "{msg}");
    }

    #[test]
    fn extension_manifest_accepts_capability_manifest_v2() {
        let manifest = ExtensionManifest {
            schema: "pi.ext.manifest.v1".to_string(),
            extension_id: "ext.test".to_string(),
            name: "ext".to_string(),
            version: "0.1.0".to_string(),
            api_version: PROTOCOL_VERSION.to_string(),
            runtime: ExtensionRuntime::Js,
            entrypoint: "index.js".to_string(),
            capabilities: Vec::new(),
            capability_manifest: Some(CapabilityManifest {
                schema: CAPABILITY_MANIFEST_SCHEMA_V2.to_string(),
                capabilities: vec![CapabilityRequirement {
                    capability: "read".to_string(),
                    methods: Vec::new(),
                    intents: vec!["file_read".to_string()],
                    connector_classes: vec!["fs".to_string()],
                    hostcall_classes: vec!["fs.read".to_string()],
                    risk_tier: Some("low".to_string()),
                    scope: Some(CapabilityScope {
                        paths: Some(vec![".".to_string()]),
                        hosts: None,
                        env: None,
                        allowed_tools: Some(vec!["read".to_string()]),
                    }),
                    provenance: Some(CapabilityProvenance {
                        source: "local".to_string(),
                        integrity: CapabilityIntegrityAttestation {
                            algorithm: "sha256".to_string(),
                            digest:
                                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                    .to_string(),
                        },
                        publisher: CapabilityPublisherAttestation {
                            id: "dev@example".to_string(),
                            verification: "self_attested".to_string(),
                        },
                    }),
                }],
            }),
            description: None,
        };

        validate_extension_manifest(&manifest).expect("v2 manifest should validate");
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
            "capability": "read",
            "method": "tool",
            "params": { "name": "read", "input": { "path": "README.md" } },
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
    fn js_hostcall_prompt_mode_asks_once_per_capability() {
        let manager = extension_manager_no_persisted_permissions();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let handle = runtime.handle();

        runtime.block_on(async move {
            use std::sync::atomic::{AtomicUsize, Ordering};

            let (ui_tx, ui_rx) = mpsc::channel(16);
            manager.set_ui_sender(ui_tx);

            let prompt_count = Arc::new(AtomicUsize::new(0));
            let prompt_count_clone = Arc::clone(&prompt_count);

            let responder = manager.clone();
            handle.spawn(async move {
                let cx = Cx::for_request();
                while let Ok(req) = ui_rx.recv(&cx).await {
                    prompt_count_clone.fetch_add(1, Ordering::SeqCst);
                    responder.respond_ui(ExtensionUiResponse {
                        id: req.id,
                        value: Some(json!(true)),
                        cancelled: false,
                    });
                }
            });

            let dir = tempdir().expect("tempdir");
            let host = JsRuntimeHost {
                tools: Arc::new(ToolRegistry::new(&[], dir.path(), None)),
                manager_ref: Arc::downgrade(&manager.inner),
                http: Arc::new(HttpConnector::with_defaults()),
                policy: ExtensionPolicy {
                    mode: ExtensionPolicyMode::Prompt,
                    max_memory_mb: 256,
                    default_caps: Vec::new(),
                    deny_caps: Vec::new(),
                    ..Default::default()
                },
                interceptor: None,
            };

            let request = HostcallRequest {
                call_id: "call-1".to_string(),
                kind: HostcallKind::Tool {
                    name: "nonexistent".to_string(),
                },
                payload: json!({}),
                trace_id: 1,
                extension_id: Some("ext.test".to_string()),
            };

            let _ = dispatch_hostcall(&host, request).await;

            let request = HostcallRequest {
                call_id: "call-2".to_string(),
                kind: HostcallKind::Tool {
                    name: "nonexistent".to_string(),
                },
                payload: json!({}),
                trace_id: 2,
                extension_id: Some("ext.test".to_string()),
            };

            let _ = dispatch_hostcall(&host, request).await;

            assert_eq!(prompt_count.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn js_runtime_pump_once_advances_timers_and_hostcalls() {
        let manager = ExtensionManager::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");

        runtime.block_on(async move {
            let dir = tempdir().expect("tempdir");
            let entry_path = dir.path().join("ext.mjs");
            std::fs::write(
                &entry_path,
                r#"
                export default function init(pi) {
                  pi.on("agent_start", () => {
                    setTimeout(() => {
                      pi.tool("write", { path: "out.txt", content: "hi" });
                    }, 0);
                  });
                }
                "#,
            )
            .expect("write extension entry");

            let tools = Arc::new(ToolRegistry::new(&["write"], dir.path(), None));
            let js_runtime = JsExtensionRuntimeHandle::start(
                PiJsRuntimeConfig {
                    cwd: dir.path().display().to_string(),
                    ..Default::default()
                },
                Arc::clone(&tools),
                manager.clone(),
            )
            .await
            .expect("start js runtime");
            manager.set_js_runtime(js_runtime.clone());

            let spec = JsExtensionLoadSpec::from_entry_path(&entry_path).expect("load spec");
            manager
                .load_js_extensions(vec![spec])
                .await
                .expect("load extension");

            manager
                .dispatch_event(ExtensionEventName::AgentStart, None)
                .await
                .expect("dispatch agent_start");

            let out_path = dir.path().join("out.txt");
            let mut wrote = false;
            for _ in 0..20 {
                let _ = js_runtime.pump_once().await.expect("pump_once");
                if out_path.exists() {
                    wrote = true;
                    break;
                }
                sleep(wall_now(), Duration::from_millis(1)).await;
            }

            assert!(wrote, "expected out.txt to be created after pumping");
            let contents = std::fs::read_to_string(&out_path).expect("read out.txt");
            assert_eq!(contents, "hi");
        });
    }

    #[test]
    #[cfg(unix)]
    fn js_runtime_pump_once_exec_streaming_callback_delivers_chunks_and_final_result() {
        futures::executor::block_on(async {
            let dir = tempdir().expect("tempdir");
            let manager = ExtensionManager::new();
            let host = JsRuntimeHost {
                tools: Arc::new(ToolRegistry::new(&[], dir.path(), None)),
                manager_ref: Arc::downgrade(&manager.inner),
                http: Arc::new(HttpConnector::with_defaults()),
                policy: ExtensionPolicy {
                    mode: ExtensionPolicyMode::Permissive,
                    max_memory_mb: 256,
                    default_caps: Vec::new(),
                    deny_caps: Vec::new(),
                    ..Default::default()
                },
                interceptor: None,
            };

            let runtime = PiJsRuntime::new().await.expect("runtime");
            runtime
                .eval(
                    r#"
                    globalThis.chunks = [];
                    globalThis.finalResult = null;
                    globalThis.finalErr = null;
                    pi.exec("sh", ["-c", "printf 'out-1\n'; printf 'err-1\n' 1>&2; printf 'out-2\n'"], {
                        stream: true,
                        onChunk: (chunk, isFinal) => {
                            globalThis.chunks.push({ chunk, isFinal });
                        },
                    })
                    .then((r) => { globalThis.finalResult = r; })
                    .catch((e) => { globalThis.finalErr = { code: e.code, message: e.message || String(e) }; });
                "#,
                )
                .await
                .expect("eval");

            for _ in 0..256 {
                let has_pending = pump_js_runtime_once(&runtime, &host)
                    .await
                    .expect("pump_once");
                if !has_pending {
                    break;
                }
            }
            assert!(
                !runtime.has_pending(),
                "runtime should have no pending tasks after streaming exec"
            );

            let chunks = runtime
                .read_global_json("chunks")
                .await
                .expect("read chunks");
            let entries = chunks.as_array().expect("chunks array");
            assert!(
                entries.len() >= 3,
                "expected stream chunks plus final chunk, got: {entries:?}"
            );
            assert!(
                entries.iter().any(|entry| {
                    entry
                        .get("chunk")
                        .and_then(|chunk| chunk.get("stdout"))
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.contains("out-1"))
                }),
                "missing stdout chunk: {entries:?}"
            );
            assert!(
                entries.iter().any(|entry| {
                    entry
                        .get("chunk")
                        .and_then(|chunk| chunk.get("stderr"))
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.contains("err-1"))
                }),
                "missing stderr chunk: {entries:?}"
            );
            assert_eq!(
                entries.last().and_then(|entry| entry.get("isFinal")),
                Some(&Value::Bool(true)),
                "expected final stream marker: {entries:?}"
            );

            let final_result = runtime
                .read_global_json("finalResult")
                .await
                .expect("read finalResult");
            assert_eq!(final_result.get("code"), Some(&json!(0)));
            assert_eq!(final_result.get("killed"), Some(&Value::Bool(false)));
            assert_eq!(
                runtime
                    .read_global_json("finalErr")
                    .await
                    .expect("read finalErr"),
                Value::Null
            );
        });
    }

    #[test]
    #[cfg(unix)]
    fn js_runtime_pump_once_exec_streaming_signal_termination_reports_nonzero_code() {
        futures::executor::block_on(async {
            let dir = tempdir().expect("tempdir");
            let manager = ExtensionManager::new();
            let host = JsRuntimeHost {
                tools: Arc::new(ToolRegistry::new(&[], dir.path(), None)),
                manager_ref: Arc::downgrade(&manager.inner),
                http: Arc::new(HttpConnector::with_defaults()),
                policy: ExtensionPolicy {
                    mode: ExtensionPolicyMode::Permissive,
                    max_memory_mb: 256,
                    default_caps: Vec::new(),
                    deny_caps: Vec::new(),
                    ..Default::default()
                },
                interceptor: None,
            };

            let runtime = PiJsRuntime::new().await.expect("runtime");
            runtime
                .eval(
                    r#"
                    globalThis.sigChunks = [];
                    globalThis.sigDone = false;
                    globalThis.sigErr = null;
                    (async () => {
                        try {
                            const stream = pi.exec("/bin/sh", ["-c", "kill -KILL $$"], { stream: true });
                            for await (const chunk of stream) {
                                globalThis.sigChunks.push(chunk);
                            }
                            globalThis.sigDone = true;
                        } catch (e) {
                            globalThis.sigErr = e.message || String(e);
                        }
                    })();
                "#,
                )
                .await
                .expect("eval");

            for _ in 0..256 {
                let has_pending = pump_js_runtime_once(&runtime, &host)
                    .await
                    .expect("pump_once");
                if !has_pending {
                    break;
                }
            }
            assert!(
                !runtime.has_pending(),
                "runtime should have no pending tasks after signal-terminated exec stream"
            );

            let signal_chunks = runtime
                .read_global_json("sigChunks")
                .await
                .expect("read sigChunks");
            let entries = signal_chunks.as_array().expect("sigChunks array");
            assert!(
                !entries.is_empty(),
                "expected a final chunk for signal termination"
            );
            let final_chunk = entries.last().expect("final chunk");
            let code = final_chunk
                .get("code")
                .and_then(Value::as_i64)
                .expect("numeric final exit code");
            assert_ne!(
                code, 0,
                "signal-terminated process must not report exit code 0"
            );
            assert_eq!(final_chunk.get("killed"), Some(&Value::Bool(false)));
            assert_eq!(
                runtime
                    .read_global_json("sigDone")
                    .await
                    .expect("read sigDone"),
                Value::Bool(true)
            );
            assert_eq!(
                runtime
                    .read_global_json("sigErr")
                    .await
                    .expect("read sigErr"),
                Value::Null
            );
        });
    }

    #[test]
    #[cfg(unix)]
    fn js_runtime_pump_once_exec_streaming_async_iterator_delivers_chunks_in_order() {
        futures::executor::block_on(async {
            let dir = tempdir().expect("tempdir");
            let manager = ExtensionManager::new();
            let host = JsRuntimeHost {
                tools: Arc::new(ToolRegistry::new(&[], dir.path(), None)),
                manager_ref: Arc::downgrade(&manager.inner),
                http: Arc::new(HttpConnector::with_defaults()),
                policy: ExtensionPolicy {
                    mode: ExtensionPolicyMode::Permissive,
                    max_memory_mb: 256,
                    default_caps: Vec::new(),
                    deny_caps: Vec::new(),
                    ..Default::default()
                },
                interceptor: None,
            };

            let runtime = PiJsRuntime::new().await.expect("runtime");
            runtime
                .eval(
                    r#"
                    globalThis.iterChunks = [];
                    globalThis.iterDone = false;
                    globalThis.iterErr = null;
                    (async () => {
                        try {
                            const stream = pi.exec("sh", ["-c", "printf 'a\n'; printf 'b\n'"], { stream: true });
                            for await (const chunk of stream) {
                                globalThis.iterChunks.push(chunk);
                            }
                            globalThis.iterDone = true;
                        } catch (e) {
                            globalThis.iterErr = e.message || String(e);
                        }
                    })();
                "#,
                )
                .await
                .expect("eval");

            for _ in 0..256 {
                let has_pending = pump_js_runtime_once(&runtime, &host)
                    .await
                    .expect("pump_once");
                if !has_pending {
                    break;
                }
            }
            assert!(
                !runtime.has_pending(),
                "runtime should have no pending tasks after streaming exec"
            );

            let iter_chunks = runtime
                .read_global_json("iterChunks")
                .await
                .expect("read iterChunks");
            let entries = iter_chunks.as_array().expect("iterChunks array");
            assert!(
                entries.len() >= 3,
                "expected stdout/stdout/final chunks, got: {entries:?}"
            );
            assert_eq!(
                entries[0].get("stdout"),
                Some(&Value::String("a\n".to_string()))
            );
            assert_eq!(
                entries[1].get("stdout"),
                Some(&Value::String("b\n".to_string()))
            );
            let final_chunk = entries.last().expect("final chunk");
            assert_eq!(final_chunk.get("code"), Some(&json!(0)));
            assert_eq!(final_chunk.get("killed"), Some(&Value::Bool(false)));
            assert_eq!(
                runtime
                    .read_global_json("iterDone")
                    .await
                    .expect("read iterDone"),
                Value::Bool(true)
            );
            assert_eq!(
                runtime
                    .read_global_json("iterErr")
                    .await
                    .expect("read iterErr"),
                Value::Null
            );
        });
    }

    #[test]
    #[cfg(unix)]
    fn js_runtime_pump_once_exec_streaming_timeout_sets_killed_final_chunk() {
        futures::executor::block_on(async {
            let dir = tempdir().expect("tempdir");
            let manager = ExtensionManager::new();
            let host = JsRuntimeHost {
                tools: Arc::new(ToolRegistry::new(&[], dir.path(), None)),
                manager_ref: Arc::downgrade(&manager.inner),
                http: Arc::new(HttpConnector::with_defaults()),
                policy: ExtensionPolicy {
                    mode: ExtensionPolicyMode::Permissive,
                    max_memory_mb: 256,
                    default_caps: Vec::new(),
                    deny_caps: Vec::new(),
                    ..Default::default()
                },
                interceptor: None,
            };

            let runtime = PiJsRuntime::new().await.expect("runtime");
            runtime
                .eval(
                    r#"
                    globalThis.timeoutChunks = [];
                    globalThis.timeoutDone = false;
                    globalThis.timeoutErr = null;
                    (async () => {
                        try {
                            const stream = pi.exec("sh", ["-c", "sleep 10"], { stream: true, timeoutMs: 200 });
                            for await (const chunk of stream) {
                                globalThis.timeoutChunks.push(chunk);
                            }
                            globalThis.timeoutDone = true;
                        } catch (e) {
                            globalThis.timeoutErr = e.message || String(e);
                        }
                    })();
                "#,
                )
                .await
                .expect("eval");

            for _ in 0..256 {
                let has_pending = pump_js_runtime_once(&runtime, &host)
                    .await
                    .expect("pump_once");
                if !has_pending {
                    break;
                }
            }
            assert!(
                !runtime.has_pending(),
                "runtime should have no pending tasks after timeout stream"
            );

            let timeout_chunks = runtime
                .read_global_json("timeoutChunks")
                .await
                .expect("read timeoutChunks");
            let entries = timeout_chunks.as_array().expect("timeoutChunks array");
            assert!(!entries.is_empty(), "expected at least one final chunk");
            let final_chunk = entries.last().expect("final chunk");
            assert_eq!(final_chunk.get("killed"), Some(&Value::Bool(true)));
            assert!(
                final_chunk.get("code").and_then(Value::as_i64).is_some(),
                "expected numeric exit code in final chunk: {final_chunk:?}"
            );
            assert_eq!(
                runtime
                    .read_global_json("timeoutDone")
                    .await
                    .expect("read timeoutDone"),
                Value::Bool(true)
            );
            assert_eq!(
                runtime
                    .read_global_json("timeoutErr")
                    .await
                    .expect("read timeoutErr"),
                Value::Null
            );
        });
    }

    #[test]
    #[cfg(unix)]
    fn js_runtime_pump_once_exec_streaming_return_cancels_before_dispatch() {
        futures::executor::block_on(async {
            let dir = tempdir().expect("tempdir");
            let manager = ExtensionManager::new();
            let host = JsRuntimeHost {
                tools: Arc::new(ToolRegistry::new(&[], dir.path(), None)),
                manager_ref: Arc::downgrade(&manager.inner),
                http: Arc::new(HttpConnector::with_defaults()),
                policy: ExtensionPolicy {
                    mode: ExtensionPolicyMode::Permissive,
                    max_memory_mb: 256,
                    default_caps: Vec::new(),
                    deny_caps: Vec::new(),
                    ..Default::default()
                },
                interceptor: None,
            };

            let runtime = PiJsRuntime::new().await.expect("runtime");
            runtime
                .eval(
                    r#"
                    globalThis.cancelDone = false;
                    (async () => {
                        const stream = pi.exec("sh", ["-c", "sleep 2"], { stream: true });
                        await stream.return();
                        globalThis.cancelDone = true;
                    })();
                "#,
                )
                .await
                .expect("eval");

            let start = Instant::now();
            for _ in 0..64 {
                let has_pending = pump_js_runtime_once(&runtime, &host)
                    .await
                    .expect("pump_once");
                if !has_pending {
                    break;
                }
            }
            let elapsed = start.elapsed();

            assert!(
                !runtime.has_pending(),
                "runtime should not remain pending after stream.return() cancellation"
            );
            assert!(
                elapsed < Duration::from_secs(5),
                "stream cancellation should complete quickly, took {elapsed:?}",
            );
            assert_eq!(
                runtime
                    .read_global_json("cancelDone")
                    .await
                    .expect("read cancelDone"),
                Value::Bool(true)
            );
        });
    }

    #[test]
    fn extension_protocol_schema_accepts_all_variants() {
        let schema = compiled_extension_protocol_schema();
        for (label, message) in sample_protocol_messages() {
            let instance = serde_json::to_value(&message)
                .map_err(|err| format!("{label}: {err}"))
                .unwrap();

            let errors = schema
                .iter_errors(&instance)
                .map(|err| err.to_string())
                .collect::<Vec<_>>();
            assert!(
                errors.is_empty(),
                "{label}: schema validation failed:\n{}",
                errors.join("\n")
            );

            let json = serde_json::to_string(&message)
                .map_err(|err| format!("{label}: {err}"))
                .unwrap();
            let parsed = ExtensionMessage::parse_and_validate(&json)
                .map_err(|err| format!("{label}: parse_and_validate failed: {err}"))
                .unwrap();
            let parsed_json = serde_json::to_value(&parsed)
                .map_err(|err| format!("{label}: {err}"))
                .unwrap();
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

    #[test]
    fn parse_fs_host_call_message() {
        let json = r#"
        {
          "id": "msg-fs",
          "version": "1.0",
          "type": "host_call",
          "payload": {
            "call_id": "call-1",
            "capability": "read",
            "method": "fs",
            "params": { "op": "read", "path": "README.md" }
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::HostCall(_)));
    }

    #[test]
    fn required_capability_for_host_call_maps_tools_and_fs_ops() {
        let tool_read = HostCallPayload {
            call_id: "call-tool-read".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "read", "input": { "path": "README.md" } }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert_eq!(
            required_capability_for_host_call(&tool_read).as_deref(),
            Some("read")
        );

        let tool_bash = HostCallPayload {
            call_id: "call-tool-bash".to_string(),
            capability: "exec".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "bash", "input": { "command": "echo hi" } }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert_eq!(
            required_capability_for_host_call(&tool_bash).as_deref(),
            Some("exec")
        );

        let fs_delete = HostCallPayload {
            call_id: "call-fs-delete".to_string(),
            capability: "write".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "delete", "path": "tmp.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert_eq!(
            required_capability_for_host_call(&fs_delete).as_deref(),
            Some("write")
        );

        let env_get = HostCallPayload {
            call_id: "call-env-get".to_string(),
            capability: "env".to_string(),
            method: "env".to_string(),
            params: json!({ "name": "HOME" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert_eq!(
            required_capability_for_host_call(&env_get).as_deref(),
            Some("env")
        );

        let unknown = HostCallPayload {
            call_id: "call-unknown".to_string(),
            capability: "read".to_string(),
            method: "nope".to_string(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        assert!(required_capability_for_host_call(&unknown).is_none());
    }

    #[test]
    fn fs_connector_denies_path_traversal_outside_cwd() {
        let dir = tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).expect("create project dir");

        let inside = project.join("inside.txt");
        std::fs::write(&inside, "hello").expect("write inside");

        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "secret").expect("write outside");

        let policy = ExtensionPolicy::default();
        let scopes = FsScopes::for_cwd(&project).expect("scopes");
        let connector = FsConnector::new(project, policy, scopes).expect("connector");

        let ok_call = HostCallPayload {
            call_id: "call-ok".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "read", "path": "inside.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        let ok_result = connector.handle_host_call(&ok_call);
        assert!(!ok_result.is_error);

        let denied_call = HostCallPayload {
            call_id: "call-deny".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "read", "path": "../outside.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        let denied = connector.handle_host_call(&denied_call);
        assert!(denied.is_error);
        assert_eq!(
            denied.error.as_ref().expect("error").code,
            HostCallErrorCode::Denied
        );
    }

    #[test]
    fn fs_connector_denies_write_escape_via_dotdot_segments() {
        let dir = tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).expect("create project dir");

        let policy = ExtensionPolicy::default();
        let scopes = FsScopes::for_cwd(&project).expect("scopes");
        let connector = FsConnector::new(&project, policy, scopes).expect("connector");

        let denied_call = HostCallPayload {
            call_id: "call-write-deny".to_string(),
            capability: "write".to_string(),
            method: "fs".to_string(),
            params: json!({
                "op": "write",
                "path": "subdir/../../outside.txt",
                "data": "secret",
            }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        let denied = connector.handle_host_call(&denied_call);
        assert!(denied.is_error);
        assert_eq!(
            denied.error.as_ref().expect("error").code,
            HostCallErrorCode::Denied
        );
    }

    #[cfg(unix)]
    #[test]
    fn fs_connector_denies_symlink_escape() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).expect("create project dir");

        let outside = dir.path().join("secret.txt");
        std::fs::write(&outside, "secret").expect("write outside");

        let link = project.join("link.txt");
        symlink(&outside, &link).expect("symlink");

        let policy = ExtensionPolicy::default();
        let scopes = FsScopes::for_cwd(&project).expect("scopes");
        let connector = FsConnector::new(project, policy, scopes).expect("connector");

        let call = HostCallPayload {
            call_id: "call-link".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "read", "path": "link.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        let result = connector.handle_host_call(&call);
        assert!(result.is_error);
        assert_eq!(
            result.error.as_ref().expect("error").code,
            HostCallErrorCode::Denied
        );
    }

    #[test]
    fn fs_connector_denies_when_policy_denies_capability() {
        let dir = tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).expect("create project dir");

        let inside = project.join("inside.txt");
        std::fs::write(&inside, "hello").expect("write inside");

        let mut policy = ExtensionPolicy::default();
        policy.deny_caps.push("read".to_string());

        let scopes = FsScopes::for_cwd(&project).expect("scopes");
        let connector = FsConnector::new(&project, policy, scopes).expect("connector");

        let call = HostCallPayload {
            call_id: "call-policy-deny".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "read", "path": "inside.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        let result = connector.handle_host_call(&call);
        assert!(result.is_error);
        assert_eq!(
            result.error.as_ref().expect("error").code,
            HostCallErrorCode::Denied
        );
    }

    #[test]
    fn fs_connector_denies_write_when_manifest_does_not_declare_write_scope() {
        let dir = tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).expect("create project dir");

        let inside = project.join("inside.txt");
        std::fs::write(&inside, "hello").expect("write inside");

        let manifest = CapabilityManifest {
            schema: "pi.ext.cap.v1".to_string(),
            capabilities: vec![CapabilityRequirement {
                capability: "read".to_string(),
                methods: vec!["fs".to_string()],
                intents: Vec::new(),
                connector_classes: Vec::new(),
                hostcall_classes: Vec::new(),
                risk_tier: None,
                scope: Some(CapabilityScope {
                    paths: Some(vec![".".to_string()]),
                    hosts: None,
                    env: None,
                    allowed_tools: None,
                }),
                provenance: None,
            }],
        };
        let scopes = FsScopes::from_manifest(Some(&manifest), &project).expect("scopes");
        let connector =
            FsConnector::new(&project, ExtensionPolicy::default(), scopes).expect("connector");

        let call = HostCallPayload {
            call_id: "call-scope-deny".to_string(),
            capability: "write".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "write", "path": "inside.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        let result = connector.handle_host_call(&call);
        assert!(result.is_error);
        assert_eq!(
            result.error.as_ref().expect("error").code,
            HostCallErrorCode::Denied
        );
    }

    fn canonicalize_json(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                let mut out = serde_json::Map::new();
                for key in keys {
                    if let Some(value) = map.get(&key) {
                        out.insert(key, canonicalize_json(value));
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
            other => other.clone(),
        }
    }

    fn sha256_hex(input: &str) -> String {
        use std::fmt::Write as _;

        let mut hasher = sha2::Sha256::new();
        hasher.update(input.as_bytes());
        let digest = hasher.finalize();

        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut out, "{byte:02x}").expect("write hex");
        }
        out
    }

    fn hostcall_params_hash(method: &str, params: &Value) -> String {
        let canonical = canonicalize_json(&json!({ "method": method, "params": params }));
        let json = serde_json::to_string(&canonical).expect("serialize canonical hostcall");
        sha256_hex(&json)
    }

    fn hostcall_ledger_start_data(call: &HostCallPayload) -> Value {
        let mut data = serde_json::Map::new();
        data.insert(
            "capability".to_string(),
            Value::String(call.capability.clone()),
        );
        data.insert("method".to_string(), Value::String(call.method.clone()));
        data.insert(
            "params_hash".to_string(),
            Value::String(hostcall_params_hash(&call.method, &call.params)),
        );
        if let Some(timeout_ms) = call.timeout_ms {
            data.insert("timeout_ms".to_string(), json!(timeout_ms));
        }
        Value::Object(data)
    }

    fn hostcall_ledger_end_data(
        call: &HostCallPayload,
        duration_ms: u64,
        result: &HostResultPayload,
    ) -> Value {
        let mut data = serde_json::Map::new();
        data.insert(
            "capability".to_string(),
            Value::String(call.capability.clone()),
        );
        data.insert("method".to_string(), Value::String(call.method.clone()));
        data.insert(
            "params_hash".to_string(),
            Value::String(hostcall_params_hash(&call.method, &call.params)),
        );
        if let Some(timeout_ms) = call.timeout_ms {
            data.insert("timeout_ms".to_string(), json!(timeout_ms));
        }
        data.insert("duration_ms".to_string(), json!(duration_ms));
        data.insert("is_error".to_string(), Value::Bool(result.is_error));
        if result.is_error {
            if let Some(error) = result.error.as_ref() {
                data.insert("error".to_string(), json!({ "code": error.code }));
            }
        }
        Value::Object(data)
    }

    #[test]
    fn hostcall_params_hash_is_stable_for_key_ordering() {
        let mut first = serde_json::Map::new();
        first.insert("b".to_string(), json!(2));
        first.insert("a".to_string(), json!(1));
        let first = Value::Object(first);

        let mut second = serde_json::Map::new();
        second.insert("a".to_string(), json!(1));
        second.insert("b".to_string(), json!(2));
        let second = Value::Object(second);

        assert_eq!(
            hostcall_params_hash("http", &first),
            hostcall_params_hash("http", &second)
        );
        assert_ne!(
            hostcall_params_hash("http", &first),
            hostcall_params_hash("tool", &first)
        );
    }

    #[test]
    fn hostcall_params_shape_hash_ignores_scalar_value_drift() {
        let first = json!({
            "url": "https://example.com/a",
            "headers": { "authorization": "Bearer abc" },
            "retries": 3,
            "flags": [true, false]
        });
        let second = json!({
            "url": "https://another.example/path",
            "headers": { "authorization": "Bearer xyz" },
            "retries": 99,
            "flags": [false, true]
        });
        assert_eq!(
            hostcall_params_shape_hash("http", &first),
            hostcall_params_shape_hash("http", &second),
            "shape hash should remain stable when only scalar values change"
        );
        assert_ne!(
            hostcall_params_shape_hash("http", &first),
            hostcall_params_shape_hash("tool", &first),
            "method remains part of the shape identity"
        );
    }

    #[test]
    fn runtime_hostcall_resource_target_class_detects_common_targets() {
        assert_eq!(
            runtime_hostcall_resource_target_class(
                "http",
                &json!({"url":"http://127.0.0.1:8080/health"})
            ),
            "network.private"
        );
        assert_eq!(
            runtime_hostcall_resource_target_class(
                "http",
                &json!({"url":"https://api.example.com/v1/messages"})
            ),
            "network.public"
        );
        assert_eq!(
            runtime_hostcall_resource_target_class(
                "tool",
                &json!({"name":"read","input":{"path":"README.md"}})
            ),
            "filesystem.tool"
        );
        assert_eq!(
            runtime_hostcall_resource_target_class("tool", &json!({"name":"bash","input":{}})),
            "subprocess.tool"
        );
    }

    #[test]
    fn hostcall_ledger_start_redacts_params_and_includes_hash() {
        let call = HostCallPayload {
            call_id: "host-ledger-1".to_string(),
            capability: "env".to_string(),
            method: "env".to_string(),
            params: json!({ "name": "ANTHROPIC_API_KEY", "value": "sk-ant-SECRET" }),
            timeout_ms: Some(1234),
            cancel_token: None,
            context: None,
        };

        let data = hostcall_ledger_start_data(&call);
        let obj = data.as_object().expect("object");
        assert!(obj.get("params_hash").is_some());
        assert!(obj.get("params").is_none());

        let encoded = serde_json::to_string(&data).expect("serialize data");
        assert!(!encoded.contains("sk-ant-SECRET"));
        assert!(!encoded.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn hostcall_ledger_end_includes_error_code_when_is_error() {
        let call = HostCallPayload {
            call_id: "host-ledger-2".to_string(),
            capability: "exec".to_string(),
            method: "exec".to_string(),
            params: json!({ "cmd": "ls", "args": ["-la"] }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        let result = HostResultPayload {
            call_id: call.call_id.clone(),
            output: json!({}),
            is_error: true,
            error: Some(HostCallError {
                code: HostCallErrorCode::Denied,
                message: "Denied".to_string(),
                details: None,
                retryable: None,
            }),
            chunk: None,
        };

        let data = hostcall_ledger_end_data(&call, 10, &result);
        let obj = data.as_object().expect("object");
        assert_eq!(obj.get("is_error").and_then(Value::as_bool), Some(true));

        let error = obj
            .get("error")
            .and_then(Value::as_object)
            .expect("error object");
        assert_eq!(error.get("code").and_then(Value::as_str), Some("denied"));
    }

    #[derive(Debug, Clone)]
    struct CapturedEvent {
        level: tracing::Level,
        fields: std::collections::BTreeMap<String, String>,
    }

    #[derive(Clone, Default)]
    struct CaptureLayer {
        events: std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
    }

    impl CaptureLayer {
        fn snapshot(&self) -> Vec<CapturedEvent> {
            self.events.lock().expect("events mutex").clone()
        }
    }

    struct FieldVisitor<'a> {
        fields: &'a mut std::collections::BTreeMap<String, String>,
    }

    impl tracing::field::Visit for FieldVisitor<'_> {
        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    impl<S> tracing_subscriber::Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = std::collections::BTreeMap::new();
            let mut visitor = FieldVisitor {
                fields: &mut fields,
            };
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("events mutex")
                .push(CapturedEvent {
                    level: *event.metadata().level(),
                    fields,
                });
        }
    }

    fn capture_tracing_events<T>(f: impl FnOnce() -> T) -> (T, Vec<CapturedEvent>) {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let result = tracing::subscriber::with_default(subscriber, f);
        (result, capture.snapshot())
    }

    fn run_async<T, Fut>(future: Fut) -> T
    where
        Fut: std::future::Future<Output = T>,
    {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build asupersync runtime");
        runtime.block_on(future)
    }

    fn extension_manager_no_persisted_permissions() -> ExtensionManager {
        let manager = ExtensionManager::new();
        {
            let mut guard = manager.inner.lock().expect("extension manager lock");
            // Unit tests should be deterministic and should never mutate the user's
            // global permissions file.
            guard.permission_store = None;
            guard.policy_prompt_cache.clear();
        }
        manager
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn js_hostcall_prompt_policy_caches_user_allow_and_never_logs_raw_params() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();

        let manager = extension_manager_no_persisted_permissions();

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Prompt,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let request = crate::extensions_js::HostcallRequest {
            call_id: "hostcall-1".to_string(),
            kind: crate::extensions_js::HostcallKind::Tool {
                name: "custom_tool".to_string(),
            },
            payload: serde_json::json!({
                "token": "supersecret",
                "nested": { "apiKey": "sk-ant-SECRET" }
            }),
            trace_id: 0,
            extension_id: Some("ext-1".to_string()),
        };

        let request_cached = crate::extensions_js::HostcallRequest {
            call_id: "hostcall-2".to_string(),
            kind: crate::extensions_js::HostcallKind::Tool {
                name: "custom_tool".to_string(),
            },
            payload: serde_json::json!({ "token": "supersecret" }),
            trace_id: 0,
            extension_id: Some("ext-1".to_string()),
        };

        let ((first, second), events) = capture_tracing_events(|| {
            run_async(async {
                use asupersync::time::{timeout, wall_now};
                use std::time::Duration;

                let cx = asupersync::Cx::for_request();
                let (ui_tx, ui_rx) = asupersync::channel::mpsc::channel(8);
                manager.set_ui_sender(ui_tx);

                let ui_task = async {
                    let ui_request = timeout(wall_now(), Duration::from_secs(2), ui_rx.recv(&cx))
                        .await
                        .expect("timed out waiting for ui request")
                        .expect("ui request");
                    assert_eq!(ui_request.method, "confirm");

                    assert!(
                        manager.respond_ui(ExtensionUiResponse {
                            id: ui_request.id,
                            value: Some(serde_json::Value::Bool(true)),
                            cancelled: false,
                        }),
                        "respond_ui"
                    );

                    // Ensure the allow decision is cached (second hostcall should not prompt again).
                    if let Ok(Ok(_)) =
                        timeout(wall_now(), Duration::from_millis(200), ui_rx.recv(&cx)).await
                    {
                        panic!("unexpected second ui prompt");
                    }
                };

                let hostcalls = async {
                    let first = super::dispatch_hostcall(&host, request).await;
                    let second = super::dispatch_hostcall(&host, request_cached).await;
                    (first, second)
                };

                let ((), (first, second)) = futures::join!(ui_task, hostcalls);
                (first, second)
            })
        });

        assert!(matches!(first, HostcallOutcome::Error { code, .. } if code == "invalid_request"));
        assert!(matches!(second, HostcallOutcome::Error { code, .. } if code == "invalid_request"));

        let decision_events = events
            .iter()
            .filter(|event| {
                event
                    .fields
                    .get("event")
                    .is_some_and(|value| value.contains("policy.decision"))
            })
            .collect::<Vec<_>>();
        assert_eq!(decision_events.len(), 2);
        assert!(
            decision_events[0]
                .fields
                .get("reason")
                .is_some_and(|value| value.contains("prompt_user_allow")),
            "expected prompt_user_allow reason, got {:?}",
            decision_events[0].fields
        );
        assert!(
            decision_events[1]
                .fields
                .get("reason")
                .is_some_and(|value| value.contains("prompt_cache_allow")),
            "expected prompt_cache_allow reason, got {:?}",
            decision_events[1].fields
        );

        for event in &events {
            for value in event.fields.values() {
                assert!(
                    !value.contains("supersecret"),
                    "secret leaked into logs: {value}"
                );
                assert!(
                    !value.contains("sk-ant-SECRET"),
                    "api key leaked into logs: {value}"
                );
            }
        }

        let params_hash = decision_events[0]
            .fields
            .get("params_hash")
            .expect("params_hash");
        let params_hash = params_hash.trim_matches('"');
        assert_eq!(params_hash.len(), 64);
        assert!(params_hash.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn js_hostcall_strict_policy_denies_and_logs_reason() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();

        let mgr = ExtensionManager::new();
        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None)),
            manager_ref: Arc::downgrade(&mgr.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: vec!["read".to_string()],
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let request = crate::extensions_js::HostcallRequest {
            call_id: "hostcall-strict-1".to_string(),
            kind: crate::extensions_js::HostcallKind::Exec {
                cmd: "does-not-run".to_string(),
            },
            payload: serde_json::json!({}),
            trace_id: 0,
            extension_id: Some("ext-1".to_string()),
        };

        let (outcome, events) = capture_tracing_events(|| {
            run_async(async { super::dispatch_hostcall(&host, request).await })
        });

        assert!(matches!(outcome, HostcallOutcome::Error { code, .. } if code == "denied"));

        let decision = events.iter().find(|event| {
            event
                .fields
                .get("event")
                .is_some_and(|value| value.contains("policy.decision"))
        });
        let decision = decision.expect("policy.decision event");
        assert_eq!(decision.level, tracing::Level::WARN);
        assert!(
            decision
                .fields
                .get("reason")
                .is_some_and(|value| value.contains("not_in_default_caps"))
        );
        assert!(
            decision
                .fields
                .get("call_id")
                .is_some_and(|value| value.contains("hostcall-strict-1"))
        );
    }

    #[test]
    fn shared_dispatcher_logs_runtime_from_context() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let tools = Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None));
        let http = Arc::new(crate::connectors::http::HttpConnector::with_defaults());
        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Permissive,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: Vec::new(),
            ..Default::default()
        };
        let call = HostCallPayload {
            call_id: "runtime-log-1".to_string(),
            capability: "ui".to_string(),
            method: "ui".to_string(),
            params: serde_json::json!({ "op": "confirm" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        let (_result, events) = capture_tracing_events(|| {
            run_async(async {
                let ctx = HostCallContext {
                    runtime_name: "protocol",
                    extension_id: Some("ext-log"),
                    tools: &tools,
                    http: &http,
                    manager: None,
                    policy: &policy,
                    js_runtime: None,
                    interceptor: None,
                };
                dispatch_host_call_shared(&ctx, call).await
            })
        });

        let start = events.iter().find(|event| {
            event
                .fields
                .get("event")
                .is_some_and(|value| value.contains("host_call.start"))
        });
        let start = start.unwrap_or_else(|| {
            panic!(
                "host_call.start event not found; captured {} events: {:#?}",
                events.len(),
                events
            )
        });
        assert_eq!(
            start.fields.get("runtime").map(std::string::String::as_str),
            Some("protocol")
        );
    }

    #[test]
    fn js_hostcall_ui_missing_op_is_invalid_request() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let manager = extension_manager_no_persisted_permissions();

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: vec!["ui".to_string()],
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let request = crate::extensions_js::HostcallRequest {
            call_id: "hostcall-ui-missing-op".to_string(),
            kind: crate::extensions_js::HostcallKind::Ui { op: String::new() },
            payload: serde_json::json!({}),
            trace_id: 0,
            extension_id: Some("ext-ui".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, request).await });
        assert!(
            matches!(outcome, HostcallOutcome::Error { code, .. } if code == "invalid_request")
        );
    }

    #[test]
    fn js_hostcall_ui_timeout_maps_to_timeout_taxonomy() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let manager = extension_manager_no_persisted_permissions();
        let (ui_tx, _ui_rx) = mpsc::channel(8);
        manager.set_ui_sender(ui_tx);

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: vec!["ui".to_string()],
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let request = crate::extensions_js::HostcallRequest {
            call_id: "hostcall-ui-timeout".to_string(),
            kind: crate::extensions_js::HostcallKind::Ui {
                op: "confirm".to_string(),
            },
            payload: serde_json::json!({ "timeout": 10 }),
            trace_id: 0,
            extension_id: Some("ext-ui".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, request).await });
        assert!(matches!(outcome, HostcallOutcome::Error { code, .. } if code == "timeout"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn js_hostcall_capability_denial_matrix_emits_deterministic_errors_and_logs() {
        use std::sync::Arc;

        #[derive(Clone)]
        struct DenyCase {
            call_id: &'static str,
            kind: crate::extensions_js::HostcallKind,
            payload: serde_json::Value,
            capability: &'static str,
            reason: &'static str,
        }

        fn to_request(case: &DenyCase) -> crate::extensions_js::HostcallRequest {
            crate::extensions_js::HostcallRequest {
                call_id: case.call_id.to_string(),
                kind: case.kind.clone(),
                payload: case.payload.clone(),
                trace_id: 0,
                extension_id: Some("ext.test".to_string()),
            }
        }

        fn assert_denied(outcome: &HostcallOutcome, capability: &str, reason: &str) {
            match outcome {
                HostcallOutcome::Error { code, message } => {
                    assert_eq!(code, "denied");
                    assert!(
                        message.contains(&format!(
                            "Capability '{capability}' denied by policy ({reason})"
                        )),
                        "unexpected denial message: {message}"
                    );
                }
                other @ (HostcallOutcome::Success(_) | HostcallOutcome::StreamChunk { .. }) => {
                    panic!("expected denied outcome for capability={capability}, got {other:?}");
                }
            }
        }

        fn assert_policy_decision_logged(
            events: &[CapturedEvent],
            call_id: &str,
            capability: &str,
            reason: &str,
        ) {
            let matching = events
                .iter()
                .filter(|event| {
                    event
                        .fields
                        .get("event")
                        .is_some_and(|value| value.contains("policy.decision"))
                        && event
                            .fields
                            .get("call_id")
                            .is_some_and(|value| value.contains(call_id))
                })
                .collect::<Vec<_>>();

            assert!(
                !matching.is_empty(),
                "expected policy.decision log for call_id={call_id}; got events: {events:#?}"
            );

            assert!(
                matching.iter().any(|event| {
                    event.level == tracing::Level::WARN
                        && event
                            .fields
                            .get("capability")
                            .is_some_and(|value| value.contains(capability))
                        && event
                            .fields
                            .get("reason")
                            .is_some_and(|value| value.contains(reason))
                }),
                "expected WARN policy.decision with capability={capability} reason={reason} for call_id={call_id}; got: {matching:#?}"
            );
        }

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let tools = Arc::new(crate::tools::ToolRegistry::new(
            &["read", "write", "bash"],
            &cwd,
            None,
        ));

        // Strict: deny anything not in default_caps.
        let mgr_strict = ExtensionManager::new();
        let host_strict = JsRuntimeHost {
            tools: Arc::clone(&tools),
            manager_ref: Arc::downgrade(&mgr_strict.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: vec!["read".to_string()],
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let strict_cases = vec![
            DenyCase {
                call_id: "deny-strict-exec",
                kind: crate::extensions_js::HostcallKind::Exec {
                    cmd: "does-not-run".to_string(),
                },
                payload: serde_json::json!({}),
                capability: "exec",
                reason: "not_in_default_caps",
            },
            DenyCase {
                call_id: "deny-strict-http",
                kind: crate::extensions_js::HostcallKind::Http,
                payload: serde_json::json!({ "url": "https://example.com", "method": "GET" }),
                capability: "http",
                reason: "not_in_default_caps",
            },
            DenyCase {
                call_id: "deny-strict-session",
                kind: crate::extensions_js::HostcallKind::Session {
                    op: "get_name".to_string(),
                },
                payload: serde_json::json!({}),
                capability: "session",
                reason: "not_in_default_caps",
            },
            DenyCase {
                call_id: "deny-strict-ui",
                kind: crate::extensions_js::HostcallKind::Ui {
                    op: "confirm".to_string(),
                },
                payload: serde_json::json!({ "title": "t", "message": "m" }),
                capability: "ui",
                reason: "not_in_default_caps",
            },
            DenyCase {
                call_id: "deny-strict-events",
                kind: crate::extensions_js::HostcallKind::Events {
                    op: "getTools".to_string(),
                },
                payload: serde_json::json!({}),
                capability: "events",
                reason: "not_in_default_caps",
            },
            // Use a tool hostcall to cover filesystem-ish access (write capability).
            DenyCase {
                call_id: "deny-strict-write",
                kind: crate::extensions_js::HostcallKind::Tool {
                    name: "write".to_string(),
                },
                payload: serde_json::json!({ "path": "note.txt", "content": "hi" }),
                capability: "write",
                reason: "not_in_default_caps",
            },
        ];

        let (strict_outcomes, strict_events) = capture_tracing_events(|| {
            run_async(async {
                let mut out = Vec::new();
                for case in &strict_cases {
                    let outcome = super::dispatch_hostcall(&host_strict, to_request(case)).await;
                    out.push((case.call_id, case.capability, case.reason, outcome));
                }
                out
            })
        });

        for (call_id, capability, reason, outcome) in &strict_outcomes {
            assert_denied(outcome, capability, reason);
            assert_policy_decision_logged(&strict_events, call_id, capability, reason);
        }

        // Prompt: non-default capabilities trigger UI, simulate user deny for each capability.
        let manager_prompt = extension_manager_no_persisted_permissions();

        let host_prompt = JsRuntimeHost {
            tools: Arc::clone(&tools),
            manager_ref: Arc::downgrade(&manager_prompt.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Prompt,
                max_memory_mb: 256,
                default_caps: vec!["read".to_string()],
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let prompt_cases = strict_cases
            .iter()
            .map(|case| DenyCase {
                call_id: match case.call_id {
                    "deny-strict-exec" => "deny-prompt-exec",
                    "deny-strict-http" => "deny-prompt-http",
                    "deny-strict-session" => "deny-prompt-session",
                    "deny-strict-ui" => "deny-prompt-ui",
                    "deny-strict-events" => "deny-prompt-events",
                    "deny-strict-write" => "deny-prompt-write",
                    _ => "deny-prompt-unknown",
                },
                kind: case.kind.clone(),
                payload: case.payload.clone(),
                capability: case.capability,
                reason: "prompt_user_deny",
            })
            .collect::<Vec<_>>();

        let (prompt_outcomes, prompt_events) = capture_tracing_events(|| {
            run_async(async {
                use asupersync::time::{timeout, wall_now};
                use std::time::Duration;

                let cx = asupersync::Cx::for_request();
                let (ui_tx, ui_rx) = asupersync::channel::mpsc::channel(16);
                manager_prompt.set_ui_sender(ui_tx);
                let prompt_count = prompt_cases.len();

                let ui_task = async {
                    for _ in 0..prompt_count {
                        let ui_request =
                            timeout(wall_now(), Duration::from_secs(2), ui_rx.recv(&cx))
                                .await
                                .expect("timed out waiting for ui request")
                                .expect("ui request");
                        assert_eq!(ui_request.method, "confirm");

                        assert!(
                            manager_prompt.respond_ui(ExtensionUiResponse {
                                id: ui_request.id,
                                value: Some(serde_json::Value::Bool(false)),
                                cancelled: false,
                            }),
                            "respond_ui"
                        );
                    }

                    // Ensure we don't leak an extra prompt that would hang on future runs.
                    if let Ok(Ok(_)) =
                        timeout(wall_now(), Duration::from_millis(200), ui_rx.recv(&cx)).await
                    {
                        panic!("unexpected extra ui prompt");
                    }
                };

                let hostcalls = async {
                    let mut out = Vec::new();
                    for case in &prompt_cases {
                        let outcome =
                            super::dispatch_hostcall(&host_prompt, to_request(case)).await;
                        out.push((case.call_id, case.capability, case.reason, outcome));
                    }
                    out
                };

                let ((), out) = futures::join!(ui_task, hostcalls);
                out
            })
        });

        for (call_id, capability, reason, outcome) in &prompt_outcomes {
            assert_denied(outcome, capability, reason);
            assert_policy_decision_logged(&prompt_events, call_id, capability, reason);
        }

        // Permissive: deny_caps still takes precedence and must produce deterministic denial.
        let mgr_perm = ExtensionManager::new();
        let host_perm = JsRuntimeHost {
            tools,
            manager_ref: Arc::downgrade(&mgr_perm.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: vec!["http".to_string()],
                ..Default::default()
            },
            interceptor: None,
        };

        let perm_case = DenyCase {
            call_id: "deny-permissive-http",
            kind: crate::extensions_js::HostcallKind::Http,
            payload: serde_json::json!({ "url": "https://example.com" }),
            capability: "http",
            reason: "deny_caps",
        };

        let (perm_outcome, perm_events) = capture_tracing_events(|| {
            run_async(async { super::dispatch_hostcall(&host_perm, to_request(&perm_case)).await })
        });

        assert_denied(&perm_outcome, perm_case.capability, perm_case.reason);
        assert_policy_decision_logged(
            &perm_events,
            perm_case.call_id,
            perm_case.capability,
            perm_case.reason,
        );
    }

    #[test]
    fn js_hostcall_routes_write_and_read_tools_when_allowed() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();

        let mgr2 = ExtensionManager::new();
        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(
                &["read", "write"],
                &cwd,
                None,
            )),
            manager_ref: Arc::downgrade(&mgr2.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: vec!["read".to_string(), "write".to_string()],
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let write_request = crate::extensions_js::HostcallRequest {
            call_id: "hostcall-write".to_string(),
            kind: crate::extensions_js::HostcallKind::Tool {
                name: "write".to_string(),
            },
            payload: serde_json::json!({
                "path": "note.txt",
                "content": "hello"
            }),
            trace_id: 0,
            extension_id: Some("ext-1".to_string()),
        };

        let read_request = crate::extensions_js::HostcallRequest {
            call_id: "hostcall-read".to_string(),
            kind: crate::extensions_js::HostcallKind::Tool {
                name: "read".to_string(),
            },
            payload: serde_json::json!({ "path": "note.txt" }),
            trace_id: 0,
            extension_id: Some("ext-1".to_string()),
        };

        let ((write_outcome, read_outcome), events) = capture_tracing_events(|| {
            run_async(async {
                let write_outcome = super::dispatch_hostcall(&host, write_request).await;
                let read_outcome = super::dispatch_hostcall(&host, read_request).await;
                (write_outcome, read_outcome)
            })
        });

        assert!(matches!(write_outcome, HostcallOutcome::Success(_)));
        assert_eq!(
            std::fs::read_to_string(cwd.join("note.txt")).expect("read note.txt"),
            "hello"
        );

        let value = match read_outcome {
            HostcallOutcome::Success(value) => value,
            HostcallOutcome::Error { code, message } => {
                assert!(
                    code == "__expected_success__",
                    "expected read success, got error {code}: {message}"
                );
                return;
            }
            HostcallOutcome::StreamChunk {
                sequence,
                chunk,
                is_final,
            } => {
                panic!(
                    "expected read success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                );
            }
        };

        let encoded = serde_json::to_string(&value).expect("serialize read output");
        assert!(encoded.contains("hello"));

        let decisions = events
            .iter()
            .filter(|event| {
                event
                    .fields
                    .get("event")
                    .is_some_and(|value| value.contains("policy.decision"))
            })
            .collect::<Vec<_>>();
        assert_eq!(decisions.len(), 2);
        for decision in decisions {
            assert_eq!(decision.level, tracing::Level::INFO);
            assert!(
                decision
                    .fields
                    .get("reason")
                    .is_some_and(|value| value.contains("default_caps"))
            );
        }
    }

    #[test]
    fn events_get_active_tools_returns_all_when_none_set() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools =
                crate::tools::ToolRegistry::new(&["read", "bash", "edit"], Path::new("."), None);

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "getActiveTools", json!({}))
                    .await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            let tool_names: Vec<String> = value
                .get("tools")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
            assert_eq!(tool_names, vec!["read", "bash", "edit"]);
        });
    }

    #[test]
    fn events_get_active_tools_returns_filtered_list() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools =
                crate::tools::ToolRegistry::new(&["read", "bash", "edit"], Path::new("."), None);

            manager.set_active_tools(vec!["read".to_string(), "bash".to_string()]);

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "get_active_tools", json!({}))
                    .await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            let tool_names: Vec<String> = value
                .get("tools")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
            assert_eq!(tool_names, vec!["read", "bash"]);
        });
    }

    #[test]
    fn events_get_all_tools_returns_builtin_tools() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read", "bash"], Path::new("."), None);

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "getAllTools", json!({}))
                    .await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            let tool_list = value.get("tools").and_then(Value::as_array).unwrap();
            assert_eq!(tool_list.len(), 2);

            let names: Vec<&str> = tool_list
                .iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .collect();
            assert!(names.contains(&"read"));
            assert!(names.contains(&"bash"));

            // Each tool should have a description
            for tool in tool_list {
                assert!(tool.get("description").and_then(Value::as_str).is_some());
            }
        });
    }

    #[test]
    fn events_get_all_tools_includes_extension_tools() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            // Register an extension with a custom tool
            manager.register(RegisterPayload {
                name: "test-ext".to_string(),
                version: "1.0.0".to_string(),
                api_version: PROTOCOL_VERSION.to_string(),
                capabilities: Vec::new(),
                capability_manifest: None,
                tools: vec![json!({
                    "name": "custom_tool",
                    "label": "Custom Tool",
                    "description": "A custom extension tool",
                    "parameters": { "type": "object" }
                })],
                slash_commands: Vec::new(),
                shortcuts: Vec::new(),
                flags: Vec::new(),
                event_hooks: Vec::new(),
            });

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "get_all_tools", json!({}))
                    .await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            let tool_list = value.get("tools").and_then(Value::as_array).unwrap();
            assert_eq!(tool_list.len(), 2); // 1 built-in + 1 extension

            let names: Vec<&str> = tool_list
                .iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .collect();
            assert!(names.contains(&"read"));
            assert!(names.contains(&"custom_tool"));
        });
    }

    #[test]
    fn events_set_active_tools_changes_get_active_tools_result() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools =
                crate::tools::ToolRegistry::new(&["read", "bash", "edit"], Path::new("."), None);

            // Set active tools via hostcall
            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "setActiveTools",
                json!({ "tools": ["edit"] }),
            )
            .await;
            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            // Verify getActiveTools reflects the change
            let outcome =
                dispatch_hostcall_events("call-2", &manager, &tools, "getActiveTools", json!({}))
                    .await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            let tool_names: Vec<String> = value
                .get("tools")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
            assert_eq!(tool_names, vec!["edit"]);
        });
    }

    // ========================================================================
    // Extension Registration API tests (bd-1yh7)
    // ========================================================================

    // --- registerCommand tests ---

    #[test]
    fn register_command_stores_metadata() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerCommand",
                json!({ "name": "deploy", "description": "Deploy the app" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));
            assert!(manager.has_command("deploy"));

            let commands = manager.list_commands();
            let cmd = commands
                .iter()
                .find(|c| c.get("name").and_then(Value::as_str) == Some("deploy"))
                .expect("deploy command should exist");
            assert_eq!(
                cmd.get("description").and_then(Value::as_str),
                Some("Deploy the app")
            );
        });
    }

    #[test]
    fn register_command_empty_name_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerCommand",
                json!({ "name": "" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
            if let HostcallOutcome::Error { code, message } = outcome {
                assert_eq!(code, "invalid_request");
                assert!(message.contains("name is required"));
            }
        });
    }

    #[test]
    fn register_command_missing_name_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "registerCommand", json!({}))
                    .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
        });
    }

    #[test]
    fn register_command_no_description_ok() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerCommand",
                json!({ "name": "build" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));
            assert!(manager.has_command("build"));
        });
    }

    #[test]
    fn register_command_multiple_commands() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            for name in &["deploy", "build", "test"] {
                let outcome = dispatch_hostcall_events(
                    "call-1",
                    &manager,
                    &tools,
                    "registerCommand",
                    json!({ "name": name }),
                )
                .await;
                assert!(matches!(outcome, HostcallOutcome::Success(_)));
            }

            assert!(manager.has_command("deploy"));
            assert!(manager.has_command("build"));
            assert!(manager.has_command("test"));
            assert_eq!(manager.list_commands().len(), 3);
        });
    }

    #[test]
    fn register_command_via_register_payload() {
        let manager = ExtensionManager::new();
        manager.register(RegisterPayload {
            name: "test-ext".to_string(),
            version: "1.0.0".to_string(),
            api_version: PROTOCOL_VERSION.to_string(),
            capabilities: Vec::new(),
            capability_manifest: None,
            tools: Vec::new(),
            slash_commands: vec![
                json!({ "name": "deploy", "description": "Deploy" }),
                json!({ "name": "rollback", "description": "Rollback" }),
            ],
            shortcuts: Vec::new(),
            flags: Vec::new(),
            event_hooks: Vec::new(),
        });

        assert!(manager.has_command("deploy"));
        assert!(manager.has_command("rollback"));
        assert!(!manager.has_command("nonexistent"));

        let commands = manager.list_commands();
        assert_eq!(commands.len(), 2);
    }

    // --- registerFlag tests ---

    #[test]
    fn register_flag_stores_spec() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerFlag",
                json!({ "name": "verbose", "type": "bool", "default": false, "description": "Enable verbose output" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            let flags = manager.list_flags();
            assert_eq!(flags.len(), 1);
            let flag = &flags[0];
            assert_eq!(flag.get("name").and_then(Value::as_str), Some("verbose"));
            assert_eq!(flag.get("type").and_then(Value::as_str), Some("bool"));
            assert_eq!(flag.get("default").and_then(Value::as_bool), Some(false));
        });
    }

    #[test]
    fn register_flag_empty_name_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerFlag",
                json!({ "name": "", "type": "string" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
            if let HostcallOutcome::Error { code, message } = outcome {
                assert_eq!(code, "invalid_request");
                assert!(message.contains("name is required"));
            }
        });
    }

    #[test]
    fn register_flag_hostcall_deduplicates_by_name() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerFlag",
                json!({ "name": "output", "type": "string", "default": "json" }),
            )
            .await;

            dispatch_hostcall_events(
                "call-2",
                &manager,
                &tools,
                "registerFlag",
                json!({ "name": "output", "type": "string", "default": "yaml" }),
            )
            .await;

            let flags = manager.list_flags();
            assert_eq!(flags.len(), 1);
            assert_eq!(
                flags[0].get("default").and_then(Value::as_str),
                Some("yaml")
            );
        });
    }

    #[test]
    fn register_flag_multiple_types() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            for (name, ty, default) in [
                ("verbose", "bool", json!(false)),
                ("timeout", "number", json!(30)),
                ("format", "string", json!("json")),
            ] {
                dispatch_hostcall_events(
                    "call-1",
                    &manager,
                    &tools,
                    "registerFlag",
                    json!({ "name": name, "type": ty, "default": default }),
                )
                .await;
            }

            let flags = manager.list_flags();
            assert_eq!(flags.len(), 3);
        });
    }

    #[test]
    fn register_flag_via_register_payload() {
        let manager = ExtensionManager::new();
        manager.register(RegisterPayload {
            name: "test-ext".to_string(),
            version: "1.0.0".to_string(),
            api_version: PROTOCOL_VERSION.to_string(),
            capabilities: Vec::new(),
            capability_manifest: None,
            tools: Vec::new(),
            slash_commands: Vec::new(),
            shortcuts: Vec::new(),
            flags: vec![
                json!({ "name": "verbose", "type": "bool", "default": false }),
                json!({ "name": "format", "type": "string", "default": "json" }),
            ],
            event_hooks: Vec::new(),
        });

        let flags = manager.list_flags();
        assert_eq!(flags.len(), 2);
    }

    // --- registerProvider tests ---

    #[test]
    fn register_provider_stores_config() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerProvider",
                json!({
                    "id": "my-llm",
                    "api": "openai-completions",
                    "baseUrl": "https://api.example.com/v1",
                    "apiKey": "MY_API_KEY",
                    "models": [{ "id": "fast-1", "name": "Fast Model" }]
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            let providers = manager.extension_providers();
            assert_eq!(providers.len(), 1);
            assert_eq!(
                providers[0].get("id").and_then(Value::as_str),
                Some("my-llm")
            );
        });
    }

    #[test]
    fn register_provider_missing_id_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerProvider",
                json!({ "api": "openai-completions" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
            if let HostcallOutcome::Error { code, message } = outcome {
                assert_eq!(code, "invalid_request");
                assert!(message.contains("id is required"));
            }
        });
    }

    #[test]
    fn register_provider_missing_api_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerProvider",
                json!({ "id": "my-llm" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
            if let HostcallOutcome::Error { code, message } = outcome {
                assert_eq!(code, "invalid_request");
                assert!(message.contains("api is required"));
            }
        });
    }

    #[test]
    fn register_provider_unsupported_api_type_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerProvider",
                json!({ "id": "my-llm", "api": "custom-nonsense" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
            if let HostcallOutcome::Error { code, message } = outcome {
                assert_eq!(code, "invalid_request");
                assert!(message.contains("unsupported api type"));
            }
        });
    }

    #[test]
    fn register_provider_all_valid_api_types() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            for api in [
                "anthropic-messages",
                "openai-completions",
                "openai-responses",
                "google-generative-ai",
            ] {
                let outcome = dispatch_hostcall_events(
                    "call-1",
                    &manager,
                    &tools,
                    "registerProvider",
                    json!({ "id": format!("provider-{api}"), "api": api }),
                )
                .await;
                assert!(
                    matches!(outcome, HostcallOutcome::Success(_)),
                    "api type {api} should be accepted"
                );
            }

            assert_eq!(manager.extension_providers().len(), 4);
        });
    }

    #[test]
    fn register_provider_model_entries() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerProvider",
                json!({
                    "id": "my-llm",
                    "api": "openai-completions",
                    "baseUrl": "https://api.example.com/v1",
                    "models": [
                        { "id": "fast-1", "name": "Fast Model" },
                        { "id": "slow-1", "name": "Slow Model", "reasoning": true }
                    ]
                }),
            )
            .await;

            let entries = manager.extension_model_entries();
            assert_eq!(entries.len(), 2);
        });
    }

    #[test]
    fn register_provider_oauth_config_extracted() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-oauth",
                &manager,
                &tools,
                "registerProvider",
                json!({
                    "id": "oauth-llm",
                    "api": "openai-completions",
                    "baseUrl": "https://api.oauth-llm.com/v1",
                    "oauth": {
                        "authUrl": "https://auth.oauth-llm.com/authorize",
                        "tokenUrl": "https://auth.oauth-llm.com/token",
                        "clientId": "client-abc",
                        "scopes": ["read", "write", "admin"],
                        "redirectUri": "http://localhost:9999/callback"
                    },
                    "models": [
                        { "id": "oauth-model-1", "name": "OAuth Model" }
                    ]
                }),
            )
            .await;

            let entries = manager.extension_model_entries();
            assert_eq!(entries.len(), 1);
            let entry = &entries[0];
            let oauth = entry
                .oauth_config
                .as_ref()
                .expect("oauth_config should be present");
            assert_eq!(oauth.auth_url, "https://auth.oauth-llm.com/authorize");
            assert_eq!(oauth.token_url, "https://auth.oauth-llm.com/token");
            assert_eq!(oauth.client_id, "client-abc");
            assert_eq!(oauth.scopes, vec!["read", "write", "admin"]);
            assert_eq!(
                oauth.redirect_uri.as_deref(),
                Some("http://localhost:9999/callback")
            );
        });
    }

    #[test]
    fn register_provider_without_oauth_config_has_none() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-no-oauth",
                &manager,
                &tools,
                "registerProvider",
                json!({
                    "id": "plain-llm",
                    "api": "anthropic-messages",
                    "baseUrl": "https://api.plain-llm.com/v1",
                    "models": [
                        { "id": "plain-model", "name": "Plain Model" }
                    ]
                }),
            )
            .await;

            let entries = manager.extension_model_entries();
            assert_eq!(entries.len(), 1);
            assert!(entries[0].oauth_config.is_none());
        });
    }

    #[test]
    fn register_provider_oauth_missing_required_fields_ignored() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-bad-oauth",
                &manager,
                &tools,
                "registerProvider",
                json!({
                    "id": "bad-oauth-llm",
                    "api": "openai-completions",
                    "baseUrl": "https://api.bad.com/v1",
                    "oauth": {
                        "authUrl": "https://auth.bad.com/authorize",
                        "tokenUrl": "https://auth.bad.com/token"
                    },
                    "models": [
                        { "id": "bad-model", "name": "Bad Model" }
                    ]
                }),
            )
            .await;

            let entries = manager.extension_model_entries();
            assert_eq!(entries.len(), 1);
            assert!(entries[0].oauth_config.is_none());
        });
    }

    #[test]
    fn register_provider_oauth_no_redirect_uri() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-no-redirect",
                &manager,
                &tools,
                "registerProvider",
                json!({
                    "id": "no-redirect-llm",
                    "api": "openai-completions",
                    "baseUrl": "https://api.nr.com/v1",
                    "oauth": {
                        "authUrl": "https://auth.nr.com/authorize",
                        "tokenUrl": "https://auth.nr.com/token",
                        "clientId": "client-nr"
                    },
                    "models": [
                        { "id": "nr-model", "name": "NR Model" }
                    ]
                }),
            )
            .await;

            let entries = manager.extension_model_entries();
            assert_eq!(entries.len(), 1);
            let oauth = entries[0]
                .oauth_config
                .as_ref()
                .expect("oauth should be present");
            assert_eq!(oauth.client_id, "client-nr");
            assert!(oauth.redirect_uri.is_none());
            assert!(oauth.scopes.is_empty());
        });
    }

    // --- registerShortcut tests ---

    #[test]
    fn register_shortcut_via_payload() {
        let manager = ExtensionManager::new();
        manager.register(RegisterPayload {
            name: "test-ext".to_string(),
            version: "1.0.0".to_string(),
            api_version: PROTOCOL_VERSION.to_string(),
            capabilities: Vec::new(),
            capability_manifest: None,
            tools: Vec::new(),
            slash_commands: Vec::new(),
            shortcuts: vec![json!({
                "key": "Ctrl+Shift+D",
                "key_id": "ctrl+shift+d",
                "description": "Deploy shortcut"
            })],
            flags: Vec::new(),
            event_hooks: Vec::new(),
        });

        assert!(manager.has_shortcut("ctrl+shift+d"));
        assert!(!manager.has_shortcut("ctrl+x"));

        let shortcuts = manager.list_shortcuts();
        assert_eq!(shortcuts.len(), 1);
        assert_eq!(
            shortcuts[0].get("description").and_then(Value::as_str),
            Some("Deploy shortcut")
        );
    }

    #[test]
    fn register_shortcut_case_insensitive_lookup() {
        let manager = ExtensionManager::new();
        manager.register(RegisterPayload {
            name: "test-ext".to_string(),
            version: "1.0.0".to_string(),
            api_version: PROTOCOL_VERSION.to_string(),
            capabilities: Vec::new(),
            capability_manifest: None,
            tools: Vec::new(),
            slash_commands: Vec::new(),
            shortcuts: vec![json!({
                "key": "Ctrl+K",
                "key_id": "ctrl+k",
                "description": "Quick action"
            })],
            flags: Vec::new(),
            event_hooks: Vec::new(),
        });

        assert!(manager.has_shortcut("ctrl+k"));
        assert!(manager.has_shortcut("Ctrl+K"));
        assert!(manager.has_shortcut("CTRL+K"));
    }

    #[test]
    fn register_shortcut_multiple() {
        let manager = ExtensionManager::new();
        manager.register(RegisterPayload {
            name: "test-ext".to_string(),
            version: "1.0.0".to_string(),
            api_version: PROTOCOL_VERSION.to_string(),
            capabilities: Vec::new(),
            capability_manifest: None,
            tools: Vec::new(),
            slash_commands: Vec::new(),
            shortcuts: vec![
                json!({ "key": "Ctrl+K", "key_id": "ctrl+k", "description": "Action 1" }),
                json!({ "key": "Alt+D", "key_id": "alt+d", "description": "Action 2" }),
                json!({ "key": "F5", "key_id": "f5", "description": "Action 3" }),
            ],
            flags: Vec::new(),
            event_hooks: Vec::new(),
        });

        assert_eq!(manager.list_shortcuts().len(), 3);
        assert!(manager.has_shortcut("ctrl+k"));
        assert!(manager.has_shortcut("alt+d"));
        assert!(manager.has_shortcut("f5"));
    }

    // --- Combined registration tests ---

    #[test]
    fn register_all_apis_on_single_extension() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            // Register extension with commands, shortcuts, flags, and a tool
            manager.register(RegisterPayload {
                name: "full-ext".to_string(),
                version: "2.0.0".to_string(),
                api_version: PROTOCOL_VERSION.to_string(),
                capabilities: Vec::new(),
                capability_manifest: None,
                tools: vec![json!({
                    "name": "ext_tool",
                    "label": "Extension Tool",
                    "description": "A tool",
                    "parameters": { "type": "object" }
                })],
                slash_commands: vec![json!({ "name": "deploy", "description": "Deploy" })],
                shortcuts: vec![json!({
                    "key": "Ctrl+D",
                    "key_id": "ctrl+d",
                    "description": "Deploy shortcut"
                })],
                flags: vec![json!({ "name": "verbose", "type": "bool", "default": false })],
                event_hooks: vec!["tool_call".to_string()],
            });

            // Also register a provider via hostcall
            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerProvider",
                json!({
                    "id": "my-llm",
                    "api": "anthropic-messages",
                    "models": [{ "id": "model-1" }]
                }),
            )
            .await;

            // Verify everything is accessible
            assert!(manager.has_command("deploy"));
            assert!(manager.has_shortcut("ctrl+d"));
            assert_eq!(manager.list_commands().len(), 1);
            assert_eq!(manager.list_shortcuts().len(), 1);
            assert_eq!(manager.list_flags().len(), 1);
            assert_eq!(manager.extension_providers().len(), 1);
            assert_eq!(manager.extension_model_entries().len(), 1);
        });
    }

    // ========================================================================
    // Model Control API tests (bd-1rqs / bd-vs72)
    // ========================================================================

    #[test]
    fn events_get_model_returns_null_when_no_session() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "getModel", json!({})).await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert!(value.get("provider").unwrap().is_null());
            assert!(value.get("modelId").unwrap().is_null());
        });
    }

    #[test]
    fn events_set_model_updates_in_memory_state() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            // Set model via hostcall.
            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "setModel",
                json!({ "provider": "anthropic", "modelId": "claude-opus-4-5-20251101" }),
            )
            .await;
            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            // In-memory state should reflect the change.
            let (provider, model_id) = manager.current_model();
            assert_eq!(provider.as_deref(), Some("anthropic"));
            assert_eq!(model_id.as_deref(), Some("claude-opus-4-5-20251101"));
        });
    }

    #[test]
    fn events_get_thinking_level_returns_null_when_not_set() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "getThinkingLevel", json!({}))
                    .await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert!(value.get("thinkingLevel").unwrap().is_null());
        });
    }

    #[test]
    fn events_set_thinking_level_updates_and_reflects() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            // Set thinking level.
            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "setThinkingLevel",
                json!({ "thinkingLevel": "high" }),
            )
            .await;
            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            // In-memory state should reflect the change.
            assert_eq!(manager.current_thinking_level().as_deref(), Some("high"));

            // Getting via hostcall should also reflect.
            let outcome =
                dispatch_hostcall_events("call-2", &manager, &tools, "getThinkingLevel", json!({}))
                    .await;

            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert_eq!(
                value.get("thinkingLevel").and_then(Value::as_str),
                Some("high")
            );
        });
    }

    #[test]
    fn events_set_model_snake_case_variant() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "set_model",
                json!({ "provider": "openai", "model_id": "gpt-5.2" }),
            )
            .await;
            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            let (provider, model_id) = manager.current_model();
            assert_eq!(provider.as_deref(), Some("openai"));
            assert_eq!(model_id.as_deref(), Some("gpt-5.2"));
        });
    }

    #[test]
    fn events_set_thinking_level_empty_becomes_none() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            // Set a level first.
            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "setThinkingLevel",
                json!({ "thinkingLevel": "medium" }),
            )
            .await;
            assert_eq!(manager.current_thinking_level().as_deref(), Some("medium"));

            // Set empty string should clear (filter removes empty).
            dispatch_hostcall_events(
                "call-2",
                &manager,
                &tools,
                "setThinkingLevel",
                json!({ "thinkingLevel": "" }),
            )
            .await;
            assert!(manager.current_thinking_level().is_none());
        });
    }

    // ========================================================================
    // Session dispatch tests (bd-1rqs)
    // ========================================================================

    /// Minimal test session for session dispatch testing.
    struct MockSession {
        name: std::sync::Mutex<Option<String>>,
        labels: std::sync::Mutex<Vec<(String, Option<String>)>>,
        model: std::sync::Mutex<(Option<String>, Option<String>)>,
        thinking_level: std::sync::Mutex<Option<String>>,
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                name: std::sync::Mutex::new(None),
                labels: std::sync::Mutex::new(Vec::new()),
                model: std::sync::Mutex::new((None, None)),
                thinking_level: std::sync::Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl ExtensionSession for MockSession {
        async fn get_state(&self) -> Value {
            let name = self.name.lock().unwrap().clone();
            json!({ "sessionName": name })
        }
        async fn get_messages(&self) -> Vec<crate::session::SessionMessage> {
            Vec::new()
        }
        async fn get_entries(&self) -> Vec<Value> {
            Vec::new()
        }
        async fn get_branch(&self) -> Vec<Value> {
            Vec::new()
        }
        async fn set_name(&self, name: String) -> Result<()> {
            *self.name.lock().unwrap() = Some(name);
            Ok(())
        }
        async fn append_message(&self, _message: crate::session::SessionMessage) -> Result<()> {
            Ok(())
        }
        async fn append_custom_entry(
            &self,
            _custom_type: String,
            _data: Option<Value>,
        ) -> Result<()> {
            Ok(())
        }
        async fn set_model(&self, provider: String, model_id: String) -> Result<()> {
            *self.model.lock().unwrap() = (Some(provider), Some(model_id));
            Ok(())
        }
        async fn get_model(&self) -> (Option<String>, Option<String>) {
            self.model.lock().unwrap().clone()
        }
        async fn set_thinking_level(&self, level: String) -> Result<()> {
            *self.thinking_level.lock().unwrap() = Some(level);
            Ok(())
        }
        async fn get_thinking_level(&self) -> Option<String> {
            self.thinking_level.lock().unwrap().clone()
        }
        async fn set_label(&self, target_id: String, label: Option<String>) -> Result<()> {
            self.labels.lock().unwrap().push((target_id, label));
            Ok(())
        }
    }

    #[test]
    fn session_set_name_and_get_name() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            // Set name via session dispatch.
            let outcome = dispatch_hostcall_session(
                "call-1",
                &manager,
                "set_name",
                json!({ "name": "My Feature Work" }),
            )
            .await;
            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            // Get name via session dispatch.
            let outcome =
                dispatch_hostcall_session("call-2", &manager, "get_name", json!({})).await;
            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert_eq!(value.as_str(), Some("My Feature Work"));
        });
    }

    #[test]
    fn session_set_label_dispatches_to_session() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            let outcome = dispatch_hostcall_session(
                "call-1",
                &manager,
                "set_label",
                json!({ "targetId": "entry-42", "label": "important" }),
            )
            .await;
            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            {
                let labels = session.labels.lock().unwrap();
                assert_eq!(labels.len(), 1);
                assert_eq!(labels[0].0, "entry-42");
                assert_eq!(labels[0].1.as_deref(), Some("important"));
                drop(labels);
            }
        });
    }

    #[test]
    fn session_set_label_requires_target_id() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            let outcome = dispatch_hostcall_session(
                "call-1",
                &manager,
                "set_label",
                json!({ "label": "important" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
        });
    }

    #[test]
    fn session_set_label_null_label_clears() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            let outcome = dispatch_hostcall_session(
                "call-1",
                &manager,
                "set_label",
                json!({ "targetId": "entry-99" }),
            )
            .await;
            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            {
                let labels = session.labels.lock().unwrap();
                assert_eq!(labels.len(), 1);
                assert_eq!(labels[0].0, "entry-99");
                assert!(labels[0].1.is_none());
                drop(labels);
            }
        });
    }

    #[test]
    fn session_dispatch_fails_without_session() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();

            let outcome =
                dispatch_hostcall_session("call-1", &manager, "get_name", json!({})).await;
            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
        });
    }

    #[test]
    fn session_model_control_via_session_dispatch() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            // setModel via events should persist to session.
            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "setModel",
                json!({ "provider": "anthropic", "modelId": "claude-opus-4-5-20251101" }),
            )
            .await;

            // Verify session was updated.
            let (provider, model_id) = session.model.lock().unwrap().clone();
            assert_eq!(provider.as_deref(), Some("anthropic"));
            assert_eq!(model_id.as_deref(), Some("claude-opus-4-5-20251101"));

            // getModel via events should read from session.
            let outcome =
                dispatch_hostcall_events("call-2", &manager, &tools, "getModel", json!({})).await;
            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert_eq!(
                value.get("provider").and_then(Value::as_str),
                Some("anthropic")
            );
            assert_eq!(
                value.get("modelId").and_then(Value::as_str),
                Some("claude-opus-4-5-20251101")
            );
        });
    }

    #[test]
    fn session_thinking_level_via_session_dispatch() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            // setThinkingLevel via events should persist to session.
            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "setThinkingLevel",
                json!({ "thinkingLevel": "low" }),
            )
            .await;

            // Verify session was updated.
            let level = session.thinking_level.lock().unwrap().clone();
            assert_eq!(level.as_deref(), Some("low"));

            // getThinkingLevel via events should read from session.
            let outcome =
                dispatch_hostcall_events("call-2", &manager, &tools, "getThinkingLevel", json!({}))
                    .await;
            let value = match outcome {
                HostcallOutcome::Success(value) => value,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert_eq!(
                value.get("thinkingLevel").and_then(Value::as_str),
                Some("low")
            );
        });
    }

    // ========================================================================
    // MockHostActions for sendMessage / sendUserMessage tests
    // ========================================================================

    struct MockHostActions {
        messages: std::sync::Mutex<Vec<ExtensionSendMessage>>,
        user_messages: std::sync::Mutex<Vec<ExtensionSendUserMessage>>,
    }

    impl MockHostActions {
        fn new() -> Self {
            Self {
                messages: std::sync::Mutex::new(Vec::new()),
                user_messages: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ExtensionHostActions for MockHostActions {
        async fn send_message(&self, message: ExtensionSendMessage) -> Result<()> {
            self.messages.lock().unwrap().push(message);
            Ok(())
        }
        async fn send_user_message(&self, message: ExtensionSendUserMessage) -> Result<()> {
            self.user_messages.lock().unwrap().push(message);
            Ok(())
        }
    }

    // ========================================================================
    // sendMessage tests (bd-1rqs)
    // ========================================================================

    #[test]
    fn events_send_message_dispatches_to_host_actions() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
            let actions = Arc::new(MockHostActions::new());
            manager.set_host_actions(actions.clone());

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "sendMessage",
                json!({
                    "message": {
                        "customType": "status-update",
                        "content": "Deployment succeeded",
                        "display": true,
                        "details": { "version": "1.2.3" }
                    },
                    "options": {
                        "deliverAs": "followUp",
                        "triggerTurn": true
                    }
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));
            {
                let msgs = actions.messages.lock().unwrap();
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].custom_type, "status-update");
                assert_eq!(msgs[0].content, "Deployment succeeded");
                assert!(msgs[0].display);
                assert!(msgs[0].trigger_turn);
                assert!(msgs[0].details.is_some());
                drop(msgs);
            }
        });
    }

    #[test]
    fn events_send_message_requires_custom_type() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
            let actions = Arc::new(MockHostActions::new());
            manager.set_host_actions(actions.clone());

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "sendMessage",
                json!({
                    "message": {
                        "content": "No type here"
                    }
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
            // No message should have been dispatched.
            assert!(actions.messages.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn events_send_message_without_host_actions_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "sendMessage",
                json!({
                    "message": {
                        "customType": "test",
                        "content": "hello"
                    }
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
        });
    }

    // ========================================================================
    // sendUserMessage tests (bd-1rqs)
    // ========================================================================

    #[test]
    fn events_send_user_message_dispatches_to_host_actions() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
            let actions = Arc::new(MockHostActions::new());
            manager.set_host_actions(actions.clone());

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "sendUserMessage",
                json!({
                    "text": "Please review the PR",
                    "options": {
                        "deliverAs": "steer"
                    }
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));
            {
                let msgs = actions.user_messages.lock().unwrap();
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].text, "Please review the PR");
                drop(msgs);
            }
        });
    }

    #[test]
    fn events_send_user_message_empty_text_succeeds_noop() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
            let actions = Arc::new(MockHostActions::new());
            manager.set_host_actions(actions.clone());

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "sendUserMessage",
                json!({ "text": "  " }),
            )
            .await;

            // Empty text returns Success(null) without dispatching.
            assert!(matches!(outcome, HostcallOutcome::Success(_)));
            assert!(actions.user_messages.lock().unwrap().is_empty());
        });
    }

    // ========================================================================
    // appendEntry tests (bd-1rqs)
    // ========================================================================

    #[test]
    fn session_append_entry_dispatches_to_session() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            let outcome = dispatch_hostcall_session(
                "call-1",
                &manager,
                "append_entry",
                json!({
                    "customType": "bookmark",
                    "data": { "line": 42, "file": "main.rs" }
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));
        });
    }

    #[test]
    fn events_append_entry_dispatches_to_session() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "appendEntry",
                json!({
                    "customType": "annotation",
                    "data": { "note": "refactor candidate" }
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));
        });
    }

    #[test]
    fn events_append_entry_without_session_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "appendEntry",
                json!({
                    "customType": "annotation",
                    "data": { "note": "test" }
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
        });
    }

    #[test]
    fn session_unknown_op_returns_error() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let session = Arc::new(MockSession::new());
            manager.set_session(session.clone());

            let outcome =
                dispatch_hostcall_session("call-1", &manager, "nonexistent_op", json!({})).await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
        });
    }

    // --- registerFlag hostcall tests ---

    #[test]
    fn register_flag_via_hostcall() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerFlag",
                json!({
                    "name": "verbose",
                    "description": "Enable verbose output",
                    "type": "boolean",
                    "default": false
                }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Success(_)));

            let flags = manager.list_flags();
            assert_eq!(flags.len(), 1);
            assert_eq!(
                flags[0].get("name").and_then(Value::as_str),
                Some("verbose")
            );
            assert_eq!(
                flags[0].get("type").and_then(Value::as_str),
                Some("boolean")
            );
        });
    }

    #[test]
    fn register_flag_missing_name_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerFlag",
                json!({ "description": "No name" }),
            )
            .await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
            if let HostcallOutcome::Error { code, message } = outcome {
                assert_eq!(code, "invalid_request");
                assert!(message.contains("name is required"));
            }
        });
    }

    #[test]
    fn register_flag_dedup_last_write_wins() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerFlag",
                json!({ "name": "flag-a", "type": "string", "default": "v1" }),
            )
            .await;

            dispatch_hostcall_events(
                "call-2",
                &manager,
                &tools,
                "registerFlag",
                json!({ "name": "flag-a", "type": "string", "default": "v2" }),
            )
            .await;

            let flags = manager.list_flags();
            assert_eq!(flags.len(), 1);
            assert_eq!(flags[0].get("default").and_then(Value::as_str), Some("v2"));
        });
    }

    #[test]
    fn get_flag_returns_registered_flag() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "registerFlag",
                json!({ "name": "output-dir", "type": "string", "default": "/tmp" }),
            )
            .await;

            let outcome = dispatch_hostcall_events(
                "call-2",
                &manager,
                &tools,
                "getFlag",
                json!({ "name": "output-dir" }),
            )
            .await;

            let val = match outcome {
                HostcallOutcome::Success(val) => val,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert_eq!(val.get("name").and_then(Value::as_str), Some("output-dir"));
            assert_eq!(val.get("type").and_then(Value::as_str), Some("string"));
        });
    }

    #[test]
    fn get_flag_missing_name_fails() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome =
                dispatch_hostcall_events("call-1", &manager, &tools, "getFlag", json!({})).await;

            assert!(matches!(outcome, HostcallOutcome::Error { .. }));
        });
    }

    #[test]
    fn get_flag_unknown_returns_null() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            let outcome = dispatch_hostcall_events(
                "call-1",
                &manager,
                &tools,
                "getFlag",
                json!({ "name": "nonexistent" }),
            )
            .await;

            let val = match outcome {
                HostcallOutcome::Success(val) => val,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success with null, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success with null, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            assert!(val.is_null());
        });
    }

    #[test]
    fn list_flags_hostcall_returns_all() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);

            for flag_name in ["alpha", "beta", "gamma"] {
                dispatch_hostcall_events(
                    "call-1",
                    &manager,
                    &tools,
                    "registerFlag",
                    json!({ "name": flag_name, "type": "string" }),
                )
                .await;
            }

            let outcome =
                dispatch_hostcall_events("call-2", &manager, &tools, "listFlags", json!({})).await;

            let val = match outcome {
                HostcallOutcome::Success(val) => val,
                HostcallOutcome::Error { code, message } => {
                    unreachable!("expected success, got error {code}: {message}");
                }
                HostcallOutcome::StreamChunk {
                    sequence,
                    chunk,
                    is_final,
                } => {
                    unreachable!(
                        "expected success, got stream chunk seq={sequence} final={is_final}: {chunk}"
                    );
                }
            };
            let arr = val.as_array().expect("expected array");
            assert_eq!(arr.len(), 3);
        });
    }

    // --- provider_has_stream_simple tests ---

    #[test]
    fn provider_has_stream_simple_detects_flag() {
        let manager = ExtensionManager::new();
        manager.register_provider(json!({
            "id": "custom-provider",
            "api": "openai-completions",
            "hasStreamSimple": true,
        }));

        assert!(manager.provider_has_stream_simple("custom-provider"));
        assert!(!manager.provider_has_stream_simple("nonexistent"));
    }

    #[test]
    fn provider_has_stream_simple_false_when_not_set() {
        let manager = ExtensionManager::new();
        manager.register_provider(json!({
            "id": "standard-provider",
            "api": "openai-completions",
        }));

        assert!(!manager.provider_has_stream_simple("standard-provider"));
    }

    #[test]
    fn provider_has_stream_simple_empty_id_returns_false() {
        let manager = ExtensionManager::new();
        manager.register_provider(json!({
            "id": "custom-provider",
            "api": "openai-completions",
            "hasStreamSimple": true,
        }));

        assert!(!manager.provider_has_stream_simple(""));
        assert!(!manager.provider_has_stream_simple("  "));
    }

    // --- streamSimple JS runtime integration tests ---

    #[test]
    fn stream_simple_yields_chunks_in_order() {
        let manager = ExtensionManager::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");

        runtime.block_on(async move {
            let dir = tempdir().expect("tempdir");
            let entry_path = dir.path().join("ext.mjs");
            std::fs::write(
                &entry_path,
                r#"
                export default function init(pi) {
                    pi.registerProvider("stream-test", {
                        api: "openai-completions",
                        baseUrl: "https://not-used.example.com",
                        models: [{ id: "test-model", name: "Test Model" }],
                        streamSimple: async function*(model, context, options) {
                            yield "Hello";
                            yield " ";
                            yield "World";
                        }
                    });
                }
                "#,
            )
            .expect("write extension entry");

            let tools = Arc::new(crate::tools::ToolRegistry::new(&[], dir.path(), None));
            let js_runtime = JsExtensionRuntimeHandle::start(
                PiJsRuntimeConfig {
                    cwd: dir.path().display().to_string(),
                    ..Default::default()
                },
                Arc::clone(&tools),
                manager.clone(),
            )
            .await
            .expect("start js runtime");
            manager.set_js_runtime(js_runtime.clone());

            let spec = JsExtensionLoadSpec::from_entry_path(&entry_path).expect("load spec");
            manager
                .load_js_extensions(vec![spec])
                .await
                .expect("load extension");

            assert!(manager.provider_has_stream_simple("stream-test"));

            let stream_id = js_runtime
                .provider_stream_simple_start(
                    "stream-test".to_string(),
                    json!({"id": "test-model"}),
                    json!({"messages": []}),
                    json!({}),
                    30_000,
                )
                .await
                .expect("start stream");

            let mut chunks = Vec::new();
            while let Some(val) = js_runtime
                .provider_stream_simple_next(stream_id.clone(), 30_000)
                .await
                .expect("next")
            {
                chunks.push(val.as_str().unwrap_or_default().to_string());
            }

            assert_eq!(chunks, vec!["Hello", " ", "World"]);
        });
    }

    #[test]
    fn stream_simple_error_in_js_propagates() {
        let manager = ExtensionManager::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");

        runtime.block_on(async move {
            let dir = tempdir().expect("tempdir");
            let entry_path = dir.path().join("ext.mjs");
            std::fs::write(
                &entry_path,
                r#"
                export default function init(pi) {
                    pi.registerProvider("error-provider", {
                        api: "openai-completions",
                        baseUrl: "https://not-used.example.com",
                        models: [{ id: "err-model", name: "Error Model" }],
                        streamSimple: async function*(model, context, options) {
                            yield "partial";
                            throw new Error("stream explosion");
                        }
                    });
                }
                "#,
            )
            .expect("write extension entry");

            let tools = Arc::new(crate::tools::ToolRegistry::new(&[], dir.path(), None));
            let js_runtime = JsExtensionRuntimeHandle::start(
                PiJsRuntimeConfig {
                    cwd: dir.path().display().to_string(),
                    ..Default::default()
                },
                Arc::clone(&tools),
                manager.clone(),
            )
            .await
            .expect("start js runtime");
            manager.set_js_runtime(js_runtime.clone());

            let spec = JsExtensionLoadSpec::from_entry_path(&entry_path).expect("load spec");
            manager
                .load_js_extensions(vec![spec])
                .await
                .expect("load extension");

            let stream_id = js_runtime
                .provider_stream_simple_start(
                    "error-provider".to_string(),
                    json!({"id": "err-model"}),
                    json!({"messages": []}),
                    json!({}),
                    30_000,
                )
                .await
                .expect("start stream");

            // First chunk should succeed.
            let first = js_runtime
                .provider_stream_simple_next(stream_id.clone(), 30_000)
                .await
                .expect("first next");
            assert!(first.is_some());
            assert_eq!(first.unwrap().as_str().unwrap_or_default(), "partial");

            // Second call should fail with the JS error.
            let result = js_runtime
                .provider_stream_simple_next(stream_id.clone(), 30_000)
                .await;
            assert!(result.is_err(), "expected error from JS throw");
        });
    }

    #[test]
    fn stream_simple_cancel_stops_iteration() {
        let manager = ExtensionManager::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");

        runtime.block_on(async move {
            let dir = tempdir().expect("tempdir");
            let entry_path = dir.path().join("ext.mjs");
            std::fs::write(
                &entry_path,
                r#"
                export default function init(pi) {
                    pi.registerProvider("cancel-provider", {
                        api: "openai-completions",
                        baseUrl: "https://not-used.example.com",
                        models: [{ id: "cancel-model", name: "Cancel Model" }],
                        streamSimple: async function*(model, context, options) {
                            yield "chunk-1";
                            yield "chunk-2";
                            yield "chunk-3";
                            yield "chunk-4";
                        }
                    });
                }
                "#,
            )
            .expect("write extension entry");

            let tools = Arc::new(crate::tools::ToolRegistry::new(&[], dir.path(), None));
            let js_runtime = JsExtensionRuntimeHandle::start(
                PiJsRuntimeConfig {
                    cwd: dir.path().display().to_string(),
                    ..Default::default()
                },
                Arc::clone(&tools),
                manager.clone(),
            )
            .await
            .expect("start js runtime");
            manager.set_js_runtime(js_runtime.clone());

            let spec = JsExtensionLoadSpec::from_entry_path(&entry_path).expect("load spec");
            manager
                .load_js_extensions(vec![spec])
                .await
                .expect("load extension");

            let stream_id = js_runtime
                .provider_stream_simple_start(
                    "cancel-provider".to_string(),
                    json!({"id": "cancel-model"}),
                    json!({"messages": []}),
                    json!({}),
                    30_000,
                )
                .await
                .expect("start stream");

            // Read first chunk.
            let first = js_runtime
                .provider_stream_simple_next(stream_id.clone(), 30_000)
                .await
                .expect("first next");
            assert!(first.is_some());

            // Cancel the stream.
            js_runtime
                .provider_stream_simple_cancel(stream_id.clone(), 30_000)
                .await
                .expect("cancel");

            // After cancel, next should return done.
            let after_cancel = js_runtime
                .provider_stream_simple_next(stream_id, 30_000)
                .await
                .expect("next after cancel");
            assert!(after_cancel.is_none(), "expected None after cancellation");
        });
    }

    // ========================================================================
    // Budget / structured concurrency tests (bd-2vie)
    // ========================================================================

    #[test]
    fn extension_manager_default_budget_is_infinite() {
        let manager = ExtensionManager::new();
        let budget = manager.budget();
        assert!(budget.deadline.is_none());
        assert_eq!(budget.poll_quota, u32::MAX);
        assert!(budget.cost_quota.is_none());
    }

    #[test]
    fn extension_manager_with_budget_stores_it() {
        let budget = Budget::with_deadline_secs(30);
        let manager = ExtensionManager::with_budget(budget);
        let stored = manager.budget();
        assert!(stored.deadline.is_some());
    }

    #[test]
    fn extension_manager_set_budget_updates() {
        let manager = ExtensionManager::new();
        assert!(manager.budget().deadline.is_none());

        manager.set_budget(Budget::with_deadline_secs(10));
        assert!(manager.budget().deadline.is_some());
    }

    #[test]
    fn extension_cx_returns_unbounded_by_default() {
        let manager = ExtensionManager::new();
        let cx = manager.extension_cx();
        // Default budget is infinite, so Cx should be unbounded.
        assert!(cx.budget().deadline.is_none());
    }

    #[test]
    fn extension_cx_applies_configured_budget() {
        let manager = ExtensionManager::with_budget(Budget::with_deadline_secs(30));
        let cx = manager.extension_cx();
        assert!(cx.budget().deadline.is_some());
    }

    #[test]
    fn effective_timeout_no_budget_returns_operation_timeout() {
        let manager = ExtensionManager::new();
        assert_eq!(manager.effective_timeout(5_000), 5_000);
        assert_eq!(manager.effective_timeout(30_000), 30_000);
    }

    #[test]
    fn effective_timeout_with_tight_budget_caps_timeout() {
        // Set a budget that expires 2 seconds from now.
        let budget = Budget {
            deadline: Some(wall_now() + Duration::from_secs(2)),
            ..Budget::INFINITE
        };
        let manager = ExtensionManager::with_budget(budget);
        // A 30s operation timeout should be capped to ~2s.
        let effective = manager.effective_timeout(30_000);
        assert!(effective <= 2_100, "expected <=2100ms, got {effective}");
        assert!(effective >= 1_000, "expected >=1000ms, got {effective}");
    }

    #[test]
    fn effective_timeout_with_expired_budget_returns_zero() {
        // Set a budget with a deadline in the past.
        let budget = Budget {
            deadline: Some(wall_now()),
            ..Budget::INFINITE
        };
        let manager = ExtensionManager::with_budget(budget);
        // Should return 0 (or close to it) since the deadline has passed.
        let effective = manager.effective_timeout(30_000);
        assert!(effective <= 1, "expected ~0ms, got {effective}");
    }

    #[test]
    fn effective_timeout_takes_min_of_budget_and_operation() {
        // Budget with a far-off deadline (60s) — operation timeout (5s) wins.
        let budget = Budget {
            deadline: Some(wall_now() + Duration::from_secs(60)),
            ..Budget::INFINITE
        };
        let manager = ExtensionManager::with_budget(budget);
        let effective = manager.effective_timeout(5_000);
        assert_eq!(effective, 5_000);
    }

    #[test]
    fn extension_manager_shutdown_without_runtime_is_noop() {
        asupersync::test_utils::run_test(|| async {
            let manager = ExtensionManager::new();
            let ok = manager.shutdown(Duration::from_secs(1)).await;
            assert!(ok, "shutdown without runtime should succeed");
        });
    }

    // ========================================================================
    // LabRuntime deterministic testing (bd-48tv)
    // ========================================================================

    mod lab_runtime_tests {
        use super::*;
        use asupersync::{LabConfig, LabRuntime};
        use std::sync::atomic::{AtomicBool, Ordering};

        /// Create a LabRuntime configured for extension testing.
        fn ext_lab(seed: u64) -> LabRuntime {
            LabRuntime::new(LabConfig::new(seed).trace_capacity(4096))
        }

        #[test]
        fn lab_oneshot_recv_completes_under_virtual_time() {
            let mut runtime = ext_lab(42);
            let root = runtime.state.create_root_region(Budget::INFINITE);

            let (tx, rx) = oneshot::channel::<String>();
            let received = Arc::new(std::sync::Mutex::new(None));
            let received_clone = received.clone();

            // Sender task: send a value immediately.
            let (send_task, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("cx");
                    tx.send(&cx, "hello".to_string()).expect("send");
                })
                .expect("create send task");
            runtime.scheduler.lock().unwrap().schedule(send_task, 0);

            // Receiver task: receive with infinite budget.
            let (recv_task, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("cx");
                    if let Ok(val) = rx.recv(&cx).await {
                        *received_clone.lock().unwrap() = Some(val);
                    }
                })
                .expect("create recv task");
            runtime.scheduler.lock().unwrap().schedule(recv_task, 0);

            runtime.run_until_quiescent();

            let val = received.lock().unwrap().take();
            assert_eq!(val.as_deref(), Some("hello"));
        }

        #[test]
        fn lab_sender_drop_unblocks_receiver() {
            // Simulates extension runtime shutdown: when the JS runtime
            // thread exits, it drops the reply sender. The ExtensionManager
            // method (receiver) should see an error, not hang.
            let mut runtime = ext_lab(0xDEAD);
            let root = runtime.state.create_root_region(Budget::INFINITE);

            let (tx, rx) = oneshot::channel::<String>();
            let got_error = Arc::new(AtomicBool::new(false));
            let got_error_clone = got_error.clone();

            // Task 1: drop the sender (simulates runtime exit).
            let (drop_task, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    drop(tx);
                })
                .expect("create drop task");
            runtime.scheduler.lock().unwrap().schedule(drop_task, 0);

            // Task 2: try to recv (should fail because sender was dropped).
            let (recv_task, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("cx");
                    if rx.recv(&cx).await.is_err() {
                        got_error_clone.store(true, Ordering::SeqCst);
                    }
                })
                .expect("create recv task");
            runtime.scheduler.lock().unwrap().schedule(recv_task, 0);

            runtime.run_until_quiescent();

            assert!(
                got_error.load(Ordering::SeqCst),
                "recv should fail when sender is dropped (runtime shutdown)"
            );
        }

        #[test]
        fn lab_extension_dispatch_deterministic_across_runs() {
            // Running the same scenario with the same seed must produce
            // identical results — verifying deterministic scheduling.
            fn run_once(seed: u64) -> Vec<String> {
                let mut runtime = ext_lab(seed);
                let root = runtime.state.create_root_region(Budget::INFINITE);

                let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

                for i in 0..5 {
                    let log = Arc::clone(&log);
                    let (task_id, _) = runtime
                        .state
                        .create_task(root, Budget::INFINITE, async move {
                            let cx = Cx::current().expect("cx");
                            // Simulate extension dispatch: send/recv on a channel.
                            let (tx, rx) = oneshot::channel::<u32>();
                            tx.send(&cx, i).expect("send");
                            let val = rx.recv(&cx).await.expect("recv");
                            log.lock().unwrap().push(format!("task-{val}"));
                        })
                        .expect("create task");
                    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
                }

                runtime.run_until_quiescent();
                log.lock().unwrap().clone()
            }

            let run_a = run_once(0xCAFE);
            let run_b = run_once(0xCAFE);
            assert_eq!(run_a, run_b, "same seed must produce same execution order");
        }

        #[test]
        fn lab_multiworker_extension_dispatch_deterministic() {
            // Under multi-worker scheduling, same seed must still produce
            // deterministic results.
            fn run_multi(seed: u64) -> Vec<String> {
                let config = LabConfig::new(seed).worker_count(4).trace_capacity(4096);
                let mut runtime = LabRuntime::new(config);
                let root = runtime.state.create_root_region(Budget::INFINITE);

                let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

                for i in 0..8 {
                    let log = Arc::clone(&log);
                    let (task_id, _) = runtime
                        .state
                        .create_task(root, Budget::INFINITE, async move {
                            // Yield to interleave with other tasks.
                            asupersync::runtime::yield_now().await;
                            log.lock().unwrap().push(format!("w-{i}"));
                        })
                        .expect("create task");
                    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
                }

                runtime.run_until_quiescent();
                log.lock().unwrap().clone()
            }

            let run_a = run_multi(0xF00D);
            let run_b = run_multi(0xF00D);
            assert_eq!(
                run_a, run_b,
                "multi-worker execution must be deterministic with same seed"
            );
        }
    }

    // ========================================================================
    // Extension lifecycle / structured concurrency tests (bd-2vie)
    // ========================================================================

    mod lifecycle {
        use super::*;

        #[test]
        fn region_shutdown_returns_true_when_no_runtime() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let region = ExtensionRegion::new(manager);
                let ok = region.shutdown().await;
                assert!(ok, "shutdown should succeed when no JS runtime is running");
            });
        }

        #[test]
        fn region_shutdown_is_idempotent() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let region = ExtensionRegion::new(manager);
                assert!(region.shutdown().await);
                assert!(region.shutdown().await, "second shutdown should be no-op");
                assert!(region.shutdown().await, "third shutdown should be no-op");
            });
        }

        #[test]
        fn manager_shutdown_clears_js_runtime_handle() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let tools = Arc::new(crate::tools::ToolRegistry::new(
                    &[],
                    Path::new("/tmp"),
                    None,
                ));

                let runtime = JsExtensionRuntimeHandle::start(
                    PiJsRuntimeConfig {
                        cwd: "/tmp".to_string(),
                        ..Default::default()
                    },
                    Arc::clone(&tools),
                    manager.clone(),
                )
                .await
                .expect("start js runtime");
                manager.set_js_runtime(runtime);

                assert!(
                    manager.js_runtime().is_some(),
                    "runtime should be set before shutdown"
                );

                let ok = manager.shutdown(Duration::from_secs(5)).await;
                assert!(ok, "shutdown should succeed");
                assert!(
                    manager.js_runtime().is_none(),
                    "runtime should be cleared after shutdown"
                );
            });
        }

        #[test]
        fn runtime_shutdown_treats_closed_exit_signal_as_success() {
            asupersync::test_utils::run_test(|| async {
                let (sender, _rx) = mpsc::channel(1);
                let (exit_tx, exit_rx) = oneshot::channel::<()>();
                drop(exit_tx);

                let runtime = JsExtensionRuntimeHandle {
                    sender,
                    exit_signal: Arc::new(Mutex::new(Some(exit_rx))),
                };

                let ok = runtime.shutdown(Duration::from_secs(1)).await;
                assert!(
                    ok,
                    "closed exit signal means runtime is already gone; shutdown should succeed"
                );
            });
        }

        #[test]
        fn region_with_runtime_shuts_down_cleanly() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let tools = Arc::new(crate::tools::ToolRegistry::new(
                    &[],
                    Path::new("/tmp"),
                    None,
                ));

                let runtime = JsExtensionRuntimeHandle::start(
                    PiJsRuntimeConfig {
                        cwd: "/tmp".to_string(),
                        ..Default::default()
                    },
                    Arc::clone(&tools),
                    manager.clone(),
                )
                .await
                .expect("start js runtime");
                manager.set_js_runtime(runtime);

                let region = ExtensionRegion::new(manager);
                let ok = region.shutdown().await;
                assert!(ok, "region shutdown with active runtime should succeed");
                assert!(
                    region.manager().js_runtime().is_none(),
                    "runtime should be cleared after region shutdown"
                );
            });
        }

        #[test]
        fn region_with_custom_budget() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let region = ExtensionRegion::with_budget(manager, Duration::from_millis(100));
                assert!(region.shutdown().await);
            });
        }

        #[test]
        fn region_drop_after_explicit_shutdown_is_silent() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let tools = Arc::new(crate::tools::ToolRegistry::new(
                    &[],
                    Path::new("/tmp"),
                    None,
                ));

                let runtime = JsExtensionRuntimeHandle::start(
                    PiJsRuntimeConfig {
                        cwd: "/tmp".to_string(),
                        ..Default::default()
                    },
                    Arc::clone(&tools),
                    manager.clone(),
                )
                .await
                .expect("start js runtime");
                manager.set_js_runtime(runtime);

                let region = ExtensionRegion::new(manager);
                region.shutdown().await;
                // Drop should be silent (no warning) since shutdown was called.
                drop(region);
            });
        }

        #[test]
        fn region_into_inner_prevents_drop_shutdown() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let region = ExtensionRegion::new(manager);
                let _manager = region.into_inner();
                // into_inner marks shutdown_done=true, so drop is silent.
            });
        }

        #[test]
        fn weak_ref_breaks_arc_cycle() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let weak = Arc::downgrade(&manager.inner);
                let tools = Arc::new(crate::tools::ToolRegistry::new(
                    &[],
                    Path::new("/tmp"),
                    None,
                ));

                let runtime = JsExtensionRuntimeHandle::start(
                    PiJsRuntimeConfig {
                        cwd: "/tmp".to_string(),
                        ..Default::default()
                    },
                    Arc::clone(&tools),
                    manager.clone(),
                )
                .await
                .expect("start js runtime");
                manager.set_js_runtime(runtime.clone());

                // Shut down the runtime so the thread exits
                // and drops its host (which held a Weak, not Arc).
                let ok = runtime.shutdown(Duration::from_secs(5)).await;
                assert!(ok, "shutdown should succeed");

                // Give the thread a moment to fully exit.
                asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(50))
                    .await;

                // Now drop the manager — Arc should be the only strong ref.
                drop(manager);
                assert!(
                    weak.upgrade().is_none(),
                    "After shutdown + drop, the inner Arc should be deallocated \
                     (Weak breaks the cycle)"
                );
            });
        }

        #[test]
        fn runtime_processes_commands_before_shutdown() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let tools = Arc::new(crate::tools::ToolRegistry::new(
                    &[],
                    Path::new("/tmp"),
                    None,
                ));

                let runtime = JsExtensionRuntimeHandle::start(
                    PiJsRuntimeConfig {
                        cwd: "/tmp".to_string(),
                        ..Default::default()
                    },
                    Arc::clone(&tools),
                    manager.clone(),
                )
                .await
                .expect("start js runtime");
                manager.set_js_runtime(runtime.clone());

                // Send a command (get_registered_tools) that the runtime
                // thread must process before we shut down.
                let tool_defs = runtime.get_registered_tools().await;
                assert!(
                    tool_defs.is_ok(),
                    "get_registered_tools should succeed on a fresh runtime"
                );
                assert!(tool_defs.unwrap().is_empty(), "no tools registered yet");

                // Pump the runtime to verify it's responsive.
                let pump = runtime.pump_once().await;
                assert!(pump.is_ok(), "pump_once should succeed");

                // Now shut down.
                let ok = runtime.shutdown(Duration::from_secs(5)).await;
                assert!(ok, "shutdown after command processing should succeed");
            });
        }
    }

    // ========================================================================
    // Cancellation budget tests (bd-1yr1)
    // ========================================================================

    mod budget_tests {
        use super::*;
        use asupersync::channel::oneshot;

        #[test]
        fn cx_with_deadline_has_finite_budget() {
            asupersync::test_utils::run_test(|| async {
                let before = wall_now();
                let cx = cx_with_deadline(500);
                let budget = cx.budget();
                assert!(
                    budget.deadline.is_some(),
                    "cx_with_deadline should set a deadline"
                );
                let deadline = budget.deadline.unwrap();
                let expected = before + Duration::from_millis(500);
                // Deadline should be within 100ms of expected (accounting for wall clock drift).
                let delta_ns = if deadline >= expected {
                    deadline.duration_since(expected)
                } else {
                    expected.duration_since(deadline)
                };
                assert!(
                    u128::from(delta_ns) <= Duration::from_millis(100).as_nanos(),
                    "deadline {deadline:?} should be ~500ms after {before:?}"
                );
            });
        }

        #[test]
        fn budget_constants_are_reasonable() {
            const _: () = {
                assert!(EXTENSION_EVENT_TIMEOUT_MS >= 1_000);
                assert!(EXTENSION_EVENT_TIMEOUT_MS <= 60_000);
                assert!(EXTENSION_TOOL_BUDGET_MS >= 5_000);
                assert!(EXTENSION_TOOL_BUDGET_MS <= 300_000);
                assert!(EXTENSION_COMMAND_BUDGET_MS >= 5_000);
                assert!(EXTENSION_SHORTCUT_BUDGET_MS >= 5_000);
                assert!(EXTENSION_UI_BUDGET_MS >= 100);
                assert!(EXTENSION_UI_BUDGET_MS <= 10_000);
                assert!(EXTENSION_PROVIDER_BUDGET_MS >= 30_000);
                assert!(EXTENSION_QUERY_BUDGET_MS >= 1_000);
                assert!(EXTENSION_LOAD_BUDGET_MS >= 10_000);
            };
        }

        #[test]
        fn tight_deadline_cancels_blocked_recv() {
            asupersync::test_utils::run_test(|| async {
                // Create a oneshot where nobody will send.
                let (_tx, rx) = oneshot::channel::<()>();
                let cx = cx_with_deadline(50); // 50ms deadline
                let start = wall_now();
                let result = timeout(wall_now(), Duration::from_millis(50), rx.recv(&cx)).await;
                let elapsed = Duration::from_nanos(wall_now().duration_since(start));
                assert!(
                    result.is_err() || matches!(result, Ok(Err(_))),
                    "recv should fail when the deadline is exceeded; got: {result:?}"
                );
                // Should not hang forever.
                assert!(
                    elapsed < Duration::from_secs(1),
                    "recv should be cancelled quickly, took {elapsed:?}"
                );
            });
        }

        #[test]
        fn tight_deadline_cancels_runtime_send() {
            asupersync::test_utils::run_test(|| async {
                let manager = ExtensionManager::new();
                let tools = Arc::new(crate::tools::ToolRegistry::new(
                    &[],
                    Path::new("/tmp"),
                    None,
                ));

                let runtime = JsExtensionRuntimeHandle::start(
                    PiJsRuntimeConfig {
                        cwd: "/tmp".to_string(),
                        ..Default::default()
                    },
                    Arc::clone(&tools),
                    manager.clone(),
                )
                .await
                .expect("start js runtime");
                manager.set_js_runtime(runtime.clone());

                // Shut down the runtime first so channels close.
                runtime.shutdown(Duration::from_secs(2)).await;

                // Now try get_registered_tools — the send should fail
                // because the channel is closed, regardless of budget.
                let result = runtime.get_registered_tools().await;
                assert!(result.is_err(), "send to shut-down runtime should fail");
            });
        }
    }

    // ========================================================================
    // Property-based tests for hostcall dispatch (bd-3pcw)
    // ========================================================================

    mod proptest_dispatch {
        use super::*;
        use proptest::prelude::*;

        fn op_strategy() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("getActiveTools".to_string()),
                Just("getAllTools".to_string()),
                Just("setActiveTools".to_string()),
                Just("appendEntry".to_string()),
                Just("sendMessage".to_string()),
                Just("sendUserMessage".to_string()),
                Just("registerCommand".to_string()),
                Just("registerProvider".to_string()),
                Just("registerFlag".to_string()),
                Just("getModel".to_string()),
                Just("setModel".to_string()),
                Just("getThinkingLevel".to_string()),
                Just("setThinkingLevel".to_string()),
                Just("getFlag".to_string()),
                Just("listFlags".to_string()),
                Just("get_state".to_string()),
                Just("get_name".to_string()),
                Just("set_name".to_string()),
                Just("set_label".to_string()),
                Just("append_entry".to_string()),
                Just("get_messages".to_string()),
                "[a-zA-Z_]{0,30}".prop_map(|s| s),
            ]
        }

        fn json_leaf() -> impl Strategy<Value = Value> {
            prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::Bool),
                any::<i64>().prop_map(|n| json!(n)),
                ".{0,64}".prop_map(|s| json!(s)),
            ]
        }

        fn json_value() -> impl Strategy<Value = Value> {
            json_leaf().prop_recursive(3, 64, 8, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                    prop::collection::btree_map("[a-zA-Z0-9_]{1,10}", inner, 0..4).prop_map(
                        |map| {
                            let mut out = serde_json::Map::new();
                            for (key, value) in map {
                                out.insert(key, value);
                            }
                            Value::Object(out)
                        }
                    ),
                ]
            })
        }

        fn unicode_string() -> impl Strategy<Value = String> {
            prop_oneof![
                Just(String::new()),
                Just("\u{0}".to_string()),
                Just("\u{FEFF}BOM-prefixed".to_string()),
                Just("café résumé naïve".to_string()),
                Just("\u{200B}zero-width\u{200B}".to_string()),
                Just("\u{1F600}\u{1F4A9}\u{1F680}".to_string()),
                Just("日本語テスト".to_string()),
                Just("مرحبا".to_string()),
                "\\PC{1,100}".prop_map(|s| s),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 512,
                max_shrink_iters: 0,
                .. ProptestConfig::default()
            })]

            #[test]
            fn events_dispatch_never_panics(op in op_strategy(), payload in json_value()) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);
                    let _outcome = dispatch_hostcall_events(
                        "prop-call", &manager, &tools, &op, payload,
                    ).await;
                });
            }

            #[test]
            fn session_dispatch_never_panics(op in op_strategy(), payload in json_value()) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let session = Arc::new(MockSession::new());
                    manager.set_session(session);
                    let _outcome = dispatch_hostcall_session(
                        "prop-call", &manager, &op, payload,
                    ).await;
                });
            }

            #[test]
            fn events_unknown_op_returns_error(
                op in "[a-z]{1,20}".prop_filter("not a known op", |s| {
                    let norm = s.trim().to_ascii_lowercase();
                    !matches!(
                        norm.as_str(),
                        "getactivetools" | "get_active_tools"
                            | "getalltools" | "get_all_tools"
                            | "setactivetools" | "set_active_tools"
                            | "appendentry" | "append_entry"
                            | "sendmessage" | "send_message"
                            | "sendusermessage" | "send_user_message"
                            | "registercommand" | "register_command"
                            | "registershortcut" | "register_shortcut"
                            | "registerprovider" | "register_provider"
                            | "registerflag" | "register_flag"
                            | "getmodel" | "get_model"
                            | "setmodel" | "set_model"
                            | "getthinkinglevel" | "get_thinking_level"
                            | "setthinkinglevel" | "set_thinking_level"
                            | "getflag" | "get_flag"
                            | "listflags" | "list_flags"
                            | "emit"
                    )
                }),
                payload in json_value(),
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);
                    let outcome = dispatch_hostcall_events(
                        "prop-call", &manager, &tools, &op, payload,
                    ).await;
                    assert!(
                        matches!(outcome, HostcallOutcome::Error { .. }),
                        "unknown op '{op}' should produce error, got: {outcome:?}"
                    );
                });
            }

            #[test]
            fn session_unknown_op_returns_error(
                op in "[a-z]{1,20}".prop_filter("not a known session op", |s| {
                    let norm = s.trim().to_ascii_lowercase();
                    !matches!(
                        norm.as_str(),
                        "get_state" | "getstate"
                            | "get_messages" | "getmessages"
                            | "get_entries" | "getentries"
                            | "get_branch" | "getbranch"
                            | "get_file" | "getfile"
                            | "get_name" | "getname"
                            | "set_name" | "setname"
                            | "append_message" | "appendmessage"
                            | "append_entry" | "appendentry"
                            | "set_label" | "setlabel"
                    )
                }),
                payload in json_value(),
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let session = Arc::new(MockSession::new());
                    manager.set_session(session);
                    let outcome = dispatch_hostcall_session(
                        "prop-call", &manager, &op, payload,
                    ).await;
                    assert!(
                        matches!(outcome, HostcallOutcome::Error { .. }),
                        "unknown session op '{op}' should produce error, got: {outcome:?}"
                    );
                });
            }

            #[test]
            fn events_unicode_payloads_safe(
                op in op_strategy(),
                key in unicode_string(),
                value in unicode_string(),
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let tools = crate::tools::ToolRegistry::new(&["read"], Path::new("."), None);
                    let actions = Arc::new(MockHostActions::new());
                    manager.set_host_actions(actions);
                    let session = Arc::new(MockSession::new());
                    manager.set_session(session);
                    let payload = json!({ key: value });
                    let _outcome = dispatch_hostcall_events(
                        "prop-call", &manager, &tools, &op, payload,
                    ).await;
                });
            }

            #[test]
            fn session_unicode_payloads_safe(
                op in op_strategy(),
                key in unicode_string(),
                value in unicode_string(),
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let session = Arc::new(MockSession::new());
                    manager.set_session(session);
                    let payload = json!({ key: value });
                    let _outcome = dispatch_hostcall_session(
                        "prop-call", &manager, &op, payload,
                    ).await;
                });
            }

            #[test]
            fn events_send_message_requires_custom_type(payload in json_value()) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);
                    let actions = Arc::new(MockHostActions::new());
                    manager.set_host_actions(actions.clone());
                    let message = match payload {
                        Value::Object(map) => {
                            let mut filtered = map;
                            filtered.remove("customType");
                            filtered.remove("custom_type");
                            Value::Object(filtered)
                        }
                        other => other,
                    };
                    let mut obj = serde_json::Map::new();
                    obj.insert("message".to_string(), message);
                    let outcome = dispatch_hostcall_events(
                        "prop-call", &manager, &tools, "sendMessage",
                        Value::Object(obj),
                    ).await;
                    assert!(
                        matches!(outcome, HostcallOutcome::Error { .. }),
                        "sendMessage without customType should error, got: {outcome:?}"
                    );
                    assert_eq!(actions.messages.lock().unwrap().len(), 0);
                });
            }

            #[test]
            fn session_dispatch_without_session_returns_error(
                op in op_strategy(),
                payload in json_value(),
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let outcome = dispatch_hostcall_session(
                        "prop-call", &manager, &op, payload,
                    ).await;
                    assert!(
                        matches!(outcome, HostcallOutcome::Error { .. }),
                        "session dispatch without session should error, got: {outcome:?}"
                    );
                });
            }

            #[test]
            fn events_model_state_consistent(
                providers in prop::collection::vec("[a-z]{1,10}", 1..8),
                models in prop::collection::vec("[a-z]{1,10}", 1..8),
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);
                    let count = providers.len().min(models.len());
                    for i in 0..count {
                        let _ = dispatch_hostcall_events(
                            "prop-call", &manager, &tools, "setModel",
                            json!({ "provider": providers[i], "modelId": models[i] }),
                        ).await;
                    }
                    let outcome = dispatch_hostcall_events(
                        "prop-call", &manager, &tools, "getModel", json!({}),
                    ).await;
                    if let HostcallOutcome::Success(value) = outcome {
                        let last = count - 1;
                        assert_eq!(
                            value.get("provider").and_then(Value::as_str),
                            Some(providers[last].as_str())
                        );
                        assert_eq!(
                            value.get("modelId").and_then(Value::as_str),
                            Some(models[last].as_str())
                        );
                    }
                });
            }

            #[test]
            fn events_thinking_level_state_consistent(
                levels in prop::collection::vec(
                    prop_oneof![
                        Just("low".to_string()),
                        Just("medium".to_string()),
                        Just("high".to_string()),
                        Just("xhigh".to_string()),
                        "[a-z]{1,10}".prop_map(|s| s),
                    ],
                    1..10,
                )
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);
                    for level in &levels {
                        let _ = dispatch_hostcall_events(
                            "prop-call", &manager, &tools, "setThinkingLevel",
                            json!({ "thinkingLevel": level }),
                        ).await;
                    }
                    let outcome = dispatch_hostcall_events(
                        "prop-call", &manager, &tools, "getThinkingLevel", json!({}),
                    ).await;
                    if let HostcallOutcome::Success(value) = outcome {
                        assert_eq!(
                            value.get("thinkingLevel").and_then(Value::as_str),
                            Some(levels.last().unwrap().as_str())
                        );
                    }
                });
            }

            #[test]
            fn events_active_tools_roundtrip(
                tools_list in prop::collection::vec("[a-z]{1,10}", 0..8)
            ) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let tools = crate::tools::ToolRegistry::new(&[], Path::new("."), None);
                    let _ = dispatch_hostcall_events(
                        "prop-call", &manager, &tools, "setActiveTools",
                        json!({ "tools": tools_list }),
                    ).await;
                    let expected = manager.active_tools();
                    assert_eq!(expected, Some(tools_list));
                });
            }

            #[test]
            fn session_set_label_requires_target_id(label in ".*") {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let session = Arc::new(MockSession::new());
                    manager.set_session(session);
                    let outcome = dispatch_hostcall_session(
                        "prop-call", &manager, "set_label",
                        json!({ "targetId": "", "label": label }),
                    ).await;
                    assert!(
                        matches!(outcome, HostcallOutcome::Error { .. }),
                        "set_label with empty targetId should error"
                    );
                    let outcome2 = dispatch_hostcall_session(
                        "prop-call", &manager, "set_label",
                        json!({ "label": label }),
                    ).await;
                    assert!(
                        matches!(outcome2, HostcallOutcome::Error { .. }),
                        "set_label without targetId should error"
                    );
                });
            }

            #[test]
            fn session_name_roundtrip(name in unicode_string()) {
                asupersync::test_utils::run_test(|| async move {
                    let manager = ExtensionManager::new();
                    let session = Arc::new(MockSession::new());
                    manager.set_session(session);
                    let _ = dispatch_hostcall_session(
                        "prop-call", &manager, "set_name",
                        json!({ "name": name }),
                    ).await;
                    let outcome = dispatch_hostcall_session(
                        "prop-call", &manager, "get_name", json!({}),
                    ).await;
                    if let HostcallOutcome::Success(value) = outcome {
                        let got = value.as_str().unwrap_or_default();
                        assert_eq!(got, &name);
                    }
                });
            }
        }
    }

    // ========================================================================
    // Shared dispatcher tests (bd-1uy.1.3)
    // ========================================================================

    /// Build a permissive `HostCallContext` for testing dispatch behaviour.
    fn test_host_call_context<'a>(
        tools: &'a ToolRegistry,
        http: &'a HttpConnector,
        policy: &'a ExtensionPolicy,
    ) -> HostCallContext<'a>
    where
        'a: 'a,
    {
        HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools,
            http,
            manager: None,
            policy,
            js_runtime: None,
            interceptor: None,
        }
    }

    fn permissive_policy() -> ExtensionPolicy {
        ExtensionPolicy {
            mode: ExtensionPolicyMode::Permissive,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: Vec::new(),
            ..Default::default()
        }
    }

    fn deny_all_policy() -> ExtensionPolicy {
        ExtensionPolicy {
            mode: ExtensionPolicyMode::Strict,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: vec![
                "read".to_string(),
                "write".to_string(),
                "exec".to_string(),
                "http".to_string(),
                "tool".to_string(),
                "session".to_string(),
                "ui".to_string(),
                "events".to_string(),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn shared_dispatch_unknown_tool_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-1".to_string(),
            capability: "tool".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "nonexistent_tool", "input": {} }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error, "expected error for unknown tool");
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
            assert!(
                err.message.contains("Unknown tool"),
                "message should mention unknown tool, got: {}",
                err.message
            );
            // output must be object per spec (not null)
            assert!(result.output.is_object(), "output must be {{}} on error");
        });
    }

    #[test]
    fn shared_dispatch_denied_by_policy() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = deny_all_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-deny".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "read", "input": { "path": "/etc/passwd" } }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error, "expected denial");
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("denied"),
                "message should mention denial, got: {}",
                err.message
            );
        });
    }

    #[test]
    fn shared_dispatch_policy_denial_skips_runtime_risk_ledger() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = deny_all_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 256,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "call-deny-no-risk".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "read", "input": { "path": "README.md" } }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(
                result.is_error,
                "policy deny should short-circuit execution"
            );
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::Denied);

            let ledger = manager.runtime_risk_ledger_snapshot();
            assert!(
                ledger.is_empty(),
                "runtime risk ledger must remain empty when policy denies the call"
            );
        });
    }

    #[test]
    fn shared_dispatch_prompt_without_manager_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Prompt,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: Vec::new(),
            ..Default::default()
        };
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-prompt-no-manager".to_string(),
            capability: "exec".to_string(),
            method: "exec".to_string(),
            params: json!({ "cmd": "echo", "args": ["hi"] }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(
                result.is_error,
                "prompt flow must fail closed without manager"
            );
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("(shutdown)"),
                "expected shutdown reason in fail-closed denial, got: {}",
                err.message
            );
        });
    }

    #[test]
    fn shared_dispatch_runtime_risk_disabled_is_isomorphic() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let baseline_ctx = test_host_call_context(&tools, &http, &policy);

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: false,
            ..Default::default()
        });
        let risk_ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "call-risk-off".to_string(),
            capability: "log".to_string(),
            method: "log".to_string(),
            params: json!({ "level": "info", "message": "isomorphism" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let baseline = dispatch_host_call_shared(&baseline_ctx, call.clone()).await;
            let with_risk = dispatch_host_call_shared(&risk_ctx, call).await;
            assert_eq!(baseline.is_error, with_risk.is_error);
            assert_eq!(baseline.error.is_some(), with_risk.error.is_some());
            if let (Some(a), Some(b)) = (baseline.error, with_risk.error) {
                assert_eq!(a.code, b.code);
                assert_eq!(a.message, b.message);
            }
        });
    }

    #[test]
    fn shared_dispatch_runtime_risk_hardens_exec_calls() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "call-risk-harden".to_string(),
            capability: "exec".to_string(),
            method: "exec".to_string(),
            params: json!({ "cmd": "echo", "args": ["hello"] }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error, "exec should be denied by risk hardening");
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("runtime risk"),
                "expected runtime risk denial, got: {}",
                err.message
            );

            let ledger = manager.runtime_risk_ledger_snapshot();
            assert!(!ledger.is_empty(), "risk ledger should record decisions");
            let last = ledger.last().expect("last ledger entry");
            assert_ne!(last.selected_action, RuntimeRiskAction::Allow);
            assert!(
                !last.ledger_hash.is_empty(),
                "ledger entry should include hash chain"
            );
        });
    }

    #[test]
    fn shared_dispatch_runtime_risk_quarantines_repeated_unsafe_attempts() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 32,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        run_async(async {
            let mut saw_quarantine = false;
            for idx in 0..6 {
                let call = HostCallPayload {
                    call_id: format!("call-risk-unsafe-{idx}"),
                    capability: "exec".to_string(),
                    method: "exec".to_string(),
                    params: json!({ "cmd": "echo", "args": [idx.to_string()] }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                };
                let result = dispatch_host_call_shared(&ctx, call).await;
                assert!(result.is_error, "unsafe exec attempt should be blocked");
                let err = result.error.expect("error payload");
                if err.message.contains("quarantined") {
                    saw_quarantine = true;
                }
            }

            assert!(
                saw_quarantine,
                "controller should eventually quarantine repeated unsafe attempts"
            );
            let ledger = manager.runtime_risk_ledger_snapshot();
            assert!(
                ledger
                    .iter()
                    .any(|entry| matches!(entry.selected_action, RuntimeRiskAction::Terminate)),
                "ledger should include at least one terminate action"
            );
        });
    }

    #[test]
    fn shared_dispatch_runtime_risk_ledger_is_tamper_evident() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        run_async(async {
            for idx in 0..3 {
                let call = HostCallPayload {
                    call_id: format!("call-risk-tamper-{idx}"),
                    capability: "exec".to_string(),
                    method: "exec".to_string(),
                    params: json!({ "cmd": "echo", "args": [idx.to_string()] }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                };
                let _ = dispatch_host_call_shared(&ctx, call).await;
            }

            let artifact = manager.runtime_risk_ledger_artifact();
            let verification = verify_runtime_risk_ledger_artifact(&artifact);
            assert!(verification.valid, "baseline ledger should verify");

            let mut tampered = artifact;
            let first = tampered.entries.first_mut().expect("at least one entry");
            first.risk_score = runtime_risk_clamp01(first.risk_score + 0.11);
            let tampered_verification = verify_runtime_risk_ledger_artifact(&tampered);
            assert!(
                !tampered_verification.valid,
                "tampered ledger should fail verification"
            );
            assert!(
                tampered_verification
                    .errors
                    .iter()
                    .any(|err| { err.code == "hash_mismatch" || err.code == "data_hash_mismatch" }),
                "expected hash/data mismatch in verification errors"
            );
        });
    }

    #[test]
    fn shared_dispatch_runtime_risk_ledger_replay_reconstructs_decision_path() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        run_async(async {
            for idx in 0..4 {
                let (capability, method) = if idx % 2 == 0 {
                    ("exec", "exec")
                } else {
                    ("log", "log")
                };
                let call = HostCallPayload {
                    call_id: format!("call-risk-replay-{idx}"),
                    capability: capability.to_string(),
                    method: method.to_string(),
                    params: json!({ "cmd": "echo", "args": [idx.to_string()], "message": "ok" }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                };
                let _ = dispatch_host_call_shared(&ctx, call).await;
            }

            let artifact = manager.runtime_risk_ledger_artifact();
            let replay =
                replay_runtime_risk_ledger_artifact(&artifact).expect("replay should verify");
            assert_eq!(replay.entry_count, artifact.entries.len());
            assert_eq!(replay.steps.len(), artifact.entries.len());
            for (idx, (step, entry)) in replay.steps.iter().zip(artifact.entries.iter()).enumerate()
            {
                assert_eq!(step.index, idx);
                assert_eq!(step.call_id, entry.call_id);
                assert_eq!(step.extension_id, entry.extension_id);
                assert_eq!(step.selected_action, entry.selected_action);
                assert_eq!(step.derived_state, entry.derived_state);
                assert_eq!(step.reason_codes, entry.triggers);
                assert_eq!(step.ledger_hash, entry.ledger_hash);
            }
        });
    }

    #[test]
    fn shared_dispatch_runtime_risk_ledger_verifies_after_ring_buffer_truncation() {
        let ledger_limit = 32;
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 32,
            ledger_limit,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        run_async(async {
            for idx in 0..48 {
                let call = HostCallPayload {
                    call_id: format!("call-risk-truncate-{idx}"),
                    capability: "exec".to_string(),
                    method: "exec".to_string(),
                    params: json!({ "cmd": "echo", "args": [idx.to_string()] }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                };
                let _ = dispatch_host_call_shared(&ctx, call).await;
            }

            let artifact = manager.runtime_risk_ledger_artifact();
            assert_eq!(
                artifact.entries.len(),
                ledger_limit,
                "ring buffer should truncate"
            );
            assert_eq!(artifact.entry_count, ledger_limit);
            assert!(
                artifact
                    .entries
                    .first()
                    .is_some_and(|entry| entry.prev_ledger_hash.is_some()),
                "truncated first entry should retain chain anchor"
            );

            let verification = verify_runtime_risk_ledger_artifact(&artifact);
            assert!(
                verification.valid,
                "truncated ledger segment should still verify"
            );
        });
    }

    #[test]
    fn runtime_risk_calibration_is_deterministic_for_identical_ledger() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        run_async(async {
            for idx in 0..6 {
                let (capability, method) = if idx % 3 == 0 {
                    ("log", "log")
                } else {
                    ("exec", "exec")
                };
                let call = HostCallPayload {
                    call_id: format!("call-risk-calibration-{idx}"),
                    capability: capability.to_string(),
                    method: method.to_string(),
                    params: json!({ "cmd": "echo", "args": [idx.to_string()], "message": "trace" }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                };
                let _ = dispatch_host_call_shared(&ctx, call).await;
            }

            let artifact = manager.runtime_risk_ledger_artifact();
            let config = RuntimeRiskCalibrationConfig::default();
            let first = calibrate_runtime_risk_from_ledger(&artifact, &config)
                .expect("first calibration should succeed");
            let second = calibrate_runtime_risk_from_ledger(&artifact, &config)
                .expect("second calibration should succeed");
            assert_eq!(
                first, second,
                "calibration output must be deterministic for identical input"
            );
        });
    }

    #[test]
    fn runtime_hostcall_feature_vectors_are_deterministic_for_identical_traces() {
        let run_trace = || {
            let dir = tempdir().expect("tempdir");
            let tools = ToolRegistry::new(&[], dir.path(), None);
            let http = HttpConnector::with_defaults();
            let policy = permissive_policy();

            let manager = ExtensionManager::new();
            manager.set_runtime_risk_config(RuntimeRiskConfig {
                enabled: true,
                alpha: 0.01,
                window_size: 64,
                ledger_limit: 512,
                decision_timeout_ms: 50,
                fail_closed: true,
            });

            let ctx = HostCallContext {
                runtime_name: "test",
                extension_id: Some("ext.test"),
                tools: &tools,
                http: &http,
                manager: Some(manager.clone()),
                policy: &policy,
                js_runtime: None,
                interceptor: None,
            };

            run_async(async {
                for idx in 0..10 {
                    let (capability, method, params) = if idx % 3 == 0 {
                        (
                            "exec",
                            "exec",
                            json!({ "cmd": "echo", "args": [idx.to_string()] }),
                        )
                    } else {
                        (
                            "log",
                            "log",
                            json!({ "level": "info", "message": format!("msg-{idx}") }),
                        )
                    };
                    let call = HostCallPayload {
                        call_id: format!("call-feature-det-{idx}"),
                        capability: capability.to_string(),
                        method: method.to_string(),
                        params,
                        timeout_ms: None,
                        cancel_token: None,
                        context: None,
                    };
                    let _ = dispatch_host_call_shared(&ctx, call).await;
                }
            });

            manager
                .runtime_hostcall_telemetry_snapshot()
                .into_iter()
                .map(|entry| entry.features)
                .collect::<Vec<_>>()
        };

        let first = run_trace();
        let second = run_trace();
        assert_eq!(first.len(), second.len(), "trace lengths should match");
        assert_eq!(
            first, second,
            "identical traces must yield identical feature vectors"
        );
    }

    #[test]
    fn runtime_hostcall_feature_extraction_overhead_stays_bounded() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        run_async(async {
            for idx in 0..96 {
                let call = HostCallPayload {
                    call_id: format!("call-feature-budget-{idx}"),
                    capability: "log".to_string(),
                    method: "log".to_string(),
                    params: json!({ "level": "info", "message": format!("budget-{idx}") }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                };
                let _ = dispatch_host_call_shared(&ctx, call).await;
            }
        });

        let telemetry = manager.runtime_hostcall_telemetry_snapshot();
        assert!(!telemetry.is_empty(), "telemetry should not be empty");

        let total_us = telemetry
            .iter()
            .map(|entry| u128::from(entry.extraction_latency_us))
            .sum::<u128>();
        let avg_us = total_us / u128::try_from(telemetry.len()).unwrap_or(1);
        let max_us = telemetry
            .iter()
            .map(|entry| entry.extraction_latency_us)
            .max()
            .unwrap_or(0);
        let budget = u128::from(RUNTIME_HOSTCALL_FEATURE_BUDGET_US);

        assert!(
            avg_us <= budget * 6,
            "average extraction overhead must remain bounded: avg={avg_us}us budget={RUNTIME_HOSTCALL_FEATURE_BUDGET_US}us"
        );
        assert!(
            u128::from(max_us) <= budget * 30,
            "worst-case extraction overhead too high: max={max_us}us budget={RUNTIME_HOSTCALL_FEATURE_BUDGET_US}us"
        );
    }

    #[test]
    fn runtime_hostcall_telemetry_schema_is_backward_readable() {
        let raw = json!({
            "schema": RUNTIME_HOSTCALL_TELEMETRY_SCHEMA_VERSION,
            "ts_ms": 1,
            "extension_id": "ext.legacy",
            "call_id": "legacy-1",
            "capability": "log",
            "method": "log",
            "params_hash": "abc",
            "args_shape_hash": "def",
            "resource_target_class": "telemetry.log",
            "policy_reason": "permissive",
            "policy_profile": "permissive",
            "latency_ms": 3,
            "outcome": "success",
            "selected_action": "allow",
            "reason_codes": []
        });
        let parsed: RuntimeHostcallTelemetryEvent =
            serde_json::from_value(raw).expect("deserialize legacy-compatible telemetry event");
        assert_eq!(
            parsed.features.schema,
            RUNTIME_HOSTCALL_FEATURE_SCHEMA_VERSION
        );
        assert_eq!(
            parsed.extraction_budget_us,
            RUNTIME_HOSTCALL_FEATURE_BUDGET_US
        );
        assert_eq!(
            parsed.redaction_summary,
            "params redacted via hash-only telemetry"
        );
        assert_eq!(
            parsed.explanation_level,
            RuntimeRiskExplanationLevelValue::Standard
        );
        assert_eq!(parsed.top_contributors.len(), 0);
        assert!(!parsed.budget_state.exhausted);
        assert_eq!(
            parsed.budget_state.term_budget,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET
        );
    }

    #[test]
    fn runtime_risk_explanation_order_is_deterministic_with_ties() {
        let features = RuntimeHostcallFeatureVector::default();
        let posterior = RuntimeRiskPosterior {
            safe_fast: 0.0,
            suspicious: 0.0,
            unsafe_: 0.0,
        };
        let expected_loss = RuntimeRiskExpectedLoss {
            allow: 0.0,
            harden: 0.0,
            deny: 0.0,
            terminate: 0.0,
        };
        let triggers = vec!["zeta".to_string(), "alpha".to_string()];

        let (level_a, summary_a, contributors_a, budget_a) = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.0,
            &posterior,
            &expected_loss,
            &features,
            &triggers,
            None,
            32,
            1_000,
        );
        let (level_b, summary_b, contributors_b, budget_b) = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.0,
            &posterior,
            &expected_loss,
            &features,
            &triggers,
            None,
            32,
            1_000,
        );

        assert_eq!(level_a, RuntimeRiskExplanationLevelValue::Standard);
        assert_eq!(level_a, level_b);
        assert_eq!(summary_a, summary_b);
        assert_eq!(contributors_a, contributors_b);
        assert_eq!(budget_a, budget_b);
        assert!(!budget_a.exhausted);
        assert!(
            contributors_a.len() >= 2,
            "expected at least two contributors for trigger tie test"
        );
        assert_eq!(contributors_a[0].code, "trigger_alpha");
        assert_eq!(contributors_a[1].code, "trigger_zeta");
    }

    #[test]
    fn runtime_risk_explanation_budget_exhaustion_falls_back_conservatively() {
        let features = RuntimeHostcallFeatureVector::default();
        let posterior = RuntimeRiskPosterior {
            safe_fast: 0.1,
            suspicious: 0.2,
            unsafe_: 0.3,
        };
        let expected_loss = RuntimeRiskExpectedLoss {
            allow: 1.0,
            harden: 0.9,
            deny: 0.8,
            terminate: 0.7,
        };
        let triggers = (0..16)
            .map(|idx| format!("trigger-{idx}"))
            .collect::<Vec<_>>();

        let (level, summary, contributors, budget) = runtime_risk_build_explanation(
            RuntimeRiskAction::Deny,
            0.7,
            &posterior,
            &expected_loss,
            &features,
            &triggers,
            Some("decision_timeout"),
            2,
            1_000,
        );

        assert_eq!(level, RuntimeRiskExplanationLevelValue::Compact);
        assert!(budget.exhausted);
        assert!(budget.fallback_mode);
        assert_eq!(budget.term_budget, 2);
        assert_eq!(contributors.len(), 2);
        assert_eq!(contributors[0].code, "action_deny");
        assert_eq!(contributors[1].code, "budget_exhausted");
        assert!(
            summary.contains("conservative_explanation_fallback=true"),
            "expected conservative fallback summary, got: {summary}"
        );
    }

    // ========================================================================
    // Quantile selection semantics: edge-case coverage (bd-xqipg)
    // ========================================================================

    #[test]
    fn quantile_empty_input_returns_zero() {
        let result = runtime_risk_quantile(vec![], 0.5);
        assert!(
            (result - 0.0).abs() < f64::EPSILON,
            "empty input should return 0.0, got {result}"
        );
    }

    #[test]
    fn quantile_single_element_bd_xqipg_full() {
        let result = runtime_risk_quantile(vec![0.42], 0.5);
        assert!(
            (result - 0.42).abs() < f64::EPSILON,
            "single-element input should return that element, got {result}"
        );
    }

    #[test]
    fn quantile_q0_returns_minimum() {
        let result = runtime_risk_quantile(vec![0.3, 0.1, 0.5, 0.9, 0.7], 0.0);
        assert!(
            (result - 0.1).abs() < f64::EPSILON,
            "q=0 should return minimum value 0.1, got {result}"
        );
    }

    #[test]
    fn quantile_q1_returns_maximum() {
        let result = runtime_risk_quantile(vec![0.3, 0.1, 0.5, 0.9, 0.7], 1.0);
        assert!(
            (result - 0.9).abs() < f64::EPSILON,
            "q=1 should return maximum value 0.9, got {result}"
        );
    }

    #[test]
    fn quantile_odd_sample_count_median_bd_xqipg_full() {
        // 5 elements sorted: [0.1, 0.3, 0.5, 0.7, 0.9]
        // q=0.5 → idx = round((5-1)*0.5) = round(2.0) = 2 → values[2] = 0.5
        let result = runtime_risk_quantile(vec![0.9, 0.1, 0.7, 0.3, 0.5], 0.5);
        assert!(
            (result - 0.5).abs() < f64::EPSILON,
            "odd-count median should be 0.5, got {result}"
        );
    }

    #[test]
    fn quantile_even_sample_count_median_bd_xqipg_full() {
        // 4 elements sorted: [0.1, 0.3, 0.7, 0.9]
        // q=0.5 → idx = round((4-1)*0.5) = round(1.5) = 2 → values[2] = 0.7
        let result = runtime_risk_quantile(vec![0.9, 0.1, 0.7, 0.3], 0.5);
        assert!(
            (result - 0.7).abs() < f64::EPSILON,
            "even-count median should be 0.7, got {result}"
        );
    }

    #[test]
    fn quantile_duplicate_values_bd_xqipg_full() {
        let result = runtime_risk_quantile(vec![0.5, 0.5, 0.5, 0.5], 0.75);
        assert!(
            (result - 0.5).abs() < f64::EPSILON,
            "all-duplicate input should return 0.5 for any q, got {result}"
        );
    }

    #[test]
    fn quantile_negative_q_clamps_to_zero() {
        // runtime_risk_clamp01(-0.5) → 0.0, so q=0 → minimum
        let result = runtime_risk_quantile(vec![0.2, 0.4, 0.6, 0.8], -0.5);
        assert!(
            (result - 0.2).abs() < f64::EPSILON,
            "negative q should clamp to 0 (minimum), got {result}"
        );
    }

    #[test]
    fn quantile_q_greater_than_one_clamps_to_one() {
        // runtime_risk_clamp01(2.0) → 1.0, so q=1 → maximum
        let result = runtime_risk_quantile(vec![0.2, 0.4, 0.6, 0.8], 2.0);
        assert!(
            (result - 0.8).abs() < f64::EPSILON,
            "q>1 should clamp to 1 (maximum), got {result}"
        );
    }

    #[test]
    fn quantile_nan_q_treated_as_zero_bd_xqipg_full() {
        // runtime_risk_clamp01(NaN) → 0.0, so returns minimum
        let result = runtime_risk_quantile(vec![0.2, 0.4, 0.6], f64::NAN);
        assert!(
            (result - 0.2).abs() < f64::EPSILON,
            "NaN q should be treated as 0 (minimum), got {result}"
        );
    }

    #[test]
    fn quantile_nan_values_sorted_consistently() {
        // NaN sorts to beginning due to partial_cmp unwrap_or(Equal)
        let result = runtime_risk_quantile(vec![0.5, f64::NAN, 0.3], 1.0);
        // After sort with NaN as Equal: order depends on sort stability.
        // Key invariant: function does not panic.
        assert!(
            result.is_nan() || result.is_finite(),
            "should not panic on NaN values"
        );
    }

    #[test]
    fn quantile_inf_values_handled() {
        let result = runtime_risk_quantile(vec![0.1, f64::INFINITY, 0.5], 1.0);
        assert!(
            result == f64::INFINITY,
            "q=1 with INFINITY should return INFINITY, got {result}"
        );
    }

    #[test]
    fn quantile_large_input_deterministic() {
        let values: Vec<f64> = (0..1000).map(|i| f64::from(i) / 1000.0).collect();
        let result_a = runtime_risk_quantile(values.clone(), 0.95);
        let result_b = runtime_risk_quantile(values, 0.95);
        assert!(
            (result_a - result_b).abs() < f64::EPSILON,
            "quantile must be deterministic across runs"
        );
        // q=0.95, idx = round((999)*0.95) = round(949.05) = 949 → values[949] = 0.949
        assert!(
            (result_a - 0.949).abs() < f64::EPSILON,
            "expected 0.949 for large sorted input at q=0.95, got {result_a}"
        );
    }

    #[test]
    fn quantile_two_elements() {
        // 2 elements sorted: [0.1, 0.9]
        // q=0.0 → idx = round(1*0) = 0 → 0.1
        // q=0.5 → idx = round(1*0.5) = round(0.5) = 0 → 0.1 (banker's rounding)
        // q=1.0 → idx = round(1*1) = 1 → 0.9
        let min = runtime_risk_quantile(vec![0.9, 0.1], 0.0);
        let max = runtime_risk_quantile(vec![0.9, 0.1], 1.0);
        assert!(
            (min - 0.1).abs() < f64::EPSILON,
            "q=0 with 2 elements should return min, got {min}"
        );
        assert!(
            (max - 0.9).abs() < f64::EPSILON,
            "q=1 with 2 elements should return max, got {max}"
        );
    }

    #[test]
    fn quantile_boundary_quartiles() {
        // 5 elements sorted: [0.0, 0.25, 0.5, 0.75, 1.0]
        // q=0.25 → idx = round(4*0.25) = round(1.0) = 1 → 0.25
        // q=0.75 → idx = round(4*0.75) = round(3.0) = 3 → 0.75
        let q25 = runtime_risk_quantile(vec![0.5, 0.0, 1.0, 0.75, 0.25], 0.25);
        let q75 = runtime_risk_quantile(vec![0.5, 0.0, 1.0, 0.75, 0.25], 0.75);
        assert!(
            (q25 - 0.25).abs() < f64::EPSILON,
            "25th percentile should be 0.25, got {q25}"
        );
        assert!(
            (q75 - 0.75).abs() < f64::EPSILON,
            "75th percentile should be 0.75, got {q75}"
        );
    }

    #[test]
    fn quantile_conformal_alpha_001() {
        // Mimics the actual conformal prediction use: q = 1 - alpha = 0.99
        // 10 residuals: [0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10]
        // q=0.99 → idx = round(9*0.99) = round(8.91) = 9 → 0.10
        let residuals: Vec<f64> = (1..=10).map(|i| f64::from(i) / 100.0).collect();
        let result = runtime_risk_quantile(residuals, 0.99);
        assert!(
            (result - 0.10).abs() < f64::EPSILON,
            "99th percentile of 10 residuals should be 0.10, got {result}"
        );
    }

    // ========================================================================
    // Per-extension override tests at hostcall boundary (bd-k5q5.4.3)
    // ========================================================================

    #[test]
    fn shared_dispatch_per_extension_deny_overrides_global_allow() {
        // Global policy allows "read", but ext.test has a per-extension deny
        // for "read". The dispatch boundary should deny the call.
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let mut policy = permissive_policy();
        policy.per_extension.insert(
            "ext.test".to_string(),
            ExtensionOverride {
                deny: vec!["read".to_string()],
                ..Default::default()
            },
        );
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-ext-deny".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "read", "input": { "path": "/tmp/test" } }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(
                result.is_error,
                "expected denial from per-extension override"
            );
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("denied"),
                "message should mention denial, got: {}",
                err.message
            );
        });
    }

    #[test]
    fn shared_dispatch_per_extension_allow_overrides_global_deny() {
        // Global policy denies "exec" (in deny_caps), but ext.trusted has a
        // per-extension allow for "exec". The dispatch boundary should allow it.
        // (It will fail downstream because no actual tool, but we check it's
        // not denied by policy.)
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let mut policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Strict,
            max_memory_mb: 256,
            default_caps: vec!["read".to_string()],
            deny_caps: vec!["exec".to_string()],
            per_extension: HashMap::new(),
            ..Default::default()
        };
        policy.per_extension.insert(
            "ext.trusted".to_string(),
            ExtensionOverride {
                allow: vec!["exec".to_string()],
                ..Default::default()
            },
        );
        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.trusted"),
            tools: &tools,
            http: &http,
            manager: None,
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "call-ext-allow".to_string(),
            capability: "exec".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "exec", "input": { "command": "echo hi" } }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            // Not denied by policy — may fail downstream (no tool registered),
            // but the error code should NOT be Denied.
            if result.is_error {
                let err = result.error.as_ref().expect("expected error payload");
                assert_ne!(
                    err.code,
                    HostCallErrorCode::Denied,
                    "per-extension allow should override global deny, got: {}",
                    err.message
                );
            }
        });
    }

    #[test]
    fn shared_dispatch_per_extension_deny_does_not_affect_other_extensions() {
        // ext.restricted has "read" denied, but ext.normal (ctx extension_id)
        // should still be allowed to read.
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let mut policy = permissive_policy();
        policy.per_extension.insert(
            "ext.restricted".to_string(),
            ExtensionOverride {
                deny: vec!["read".to_string()],
                ..Default::default()
            },
        );
        // ctx uses ext.test (not ext.restricted), so override should not apply
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-other-ext".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "read", "input": { "path": "/tmp/test" } }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            // Should NOT be denied — the deny override is for ext.restricted, not ext.test
            if result.is_error {
                let err = result.error.as_ref().expect("expected error payload");
                assert_ne!(
                    err.code,
                    HostCallErrorCode::Denied,
                    "deny for ext.restricted should not affect ext.test, got: {}",
                    err.message
                );
            }
        });
    }

    #[test]
    fn shared_dispatch_per_extension_mode_override_applies() {
        // Global mode is Strict (fallback → Deny), but ext.test has mode
        // overridden to Permissive. A capability not in any allow/deny list
        // should fall through to the effective mode and be allowed.
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let mut policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Strict,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: Vec::new(),
            per_extension: HashMap::new(),
            ..Default::default()
        };
        policy.per_extension.insert(
            "ext.test".to_string(),
            ExtensionOverride {
                mode: Some(ExtensionPolicyMode::Permissive),
                ..Default::default()
            },
        );
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-mode-override".to_string(),
            capability: "log".to_string(),
            method: "log".to_string(),
            params: json!({ "level": "info", "message": "test" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            // With Strict mode globally, "log" would be denied. But ext.test
            // overrides to Permissive, so it should be allowed (may fail
            // downstream for other reasons, but not denied).
            if result.is_error {
                let err = result.error.as_ref().expect("expected error payload");
                assert_ne!(
                    err.code,
                    HostCallErrorCode::Denied,
                    "per-extension mode override to Permissive should allow 'log', got: {}",
                    err.message
                );
            }
        });
    }

    #[test]
    fn shared_dispatch_unsupported_method_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-bad-method".to_string(),
            capability: "unknown_cap".to_string(),
            method: "nonsense_method".to_string(),
            params: json!({}),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
            assert!(
                err.message.contains("Unknown or invalid host call method")
                    || err.message.contains("Unsupported hostcall method"),
                "unexpected error message: {}",
                err.message
            );
        });
    }

    #[test]
    fn shared_dispatch_session_without_manager_returns_denied() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        // ctx.manager is None → session/ui/events should return "denied"
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "call-session".to_string(),
            capability: "session".to_string(),
            method: "session".to_string(),
            params: json!({ "op": "get_state" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::Denied);
        });
    }

    // ========================================================================
    // bd-2hz.4: UI method routing through shared dispatcher + taxonomy
    // ========================================================================

    /// UI confirm success path via shared dispatcher.
    #[test]
    fn shared_dispatch_ui_confirm_success() {
        use asupersync::channel::mpsc;

        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = extension_manager_no_persisted_permissions();
        let (ui_tx, ui_rx) = mpsc::channel(8);
        manager.set_ui_sender(ui_tx);

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.ui-test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "ui-confirm-1".to_string(),
            capability: "ui".to_string(),
            method: "ui".to_string(),
            params: json!({ "op": "confirm", "title": "Test?", "message": "Really?" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let cx = asupersync::Cx::for_request();

            let ui_handler = async {
                let req = ui_rx.recv(&cx).await.expect("ui recv");
                assert_eq!(req.method, "confirm");
                manager.respond_ui(ExtensionUiResponse {
                    id: req.id,
                    value: Some(Value::Bool(true)),
                    cancelled: false,
                });
            };

            let dispatch = async { dispatch_host_call_shared(&ctx, call).await };

            let ((), result) = futures::join!(ui_handler, dispatch);
            assert!(
                !result.is_error,
                "expected success, got error: {:?}",
                result.error
            );
            // confirm returns the boolean value
            assert_eq!(result.output, json!(true));
        });
    }

    /// UI with no manager (shutdown) returns denied.
    #[test]
    fn shared_dispatch_ui_without_manager_returns_denied() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "ui-no-mgr".to_string(),
            capability: "ui".to_string(),
            method: "ui".to_string(),
            params: json!({ "op": "confirm" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::Denied);
            assert!(
                err.message.contains("shutting down"),
                "expected shutdown message, got: {}",
                err.message
            );
        });
    }

    /// UI with no UI sender configured returns denied.
    #[test]
    fn shared_dispatch_ui_no_sender_returns_denied() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        // Manager exists but no UI sender configured.
        let manager = extension_manager_no_persisted_permissions();
        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.ui-test"),
            tools: &tools,
            http: &http,
            manager: Some(manager),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "ui-no-sender".to_string(),
            capability: "ui".to_string(),
            method: "ui".to_string(),
            params: json!({ "op": "confirm", "title": "Test?" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("expected error payload");
            // "not configured" maps to "denied" via classify_ui_hostcall_error
            assert_eq!(err.code, HostCallErrorCode::Denied);
        });
    }

    /// UI cancelled response maps to deterministic cancelled output.
    #[test]
    fn shared_dispatch_ui_cancelled_returns_deterministic_value() {
        use asupersync::channel::mpsc;

        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = extension_manager_no_persisted_permissions();
        let (ui_tx, ui_rx) = mpsc::channel(8);
        manager.set_ui_sender(ui_tx);

        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.ui-test"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "ui-cancel-1".to_string(),
            capability: "ui".to_string(),
            method: "ui".to_string(),
            params: json!({ "op": "confirm", "title": "Cancel me" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let cx = asupersync::Cx::for_request();

            let ui_handler = async {
                let req = ui_rx.recv(&cx).await.expect("ui recv");
                assert_eq!(req.method, "confirm");
                // Simulate user cancellation.
                manager.respond_ui(ExtensionUiResponse {
                    id: req.id,
                    value: None,
                    cancelled: true,
                });
            };

            let dispatch = async { dispatch_host_call_shared(&ctx, call).await };

            let ((), result) = futures::join!(ui_handler, dispatch);
            // Cancelled confirm resolves with false (not an error).
            assert!(!result.is_error, "cancelled should not be an error");
            assert_eq!(
                result.output,
                json!(false),
                "cancelled confirm should resolve to false"
            );
        });
    }

    /// UI with invalid (empty) op returns invalid_request.
    #[test]
    fn shared_dispatch_ui_empty_op_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = extension_manager_no_persisted_permissions();
        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.ui-test"),
            tools: &tools,
            http: &http,
            manager: Some(manager),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "ui-empty-op".to_string(),
            capability: "ui".to_string(),
            method: "ui".to_string(),
            params: json!({ "op": "" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let result = dispatch_host_call_shared(&ctx, call).await;
            assert!(result.is_error);
            let err = result.error.expect("expected error payload");
            assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
        });
    }

    /// UI shared dispatch emits structured logs with params_hash and no raw payload.
    #[test]
    fn shared_dispatch_ui_logs_params_hash_no_raw_payload() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();

        let manager = extension_manager_no_persisted_permissions();
        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.ui-log"),
            tools: &tools,
            http: &http,
            manager: Some(manager),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "ui-log-1".to_string(),
            capability: "ui".to_string(),
            method: "ui".to_string(),
            params: json!({
                "op": "confirm",
                "title": "Secret Title",
                "message": "Secret Body"
            }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        let (_result, events) = capture_tracing_events(|| {
            run_async(async { dispatch_host_call_shared(&ctx, call).await })
        });

        // Should have host_call.start with params_hash.
        let start = events.iter().find(|e| {
            e.fields
                .get("event")
                .is_some_and(|v| v.contains("host_call.start"))
        });
        let start = start.expect("host_call.start event for ui call");
        assert!(
            start.fields.contains_key("params_hash"),
            "start event must include params_hash"
        );

        // Should have host_call.end with duration_ms.
        let end = events.iter().find(|e| {
            e.fields
                .get("event")
                .is_some_and(|v| v.contains("host_call.end"))
        });
        let end = end.expect("host_call.end event for ui call");
        assert!(
            end.fields.contains_key("duration_ms"),
            "end event must include duration_ms"
        );

        // No raw payload fields should appear in any log event.
        for event in &events {
            for value in event.fields.values() {
                assert!(
                    !value.contains("Secret Title"),
                    "raw payload leaked into logs: {value}"
                );
                assert!(
                    !value.contains("Secret Body"),
                    "raw payload leaked into logs: {value}"
                );
            }
        }
    }

    // ========================================================================
    // bd-1uy.1.2: Protocol adapter (handle_extension_message) tests
    // ========================================================================

    fn make_host_call_msg(
        call_id: &str,
        method: &str,
        capability: &str,
        params: Value,
    ) -> ExtensionMessage {
        ExtensionMessage {
            id: format!("msg-{call_id}"),
            version: PROTOCOL_VERSION.to_string(),
            body: ExtensionBody::HostCall(HostCallPayload {
                call_id: call_id.to_string(),
                capability: capability.to_string(),
                method: method.to_string(),
                params,
                timeout_ms: None,
                cancel_token: None,
                context: None,
            }),
        }
    }

    /// Round-trip: host_call -> adapter -> host_result validates.
    #[test]
    fn protocol_adapter_host_call_roundtrip_validates() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&["read"], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let msg = make_host_call_msg(
            "call-roundtrip",
            "tool",
            "tool",
            json!({ "name": "nonexistent_tool", "input": {} }),
        );

        let responses = run_async(async { handle_extension_message(&ctx, msg).await });
        assert_eq!(responses.len(), 1);

        let response = &responses[0];
        // Response id should follow the deterministic format.
        assert_eq!(response.id, "host_result:call-roundtrip");
        assert_eq!(response.version, PROTOCOL_VERSION);

        // Validate the response message.
        response.validate().expect("response must be schema-valid");

        // The body should be HostResult.
        let result = match &response.body {
            ExtensionBody::HostResult(result) => result,
            other => panic!(
                "expected HostResult, got {:?}",
                extension_body_type_name(other)
            ),
        };

        // call_id must be preserved.
        assert_eq!(result.call_id, "call-roundtrip");
        // Unknown tool -> error.
        assert!(result.is_error);
        let err = result.error.as_ref().expect("error payload");
        assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
    }

    /// Protocol adapter: capability mismatch -> invalid_request.
    #[test]
    fn protocol_adapter_capability_mismatch_returns_invalid_request() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        // Claim capability "exec" but method is "tool" with name "read" (requires "read").
        let msg = make_host_call_msg(
            "call-mismatch",
            "tool",
            "exec",
            json!({ "name": "read", "input": {} }),
        );

        let responses = run_async(async { handle_extension_message(&ctx, msg).await });
        assert_eq!(responses.len(), 1);

        let result = match &responses[0].body {
            ExtensionBody::HostResult(result) => result,
            other => panic!(
                "expected HostResult, got {:?}",
                extension_body_type_name(other)
            ),
        };

        assert!(result.is_error);
        let err = result.error.as_ref().expect("error payload");
        assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
        assert!(
            err.message.contains("mismatch"),
            "expected mismatch in message: {}",
            err.message
        );
    }

    /// Protocol adapter: denied-by-policy -> denied.
    #[test]
    fn protocol_adapter_denied_by_policy() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = deny_all_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let msg = make_host_call_msg(
            "call-deny",
            "tool",
            "read",
            json!({ "name": "read", "input": { "path": "/etc/passwd" } }),
        );

        let responses = run_async(async { handle_extension_message(&ctx, msg).await });
        assert_eq!(responses.len(), 1);

        let result = match &responses[0].body {
            ExtensionBody::HostResult(result) => result,
            other => panic!(
                "expected HostResult, got {:?}",
                extension_body_type_name(other)
            ),
        };

        assert!(result.is_error);
        let err = result.error.as_ref().expect("error payload");
        assert_eq!(err.code, HostCallErrorCode::Denied);
    }

    /// Protocol adapter: wrong message type -> invalid_request error.
    #[test]
    fn protocol_adapter_wrong_message_type_returns_error() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        // Send an error message instead of host_call.
        let msg = ExtensionMessage {
            id: "msg-wrong".to_string(),
            version: PROTOCOL_VERSION.to_string(),
            body: ExtensionBody::Error(ErrorPayload {
                code: "test_error".to_string(),
                message: "this is not a host_call".to_string(),
                details: None,
            }),
        };

        let responses = run_async(async { handle_extension_message(&ctx, msg).await });
        assert_eq!(responses.len(), 1);

        let result = match &responses[0].body {
            ExtensionBody::HostResult(result) => result,
            other => panic!(
                "expected HostResult, got {:?}",
                extension_body_type_name(other)
            ),
        };

        assert!(result.is_error);
        let err = result.error.as_ref().expect("error payload");
        assert_eq!(err.code, HostCallErrorCode::InvalidRequest);
        assert!(
            err.message.contains("expects host_call"),
            "error should mention expected type: {}",
            err.message
        );
    }

    /// Protocol adapter: successful tool execution roundtrip.
    #[test]
    fn protocol_adapter_tool_success_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let cwd = dir.path();

        // Write a file we can read.
        std::fs::write(cwd.join("hello.txt"), "world").expect("write test file");

        let tools = ToolRegistry::new(&["read"], cwd, None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = HostCallContext {
            runtime_name: "protocol",
            extension_id: Some("ext.test"),
            tools: &tools,
            http: &http,
            manager: None,
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let msg = make_host_call_msg(
            "call-read-ok",
            "tool",
            "read",
            json!({ "name": "read", "input": { "path": cwd.join("hello.txt").to_str().unwrap() } }),
        );

        let responses = run_async(async { handle_extension_message(&ctx, msg).await });
        assert_eq!(responses.len(), 1);

        let response = &responses[0];
        response.validate().expect("response must validate");

        let result = match &response.body {
            ExtensionBody::HostResult(result) => result,
            other => panic!(
                "expected HostResult, got {:?}",
                extension_body_type_name(other)
            ),
        };

        assert_eq!(result.call_id, "call-read-ok");
        assert!(!result.is_error, "read should succeed: {:?}", result.error);
        // Output should contain the file content.
        let output_str = serde_json::to_string(&result.output).expect("serialize");
        assert!(
            output_str.contains("world"),
            "output should contain file content: {output_str}"
        );
    }

    #[test]
    fn hostcall_request_to_payload_preserves_method_and_capability() {
        let request = HostcallRequest {
            call_id: "call-conv".to_string(),
            kind: HostcallKind::Tool {
                name: "read".to_string(),
            },
            payload: json!({ "path": "test.txt" }),
            trace_id: 42,
            extension_id: Some("ext.test".to_string()),
        };

        let payload = hostcall_request_to_payload(&request);
        assert_eq!(payload.method, "tool");
        assert_eq!(payload.capability, "read");
        assert_eq!(payload.call_id, "call-conv");
        assert_eq!(
            payload.params,
            json!({ "name": "read", "input": { "path": "test.txt" } })
        );
    }

    #[test]
    fn hostcall_request_to_payload_exec_shape() {
        let request = HostcallRequest {
            call_id: "call-exec".to_string(),
            kind: HostcallKind::Exec {
                cmd: "ls".to_string(),
            },
            payload: json!({ "args": ["-la"], "timeout": 30000 }),
            trace_id: 1,
            extension_id: None,
        };

        let payload = hostcall_request_to_payload(&request);
        assert_eq!(payload.method, "exec");
        assert_eq!(payload.capability, "exec");
        // Params should have "cmd" injected
        assert_eq!(
            payload.params.get("cmd").and_then(Value::as_str),
            Some("ls")
        );
        assert!(payload.params.get("args").is_some());
    }

    #[test]
    fn hostcall_request_to_payload_session_shape() {
        let request = HostcallRequest {
            call_id: "call-session".to_string(),
            kind: HostcallKind::Session {
                op: "get_state".to_string(),
            },
            payload: json!({ "key": "value" }),
            trace_id: 1,
            extension_id: None,
        };

        let payload = hostcall_request_to_payload(&request);
        assert_eq!(payload.method, "session");
        assert_eq!(payload.capability, "session");
        // Params should have "op" injected
        assert_eq!(
            payload.params.get("op").and_then(Value::as_str),
            Some("get_state")
        );
        assert_eq!(
            payload.params.get("key").and_then(Value::as_str),
            Some("value")
        );
    }

    #[test]
    fn params_hash_parity_request_vs_payload() {
        let request = HostcallRequest {
            call_id: "call-hash".to_string(),
            kind: HostcallKind::Tool {
                name: "read".to_string(),
            },
            payload: json!({ "path": "hello.txt", "offset": 0 }),
            trace_id: 1,
            extension_id: None,
        };

        let payload = hostcall_request_to_payload(&request);

        // The params_hash from the request and from the payload must match,
        // since both use the same canonical shape.
        let request_hash = request.params_hash();
        let payload_hash = hostcall_params_hash(&payload.method, &payload.params);
        assert_eq!(
            request_hash, payload_hash,
            "params_hash must be identical for HostcallRequest and HostCallPayload"
        );
    }

    #[test]
    fn host_result_to_outcome_success_roundtrip() {
        let result = HostResultPayload {
            call_id: "call-ok".to_string(),
            output: json!({"data": "hello"}),
            is_error: false,
            error: None,
            chunk: None,
        };

        let outcome = host_result_to_outcome(result);
        assert!(
            matches!(outcome, HostcallOutcome::Success(ref v) if v == &json!({"data": "hello"}))
        );
    }

    #[test]
    fn host_result_to_outcome_error_roundtrip() {
        let result = HostResultPayload {
            call_id: "call-err".to_string(),
            output: json!({}),
            is_error: true,
            error: Some(HostCallError {
                code: HostCallErrorCode::Io,
                message: "disk full".to_string(),
                details: None,
                retryable: Some(true),
            }),
            chunk: None,
        };

        let outcome = host_result_to_outcome(result);
        match outcome {
            HostcallOutcome::Error { code, message } => {
                assert_eq!(code, "io");
                assert_eq!(message, "disk full");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn host_result_to_outcome_stream_chunk() {
        let result = HostResultPayload {
            call_id: "call-stream".to_string(),
            output: json!("line 1\n"),
            is_error: false,
            error: None,
            chunk: Some(HostStreamChunk {
                index: 5,
                is_last: false,
                backpressure: None,
            }),
        };

        let outcome = host_result_to_outcome(result);
        match outcome {
            HostcallOutcome::StreamChunk {
                sequence,
                chunk,
                is_final,
            } => {
                assert_eq!(sequence, 5);
                assert_eq!(chunk, json!("line 1\n"));
                assert!(!is_final);
            }
            other => panic!("expected StreamChunk, got {other:?}"),
        }
    }

    #[test]
    fn outcome_to_host_result_preserves_taxonomy() {
        let outcome = HostcallOutcome::Error {
            code: "timeout".to_string(),
            message: "timed out".to_string(),
        };
        let result = outcome_to_host_result("call-t", &outcome);
        assert!(result.is_error);
        assert_eq!(result.output, json!({}));
        let err = result.error.unwrap();
        assert_eq!(err.code, HostCallErrorCode::Timeout);
        assert_eq!(err.message, "timed out");
    }

    #[test]
    fn outcome_to_host_result_unknown_code_maps_to_internal() {
        let outcome = HostcallOutcome::Error {
            code: "some_weird_code".to_string(),
            message: "surprise".to_string(),
        };
        let result = outcome_to_host_result("call-x", &outcome);
        assert!(result.is_error);
        let err = result.error.unwrap();
        assert_eq!(err.code, HostCallErrorCode::Internal);
    }

    // ========================================================================
    // bd-1uy.1.3: JS-origin hostcalls produce taxonomy-only error codes
    // ========================================================================

    #[test]
    fn js_hostcall_log_defaults_correlation_and_succeeds() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let manager = extension_manager_no_persisted_permissions();

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let request = crate::extensions_js::HostcallRequest {
            call_id: "call-log-ok".to_string(),
            kind: crate::extensions_js::HostcallKind::Log,
            payload: serde_json::json!({
                "level": "info",
                "event": "unit.log",
                "message": "hello from extension"
            }),
            trace_id: 0,
            extension_id: Some("ext.test".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, request).await });
        match outcome {
            HostcallOutcome::Success(value) => {
                assert_eq!(value["ok"], true);
                assert_eq!(value["schema"], LOG_SCHEMA_VERSION);
                assert_eq!(value["event"], "unit.log");
            }
            other => panic!("expected Success for log hostcall, got {other:?}"),
        }
    }

    #[test]
    fn js_hostcall_log_missing_required_fields_is_invalid_request() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let manager = extension_manager_no_persisted_permissions();

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let request = crate::extensions_js::HostcallRequest {
            call_id: "call-log-bad".to_string(),
            kind: crate::extensions_js::HostcallKind::Log,
            payload: serde_json::json!({
                "level": "info",
                "message": "missing event"
            }),
            trace_id: 0,
            extension_id: Some("ext.test".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, request).await });
        match outcome {
            HostcallOutcome::Error { code, message } => {
                assert_eq!(code, "invalid_request");
                assert!(
                    message.contains("validation failed") || message.contains("payload is invalid"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected invalid_request for malformed log hostcall, got {other:?}"),
        }
    }

    /// Unknown tool → `invalid_request` (not `tool_error`).
    #[test]
    fn js_hostcall_unknown_tool_returns_invalid_request() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let manager = extension_manager_no_persisted_permissions();

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&["read"], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        let request = crate::extensions_js::HostcallRequest {
            call_id: "call-unknown-tool".to_string(),
            kind: crate::extensions_js::HostcallKind::Tool {
                name: "nonexistent_tool_xyz".to_string(),
            },
            payload: serde_json::json!({}),
            trace_id: 0,
            extension_id: Some("ext.test".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, request).await });
        match &outcome {
            HostcallOutcome::Error { code, message } => {
                assert_eq!(
                    code, "invalid_request",
                    "expected taxonomy code, got: {code}"
                );
                assert!(
                    message.contains("nonexistent_tool_xyz"),
                    "error should mention tool name: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Tool execution failure → `io` (not `tool_error`).
    #[test]
    fn js_hostcall_tool_execution_failure_maps_to_taxonomy() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let manager = extension_manager_no_persisted_permissions();

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&["read"], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        // Read a nonexistent file to trigger a tool execution error.
        let request = crate::extensions_js::HostcallRequest {
            call_id: "call-tool-fail".to_string(),
            kind: crate::extensions_js::HostcallKind::Tool {
                name: "read".to_string(),
            },
            payload: serde_json::json!({
                "path": "/nonexistent/path/that/does/not/exist.txt"
            }),
            trace_id: 0,
            extension_id: Some("ext.test".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, request).await });
        match &outcome {
            HostcallOutcome::Error { code, .. } => {
                // Must be a taxonomy code, never "tool_error".
                assert!(
                    ["timeout", "denied", "io", "invalid_request", "internal"]
                        .contains(&code.as_str()),
                    "expected taxonomy error code, got non-taxonomy code: {code}"
                );
                assert_ne!(code, "tool_error", "must not emit legacy tool_error code");
            }
            // Tool may succeed with an error message in output (depends on implementation).
            HostcallOutcome::Success(_) => {}
            HostcallOutcome::StreamChunk { .. } => {
                panic!("unexpected stream chunk from tool dispatch");
            }
        }
    }

    /// Manager shutdown → `denied` (not `SHUTDOWN`).
    #[test]
    fn js_hostcall_manager_shutdown_maps_to_denied() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();

        // Create a manager then drop the inner Arc so manager() returns None.
        let tools = Arc::new(crate::tools::ToolRegistry::new(&[], &cwd, None));
        let http = Arc::new(crate::connectors::http::HttpConnector::with_defaults());

        // Create a manager we intentionally don't hold, so the Weak ref is dead.
        let dead_manager_ref = {
            let manager = extension_manager_no_persisted_permissions();
            Arc::downgrade(&manager.inner)
            // manager dropped here → Weak upgrades fail
        };

        let host = JsRuntimeHost {
            tools,
            manager_ref: dead_manager_ref,
            http,
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Permissive,
                max_memory_mb: 256,
                default_caps: Vec::new(),
                deny_caps: Vec::new(),
                ..Default::default()
            },
            interceptor: None,
        };

        // Session call with dead manager should yield "denied", not "SHUTDOWN".
        let request = crate::extensions_js::HostcallRequest {
            call_id: "call-shutdown".to_string(),
            kind: crate::extensions_js::HostcallKind::Session {
                op: "get_state".to_string(),
            },
            payload: serde_json::json!({}),
            trace_id: 0,
            extension_id: Some("ext.test".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, request).await });
        match &outcome {
            HostcallOutcome::Error { code, .. } => {
                assert_eq!(
                    code, "denied",
                    "shutdown path must map to 'denied', got: {code}"
                );
                assert_ne!(code, "SHUTDOWN", "must not emit legacy SHUTDOWN code");
            }
            other => panic!("expected Error for shutdown path, got {other:?}"),
        }
    }

    /// Verify that all error codes emitted by the shared dispatcher are taxonomy-only.
    #[test]
    fn js_hostcall_all_error_codes_are_taxonomy_only() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path().to_path_buf();
        let manager = extension_manager_no_persisted_permissions();

        let host = JsRuntimeHost {
            tools: Arc::new(crate::tools::ToolRegistry::new(&["read"], &cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(crate::connectors::http::HttpConnector::with_defaults()),
            policy: ExtensionPolicy {
                mode: ExtensionPolicyMode::Strict,
                max_memory_mb: 256,
                default_caps: vec!["read".to_string()],
                deny_caps: vec!["exec".to_string()],
                ..Default::default()
            },
            interceptor: None,
        };

        let taxonomy_codes = ["timeout", "denied", "io", "invalid_request", "internal"];
        let legacy_codes = ["tool_error", "SHUTDOWN", "CANCELLED", "cancelled"];

        // Denied-by-policy (exec denied).
        let denied_req = crate::extensions_js::HostcallRequest {
            call_id: "call-denied".to_string(),
            kind: crate::extensions_js::HostcallKind::Exec {
                cmd: "ls".to_string(),
            },
            payload: serde_json::json!({}),
            trace_id: 0,
            extension_id: Some("ext.test".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, denied_req).await });
        if let HostcallOutcome::Error { code, .. } = &outcome {
            assert!(
                taxonomy_codes.contains(&code.as_str()),
                "denied-by-policy produced non-taxonomy code: {code}"
            );
            for legacy in &legacy_codes {
                assert_ne!(code, legacy, "emitted legacy code: {code}");
            }
        }

        // Unknown tool.
        let unknown_req = crate::extensions_js::HostcallRequest {
            call_id: "call-unknown".to_string(),
            kind: crate::extensions_js::HostcallKind::Tool {
                name: "no_such_tool".to_string(),
            },
            payload: serde_json::json!({}),
            trace_id: 0,
            extension_id: Some("ext.test".to_string()),
        };

        let outcome = run_async(async { super::dispatch_hostcall(&host, unknown_req).await });
        if let HostcallOutcome::Error { code, .. } = &outcome {
            assert!(
                taxonomy_codes.contains(&code.as_str()),
                "unknown-tool produced non-taxonomy code: {code}"
            );
            for legacy in &legacy_codes {
                assert_ne!(code, legacy, "emitted legacy code: {code}");
            }
        }
    }

    // ========================================================================
    // Cross-Runtime Parity Tests (bd-1uy.1.4)
    // ========================================================================
    //
    // These tests exercise the same canonical `HostCallPayload` through both
    // the shared dispatcher and the protocol adapter, then assert:
    // 1. Outputs match (same `is_error`, same error code, same output shape)
    // 2. Schema validity (`validate_host_result` passes)
    // 3. Taxonomy-only error codes
    // 4. Params hash parity between JS-origin and canonical payloads

    const TAXONOMY_CODES: [HostCallErrorCode; 5] = [
        HostCallErrorCode::Timeout,
        HostCallErrorCode::Denied,
        HostCallErrorCode::Io,
        HostCallErrorCode::InvalidRequest,
        HostCallErrorCode::Internal,
    ];

    /// A canonical test case for parity verification.
    struct ParityCase {
        name: &'static str,
        call: HostCallPayload,
        /// JS-origin request that should produce the same canonical payload.
        js_request: Option<HostcallRequest>,
        /// True if this case specifically tests manager-absent behaviour.
        /// JS dispatch always has a manager via `JsRuntimeHost`, so these
        /// cases are skipped in JS-vs-protocol parity (tested separately).
        needs_no_manager: bool,
    }

    /// Assert structural parity between two `HostResultPayload` values.
    fn assert_result_parity(label: &str, shared: &HostResultPayload, protocol: &HostResultPayload) {
        assert_eq!(
            shared.is_error, protocol.is_error,
            "[{label}] is_error mismatch: shared={}, protocol={}",
            shared.is_error, protocol.is_error
        );
        assert_eq!(
            shared.call_id, protocol.call_id,
            "[{label}] call_id mismatch"
        );
        match (&shared.error, &protocol.error) {
            (Some(se), Some(pe)) => {
                assert_eq!(
                    se.code, pe.code,
                    "[{label}] error code mismatch: shared={:?}, protocol={:?}",
                    se.code, pe.code
                );
            }
            (None, None) => {}
            _ => panic!(
                "[{label}] error presence mismatch: shared={:?}, protocol={:?}",
                shared.error.is_some(),
                protocol.error.is_some()
            ),
        }
    }

    /// Validate a `HostResultPayload` against schema invariants.
    fn assert_schema_valid(label: &str, result: &HostResultPayload) {
        assert!(
            result.output.is_object(),
            "[{label}] output must be object, got: {:?}",
            result.output
        );
        if result.is_error {
            assert!(
                result.error.is_some(),
                "[{label}] is_error=true but error is None"
            );
        } else {
            assert!(
                result.error.is_none(),
                "[{label}] is_error=false but error is Some: {:?}",
                result.error
            );
        }
        if let Some(ref err) = result.error {
            assert!(
                TAXONOMY_CODES.contains(&err.code),
                "[{label}] non-taxonomy error code: {:?}",
                err.code
            );
        }
        super::validate_host_result(result)
            .unwrap_or_else(|e| panic!("[{label}] validate_host_result failed: {e}"));
    }

    /// Extract `HostResultPayload` from a protocol adapter response.
    fn extract_protocol_result(responses: &[ExtensionMessage]) -> &HostResultPayload {
        assert_eq!(responses.len(), 1, "expected exactly 1 response");
        match &responses[0].body {
            ExtensionBody::HostResult(result) => result,
            other => panic!(
                "expected HostResult, got {}",
                extension_body_type_name(other)
            ),
        }
    }

    /// Build canonical test cases for parity verification.
    #[allow(clippy::too_many_lines)]
    fn parity_cases(cwd: &std::path::Path) -> Vec<ParityCase> {
        vec![
            ParityCase {
                name: "tool_unknown",
                call: HostCallPayload {
                    call_id: "parity-tool-unknown".to_string(),
                    capability: "tool".to_string(),
                    method: "tool".to_string(),
                    params: json!({ "name": "nonexistent_tool_xyz", "input": {} }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: Some(HostcallRequest {
                    call_id: "parity-tool-unknown".to_string(),
                    kind: HostcallKind::Tool {
                        name: "nonexistent_tool_xyz".to_string(),
                    },
                    payload: json!({}),
                    trace_id: 0,
                    extension_id: Some("ext.parity".to_string()),
                }),
                needs_no_manager: false,
            },
            ParityCase {
                name: "tool_read_success",
                call: HostCallPayload {
                    call_id: "parity-tool-read".to_string(),
                    capability: "read".to_string(),
                    method: "tool".to_string(),
                    params: json!({
                        "name": "read",
                        "input": { "path": cwd.join("parity_test.txt").to_str().unwrap() }
                    }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: Some(HostcallRequest {
                    call_id: "parity-tool-read".to_string(),
                    kind: HostcallKind::Tool {
                        name: "read".to_string(),
                    },
                    payload: json!({
                        "path": cwd.join("parity_test.txt").to_str().unwrap()
                    }),
                    trace_id: 0,
                    extension_id: Some("ext.parity".to_string()),
                }),
                needs_no_manager: false,
            },
            ParityCase {
                name: "exec_empty_cmd",
                call: HostCallPayload {
                    call_id: "parity-exec-empty".to_string(),
                    capability: "exec".to_string(),
                    method: "exec".to_string(),
                    params: json!({ "cmd": "" }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: Some(HostcallRequest {
                    call_id: "parity-exec-empty".to_string(),
                    kind: HostcallKind::Exec { cmd: String::new() },
                    payload: json!({}),
                    trace_id: 0,
                    extension_id: Some("ext.parity".to_string()),
                }),
                needs_no_manager: false,
            },
            ParityCase {
                name: "session_missing_op",
                call: HostCallPayload {
                    call_id: "parity-session-noop".to_string(),
                    capability: "session".to_string(),
                    method: "session".to_string(),
                    params: json!({ "key": "value" }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: None,
                needs_no_manager: false,
            },
            ParityCase {
                name: "session_no_manager",
                call: HostCallPayload {
                    call_id: "parity-session-mgr".to_string(),
                    capability: "session".to_string(),
                    method: "session".to_string(),
                    params: json!({ "op": "get_state" }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: Some(HostcallRequest {
                    call_id: "parity-session-mgr".to_string(),
                    kind: HostcallKind::Session {
                        op: "get_state".to_string(),
                    },
                    payload: json!({}),
                    trace_id: 0,
                    extension_id: Some("ext.parity".to_string()),
                }),
                needs_no_manager: true,
            },
            ParityCase {
                name: "ui_no_manager",
                call: HostCallPayload {
                    call_id: "parity-ui-mgr".to_string(),
                    capability: "ui".to_string(),
                    method: "ui".to_string(),
                    params: json!({ "op": "confirm", "message": "test?" }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: Some(HostcallRequest {
                    call_id: "parity-ui-mgr".to_string(),
                    kind: HostcallKind::Ui {
                        op: "confirm".to_string(),
                    },
                    payload: json!({ "message": "test?" }),
                    trace_id: 0,
                    extension_id: Some("ext.parity".to_string()),
                }),
                needs_no_manager: true,
            },
            ParityCase {
                name: "ui_empty_op",
                call: HostCallPayload {
                    call_id: "parity-ui-noop".to_string(),
                    capability: "ui".to_string(),
                    method: "ui".to_string(),
                    params: json!({ "data": 1 }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: None,
                needs_no_manager: false,
            },
            ParityCase {
                name: "events_no_manager",
                call: HostCallPayload {
                    call_id: "parity-events-mgr".to_string(),
                    capability: "events".to_string(),
                    method: "events".to_string(),
                    params: json!({ "op": "emit", "event": "test" }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: Some(HostcallRequest {
                    call_id: "parity-events-mgr".to_string(),
                    kind: HostcallKind::Events {
                        op: "emit".to_string(),
                    },
                    payload: json!({ "event": "test" }),
                    trace_id: 0,
                    extension_id: Some("ext.parity".to_string()),
                }),
                needs_no_manager: true,
            },
            ParityCase {
                name: "capability_mismatch",
                call: HostCallPayload {
                    call_id: "parity-cap-mismatch".to_string(),
                    capability: "exec".to_string(),
                    method: "tool".to_string(),
                    params: json!({ "name": "read", "input": {} }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: None,
                needs_no_manager: false,
            },
            ParityCase {
                name: "empty_call_id",
                call: HostCallPayload {
                    call_id: String::new(),
                    capability: "tool".to_string(),
                    method: "tool".to_string(),
                    params: json!({ "name": "read", "input": {} }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: None,
                needs_no_manager: false,
            },
            ParityCase {
                name: "unsupported_method",
                call: HostCallPayload {
                    call_id: "parity-bad-method".to_string(),
                    capability: "tool".to_string(),
                    method: "quantum_compute".to_string(),
                    params: json!({}),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                },
                js_request: None,
                needs_no_manager: false,
            },
        ]
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn parity_shared_vs_protocol_all_cases() {
        let dir = tempdir().expect("tempdir");
        let cwd = dir.path();
        std::fs::write(cwd.join("parity_test.txt"), "parity_data").expect("write test file");

        let tools = ToolRegistry::new(&["read"], cwd, None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let cases = parity_cases(cwd);

        for case in &cases {
            run_async(async {
                let shared_result = dispatch_host_call_shared(&ctx, case.call.clone()).await;

                let msg = make_host_call_msg(
                    &case.call.call_id,
                    &case.call.method,
                    &case.call.capability,
                    case.call.params.clone(),
                );
                let responses = handle_extension_message(&ctx, msg).await;
                let protocol_result = extract_protocol_result(&responses);

                assert_result_parity(case.name, &shared_result, protocol_result);

                if !case.call.call_id.is_empty() {
                    assert_schema_valid(&format!("{}/shared", case.name), &shared_result);
                    assert_schema_valid(&format!("{}/protocol", case.name), protocol_result);
                }
            });
        }
    }

    #[test]
    fn parity_params_hash_all_js_cases() {
        let dir = tempdir().expect("tempdir");
        let cwd = dir.path();
        std::fs::write(cwd.join("parity_test.txt"), "parity_data").expect("write test file");

        let cases = parity_cases(cwd);

        for case in &cases {
            let Some(ref js_req) = case.js_request else {
                continue;
            };
            let converted = hostcall_request_to_payload(js_req);
            let js_hash = js_req.params_hash();
            let canonical_hash = hostcall_params_hash(&converted.method, &converted.params);

            assert_eq!(
                js_hash, canonical_hash,
                "[{}] params_hash mismatch: JS={}, canonical={}",
                case.name, js_hash, canonical_hash
            );

            assert_eq!(
                converted.method, case.call.method,
                "[{}] method mismatch after JS conversion",
                case.name
            );
        }
    }

    #[test]
    fn parity_js_conversion_vs_protocol() {
        use std::sync::Arc;

        let dir = tempdir().expect("tempdir");
        let cwd = dir.path();
        std::fs::write(cwd.join("parity_test.txt"), "parity_data").expect("write test file");

        let tools = ToolRegistry::new(&["read"], cwd, None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let manager = extension_manager_no_persisted_permissions();
        let host = JsRuntimeHost {
            tools: Arc::new(ToolRegistry::new(&["read"], cwd, None)),
            manager_ref: Arc::downgrade(&manager.inner),
            http: Arc::new(HttpConnector::with_defaults()),
            policy: permissive_policy(),
            interceptor: None,
        };

        let cases = parity_cases(cwd);

        for case in &cases {
            let Some(ref js_req) = case.js_request else {
                continue;
            };
            // JS dispatch always has a manager via JsRuntimeHost; skip cases
            // that specifically test manager-absent behaviour (tested separately
            // in `parity_shared_vs_protocol_all_cases`).
            if case.needs_no_manager {
                continue;
            }

            run_async(async {
                let js_outcome = super::dispatch_hostcall(&host, js_req.clone()).await;

                let msg = make_host_call_msg(
                    &case.call.call_id,
                    &case.call.method,
                    &case.call.capability,
                    case.call.params.clone(),
                );
                let responses = handle_extension_message(&ctx, msg).await;
                let protocol_result = extract_protocol_result(&responses);

                let js_result = outcome_to_host_result(&case.call.call_id, &js_outcome);

                assert_result_parity(
                    &format!("{}/js_vs_protocol", case.name),
                    &js_result,
                    protocol_result,
                );

                if !case.call.call_id.is_empty() {
                    assert_schema_valid(&format!("{}/js_result", case.name), &js_result);
                }
            });
        }
    }

    #[test]
    fn parity_all_errors_are_taxonomy_only() {
        let dir = tempdir().expect("tempdir");
        let cwd = dir.path();

        let tools = ToolRegistry::new(&["read"], cwd, None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let cases = parity_cases(cwd);

        for case in &cases {
            run_async(async {
                let result = dispatch_host_call_shared(&ctx, case.call.clone()).await;
                if let Some(ref err) = result.error {
                    assert!(
                        TAXONOMY_CODES.contains(&err.code),
                        "[{}] non-taxonomy error code: {:?} (message: {})",
                        case.name,
                        err.code,
                        err.message
                    );
                }
            });
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn parity_denied_by_policy_shared_vs_protocol() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = deny_all_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let denied_cases = vec![
            // name=read → required capability "read", not "tool"
            (
                "tool_denied",
                "tool",
                "read",
                json!({ "name": "read", "input": {} }),
            ),
            ("exec_denied", "exec", "exec", json!({ "cmd": "ls" })),
            (
                "http_denied",
                "http",
                "http",
                json!({ "url": "https://example.com" }),
            ),
            (
                "session_denied",
                "session",
                "session",
                json!({ "op": "get_state" }),
            ),
            (
                "ui_denied",
                "ui",
                "ui",
                json!({ "op": "confirm", "message": "test" }),
            ),
            (
                "events_denied",
                "events",
                "events",
                json!({ "op": "emit", "event": "test" }),
            ),
        ];

        for (name, method, capability, params) in &denied_cases {
            let call = HostCallPayload {
                call_id: format!("parity-deny-{name}"),
                capability: capability.to_string(),
                method: method.to_string(),
                params: params.clone(),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };

            run_async(async {
                let shared_result = dispatch_host_call_shared(&ctx, call.clone()).await;
                let msg = make_host_call_msg(
                    &call.call_id,
                    &call.method,
                    &call.capability,
                    call.params.clone(),
                );
                let responses = handle_extension_message(&ctx, msg).await;
                let protocol_result = extract_protocol_result(&responses);

                assert!(
                    shared_result.is_error,
                    "[{name}] shared: expected error for denied call"
                );
                assert!(
                    protocol_result.is_error,
                    "[{name}] protocol: expected error for denied call"
                );

                let shared_code = shared_result.error.as_ref().expect("shared error").code;
                let protocol_code = protocol_result.error.as_ref().expect("protocol error").code;
                assert_eq!(
                    shared_code,
                    HostCallErrorCode::Denied,
                    "[{name}] shared: expected Denied, got {shared_code:?}"
                );
                assert_eq!(
                    protocol_code,
                    HostCallErrorCode::Denied,
                    "[{name}] protocol: expected Denied, got {protocol_code:?}"
                );

                assert_result_parity(name, &shared_result, protocol_result);
                assert_schema_valid(&format!("{name}/shared"), &shared_result);
                assert_schema_valid(&format!("{name}/protocol"), protocol_result);
            });
        }
    }

    #[test]
    fn parity_tool_read_success_shared_vs_protocol() {
        let dir = tempdir().expect("tempdir");
        let cwd = dir.path();
        std::fs::write(cwd.join("hello_parity.txt"), "parity_content_42").expect("write test file");

        let tools = ToolRegistry::new(&["read"], cwd, None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = HostCallContext {
            runtime_name: "parity_test",
            extension_id: Some("ext.parity"),
            tools: &tools,
            http: &http,
            manager: None,
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        let call = HostCallPayload {
            call_id: "parity-read-ok".to_string(),
            capability: "read".to_string(),
            method: "tool".to_string(),
            params: json!({
                "name": "read",
                "input": { "path": cwd.join("hello_parity.txt").to_str().unwrap() }
            }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let shared_result = dispatch_host_call_shared(&ctx, call.clone()).await;
            let msg = make_host_call_msg(
                &call.call_id,
                &call.method,
                &call.capability,
                call.params.clone(),
            );
            let responses = handle_extension_message(&ctx, msg).await;
            let protocol_result = extract_protocol_result(&responses);

            assert!(
                !shared_result.is_error,
                "shared: expected success, got: {:?}",
                shared_result.error
            );
            assert!(
                !protocol_result.is_error,
                "protocol: expected success, got: {:?}",
                protocol_result.error
            );

            assert_result_parity("read_success", &shared_result, protocol_result);
            assert_schema_valid("read_success/shared", &shared_result);
            assert_schema_valid("read_success/protocol", protocol_result);

            let shared_str = serde_json::to_string(&shared_result.output).unwrap();
            let protocol_str = serde_json::to_string(&protocol_result.output).unwrap();
            assert!(
                shared_str.contains("parity_content_42"),
                "shared output missing file content: {shared_str}"
            );
            assert!(
                protocol_str.contains("parity_content_42"),
                "protocol output missing file content: {protocol_str}"
            );
        });
    }

    #[test]
    fn parity_outcome_roundtrip_error_preserves_taxonomy() {
        for code in &TAXONOMY_CODES {
            let code_str = host_call_error_code_str(*code);
            let outcome = HostcallOutcome::Error {
                code: code_str.to_string(),
                message: format!("test {code_str}"),
            };

            let result = outcome_to_host_result("rt-test", &outcome);
            assert_schema_valid(&format!("roundtrip/{code_str}"), &result);

            let back = host_result_to_outcome(result);
            match back {
                HostcallOutcome::Error {
                    code: back_code,
                    message: back_msg,
                } => {
                    assert_eq!(
                        back_code, code_str,
                        "roundtrip code mismatch: {back_code} != {code_str}"
                    );
                    assert!(
                        back_msg.contains(code_str),
                        "roundtrip message lost: {back_msg}"
                    );
                }
                other => panic!("expected Error after roundtrip, got {other:?}"),
            }
        }
    }

    #[test]
    fn parity_outcome_roundtrip_success_preserves_output() {
        let output = json!({"key": "value", "count": 42});
        let outcome = HostcallOutcome::Success(output.clone());

        let result = outcome_to_host_result("rt-ok", &outcome);
        assert_schema_valid("roundtrip/success", &result);
        assert_eq!(result.output, output);

        let back = host_result_to_outcome(result);
        match back {
            HostcallOutcome::Success(v) => assert_eq!(v, output),
            other => panic!("expected Success after roundtrip, got {other:?}"),
        }
    }

    #[test]
    fn parity_outcome_roundtrip_stream_chunk() {
        let chunk = json!({"data": "partial"});
        let outcome = HostcallOutcome::StreamChunk {
            sequence: 7,
            chunk: chunk.clone(),
            is_final: false,
        };

        let result = outcome_to_host_result("rt-stream", &outcome);
        assert!(!result.is_error);
        assert!(result.error.is_none());
        assert_eq!(result.output, chunk);
        let stream_info = result.chunk.as_ref().expect("chunk info");
        assert_eq!(stream_info.index, 7);
        assert!(!stream_info.is_last);

        let back = host_result_to_outcome(result);
        match back {
            HostcallOutcome::StreamChunk {
                sequence,
                chunk: c,
                is_final,
            } => {
                assert_eq!(sequence, 7);
                assert_eq!(c, chunk);
                assert!(!is_final);
            }
            other => panic!("expected StreamChunk after roundtrip, got {other:?}"),
        }
    }

    #[test]
    fn parity_empty_call_id_rejected_both_paths() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: String::new(),
            capability: "tool".to_string(),
            method: "tool".to_string(),
            params: json!({ "name": "read", "input": {} }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let shared = dispatch_host_call_shared(&ctx, call.clone()).await;
            assert!(shared.is_error, "shared must reject empty call_id");
            let shared_err = shared.error.as_ref().expect("shared error");
            assert_eq!(shared_err.code, HostCallErrorCode::InvalidRequest);

            let msg =
                make_host_call_msg("", "tool", "tool", json!({ "name": "read", "input": {} }));
            let responses = handle_extension_message(&ctx, msg).await;
            let protocol = extract_protocol_result(&responses);
            assert!(protocol.is_error, "protocol must reject empty call_id");
            let protocol_err = protocol.error.as_ref().expect("protocol error");
            assert_eq!(protocol_err.code, HostCallErrorCode::InvalidRequest);
        });
    }

    #[test]
    fn parity_non_object_params_rejected() {
        let dir = tempdir().expect("tempdir");
        let tools = ToolRegistry::new(&[], dir.path(), None);
        let http = HttpConnector::with_defaults();
        let policy = permissive_policy();
        let ctx = test_host_call_context(&tools, &http, &policy);

        let call = HostCallPayload {
            call_id: "parity-badparams".to_string(),
            capability: "tool".to_string(),
            method: "tool".to_string(),
            params: json!("not an object"),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };

        run_async(async {
            let shared = dispatch_host_call_shared(&ctx, call.clone()).await;
            assert!(shared.is_error, "shared must reject non-object params");
            let shared_err = shared.error.as_ref().expect("shared error");
            assert_eq!(shared_err.code, HostCallErrorCode::InvalidRequest);

            let msg = ExtensionMessage {
                id: "msg-badparams".to_string(),
                version: PROTOCOL_VERSION.to_string(),
                body: ExtensionBody::HostCall(call),
            };
            let responses = handle_extension_message(&ctx, msg).await;
            let protocol = extract_protocol_result(&responses);
            assert!(protocol.is_error, "protocol must reject non-object params");
            let protocol_err = protocol.error.as_ref().expect("protocol error");
            assert_eq!(protocol_err.code, HostCallErrorCode::InvalidRequest);
        });
    }

    // ========================================================================
    // bd-2tl1.5: Streaming Hostcall Protocol Invariants
    // ========================================================================

    #[test]
    fn stream_chunk_serde_roundtrip() {
        let chunk = HostStreamChunk {
            index: 42,
            is_last: false,
            backpressure: None,
        };
        let json = serde_json::to_string(&chunk).unwrap();
        let back: HostStreamChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, 42);
        assert!(!back.is_last);
        assert!(back.backpressure.is_none());
    }

    #[test]
    fn stream_chunk_serde_with_backpressure() {
        let chunk = HostStreamChunk {
            index: 0,
            is_last: true,
            backpressure: Some(HostStreamBackpressure {
                credits: Some(10),
                delay_ms: Some(500),
            }),
        };
        let json = serde_json::to_value(&chunk).unwrap();
        assert_eq!(json["index"], 0);
        assert_eq!(json["is_last"], true);
        assert_eq!(json["backpressure"]["credits"], 10);
        assert_eq!(json["backpressure"]["delay_ms"], 500);

        let back: HostStreamChunk = serde_json::from_value(json).unwrap();
        assert!(back.is_last);
        let bp = back.backpressure.unwrap();
        assert_eq!(bp.credits, Some(10));
        assert_eq!(bp.delay_ms, Some(500));
    }

    #[test]
    fn stream_chunk_serde_skips_none_backpressure() {
        let chunk = HostStreamChunk {
            index: 5,
            is_last: false,
            backpressure: None,
        };
        let json = serde_json::to_value(&chunk).unwrap();
        assert!(
            json.get("backpressure").is_none(),
            "None backpressure should be omitted from serialized JSON"
        );
    }

    #[test]
    fn stream_backpressure_serde_roundtrip() {
        let bp = HostStreamBackpressure {
            credits: Some(100),
            delay_ms: None,
        };
        let json = serde_json::to_value(&bp).unwrap();
        assert_eq!(json["credits"], 100);
        assert!(
            json.get("delay_ms").is_none(),
            "None delay_ms should be omitted"
        );

        let back: HostStreamBackpressure = serde_json::from_value(json).unwrap();
        assert_eq!(back.credits, Some(100));
        assert!(back.delay_ms.is_none());
    }

    #[test]
    fn stream_backpressure_both_none_serde() {
        let bp = HostStreamBackpressure {
            credits: None,
            delay_ms: None,
        };
        let json = serde_json::to_value(&bp).unwrap();
        assert_eq!(
            json,
            json!({}),
            "both-None backpressure should serialize to empty object"
        );

        let back: HostStreamBackpressure = serde_json::from_value(json).unwrap();
        assert!(back.credits.is_none());
        assert!(back.delay_ms.is_none());
    }

    #[test]
    fn validate_host_result_accepts_stream_chunk_with_object_output() {
        let result = HostResultPayload {
            call_id: "stream-valid".to_string(),
            output: json!({"data": "chunk"}),
            is_error: false,
            error: None,
            chunk: Some(HostStreamChunk {
                index: 0,
                is_last: false,
                backpressure: None,
            }),
        };
        super::validate_host_result(&result)
            .expect("valid stream chunk with object output should pass validation");
    }

    #[test]
    fn validate_host_result_rejects_stream_chunk_non_object_output() {
        // Stream chunks in practice may carry string output (e.g., "line 1\n"),
        // but `validate_host_result` enforces object output uniformly.
        let result = HostResultPayload {
            call_id: "stream-bad-output".to_string(),
            output: json!("string output"),
            is_error: false,
            error: None,
            chunk: Some(HostStreamChunk {
                index: 0,
                is_last: false,
                backpressure: None,
            }),
        };
        assert!(
            super::validate_host_result(&result).is_err(),
            "non-object output should be rejected even for stream chunks"
        );
    }

    #[test]
    fn stream_final_chunk_roundtrip_preserves_is_last() {
        let outcome = HostcallOutcome::StreamChunk {
            sequence: 99,
            chunk: json!({"final": true}),
            is_final: true,
        };
        let result = outcome_to_host_result("final-test", &outcome);
        let chunk_info = result.chunk.as_ref().expect("chunk info");
        assert!(chunk_info.is_last);
        assert_eq!(chunk_info.index, 99);

        let back = host_result_to_outcome(result);
        match back {
            HostcallOutcome::StreamChunk {
                sequence, is_final, ..
            } => {
                assert_eq!(sequence, 99);
                assert!(is_final);
            }
            other => panic!("expected StreamChunk, got {other:?}"),
        }
    }

    #[test]
    fn stream_outcome_roundtrip_backpressure_not_preserved() {
        // Backpressure is lost in the outcome roundtrip because
        // `HostcallOutcome::StreamChunk` does not carry backpressure.
        let result = HostResultPayload {
            call_id: "bp-test".to_string(),
            output: json!({"data": "x"}),
            is_error: false,
            error: None,
            chunk: Some(HostStreamChunk {
                index: 3,
                is_last: false,
                backpressure: Some(HostStreamBackpressure {
                    credits: Some(5),
                    delay_ms: Some(100),
                }),
            }),
        };

        let outcome = host_result_to_outcome(result);
        let back = outcome_to_host_result("bp-test", &outcome);

        // Backpressure is lost (`outcome_to_host_result` always sets None).
        assert!(
            back.chunk.as_ref().unwrap().backpressure.is_none(),
            "backpressure should not survive outcome roundtrip"
        );
        // But sequence and is_last are preserved.
        assert_eq!(back.chunk.as_ref().unwrap().index, 3);
        assert!(!back.chunk.as_ref().unwrap().is_last);
    }

    #[test]
    fn stream_chunk_call_id_preserved_through_conversion() {
        let outcome = HostcallOutcome::StreamChunk {
            sequence: 0,
            chunk: json!({}),
            is_final: false,
        };
        let result = outcome_to_host_result("my-call-id-42", &outcome);
        assert_eq!(result.call_id, "my-call-id-42");
    }

    #[test]
    fn stream_chunk_zero_index_roundtrip() {
        let chunk = HostStreamChunk {
            index: 0,
            is_last: false,
            backpressure: None,
        };
        let json = serde_json::to_value(&chunk).unwrap();
        assert_eq!(json["index"], 0);
        let back: HostStreamChunk = serde_json::from_value(json).unwrap();
        assert_eq!(back.index, 0);
    }

    #[test]
    fn stream_chunk_max_index_roundtrip() {
        let chunk = HostStreamChunk {
            index: u64::MAX,
            is_last: true,
            backpressure: None,
        };
        let json = serde_json::to_value(&chunk).unwrap();
        let back: HostStreamChunk = serde_json::from_value(json).unwrap();
        assert_eq!(back.index, u64::MAX);
        assert!(back.is_last);
    }

    // ========================================================================
    // Quantile selection semantics (bd-xqipg)
    // ========================================================================

    #[test]
    fn quantile_empty_vec_returns_zero() {
        assert!((runtime_risk_quantile(vec![], 0.0) - 0.0).abs() < f64::EPSILON);
        assert!((runtime_risk_quantile(vec![], 0.5) - 0.0).abs() < f64::EPSILON);
        assert!((runtime_risk_quantile(vec![], 1.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_single_element_multi_q() {
        let v = vec![42.0];
        assert!((runtime_risk_quantile(v.clone(), 0.0) - 42.0).abs() < f64::EPSILON);
        assert!((runtime_risk_quantile(v.clone(), 0.5) - 42.0).abs() < f64::EPSILON);
        assert!((runtime_risk_quantile(v, 1.0) - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_q_zero_returns_minimum() {
        let v = vec![5.0, 1.0, 9.0, 3.0, 7.0];
        assert!((runtime_risk_quantile(v, 0.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_q_one_returns_maximum() {
        let v = vec![5.0, 1.0, 9.0, 3.0, 7.0];
        assert!((runtime_risk_quantile(v, 1.0) - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_odd_sample_count_median_integer_values() {
        // 5 elements: sorted = [1,3,5,7,9], median index = (4*0.5).round() = 2
        let v = vec![5.0, 1.0, 9.0, 3.0, 7.0];
        assert!((runtime_risk_quantile(v, 0.5) - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_even_sample_count_median_integer_values() {
        // 4 elements: sorted = [2,4,6,8], median index = (3*0.5).round() = 2
        let v = vec![8.0, 2.0, 6.0, 4.0];
        assert!((runtime_risk_quantile(v, 0.5) - 6.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_all_duplicate_values() {
        let v = vec![3.0, 3.0, 3.0, 3.0, 3.0];
        assert!((runtime_risk_quantile(v.clone(), 0.0) - 3.0).abs() < f64::EPSILON);
        assert!((runtime_risk_quantile(v.clone(), 0.5) - 3.0).abs() < f64::EPSILON);
        assert!((runtime_risk_quantile(v, 1.0) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_partial_duplicates() {
        // sorted = [1,1,1,5,5,9], q=0.5 → idx = (5*0.5).round() = 3 → 5.0
        let v = vec![5.0, 1.0, 9.0, 1.0, 5.0, 1.0];
        assert!((runtime_risk_quantile(v, 0.5) - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_negative_q_clamped_to_zero() {
        let v = vec![10.0, 20.0, 30.0];
        // clamp01 maps negative to 0.0 → returns minimum
        assert!((runtime_risk_quantile(v, -5.0) - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_large_q_clamped_to_one() {
        let v = vec![10.0, 20.0, 30.0];
        // clamp01 maps >1 to 1.0 → returns maximum
        assert!((runtime_risk_quantile(v, 100.0) - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_nan_q_clamped_to_zero() {
        let v = vec![10.0, 20.0, 30.0];
        // clamp01 maps NaN to 0.0 → returns minimum
        assert!((runtime_risk_quantile(v, f64::NAN) - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_sorted_vs_unsorted_identical() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let unsorted = vec![3.0, 1.0, 5.0, 2.0, 4.0];
        for q in [0.0, 0.25, 0.5, 0.75, 1.0] {
            let a = runtime_risk_quantile(sorted.clone(), q);
            let b = runtime_risk_quantile(unsorted.clone(), q);
            assert!(
                (a - b).abs() < f64::EPSILON,
                "mismatch at q={q}: sorted={a}, unsorted={b}"
            );
        }
    }

    #[test]
    fn quantile_monotonicity() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let mut prev = f64::NEG_INFINITY;
        for q_pct in 0..=100 {
            let q = f64::from(q_pct) / 100.0;
            let val = runtime_risk_quantile(v.clone(), q);
            assert!(
                val >= prev,
                "monotonicity violated: q={q} gave {val} < prev {prev}"
            );
            prev = val;
        }
    }

    #[test]
    fn quantile_two_elements_boundary() {
        let v = vec![0.0, 1.0];
        // q=0.0 → idx=(1*0.0).round()=0 → 0.0
        assert!((runtime_risk_quantile(v.clone(), 0.0) - 0.0).abs() < f64::EPSILON);
        // q=0.25 → idx=(1*0.25).round()=0 → 0.0
        assert!((runtime_risk_quantile(v.clone(), 0.25) - 0.0).abs() < f64::EPSILON);
        // q=0.5 → idx=(1*0.5).round()=1 → 1.0
        assert!((runtime_risk_quantile(v.clone(), 0.5) - 1.0).abs() < f64::EPSILON);
        // q=1.0 → idx=(1*1.0).round()=1 → 1.0
        assert!((runtime_risk_quantile(v, 1.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn quantile_large_sample() {
        let v: Vec<f64> = (1..=1000).map(f64::from).collect();
        // q=0.0 → 1.0 (min), q=1.0 → 1000.0 (max)
        assert!((runtime_risk_quantile(v.clone(), 0.0) - 1.0).abs() < f64::EPSILON);
        assert!((runtime_risk_quantile(v.clone(), 1.0) - 1000.0).abs() < f64::EPSILON);
        // q=0.5 → idx=(999*0.5).round()=500 → 501.0
        let median = runtime_risk_quantile(v, 0.5);
        assert!(
            (median - 500.0).abs() <= 1.0,
            "expected median ~500, got {median}"
        );
    }

    #[test]
    fn quantile_conformal_residual_integration() {
        // Simulate conformal residual quantile computation used in decision flow:
        // residual_window filled with residuals, then quantile(window, 1.0 - alpha)
        let alpha = 0.01;
        let residuals: Vec<f64> = (0..64).map(|i| (f64::from(i) / 63.0) * 0.5).collect();
        let quantile_val = runtime_risk_quantile(residuals, 1.0 - alpha);
        // At q=0.99, should be close to the maximum residual (~0.5)
        assert!(
            quantile_val >= 0.45,
            "conformal quantile at 1-alpha should be near max: got {quantile_val}"
        );
        assert!(
            quantile_val <= 0.5 + f64::EPSILON,
            "conformal quantile should not exceed max: got {quantile_val}"
        );
    }

    // ========================================================================
    // Clamp01 edge cases (bd-xqipg)
    // ========================================================================

    #[test]
    fn clamp01_nan_returns_zero() {
        assert!((runtime_risk_clamp01(f64::NAN) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn clamp01_negative_infinity_returns_zero() {
        assert!((runtime_risk_clamp01(f64::NEG_INFINITY) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn clamp01_positive_infinity_returns_one() {
        assert!((runtime_risk_clamp01(f64::INFINITY) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn clamp01_normal_values_pass_through() {
        assert!((runtime_risk_clamp01(0.5) - 0.5).abs() < f64::EPSILON);
        assert!((runtime_risk_clamp01(0.0) - 0.0).abs() < f64::EPSILON);
        assert!((runtime_risk_clamp01(1.0) - 1.0).abs() < f64::EPSILON);
    }

    // ========================================================================
    // Baseline modeling (bd-153pv)
    // ========================================================================

    #[test]
    fn baseline_median_empty_returns_zero() {
        assert!((baseline_median(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_median_single_element() {
        assert!((baseline_median(&[4.2]) - 4.2).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_median_odd_count() {
        assert!((baseline_median(&[1.0, 3.0, 5.0]) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_median_even_count() {
        // midpoint of 3.0 and 5.0 = 4.0
        assert!((baseline_median(&[1.0, 3.0, 5.0, 7.0]) - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_mad_constant_data_is_zero() {
        assert!((baseline_mad(&[5.0, 5.0, 5.0, 5.0]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_mad_known_values() {
        // data = [1, 2, 3, 4, 5], median = 3
        // deviations = [2, 1, 0, 1, 2], sorted = [0, 1, 1, 2, 2], median = 1
        let sorted = &[1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((baseline_mad(sorted) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn state_label_index_mapping() {
        assert_eq!(
            state_label_to_index(RuntimeRiskStateLabelValue::SafeFast),
            0
        );
        assert_eq!(
            state_label_to_index(RuntimeRiskStateLabelValue::Suspicious),
            1
        );
        assert_eq!(state_label_to_index(RuntimeRiskStateLabelValue::Unsafe), 2);
    }

    #[test]
    fn markov_matrix_empty_states_uses_uniform_prior() {
        let matrix = build_markov_transition_matrix(&[], 1.0);
        assert_eq!(matrix.total_transitions, 0);
        // With no data, each row should be uniform (1/3 each due to smoothing)
        for row in &matrix.probabilities {
            for &prob in row {
                assert!((prob - 1.0 / 3.0).abs() < 1e-10);
            }
        }
    }

    #[test]
    fn markov_matrix_single_transition() {
        let states = vec![
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::Suspicious,
        ];
        let matrix = build_markov_transition_matrix(&states, 1.0);
        assert_eq!(matrix.total_transitions, 1);
        // Row 0 (SafeFast): 1 transition to Suspicious + 1.0 prior each
        // counts[0] = [0, 1, 0], row_total = 1 + 3*1.0 = 4
        assert!((matrix.probabilities[0][1] - 2.0 / 4.0).abs() < 1e-10);
        assert!((matrix.probabilities[0][0] - 1.0 / 4.0).abs() < 1e-10);
    }

    #[test]
    fn markov_matrix_deterministic() {
        let states = vec![
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::Suspicious,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::SafeFast,
        ];
        let m1 = build_markov_transition_matrix(&states, 1.0);
        let m2 = build_markov_transition_matrix(&states, 1.0);
        assert_eq!(m1, m2, "Markov matrix must be deterministic");
    }

    #[test]
    fn markov_stationary_sums_to_one() {
        let states = vec![
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::Suspicious,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::Suspicious,
        ];
        let matrix = build_markov_transition_matrix(&states, 1.0);
        let sum: f64 = matrix.stationary_distribution.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-8,
            "stationary distribution should sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn kl_divergence_identical_is_zero() {
        let p = [0.5, 0.3, 0.2];
        assert!((kl_divergence(&p, &p) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn kl_divergence_different_is_positive() {
        let p = [0.9, 0.05, 0.05];
        let q = [0.33, 0.34, 0.33];
        assert!(kl_divergence(&p, &q) > 0.0);
    }

    #[test]
    fn build_baseline_deterministic() {
        use crate::extensions::RuntimeRiskConfig;
        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Permissive,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: Vec::new(),
            ..Default::default()
        };
        let tools = crate::tools::ToolRegistry::new(&[], std::path::Path::new("/tmp"), None);
        let http = crate::connectors::http::HttpConnector::with_defaults();
        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test.baseline"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        futures::executor::block_on(async {
            for i in 0..10 {
                let call = HostCallPayload {
                    call_id: format!("baseline-{i}"),
                    capability: "log".to_string(),
                    method: "log".to_string(),
                    params: serde_json::json!({ "message": format!("test-{i}") }),
                    timeout_ms: None,
                    cancel_token: None,
                    context: None,
                };
                let _ = dispatch_host_call_shared(&ctx, call).await;
            }
        });

        let b1 = manager.build_baseline("ext.test.baseline").unwrap();
        let b2 = manager.build_baseline("ext.test.baseline").unwrap();

        // Schema, profiles, and transition matrix should match (timestamps may differ)
        assert_eq!(b1.schema, b2.schema);
        assert_eq!(b1.capability_profiles, b2.capability_profiles);
        assert_eq!(b1.transition_matrix, b2.transition_matrix);
        assert_eq!(b1.source_entry_count, b2.source_entry_count);
    }

    #[test]
    fn build_baseline_sparse_data_has_fallback() {
        use crate::extensions::RuntimeRiskConfig;
        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Permissive,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: Vec::new(),
            ..Default::default()
        };
        let tools = crate::tools::ToolRegistry::new(&[], std::path::Path::new("/tmp"), None);
        let http = crate::connectors::http::HttpConnector::with_defaults();
        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test.sparse"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        // Only 1 call - very sparse data
        futures::executor::block_on(async {
            let call = HostCallPayload {
                call_id: "sparse-0".to_string(),
                capability: "log".to_string(),
                method: "log".to_string(),
                params: serde_json::json!({ "message": "sparse" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };
            let _ = dispatch_host_call_shared(&ctx, call).await;
        });

        let baseline = manager.build_baseline("ext.test.sparse").unwrap();
        assert_eq!(baseline.source_entry_count, 1);
        assert_eq!(baseline.capability_profiles.len(), 1);
        assert_eq!(baseline.capability_profiles[0].sample_count, 1);
        // Markov matrix should have uniform prior (no transitions from 1 entry)
        assert_eq!(baseline.transition_matrix.total_transitions, 0);
    }

    #[test]
    fn build_baseline_wrong_extension_returns_error() {
        use crate::extensions::RuntimeRiskConfig;
        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 512,
            decision_timeout_ms: 50,
            fail_closed: true,
        });

        let policy = ExtensionPolicy {
            mode: ExtensionPolicyMode::Permissive,
            max_memory_mb: 256,
            default_caps: Vec::new(),
            deny_caps: Vec::new(),
            ..Default::default()
        };
        let tools = crate::tools::ToolRegistry::new(&[], std::path::Path::new("/tmp"), None);
        let http = crate::connectors::http::HttpConnector::with_defaults();
        let ctx = HostCallContext {
            runtime_name: "test",
            extension_id: Some("ext.test.exists"),
            tools: &tools,
            http: &http,
            manager: Some(manager.clone()),
            policy: &policy,
            js_runtime: None,
            interceptor: None,
        };

        futures::executor::block_on(async {
            let call = HostCallPayload {
                call_id: "exists-0".to_string(),
                capability: "log".to_string(),
                method: "log".to_string(),
                params: serde_json::json!({ "message": "exists" }),
                timeout_ms: None,
                cancel_token: None,
                context: None,
            };
            let _ = dispatch_host_call_shared(&ctx, call).await;
        });

        let result = manager.build_baseline("ext.nonexistent");
        assert!(result.is_err(), "should fail for nonexistent extension");
    }

    #[test]
    fn drift_detection_no_anomaly_for_baseline_data() {
        let profile = BaselineCapabilityProfile {
            capability: "log".to_string(),
            sample_count: 100,
            risk_score_median: 0.10,
            risk_score_mad: 0.02,
            risk_score_p5: 0.06,
            risk_score_p95: 0.14,
            error_rate_median: 0.0,
            burst_density_1s_median: 0.1,
            burst_density_10s_median: 0.05,
        };
        let baseline = RuntimeRiskBaselineModel {
            schema: RUNTIME_RISK_BASELINE_SCHEMA_VERSION.to_string(),
            extension_id: "ext.test".to_string(),
            generated_at_ms: 0,
            source_data_hash: "test".to_string(),
            source_entry_count: 100,
            capability_profiles: vec![profile],
            transition_matrix: build_markov_transition_matrix(&[], 1.0),
            anomaly_threshold_mads: 3.0,
            transition_divergence_threshold: 0.5,
        };

        let report = detect_baseline_drift(
            &baseline,
            "ext.test",
            "log",
            0.10, // close to median
            0.0,
            0.1,
            0.05,
            &[],
        );
        assert!(
            !report.drift_detected,
            "should not detect drift for baseline-matching data"
        );
        assert!(report.anomalies.is_empty());
    }

    #[test]
    fn drift_detection_flags_outlier_risk_score() {
        let profile = BaselineCapabilityProfile {
            capability: "log".to_string(),
            sample_count: 100,
            risk_score_median: 0.10,
            risk_score_mad: 0.02,
            risk_score_p5: 0.06,
            risk_score_p95: 0.14,
            error_rate_median: 0.0,
            burst_density_1s_median: 0.1,
            burst_density_10s_median: 0.05,
        };
        let baseline = RuntimeRiskBaselineModel {
            schema: RUNTIME_RISK_BASELINE_SCHEMA_VERSION.to_string(),
            extension_id: "ext.test".to_string(),
            generated_at_ms: 0,
            source_data_hash: "test".to_string(),
            source_entry_count: 100,
            capability_profiles: vec![profile],
            transition_matrix: build_markov_transition_matrix(&[], 1.0),
            anomaly_threshold_mads: 3.0,
            transition_divergence_threshold: 0.5,
        };

        let report = detect_baseline_drift(
            &baseline,
            "ext.test",
            "log",
            0.90, // far from baseline median 0.10
            0.0,
            0.1,
            0.05,
            &[],
        );
        assert!(
            report.drift_detected,
            "should detect drift for outlier score"
        );
        assert!(
            report.anomalies.iter().any(|a| a.metric == "risk_score"),
            "should have risk_score anomaly"
        );
    }

    #[test]
    fn drift_detection_transition_anomaly() {
        // Baseline: mostly SafeFast transitions
        let baseline_states = vec![
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::SafeFast,
            RuntimeRiskStateLabelValue::SafeFast,
        ];
        let baseline = RuntimeRiskBaselineModel {
            schema: RUNTIME_RISK_BASELINE_SCHEMA_VERSION.to_string(),
            extension_id: "ext.test".to_string(),
            generated_at_ms: 0,
            source_data_hash: "test".to_string(),
            source_entry_count: 50,
            capability_profiles: vec![],
            transition_matrix: build_markov_transition_matrix(&baseline_states, 1.0),
            anomaly_threshold_mads: 3.0,
            transition_divergence_threshold: 0.1, // low threshold for sensitivity
        };

        // Live: mostly Unsafe transitions
        let live_states = vec![
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
        ];
        let report = detect_baseline_drift(
            &baseline,
            "ext.test",
            "log",
            0.10,
            0.0,
            0.0,
            0.0,
            &live_states,
        );
        assert!(
            report.transition_anomalous,
            "should detect transition anomaly when live pattern differs from baseline"
        );
        assert!(report.transition_divergence > 0.0);
    }

    #[test]
    fn baseline_model_json_roundtrip() {
        let baseline = RuntimeRiskBaselineModel {
            schema: RUNTIME_RISK_BASELINE_SCHEMA_VERSION.to_string(),
            extension_id: "ext.roundtrip".to_string(),
            generated_at_ms: 1_234_567_890,
            source_data_hash: "abc123".to_string(),
            source_entry_count: 42,
            capability_profiles: vec![BaselineCapabilityProfile {
                capability: "log".to_string(),
                sample_count: 42,
                risk_score_median: 0.1,
                risk_score_mad: 0.02,
                risk_score_p5: 0.06,
                risk_score_p95: 0.14,
                error_rate_median: 0.0,
                burst_density_1s_median: 0.1,
                burst_density_10s_median: 0.05,
            }],
            transition_matrix: build_markov_transition_matrix(&[], 1.0),
            anomaly_threshold_mads: 3.0,
            transition_divergence_threshold: 0.5,
        };

        let json = serde_json::to_string(&baseline).unwrap();
        let deserialized: RuntimeRiskBaselineModel = serde_json::from_str(&json).unwrap();
        assert_eq!(
            baseline, deserialized,
            "roundtrip should preserve all fields"
        );
    }

    // ── SEC-4.1: Per-Extension Resource Quota Tests ──────────────────────

    #[test]
    fn quota_default_matches_prompt_mode() {
        let default = ExtensionQuotaConfig::default();
        let prompt = ExtensionQuotaConfig::for_mode(ExtensionPolicyMode::Prompt);
        assert_eq!(
            default.max_hostcalls_per_second,
            prompt.max_hostcalls_per_second
        );
        assert_eq!(
            default.max_hostcalls_per_minute,
            prompt.max_hostcalls_per_minute
        );
        assert_eq!(default.max_subprocesses, prompt.max_subprocesses);
    }

    #[test]
    fn quota_strict_more_restrictive_than_prompt() {
        let strict = ExtensionQuotaConfig::for_mode(ExtensionPolicyMode::Strict);
        let prompt = ExtensionQuotaConfig::for_mode(ExtensionPolicyMode::Prompt);
        assert!(
            strict.max_hostcalls_per_second.unwrap() < prompt.max_hostcalls_per_second.unwrap()
        );
        assert!(
            strict.max_hostcalls_per_minute.unwrap() < prompt.max_hostcalls_per_minute.unwrap()
        );
        assert!(strict.max_subprocesses.unwrap() < prompt.max_subprocesses.unwrap());
        assert!(strict.max_hostcalls_total.is_some());
        assert!(prompt.max_hostcalls_total.is_none());
    }

    #[test]
    fn quota_permissive_more_relaxed_than_prompt() {
        let permissive = ExtensionQuotaConfig::for_mode(ExtensionPolicyMode::Permissive);
        let prompt = ExtensionQuotaConfig::for_mode(ExtensionPolicyMode::Prompt);
        assert!(
            permissive.max_hostcalls_per_second.unwrap() > prompt.max_hostcalls_per_second.unwrap()
        );
        assert!(
            permissive.max_hostcalls_per_minute.unwrap() > prompt.max_hostcalls_per_minute.unwrap()
        );
        assert!(permissive.max_subprocesses.unwrap() > prompt.max_subprocesses.unwrap());
    }

    #[test]
    fn quota_check_allows_within_limits() {
        let config = ExtensionQuotaConfig::default();
        let mut state = ExtensionQuotaState::default();
        let result = check_extension_quota(&config, &mut state, 1000, "tool");
        assert_eq!(result, QuotaCheckResult::Allowed);
        assert_eq!(state.hostcalls_total, 1);
    }

    #[test]
    fn quota_per_second_burst_exceeded() {
        let config = ExtensionQuotaConfig {
            max_hostcalls_per_second: Some(3),
            ..Default::default()
        };
        let mut state = ExtensionQuotaState::default();
        for i in 0..3 {
            let r = check_extension_quota(&config, &mut state, 1000 + i64::from(i), "tool");
            assert_eq!(r, QuotaCheckResult::Allowed);
        }
        let r = check_extension_quota(&config, &mut state, 1002, "tool");
        assert!(matches!(r, QuotaCheckResult::Exceeded { .. }));
    }

    #[test]
    fn quota_per_minute_rate_exceeded() {
        let config = ExtensionQuotaConfig {
            max_hostcalls_per_minute: Some(5),
            max_hostcalls_per_second: None,
            ..Default::default()
        };
        let mut state = ExtensionQuotaState::default();
        for i in 0..5 {
            let r = check_extension_quota(&config, &mut state, 1000 + i * 10_000, "tool");
            assert_eq!(r, QuotaCheckResult::Allowed);
        }
        let r = check_extension_quota(&config, &mut state, 41_000, "tool");
        assert!(matches!(r, QuotaCheckResult::Exceeded { .. }));
    }

    #[test]
    fn quota_sliding_window_expiry() {
        let config = ExtensionQuotaConfig {
            max_hostcalls_per_minute: Some(3),
            max_hostcalls_per_second: None,
            ..Default::default()
        };
        let mut state = ExtensionQuotaState::default();
        for _ in 0..3 {
            let _ = check_extension_quota(&config, &mut state, 1000, "tool");
        }
        let r = check_extension_quota(&config, &mut state, 1000, "tool");
        assert!(matches!(r, QuotaCheckResult::Exceeded { .. }));
        let r = check_extension_quota(&config, &mut state, 62_000, "tool");
        assert_eq!(r, QuotaCheckResult::Allowed);
    }

    #[test]
    fn quota_total_budget_exceeded() {
        let config = ExtensionQuotaConfig {
            max_hostcalls_total: Some(2),
            max_hostcalls_per_second: None,
            max_hostcalls_per_minute: None,
            ..Default::default()
        };
        let mut state = ExtensionQuotaState::default();
        let _ = check_extension_quota(&config, &mut state, 1000, "tool");
        let _ = check_extension_quota(&config, &mut state, 2000, "tool");
        let r = check_extension_quota(&config, &mut state, 3000, "tool");
        assert!(matches!(r, QuotaCheckResult::Exceeded { .. }));
    }

    #[test]
    fn quota_subprocess_limit_enforced() {
        let config = ExtensionQuotaConfig {
            max_subprocesses: Some(2),
            max_hostcalls_per_second: None,
            max_hostcalls_per_minute: None,
            ..Default::default()
        };
        let mut state = ExtensionQuotaState {
            active_subprocesses: 2,
            ..Default::default()
        };
        let r = check_extension_quota(&config, &mut state, 1000, "exec");
        assert!(matches!(r, QuotaCheckResult::Exceeded { .. }));
        let r2 = check_extension_quota(&config, &mut state, 2000, "tool");
        assert_eq!(r2, QuotaCheckResult::Allowed);
    }

    #[test]
    fn quota_http_request_limit_enforced() {
        let config = ExtensionQuotaConfig {
            max_http_requests: Some(2),
            max_hostcalls_per_second: None,
            max_hostcalls_per_minute: None,
            ..Default::default()
        };
        let mut state = ExtensionQuotaState::default();
        let r1 = check_extension_quota(&config, &mut state, 1000, "http");
        assert_eq!(r1, QuotaCheckResult::Allowed);
        let r2 = check_extension_quota(&config, &mut state, 2000, "http");
        assert_eq!(r2, QuotaCheckResult::Allowed);
        let r3 = check_extension_quota(&config, &mut state, 3000, "http");
        assert!(matches!(r3, QuotaCheckResult::Exceeded { .. }));
    }

    #[test]
    fn quota_write_bytes_limit_enforced() {
        let config = ExtensionQuotaConfig {
            max_write_bytes: Some(1024),
            max_hostcalls_per_second: None,
            max_hostcalls_per_minute: None,
            ..Default::default()
        };
        let mut state = ExtensionQuotaState {
            write_bytes_total: 1024,
            ..Default::default()
        };
        let r = check_extension_quota(&config, &mut state, 1000, "write");
        assert!(matches!(r, QuotaCheckResult::Exceeded { .. }));
        let mut state2 = ExtensionQuotaState {
            write_bytes_total: 500,
            ..Default::default()
        };
        let r2 = check_extension_quota(&config, &mut state2, 1000, "write");
        assert_eq!(r2, QuotaCheckResult::Allowed);
    }

    #[test]
    fn quota_manager_per_extension_override() {
        let manager = ExtensionManager::new();
        let mut policy = ExtensionPolicy::default();
        policy.per_extension.insert(
            "test-ext".to_string(),
            ExtensionOverride {
                quota: Some(ExtensionQuotaConfig {
                    max_hostcalls_per_second: Some(1),
                    max_hostcalls_per_minute: Some(5),
                    max_hostcalls_total: None,
                    max_subprocesses: Some(1),
                    max_write_bytes: None,
                    max_http_requests: None,
                }),
                ..Default::default()
            },
        );
        let r1 = manager.check_quota(Some("test-ext"), "tool", 1000, &policy);
        assert_eq!(r1, QuotaCheckResult::Allowed);
        let r2 = manager.check_quota(Some("test-ext"), "tool", 1000, &policy);
        assert!(matches!(r2, QuotaCheckResult::Exceeded { .. }));
    }

    #[test]
    fn quota_manager_global_default_no_override() {
        let manager = ExtensionManager::new();
        let policy = ExtensionPolicy::default();
        for i in 0..50 {
            let r = manager.check_quota(Some("other-ext"), "tool", 1000 + i, &policy);
            assert_eq!(r, QuotaCheckResult::Allowed);
        }
    }

    #[test]
    fn quota_manager_no_ext_id_always_allowed() {
        let manager = ExtensionManager::new();
        let policy = ExtensionPolicy::default();
        let r = manager.check_quota(None, "tool", 1000, &policy);
        assert_eq!(r, QuotaCheckResult::Allowed);
    }

    #[test]
    fn quota_subprocess_spawn_exit_tracking() {
        let manager = ExtensionManager::new();
        assert_eq!(manager.quota_state("ext-1"), None);
        manager.record_subprocess_spawn("ext-1");
        let (_, active, _, _) = manager.quota_state("ext-1").unwrap();
        assert_eq!(active, 1);
        manager.record_subprocess_spawn("ext-1");
        let (_, active, _, _) = manager.quota_state("ext-1").unwrap();
        assert_eq!(active, 2);
        manager.record_subprocess_exit("ext-1");
        let (_, active, _, _) = manager.quota_state("ext-1").unwrap();
        assert_eq!(active, 1);
        manager.record_subprocess_exit("ext-1");
        manager.record_subprocess_exit("ext-1");
        let (_, active, _, _) = manager.quota_state("ext-1").unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    fn quota_write_bytes_tracking() {
        let manager = ExtensionManager::new();
        manager.record_write_bytes("ext-1", 512);
        let (_, _, wb, _) = manager.quota_state("ext-1").unwrap();
        assert_eq!(wb, 512);
        manager.record_write_bytes("ext-1", 1024);
        let (_, _, wb, _) = manager.quota_state("ext-1").unwrap();
        assert_eq!(wb, 1536);
    }

    #[test]
    fn quota_breach_telemetry_recorded() {
        let manager = ExtensionManager::new();
        let mut policy = ExtensionPolicy::default();
        policy.per_extension.insert(
            "bad-ext".to_string(),
            ExtensionOverride {
                quota: Some(ExtensionQuotaConfig {
                    max_hostcalls_per_second: Some(1),
                    max_hostcalls_per_minute: Some(1),
                    max_hostcalls_total: None,
                    max_subprocesses: None,
                    max_write_bytes: None,
                    max_http_requests: None,
                }),
                ..Default::default()
            },
        );
        let _ = manager.check_quota(Some("bad-ext"), "tool", 1000, &policy);
        assert_eq!(manager.quota_breach_count(), 0);
        let r = manager.check_quota(Some("bad-ext"), "tool", 1000, &policy);
        assert!(matches!(r, QuotaCheckResult::Exceeded { .. }));
        assert_eq!(manager.quota_breach_count(), 1);
        let events = manager.drain_quota_breach_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].extension_id, "bad-ext");
        assert_eq!(events[0].capability, "tool");
        assert_eq!(events[0].quota_config_source, "per_extension");
        assert_eq!(manager.quota_breach_count(), 0);
    }

    #[test]
    fn quota_reset_clears_state() {
        let manager = ExtensionManager::new();
        let policy = ExtensionPolicy::default();
        let _ = manager.check_quota(Some("ext-1"), "tool", 1000, &policy);
        manager.record_subprocess_spawn("ext-1");
        manager.record_write_bytes("ext-1", 1000);
        assert!(manager.quota_state("ext-1").is_some());
        manager.reset_quota_state("ext-1");
        assert!(manager.quota_state("ext-1").is_none());
    }

    #[test]
    fn quota_config_serialization_roundtrip() {
        let config = ExtensionQuotaConfig::for_mode(ExtensionPolicyMode::Strict);
        let json = serde_json::to_string(&config).unwrap();
        let restored: ExtensionQuotaConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config.max_hostcalls_per_second,
            restored.max_hostcalls_per_second
        );
        assert_eq!(config.max_subprocesses, restored.max_subprocesses);
        assert_eq!(config.max_write_bytes, restored.max_write_bytes);
    }

    #[test]
    fn quota_per_extension_override_policy_serialization() {
        let mut policy = ExtensionPolicy::default();
        policy.per_extension.insert(
            "my-ext".to_string(),
            ExtensionOverride {
                quota: Some(ExtensionQuotaConfig {
                    max_hostcalls_per_second: Some(10),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let json = serde_json::to_string(&policy).unwrap();
        let restored: ExtensionPolicy = serde_json::from_str(&json).unwrap();
        let ovr = restored.per_extension.get("my-ext").unwrap();
        assert_eq!(
            ovr.quota.as_ref().unwrap().max_hostcalls_per_second,
            Some(10)
        );
    }

    #[test]
    fn quota_monotonic_total_never_decreases() {
        let config = ExtensionQuotaConfig {
            max_hostcalls_per_second: None,
            max_hostcalls_per_minute: None,
            ..Default::default()
        };
        let mut state = ExtensionQuotaState::default();
        for i in 0..100 {
            let _ = check_extension_quota(&config, &mut state, i * 1000, "tool");
        }
        assert_eq!(state.hostcalls_total, 100);
    }

    // ========================================================================
    // SEC-3.2 Baseline Modeling Tests (bd-153pv)
    // ========================================================================

    /// Helper: build a test ledger artifact entry with required fields.
    #[allow(clippy::too_many_arguments)]
    fn make_test_ledger_entry(
        ext_id: &str,
        capability: &str,
        method: &str,
        risk_score: f64,
        state: RuntimeRiskStateLabelValue,
        ts_ms: i64,
        call_id: &str,
        outcome_error: Option<&str>,
    ) -> RuntimeRiskLedgerArtifactEntry {
        RuntimeRiskLedgerArtifactEntry {
            ts_ms,
            extension_id: ext_id.to_string(),
            call_id: call_id.to_string(),
            capability: capability.to_string(),
            method: method.to_string(),
            params_hash: "test_hash".to_string(),
            policy_reason: "allowed".to_string(),
            risk_score,
            posterior: RuntimeRiskPosteriorEvidence {
                safe_fast: 0.7,
                suspicious: 0.2,
                unsafe_: 0.1,
            },
            expected_loss: RuntimeRiskExpectedLossEvidence {
                allow: 1.0,
                harden: 2.0,
                deny: 3.0,
                terminate: 4.0,
            },
            selected_action: RuntimeRiskActionValue::Allow,
            derived_state: state,
            triggers: Vec::new(),
            fallback_reason: None,
            e_process: 0.5,
            e_threshold: 100.0,
            conformal_residual: 0.01,
            conformal_quantile: 0.05,
            drift_detected: false,
            outcome_error_code: outcome_error.map(ToString::to_string),
            explanation_schema: RUNTIME_RISK_EXPLANATION_SCHEMA_VERSION.to_string(),
            explanation_level: RuntimeRiskExplanationLevelValue::Standard,
            explanation_summary: "test explanation".to_string(),
            top_contributors: vec![RuntimeRiskExplanationContributor {
                code: "test_contributor".to_string(),
                signed_impact: 0.25,
                magnitude: 0.25,
                rationale: "test rationale".to_string(),
            }],
            budget_state: RuntimeRiskExplanationBudgetState::default(),
            ledger_hash: String::new(),
            prev_ledger_hash: None,
        }
    }

    /// Helper: build a valid ledger artifact with hash chains.
    fn make_test_ledger_artifact(
        entries: Vec<RuntimeRiskLedgerArtifactEntry>,
    ) -> RuntimeRiskLedgerArtifact {
        let mut hashed_entries = Vec::with_capacity(entries.len());
        let mut prev_hash: Option<String> = None;
        for mut entry in entries {
            let hash = runtime_risk_compute_ledger_hash_artifact(&entry, prev_hash.as_deref());
            entry.ledger_hash = hash.clone();
            entry.prev_ledger_hash = prev_hash.clone();
            prev_hash = Some(hash);
            hashed_entries.push(entry);
        }
        let data_hash = runtime_risk_ledger_data_hash(&hashed_entries);
        RuntimeRiskLedgerArtifact {
            schema: RUNTIME_RISK_LEDGER_SCHEMA_VERSION.to_string(),
            generated_at_ms: 1000,
            entry_count: hashed_entries.len(),
            head_ledger_hash: hashed_entries.first().map(|e| e.ledger_hash.clone()),
            tail_ledger_hash: hashed_entries.last().map(|e| e.ledger_hash.clone()),
            data_hash,
            entries: hashed_entries,
        }
    }

    #[test]
    fn baseline_generation_is_deterministic() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.test",
                "log",
                "log",
                0.15,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.test",
                "exec",
                "exec",
                0.85,
                RuntimeRiskStateLabelValue::Suspicious,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.test",
                "log",
                "log",
                0.20,
                RuntimeRiskStateLabelValue::SafeFast,
                3000,
                "c3",
                None,
            ),
            make_test_ledger_entry(
                "ext.test",
                "http",
                "fetch",
                0.65,
                RuntimeRiskStateLabelValue::Suspicious,
                4000,
                "c4",
                None,
            ),
            make_test_ledger_entry(
                "ext.test",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                5000,
                "c5",
                None,
            ),
            make_test_ledger_entry(
                "ext.test",
                "exec",
                "exec",
                0.90,
                RuntimeRiskStateLabelValue::Unsafe,
                6000,
                "c6",
                Some("denied"),
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);

        let model1 = build_baseline_from_ledger(&artifact, "ext.test").unwrap();
        let model2 = build_baseline_from_ledger(&artifact, "ext.test").unwrap();

        // Compare everything except generated_at_ms (uses wall clock)
        assert_eq!(model1.schema, model2.schema);
        assert_eq!(model1.extension_id, model2.extension_id);
        assert_eq!(model1.source_data_hash, model2.source_data_hash);
        assert_eq!(model1.source_entry_count, model2.source_entry_count);
        assert_eq!(model1.capability_profiles, model2.capability_profiles);
        assert_eq!(model1.transition_matrix, model2.transition_matrix);
        assert!(
            (model1.anomaly_threshold_mads - model2.anomaly_threshold_mads).abs() < f64::EPSILON
        );
        assert!(
            (model1.transition_divergence_threshold - model2.transition_divergence_threshold).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn baseline_schema_version_is_set() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.2,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.a").unwrap();
        assert_eq!(model.schema, RUNTIME_RISK_BASELINE_SCHEMA_VERSION);
    }

    #[test]
    fn baseline_sparse_data_single_entry() {
        // A single entry should still produce a valid baseline (not error).
        let entries = vec![make_test_ledger_entry(
            "ext.sparse",
            "log",
            "log",
            0.15,
            RuntimeRiskStateLabelValue::SafeFast,
            1000,
            "c1",
            None,
        )];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.sparse").unwrap();
        assert_eq!(model.source_entry_count, 1);
        assert_eq!(model.capability_profiles.len(), 1);
        assert_eq!(model.capability_profiles[0].sample_count, 1);
        // Median should equal the single observation
        assert!((model.capability_profiles[0].risk_score_median - 0.15).abs() < 1e-10);
        // MAD of a single value is 0
        assert!((model.capability_profiles[0].risk_score_mad).abs() < 1e-10);
    }

    #[test]
    fn baseline_sparse_markov_with_single_entry() {
        let entries = vec![make_test_ledger_entry(
            "ext.sparse",
            "log",
            "log",
            0.1,
            RuntimeRiskStateLabelValue::SafeFast,
            1000,
            "c1",
            None,
        )];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.sparse").unwrap();
        // No transitions possible with a single entry
        assert_eq!(model.transition_matrix.total_transitions, 0);
        // Stationary distribution should still exist (from smoothing)
        let sum: f64 = model.transition_matrix.stationary_distribution.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-6,
            "stationary distribution must sum to 1"
        );
    }

    #[test]
    fn baseline_per_capability_profiles_correct() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.20,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.30,
                RuntimeRiskStateLabelValue::SafeFast,
                3000,
                "c3",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "exec",
                "exec",
                0.90,
                RuntimeRiskStateLabelValue::Unsafe,
                4000,
                "c4",
                Some("denied"),
            ),
            make_test_ledger_entry(
                "ext.a",
                "exec",
                "exec",
                0.85,
                RuntimeRiskStateLabelValue::Suspicious,
                5000,
                "c5",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.a").unwrap();

        // Should have 2 capability profiles: exec and log (sorted by BTreeMap)
        assert_eq!(model.capability_profiles.len(), 2);
        let exec_prof = model
            .capability_profiles
            .iter()
            .find(|p| p.capability == "exec")
            .unwrap();
        let log_prof = model
            .capability_profiles
            .iter()
            .find(|p| p.capability == "log")
            .unwrap();

        assert_eq!(exec_prof.sample_count, 2);
        assert_eq!(log_prof.sample_count, 3);

        // Log median: sorted [0.10, 0.20, 0.30] → median = 0.20
        assert!((log_prof.risk_score_median - 0.20).abs() < 1e-10);

        // Exec median: sorted [0.85, 0.90] → median = (0.85 + 0.90)/2 = 0.875
        assert!((exec_prof.risk_score_median - 0.875).abs() < 1e-10);

        // Exec error rate: 1 error out of 2 = 0.5
        assert!((exec_prof.error_rate_median - 0.5).abs() < 1e-10);

        // Log error rate: 0 errors = 0.0
        assert!(log_prof.error_rate_median.abs() < 1e-10);
    }

    #[test]
    fn baseline_markov_transition_matrix_correct() {
        // Sequence: Safe → Safe → Suspicious → Unsafe → Safe → Suspicious
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.15,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "exec",
                "exec",
                0.7,
                RuntimeRiskStateLabelValue::Suspicious,
                3000,
                "c3",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "exec",
                "exec",
                0.95,
                RuntimeRiskStateLabelValue::Unsafe,
                4000,
                "c4",
                Some("denied"),
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                5000,
                "c5",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "exec",
                "exec",
                0.6,
                RuntimeRiskStateLabelValue::Suspicious,
                6000,
                "c6",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.a").unwrap();

        assert_eq!(model.transition_matrix.total_transitions, 5);
        // Safe→Safe: 1, Safe→Suspicious: 2, Suspicious→Unsafe: 1, Unsafe→Safe: 1
        assert_eq!(model.transition_matrix.counts[0][0], 1); // Safe→Safe
        assert_eq!(model.transition_matrix.counts[0][1], 2); // Safe→Suspicious
        assert_eq!(model.transition_matrix.counts[1][2], 1); // Suspicious→Unsafe
        assert_eq!(model.transition_matrix.counts[2][0], 1); // Unsafe→Safe
    }

    #[test]
    fn baseline_stationary_distribution_sums_to_one() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "exec",
                "exec",
                0.8,
                RuntimeRiskStateLabelValue::Suspicious,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                3000,
                "c3",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.a").unwrap();

        let sum: f64 = model.transition_matrix.stationary_distribution.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-6,
            "stationary distribution must sum to 1, got {sum}"
        );
    }

    #[test]
    fn baseline_from_ledger_serialization_roundtrip() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.serde",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.serde",
                "exec",
                "exec",
                0.9,
                RuntimeRiskStateLabelValue::Unsafe,
                2000,
                "c2",
                Some("timeout"),
            ),
            make_test_ledger_entry(
                "ext.serde",
                "http",
                "fetch",
                0.5,
                RuntimeRiskStateLabelValue::Suspicious,
                3000,
                "c3",
                None,
            ),
            make_test_ledger_entry(
                "ext.serde",
                "log",
                "log",
                0.15,
                RuntimeRiskStateLabelValue::SafeFast,
                4000,
                "c4",
                None,
            ),
            make_test_ledger_entry(
                "ext.serde",
                "log",
                "log",
                0.2,
                RuntimeRiskStateLabelValue::SafeFast,
                5000,
                "c5",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.serde").unwrap();

        let json = serde_json::to_string(&model).expect("serialize baseline");
        let deser: RuntimeRiskBaselineModel =
            serde_json::from_str(&json).expect("deserialize baseline");
        assert_eq!(model, deser, "roundtrip must preserve equality");
    }

    #[test]
    fn baseline_drift_detects_risk_score_anomaly() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.12,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.11,
                RuntimeRiskStateLabelValue::SafeFast,
                3000,
                "c3",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.13,
                RuntimeRiskStateLabelValue::SafeFast,
                4000,
                "c4",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                5000,
                "c5",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.a").unwrap();

        // Drift: live risk_score of 0.90 vs baseline median ~0.11
        let report = detect_baseline_drift(
            &model,
            "ext.a",
            "log",
            0.90, // far from median
            0.0,  // error rate
            0.0,  // burst 1s
            0.0,  // burst 10s
            &[],  // no recent states
        );
        assert!(
            report.drift_detected,
            "should detect drift for extreme score"
        );
        assert!(
            report.anomalies.iter().any(|a| a.metric == "risk_score"),
            "anomalies should include risk_score"
        );
    }

    #[test]
    fn baseline_drift_no_anomaly_within_normal_range() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.15,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.12,
                RuntimeRiskStateLabelValue::SafeFast,
                3000,
                "c3",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.14,
                RuntimeRiskStateLabelValue::SafeFast,
                4000,
                "c4",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.13,
                RuntimeRiskStateLabelValue::SafeFast,
                5000,
                "c5",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.a").unwrap();

        let report = detect_baseline_drift(
            &model,
            "ext.a",
            "log",
            0.13, // within normal range
            0.0,
            0.0,
            0.0,
            &[],
        );
        assert!(
            !report.drift_detected,
            "should not detect drift for values within normal range"
        );
    }

    #[test]
    fn baseline_drift_transition_anomaly_detected() {
        // Baseline: mostly Safe→Safe transitions
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                3000,
                "c3",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                4000,
                "c4",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                5000,
                "c5",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        // Use low divergence threshold and small smoothing so transition
        // anomaly is clearly detectable.
        let model =
            build_baseline_from_ledger_with_options(&artifact, "ext.a", 3.0, 0.01, 0.01).unwrap();

        // Live: mostly Unsafe→Unsafe transitions (very different from baseline)
        let live_states = vec![
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
            RuntimeRiskStateLabelValue::Unsafe,
        ];
        let report =
            detect_baseline_drift(&model, "ext.a", "log", 0.1, 0.0, 0.0, 0.0, &live_states);
        assert!(
            report.transition_divergence > 0.0,
            "divergence should be positive for different state patterns"
        );
        assert!(
            report.transition_anomalous,
            "should detect transition anomaly (div={:.4}, thr={:.4})",
            report.transition_divergence, model.transition_divergence_threshold,
        );
    }

    #[test]
    fn baseline_drift_anomaly_has_explanation() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.10,
                RuntimeRiskStateLabelValue::SafeFast,
                3000,
                "c3",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model = build_baseline_from_ledger(&artifact, "ext.a").unwrap();

        let report = detect_baseline_drift(
            &model,
            "ext.a",
            "log",
            0.95, // extreme anomaly
            0.0,
            0.0,
            0.0,
            &[],
        );
        assert!(report.drift_detected);
        let anomaly = report
            .anomalies
            .iter()
            .find(|a| a.metric == "risk_score")
            .unwrap();
        assert!(
            !anomaly.explanation.is_empty(),
            "anomaly must have explanation"
        );
        assert!(
            anomaly.explanation.contains("MAD"),
            "explanation should reference MAD, got: {}",
            anomaly.explanation,
        );
        assert!(anomaly.deviation_mads > 3.0, "deviation should be large");
    }

    #[test]
    fn baseline_rejects_invalid_ledger() {
        let artifact = RuntimeRiskLedgerArtifact {
            schema: "wrong_schema".to_string(),
            generated_at_ms: 1000,
            entry_count: 0,
            head_ledger_hash: None,
            tail_ledger_hash: None,
            data_hash: String::new(),
            entries: Vec::new(),
        };
        let result = build_baseline_from_ledger(&artifact, "ext.x");
        assert!(result.is_err());
    }

    #[test]
    fn baseline_rejects_empty_entries() {
        let artifact = RuntimeRiskLedgerArtifact {
            schema: RUNTIME_RISK_LEDGER_SCHEMA_VERSION.to_string(),
            generated_at_ms: 1000,
            entry_count: 0,
            head_ledger_hash: None,
            tail_ledger_hash: None,
            data_hash: runtime_risk_ledger_data_hash(&[]),
            entries: Vec::new(),
        };
        let result = build_baseline_from_ledger(&artifact, "ext.x");
        assert!(result.is_err());
    }

    #[test]
    fn baseline_rejects_missing_extension() {
        let entries = vec![make_test_ledger_entry(
            "ext.other",
            "log",
            "log",
            0.1,
            RuntimeRiskStateLabelValue::SafeFast,
            1000,
            "c1",
            None,
        )];
        let artifact = make_test_ledger_artifact(entries);
        let result = build_baseline_from_ledger(&artifact, "ext.missing");
        assert!(result.is_err());
    }

    #[test]
    fn baseline_kl_divergence_zero_for_identical() {
        let p = [0.6, 0.3, 0.1];
        assert!(kl_divergence(&p, &p).abs() < 1e-12);
    }

    #[test]
    fn baseline_kl_divergence_positive_for_different() {
        let p = [0.8, 0.1, 0.1];
        let q = [0.1, 0.1, 0.8];
        let kl = kl_divergence(&p, &q);
        assert!(
            kl > 0.0,
            "KL divergence should be positive for different distributions"
        );
    }

    #[test]
    fn baseline_median_correct() {
        assert!((baseline_median(&[1.0, 2.0, 3.0]) - 2.0).abs() < 1e-10);
        assert!((baseline_median(&[1.0, 2.0, 3.0, 4.0]) - 2.5).abs() < 1e-10);
        assert!((baseline_median(&[5.0]) - 5.0).abs() < 1e-10);
        assert!((baseline_median(&[]) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn baseline_mad_correct() {
        // Values: [1, 2, 3, 4, 5], median=3, deviations=[2,1,0,1,2], sorted=[0,1,1,2,2], MAD=1
        assert!((baseline_mad(&[1.0, 2.0, 3.0, 4.0, 5.0]) - 1.0).abs() < 1e-10);
        // Single value: MAD = 0
        assert!((baseline_mad(&[7.0]) - 0.0).abs() < 1e-10);
        assert!((baseline_mad(&[]) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn baseline_custom_thresholds_propagate() {
        let entries = vec![
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.1,
                RuntimeRiskStateLabelValue::SafeFast,
                1000,
                "c1",
                None,
            ),
            make_test_ledger_entry(
                "ext.a",
                "log",
                "log",
                0.15,
                RuntimeRiskStateLabelValue::SafeFast,
                2000,
                "c2",
                None,
            ),
        ];
        let artifact = make_test_ledger_artifact(entries);
        let model =
            build_baseline_from_ledger_with_options(&artifact, "ext.a", 5.0, 2.0, 0.1).unwrap();
        assert!((model.anomaly_threshold_mads - 5.0).abs() < 1e-10);
        assert!((model.transition_divergence_threshold - 2.0).abs() < 1e-10);
    }

    // ── SEC-3.3A: Bayesian evidence decomposition tests (bd-3ihzn) ──

    fn make_test_features(base: f64, recent_mean: f64) -> RuntimeHostcallFeatureVector {
        RuntimeHostcallFeatureVector {
            schema: "test".to_string(),
            base_score: base,
            recent_mean_score: recent_mean,
            recent_error_rate: 0.0,
            burst_density_1s: 0.0,
            burst_density_10s: 0.0,
            prior_failure_streak_norm: 0.0,
            dangerous_capability: 0.0,
            timeout_requested: 0.0,
            policy_prompt_bias: 0.0,
        }
    }

    fn make_test_posterior(safe: f64, suspicious: f64, unsafe_: f64) -> RuntimeRiskPosterior {
        RuntimeRiskPosterior {
            safe_fast: safe,
            suspicious,
            unsafe_,
        }
    }

    fn make_test_expected_loss() -> RuntimeRiskExpectedLoss {
        RuntimeRiskExpectedLoss {
            allow: 50.0,
            harden: 20.0,
            deny: 8.0,
            terminate: 5.0,
        }
    }

    #[test]
    fn explanation_allow_has_contributors() {
        let features = make_test_features(0.1, 0.05);
        let posterior = make_test_posterior(0.8, 0.15, 0.05);
        let loss = make_test_expected_loss();
        let (level, summary, contributors, budget) = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.1,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Compact);
        assert!(!contributors.is_empty(), "allow must have contributors");
        assert!(summary.contains("action=allow"));
        assert!(!budget.exhausted);
    }

    #[test]
    fn explanation_deny_has_full_detail() {
        let features = make_test_features(0.8, 0.7);
        let posterior = make_test_posterior(0.1, 0.3, 0.6);
        let loss = make_test_expected_loss();
        let (level, summary, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Deny,
            0.85,
            &posterior,
            &loss,
            &features,
            &["e_process_breach".to_string()],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Full);
        assert!(summary.contains("action=deny"));
        assert!(
            contributors.iter().any(|c| c.code == "posterior_unsafe"),
            "deny explanation must include posterior_unsafe contributor"
        );
        assert!(
            contributors
                .iter()
                .any(|c| c.code == "trigger_e_process_breach"),
            "deny explanation must include trigger contributor"
        );
    }

    #[test]
    fn explanation_terminate_has_full_detail() {
        let features = make_test_features(0.9, 0.85);
        let posterior = make_test_posterior(0.05, 0.15, 0.8);
        let loss = make_test_expected_loss();
        let (level, _, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Terminate,
            0.95,
            &posterior,
            &loss,
            &features,
            &["unsafe_streak".to_string()],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Full);
        assert!(
            contributors.iter().any(|c| c.code == "posterior_unsafe"),
            "terminate explanation must include posterior_unsafe"
        );
    }

    #[test]
    fn explanation_harden_has_standard_level() {
        let features = make_test_features(0.4, 0.3);
        let posterior = make_test_posterior(0.5, 0.35, 0.15);
        let loss = make_test_expected_loss();
        let (level, summary, _, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Harden,
            0.4,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Standard);
        assert!(summary.contains("action=harden"));
    }

    #[test]
    fn explanation_contributors_sorted_by_magnitude_desc() {
        let features = RuntimeHostcallFeatureVector {
            schema: "test".to_string(),
            base_score: 0.5,
            recent_mean_score: 0.3,
            recent_error_rate: 0.8,
            burst_density_1s: 0.6,
            burst_density_10s: 0.0,
            prior_failure_streak_norm: 0.2,
            dangerous_capability: 0.0,
            timeout_requested: 0.0,
            policy_prompt_bias: 0.0,
        };
        let posterior = make_test_posterior(0.3, 0.3, 0.4);
        let loss = make_test_expected_loss();
        let (_, _, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Harden,
            0.5,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        for window in contributors.windows(2) {
            assert!(
                window[0].magnitude >= window[1].magnitude
                    || (window[0].magnitude == window[1].magnitude
                        && window[0].code <= window[1].code),
                "contributors must be sorted by magnitude desc, then code asc: {:?} vs {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn explanation_deterministic_replay() {
        let features = make_test_features(0.6, 0.5);
        let posterior = make_test_posterior(0.3, 0.4, 0.3);
        let loss = make_test_expected_loss();
        let triggers = vec!["drift_detected".to_string()];
        let results: Vec<_> = (0..5)
            .map(|_| {
                runtime_risk_build_explanation(
                    RuntimeRiskAction::Harden,
                    0.55,
                    &posterior,
                    &loss,
                    &features,
                    &triggers,
                    None,
                    RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
                    RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
                )
            })
            .collect();
        for (i, (level, summary, contributors, _)) in results.iter().enumerate().skip(1) {
            assert_eq!(*level, results[0].0, "level mismatch at iteration {i}");
            assert_eq!(*summary, results[0].1, "summary mismatch at iteration {i}");
            assert_eq!(
                contributors.len(),
                results[0].2.len(),
                "contributor count mismatch at iteration {i}"
            );
            for (j, contrib) in contributors.iter().enumerate() {
                assert_eq!(
                    contrib.code, results[0].2[j].code,
                    "contributor code mismatch at [{i}][{j}]"
                );
                assert!(
                    (contrib.signed_impact - results[0].2[j].signed_impact).abs() < 1e-12,
                    "contributor impact mismatch at [{i}][{j}]"
                );
            }
        }
    }

    #[test]
    fn explanation_deterministic_ordering_stable() {
        let features = make_test_features(0.3, 0.3);
        let posterior = make_test_posterior(0.5, 0.3, 0.2);
        let loss = make_test_expected_loss();
        let first = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.3,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        let second = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.3,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        let codes_first: Vec<&str> = first.2.iter().map(|c| c.code.as_str()).collect();
        let codes_second: Vec<&str> = second.2.iter().map(|c| c.code.as_str()).collect();
        assert_eq!(
            codes_first, codes_second,
            "contributor ordering must be stable across replays"
        );
    }

    #[test]
    fn explanation_budget_exhausted_by_terms() {
        let features = make_test_features(0.5, 0.4);
        let posterior = make_test_posterior(0.3, 0.3, 0.4);
        let loss = make_test_expected_loss();
        // Use term_budget=1 to force budget exhaustion (normal produces 8+ contributors)
        let (level, summary, contributors, budget) = runtime_risk_build_explanation(
            RuntimeRiskAction::Deny,
            0.7,
            &posterior,
            &loss,
            &features,
            &["e_process_breach".to_string(), "drift_detected".to_string()],
            None,
            1,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Compact);
        assert!(budget.exhausted, "budget must be exhausted");
        assert!(budget.fallback_mode, "must be in fallback mode");
        assert_eq!(contributors.len(), 2, "fallback produces exactly 2 terms");
        assert!(
            contributors[0].code.starts_with("action_"),
            "first fallback contributor must be action code"
        );
        assert_eq!(
            contributors[1].code, "budget_exhausted",
            "second fallback contributor must be budget_exhausted"
        );
        assert!(
            summary.contains("conservative_explanation_fallback=true"),
            "summary must indicate fallback mode"
        );
    }

    #[test]
    fn explanation_budget_fallback_preserves_action() {
        let features = make_test_features(0.5, 0.5);
        let posterior = make_test_posterior(0.2, 0.3, 0.5);
        let loss = make_test_expected_loss();
        for action in [
            RuntimeRiskAction::Allow,
            RuntimeRiskAction::Harden,
            RuntimeRiskAction::Deny,
            RuntimeRiskAction::Terminate,
        ] {
            let (_, _, contributors, budget) = runtime_risk_build_explanation(
                action,
                0.7,
                &posterior,
                &loss,
                &features,
                &["trigger".to_string()],
                None,
                1,
                RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
            );
            assert!(budget.fallback_mode);
            let action_code = runtime_risk_action_code(action);
            assert_eq!(
                contributors[0].code,
                format!("action_{action_code}"),
                "fallback must preserve action {action_code}"
            );
        }
    }

    #[test]
    fn explanation_budget_state_tracks_terms() {
        let features = make_test_features(0.2, 0.1);
        let posterior = make_test_posterior(0.7, 0.2, 0.1);
        let loss = make_test_expected_loss();
        let (_, _, contributors, budget) = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.15,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(budget.terms_emitted, contributors.len());
        assert_eq!(budget.term_budget, RUNTIME_RISK_EXPLANATION_TERM_BUDGET);
        assert_eq!(
            budget.time_budget_ms,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS
        );
        assert!(!budget.exhausted);
        assert!(!budget.fallback_mode);
    }

    #[test]
    fn explanation_trigger_adds_contributor() {
        let features = make_test_features(0.5, 0.4);
        let posterior = make_test_posterior(0.4, 0.3, 0.3);
        let loss = make_test_expected_loss();
        let (_, _, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Harden,
            0.5,
            &posterior,
            &loss,
            &features,
            &["e_process_breach".to_string(), "drift_detected".to_string()],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert!(
            contributors
                .iter()
                .any(|c| c.code == "trigger_e_process_breach"),
            "e_process_breach trigger must generate contributor"
        );
        assert!(
            contributors
                .iter()
                .any(|c| c.code == "trigger_drift_detected"),
            "drift_detected trigger must generate contributor"
        );
    }

    #[test]
    fn explanation_fallback_reason_adds_contributor() {
        let features = make_test_features(0.3, 0.2);
        let posterior = make_test_posterior(0.6, 0.25, 0.15);
        let loss = make_test_expected_loss();
        let (level, _, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Harden,
            0.3,
            &posterior,
            &loss,
            &features,
            &[],
            Some("decision_timeout"),
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Full);
        assert!(
            contributors
                .iter()
                .any(|c| c.code == "fallback_decision_timeout"),
            "fallback reason must generate contributor"
        );
    }

    #[test]
    fn explanation_posterior_decomposition_present() {
        let features = make_test_features(0.5, 0.4);
        let posterior = make_test_posterior(0.3, 0.35, 0.35);
        let loss = make_test_expected_loss();
        let (_, _, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Harden,
            0.5,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert!(
            contributors.iter().any(|c| c.code == "posterior_unsafe"),
            "must include posterior_unsafe contributor"
        );
        assert!(
            contributors
                .iter()
                .any(|c| c.code == "posterior_suspicious"),
            "must include posterior_suspicious contributor"
        );
    }

    #[test]
    fn explanation_expected_loss_delta_present() {
        let features = make_test_features(0.5, 0.4);
        let posterior = make_test_posterior(0.3, 0.35, 0.35);
        let loss = RuntimeRiskExpectedLoss {
            allow: 80.0,
            harden: 30.0,
            deny: 10.0,
            terminate: 5.0,
        };
        let (_, _, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Deny,
            0.7,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        let loss_contrib = contributors
            .iter()
            .find(|c| c.code == "expected_loss_delta_vs_allow")
            .expect("must include expected_loss_delta_vs_allow contributor");
        assert!(
            (loss_contrib.signed_impact - (80.0 - 10.0)).abs() < 1e-10,
            "loss delta must be allow_loss - deny_loss = 70.0, got {}",
            loss_contrib.signed_impact
        );
    }

    #[test]
    fn explanation_feature_weights_match_scoring() {
        let features = RuntimeHostcallFeatureVector {
            schema: "test".to_string(),
            base_score: 0.6,
            recent_mean_score: 0.4,
            recent_error_rate: 0.5,
            burst_density_1s: 0.3,
            burst_density_10s: 0.0,
            prior_failure_streak_norm: 0.2,
            dangerous_capability: 0.0,
            timeout_requested: 0.0,
            policy_prompt_bias: 0.0,
        };
        let posterior = make_test_posterior(0.4, 0.3, 0.3);
        let loss = make_test_expected_loss();
        let (_, _, contributors, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Harden,
            0.5,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        let base = contributors
            .iter()
            .find(|c| c.code == "feature_base_score")
            .expect("must have feature_base_score");
        assert!(
            (base.signed_impact - 0.65 * 0.6).abs() < 1e-10,
            "base_score weight must be 0.65"
        );
        let recent = contributors
            .iter()
            .find(|c| c.code == "feature_recent_mean_score")
            .expect("must have feature_recent_mean_score");
        assert!(
            (recent.signed_impact - 0.35 * 0.4).abs() < 1e-10,
            "recent_mean_score weight must be 0.35"
        );
        let error = contributors
            .iter()
            .find(|c| c.code == "feature_recent_error_rate")
            .expect("must have feature_recent_error_rate");
        assert!(
            (error.signed_impact - 0.12 * 0.5).abs() < 1e-10,
            "recent_error_rate weight must be 0.12"
        );
        let burst = contributors
            .iter()
            .find(|c| c.code == "feature_burst_density_1s")
            .expect("must have feature_burst_density_1s");
        assert!(
            (burst.signed_impact - 0.08 * 0.3).abs() < 1e-10,
            "burst_density_1s weight must be 0.08"
        );
        let streak = contributors
            .iter()
            .find(|c| c.code == "feature_prior_failure_streak")
            .expect("must have feature_prior_failure_streak");
        assert!(
            (streak.signed_impact - 0.05 * 0.2).abs() < 1e-10,
            "prior_failure_streak_norm weight must be 0.05"
        );
    }

    #[test]
    fn explanation_level_escalation_with_triggers() {
        let features = make_test_features(0.3, 0.2);
        let posterior = make_test_posterior(0.6, 0.25, 0.15);
        let loss = make_test_expected_loss();
        // Allow with no triggers → Compact
        let (level, _, _, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.2,
            &posterior,
            &loss,
            &features,
            &[],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Compact);
        // Allow with triggers → Standard
        let (level, _, _, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Allow,
            0.2,
            &posterior,
            &loss,
            &features,
            &["feature_budget_exceeded".to_string()],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert_eq!(level, RuntimeRiskExplanationLevelValue::Standard);
    }

    #[test]
    fn explanation_schema_version_correct() {
        assert_eq!(
            RUNTIME_RISK_EXPLANATION_SCHEMA_VERSION,
            "pi.ext.runtime_risk_explanation.v1"
        );
    }

    #[test]
    fn explanation_sort_tiebreak_by_code() {
        let mut contributors = vec![
            RuntimeRiskExplanationContributor {
                code: "zzz".to_string(),
                signed_impact: 0.5,
                magnitude: 0.5,
                rationale: String::new(),
            },
            RuntimeRiskExplanationContributor {
                code: "aaa".to_string(),
                signed_impact: 0.5,
                magnitude: 0.5,
                rationale: String::new(),
            },
        ];
        runtime_risk_sort_contributors(&mut contributors);
        assert_eq!(contributors[0].code, "aaa");
        assert_eq!(contributors[1].code, "zzz");
    }

    #[test]
    fn explanation_summary_format_normal() {
        let features = make_test_features(0.4, 0.3);
        let posterior = make_test_posterior(0.4, 0.35, 0.25);
        let loss = make_test_expected_loss();
        let (_, summary, _, budget) = runtime_risk_build_explanation(
            RuntimeRiskAction::Harden,
            0.4,
            &posterior,
            &loss,
            &features,
            &["drift_detected".to_string()],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert!(!budget.fallback_mode);
        assert!(summary.contains("action=harden"));
        assert!(summary.contains("score=0.400"));
        assert!(summary.contains("unsafe="));
        assert!(summary.contains("suspicious="));
        assert!(summary.contains("triggers=drift_detected"));
    }

    #[test]
    fn explanation_summary_triggers_sorted() {
        let features = make_test_features(0.5, 0.4);
        let posterior = make_test_posterior(0.3, 0.35, 0.35);
        let loss = make_test_expected_loss();
        let (_, summary, _, _) = runtime_risk_build_explanation(
            RuntimeRiskAction::Deny,
            0.7,
            &posterior,
            &loss,
            &features,
            &["zzz_trigger".to_string(), "aaa_trigger".to_string()],
            None,
            RUNTIME_RISK_EXPLANATION_TERM_BUDGET,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS,
        );
        assert!(
            summary.contains("triggers=aaa_trigger|zzz_trigger"),
            "triggers in summary must be sorted: {summary}"
        );
    }

    #[test]
    fn explanation_e2e_through_manager() {
        let manager = ExtensionManager::new();
        manager.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 1024,
            decision_timeout_ms: 5000,
            fail_closed: true,
        });
        let meta = RuntimeRiskCallMetadata {
            args_shape_hash: "hash_test",
            resource_target_class: "fs",
            timeout_ms: None,
            policy_profile: "permissive",
        };
        let decision = manager
            .evaluate_runtime_risk(
                Some("ext.test.explain"),
                "call-1",
                "exec",
                "exec",
                "param_hash",
                meta,
                "permissive",
            )
            .expect("decision must be returned when enabled");
        assert_eq!(
            decision.explanation_schema,
            RUNTIME_RISK_EXPLANATION_SCHEMA_VERSION
        );
        assert!(!decision.top_contributors.is_empty());
        assert!(!decision.explanation_summary.is_empty());
        // Verify deterministic replay
        let manager2 = ExtensionManager::new();
        manager2.set_runtime_risk_config(RuntimeRiskConfig {
            enabled: true,
            alpha: 0.01,
            window_size: 64,
            ledger_limit: 1024,
            decision_timeout_ms: 5000,
            fail_closed: true,
        });
        let decision2 = manager2
            .evaluate_runtime_risk(
                Some("ext.test.explain"),
                "call-1",
                "exec",
                "exec",
                "param_hash",
                meta,
                "permissive",
            )
            .expect("decision must be returned");
        assert_eq!(decision.explanation_level, decision2.explanation_level);
        assert_eq!(
            decision.top_contributors.len(),
            decision2.top_contributors.len()
        );
        for (a, b) in decision
            .top_contributors
            .iter()
            .zip(decision2.top_contributors.iter())
        {
            assert_eq!(a.code, b.code);
            assert!(
                (a.signed_impact - b.signed_impact).abs() < 1e-12,
                "contributor impacts must be identical across replays"
            );
        }
    }

    #[test]
    fn explanation_budget_default_values() {
        let budget = RuntimeRiskExplanationBudgetState::default();
        assert_eq!(
            budget.time_budget_ms,
            RUNTIME_RISK_EXPLANATION_TIME_BUDGET_MS
        );
        assert_eq!(budget.term_budget, RUNTIME_RISK_EXPLANATION_TERM_BUDGET);
        assert_eq!(budget.elapsed_ms, 0);
        assert_eq!(budget.terms_emitted, 0);
        assert!(!budget.exhausted);
        assert!(!budget.fallback_mode);
    }
}
