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
    fn report_json_roundtrip() {
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
}
