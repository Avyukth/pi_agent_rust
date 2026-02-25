//! Performance & latency evidence pipeline (bd-1xz.4).
//!
//! Shared schemas, helpers, and ingestion logic for benchmark evidence
//! across criterion suites, custom latency measurements, and CI artifact
//! workflows. Supports per-machine baseline comparison without forcing a
//! single universal threshold.
//!
//! # Schemas
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`EnvFingerprint`] | Machine/build environment metadata |
//! | [`PercentileStats`] | p50/p95/p99/min/max summary |
//! | [`BenchmarkRecord`] | Unified evidence record envelope |
//! | [`BaselineEntry`] | Per-machine baseline with tolerances |
//! | [`BaselineComparison`] | Comparison result: pass/regressed/improved |
//! | [`EvidenceReport`] | Aggregated report for CI output |
//! | [`ArtifactMetadata`] | CI artifact provenance and diagnostics |
//!
//! # Per-Machine Baselines
//!
//! The [`BaselineStore`] groups reference values by machine ID (derived from
//! hardware fingerprint). Each machine has its own thresholds, avoiding
//! false positives from cross-hardware comparisons.
//!
//! # Criterion Ingestion
//!
//! [`ingest_criterion_dir`] reads `estimates.json` files from criterion's
//! output directory and normalizes them into [`BenchmarkRecord`]s.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Schema version for the evidence pipeline envelope.
pub const EVIDENCE_SCHEMA_VERSION: &str = "pi.perf.evidence.v1";

/// Default regression threshold (20% worse than baseline).
pub const DEFAULT_REGRESSION_THRESHOLD_PCT: f64 = 20.0;

/// Default improvement threshold (10% better than baseline).
pub const DEFAULT_IMPROVEMENT_THRESHOLD_PCT: f64 = 10.0;

// ─── Environment Fingerprint ──────────────────────────────────────────────

/// Machine and build environment metadata embedded in every evidence record.
///
/// Provides enough context to compare baselines across machines without
/// requiring identical hardware. The [`machine_id`](Self::machine_id) groups
/// results by hardware tier for per-machine baseline comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvFingerprint {
    /// Operating system name and version.
    pub os: String,
    /// CPU architecture (e.g., `"x86_64"`, `"aarch64"`).
    pub arch: String,
    /// CPU model string.
    pub cpu_model: String,
    /// Logical CPU core count.
    pub cpu_cores: u32,
    /// Total system memory in MB.
    pub mem_total_mb: u64,
    /// Cargo build profile: `"debug"`, `"release"`, or `"perf"`.
    pub build_profile: String,
    /// Short git commit hash.
    pub git_commit: String,
    /// Active Cargo feature flags.
    #[serde(default)]
    pub features: Vec<String>,
    /// SHA-256 of concatenated env fields for dedup/comparison.
    pub config_hash: String,
}

impl EnvFingerprint {
    /// Collect the current environment fingerprint from the running system.
    pub fn collect() -> Self {
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_all();
        sys.refresh_memory();

        let cpu_model = sys
            .cpus()
            .first()
            .map_or_else(|| "unknown".to_string(), |c| c.brand().to_string());
        let cpu_cores = sys.cpus().len() as u32;
        let mem_total_mb = sys.total_memory() / 1024 / 1024;
        let os =
            sysinfo::System::long_os_version().unwrap_or_else(|| std::env::consts::OS.to_string());
        let arch = std::env::consts::ARCH.to_string();
        let build_profile = crate::perf_build::detect_build_profile();
        let git_commit = option_env!("VERGEN_GIT_SHA")
            .unwrap_or("unknown")
            .to_string();

        let config_input = format!(
            "os={os} arch={arch} cpu={cpu_model} cores={cpu_cores} mem={mem_total_mb} \
             profile={build_profile} git={git_commit}"
        );
        let config_hash = sha256_hex(&config_input);

        Self {
            os,
            arch,
            cpu_model,
            cpu_cores,
            mem_total_mb,
            build_profile,
            git_commit,
            features: Vec::new(),
            config_hash,
        }
    }

    /// Compute a stable machine ID for baseline grouping.
    ///
    /// Groups by OS + arch + CPU model + core count + memory tier, so
    /// different builds on the same machine share a baseline while different
    /// hardware gets its own reference values.
    pub fn machine_id(&self) -> String {
        let mem_tier = match self.mem_total_mb {
            0..=4096 => "4gb",
            4097..=8192 => "8gb",
            8193..=16384 => "16gb",
            16385..=32768 => "32gb",
            _ => "64gb+",
        };
        let input = format!(
            "{}-{}-{}-{}c-{}",
            self.os, self.arch, self.cpu_model, self.cpu_cores, mem_tier
        );
        sha256_hex(&input)[..16].to_string()
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ─── Statistics ───────────────────────────────────────────────────────────

/// Percentile summary statistics for latency or throughput data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PercentileStats {
    /// Number of samples.
    pub sample_count: u64,
    /// Minimum observed value.
    pub min: f64,
    /// 50th percentile (median).
    pub p50: f64,
    /// 95th percentile.
    pub p95: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Maximum observed value.
    pub max: f64,
    /// Arithmetic mean.
    pub mean: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// Unit of measurement (e.g., `"us"`, `"ms"`, `"ns"`, `"bytes"`, `"calls/s"`).
    pub unit: String,
}

impl PercentileStats {
    /// Compute percentile stats from a mutable slice of samples.
    ///
    /// The slice is sorted in place. Returns `None` if the slice is empty.
    pub fn from_samples(samples: &mut [f64], unit: &str) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = samples.len();
        let sum: f64 = samples.iter().sum();
        let mean = sum / n as f64;
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;

        Some(Self {
            sample_count: n as u64,
            min: samples[0],
            p50: percentile_sorted(samples, 50.0),
            p95: percentile_sorted(samples, 95.0),
            p99: percentile_sorted(samples, 99.0),
            max: samples[n - 1],
            mean,
            stddev: variance.sqrt(),
            unit: unit.to_string(),
        })
    }
}

/// Compute a percentile value from a pre-sorted slice using nearest-rank.
fn percentile_sorted(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (pct / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ─── Evidence Records ─────────────────────────────────────────────────────

/// Source of a benchmark measurement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Criterion micro-benchmark output.
    Criterion,
    /// Custom latency measurement harness.
    Custom,
    /// PiJS workload harness.
    Workload,
    /// Hyperfine startup time measurement.
    Hyperfine,
    /// Extension benchmark.
    ExtensionBench,
}

/// Unified benchmark evidence record.
///
/// Every measurement — whether from criterion, a custom harness, or
/// workload bench — is normalized into this envelope for storage,
/// comparison, and CI artifact upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRecord {
    /// Schema identifier for forward compatibility.
    pub schema: String,
    /// Benchmark or scenario name.
    pub name: String,
    /// Category grouping (e.g., `"latency"`, `"throughput"`, `"startup"`, `"memory"`).
    pub category: String,
    /// Source of the measurement.
    pub source: EvidenceSource,
    /// Environment fingerprint at measurement time.
    pub env: EnvFingerprint,
    /// Percentile statistics (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<PercentileStats>,
    /// Single scalar value (when stats are not applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// Unit for the `value` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_unit: Option<String>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Additional scenario-specific metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl BenchmarkRecord {
    /// Create a new record with current environment and timestamp.
    pub fn new(name: &str, category: &str, source: EvidenceSource) -> Self {
        Self {
            schema: EVIDENCE_SCHEMA_VERSION.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            source,
            env: EnvFingerprint::collect(),
            stats: None,
            value: None,
            value_unit: None,
            timestamp: Utc::now().to_rfc3339(),
            metadata: BTreeMap::new(),
        }
    }

    /// Attach percentile stats to this record.
    pub fn with_stats(mut self, stats: PercentileStats) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Attach a scalar value to this record.
    pub fn with_value(mut self, value: f64, unit: &str) -> Self {
        self.value = Some(value);
        self.value_unit = Some(unit.to_string());
        self
    }

    /// Add a metadata key-value pair.
    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    /// The primary numeric value for comparison.
    ///
    /// Returns `p50` from stats if available, otherwise the scalar `value`.
    pub fn primary_value(&self) -> Option<f64> {
        self.stats.as_ref().map(|s| s.p50).or(self.value)
    }
}

// ─── Baseline Comparison ──────────────────────────────────────────────────

/// A baseline entry for one benchmark on one machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Benchmark name.
    pub name: String,
    /// Machine ID (from [`EnvFingerprint::machine_id`]).
    pub machine_id: String,
    /// Reference value (typically p50).
    pub reference_value: f64,
    /// Unit of measurement.
    pub unit: String,
    /// Custom regression threshold override (percentage).
    /// If `None`, uses [`DEFAULT_REGRESSION_THRESHOLD_PCT`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regression_threshold_pct: Option<f64>,
    /// Git commit where baseline was captured.
    pub git_commit: String,
    /// ISO 8601 timestamp.
    pub captured_at: String,
    /// Number of samples used to establish baseline.
    pub sample_count: u64,
}

/// Result of comparing a measurement against its baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonVerdict {
    /// Within acceptable tolerance.
    Pass,
    /// Significantly worse than baseline.
    Regressed,
    /// Significantly better than baseline.
    Improved,
    /// No baseline available for this machine.
    NoBaseline,
}

/// Comparison of a single measurement against its baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    /// Benchmark name.
    pub name: String,
    /// Machine ID used for lookup.
    pub machine_id: String,
    /// Current measured value.
    pub current_value: f64,
    /// Baseline reference value (if available).
    pub baseline_value: Option<f64>,
    /// Percentage change from baseline (positive = regression).
    pub delta_pct: Option<f64>,
    /// Threshold used for verdict.
    pub threshold_pct: f64,
    /// Pass/regressed/improved/no-baseline.
    pub verdict: ComparisonVerdict,
    /// Unit of measurement.
    pub unit: String,
}

/// Per-machine baseline store.
///
/// Baselines are keyed by `(machine_id, benchmark_name)`. Each machine has
/// its own reference values, avoiding cross-hardware false positives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineStore {
    /// All baseline entries.
    pub entries: Vec<BaselineEntry>,
}

impl BaselineStore {
    /// Load from a JSON file. Returns empty store if file doesn't exist.
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Save to a JSON file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }

    /// Find baseline for a specific benchmark on a specific machine.
    pub fn find(&self, machine_id: &str, name: &str) -> Option<&BaselineEntry> {
        self.entries
            .iter()
            .find(|e| e.machine_id == machine_id && e.name == name)
    }

    /// Upsert a baseline entry (update existing or insert new).
    pub fn upsert(&mut self, entry: BaselineEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.machine_id == entry.machine_id && e.name == entry.name)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Compare a record against its machine-specific baseline.
    pub fn compare(&self, record: &BenchmarkRecord) -> BaselineComparison {
        let machine_id = record.env.machine_id();
        let current = record.primary_value().unwrap_or(0.0);
        let unit = record
            .stats
            .as_ref()
            .map(|s| s.unit.clone())
            .or_else(|| record.value_unit.clone())
            .unwrap_or_default();

        match self.find(&machine_id, &record.name) {
            Some(baseline) => {
                let threshold = baseline
                    .regression_threshold_pct
                    .unwrap_or(DEFAULT_REGRESSION_THRESHOLD_PCT);
                let delta_pct = if baseline.reference_value.abs() > f64::EPSILON {
                    ((current - baseline.reference_value) / baseline.reference_value) * 100.0
                } else {
                    0.0
                };
                let verdict = if delta_pct > threshold {
                    ComparisonVerdict::Regressed
                } else if delta_pct < -DEFAULT_IMPROVEMENT_THRESHOLD_PCT {
                    ComparisonVerdict::Improved
                } else {
                    ComparisonVerdict::Pass
                };
                BaselineComparison {
                    name: record.name.clone(),
                    machine_id,
                    current_value: current,
                    baseline_value: Some(baseline.reference_value),
                    delta_pct: Some(delta_pct),
                    threshold_pct: threshold,
                    verdict,
                    unit,
                }
            }
            None => BaselineComparison {
                name: record.name.clone(),
                machine_id,
                current_value: current,
                baseline_value: None,
                delta_pct: None,
                threshold_pct: DEFAULT_REGRESSION_THRESHOLD_PCT,
                verdict: ComparisonVerdict::NoBaseline,
                unit,
            },
        }
    }

    /// Create a baseline entry from a benchmark record.
    pub fn entry_from_record(record: &BenchmarkRecord) -> Option<BaselineEntry> {
        let value = record.primary_value()?;
        let unit = record
            .stats
            .as_ref()
            .map(|s| s.unit.clone())
            .or_else(|| record.value_unit.clone())
            .unwrap_or_default();
        let sample_count = record.stats.as_ref().map(|s| s.sample_count).unwrap_or(1);

        Some(BaselineEntry {
            name: record.name.clone(),
            machine_id: record.env.machine_id(),
            reference_value: value,
            unit,
            regression_threshold_pct: None,
            git_commit: record.env.git_commit.clone(),
            captured_at: record.timestamp.clone(),
            sample_count,
        })
    }
}

// ─── Criterion Ingestion ──────────────────────────────────────────────────

/// Parsed criterion benchmark estimate (single statistic).
#[derive(Debug, Clone, Deserialize)]
struct CriterionEstimate {
    point_estimate: f64,
    #[allow(dead_code)]
    standard_error: f64,
    confidence_interval: CriterionCI,
}

#[derive(Debug, Clone, Deserialize)]
struct CriterionCI {
    #[allow(dead_code)]
    confidence_level: f64,
    lower_bound: f64,
    upper_bound: f64,
}

/// Parsed criterion `estimates.json` file.
#[derive(Debug, Clone, Deserialize)]
struct CriterionEstimates {
    mean: CriterionEstimate,
    median: CriterionEstimate,
    #[serde(default)]
    std_dev: Option<CriterionEstimate>,
}

/// Ingest criterion benchmark results from a `target/criterion/` directory.
///
/// Reads `estimates.json` files under `<dir>/<group>/<bench>/new/` and
/// converts them into [`BenchmarkRecord`]s with the current environment.
pub fn ingest_criterion_dir(criterion_dir: &Path) -> Vec<BenchmarkRecord> {
    let mut records = Vec::new();
    ingest_criterion_recursive(criterion_dir, criterion_dir, &mut records);
    records
}

fn ingest_criterion_recursive(
    base_dir: &Path,
    current_dir: &Path,
    records: &mut Vec<BenchmarkRecord>,
) {
    let new_dir = current_dir.join("new");
    let estimates_path = new_dir.join("estimates.json");

    if estimates_path.is_file() {
        if let Some(record) = parse_criterion_estimates(base_dir, current_dir, &estimates_path) {
            records.push(record);
        }
    }

    if let Ok(entries) = std::fs::read_dir(current_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.file_name().is_some_and(|n| n != "new" && n != "base") {
                ingest_criterion_recursive(base_dir, &path, records);
            }
        }
    }
}

fn parse_criterion_estimates(
    base_dir: &Path,
    bench_dir: &Path,
    estimates_path: &Path,
) -> Option<BenchmarkRecord> {
    let content = std::fs::read_to_string(estimates_path).ok()?;
    let estimates: CriterionEstimates = serde_json::from_str(&content).ok()?;

    let name = bench_dir
        .strip_prefix(base_dir)
        .ok()?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");

    let stddev = estimates
        .std_dev
        .as_ref()
        .map(|s| s.point_estimate)
        .unwrap_or(0.0);

    // Criterion reports in nanoseconds by default.
    let mut record = BenchmarkRecord::new(&name, "latency", EvidenceSource::Criterion);
    record.stats = Some(PercentileStats {
        sample_count: 0, // criterion doesn't expose sample count in estimates.json
        min: estimates.mean.confidence_interval.lower_bound,
        p50: estimates.median.point_estimate,
        p95: estimates.mean.point_estimate + 1.645 * stddev,
        p99: estimates.mean.point_estimate + 2.326 * stddev,
        max: estimates.mean.confidence_interval.upper_bound,
        mean: estimates.mean.point_estimate,
        stddev,
        unit: "ns".to_string(),
    });

    Some(record)
}

// ─── Custom Latency Measurement ───────────────────────────────────────────

/// Record a custom latency measurement from raw sample data.
///
/// Computes percentile statistics and wraps them in a [`BenchmarkRecord`]
/// with [`EvidenceSource::Custom`].
pub fn record_latency(
    name: &str,
    samples_us: &mut [f64],
    metadata: BTreeMap<String, serde_json::Value>,
) -> Option<BenchmarkRecord> {
    let stats = PercentileStats::from_samples(samples_us, "us")?;
    let mut record = BenchmarkRecord::new(name, "latency", EvidenceSource::Custom);
    record.stats = Some(stats);
    record.metadata = metadata;
    Some(record)
}

// ─── Evidence Report ──────────────────────────────────────────────────────

/// Aggregated evidence report for CI output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReport {
    /// Schema identifier.
    pub schema: String,
    /// ISO 8601 generation timestamp.
    pub generated_at: String,
    /// Machine ID for this report.
    pub machine_id: String,
    /// Environment fingerprint.
    pub env: EnvFingerprint,
    /// All benchmark records.
    pub records: Vec<BenchmarkRecord>,
    /// Baseline comparisons.
    pub comparisons: Vec<BaselineComparison>,
    /// Summary statistics.
    pub summary: ReportSummary,
}

/// Summary statistics for an evidence report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total number of benchmarks.
    pub total_benchmarks: usize,
    /// Benchmarks within tolerance.
    pub passed: usize,
    /// Benchmarks that regressed.
    pub regressed: usize,
    /// Benchmarks that improved.
    pub improved: usize,
    /// Benchmarks without a baseline.
    pub no_baseline: usize,
    /// Overall verdict: `true` if no regressions detected.
    pub gate_passed: bool,
}

impl EvidenceReport {
    /// Generate a report from records and a baseline store.
    pub fn generate(records: Vec<BenchmarkRecord>, baselines: &BaselineStore) -> Self {
        let env = if let Some(first) = records.first() {
            first.env.clone()
        } else {
            EnvFingerprint::collect()
        };
        let machine_id = env.machine_id();

        let comparisons: Vec<BaselineComparison> =
            records.iter().map(|r| baselines.compare(r)).collect();

        let passed = comparisons
            .iter()
            .filter(|c| c.verdict == ComparisonVerdict::Pass)
            .count();
        let regressed = comparisons
            .iter()
            .filter(|c| c.verdict == ComparisonVerdict::Regressed)
            .count();
        let improved = comparisons
            .iter()
            .filter(|c| c.verdict == ComparisonVerdict::Improved)
            .count();
        let no_baseline = comparisons
            .iter()
            .filter(|c| c.verdict == ComparisonVerdict::NoBaseline)
            .count();

        Self {
            schema: EVIDENCE_SCHEMA_VERSION.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            machine_id,
            env,
            summary: ReportSummary {
                total_benchmarks: records.len(),
                passed,
                regressed,
                improved,
                no_baseline,
                gate_passed: regressed == 0,
            },
            records,
            comparisons,
        }
    }

    /// Serialize to JSONL format (one line per record) for CI artifact upload.
    pub fn to_jsonl(&self) -> String {
        let mut lines = Vec::new();

        // Envelope line with summary
        let envelope = serde_json::json!({
            "schema": self.schema,
            "generated_at": self.generated_at,
            "machine_id": self.machine_id,
            "env": self.env,
            "summary": self.summary,
        });
        lines.push(serde_json::to_string(&envelope).unwrap_or_default());

        // Individual record lines
        for record in &self.records {
            if let Ok(line) = serde_json::to_string(record) {
                lines.push(line);
            }
        }

        // Comparison lines
        for comparison in &self.comparisons {
            if let Ok(line) = serde_json::to_string(comparison) {
                lines.push(line);
            }
        }

        lines.join("\n") + "\n"
    }
}

// ─── CI Artifact Metadata ─────────────────────────────────────────────────

/// Metadata for CI artifact provenance and diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// Artifact name for upload.
    pub name: String,
    /// Local file path.
    pub path: PathBuf,
    /// Retention period in days.
    pub retention_days: u32,
    /// Git commit hash.
    pub git_commit: String,
    /// CI run identifier (from `GITHUB_RUN_ID` env).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_run_id: Option<String>,
    /// Content SHA-256 for integrity verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

impl ArtifactMetadata {
    /// Create metadata for a local artifact file.
    ///
    /// Computes content hash from the file at `path` if it exists.
    pub fn for_file(name: &str, path: PathBuf, retention_days: u32) -> Self {
        let content_hash = std::fs::read(&path).ok().map(|bytes| {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            format!("{:x}", hasher.finalize())
        });

        Self {
            name: name.to_string(),
            path,
            retention_days,
            git_commit: option_env!("VERGEN_GIT_SHA")
                .unwrap_or("unknown")
                .to_string(),
            ci_run_id: std::env::var("GITHUB_RUN_ID").ok(),
            content_hash,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Helper: create a deterministic EnvFingerprint for tests.
    fn test_env() -> EnvFingerprint {
        EnvFingerprint {
            os: "Linux (Test 1.0)".to_string(),
            arch: "x86_64".to_string(),
            cpu_model: "Test CPU".to_string(),
            cpu_cores: 8,
            mem_total_mb: 16384,
            build_profile: "release".to_string(),
            git_commit: "abc1234".to_string(),
            features: vec![],
            config_hash: "testhash".to_string(),
        }
    }

    // Helper: create a BenchmarkRecord with deterministic env/timestamp.
    fn test_record(name: &str, source: EvidenceSource) -> BenchmarkRecord {
        BenchmarkRecord {
            schema: EVIDENCE_SCHEMA_VERSION.to_string(),
            name: name.to_string(),
            category: "latency".to_string(),
            source,
            env: test_env(),
            stats: None,
            value: None,
            value_unit: None,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    // ── EnvFingerprint ──

    #[test]
    fn env_fingerprint_collect_returns_valid_data() {
        let env = EnvFingerprint::collect();
        assert!(!env.os.is_empty());
        assert!(!env.arch.is_empty());
        assert!(env.cpu_cores > 0);
        assert!(env.mem_total_mb > 0);
        assert!(!env.config_hash.is_empty());
    }

    #[test]
    fn env_fingerprint_machine_id_is_deterministic() {
        let env = test_env();
        let id1 = env.machine_id();
        let id2 = env.machine_id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16, "machine_id should be 16 hex chars");
    }

    #[test]
    fn env_fingerprint_machine_id_differs_by_hardware() {
        let env1 = test_env();
        let mut env2 = test_env();
        env2.cpu_model = "Different CPU".to_string();

        assert_ne!(env1.machine_id(), env2.machine_id());
    }

    #[test]
    fn env_fingerprint_machine_id_groups_by_memory_tier() {
        let mut env_8gb = test_env();
        env_8gb.mem_total_mb = 8000;

        let mut env_8gb_other = test_env();
        env_8gb_other.mem_total_mb = 7500;

        // Both should be in the "8gb" tier
        assert_eq!(env_8gb.machine_id(), env_8gb_other.machine_id());

        let mut env_16gb = test_env();
        env_16gb.mem_total_mb = 16000;

        // 8gb vs 16gb should differ
        assert_ne!(env_8gb.machine_id(), env_16gb.machine_id());
    }

    #[test]
    fn env_fingerprint_serialization_roundtrip() {
        let env = test_env();
        let json = serde_json::to_string(&env).unwrap();
        let decoded: EnvFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(env, decoded);
    }

    // ── PercentileStats ──

    #[test]
    fn percentile_stats_empty_returns_none() {
        let result = PercentileStats::from_samples(&mut [], "us");
        assert!(result.is_none());
    }

    #[test]
    fn percentile_stats_single_sample() {
        let stats = PercentileStats::from_samples(&mut [42.0], "us").unwrap();
        assert_eq!(stats.sample_count, 1);
        assert!((stats.min - 42.0).abs() < f64::EPSILON);
        assert!((stats.max - 42.0).abs() < f64::EPSILON);
        assert!((stats.p50 - 42.0).abs() < f64::EPSILON);
        assert!((stats.mean - 42.0).abs() < f64::EPSILON);
        assert!((stats.stddev - 0.0).abs() < f64::EPSILON);
        assert_eq!(stats.unit, "us");
    }

    #[test]
    fn percentile_stats_known_distribution() {
        // 100 values: 1.0, 2.0, ..., 100.0
        let mut samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let stats = PercentileStats::from_samples(&mut samples, "ms").unwrap();

        assert_eq!(stats.sample_count, 100);
        assert!((stats.min - 1.0).abs() < f64::EPSILON);
        assert!((stats.max - 100.0).abs() < f64::EPSILON);
        assert!((stats.p50 - 50.0).abs() < 1.5); // nearest-rank
        assert!((stats.p95 - 95.0).abs() < 1.5);
        assert!((stats.p99 - 99.0).abs() < 1.5);
        assert!((stats.mean - 50.5).abs() < 0.01);
        assert!(stats.stddev > 28.0 && stats.stddev < 30.0); // ~28.87
    }

    #[test]
    fn percentile_stats_sorts_input() {
        let mut samples = vec![100.0, 1.0, 50.0, 25.0, 75.0];
        let stats = PercentileStats::from_samples(&mut samples, "ns").unwrap();
        assert!((stats.min - 1.0).abs() < f64::EPSILON);
        assert!((stats.max - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn percentile_stats_serialization_roundtrip() {
        let mut samples = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let stats = PercentileStats::from_samples(&mut samples, "us").unwrap();
        let json = serde_json::to_string(&stats).unwrap();
        let decoded: PercentileStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats.sample_count, decoded.sample_count);
        assert!((stats.min - decoded.min).abs() < 1e-10);
        assert!((stats.p50 - decoded.p50).abs() < 1e-10);
        assert!((stats.p95 - decoded.p95).abs() < 1e-10);
        assert!((stats.p99 - decoded.p99).abs() < 1e-10);
        assert!((stats.max - decoded.max).abs() < 1e-10);
        assert!((stats.mean - decoded.mean).abs() < 1e-10);
        assert!((stats.stddev - decoded.stddev).abs() < 1e-10);
        assert_eq!(stats.unit, decoded.unit);
    }

    // ── BenchmarkRecord ──

    #[test]
    fn benchmark_record_new_sets_defaults() {
        let record = BenchmarkRecord::new("test_bench", "latency", EvidenceSource::Custom);
        assert_eq!(record.schema, EVIDENCE_SCHEMA_VERSION);
        assert_eq!(record.name, "test_bench");
        assert_eq!(record.category, "latency");
        assert_eq!(record.source, EvidenceSource::Custom);
        assert!(record.stats.is_none());
        assert!(record.value.is_none());
        assert!(!record.timestamp.is_empty());
    }

    #[test]
    fn benchmark_record_primary_value_prefers_stats() {
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.value = Some(999.0);
        record.stats = Some(PercentileStats {
            sample_count: 10,
            min: 1.0,
            p50: 50.0,
            p95: 95.0,
            p99: 99.0,
            max: 100.0,
            mean: 50.0,
            stddev: 10.0,
            unit: "us".to_string(),
        });
        // p50 should be preferred over value
        assert!((record.primary_value().unwrap() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn benchmark_record_primary_value_falls_back_to_scalar() {
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.value = Some(42.0);
        assert!((record.primary_value().unwrap() - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn benchmark_record_primary_value_none_when_empty() {
        let record = test_record("bench", EvidenceSource::Custom);
        assert!(record.primary_value().is_none());
    }

    #[test]
    fn benchmark_record_with_metadata() {
        let record = test_record("bench", EvidenceSource::Workload)
            .with_metadata("iterations", json!(1000))
            .with_metadata("runtime", json!("pi_agent_rust"));

        assert_eq!(record.metadata.len(), 2);
        assert_eq!(record.metadata["iterations"], json!(1000));
    }

    #[test]
    fn benchmark_record_serialization_roundtrip() {
        let mut record = test_record("bench/latency", EvidenceSource::Criterion);
        record.stats = Some(PercentileStats {
            sample_count: 100,
            min: 1.0,
            p50: 50.0,
            p95: 95.0,
            p99: 99.0,
            max: 100.0,
            mean: 50.5,
            stddev: 28.87,
            unit: "ns".to_string(),
        });

        let json = serde_json::to_string(&record).unwrap();
        let decoded: BenchmarkRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "bench/latency");
        assert_eq!(decoded.source, EvidenceSource::Criterion);
        assert!(decoded.stats.is_some());
    }

    // ── BaselineStore ──

    #[test]
    fn baseline_store_empty_returns_no_baseline() {
        let store = BaselineStore::default();
        let record = test_record("bench", EvidenceSource::Custom);
        let comparison = store.compare(&record);
        assert_eq!(comparison.verdict, ComparisonVerdict::NoBaseline);
    }

    #[test]
    fn baseline_store_find_returns_matching_entry() {
        let mut store = BaselineStore::default();
        let env = test_env();
        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: env.machine_id(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        assert!(store.find(&env.machine_id(), "bench").is_some());
        assert!(store.find(&env.machine_id(), "other").is_none());
        assert!(store.find("different_machine", "bench").is_none());
    }

    #[test]
    fn baseline_store_upsert_updates_existing() {
        let mut store = BaselineStore::default();
        let env = test_env();
        let machine_id = env.machine_id();

        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: machine_id.clone(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: machine_id.clone(),
            reference_value: 110.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "def5678".to_string(),
            captured_at: "2026-01-02T00:00:00Z".to_string(),
            sample_count: 60,
        });

        assert_eq!(
            store.entries.len(),
            1,
            "upsert should replace, not duplicate"
        );
        assert!(
            (store.find(&machine_id, "bench").unwrap().reference_value - 110.0).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn baseline_comparison_pass_within_threshold() {
        let env = test_env();
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: env.machine_id(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        // 10% worse — within default 20% threshold
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.value = Some(110.0);
        record.value_unit = Some("us".to_string());

        let comparison = store.compare(&record);
        assert_eq!(comparison.verdict, ComparisonVerdict::Pass);
        assert!((comparison.delta_pct.unwrap() - 10.0).abs() < 0.01);
    }

    #[test]
    fn baseline_comparison_regressed_beyond_threshold() {
        let env = test_env();
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: env.machine_id(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        // 25% worse — exceeds default 20% threshold
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.value = Some(125.0);
        record.value_unit = Some("us".to_string());

        let comparison = store.compare(&record);
        assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
        assert!((comparison.delta_pct.unwrap() - 25.0).abs() < 0.01);
    }

    #[test]
    fn baseline_comparison_improved_significantly() {
        let env = test_env();
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: env.machine_id(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        // 15% better — exceeds 10% improvement threshold
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.value = Some(85.0);
        record.value_unit = Some("us".to_string());

        let comparison = store.compare(&record);
        assert_eq!(comparison.verdict, ComparisonVerdict::Improved);
        assert!((comparison.delta_pct.unwrap() - (-15.0)).abs() < 0.01);
    }

    #[test]
    fn baseline_comparison_custom_threshold() {
        let env = test_env();
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: env.machine_id(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: Some(5.0), // strict 5% threshold
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        // 10% worse — within default 20% but exceeds custom 5%
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.value = Some(110.0);
        record.value_unit = Some("us".to_string());

        let comparison = store.compare(&record);
        assert_eq!(comparison.verdict, ComparisonVerdict::Regressed);
        assert!((comparison.threshold_pct - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn baseline_store_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pi-perf-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baselines.json");

        let env = test_env();
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench_a".to_string(),
            machine_id: env.machine_id(),
            reference_value: 42.0,
            unit: "us".to_string(),
            regression_threshold_pct: Some(15.0),
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 100,
        });
        store.upsert(BaselineEntry {
            name: "bench_b".to_string(),
            machine_id: "other_machine".to_string(),
            reference_value: 99.0,
            unit: "ms".to_string(),
            regression_threshold_pct: None,
            git_commit: "def5678".to_string(),
            captured_at: "2026-01-02T00:00:00Z".to_string(),
            sample_count: 50,
        });

        store.save(&path).unwrap();
        let loaded = BaselineStore::load(&path);

        assert_eq!(loaded.entries.len(), 2);
        assert!(loaded.find(&env.machine_id(), "bench_a").is_some());
        assert!(loaded.find("other_machine", "bench_b").is_some());

        // Clean up
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_store_load_missing_file_returns_empty() {
        let store = BaselineStore::load(Path::new("/nonexistent/baselines.json"));
        assert!(store.entries.is_empty());
    }

    #[test]
    fn baseline_entry_from_record_with_stats() {
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.stats = Some(PercentileStats {
            sample_count: 50,
            min: 1.0,
            p50: 42.0,
            p95: 90.0,
            p99: 99.0,
            max: 100.0,
            mean: 45.0,
            stddev: 10.0,
            unit: "us".to_string(),
        });

        let entry = BaselineStore::entry_from_record(&record).unwrap();
        assert_eq!(entry.name, "bench");
        assert!((entry.reference_value - 42.0).abs() < f64::EPSILON); // p50
        assert_eq!(entry.unit, "us");
        assert_eq!(entry.sample_count, 50);
    }

    #[test]
    fn baseline_entry_from_record_with_scalar() {
        let mut record = test_record("bench", EvidenceSource::Hyperfine);
        record.value = Some(150.0);
        record.value_unit = Some("ms".to_string());

        let entry = BaselineStore::entry_from_record(&record).unwrap();
        assert!((entry.reference_value - 150.0).abs() < f64::EPSILON);
        assert_eq!(entry.unit, "ms");
        assert_eq!(entry.sample_count, 1); // scalar default
    }

    #[test]
    fn baseline_entry_from_record_empty_returns_none() {
        let record = test_record("bench", EvidenceSource::Custom);
        assert!(BaselineStore::entry_from_record(&record).is_none());
    }

    // ── Criterion Ingestion ──

    #[test]
    fn ingest_criterion_dir_reads_estimates() {
        let dir = std::env::temp_dir().join(format!("pi-criterion-test-{}", std::process::id()));
        let bench_dir = dir.join("group/bench_name/new");
        std::fs::create_dir_all(&bench_dir).unwrap();

        let estimates = json!({
            "mean": {
                "point_estimate": 1000.0,
                "standard_error": 10.0,
                "confidence_interval": {
                    "confidence_level": 0.95,
                    "lower_bound": 980.0,
                    "upper_bound": 1020.0
                }
            },
            "median": {
                "point_estimate": 990.0,
                "standard_error": 8.0,
                "confidence_interval": {
                    "confidence_level": 0.95,
                    "lower_bound": 975.0,
                    "upper_bound": 1005.0
                }
            },
            "std_dev": {
                "point_estimate": 50.0,
                "standard_error": 5.0,
                "confidence_interval": {
                    "confidence_level": 0.95,
                    "lower_bound": 40.0,
                    "upper_bound": 60.0
                }
            }
        });
        std::fs::write(
            bench_dir.join("estimates.json"),
            serde_json::to_string(&estimates).unwrap(),
        )
        .unwrap();

        let records = ingest_criterion_dir(&dir);
        assert_eq!(records.len(), 1);

        let record = &records[0];
        assert_eq!(record.name, "group/bench_name");
        assert_eq!(record.source, EvidenceSource::Criterion);
        let stats = record.stats.as_ref().unwrap();
        assert!((stats.p50 - 990.0).abs() < f64::EPSILON);
        assert!((stats.mean - 1000.0).abs() < f64::EPSILON);
        assert!((stats.stddev - 50.0).abs() < f64::EPSILON);
        assert_eq!(stats.unit, "ns");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ingest_criterion_dir_empty_returns_empty() {
        let dir = std::env::temp_dir().join(format!("pi-criterion-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let records = ingest_criterion_dir(&dir);
        assert!(records.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Custom Latency Recording ──

    #[test]
    fn record_latency_computes_stats() {
        let mut samples = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let record = record_latency("socket_roundtrip", &mut samples, BTreeMap::new()).unwrap();

        assert_eq!(record.name, "socket_roundtrip");
        assert_eq!(record.source, EvidenceSource::Custom);
        let stats = record.stats.as_ref().unwrap();
        assert_eq!(stats.sample_count, 5);
        assert_eq!(stats.unit, "us");
    }

    #[test]
    fn record_latency_empty_returns_none() {
        let result = record_latency("empty", &mut [], BTreeMap::new());
        assert!(result.is_none());
    }

    // ── EvidenceReport ──

    #[test]
    fn evidence_report_no_records_gate_passes() {
        let store = BaselineStore::default();
        let report = EvidenceReport::generate(vec![], &store);
        assert!(report.summary.gate_passed);
        assert_eq!(report.summary.total_benchmarks, 0);
    }

    #[test]
    fn evidence_report_all_pass_gate_passes() {
        let env = test_env();
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench_a".to_string(),
            machine_id: env.machine_id(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        let mut record = test_record("bench_a", EvidenceSource::Custom);
        record.value = Some(105.0); // 5% worse, within threshold
        record.value_unit = Some("us".to_string());

        let report = EvidenceReport::generate(vec![record], &store);
        assert!(report.summary.gate_passed);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.regressed, 0);
    }

    #[test]
    fn evidence_report_regression_fails_gate() {
        let env = test_env();
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench_a".to_string(),
            machine_id: env.machine_id(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        let mut record = test_record("bench_a", EvidenceSource::Custom);
        record.value = Some(130.0); // 30% worse, exceeds 20% threshold
        record.value_unit = Some("us".to_string());

        let report = EvidenceReport::generate(vec![record], &store);
        assert!(!report.summary.gate_passed);
        assert_eq!(report.summary.regressed, 1);
    }

    #[test]
    fn evidence_report_to_jsonl_format() {
        let store = BaselineStore::default();
        let mut record = test_record("bench_a", EvidenceSource::Custom);
        record.value = Some(42.0);
        record.value_unit = Some("us".to_string());

        let report = EvidenceReport::generate(vec![record], &store);
        let jsonl = report.to_jsonl();

        let lines: Vec<&str> = jsonl.trim().split('\n').collect();
        assert_eq!(lines.len(), 3, "envelope + 1 record + 1 comparison");

        // Each line should be valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.is_object());
        }

        // Envelope line should have summary
        let envelope: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(envelope.get("summary").is_some());
        assert!(envelope.get("machine_id").is_some());
    }

    // ── ArtifactMetadata ──

    #[test]
    fn artifact_metadata_missing_file_has_no_hash() {
        let meta = ArtifactMetadata::for_file("test", PathBuf::from("/nonexistent/file.jsonl"), 30);
        assert!(meta.content_hash.is_none());
        assert_eq!(meta.retention_days, 30);
    }

    #[test]
    fn artifact_metadata_existing_file_has_hash() {
        let dir = std::env::temp_dir().join(format!("pi-artifact-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.jsonl");
        std::fs::write(&path, "test content").unwrap();

        let meta = ArtifactMetadata::for_file("test-artifact", path, 30);
        assert!(meta.content_hash.is_some());
        assert_eq!(meta.name, "test-artifact");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn artifact_metadata_serialization_roundtrip() {
        let meta = ArtifactMetadata {
            name: "bench-results".to_string(),
            path: PathBuf::from("/ci/artifacts/bench.jsonl"),
            retention_days: 30,
            git_commit: "abc1234".to_string(),
            ci_run_id: Some("12345".to_string()),
            content_hash: Some("deadbeef".to_string()),
        };

        let json = serde_json::to_string(&meta).unwrap();
        let decoded: ArtifactMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, meta.name);
        assert_eq!(decoded.retention_days, 30);
        assert_eq!(decoded.ci_run_id, Some("12345".to_string()));
    }

    // ── EvidenceSource ──

    #[test]
    fn evidence_source_serde_snake_case() {
        let json = serde_json::to_string(&EvidenceSource::ExtensionBench).unwrap();
        assert_eq!(json, "\"extension_bench\"");

        let decoded: EvidenceSource = serde_json::from_str("\"criterion\"").unwrap();
        assert_eq!(decoded, EvidenceSource::Criterion);
    }

    // ── Cross-machine isolation ──

    #[test]
    fn baseline_does_not_match_different_machine() {
        let mut store = BaselineStore::default();
        store.upsert(BaselineEntry {
            name: "bench".to_string(),
            machine_id: "machine_a".to_string(),
            reference_value: 100.0,
            unit: "us".to_string(),
            regression_threshold_pct: None,
            git_commit: "abc1234".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            sample_count: 50,
        });

        // Record from a different machine (test_env generates a different machine_id)
        let mut record = test_record("bench", EvidenceSource::Custom);
        record.value = Some(200.0);
        record.value_unit = Some("us".to_string());

        let comparison = store.compare(&record);
        assert_eq!(
            comparison.verdict,
            ComparisonVerdict::NoBaseline,
            "should not match baseline from a different machine"
        );
    }
}
