//! OQ2 unix-socket round-trip latency evidence harness (`bd-2s1`).
//!
//! Run:
//! - `cargo bench --bench socket_latency`
//! - `PI_SOCKET_LATENCY_SAMPLES=200 cargo bench --bench socket_latency` (faster local check)
//! - `PI_SOCKET_LATENCY_PAYLOADS=1024,8192 cargo bench --bench socket_latency`
//!
//! Outputs:
//! - `benches/baselines/socket_latency_baseline.json` (raw samples + metadata)
//! - `benches/baselines/socket_latency_baseline.md` (human summary)

#![allow(clippy::print_stdout)]

#[path = "bench_env.rs"]
mod bench_env;

use std::io::{BufRead, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pi::chrome::protocol;
use serde::Serialize;
use serde_json::json;

const DEFAULT_SAMPLES: usize = 1000;
const DEFAULT_PAYLOAD_SIZES: &[usize] = &[256, 1024, 4096, 16384];
const BASELINE_JSON_PATH: &str = "benches/baselines/socket_latency_baseline.json";
const BASELINE_MD_PATH: &str = "benches/baselines/socket_latency_baseline.md";
const SOFT_SOCKET_P95_TARGET_NS: u64 = 5_000_000; // 5ms socket-layer target from OQ2 notes

#[derive(Debug, Clone, Serialize)]
struct SerializableBenchEnv {
    os: String,
    arch: String,
    cpu_brand: String,
    cpu_cores: usize,
    mem_total_mb: u64,
    governor: String,
    turbo_boost: String,
    aslr: String,
    thp: String,
    noise_score: u8,
    config_hash: String,
}

impl From<bench_env::BenchEnvFingerprint> for SerializableBenchEnv {
    fn from(value: bench_env::BenchEnvFingerprint) -> Self {
        Self {
            os: value.os,
            arch: value.arch.to_string(),
            cpu_brand: value.cpu_brand,
            cpu_cores: value.cpu_cores,
            mem_total_mb: value.mem_total_mb,
            governor: value.governor,
            turbo_boost: value.turbo_boost,
            aslr: value.aslr,
            thp: value.thp,
            noise_score: value.noise_score,
            config_hash: value.config_hash,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct Percentiles {
    min_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
    mean_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DecompositionSummary {
    encode_request: Percentiles,
    decode_response: Percentiles,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RoundTripMeasurement {
    payload_bytes: usize,
    request_frame_bytes: usize,
    response_frame_bytes: usize,
    samples: usize,
    round_trip: Percentiles,
    decomposition: DecompositionSummary,
    raw_round_trip_ns: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct CompatibilityChecks {
    unix_socket_roundtrip_ok: bool,
    protocol_decode_ok: bool,
    platform_supported: bool,
}

#[derive(Debug, Clone, Serialize)]
struct MatrixStatus {
    local_machine_is_reference_target: bool,
    macos_apple_silicon_recorded: bool,
    linux_x86_64_recorded: bool,
    remaining_reference_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SocketLatencyReport {
    schema: &'static str,
    bead_id: &'static str,
    captured_at_unix_ms: u64,
    env: SerializableBenchEnv,
    hostname: Option<String>,
    rustc_version: String,
    cargo_profile: &'static str,
    includes_end_to_end_chrome: bool,
    chrome_version: Option<String>,
    measurement_component: &'static str,
    soft_target_socket_p95_ns: u64,
    measurements: Vec<RoundTripMeasurement>,
    compatibility_checks: CompatibilityChecks,
    matrix_status: MatrixStatus,
    handoff_notes: Vec<String>,
}

fn main() {
    bench_env::print_env_banner_once();

    let samples = read_env_usize("PI_SOCKET_LATENCY_SAMPLES").unwrap_or(DEFAULT_SAMPLES);
    let payload_sizes = read_env_payload_sizes().unwrap_or_else(|| DEFAULT_PAYLOAD_SIZES.to_vec());
    let env = SerializableBenchEnv::from(bench_env::collect_fingerprint());

    let mut measurements = Vec::with_capacity(payload_sizes.len());
    for payload_bytes in &payload_sizes {
        let measurement = measure_payload_latency(*payload_bytes, samples).unwrap_or_else(|err| {
            panic!("socket latency measurement failed for {payload_bytes}B: {err}")
        });
        measurements.push(measurement);
    }

    let compatibility_checks = CompatibilityChecks {
        unix_socket_roundtrip_ok: true,
        protocol_decode_ok: true,
        platform_supported: matches!(std::env::consts::OS, "macos" | "linux"),
    };

    let is_macos_arm = std::env::consts::OS == "macos" && std::env::consts::ARCH == "aarch64";
    let is_linux_x64 = std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64";
    let matrix_status = MatrixStatus {
        local_machine_is_reference_target: is_macos_arm || is_linux_x64,
        macos_apple_silicon_recorded: is_macos_arm,
        linux_x86_64_recorded: is_linux_x64,
        remaining_reference_targets: [
            (!is_macos_arm, "macOS Apple Silicon"),
            (!is_linux_x64, "Linux x86_64"),
        ]
        .into_iter()
        .filter_map(|(missing, label)| missing.then(|| label.to_string()))
        .collect(),
    };

    let report = SocketLatencyReport {
        schema: "pi.chrome.socket_latency.v1",
        bead_id: "bd-2s1",
        captured_at_unix_ms: unix_time_ms(),
        env,
        hostname: read_hostname(),
        rustc_version: read_rustc_version(),
        cargo_profile: "bench",
        includes_end_to_end_chrome: false,
        chrome_version: None,
        measurement_component: "unix_socket_ping_pong_protocol_frame_roundtrip",
        soft_target_socket_p95_ns: SOFT_SOCKET_P95_TARGET_NS,
        measurements,
        compatibility_checks,
        matrix_status,
        handoff_notes: vec![
            "This harness measures socket/protocol round-trip only (no Chrome execution time)."
                .to_string(),
            "Decomposition notes estimate T_ser + T_deser directly; T_socket and scheduler overhead remain combined in the round-trip measurement.".to_string(),
            "Exact Chrome version is intentionally omitted because this report excludes end-to-end Chrome processing.".to_string(),
        ],
    };

    write_report_artifacts(&report).expect("write socket latency baseline artifacts");
    print_summary(&report);
}

fn measure_payload_latency(
    payload_bytes: usize,
    samples: usize,
) -> Result<RoundTripMeasurement, Box<dyn std::error::Error + Send + Sync>> {
    let request_frame = build_request_frame(payload_bytes)?;
    let response_frame = build_response_frame(payload_bytes)?;

    let server_response = response_frame.clone();
    let socket_dir = tempfile::tempdir()?;
    let socket_path = socket_dir.path().join(format!("oq2-{payload_bytes}.sock"));
    let listener = UnixListener::bind(&socket_path)?;

    let server = thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let (mut server_stream, _) = listener.accept()?;
            let mut server_reader = std::io::BufReader::new(server_stream.try_clone()?);
            let mut line = Vec::new();

            for _ in 0..samples {
                line.clear();
                let bytes = server_reader.read_until(b'\n', &mut line)?;
                if bytes == 0 {
                    return Err("client disconnected during measurement".into());
                }
                server_stream.write_all(&server_response)?;
            }
            Ok(())
        },
    );

    let mut client_stream = UnixStream::connect(&socket_path)?;
    let mut client_reader = std::io::BufReader::new(client_stream.try_clone()?);
    let mut latencies_ns = Vec::with_capacity(samples);
    let mut line = Vec::new();

    for _ in 0..samples {
        let started = Instant::now();
        client_stream.write_all(&request_frame)?;
        line.clear();
        let bytes = client_reader.read_until(b'\n', &mut line)?;
        if bytes == 0 {
            return Err("server disconnected during measurement".into());
        }
        let (message, consumed) = protocol::decode_frame::<protocol::MessageType>(&line)?
            .ok_or_else(|| std::io::Error::other("partial response frame"))?;
        if consumed != line.len() {
            return Err("response frame had trailing data".into());
        }
        match message {
            protocol::MessageType::Response(_) => {}
            other => {
                return Err(std::io::Error::other(format!(
                    "expected response frame, got {other:?}"
                ))
                .into());
            }
        }
        latencies_ns.push(duration_ns_u64(started.elapsed()));
    }

    let server_result = server.join().map_err(|_| {
        std::io::Error::other("server thread panicked during socket latency measurement")
    })?;
    server_result?;

    let encode_samples = measure_encode_costs(&request_frame, payload_bytes, samples)?;
    let decode_samples = measure_decode_costs(&response_frame, samples)?;

    Ok(RoundTripMeasurement {
        payload_bytes,
        request_frame_bytes: request_frame.len(),
        response_frame_bytes: response_frame.len(),
        samples,
        round_trip: summarize_ns(&latencies_ns),
        decomposition: DecompositionSummary {
            encode_request: summarize_ns(&encode_samples),
            decode_response: summarize_ns(&decode_samples),
            notes: vec![
                "T_ser approximated by repeated protocol::encode_frame(request) on this payload."
                    .to_string(),
                "T_deser approximated by repeated protocol::decode_frame(response).".to_string(),
                "T_socket + scheduling are not isolated and remain in round_trip.".to_string(),
            ],
        },
        raw_round_trip_ns: latencies_ns,
    })
}

fn build_request_frame(payload_bytes: usize) -> Result<Vec<u8>, protocol::FrameCodecError> {
    let message = protocol::MessageType::Request(protocol::Request {
        version: protocol::PROTOCOL_VERSION_V1,
        id: "oq2-bench-request".to_string(),
        op: "oq2.ping".to_string(),
        payload: json!({
            "blob": "x".repeat(payload_bytes),
            "payload_bytes": payload_bytes,
        }),
    });
    protocol::encode_frame(&message)
}

fn build_response_frame(payload_bytes: usize) -> Result<Vec<u8>, protocol::FrameCodecError> {
    let message =
        protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(protocol::Response {
            version: protocol::PROTOCOL_VERSION_V1,
            id: "oq2-bench-request".to_string(),
            ok: true,
            result: json!({
                "pong": true,
                "payload_bytes": payload_bytes,
            }),
        }));
    protocol::encode_frame(&message)
}

fn measure_encode_costs(
    request_frame: &[u8],
    payload_bytes: usize,
    samples: usize,
) -> Result<Vec<u64>, Box<dyn std::error::Error + Send + Sync>> {
    let message = protocol::MessageType::Request(protocol::Request {
        version: protocol::PROTOCOL_VERSION_V1,
        id: "oq2-bench-request".to_string(),
        op: "oq2.ping".to_string(),
        payload: json!({
            "blob": "x".repeat(payload_bytes),
            "payload_bytes": payload_bytes,
        }),
    });
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        let encoded = protocol::encode_frame(&message)?;
        if encoded.len() != request_frame.len() {
            return Err(std::io::Error::other("encode benchmark frame length drift").into());
        }
        out.push(duration_ns_u64(started.elapsed()));
    }
    Ok(out)
}

fn measure_decode_costs(
    frame: &[u8],
    samples: usize,
) -> Result<Vec<u64>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        let (_message, consumed) = protocol::decode_frame::<protocol::MessageType>(frame)?
            .ok_or_else(|| std::io::Error::other("partial frame in decode benchmark"))?;
        if consumed != frame.len() {
            return Err(
                std::io::Error::other("decode benchmark did not consume full frame").into(),
            );
        }
        out.push(duration_ns_u64(started.elapsed()));
    }
    Ok(out)
}

fn summarize_ns(samples: &[u64]) -> Percentiles {
    assert!(!samples.is_empty(), "cannot summarize empty sample set");
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();

    let min_ns = sorted[0];
    let max_ns = *sorted.last().expect("sorted non-empty");
    let p50_ns = percentile(&sorted, 0.50);
    let p95_ns = percentile(&sorted, 0.95);
    let p99_ns = percentile(&sorted, 0.99);
    let mean_ns = sorted.iter().copied().sum::<u64>() / u64::try_from(sorted.len()).unwrap_or(1);

    Percentiles {
        min_ns,
        p50_ns,
        p95_ns,
        p99_ns,
        max_ns,
        mean_ns,
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let len = sorted.len();
    let idx = ((len.saturating_sub(1)) as f64 * p).round() as usize;
    sorted[idx.min(len.saturating_sub(1))]
}

fn write_report_artifacts(report: &SocketLatencyReport) -> std::io::Result<()> {
    let json_path = Path::new(BASELINE_JSON_PATH);
    let md_path = Path::new(BASELINE_MD_PATH);
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = md_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json_bytes = serde_json::to_vec_pretty(report)
        .map_err(|err| std::io::Error::other(format!("serialize baseline json: {err}")))?;
    std::fs::write(json_path, json_bytes)?;
    std::fs::write(md_path, render_markdown_summary(report))?;
    Ok(())
}

fn render_markdown_summary(report: &SocketLatencyReport) -> String {
    let mut out = String::new();
    out.push_str("# Unix Socket Latency Baseline (OQ2)\n\n");
    out.push_str(&format!(
        "Captured: {} (unix_ms)\n",
        report.captured_at_unix_ms
    ));
    out.push_str(&format!(
        "Platform: {} / {} / {} cores\n",
        report.env.os, report.env.arch, report.env.cpu_cores
    ));
    out.push_str(&format!("CPU: {}\n", report.env.cpu_brand));
    out.push_str(&format!("Rust: {}\n", report.rustc_version));
    out.push_str(&format!("Profile: {}\n", report.cargo_profile));
    out.push_str(&format!(
        "Noise Score: {} (governor={}, turbo={}, aslr={}, thp={})\n\n",
        report.env.noise_score,
        report.env.governor,
        report.env.turbo_boost,
        report.env.aslr,
        report.env.thp
    ));

    out.push_str("## Round-trip latency (unix socket + protocol frame)\n\n");
    out.push_str("| Payload | Samples | Req frame | Resp frame | p50 | p95 | p99 | mean | max |\n");
    out.push_str("|---------|---------|-----------|------------|-----|-----|-----|------|-----|\n");
    for m in &report.measurements {
        out.push_str(&format!(
            "| {} B | {} | {} B | {} B | {} | {} | {} | {} | {} |\n",
            m.payload_bytes,
            m.samples,
            m.request_frame_bytes,
            m.response_frame_bytes,
            fmt_ns(m.round_trip.p50_ns),
            fmt_ns(m.round_trip.p95_ns),
            fmt_ns(m.round_trip.p99_ns),
            fmt_ns(m.round_trip.mean_ns),
            fmt_ns(m.round_trip.max_ns),
        ));
    }
    out.push('\n');

    out.push_str("## Decomposition notes\n\n");
    out.push_str("- `T_ser`: `protocol::encode_frame(request)` microbench on the same payload.\n");
    out.push_str("- `T_deser`: `protocol::decode_frame(response)` microbench on the same frame.\n");
    out.push_str(
        "- `T_socket + T_sched`: included in round-trip and not isolated by this harness.\n",
    );
    out.push_str(
        "- This report excludes Chrome execution time (`includes_end_to_end_chrome=false`).\n\n",
    );

    out.push_str("## Reference matrix status\n\n");
    out.push_str(&format!(
        "- Local machine is reference target: {}\n",
        report.matrix_status.local_machine_is_reference_target
    ));
    out.push_str(&format!(
        "- macOS Apple Silicon recorded: {}\n",
        report.matrix_status.macos_apple_silicon_recorded
    ));
    out.push_str(&format!(
        "- Linux x86_64 recorded: {}\n",
        report.matrix_status.linux_x86_64_recorded
    ));
    if !report.matrix_status.remaining_reference_targets.is_empty() {
        out.push_str("- Remaining reference targets:\n");
        for target in &report.matrix_status.remaining_reference_targets {
            out.push_str(&format!("  - {target}\n"));
        }
    }
    out.push('\n');

    out.push_str("## Soft target check (socket layer)\n\n");
    if let Some(one_kib) = report.measurements.iter().find(|m| m.payload_bytes == 1024) {
        let pass = one_kib.round_trip.p95_ns <= report.soft_target_socket_p95_ns;
        out.push_str(&format!(
            "- 1 KiB p95 = {} (target < {}) => {}\n",
            fmt_ns(one_kib.round_trip.p95_ns),
            fmt_ns(report.soft_target_socket_p95_ns),
            if pass { "PASS" } else { "REVIEW" }
        ));
    } else {
        out.push_str("- 1 KiB payload not measured in this run.\n");
    }

    out
}

fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.3} ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.3} us", ns as f64 / 1_000.0)
    } else {
        format!("{ns} ns")
    }
}

fn duration_ns_u64(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn unix_time_ms() -> u64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    u64::try_from(dur.as_millis()).unwrap_or(u64::MAX)
}

fn read_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            Command::new("hostname").output().ok().and_then(|out| {
                if out.status.success() {
                    String::from_utf8(out.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                } else {
                    None
                }
            })
        })
}

fn read_rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.parse().ok()
}

fn read_env_payload_sizes() -> Option<Vec<usize>> {
    let raw = std::env::var("PI_SOCKET_LATENCY_PAYLOADS").ok()?;
    let mut values = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let size = part.parse::<usize>().ok()?;
        values.push(size);
    }
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn print_summary(report: &SocketLatencyReport) {
    println!("socket latency baseline written:");
    println!("  - {}", BASELINE_JSON_PATH);
    println!("  - {}", BASELINE_MD_PATH);
    for m in &report.measurements {
        println!(
            "payload={}B p50={} p95={} p99={} (n={})",
            m.payload_bytes,
            fmt_ns(m.round_trip.p50_ns),
            fmt_ns(m.round_trip.p95_ns),
            fmt_ns(m.round_trip.p99_ns),
            m.samples,
        );
    }
}
