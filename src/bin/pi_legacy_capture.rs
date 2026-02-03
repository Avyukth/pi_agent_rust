//! Legacy pi-mono capture runner (bd-3on).
//!
//! Runs a small subset of deterministic scenarios against the pinned legacy
//! `pi-mono` implementation in print/json mode and records raw stdout/stderr plus a
//! metadata blob for later normalization + conformance comparisons.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use pi::extensions::{LogComponent, LogCorrelation, LogLevel, LogPayload, LogSource};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(name = "pi_legacy_capture")]
#[command(about = "Run legacy pi-mono RPC scenarios and record raw outputs", long_about = None)]
struct Args {
    /// Path to `docs/extension-sample.json`
    #[arg(long, default_value = "docs/extension-sample.json")]
    manifest: PathBuf,

    /// Path to pinned legacy `pi-mono/` repo root
    #[arg(long, default_value = "legacy_pi_mono_code/pi-mono")]
    pi_mono_root: PathBuf,

    /// Output directory for capture artifacts (defaults to target/ for git-ignore)
    #[arg(long, default_value = "target/legacy_capture")]
    out_dir: PathBuf,

    /// Provider to select in legacy pi-mono (required for RPC mode even for slash-command-only scenarios)
    #[arg(long, default_value = "openai")]
    provider: String,

    /// Model ID to select in legacy pi-mono (required for RPC mode even for slash-command-only scenarios)
    #[arg(long, default_value = "gpt-4o-mini")]
    model: String,

    /// Run only these scenario IDs (repeatable). If omitted, runs all supported headless scenarios.
    #[arg(long)]
    scenario_id: Vec<String>,

    /// Timeout for each scenario run.
    #[arg(long, default_value_t = 20)]
    timeout_secs: u64,

    /// Use `pi-test.sh --no-env` (recommended for deterministic/offline scenarios).
    #[arg(long, default_value_t = true)]
    no_env: bool,
}

#[derive(Debug, Deserialize)]
struct ExtensionSampleManifest {
    items: Vec<ExtensionSampleItem>,
    scenario_suite: ScenarioSuite,
}

#[derive(Debug, Deserialize)]
struct ExtensionSampleItem {
    id: String,
    source: ExtensionSource,
    #[serde(default)]
    checksum: Option<ExtensionChecksum>,
}

#[derive(Debug, Deserialize)]
struct ExtensionSource {
    commit: String,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ExtensionChecksum {
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ScenarioSuite {
    schema: String,
    items: Vec<ScenarioSuiteItem>,
}

#[derive(Debug, Deserialize)]
struct ScenarioSuiteItem {
    extension_id: String,
    scenarios: Vec<ScenarioSuiteScenario>,
}

#[derive(Debug, Deserialize)]
struct ScenarioSuiteScenario {
    id: String,
    kind: String,
    #[serde(default)]
    event_name: Option<String>,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    setup: Option<Value>,
}

#[derive(Debug)]
struct CaptureRunIds {
    run_id: String,
    pid: Option<u32>,
}

struct CaptureWriter {
    stdout: File,
    stderr: File,
    meta: File,
    log: File,
}

impl CaptureWriter {
    fn write_stdout_line(&mut self, line: &str) -> Result<()> {
        writeln!(self.stdout, "{line}")?;
        Ok(())
    }

    fn write_meta_json(&mut self, value: &Value) -> Result<()> {
        let text = serde_json::to_string_pretty(value)?;
        writeln!(self.meta, "{text}")?;
        Ok(())
    }

    fn write_capture_log(&mut self, payload: &LogPayload) -> Result<()> {
        let line = serde_json::to_string(payload)?;
        writeln!(self.log, "{line}")?;
        Ok(())
    }
}

fn now_rfc3339_millis_z() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn capture_ids() -> CaptureRunIds {
    CaptureRunIds {
        run_id: format!("run-{}", uuid::Uuid::new_v4()),
        pid: Some(std::process::id()),
    }
}

fn log_payload(ids: &CaptureRunIds, extension_id: &str, scenario_id: &str) -> LogPayload {
    LogPayload {
        schema: "pi.ext.log.v1".to_string(),
        ts: now_rfc3339_millis_z(),
        level: LogLevel::Info,
        event: "capture".to_string(),
        message: String::new(),
        correlation: LogCorrelation {
            extension_id: extension_id.to_string(),
            scenario_id: scenario_id.to_string(),
            session_id: None,
            run_id: Some(ids.run_id.clone()),
            artifact_id: None,
            tool_call_id: None,
            slash_command_id: None,
            event_id: None,
            host_call_id: None,
            rpc_id: None,
            trace_id: None,
            span_id: None,
        },
        source: Some(LogSource {
            component: LogComponent::Capture,
            host: None,
            pid: ids.pid,
        }),
        data: None,
    }
}

fn child_stdout_thread(stdout: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn child_stderr_thread(stderr: impl std::io::Read + Send + 'static, mut writer: File) {
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let _ = writeln!(writer, "{line}");
                }
                Err(_) => break,
            }
        }
    });
}

#[derive(Debug)]
struct MockOpenAiState {
    responses: Vec<Vec<u8>>,
    next_index: AtomicUsize,
    stop: AtomicBool,
}

#[derive(Debug)]
struct MockOpenAiServer {
    base_url: String,
    state: Arc<MockOpenAiState>,
    join: Option<JoinHandle<()>>,
    listener_addr: Option<std::net::SocketAddr>,
}

impl MockOpenAiServer {
    fn start(responses: Vec<Vec<u8>>) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).context("bind mock openai server")?;
        listener.set_nonblocking(true).context("set_nonblocking")?;
        let addr = listener.local_addr().context("listener.local_addr")?;

        let state = Arc::new(MockOpenAiState {
            responses,
            next_index: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
        });

        let thread_state = Arc::clone(&state);
        let join = std::thread::spawn(move || {
            loop {
                if thread_state.stop.load(Ordering::SeqCst) {
                    break;
                }

                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_openai_connection(stream, &thread_state);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            base_url: format!("http://{addr}/v1"),
            state,
            join: Some(join),
            listener_addr: Some(addr),
        })
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for MockOpenAiServer {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(addr) = self.listener_addr.take() {
            // Best-effort: connect once to wake the accept loop.
            let _ = TcpStream::connect(addr);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

const OPENAI_DONE_EVENT: &[u8] = b"data: [DONE]\n\n";

fn handle_openai_connection(mut stream: TcpStream, state: &MockOpenAiState) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let (method, path, remaining_body) = read_http_request_head(&mut stream)?;
    if method != "POST" || path != "/v1/responses" {
        let body = b"not found\n";
        write_http_response(&mut stream, 404, "text/plain", body)?;
        return Ok(());
    }

    // Drain request body to keep clients happy before we close the socket.
    drain_http_body(&mut stream, remaining_body)?;

    let idx = state.next_index.fetch_add(1, Ordering::SeqCst);
    let body = state
        .responses
        .get(idx)
        .or_else(|| state.responses.last())
        .map_or(OPENAI_DONE_EVENT, Vec::as_slice);

    write_http_response(&mut stream, 200, "text/event-stream", body)?;
    Ok(())
}

fn read_http_request_head(stream: &mut TcpStream) -> Result<(String, String, usize)> {
    let mut buf = Vec::<u8>::new();
    let mut scratch = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);

    let header_end = loop {
        if Instant::now() > deadline {
            bail!("mock openai: timed out reading request headers");
        }

        let n = stream.read(&mut scratch).context("read request")?;
        if n == 0 {
            bail!("mock openai: connection closed while reading headers");
        }
        buf.extend_from_slice(&scratch[..n]);

        if let Some(end) = find_header_end(&buf) {
            break end;
        }

        if buf.len() > 128 * 1024 {
            bail!("mock openai: header too large");
        }
    };

    let head = std::str::from_utf8(&buf[..header_end]).context("utf8 headers")?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0_usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().unwrap_or(0);
        }
    }

    let already_read_body = buf.len().saturating_sub(header_end);
    let remaining_body = content_length.saturating_sub(already_read_body);
    Ok((method, path, remaining_body))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
    }
    buf.windows(2).position(|w| w == b"\n\n").map(|pos| pos + 2)
}

fn drain_http_body(stream: &mut TcpStream, mut remaining: usize) -> Result<()> {
    let mut scratch = [0_u8; 4096];
    while remaining > 0 {
        let to_read = remaining.min(scratch.len());
        let n = stream.read(&mut scratch[..to_read]).context("read body")?;
        if n == 0 {
            break;
        }
        remaining = remaining.saturating_sub(n);
    }
    Ok(())
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        404 => "Not Found",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn run_cmd_capture_stdout(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn git_rev_parse_head(repo: &Path) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.args(["-C", repo.to_string_lossy().as_ref(), "rev-parse", "HEAD"]);
    run_cmd_capture_stdout(&mut cmd)
}

fn node_version() -> Option<String> {
    let mut cmd = Command::new("/usr/bin/node");
    cmd.arg("-v");
    run_cmd_capture_stdout(&mut cmd)
}

fn npm_version() -> Option<String> {
    let mut cmd = Command::new("/usr/bin/npm");
    cmd.arg("--version");
    run_cmd_capture_stdout(&mut cmd)
}

fn reorder_path_for_system_node() -> Option<String> {
    let current = std::env::var("PATH").ok()?;
    let mut parts = Vec::<String>::new();

    for fixed in ["/usr/bin", "/bin"] {
        parts.push(fixed.to_string());
    }

    for entry in current.split(':') {
        let entry = entry.trim();
        if entry.is_empty() || entry == "/usr/bin" || entry == "/bin" {
            continue;
        }
        parts.push(entry.to_string());
    }

    Some(parts.join(":"))
}

fn ensure_models_json(agent_dir: &Path, base_url: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(agent_dir)
        .with_context(|| format!("create agent dir {}", agent_dir.display()))?;

    let path = agent_dir.join("models.json");
    if path.is_file() {
        return Ok(path);
    }

    let content = json!({
        "providers": {
            // Provide a dummy provider config so legacy pi-mono has at least one available model.
            // We point baseUrl at a local mock server for deterministic tool-call scenarios.
            "openai": {
                "baseUrl": base_url,
                "apiKey": "DUMMY"
            }
        }
    });
    let text = serde_json::to_string_pretty(&content)?;
    std::fs::write(&path, format!("{text}\n"))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

fn ensure_settings_json(agent_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(agent_dir)
        .with_context(|| format!("create agent dir {}", agent_dir.display()))?;

    let path = agent_dir.join("settings.json");
    if path.is_file() {
        return Ok(path);
    }

    // Safety net: if a dangerous bash tool call ever slips past an extension gate,
    // the commandPrefix causes the shell to exit before running the command body.
    let content = json!({
        "shellCommandPrefix": "echo \"[pi_legacy_capture] bash disabled\"; exit 123"
    });
    let text = serde_json::to_string_pretty(&content)?;
    std::fs::write(&path, format!("{text}\n"))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

fn spawn_pi_mono_print_json(
    pi_mono_root: &Path,
    extension_path: &str,
    agent_dir: &Path,
    provider: &str,
    model: &str,
    no_env: bool,
    messages: &[String],
) -> Result<Child> {
    let pi_test = pi_mono_root.join("pi-test.sh");
    if !pi_test.is_file() {
        bail!("missing legacy runner: {}", pi_test.display());
    }

    let mut cmd = Command::new("./pi-test.sh");
    cmd.current_dir(pi_mono_root)
        .arg("--print")
        .arg("--mode")
        .arg("json")
        .arg("--extension")
        .arg(extension_path)
        .arg("--provider")
        .arg(provider)
        .arg("--model")
        .arg(model)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if no_env {
        cmd.arg("--no-env");
    }
    cmd.args(messages);

    // Determinism: use UTC timestamps wherever possible.
    cmd.env("TZ", "UTC");
    if let Some(path) = reorder_path_for_system_node() {
        cmd.env("PATH", path);
    }
    cmd.env("PI_CODING_AGENT_DIR", agent_dir);

    let child = cmd.spawn().context("spawn pi-mono rpc")?;
    Ok(child)
}

fn extract_bool(input: &Value, pointer: &str, default: bool) -> bool {
    input
        .pointer(pointer)
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

fn extract_string(input: &Value, pointer: &str) -> Option<String> {
    input
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn build_sse_body(events: &[Value]) -> Result<Vec<u8>> {
    let mut out = String::new();
    for event in events {
        let json = serde_json::to_string(event)?;
        out.push_str("data: ");
        out.push_str(&json);
        out.push_str("\n\n");
    }
    out.push_str("data: [DONE]\n\n");
    Ok(out.into_bytes())
}

fn build_openai_tool_call_responses(
    model: &str,
    tool_name: &str,
    tool_input: &Value,
) -> Result<Vec<Vec<u8>>> {
    let call_id = "call_1";
    let item_id = "fc_1";
    let response_id = "resp_1";
    let arguments = serde_json::to_string(tool_input)?;
    let tool_item = json!({
        "type": "function_call",
        "id": item_id,
        "call_id": call_id,
        "name": tool_name,
        "arguments": arguments,
        "status": "completed"
    });

    let first = build_sse_body(&[
        json!({"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":tool_item}),
        json!({"type":"response.output_item.done","sequence_number":2,"output_index":0,"item":tool_item}),
        json!({"type":"response.completed","sequence_number":3,"response": {
            "id": response_id,
            "object": "response",
            "created_at": 0,
            "model": model,
            "status": "completed",
            "output": [tool_item],
            "output_text": "",
            "error": null,
            "incomplete_details": null,
            "instructions": null,
            "metadata": null,
            "parallel_tool_calls": false,
            "temperature": null,
            "tool_choice": "auto",
            "tools": [],
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "input_tokens_details": {"cached_tokens": 0}},
            "service_tier": null
        }}),
    ])?;

    let text = "ok";
    let message_item = json!({
        "type": "message",
        "id": "msg_1",
        "role": "assistant",
        "status": "completed",
        "content": [{"type":"output_text","text": text, "annotations": []}]
    });
    let second = build_sse_body(&[
        json!({"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":message_item}),
        json!({"type":"response.output_item.done","sequence_number":2,"output_index":0,"item":message_item}),
        json!({"type":"response.completed","sequence_number":3,"response": {
            "id": "resp_2",
            "object": "response",
            "created_at": 0,
            "model": model,
            "status": "completed",
            "output": [message_item],
            "output_text": text,
            "error": null,
            "incomplete_details": null,
            "instructions": null,
            "metadata": null,
            "parallel_tool_calls": false,
            "temperature": null,
            "tool_choice": "auto",
            "tools": [],
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "input_tokens_details": {"cached_tokens": 0}},
            "service_tier": null
        }}),
    ])?;

    Ok(vec![first, second])
}

fn run_pi_mono_to_completion(
    mut child: Child,
    stdout_rx: &Receiver<String>,
    writer: &mut CaptureWriter,
    timeout: Duration,
) -> Result<ExitStatus> {
    let start = Instant::now();
    let mut exit_status: Option<ExitStatus> = None;

    loop {
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out waiting for legacy pi-mono to finish");
        }

        if exit_status.is_none() {
            exit_status = child.try_wait().context("try_wait")?;
        }

        match stdout_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => writer.write_stdout_line(&line)?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if let Some(status) = exit_status {
            // Give stdout a brief moment to flush after the process exits.
            let drain_deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < drain_deadline {
                match stdout_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(line) => writer.write_stdout_line(&line)?,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            return Ok(status);
        }
    }

    exit_status.map_or_else(|| child.wait().context("wait"), Ok)
}

fn scenario_is_supported_headless(scenario: &ScenarioSuiteScenario) -> bool {
    let has_ui = extract_bool(&scenario.input, "/ctx/has_ui", false);
    if has_ui {
        return false;
    }

    match scenario.kind.as_str() {
        "event" => {
            if scenario.event_name.as_deref() != Some("tool_call") {
                return false;
            }
            scenario
                .input
                .pointer("/event/toolName")
                .and_then(Value::as_str)
                == Some("bash")
        }
        _ => false,
    }
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let args = Args::parse();
    let ids = capture_ids();

    let manifest_bytes = std::fs::read(&args.manifest)
        .with_context(|| format!("read manifest {}", args.manifest.display()))?;
    let manifest: ExtensionSampleManifest =
        serde_json::from_slice(&manifest_bytes).context("parse extension-sample manifest")?;

    if manifest.scenario_suite.schema != "pi.ext.scenario-suite.v1" {
        bail!(
            "unsupported scenario_suite schema: {}",
            manifest.scenario_suite.schema
        );
    }

    let mut by_id: HashMap<String, ExtensionSampleItem> = HashMap::new();
    for item in manifest.items {
        by_id.insert(item.id.clone(), item);
    }

    let mut targets = Vec::new();
    for entry in manifest.scenario_suite.items {
        let Some(item) = by_id.get(&entry.extension_id) else {
            continue;
        };
        for scenario in entry.scenarios {
            if !scenario_is_supported_headless(&scenario) {
                continue;
            }
            if !args.scenario_id.is_empty() && !args.scenario_id.contains(&scenario.id) {
                continue;
            }
            targets.push((item, scenario));
        }
    }

    if targets.is_empty() {
        bail!("no supported scenarios matched selection");
    }

    let legacy_head = git_rev_parse_head(&args.pi_mono_root);
    let node = node_version();
    let npm = npm_version();

    for (item, scenario) in targets {
        let command = extract_string(&scenario.input, "/event/input/command").unwrap_or_default();
        if command.is_empty() {
            bail!("missing event.input.command for {}", scenario.id);
        }

        let started_at = now_rfc3339_millis_z();
        let scenario_dir = args.out_dir.join(&scenario.id).join(&ids.run_id);
        std::fs::create_dir_all(&scenario_dir)
            .with_context(|| format!("create {}", scenario_dir.display()))?;

        let stdout = File::create(scenario_dir.join("stdout.jsonl"))?;
        let stderr = File::create(scenario_dir.join("stderr.txt"))?;
        let meta = File::create(scenario_dir.join("meta.json"))?;
        let log = File::create(scenario_dir.join("capture.log.jsonl"))?;

        let mut writer = CaptureWriter {
            stdout,
            stderr,
            meta,
            log,
        };

        let mut payload = log_payload(&ids, &item.id, &scenario.id);
        payload.message = "capture.start".to_string();
        payload.data = Some(json!({
            "started_at": started_at,
            "pi_mono_root": args.pi_mono_root.display().to_string(),
            "extension_path": item.source.path.clone(),
            "manifest_commit": item.source.commit.clone(),
            "manifest_checksum_sha256": item.checksum.as_ref().map(|c| c.sha256.clone()),
            "legacy_head": legacy_head.clone(),
            "node_version": node.clone(),
            "npm_version": npm.clone(),
            "provider": args.provider.clone(),
            "model": args.model.clone(),
        }));
        writer.write_capture_log(&payload)?;

        let mock_responses = build_openai_tool_call_responses(
            &args.model,
            "bash",
            &json!({"command": command.clone()}),
        )?;
        let mock_server = MockOpenAiServer::start(mock_responses)?;

        let agent_dir = scenario_dir.join("agent");
        let models_json_path = ensure_models_json(&agent_dir, mock_server.base_url())?;
        let settings_json_path = ensure_settings_json(&agent_dir)?;

        let mut messages = Vec::<String>::new();
        if scenario
            .setup
            .as_ref()
            .and_then(|s| s.pointer("/state/plan_mode_enabled"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            messages.push("/plan".to_string());
        }
        messages.push(format!(
            "For test capture, call the bash tool with command: {command}"
        ));

        let mut child = spawn_pi_mono_print_json(
            &args.pi_mono_root,
            &item.source.path,
            &agent_dir,
            &args.provider,
            &args.model,
            args.no_env,
            &messages,
        )?;
        let stdout_pipe = child.stdout.take().context("take child stdout")?;
        let stderr_pipe = child.stderr.take().context("take child stderr")?;

        // Stream stderr directly into stderr.txt.
        child_stderr_thread(stderr_pipe, writer.stderr.try_clone()?);
        let stdout_rx = child_stdout_thread(stdout_pipe);

        let timeout = Duration::from_secs(args.timeout_secs);
        let exit_status = run_pi_mono_to_completion(child, &stdout_rx, &mut writer, timeout)?;

        let finished_at = now_rfc3339_millis_z();
        writer.write_meta_json(&json!({
            "schema": "pi.legacy_capture.v1",
            "run_id": ids.run_id.clone(),
            "extension_id": item.id.clone(),
            "scenario_id": scenario.id.clone(),
            "started_at": started_at,
            "finished_at": finished_at,
            "agent_dir": agent_dir.display().to_string(),
            "models_json": models_json_path.display().to_string(),
            "settings_json": settings_json_path.display().to_string(),
            "provider": args.provider.clone(),
            "model": args.model.clone(),
            "exit": {
                "success": exit_status.success(),
                "code": exit_status.code(),
            },
            "mock_openai": {
                "base_url": mock_server.base_url(),
            },
            "pi_mono": {
                "root": args.pi_mono_root.display().to_string(),
                "head": legacy_head.clone(),
                "extension_path": item.source.path.clone(),
                "manifest_commit": item.source.commit.clone(),
                "manifest_checksum_sha256": item.checksum.as_ref().map(|c| c.sha256.clone()),
            },
            "env": {
                "TZ": "UTC",
                "no_env": args.no_env,
            },
        }))?;

        let mut end = log_payload(&ids, &item.id, &scenario.id);
        end.message = "capture.finish".to_string();
        writer.write_capture_log(&end)?;
    }

    Ok(())
}
