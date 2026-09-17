//! Native subprocess execution and acceptance of a delegated result.
//!
//! Process exit, protocol completion, typed-output acceptance and worktree
//! writeback are separate gates. No isolated edit reaches the parent before
//! all required gates pass. Dropping a pending run kills its process tree and
//! settles the hub lease; rejected worktrees remain available for inspection.

use super::{
    AgentDefinition, SchemaMode, SubagentResult, SubagentStatus, SubagentTask, UpdateCallback,
    append_bounded_line, child_args, child_depth, compile_output_schema, corrective_retry_task,
    emit_progress, protocol, validate_child_output,
};
use crate::agent_cx::AgentCx;
use crate::agent_hub::{ChildKind, ChildStatus};
use crate::worktree_iso::{IsoApplyMode, IsoHandle, IsoOutcome};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const DRAIN_BATCH: usize = 32;
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const CANCELLED: &str = "Parent cancellation propagated to child process.";

pub(super) struct ChildRunner {
    cwd: PathBuf,
    global_dir: PathBuf,
    child_binary: PathBuf,
    role_model_spec: Option<String>,
    hub_kind: ChildKind,
}

impl ChildRunner {
    pub(super) const fn new(
        cwd: PathBuf,
        global_dir: PathBuf,
        child_binary: PathBuf,
        role_model_spec: Option<String>,
        hub_kind: ChildKind,
    ) -> Self {
        Self { cwd, global_dir, child_binary, role_model_spec, hub_kind }
    }

    /// At most one fresh corrective run. The first attempt's isolated edits
    /// are retained, never applied as input to that retry.
    pub(super) async fn run_one(
        &self,
        agents: &BTreeMap<String, AgentDefinition>,
        task: SubagentTask,
        step: Option<usize>,
        on_update: Option<UpdateCallback>,
    ) -> SubagentResult {
        let Some(agent) = agents.get(&task.agent) else {
            return SubagentResult::unknown(task, step);
        };
        let schema = task.output_schema.clone().or_else(|| agent.output_schema.clone());
        if let Some(schema) = &schema
            && let Err(error) = compile_output_schema(schema)
        {
            return SubagentResult::failed(agent, task, step, format!("Invalid outputSchema: {error}"));
        }
        let owner = AgentCx::for_current_or_request();
        let update = on_update.as_ref();
        let mut attempt = self.run_child_process(agent, task.clone(), step, update, schema.as_ref(), &owner).await;
        if attempt.result.is_error || schema.is_none() {
            return attempt.finish(&owner, true, update);
        }
        let schema = schema.as_ref().expect("schema checked above");
        attempt.result.schema_retries = Some(0);
        match validate_child_output(&attempt.result.output, schema) {
            Ok(data) => {
                attempt.result.data = Some(data);
                attempt.result.schema_valid = Some(true);
                return attempt.finish(&owner, true, update);
            }
            Err(errors) => {
                attempt.result.schema_valid = Some(false);
                attempt.result.validation_errors = Some(errors);
            }
        }

        let errors = attempt.result.validation_errors.clone().unwrap_or_default();
        attempt.result.fail("Child output failed schema validation; preserving this attempt before one corrective retry.".to_string());
        let previous = attempt.finish(&owner, false, update);
        let corrective = SubagentTask {
            task: corrective_retry_task(&task.task, &errors),
            ..task.clone()
        };
        let mut retry = self.run_child_process(agent, corrective, step, update, Some(schema), &owner).await;
        retry.result.schema_retries = Some(1);
        // Keep the public assignment stable; corrective prompt text is a
        // transport detail, not a replacement for the user's original task.
        retry.result.task.clone_from(&task.task);
        if let Some(iso) = previous.iso {
            retry.result.preserved_worktrees.push(iso);
        }
        if retry.result.is_error {
            retry.result.schema_valid = Some(false);
            retry.result.validation_errors = Some(errors);
            return retry.finish(&owner, false, update);
        }
        match validate_child_output(&retry.result.output, schema) {
            Ok(data) => {
                retry.result.data = Some(data);
                retry.result.schema_valid = Some(true);
            }
            Err(errors) => {
                retry.result.schema_valid = Some(false);
                retry.result.validation_errors = Some(errors);
                if task.schema_mode == SchemaMode::Strict {
                    retry.result.fail("Child output failed schema validation after the corrective retry (schemaMode: strict).".to_string());
                }
            }
        }
        // Permissive mode permits returning an invalid answer with a warning,
        // not installing edits that failed the requested acceptance contract.
        let accepted = retry.result.schema_valid == Some(true);
        retry.finish(&owner, accepted, update)
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    async fn run_child_process(
        &self,
        agent: &AgentDefinition,
        task: SubagentTask,
        step: Option<usize>,
        update: Option<&UpdateCallback>,
        schema: Option<&Value>,
        owner: &AgentCx,
    ) -> Attempt {
        let cwd = task.cwd.as_ref().map_or_else(
            || self.cwd.clone(),
            |path| if path.is_absolute() { path.clone() } else { self.cwd.join(path) },
        );
        let args = child_args(agent, &task.task, self.role_model_spec.as_deref(), schema);
        let policy = isolation_policy(&task);
        let mut attempt = Attempt::new(SubagentResult::starting(
            agent, task, step, &self.child_binary, &cwd, &args,
        ));
        if owner.checkpoint().is_err() {
            cancel(&mut attempt.result, CANCELLED);
            return attempt;
        }
        if !owner.capabilities().io || !owner.capabilities().time {
            attempt.result.fail("PI_SUBAGENT_PERMISSION: child execution requires I/O and timer capabilities".to_string());
            return attempt;
        }
        let (isolated, mode) = match policy {
            Ok(policy) => policy,
            Err(error) => { attempt.result.fail(error); return attempt; }
        };
        if !cwd.is_dir() {
            attempt.result.fail(format!("Working directory does not exist: {}", cwd.display()));
            return attempt;
        }
        if isolated {
            match crate::worktree_iso::isolate(&cwd, &attempt.result.task) {
                Ok(handle) => {
                    attempt.result.cwd.clone_from(&handle.path);
                    attempt.isolation = Some((handle, mode));
                }
                Err(error) => { attempt.result.fail(error.to_string()); return attempt; }
            }
        }
        if owner.checkpoint().is_err() {
            cancel(&mut attempt.result, CANCELLED);
            return attempt;
        }
        let hub_entry = crate::agent_hub::registry().lock().ok().and_then(|mut registry| {
            registry.register_kind(&agent.name, &attempt.result.task, self.hub_kind).ok()
        });
        attempt.result.hub_id = hub_entry.as_ref().map(|entry| entry.id.clone());
        attempt.hub.id.clone_from(&attempt.result.hub_id);
        emit_progress(update, &attempt.result);

        let mut command = Command::new(&self.child_binary);
        command.args(&args).current_dir(&attempt.result.cwd)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .env("PI_CODING_AGENT_DIR", &self.global_dir)
            .env("PI_SUBAGENT_PARENT_PID", std::process::id().to_string())
            .env("PI_SUBAGENT_DEPTH", child_depth().to_string())
            .env_remove("PI_SUBAGENT_STEER_FILE")
            .env_remove("PI_SUBAGENT_RUN_ID");
        if let Some(entry) = &hub_entry {
            command.env("PI_SUBAGENT_STEER_FILE", &entry.steer_path)
                .env("PI_SUBAGENT_RUN_ID", &entry.id);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                attempt.result.fail(format!("Failed to launch {}: {error}", self.child_binary.display()));
                return attempt;
            }
        };
        crate::tools::attach_child_job_discipline(&child);
        let mut child = ChildProcessGuard::new(child);
        attempt.result.pid = Some(child.id());
        attempt.result.status = SubagentStatus::Running;
        if let Some(id) = &attempt.result.hub_id
            && let Ok(mut registry) = crate::agent_hub::registry().lock()
        {
            registry.mark_running(id, child.id());
        }
        emit_progress(update, &attempt.result);
        let Some(stdout) = child.child.as_mut().and_then(|child| child.stdout.take()) else {
            attempt.result.fail("Child stdout was not piped.".to_string());
            return attempt;
        };
        let Some(stderr) = child.child.as_mut().and_then(|child| child.stderr.take()) else {
            attempt.result.fail("Child stderr was not piped.".to_string());
            return attempt;
        };
        let (tx, rx) = mpsc::sync_channel(protocol::PIPE_QUEUE_CAPACITY);
        let stdout = spawn_pipe_reader(stdout, PipeKind::Stdout, tx.clone());
        let stderr = spawn_pipe_reader(stderr, PipeKind::Stderr, tx);
        let mut protocol = protocol::ChildProtocol::default();
        loop {
            drain_child_frames(&rx, &mut protocol, &mut attempt.result, update);
            if owner.checkpoint().is_err() {
                cancel(&mut attempt.result, CANCELLED);
                child.terminate();
                break;
            }
            if attempt.result.is_error {
                // A producer that keeps writing after an invalid frame must
                // not keep an already-rejected task alive indefinitely.
                child.terminate();
                break;
            }
            match child.child.as_mut().expect("owned child").try_wait() {
                Ok(Some(status)) => {
                    attempt.result.exit_code = status.code();
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    attempt.result.fail(format!("Failed while waiting for child: {error}"));
                    child.terminate();
                    break;
                }
            }
            poll_pause(owner).await;
        }
        // No descendant should keep writing or hold the pipes open after its
        // root exits. The guard still owns cleanup if this drain is cancelled.
        child.stop_descendants();
        drain_until_reader_exit(rx, &mut protocol, &mut attempt.result, update, stdout, stderr, owner).await;
        if !attempt.result.is_error {
            if attempt.result.exit_code != Some(0) {
                attempt.result.fail(format!("Child exited with code {}.", attempt.result.exit_code.unwrap_or(-1)));
            } else if let Err(error) = protocol.finish() {
                attempt.result.fail(error.to_string());
            } else {
                attempt.result.status = SubagentStatus::Completed;
            }
        }
        child.disarm();
        attempt
    }
}

fn isolation_policy(task: &SubagentTask) -> Result<(bool, IsoApplyMode), String> {
    let isolated = match task.isolation.as_deref().unwrap_or("none").trim().to_ascii_lowercase().as_str() {
        "none" => false,
        "worktree" => true,
        _ => return Err("PI_SUBAGENT_ISOLATION: isolation must be none or worktree".to_string()),
    };
    let mode = IsoApplyMode::parse(task.iso_apply.as_deref()).map_err(|error| error.to_string())?;
    Ok((isolated, mode))
}

fn cancel(result: &mut SubagentResult, message: &str) {
    result.status = SubagentStatus::Cancelled;
    result.error = Some(message.to_string());
    result.is_error = true;
}

struct Attempt {
    result: SubagentResult,
    isolation: Option<(IsoHandle, IsoApplyMode)>,
    hub: HubLease,
}

impl Attempt {
    fn new(result: SubagentResult) -> Self {
        Self { result, isolation: None, hub: HubLease { id: None } }
    }

    fn finish(mut self, owner: &AgentCx, accepted: bool, update: Option<&UpdateCallback>) -> SubagentResult {
        if owner.checkpoint().is_err() {
            cancel(&mut self.result, CANCELLED);
        }
        if self.hub.was_killed() {
            cancel(&mut self.result, "Child was killed by the operator.");
        }
        let accepted = accepted && !self.result.is_error
            && matches!(self.result.status, SubagentStatus::Completed);
        if let Some((handle, requested)) = self.isolation.take() {
            // Both apply and explicit drop require an accepted result. A
            // failure keeps the evidence; no failed attempt is auto-deleted.
            let mode = if accepted { requested } else { IsoApplyMode::Keep };
            let mut outcome = IsoOutcome {
                schema: crate::worktree_iso::ISO_SCHEMA.to_string(),
                worktree_path: handle.path.display().to_string(),
                branch: handle.branch.clone(),
                diff_stat: String::new(),
                patch: String::new(),
                conflicted_files: Vec::new(),
                apply_mode: mode.as_str().to_string(),
                applied: false,
            };
            match crate::worktree_iso::collect_diff(&handle) {
                Ok((patch, stat)) => {
                    outcome.patch = patch;
                    outcome.diff_stat = stat;
                    // Recheck after snapshot collection, immediately before
                    // the externally visible mutation. No await splits this.
                    if owner.checkpoint().is_err() || self.hub.was_killed() {
                        cancel(&mut self.result, CANCELLED);
                        outcome.apply_mode = "keep".to_string();
                    } else if mode == IsoApplyMode::Apply {
                        match crate::worktree_iso::apply_to_parent(&handle, &outcome.patch) {
                            Ok(()) => {
                                outcome.applied = true;
                                if let Err(error) = crate::worktree_iso::drop_worktree(&handle) {
                                    self.result.fail(format!("Edits were applied, but isolated worktree cleanup failed: {error}"));
                                }
                            }
                            Err(error) => {
                                outcome.conflicted_files = error.to_string().lines().map(str::to_string).collect();
                                self.result.fail(error.to_string());
                            }
                        }
                    } else if mode == IsoApplyMode::Drop
                        && let Err(error) = crate::worktree_iso::drop_worktree(&handle)
                    {
                        self.result.fail(format!("Isolated worktree cleanup failed: {error}"));
                    }
                }
                Err(error) => {
                    outcome.apply_mode = "keep".to_string();
                    if !matches!(self.result.status, SubagentStatus::Cancelled) {
                        self.result.fail(format!("Failed to collect isolated diff; worktree preserved: {error}"));
                    }
                }
            }
            self.result.iso = Some(outcome);
        }
        self.hub.settle(&self.result);
        emit_progress(update, &self.result);
        self.result
    }
}

/// Independent of process ownership: a future can be dropped before spawn or
/// after process exit but before its result is accepted and written back.
struct HubLease { id: Option<String> }

impl HubLease {
    fn was_killed(&self) -> bool {
        self.id.as_ref().is_some_and(|id| {
            crate::agent_hub::registry().lock().ok()
                .and_then(|registry| registry.get(id))
                .is_some_and(|entry| entry.status == ChildStatus::Killed)
        })
    }

    fn settle(&mut self, result: &SubagentResult) {
        if let Some(id) = self.id.take()
            && let Ok(mut registry) = crate::agent_hub::registry().lock()
            && registry.get(&id).is_some_and(|entry| entry.status != ChildStatus::Killed)
        {
            let status = match result.status {
                SubagentStatus::Cancelled => ChildStatus::Cancelled,
                SubagentStatus::Completed if !result.is_error => ChildStatus::Done,
                _ => ChildStatus::Failed,
            };
            registry.settle(&id, status);
        }
    }
}

impl Drop for HubLease {
    fn drop(&mut self) {
        if let Some(id) = self.id.take()
            && let Ok(mut registry) = crate::agent_hub::registry().lock()
            && registry.get(&id).is_some_and(|entry| matches!(entry.status, ChildStatus::Starting | ChildStatus::Running))
        {
            registry.settle(&id, ChildStatus::Cancelled);
        }
    }
}

struct ChildProcessGuard {
    child: Option<std::process::Child>,
    descendants_stopped: bool,
}

impl ChildProcessGuard {
    const fn new(child: std::process::Child) -> Self {
        Self { child: Some(child), descendants_stopped: false }
    }
    fn id(&self) -> u32 { self.child.as_ref().map_or(0, std::process::Child::id) }
    fn stop_descendants(&mut self) {
        if self.descendants_stopped { return; }
        self.descendants_stopped = true;
        let pid = self.id();
        if pid == 0 { return; }
        #[cfg(unix)]
        if let Ok(pid) = i32::try_from(pid)
            && let Some(group) = rustix::process::Pid::from_raw(pid)
        {
            // This group was created by CommandExt::process_group(0).
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        #[cfg(not(unix))]
        crate::tools::kill_process_tree(Some(pid));
    }
    fn terminate(&mut self) {
        self.stop_descendants();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    fn disarm(&mut self) { let _ = self.child.take(); }
}

impl Drop for ChildProcessGuard {
    fn drop(&mut self) { self.terminate(); }
}

#[derive(Clone, Copy)]
enum PipeKind { Stdout, Stderr }

enum PipeFrame {
    Data(PipeKind, String),
    Error(&'static str),
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    pipe: R, kind: PipeKind, sender: mpsc::SyncSender<PipeFrame>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        loop {
            let bytes = match protocol::read_frame(&mut reader) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => break,
                Err(error) => { let _ = sender.send(PipeFrame::Error(error)); break; }
            };
            let line = match kind {
                PipeKind::Stderr => String::from_utf8_lossy(&bytes).into_owned(),
                PipeKind::Stdout => match String::from_utf8(bytes) {
                    Ok(line) => line,
                    Err(_) => {
                        let _ = sender.send(PipeFrame::Error("PI_SUBAGENT_PROTOCOL: child stdout is not UTF-8"));
                        break;
                    }
                },
            };
            if sender.send(PipeFrame::Data(kind, line)).is_err() { break; }
        }
    })
}

fn drain_child_frames(
    receiver: &Receiver<PipeFrame>, protocol: &mut protocol::ChildProtocol,
    result: &mut SubagentResult, update: Option<&UpdateCallback>,
) {
    // A continuously producing child cannot starve cancellation or exit checks.
    for _ in 0..DRAIN_BATCH {
        let Ok(frame) = receiver.try_recv() else { break; };
        match frame {
            PipeFrame::Error(error) if !result.is_error => result.fail(error.to_string()),
            PipeFrame::Data(PipeKind::Stderr, line) => append_bounded_line(&mut result.stderr, &line),
            PipeFrame::Data(PipeKind::Stdout, line) if !result.is_error => {
                match protocol.ingest(&line, &mut result.output) {
                    Ok(changed) => {
                        if let Some(id) = &result.hub_id
                            && let Ok(mut registry) = crate::agent_hub::registry().lock()
                        {
                            registry.append_transcript(id, &line);
                        }
                        if changed { emit_progress(update, result); }
                    }
                    Err(error) => result.fail(error.to_string()),
                }
            }
            _ => {}
        }
    }
}

async fn poll_pause(owner: &AgentCx) {
    let now = owner.cx().timer_driver().map_or_else(asupersync::time::wall_now, |timer| timer.now());
    asupersync::time::sleep(now, Duration::from_millis(10)).await;
}

#[allow(clippy::too_many_arguments)]
async fn drain_until_reader_exit(
    receiver: Receiver<PipeFrame>, protocol: &mut protocol::ChildProtocol,
    result: &mut SubagentResult, update: Option<&UpdateCallback>,
    stdout: JoinHandle<()>, stderr: JoinHandle<()>, owner: &AgentCx,
) {
    let deadline = Instant::now() + PIPE_DRAIN_TIMEOUT;
    loop {
        drain_child_frames(&receiver, protocol, result, update);
        if stdout.is_finished() && stderr.is_finished() {
            // Neither thread can produce another frame after this barrier.
            drain_child_frames(&receiver, protocol, result, update);
            let stdout_ok = stdout.join().is_ok();
            let stderr_ok = stderr.join().is_ok();
            if (!stdout_ok || !stderr_ok) && !result.is_error {
                result.fail(protocol::PIPE_ERROR.to_string());
            }
            return;
        }
        if owner.checkpoint().is_err() {
            cancel(result, CANCELLED);
        }
        if Instant::now() >= deadline {
            if !result.is_error {
                result.fail("PI_SUBAGENT_PIPE_TIMEOUT: child pipes did not close after process termination".to_string());
            }
            return;
        }
        poll_pause(owner).await;
    }
}
