//! Host-authorized shared keys for native child processes.
//!
//! A child keeps its own ephemeral transcript and job session. Only these
//! dedicated tools use the parent's frozen shared-key namespace. The grant
//! is carried in the child environment, never in prompts or tool arguments.
//! Run-id/parent/cwd checks prevent accidental reuse by unrelated launches;
//! they are not an OS sandbox against a process with arbitrary shell access.

use super::{MemoryStore, SharedMemoryStore, SharedMemoryTool, failure, validate_session};
use crate::agent_cx::AgentCx;
use crate::error::Result;
use crate::jobs::JobSessionScope;
use crate::tools::{Tool, ToolEffects, ToolOutput, ToolUpdate};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

pub(crate) const GRANT_ENV: &str = "PI_SUBAGENT_SHARED_MEMORY";
const MAX_GRANT_BYTES: usize = 16 * 1024;
const GRANT_VERSION: u32 = 1;
const TOOL_NAMES: [&str; 3] = ["read_memory", "write_memory", "list_memory"];

/// Explicit tool pins opt in; the native default tool set accepts a grant.
/// Check this before resolving a live owner, so an unshared task does not
/// depend on an unrelated or unavailable memory-session resolver.
pub(crate) fn accepts_tool_selection(tools: Option<&[String]>) -> bool {
    tools.is_none_or(|names| names.iter().any(|name| TOOL_NAMES.contains(&name.as_str())))
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Access {
    ReadOnly,
    ReadWrite,
}

/// Host binding for a delegating tool. A registry supplies its live session
/// resolver, and the subagent tool resolves it once per complete request.
/// Parallel children, chain steps and corrective retries then share that
/// immutable result, even if the parent switches session while they run.
#[derive(Clone)]
pub struct SharedMemoryBinding {
    bank: Arc<MemoryStore>,
    scope: JobSessionScope,
    access: Access,
    source_root: Option<PathBuf>,
}

impl SharedMemoryBinding {
    #[must_use]
    pub const fn new(bank: Arc<MemoryStore>, scope: JobSessionScope) -> Self {
        Self { bank, scope, access: Access::ReadWrite, source_root: None }
    }

    /// Attenuate this binding. No method upgrades an inherited read-only grant.
    #[must_use]
    pub const fn read_only(mut self) -> Self {
        self.access = Access::ReadOnly;
        self
    }

    pub(crate) async fn resolve(&self) -> Result<ResolvedMemory> {
        let owner = AgentCx::for_current_or_request();
        owner.checkpoint().map_err(|_| cancelled())?;
        if !owner.capabilities().io {
            return Err(failure("PI_SHARED_MEMORY_PERMISSION", "Shared memory requires I/O capability"));
        }
        let session_id = self.scope.session_id().await.map_err(|_| invalid_grant())?;
        owner.checkpoint().map_err(|_| cancelled())?;
        Ok(ResolvedMemory {
            store: SharedMemoryStore::new(Arc::clone(&self.bank), session_id)?,
            access: self.access,
            source_root: self.source_root.clone().unwrap_or_else(|| self.bank.project_root.clone()),
        })
    }
}

fn cancelled() -> crate::error::Error {
    failure("PI_SHARED_MEMORY_CANCELLED", "Shared-memory delegation cancelled before launch")
}

fn invalid_grant() -> crate::error::Error {
    failure(
        "PI_SHARED_MEMORY_DELEGATION",
        "Shared-memory delegation is invalid or unavailable; no session fallback is used",
    )
}

fn read_only_error() -> crate::error::Error {
    failure("PI_SHARED_MEMORY_READ_ONLY", "This child may read shared keys but cannot modify them")
}

/// Never derive Debug: the grant contains host session and storage identities.
#[derive(Clone)]
pub(crate) struct ResolvedMemory {
    store: SharedMemoryStore,
    access: Access,
    source_root: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    version: u32,
    parent_pid: u32,
    run_id: String,
    working_directory: PathBuf,
    database: PathBuf,
    project_root: PathBuf,
    project_key: String,
    session_id: String,
    access: Access,
}

fn valid_run_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256
        && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Command inherits ambient variables unless explicitly removed. Every native
/// launch calls this, including launches that have no memory binding.
pub(crate) fn configure_child_command(
    command: &mut Command,
    memory: Option<&ResolvedMemory>,
    cwd: &Path,
    parent_pid: u32,
    run_id: &str,
) -> Result<()> {
    command.env_remove(GRANT_ENV);
    if let Some(memory) = memory {
        memory.configure_command(command, cwd, parent_pid, run_id)?;
    }
    Ok(())
}

impl ResolvedMemory {
    fn binding(&self) -> SharedMemoryBinding {
        SharedMemoryBinding {
            bank: Arc::clone(&self.store.bank),
            scope: JobSessionScope::fixed(self.store.session_id.clone()),
            access: self.access,
            source_root: Some(self.source_root.clone()),
        }
    }

    /// An explicit agent tool pin remains an opt-in boundary. With a pin,
    /// at least one shared alias must be named; write_memory must be named
    /// to obtain writes. Omitting tools uses the native child's defaults.
    /// All choices are intersected with the inherited permission ceiling.
    pub(crate) fn for_tool_selection(&self, tools: Option<&[String]>) -> Option<Self> {
        if !accepts_tool_selection(tools) {
            return None;
        }
        let mut memory = self.clone();
        if let Some(tools) = tools {
            if !tools.iter().any(|name| name == "write_memory") {
                memory.access = Access::ReadOnly;
            }
        }
        Some(memory)
    }

    /// The requested source cwd must belong to the authorized project. An
    /// isolated worktree is created only after this check; its different path
    /// does not create a new bank or change the owner session.
    pub(crate) fn check_source_directory(&self, cwd: &Path) -> Result<()> {
        let root = self.source_root.canonicalize().map_err(|_| invalid_grant())?;
        let cwd = cwd.canonicalize().map_err(|_| invalid_grant())?;
        if !cwd.starts_with(root) {
            return Err(failure(
                "PI_SHARED_MEMORY_DELEGATION_SCOPE",
                "A delegated shared-memory task must start within its authorized project",
            ));
        }
        Ok(())
    }

    /// Ensure the dedicated tools are in the child's pinned schema. Existing
    /// explicit tools remain unchanged, except a read-only grant cannot request
    /// the reserved writer alias. No long-term memory or reflection tool is added.
    pub(crate) fn add_tool_args(&self, args: &mut [OsString]) -> Result<()> {
        let index = args.iter().position(|arg| arg == "--tools").ok_or_else(invalid_grant)?;
        let value = args.get_mut(index + 1).ok_or_else(invalid_grant)?;
        let original = value.to_str().ok_or_else(invalid_grant)?;
        let explicitly_selected = original.split(',').any(|name| TOOL_NAMES.contains(&name));
        let mut names: Vec<&str> = original.split(',')
            .filter(|name| !name.is_empty()
                && (*name != "write_memory" || self.access == Access::ReadWrite)).collect();
        if !explicitly_selected {
            names.push("read_memory");
            if self.access == Access::ReadWrite { names.push("write_memory"); }
            names.push("list_memory");
        }
        if names.is_empty() {
            // An empty --tools value can be interpreted as a default set by
            // a host. Never widen an exhausted explicit pin that way.
            return Err(read_only_error());
        }
        *value = OsString::from(names.join(","));
        Ok(())
    }

    pub(crate) fn configure_command(
        &self, command: &mut Command, cwd: &Path, parent_pid: u32, run_id: &str,
    ) -> Result<()> {
        if parent_pid == 0 || !valid_run_id(run_id) { return Err(invalid_grant()); }
        validate_session(&self.store.session_id).map_err(|_| invalid_grant())?;
        let grant = Grant {
            version: GRANT_VERSION,
            parent_pid,
            run_id: run_id.to_string(),
            working_directory: cwd.canonicalize().map_err(|_| invalid_grant())?,
            database: self.store.bank.db_path.clone(),
            project_root: self.store.bank.project_root.canonicalize().map_err(|_| invalid_grant())?,
            project_key: self.store.bank.project_key.clone(),
            session_id: self.store.session_id.clone(),
            access: self.access,
        };
        if !grant.database.is_absolute() || grant.project_key.is_empty() || grant.project_key.len() > 128 {
            return Err(invalid_grant());
        }
        let encoded = serde_json::to_string(&grant).map_err(|_| invalid_grant())?;
        if encoded.len() > MAX_GRANT_BYTES { return Err(invalid_grant()); }
        command.env(GRANT_ENV, encoded);
        Ok(())
    }

    fn decode(raw: &OsStr, cwd: &Path, parent_pid: Option<&OsStr>, run_id: Option<&OsStr>) -> Result<Self> {
        let raw = raw.to_str().filter(|value| value.len() <= MAX_GRANT_BYTES).ok_or_else(invalid_grant)?;
        let grant: Grant = serde_json::from_str(raw).map_err(|_| invalid_grant())?;
        let parent_pid = parent_pid.and_then(OsStr::to_str)
            .and_then(|value| value.parse::<u32>().ok()).ok_or_else(invalid_grant)?;
        let run_id = run_id.and_then(OsStr::to_str).ok_or_else(invalid_grant)?;
        if grant.version != GRANT_VERSION || parent_pid == 0 || grant.parent_pid != parent_pid
            || !valid_run_id(run_id) || grant.run_id != run_id
            || !grant.database.is_absolute() || !grant.project_root.is_absolute()
            || !grant.working_directory.is_absolute()
            || grant.project_key.is_empty() || grant.project_key.len() > 128
            || cwd.canonicalize().map_err(|_| invalid_grant())? != grant.working_directory
        {
            return Err(invalid_grant());
        }
        validate_session(&grant.session_id).map_err(|_| invalid_grant())?;
        let bank = Arc::new(MemoryStore {
            db_path: grant.database,
            project_root: grant.project_root,
            project_key: grant.project_key,
        });
        Ok(Self {
            store: SharedMemoryStore::new(bank, grant.session_id).map_err(|_| invalid_grant())?,
            access: grant.access,
            source_root: grant.working_directory,
        })
    }
}

/// Install only task-key tools for an explicitly granted child. A malformed
/// present grant installs rejecting tools, not tools targeting a fresh local
/// session. ToolRegistry's later job-scope binding cannot retarget these tools.
pub(crate) fn attach_child_tools(
    cwd: &Path,
    enabled: &[&str],
    tools: &mut Vec<Box<dyn Tool>>,
) {
    let Some(raw) = std::env::var_os(GRANT_ENV) else { return; };
    let parent_pid = std::env::var_os("PI_SUBAGENT_PARENT_PID");
    let run_id = std::env::var_os("PI_SUBAGENT_RUN_ID");
    let memory = ResolvedMemory::decode(&raw, cwd, parent_pid.as_deref(), run_id.as_deref());
    install_tools(memory, enabled, tools);
}

fn install_tools(
    memory: Result<ResolvedMemory>,
    enabled: &[&str],
    tools: &mut Vec<Box<dyn Tool>>,
) {
    let memory = memory.ok();
    // Attenuate nested launchers before collision handling too. A pre-existing
    // tool identity must not accidentally preserve a broader local-bank grant.
    let binding = memory.as_ref().map(ResolvedMemory::binding);
    for tool in &mut *tools { tool.bind_shared_memory(binding.clone()); }
    if tools.iter().any(|tool| TOOL_NAMES.contains(&tool.name())) {
        // Do not shadow or partially install over existing host tool identities.
        // Normal native construction has no aliases until this point.
        tracing::warn!("shared-memory child tool names collide; delegation was not installed");
        return;
    }
    // Inherited authority wins over a separately configured local bank. Invalid
    // inheritance explicitly clears delegation rather than using that bank.
    // A read-only child cannot upgrade nested delegations to read-write.
    if memory.is_none() {
        tracing::warn!("shared-memory child grant rejected; task-key tools will deny access");
    }
    for name in TOOL_NAMES {
        if !enabled.contains(&name) {
            continue;
        }
        let inner = memory.as_ref().map(|memory| {
            let bank = Arc::clone(&memory.store.bank);
            let mut tool = match name {
                "read_memory" => SharedMemoryTool::read(bank),
                "write_memory" => SharedMemoryTool::write(bank),
                _ => SharedMemoryTool::list(bank),
            };
            tool.bind_job_session_scope(JobSessionScope::fixed(memory.store.session_id.clone()));
            tool
        });
        tools.push(Box::new(DelegatedTool {
            name,
            writable: memory.as_ref().is_some_and(|memory| memory.access == Access::ReadWrite),
            inner,
        }));
    }
}

struct DelegatedTool {
    name: &'static str,
    writable: bool,
    inner: Option<SharedMemoryTool>,
}

#[async_trait::async_trait]
impl Tool for DelegatedTool {
    fn name(&self) -> &'static str { self.name }
    fn label(&self) -> &'static str { self.name }
    fn description(&self) -> &'static str {
        match self.name {
            "read_memory" => "Read a key and revision from this task's parent-shared namespace. It is separate from your transcript and cannot be selected in arguments.",
            "write_memory" => "Write exact text to this task's parent-shared namespace. Use expectedRevision from read_memory (or 'absent' for create-only) to avoid overwriting another agent. A read-only grant denies all writes.",
            _ => "List this task's parent-shared keys, bounded previews and revisions, with literal prefix filtering and key cursors.",
        }
    }
    fn parameters(&self) -> Value {
        self.inner.as_ref().map_or_else(|| json!({"type":"object"}), Tool::parameters)
    }
    fn effects(&self) -> ToolEffects {
        if self.name == "write_memory" { ToolEffects::write() } else { ToolEffects::read() }
    }
    // Intentionally do not implement bind_job_session_scope: the child's job
    // owner is not the parent namespace. The captured inner binding is immutable.
    async fn execute(&self, id: &str, input: Value, update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>) -> Result<ToolOutput> {
        let inner = self.inner.as_ref().ok_or_else(invalid_grant)?;
        if self.name == "write_memory" && !self.writable { return Err(read_only_error()); }
        inner.execute(id, input, update).await
    }
}

#[cfg(test)]
#[path = "delegation_tests.rs"]
mod tests;
