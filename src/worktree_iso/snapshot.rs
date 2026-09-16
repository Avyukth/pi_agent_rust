//! Build an isolated checkout from the parent's effective working tree.
//!
//! Use a private index rather than applying a diff and copying newline-delimited
//! untracked paths. Git retains binary data, symlinks, executable modes and names
//! containing tabs/newlines. The parent's index, HEAD and branch are never written.
//! This is not a filesystem-wide atomic snapshot of concurrent external writers.

use crate::error::{Error, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_INDEX_RECORD_BYTES: u64 = 32 * 1024 * 1024;

fn failure(code: &str, message: &str) -> Error {
    Error::tool("subagent", format!("{code}: {message}"))
}

fn command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo)
        .args(["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // The explicit repository is the authority, not ambient routing variables
    // inherited from a hook, another worktree, or a caller's temporary index.
    for key in ["GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
        command.env_remove(key);
    }
    command
}

fn run(command: &mut Command, operation: &str) -> Result<Vec<u8>> {
    let output = command.output().map_err(|error| {
        failure("PI_ISO_SNAPSHOT", &format!("Cannot {operation}: {error}"))
    })?;
    if !output.status.success() {
        let diagnostic: String = String::from_utf8_lossy(&output.stderr).chars().take(4096).collect();
        return Err(failure("PI_ISO_SNAPSHOT", &format!("Cannot {operation}: {}", diagnostic.trim())));
    }
    Ok(output.stdout)
}

fn object_id(bytes: &[u8]) -> Result<String> {
    let id = std::str::from_utf8(bytes).map_err(|_| failure("PI_ISO_SNAPSHOT", "Invalid Git object id"))?.trim();
    if !matches!(id.len(), 40 | 64) || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(failure("PI_ISO_SNAPSHOT", "Invalid Git object id"));
    }
    Ok(id.to_string())
}

/// Resolve the actual repository root, including when called from a subdirectory.
/// Strip only Git's record terminator, never whitespace belonging to the path.
pub(super) fn repository_root(cwd: &Path) -> Result<PathBuf> {
    let mut bytes = run(command(cwd).args(["rev-parse", "--show-toplevel"]), "locate repository root")?;
    if bytes.last() == Some(&b'\n') { bytes.pop(); }
    #[cfg(windows)]
    if bytes.last() == Some(&b'\r') { bytes.pop(); }
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStringExt as _;
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(String::from_utf8(bytes).map_err(|_| {
        failure("PI_ISO_SNAPSHOT", "Repository root is not representable on this platform")
    })?);
    path.canonicalize().map_err(|error| failure("PI_ISO_SNAPSHOT", &format!("Cannot resolve repository root: {error}")))
}

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!("pi-iso-index-{}", uuid::Uuid::new_v4().simple()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&root).map_err(|error| failure("PI_ISO_SNAPSHOT", &format!("Cannot create private index directory: {error}")))?;
        let scratch = Self { root };
        fs::create_dir(scratch.root.join("hooks")).map_err(|error| {
            failure("PI_ISO_SNAPSHOT", &format!("Cannot create empty hook directory: {error}"))
        })?;
        Ok(scratch)
    }

    fn command(&self, repo: &Path) -> Command {
        let mut command = command(repo);
        command.env("GIT_INDEX_FILE", self.root.join("index"))
            .args(["-c", "core.splitIndex=false", "-c", "core.ignorestat=false"]);
        command
    }

    fn entries(&self, mut command: Command, name: &str) -> Result<Vec<u8>> {
        let path = self.root.join(name);
        let file = File::create(&path).map_err(|error| failure("PI_ISO_SNAPSHOT", &format!("Cannot stage index records: {error}")))?;
        run(command.args(["ls-files", "--stage", "--full-name", "-z"]).stdout(file), "read index records")?;
        let mut bytes = Vec::new();
        File::open(&path).and_then(|file| file.take(MAX_INDEX_RECORD_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| failure("PI_ISO_SNAPSHOT", &format!("Cannot read index records: {error}")))?;
        if bytes.len() as u64 > MAX_INDEX_RECORD_BYTES {
            return Err(failure("PI_ISO_SNAPSHOT_LIMIT", "Index records exceed the 32 MiB isolation limit"));
        }
        Ok(bytes)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Remove only our known scratch files, not arbitrary descendants.
        for name in ["index", "index.lock", "parent", "verify", "materialized"] {
            let _ = fs::remove_file(self.root.join(name));
        }
        let _ = fs::remove_dir(self.root.join("hooks"));
        let _ = fs::remove_dir(&self.root);
    }
}

fn reject_gitlinks(records: &[u8]) -> Result<()> {
    if records.split(|byte| *byte == 0).any(|record| record.starts_with(b"160000 ")) {
        return Err(failure(
            "PI_ISO_SUBMODULE_UNSUPPORTED",
            "Isolation cannot materialize submodules or embedded repositories without a separate checkout; no incomplete child was launched",
        ));
    }
    Ok(())
}

/// An internal commit plus the private hook directory used during checkout.
pub(super) struct Snapshot {
    pub(super) baseline: String,
    scratch: Scratch,
}

impl Snapshot {
    pub(super) fn checkout(&self, repo: &Path, path: &Path, branch: &str) -> Result<()> {
        run(command(repo)
            .arg("-c").arg(format!("core.hooksPath={}", self.scratch.root.join("hooks").display()))
            .args(["worktree", "add", "-b", branch]).arg(path).arg(&self.baseline),
            "create isolated checkout")?;
        Ok(())
    }
}

/// Capture effective file contents while preserving the parent's staged state.
/// Seed from its index, not HEAD, so newly tracked ignored files and staged
/// additions remain tracked. Refresh only the private index from the filesystem.
pub(super) fn capture(repo: &Path, id: &str) -> Result<Snapshot> {
    let sparse = command(repo).args(["config", "--bool", "core.sparseCheckout"]).output()
        .map_err(|error| failure("PI_ISO_SNAPSHOT", &format!("Cannot inspect checkout mode: {error}")))?;
    if sparse.status.success() && sparse.stdout.starts_with(b"true") {
        return Err(failure("PI_ISO_SPARSE_UNSUPPORTED", "Sparse checkouts require an explicit full checkout before isolation"));
    }
    if !sparse.status.success() && sparse.status.code() != Some(1) {
        return Err(failure("PI_ISO_SNAPSHOT", "Cannot inspect checkout mode"));
    }
    let head = object_id(&run(command(repo).args(["rev-parse", "--verify", "HEAD^{commit}"]), "resolve parent commit")?)?;
    let scratch = Scratch::new()?;
    let parent_entries = scratch.entries(command(repo), "parent")?;
    reject_gitlinks(&parent_entries)?;
    run(scratch.command(repo).args(["read-tree", "--empty"]), "initialize private index")?;
    let input = File::open(scratch.root.join("parent"))
        .map_err(|error| failure("PI_ISO_SNAPSHOT", &format!("Cannot open index records: {error}")))?;
    run(scratch.command(repo).args(["update-index", "-z", "--index-info"]).stdin(input), "seed private index")?;
    run(scratch.command(repo).args(["add", "--all", "--", "."]), "snapshot working files")?;
    reject_gitlinks(&scratch.entries(scratch.command(repo), "materialized")?)?;
    let tree = object_id(&run(scratch.command(repo).arg("write-tree"), "write snapshot tree")?)?;

    // Plumbing does not run commit hooks, use the user's signing key, move HEAD,
    // or require a configured author. This commit belongs only to the pi-iso
    // branch and records the launch baseline, not a user-authored source commit.
    let mut commit = command(repo);
    commit.args(["-c", "commit.gpgSign=false", "commit-tree", &tree, "-p", &head, "--no-gpg-sign", "-m"])
        .arg(format!("pi-iso baseline {id}"))
        .env("GIT_AUTHOR_NAME", "Pi Isolation").env("GIT_AUTHOR_EMAIL", "pi-isolation@localhost")
        .env("GIT_COMMITTER_NAME", "Pi Isolation").env("GIT_COMMITTER_EMAIL", "pi-isolation@localhost")
        .env_remove("GIT_AUTHOR_DATE").env_remove("GIT_COMMITTER_DATE");
    let baseline = object_id(&run(&mut commit, "record snapshot baseline")?)?;
    let current_head = object_id(&run(command(repo).args(["rev-parse", "--verify", "HEAD^{commit}"]), "verify parent commit")?)?;
    if current_head != head || scratch.entries(command(repo), "verify")? != parent_entries {
        return Err(failure("PI_ISO_PARENT_CHANGED", "Parent HEAD or index changed while capturing isolation; retry the delegation"));
    }
    Ok(Snapshot { baseline, scratch })
}
