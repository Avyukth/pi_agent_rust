//! Registered debug adapters and target-aware launch arguments (bd-cv653.1.2).
//! Built-in adapters: lldb-dap and debugpy over stdio, Delve over owned TCP.

use std::path::Path;

use serde_json::Value;

/// One trusted debug-adapter definition. Tool arguments select this ID, never
/// an arbitrary executable. SDK hosts can override definitions explicitly.
#[derive(Debug, Clone)]
pub struct AdapterSpec {
    pub id: String,
    pub command_candidates: Vec<String>,
    pub adapter_args: Vec<String>,
    pub languages: Vec<&'static str>,
    pub install_hint: String,
}

impl AdapterSpec {
    /// Return the exact absolute path discovered now, so changing the child's
    /// working directory cannot resolve a relative PATH entry somewhere else.
    #[must_use]
    pub fn resolve_command(&self) -> Option<String> {
        self.command_candidates.iter().find_map(|candidate| {
            let path = Path::new(candidate);
            if path.is_absolute()
                || candidate.contains('/')
                || (cfg!(windows) && candidate.contains('\\'))
            {
                return resolved_executable(path);
            }
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .find_map(|directory| resolved_executable(&directory.join(candidate)))
            })
        })
    }
}

fn resolved_executable(path: &Path) -> Option<String> {
    let path = std::fs::canonicalize(path).ok()?;
    let metadata = path.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
    }
    // Command uses the actual path, never a lossy replacement spelling.
    path.to_str().map(str::to_owned)
}

#[must_use]
pub fn default_adapters() -> Vec<AdapterSpec> {
    let mut lldb_candidates = vec!["lldb-dap".to_string()];
    for dir in ["/usr/lib", "/usr/local/lib"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("llvm") {
                    let candidate = entry.path().join("bin/lldb-dap");
                    if candidate.is_file() {
                        lldb_candidates.push(candidate.display().to_string());
                    }
                }
            }
        }
    }
    lldb_candidates.push("/usr/bin/lldb-dap".to_string());
    lldb_candidates.push("/Library/Developer/CommandLineTools/usr/bin/lldb-dap".to_string());
    vec![
        AdapterSpec {
            id: "lldb-dap".to_string(),
            command_candidates: lldb_candidates,
            adapter_args: vec![],
            languages: vec!["rust", "c", "cpp", "binary"],
            install_hint: "install the LLVM toolchain (lldb-dap ships with lldb)".to_string(),
        },
        AdapterSpec {
            id: "debugpy".to_string(),
            command_candidates: vec!["python3".to_string()],
            adapter_args: vec!["-m".to_string(), "debugpy.adapter".to_string()],
            languages: vec!["python"],
            install_hint: "install with: pip install debugpy".to_string(),
        },
        AdapterSpec {
            id: "dlv".to_string(),
            command_candidates: vec!["dlv".to_string(), "dlv.exe".to_string()],
            adapter_args: vec!["dap".to_string()],
            languages: vec!["go"],
            install_hint: "install with: go install github.com/go-delve/delve/cmd/dlv@latest"
                .to_string(),
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetKind {
    NativeBinary,
    Python,
    Go,
}

/// Local package directories are meaningful Go targets, not native binaries.
/// A compiled Go binary still needs adapter="dlv" because its language cannot
/// be inferred reliably from its filename.
#[must_use]
pub fn classify_target(target: &Path) -> TargetKind {
    if target.is_dir()
        && (target.join("go.mod").is_file()
            || std::fs::read_dir(target).is_ok_and(|entries| {
                entries
                    .take(4096)
                    .filter_map(std::result::Result::ok)
                    .any(|entry| {
                        entry
                            .path()
                            .extension()
                            .is_some_and(|extension| extension == "go")
                            && entry.path().is_file()
                    })
            }))
    {
        return TargetKind::Go;
    }
    match target.extension().and_then(|extension| extension.to_str()) {
        Some("py") => TargetKind::Python,
        Some("go") => TargetKind::Go,
        _ => TargetKind::NativeBinary,
    }
}

#[must_use]
pub fn select_adapter(
    target: Option<&Path>,
    requested: Option<&str>,
    overrides: &[AdapterSpec],
) -> Option<AdapterSpec> {
    let available = if overrides.is_empty() {
        default_adapters()
    } else {
        let mut merged = overrides.to_vec();
        let overridden: Vec<_> = overrides
            .iter()
            .map(|adapter| adapter.id.as_str())
            .collect();
        merged.extend(
            default_adapters()
                .into_iter()
                .filter(|adapter| !overridden.contains(&adapter.id.as_str())),
        );
        merged
    };
    if let Some(id) = requested {
        return available.into_iter().find(|adapter| adapter.id == id);
    }
    let language = match target.map_or(TargetKind::NativeBinary, classify_target) {
        TargetKind::Python => "python",
        TargetKind::Go => "go",
        TargetKind::NativeBinary => "binary",
    };
    available
        .into_iter()
        .filter(|adapter| adapter.languages.contains(&language))
        .find(|adapter| adapter.resolve_command().is_some())
}

#[must_use]
pub fn go_launch_mode(program: &Path) -> &'static str {
    if program
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("_test.go"))
    {
        "test"
    } else if program.is_dir()
        || program
            .extension()
            .is_some_and(|extension| extension == "go")
    {
        "debug"
    } else {
        "exec"
    }
}

#[must_use]
pub fn launch_arguments(
    adapter: &AdapterSpec,
    program: &Path,
    args: &[String],
    cwd: &Path,
) -> Value {
    match adapter.id.as_str() {
        "dlv" => serde_json::json!({
            "program": program.display().to_string(),
            "args": args,
            "cwd": cwd.display().to_string(),
            "mode": go_launch_mode(program),
            "stopOnEntry": true,
        }),
        _ => serde_json::json!({
            "program": program.display().to_string(),
            "args": args,
            "cwd": cwd.display().to_string(),
            "console": "internalConsole",
            "stopOnEntry": true,
        }),
    }
}

#[must_use]
pub fn attach_arguments(adapter: &AdapterSpec, pid: u32) -> Value {
    match adapter.id.as_str() {
        "debugpy" => serde_json::json!({ "processId": pid }),
        "dlv" => serde_json::json!({ "processId": pid, "mode": "local" }),
        _ => serde_json::json!({ "pid": pid }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_by_extension() {
        assert_eq!(classify_target(Path::new("app.py")), TargetKind::Python);
        assert_eq!(classify_target(Path::new("main.go")), TargetKind::Go);
        assert_eq!(
            classify_target(Path::new("/bin/true")),
            TargetKind::NativeBinary
        );
    }

    #[test]
    fn requested_id_wins_over_auto() {
        let picked = select_adapter(Some(Path::new("app.py")), Some("lldb-dap"), &[]);
        assert_eq!(picked.expect("found").id, "lldb-dap");
    }

    #[test]
    fn auto_select_needs_resolvable_command() {
        if let Some(picked) = select_adapter(Some(Path::new("x.py")), None, &[]) {
            assert_eq!(picked.id, "debugpy");
        }
    }

    #[test]
    fn launch_args_shape_per_adapter() {
        let adapters = default_adapters();
        let lldb = adapters
            .iter()
            .find(|adapter| adapter.id == "lldb-dap")
            .unwrap();
        let args = launch_arguments(
            lldb,
            Path::new("/tmp/app"),
            &["--flag".to_string()],
            Path::new("/tmp"),
        );
        assert_eq!(args["program"], "/tmp/app");
        assert_eq!(args["args"][0], "--flag");
        let dlv = adapters.iter().find(|adapter| adapter.id == "dlv").unwrap();
        assert_eq!(
            launch_arguments(dlv, Path::new("/tmp/app"), &[], Path::new("/tmp"))["mode"],
            "exec"
        );
        assert_eq!(attach_arguments(lldb, 4242)["pid"], 4242);
        assert_eq!(
            attach_arguments(dlv, 4242),
            serde_json::json!({"processId":4242,"mode":"local"})
        );
    }

    #[test]
    fn go_sources_tests_packages_and_binaries_have_distinct_modes() {
        assert_eq!(go_launch_mode(Path::new("main.go")), "debug");
        assert_eq!(go_launch_mode(Path::new("main_test.go")), "test");
        assert_eq!(go_launch_mode(Path::new("server")), "exec");
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(go_launch_mode(directory.path()), "debug");
        assert_eq!(classify_target(directory.path()), TargetKind::NativeBinary);
        std::fs::write(directory.path().join("main.go"), "package main\n").unwrap();
        assert_eq!(classify_target(directory.path()), TargetKind::Go);
    }

    #[cfg(unix)]
    #[test]
    fn executable_resolution_preserves_identity_and_rejects_nonexecutables() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("adapter");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(resolved_executable(&program).is_none());
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = directory.path().join("link");
        symlink(&program, &link).unwrap();
        assert_eq!(
            resolved_executable(&link).unwrap(),
            std::fs::canonicalize(&program).unwrap().to_str().unwrap()
        );
        assert!(resolved_executable(directory.path()).is_none());
    }
}
