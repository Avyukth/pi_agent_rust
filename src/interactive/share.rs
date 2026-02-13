use chrono::Utc;
use std::ffi::OsString;
use std::path::Path;
use url::Url;

pub(super) fn run_command_output(
    program: &str,
    args: &[OsString],
    cwd: &Path,
    abort_signal: &crate::agent::AbortSignal,
) -> std::io::Result<std::process::Output> {
    use std::process::{Command, Stdio};
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration;

    let child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = child.id();

    let (tx, rx) = std_mpsc::channel();
    std::thread::spawn(move || {
        let result = child.wait_with_output();
        let _ = tx.send(result);
    });

    let tick = Duration::from_millis(10);
    loop {
        if abort_signal.is_aborted() {
            crate::tools::kill_process_tree(Some(pid));
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "command aborted",
            ));
        }

        match rx.recv_timeout(tick) {
            Ok(result) => return result,
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                return Err(std::io::Error::other("command output channel disconnected"));
            }
        }
    }
}

pub(super) fn parse_gist_url_and_id(output: &str) -> Option<(String, String)> {
    for raw in output.split_whitespace() {
        let candidate_url = raw.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';'));
        let Ok(url) = Url::parse(candidate_url) else {
            continue;
        };
        let Some(host) = url.host_str() else {
            continue;
        };
        if host != "gist.github.com" {
            continue;
        }
        let Some(gist_id) = url.path_segments().and_then(|mut seg| seg.next_back()) else {
            continue;
        };
        if gist_id.is_empty() {
            continue;
        }
        return Some((candidate_url.to_string(), gist_id.to_string()));
    }
    None
}

pub(super) fn format_command_output(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => "(no output)".to_string(),
        (false, true) => format!("stdout:\n{stdout}"),
        (true, false) => format!("stderr:\n{stderr}"),
        (false, false) => format!("stdout:\n{stdout}\n\nstderr:\n{stderr}"),
    }
}

/// Build a gist description from the optional session name and current time.
pub(super) fn share_gist_description(session_name: Option<&str>) -> String {
    session_name.map_or_else(
        || format!("Pi session {}", Utc::now().format("%Y-%m-%dT%H:%M:%SZ")),
        |name| format!("Pi session: {name}"),
    )
}

/// Check whether `/share` args request a public gist.
pub(super) fn parse_share_is_public(args: &str) -> bool {
    args.split_whitespace()
        .any(|w| w.eq_ignore_ascii_case("public"))
}
