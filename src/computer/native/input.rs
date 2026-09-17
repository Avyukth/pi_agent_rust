//! Authorized X11 input and owned clipboard selection service.
//!
//! Only fixed helper commands and validated operands enter argv. Literal typed
//! text travels on stdin. A separate, pre-authorized release process is armed
//! before any key/button press, so cancelling the input child does not require
//! new spawn authority to attempt key/button cleanup.

use super::{State, active_window, check_owner, error, key, output, process, query};
use crate::agent_cx::AgentCx;
use crate::error::Result;
use crate::tools::ToolOutput;
use process::{Running, strings};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

// The script is constant. The cleanup executable and arguments are positional
// parameters, never interpolated source. EOF means the owning operation was
// dropped; only an explicit completion token disarms cleanup.
const RELEASE_SCRIPT: &str =
    "IFS= read -r outcome\nif [ \"$outcome\" = complete ]; then exit 0; fi\nexec \"$@\"\n";

struct ReleaseGuard {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}

impl ReleaseGuard {
    fn arm(
        owner: &AgentCx,
        cwd: &Path,
        helpers: &BTreeMap<String, PathBuf>,
        release: &[String],
    ) -> Result<Self> {
        let executable = helpers
            .get("xdotool")
            .map_or_else(|| Path::new("xdotool"), PathBuf::as_path);
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", RELEASE_SCRIPT, "pi-desktop-release"])
            .arg(executable)
            .args(release)
            .current_dir(cwd)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = owner.process().spawn_checked(&mut command)?;
        let mut guard = Self {
            child: Some(child),
            stdin: None,
        };
        guard.stdin = guard.child.as_mut().and_then(|child| child.stdin.take());
        if guard.stdin.is_none() {
            return Err(error("cannot arm desktop input release guard"));
        }
        Ok(guard)
    }

    fn complete(&mut self) -> Result<()> {
        self.stdin
            .as_mut()
            .ok_or_else(|| error("desktop release guard closed early"))?
            .write_all(b"complete\n")?;
        drop(self.stdin.take());
        Ok(())
    }
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        // Closing the pipe wakes the already-authorized cleanup process even
        // when the request owner is cancelled. Do not spawn from Drop.
        drop(self.stdin.take());
        let Some(mut child) = self.child.take() else {
            return;
        };
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(None) | Err(_) => break,
            }
        }
        // Best-effort cleanup is bounded before forced process-group teardown.
        // Reaping is a foreign OS operation, not a hard real-time guarantee.
        if let Ok(pid) = i32::try_from(child.id())
            && let Some(group) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

struct InputTransaction {
    running: Option<Running>,
    release: Option<ReleaseGuard>,
}

impl Drop for InputTransaction {
    fn drop(&mut self) {
        // Stop further presses BEFORE the guardian sends releases. Relying on
        // incidental field-drop order could release a button before a live
        // input child presses it again.
        if let Some(running) = self.running.as_mut() {
            let _ = running.child.kill();
        }
        drop(self.running.take());
        drop(self.release.take());
    }
}

async fn dispatch(
    owner: &AgentCx,
    cwd: &Path,
    helpers: &BTreeMap<String, PathBuf>,
    command: &[String],
    input: &[u8],
    release: &[String],
) -> Result<()> {
    check_owner(owner)?;
    let guard = if release.is_empty() {
        None
    } else {
        Some(ReleaseGuard::arm(owner, cwd, helpers, release)?)
    };
    let mut transaction = InputTransaction {
        running: None,
        release: guard,
    };
    transaction.running = Some(process::start(
        owner, cwd, helpers, "xdotool", command, input,
    )?);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        check_owner(owner)?;
        if Instant::now() >= deadline {
            return Err(error(
                "desktop input helper timed out; side effects may already have occurred",
            ));
        }
        if let Some(status) = transaction
            .running
            .as_mut()
            .expect("owned input helper")
            .poll(4096)?
        {
            if !status.success() {
                return Err(error(format!(
                    "desktop input helper failed ({status}); releases were attempted"
                )));
            }
            if let Some(guard) = transaction.release.as_mut() {
                guard.complete()?;
            }
            return Ok(());
        }
        owner.time().sleep(Duration::from_millis(2)).await;
    }
}

struct InputCommand {
    args: Vec<String>,
    stdin: Vec<u8>,
    release: Vec<String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep each input action's command and cancellation-release operands together"
)]
fn input_command(args: &Value) -> Result<InputCommand> {
    let action = args["action"].as_str().expect("validated action");
    let mut command = InputCommand {
        args: Vec::new(),
        stdin: Vec::new(),
        release: Vec::new(),
    };
    let button = match args.get("button").and_then(Value::as_str).unwrap_or("left") {
        "left" => "1",
        "middle" => "2",
        "right" => "3",
        _ => return Err(error("unsupported mouse button")),
    };
    let coordinates = if let (Some(x), Some(y)) = (args["x"].as_i64(), args["y"].as_i64()) {
        if x < 0 || y < 0 {
            return Err(error("X11 desktop pixel coordinates must be nonnegative"));
        }
        Some((x.to_string(), y.to_string()))
    } else {
        None
    };
    match action {
        "mouse_move" | "mouse_click" => {
            if let Some((x, y)) = coordinates {
                command.args = strings(&["mousemove", "--sync", &x, &y]);
            }
            if action == "mouse_click" {
                command.args.extend(strings(&["click", button]));
                command.release = strings(&["mouseup", button]);
            }
        }
        "mouse_drag" => {
            let (x, y) = coordinates.ok_or_else(|| error("mouse_drag requires coordinates"))?;
            command.args = strings(&[
                "mousedown",
                button,
                "mousemove",
                "--sync",
                &x,
                &y,
                "mouseup",
                button,
            ]);
            command.release = strings(&["mouseup", button]);
        }
        "key_press" => {
            let chord = key(args["key"].as_str().expect("validated key"))?;
            command.args = strings(&["key", "--delay", "0", &chord]);
            command.release = strings(&["keyup", &chord]);
        }
        "key_type" => {
            let value = args["text"].as_str().expect("validated text");
            if value
                .chars()
                .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
            {
                return Err(error(
                    "typed text may contain newline/tab but no other control characters",
                ));
            }
            command.args = strings(&["type", "--delay", "1", "--clearmodifiers", "--file", "-"]);
            command.stdin = value.as_bytes().to_vec();
            // Derived keysyms, not the user's text, are passed to the cleanup
            // command. Xlib's Uxxxx notation covers non-ASCII text as well.
            let mut keys = BTreeSet::new();
            for ch in value.chars() {
                keys.insert(match ch {
                    '\n' => "Return".to_string(),
                    '\t' => "Tab".to_string(),
                    ' ' => "space".to_string(),
                    ch if ch.is_ascii_alphanumeric() => ch.to_string(),
                    ch => format!("U{:04X}", u32::from(ch)),
                });
            }
            command.release = strings(&[
                "keyup",
                "Shift_L",
                "Shift_R",
                "Control_L",
                "Control_R",
                "Alt_L",
                "Alt_R",
                "Super_L",
                "Super_R",
            ]);
            command.release.extend(keys);
        }
        "scroll" => {
            let wheel = match args
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("down")
            {
                "up" => "4",
                "down" => "5",
                "left" => "6",
                "right" => "7",
                _ => return Err(error("unsupported scroll direction")),
            };
            let amount = args
                .get("amount")
                .and_then(Value::as_u64)
                .unwrap_or(3)
                .to_string();
            command.args = strings(&["click", "--repeat", &amount, "--delay", "10", wheel]);
            command.release = strings(&["mouseup", wheel]);
        }
        "focus_window" => {
            let window = args["window_id"]
                .as_u64()
                .expect("validated window ID")
                .to_string();
            command.args = strings(&["windowactivate", "--sync", &window]);
        }
        _ => return Err(error("unsupported X11 input operation")),
    }
    Ok(command)
}

pub(super) async fn execute(
    owner: &AgentCx,
    cwd: &Path,
    helpers: &BTreeMap<String, PathBuf>,
    state: &mut State,
    args: &Value,
) -> Result<ToolOutput> {
    let action = args["action"].as_str().expect("validated action");
    if action == "clipboard_write" {
        return clipboard_write(owner, cwd, helpers, state, args).await;
    }
    let command = input_command(args)?;
    let requested_window = args
        .get("window_id")
        .and_then(Value::as_u64)
        .map(|id| u32::try_from(id).expect("validated window ID"));
    if action != "focus_window"
        && let Some(window) = requested_window
        && active_window(owner, cwd, helpers).await? != Some(window)
    {
        return Err(error(
            "target window is not focused; focus_window explicitly before sending input",
        ));
    }
    dispatch(
        owner,
        cwd,
        helpers,
        &command.args,
        &command.stdin,
        &command.release,
    )
    .await?;
    if action == "focus_window" && active_window(owner, cwd, helpers).await? != requested_window {
        return Err(error(
            "window activation did not produce the requested focus",
        ));
    }
    let position = if matches!(action, "mouse_move" | "mouse_drag") {
        let raw = query(
            owner,
            cwd,
            helpers,
            "xdotool",
            &["getmouselocation", "--shell"],
        )
        .await?;
        let position = parse_position(&raw)?;
        if args["x"].as_i64() != Some(position.0) || args["y"].as_i64() != Some(position.1) {
            return Err(error(
                "pointer did not reach the requested position; it may be constrained by the desktop",
            ));
        }
        Some(json!({"x":position.0,"y":position.1}))
    } else {
        None
    };
    Ok(output(
        format!(
            "Dispatched desktop {action} through X11; application-level effects are not inferred"
        ),
        json!({
            "action":action,"backend":"x11","window_id":requested_window,
            "x":args.get("x"),"y":args.get("y"),"position":position,
            "button":args.get("button"),"key":args.get("key"),
            "char_count":args.get("text").and_then(Value::as_str).map(|text| text.chars().count())
        }),
        false,
    ))
}

fn parse_position(raw: &str) -> Result<(i64, i64)> {
    let mut x = None;
    let mut y = None;
    for line in raw.lines() {
        if let Some((name, value)) = line.split_once('=') {
            let target = match name {
                "X" => &mut x,
                "Y" => &mut y,
                _ => continue,
            };
            if target.is_some() {
                return Err(error("duplicate pointer coordinate"));
            }
            *target = Some(
                value
                    .parse::<i64>()
                    .map_err(|_| error("invalid pointer coordinate"))?,
            );
        }
    }
    x.zip(y).ok_or_else(|| error("incomplete pointer position"))
}

async fn clipboard_write(
    owner: &AgentCx,
    cwd: &Path,
    helpers: &BTreeMap<String, PathBuf>,
    state: &mut State,
    args: &Value,
) -> Result<ToolOutput> {
    let value = args["text"].as_str().expect("validated clipboard text");
    // -quiet is the documented foreground mode. Default xclip forks, causing
    // the parent to exit and AgentChild to retire the new selection owner.
    let mut candidate = process::start(
        owner,
        cwd,
        helpers,
        "xclip",
        &strings(&[
            "-selection",
            "clipboard",
            "-in",
            "-quiet",
            "-target",
            "UTF8_STRING",
        ]),
        value.as_bytes(),
    )?;
    for _ in 0..50 {
        check_owner(owner)?;
        if candidate.poll(4096)?.is_some() {
            return Err(error(
                "clipboard selection owner exited before the write was verified",
            ));
        }
        let bytes = process::run(
            owner,
            cwd,
            helpers,
            "xclip",
            &strings(&["-selection", "clipboard", "-out", "-target", "UTF8_STRING"]),
            b"",
            64 * 1024,
        )
        .await?;
        if bytes == value.as_bytes() && candidate.poll(4096)?.is_none() {
            // Successful publication transfers the foreground service to the
            // tool, not a detached task. Replacing/dropping State reaps it.
            state.clipboard = Some(candidate);
            return Ok(output(
                format!(
                    "Copied {} characters to the X11 clipboard and verified the contents",
                    value.chars().count()
                ),
                json!({
                    "action":"clipboard_write","char_count":value.chars().count(),"backend":"x11",
                    "verified":true,"lifetime":"until replaced or this tool is dropped"
                }),
                false,
            ));
        }
        owner.time().sleep(Duration::from_millis(10)).await;
    }
    Err(error(
        "clipboard contents did not match the requested text; the desktop may have another clipboard owner",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn typed_text_is_stdin_not_a_command_or_argument() {
        let value = "$(touch escaped); exec not-a-command\n'quoted'";
        let command = input_command(&json!({"action":"key_type","text":value})).unwrap();
        assert_eq!(command.stdin, value.as_bytes());
        assert_eq!(
            command.args,
            strings(&["type", "--delay", "1", "--clearmodifiers", "--file", "-"])
        );
        assert!(
            !command
                .release
                .iter()
                .any(|arg| arg == "exec" || arg.contains("touch"))
        );
    }

    #[test]
    fn drag_and_scroll_pair_press_with_release() {
        let drag =
            input_command(&json!({"action":"mouse_drag","x":42,"y":31,"button":"right"})).unwrap();
        assert_eq!(
            drag.args,
            strings(&[
                "mousedown",
                "3",
                "mousemove",
                "--sync",
                "42",
                "31",
                "mouseup",
                "3"
            ])
        );
        assert_eq!(drag.release, strings(&["mouseup", "3"]));
        assert!(input_command(&json!({"action":"mouse_move","x":-1,"y":5})).is_err());
        let scroll =
            input_command(&json!({"action":"scroll","direction":"up","amount":5})).unwrap();
        assert_eq!(
            scroll.args,
            strings(&["click", "--repeat", "5", "--delay", "10", "4"])
        );
    }

    #[test]
    fn position_data_is_parsed_and_never_evaluated() {
        assert_eq!(
            parse_position("X=42\nY=31\nSCREEN=0\nWINDOW=17\n").unwrap(),
            (42, 31)
        );
        assert!(parse_position("X=$(touch escaped)\nY=31").is_err());
        assert!(parse_position("X=1\nX=2\nY=3").is_err());
        assert!(parse_position("X=1").is_err());
    }

    #[test]
    fn dropping_input_transaction_stops_input_then_runs_the_armed_release() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper");
        std::fs::write(&helper, "#!/bin/sh\ncase \"$1\" in\n  hold) printf started > started; exec sleep 30;;\n  mouseup) printf released > released;;\n  *) exit 7;;\nesac\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let helpers = BTreeMap::from([("xdotool".to_string(), helper)]);
        let owner = AgentCx::for_request();
        let guard =
            ReleaseGuard::arm(&owner, dir.path(), &helpers, &strings(&["mouseup", "1"])).unwrap();
        let running = process::start(
            &owner,
            dir.path(),
            &helpers,
            "xdotool",
            &strings(&["hold"]),
            b"",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !dir.path().join("started").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(dir.path().join("started").exists());
        let mut transaction = InputTransaction {
            running: Some(running),
            release: Some(guard),
        };
        owner.cancel_with(asupersync::types::CancelKind::User, Some("cancel input"));
        assert!(
            transaction
                .running
                .as_mut()
                .unwrap()
                .child
                .try_wait()
                .is_err()
        );
        drop(transaction);
        assert_eq!(
            std::fs::read(dir.path().join("released")).unwrap(),
            b"released"
        );
    }

    #[test]
    fn successful_input_disarms_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("release");
        std::fs::write(&helper, "#!/bin/sh\nprintf released > released\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let helpers = BTreeMap::from([("xdotool".to_string(), helper)]);
        let mut guard = ReleaseGuard::arm(
            &AgentCx::for_request(),
            dir.path(),
            &helpers,
            &strings(&["mouseup", "1"]),
        )
        .unwrap();
        guard.complete().unwrap();
        drop(guard);
        assert!(!dir.path().join("released").exists());
    }
}
