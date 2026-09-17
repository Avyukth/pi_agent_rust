//! Subprocess-level regressions for the native parent/child boundary.

#![cfg(unix)]

use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use tempfile::TempDir;

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn emit(events: &[Value]) -> String {
    events.iter().map(|event| format!("printf '%s\\n' {}\n", quote(&event.to_string()))).collect()
}

fn assistant(text: &str, reason: &str) -> Value {
    json!({"role":"assistant","stopReason":reason,"content":[{"type":"text","text":text}]})
}

fn ended(text: &str, reason: &str) -> Value {
    json!({"type":"agent_end","messages":[assistant(text, reason)]})
}

fn fixture(script: &str) -> (TempDir, SubagentTool) {
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global");
    std::fs::create_dir_all(global.join("agents")).unwrap();
    std::fs::write(global.join("agents/worker.md"), "---\nname: worker\ndescription: protocol fixture\n---\nComplete the task.").unwrap();
    let child = dir.path().join("child.sh");
    std::fs::write(&child, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
    let tool = SubagentTool::with_paths(dir.path().to_path_buf(), global, child);
    (dir, tool)
}

fn run(tool: &SubagentTool, input: Value) -> ToolOutput {
    asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap()
        .block_on(tool.execute("protocol-test", input, None)).unwrap()
}

fn request() -> Value { json!({"agent":"worker","task":"produce a result"}) }

fn result(output: &ToolOutput) -> &Value { &output.details.as_ref().unwrap()["results"][0] }

#[test]
fn zero_exit_without_an_agent_completion_is_a_failed_delegation() {
    let (_dir, tool) = fixture("exit 0");
    let output = run(&tool, request());
    assert!(output.is_error);
    assert_eq!(result(&output)["status"], "failed");
    assert_eq!(result(&output)["exitCode"], 0);
    assert!(result(&output)["error"].as_str().unwrap().contains("PI_SUBAGENT_INCOMPLETE"));
}

#[test]
fn completed_message_without_agent_end_is_not_success() {
    let (_dir, tool) = fixture(&emit(&[json!({"type":"message_end","message":assistant("partial run", "stop")})]));
    let output = run(&tool, request());
    assert!(output.is_error);
    assert_eq!(result(&output)["status"], "failed");
}

#[test]
fn malformed_stdout_does_not_become_an_ignored_diagnostic() {
    let (_dir, tool) = fixture("printf '%s\\n' 'not-json-secret-content'\nexit 0");
    let output = run(&tool, request());
    assert!(output.is_error);
    let encoded = serde_json::to_string(&output).unwrap();
    assert!(encoded.contains("PI_SUBAGENT_PROTOCOL"));
    assert!(!encoded.contains("not-json-secret-content"));
}

#[test]
fn final_snapshot_replaces_streaming_preview_and_excludes_reasoning() {
    let final_message = json!({"role":"assistant","stopReason":"stop","content":[
        {"type":"text","text":"final "}, {"type":"thinking","thinking":"private-thought"},
        {"type":"text","text":"answer"}
    ]});
    let events = [
        json!({"type":"message_start","message":{"role":"assistant"}}),
        json!({"type":"message_update","assistantMessageEvent":{"type":"thinking_delta","delta":"private-thought"}}),
        json!({"type":"message_update","assistantMessageEvent":{"type":"toolcall_delta","delta":"private-arguments"}}),
        json!({"type":"message_update","assistantMessageEvent":{"type":"text_delta","delta":"preview"}}),
        json!({"type":"message_end","message":final_message}),
        json!({"type":"agent_end","messages":[final_message]}),
    ];
    let (_dir, tool) = fixture(&emit(&events));
    let updates = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&updates);
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
    let output = runtime.block_on(tool.execute("preview", request(), Some(Box::new(move |update| {
        captured.lock().unwrap().push(serde_json::to_string(&update).unwrap());
    })))).unwrap();
    assert!(!output.is_error, "{output:?}");
    assert_eq!(result(&output)["output"], "final answer");
    for update in updates.lock().unwrap().iter() {
        assert!(!update.contains("private-thought"));
        assert!(!update.contains("private-arguments"));
    }
}

#[test]
fn zero_exit_never_overrides_an_unsuccessful_terminal_reason() {
    for reason in ["error", "aborted", "refusal", "length", "toolUse", "pauseTurn"] {
        let (_dir, tool) = fixture(&emit(&[ended("partial result", reason)]));
        let output = run(&tool, request());
        assert!(output.is_error, "{reason}: {output:?}");
        assert_eq!(result(&output)["status"], "failed");
    }
}

#[test]
fn agent_end_error_is_not_hidden_by_a_successful_assistant_snapshot() {
    let mut event = ended("looks complete", "stop");
    event["error"] = json!("secret provider diagnostic");
    let (_dir, tool) = fixture(&emit(&[event]));
    let output = run(&tool, request());
    assert!(output.is_error);
    assert!(!serde_json::to_string(&output).unwrap().contains("secret provider diagnostic"));
}

#[test]
fn nonzero_process_exit_is_failure_even_after_a_valid_agent_end() {
    let (_dir, tool) = fixture(&format!("{}exit 7\n", emit(&[ended("answer", "stop")])));
    let output = run(&tool, request());
    assert!(output.is_error);
    assert_eq!(result(&output)["exitCode"], 7);
    assert_eq!(result(&output)["status"], "failed");
}

#[test]
fn failed_first_chain_step_never_launches_the_next_assignment() {
    let (_dir, tool) = fixture("printf 'launched\\n' >> launches\nexit 0");
    let output = run(&tool, json!({"chain":[
        {"agent":"worker","task":"first"}, {"agent":"worker","task":"second"}
    ]}));
    assert!(output.is_error);
    assert_eq!(output.details.as_ref().unwrap()["results"].as_array().unwrap().len(), 1);
    assert_eq!(std::fs::read_to_string(tool.cwd.join("launches")).unwrap(), "launched\n");
}

#[test]
fn failed_corrective_retry_is_not_replaced_with_earlier_permissive_success() {
    let script = format!("if [ -f phase ]; then\n exit 9\nelse\n : > phase\n{}fi\n", emit(&[ended("not JSON", "stop")]));
    let (_dir, tool) = fixture(&script);
    let mut input = request();
    input["outputSchema"] = json!({"type":"object"});
    input["schemaMode"] = json!("permissive");
    let output = run(&tool, input);
    assert!(output.is_error, "retry failure must win: {output:?}");
    assert_eq!(result(&output)["status"], "failed");
    assert_eq!(result(&output)["exitCode"], 9);
    assert_eq!(result(&output)["schemaRetries"], 1);
    assert_eq!(result(&output)["schemaValid"], false);
    assert!(result(&output).get("data").is_none());
}

#[test]
fn public_tool_rejects_a_truncated_answer_instead_of_schema_validating_its_prefix() {
    let (_dir, tool) = fixture(&emit(&[ended(&"x".repeat(MAX_CHILD_OUTPUT_BYTES + 1), "stop")]));
    let output = run(&tool, request());
    assert!(output.is_error);
    assert!(result(&output)["error"].as_str().unwrap().contains("PI_SUBAGENT_OUTPUT_LIMIT"));
    assert!(result(&output)["output"].as_str().unwrap().len() <= MAX_CHILD_OUTPUT_BYTES);
}

#[test]
fn dropping_a_running_delegation_settles_its_hub_entry_as_cancelled() {
    let (_dir, tool) = fixture("exec sleep 30");
    let (tx, rx) = futures::channel::oneshot::channel();
    let sender = Mutex::new(Some(tx));
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
    let child_id = runtime.block_on(async {
        let future = Box::pin(tool.execute("cancel", request(), Some(Box::new(move |update| {
            if update.details.as_ref().is_some_and(|value| value["result"]["status"] == "running")
                && let Some(tx) = sender.lock().unwrap().take()
            {
                let pid = update.details.as_ref().unwrap()["result"]["pid"].as_u64().unwrap();
                let _ = tx.send(pid);
            }
        }))));
        match futures::future::select(future, rx).await {
            futures::future::Either::Right((Ok(pid), pending)) => { drop(pending); pid }
            _ => panic!("child should reach running before completing"),
        }
    });
    let entry = crate::agent_hub::registry().lock().unwrap().roster().into_iter()
        .find(|entry| entry.pid.map(u64::from) == Some(child_id)).unwrap();
    assert_eq!(entry.status, crate::agent_hub::ChildStatus::Cancelled);
}

fn initialize_git(root: &Path) {
    for args in [
        vec!["init", "--quiet"],
        vec!["config", "user.name", "Pi Test"],
        vec!["config", "user.email", "pi-test@example.invalid"],
        vec!["config", "commit.gpgSign", "false"],
    ] {
        assert!(Command::new("git").args(args).current_dir(root).status().unwrap().success());
    }
    std::fs::write(root.join("tracked.txt"), "original\n").unwrap();
    assert!(Command::new("git").args(["add", "tracked.txt"]).current_dir(root).status().unwrap().success());
    assert!(Command::new("git").args(["commit", "--quiet", "-m", "fixture"]).current_dir(root).status().unwrap().success());
}

#[test]
fn unsuccessful_child_protocol_never_applies_worktree_edits() {
    let (_dir, tool) = fixture(&format!("printf 'unsafe edit\\n' > tracked.txt\n{}", emit(&[ended("truncated", "length")])));
    initialize_git(&tool.cwd);
    let output = run(&tool, json!({"tasks":[{"agent":"worker","task":"change file","isolation":"worktree","isoApply":"apply"}]}));
    assert!(output.is_error);
    assert_eq!(std::fs::read_to_string(tool.cwd.join("tracked.txt")).unwrap(), "original\n");
    assert_eq!(result(&output)["iso"]["applyMode"], "keep");
    assert_eq!(result(&output)["iso"]["applied"], false);
}

#[test]
fn invalid_typed_output_keeps_worktree_edits_even_in_permissive_mode() {
    let (_dir, tool) = fixture(&format!("printf 'unsafe edit\\n' > tracked.txt\n{}", emit(&[ended("not JSON", "stop")])));
    initialize_git(&tool.cwd);
    let output = run(&tool, json!({"tasks":[{
        "agent":"worker","task":"change file","isolation":"worktree","isoApply":"apply",
        "outputSchema":{"type":"object"},"schemaMode":"permissive"
    }]}));
    assert!(!output.is_error, "permissive schema exhaustion remains an explicit warning: {output:?}");
    assert_eq!(result(&output)["schemaValid"], false);
    assert_eq!(result(&output)["iso"]["applyMode"], "keep");
    assert_eq!(result(&output)["iso"]["applied"], false);
    assert_eq!(std::fs::read_to_string(tool.cwd.join("tracked.txt")).unwrap(), "original\n");
}

#[test]
fn valid_corrective_retry_applies_only_accepted_edits() {
    // Retry state must not become part of either workspace snapshot.
    let retry_state = tempfile::tempdir().unwrap();
    let marker = quote(retry_state.path().join("attempted").to_str().unwrap());
    let script = format!(
        "if [ -f {marker} ]; then\n\
         test \"$(cat tracked.txt)\" = original || exit 8\n\
         test ! -e rejected.txt || exit 8\n\
         printf 'accepted\\n' > tracked.txt\n\
         {}\
         else\n\
         : > {marker}\n\
         printf 'rejected\\n' > tracked.txt\n\
         printf 'first-only\\n' > rejected.txt\n\
         {}\
         fi\n",
        emit(&[ended(r#"{"accepted":true}"#, "stop")]),
        emit(&[ended("not JSON", "stop")]),
    );
    let (_dir, tool) = fixture(&script);
    initialize_git(&tool.cwd);
    let output = run(&tool, json!({"tasks":[{
        "agent":"worker","task":"produce an accepted change",
        "isolation":"worktree","isoApply":"apply","schemaMode":"strict",
        "outputSchema":{
            "type":"object","required":["accepted"],
            "properties":{"accepted":{"type":"boolean"}}
        }
    }]}));
    assert!(!output.is_error, "{output:?}");
    let result = result(&output);
    assert_eq!(result["task"], "produce an accepted change");
    assert_eq!(result["schemaValid"], true);
    assert_eq!(result["schemaRetries"], 1);
    assert_eq!(result["data"]["accepted"], true);
    assert_eq!(result["iso"]["applied"], true);
    assert_eq!(std::fs::read_to_string(tool.cwd.join("tracked.txt")).unwrap(), "accepted\n");
    assert!(!tool.cwd.join("rejected.txt").exists());
    let preserved = result["preservedWorktrees"].as_array().unwrap();
    assert_eq!(preserved.len(), 1);
    assert_eq!(preserved[0]["applyMode"], "keep");
    assert_eq!(preserved[0]["applied"], false);
    let path = Path::new(preserved[0]["worktreePath"].as_str().unwrap());
    assert_eq!(std::fs::read_to_string(path.join("tracked.txt")).unwrap(), "rejected\n");
    assert_eq!(std::fs::read_to_string(path.join("rejected.txt")).unwrap(), "first-only\n");
}

#[test]
fn apply_conflict_marks_result_and_hub_failed() {
    let (_dir, tool) = fixture("");
    initialize_git(&tool.cwd);
    let parent_file = quote(tool.cwd.join("tracked.txt").to_str().unwrap());
    // The absolute parent write represents an independent editor changing the
    // original checkout while the child changes its isolated copy.
    let script = format!(
        "#!/bin/sh\nprintf 'child change\\n' > tracked.txt\n\
         printf 'concurrent parent change\\n' > {parent_file}\n{}",
        emit(&[ended("completed child edit", "stop")]),
    );
    std::fs::write(&tool.child_binary, script).unwrap();
    let statuses = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&statuses);
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
    let output = runtime.block_on(tool.execute(
        "conflict",
        json!({"tasks":[{
            "agent":"worker","task":"change file","isolation":"worktree","isoApply":"apply"
        }]}),
        Some(Box::new(move |update| {
            if let Some(status) = update.details.as_ref()
                .and_then(|value| value["result"]["status"].as_str())
            {
                captured.lock().unwrap().push(status.to_string());
            }
        })),
    )).unwrap();
    assert!(output.is_error, "{output:?}");
    assert_eq!(result(&output)["status"], "failed");
    assert_eq!(result(&output)["iso"]["applied"], false);
    assert!(result(&output)["error"].as_str().unwrap().contains("PI_ISO_CONFLICT"));
    assert_eq!(std::fs::read_to_string(tool.cwd.join("tracked.txt")).unwrap(), "concurrent parent change\n");
    let pid = result(&output)["pid"].as_u64().unwrap();
    let entry = crate::agent_hub::registry().lock().unwrap().roster().into_iter()
        .find(|entry| entry.pid.map(u64::from) == Some(pid)).unwrap();
    assert_eq!(entry.status, crate::agent_hub::ChildStatus::Failed);
    let statuses = statuses.lock().unwrap();
    assert_eq!(statuses.last().map(String::as_str), Some("failed"));
    assert!(!statuses.iter().any(|status| status == "completed"));
}

#[test]
fn invalid_isolation_settings_do_not_launch() {
    let (_dir, tool) = fixture(&format!(
        "printf 'launched\\n' > launched\n{}", emit(&[ended("answer", "stop")]),
    ));
    for (isolation, apply) in [("worktre", "apply"), ("worktree", "aply")] {
        let output = run(&tool, json!({"tasks":[{
            "agent":"worker","task":"must not launch","isolation":isolation,"isoApply":apply
        }]}));
        assert!(output.is_error, "{output:?}");
        assert_eq!(result(&output)["status"], "failed");
        assert!(result(&output)["pid"].is_null());
        assert!(!tool.cwd.join("launched").exists());
    }
}

#[test]
fn descendants_holding_pipes_are_stopped_after_root_exit() {
    let (_dir, tool) = fixture(&format!(
        "sleep 30 &\n{}exit 0\n", emit(&[ended("answer", "stop")]),
    ));
    // Without process-group cleanup the background sleep retains the pipes,
    // and the explicit pipe-drain deadline makes this a failed delegation.
    let output = run(&tool, request());
    assert!(!output.is_error, "{output:?}");
    assert_eq!(result(&output)["status"], "completed");
    assert_eq!(result(&output)["output"], "answer");
}

#[test]
fn oversized_frame_fails_without_waiting_for_newline() {
    let (_dir, tool) = fixture("cat oversized-frame\nsleep 30");
    std::fs::write(
        tool.cwd.join("oversized-frame"),
        vec![b'x'; protocol::MAX_FRAME_BYTES + 1],
    ).unwrap();
    let output = run(&tool, request());
    assert!(output.is_error, "{output:?}");
    assert!(result(&output)["error"].as_str().unwrap().contains("PI_SUBAGENT_FRAME_LIMIT"));
    assert!(result(&output)["output"].as_str().unwrap().is_empty());
}

#[test]
fn starting_callback_cancellation_prevents_spawn() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_dir, tool) = fixture(&format!(
        "printf 'launched\\n' > launched\n{}", emit(&[ended("answer", "stop")]),
    ));
    let owner = crate::agent_cx::AgentCx::for_request();
    let cancel_owner = owner.clone();
    let started = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&started);
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
    let output = runtime.block_on(async {
        let future = tool.execute("pre-spawn-cancel", request(), Some(Box::new(move |update| {
            if update.details.as_ref().is_some_and(|value| value["result"]["status"] == "starting") {
                observed.store(true, Ordering::SeqCst);
                cancel_owner.cancel_with(asupersync::types::CancelKind::User, Some("fixture cancellation"));
            }
        })));
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|task_cx| {
            let _guard = owner.cx().clone().set_current_restricted();
            std::future::Future::poll(future.as_mut(), task_cx)
        }).await
    }).unwrap();
    assert!(started.load(Ordering::SeqCst), "the Starting callback must actually run");
    assert!(output.is_error);
    assert_eq!(result(&output)["status"], "cancelled");
    assert!(result(&output)["pid"].is_null());
    assert!(!tool.cwd.join("launched").exists());
}
