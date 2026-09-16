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
