//! Conformance tests for session JSONL format (v3).

mod common;

use asupersync::runtime::RuntimeBuilder;
use common::TestHarness;
use pi::Error;
use pi::model::{AssistantMessage, ContentBlock, StopReason, TextContent, Usage, UserContent};
use pi::session::{
    CustomEntry, EntryBase, Session, SessionEntry, SessionHeader, SessionMessage, encode_cwd,
};
use pi::session_index::SessionIndex;
use serde_json::json;
use std::future::Future;
use std::path::Path;

fn write_session_file(harness: &TestHarness, contents: &str) -> std::path::PathBuf {
    harness.create_file("session.jsonl", contents)
}

fn run_async_test<F: Future<Output = ()>>(future: F) {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build");
    runtime.block_on(future);
}

fn make_user_message(text: &str) -> SessionMessage {
    SessionMessage::User {
        content: UserContent::Text(text.to_string()),
        timestamp: Some(0),
    }
}

fn make_assistant_message(text: &str) -> SessionMessage {
    SessionMessage::Assistant {
        message: AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new(text))],
            api: "test".to_string(),
            provider: "test".to_string(),
            model: "test".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        },
    }
}

async fn open_session(path: &Path) -> pi::PiResult<Session> {
    let path_string = path.to_string_lossy().to_string();
    Session::open(&path_string).await
}

async fn save_and_reopen(harness: &TestHarness, session: &mut Session) -> Session {
    session.save().await.expect("save session");
    let path = session.path.clone().expect("session path set");
    harness.record_artifact("session.jsonl", &path);
    open_session(&path).await.expect("reopen session")
}

fn assert_contains_entry<'a>(
    entries: &'a [SessionEntry],
    predicate: impl Fn(&'a SessionEntry) -> bool,
    description: &str,
) {
    assert!(
        entries.iter().any(predicate),
        "Expected session entries to contain {description}"
    );
}

#[test]
fn load_session_accepts_parent_session_alias_and_fills_ids() {
    run_async_test(async {
        let harness = TestHarness::new("load_session_accepts_parent_session_alias_and_fills_ids");
        let jsonl = r#"
{"type":"session","version":3,"id":"sess-123","timestamp":"2026-02-03T00:00:00.000Z","cwd":"/tmp/project","provider":"anthropic","modelId":"claude-sonnet-4-20250514","thinkingLevel":"medium","parentSession":"/tmp/parent.jsonl"}
{"type":"message","parentId":"root","timestamp":"2026-02-03T00:00:01.000Z","message":{"role":"user","content":"Hello","timestamp":1706918401000}}
{"type":"model_change","timestamp":"2026-02-03T00:00:02.000Z","provider":"anthropic","modelId":"claude-sonnet-4-20250514"}
{"type":"thinking_level_change","timestamp":"2026-02-03T00:00:03.000Z","thinkingLevel":"medium"}
{"type":"compaction","timestamp":"2026-02-03T00:00:04.000Z","summary":"compacted","firstKeptEntryId":"a1b2c3d4","tokensBefore":128}
{"type":"branch_summary","timestamp":"2026-02-03T00:00:05.000Z","fromId":"root","summary":"branch summary"}
{"type":"label","timestamp":"2026-02-03T00:00:06.000Z","targetId":"a1b2c3d4","label":"checkpoint"}
{"type":"session_info","timestamp":"2026-02-03T00:00:07.000Z","name":"demo session"}
{"type":"custom","timestamp":"2026-02-03T00:00:08.000Z","customType":"note","data":{"tag":"demo"}}
"#;

        let path = write_session_file(&harness, jsonl.trim_start());
        let session = Session::open(path.to_string_lossy().as_ref())
            .await
            .expect("open session");

        assert_eq!(
            session.header.parent_session.as_deref(),
            Some("/tmp/parent.jsonl")
        );
        assert_eq!(session.entries.len(), 8);
        assert!(
            session
                .entries
                .iter()
                .all(|entry| entry.base().id.as_ref().is_some())
        );

        let leaf = session.leaf_id.as_deref();
        let last_id = session
            .entries
            .last()
            .and_then(SessionEntry::base_id)
            .map(String::as_str);
        assert_eq!(leaf, last_id);
    });
}

#[test]
fn session_header_serializes_branched_from_field() {
    run_async_test(async {
        let _harness = TestHarness::new("session_header_serializes_branched_from_field");
        let mut session = Session::create();
        session.header.parent_session = Some("/tmp/parent.jsonl".to_string());

        let header_json = serde_json::to_string(&session.header).expect("serialize header");
        assert!(header_json.contains("\"branchedFrom\""));
        assert!(!header_json.contains("parentSession"));
    });
}

#[test]
fn open_missing_session_returns_session_not_found_error() {
    run_async_test(async {
        let harness = TestHarness::new("open_missing_session_returns_session_not_found_error");
        let missing = harness.temp_path("missing.jsonl");
        harness
            .log()
            .info("setup", "Attempting to open missing file");

        let err = open_session(&missing).await.expect_err("expected error");
        assert!(
            matches!(err, Error::SessionNotFound { .. }),
            "Expected SessionNotFound, got: {err}"
        );
    });
}

#[test]
fn open_empty_session_file_errors() {
    run_async_test(async {
        let harness = TestHarness::new("open_empty_session_file_errors");
        let path = harness.create_file("empty.jsonl", "");
        harness.record_artifact("empty.jsonl", &path);

        let err = open_session(&path).await.expect_err("expected error");
        assert!(
            matches!(err, Error::Session(_)),
            "Expected Session error, got: {err}"
        );
    });
}

#[test]
fn open_header_only_session_succeeds_with_no_entries() {
    run_async_test(async {
        let harness = TestHarness::new("open_header_only_session_succeeds_with_no_entries");
        let header = SessionHeader::new();
        let jsonl = format!(
            "{}\n",
            serde_json::to_string(&header).expect("serialize header")
        );
        let path = harness.create_file("header_only.jsonl", jsonl);
        harness.record_artifact("header_only.jsonl", &path);

        let loaded = open_session(&path).await.expect("open header-only session");
        assert!(loaded.entries.is_empty());
        assert!(loaded.leaf_id.is_none());
    });
}

#[test]
fn save_creates_path_under_override_dir() {
    run_async_test(async {
        let harness = TestHarness::new("save_creates_path_under_override_dir");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir.clone()));
        session.append_message(make_user_message("Hello"));

        session.save().await.expect("save session");
        let path = session.path.clone().expect("session path set");
        harness.record_artifact("session.jsonl", &path);

        assert!(path.exists(), "Expected session file to exist");

        let cwd = std::env::current_dir().expect("current_dir");
        let expected_prefix = base_dir.join(encode_cwd(&cwd));
        assert!(
            path.starts_with(&expected_prefix),
            "Expected session path {path:?} to start with {expected_prefix:?}"
        );
    });
}

#[test]
fn save_updates_session_index_for_override_dir() {
    run_async_test(async {
        let harness = TestHarness::new("save_updates_session_index_for_override_dir");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir.clone()));
        session.append_message(make_user_message("Hello"));

        session.save().await.expect("save session");

        let index = SessionIndex::for_sessions_root(&base_dir);
        let indexed = index
            .list_sessions(Some(&session.header.cwd))
            .expect("list sessions")
            .into_iter()
            .any(|meta| meta.id == session.header.id);

        harness.assert_log("Session saved and indexed");
        assert!(indexed, "Expected session to be indexed after save()");
    });
}

#[test]
fn save_and_open_round_trip_linear_messages_preserves_leaf_id() {
    run_async_test(async {
        let harness =
            TestHarness::new("save_and_open_round_trip_linear_messages_preserves_leaf_id");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));

        let id1 = session.append_message(make_user_message("Hello"));
        let id2 = session.append_message(make_assistant_message("Hi there!"));

        let loaded = save_and_reopen(&harness, &mut session).await;

        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.leaf_id.as_deref(), Some(id2.as_str()));

        let path = loaded.get_path_to_entry(&id2);
        assert_eq!(path, vec![id1, id2]);
    });
}

#[test]
fn save_and_open_round_trip_branching_preserves_leaves_and_branch_point() {
    run_async_test(async {
        let harness = TestHarness::new(
            "save_and_open_round_trip_branching_preserves_leaves_and_branch_point",
        );
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));

        let root = session.append_message(make_user_message("Root"));
        let leaf_a = session.append_message(make_assistant_message("Branch A"));
        assert!(session.create_branch_from(&root));
        let leaf_b = session.append_message(make_assistant_message("Branch B"));

        let loaded = save_and_reopen(&harness, &mut session).await;
        let summary = loaded.branch_summary();

        let leaves = summary
            .leaves
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            leaves,
            [leaf_a.clone(), leaf_b.clone()]
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
        );
        assert!(
            summary.branch_points.contains(&root),
            "Expected root entry to be a branch point"
        );
    });
}

#[test]
fn open_skips_corrupted_entries_and_keeps_valid_ones() {
    run_async_test(async {
        let harness = TestHarness::new("open_skips_corrupted_entries_and_keeps_valid_ones");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        session.append_message(make_user_message("Hello"));
        session.append_message(make_assistant_message("World"));

        session.save().await.expect("save session");
        let original_path = session.path.clone().expect("session path set");
        harness.record_artifact("original.jsonl", &original_path);

        let original = std::fs::read_to_string(&original_path).expect("read session");
        let mut lines: Vec<&str> = original.lines().collect();
        assert!(lines.len() >= 2);
        lines.insert(2.min(lines.len()), "{ this is not json }");

        let corrupted_path = harness.temp_path("corrupted.jsonl");
        std::fs::write(&corrupted_path, format!("{}\n", lines.join("\n")))
            .expect("write corrupted session");
        harness.record_artifact("corrupted.jsonl", &corrupted_path);

        let loaded = open_session(&corrupted_path)
            .await
            .expect("open corrupted session");
        assert_eq!(loaded.entries.len(), session.entries.len());
    });
}

#[test]
fn save_round_trips_model_change_entry() {
    run_async_test(async {
        let harness = TestHarness::new("save_round_trips_model_change_entry");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        session.append_message(make_user_message("Hello"));
        session.append_model_change("anthropic".to_string(), "claude-test".to_string());

        let loaded = save_and_reopen(&harness, &mut session).await;
        assert_contains_entry(
            &loaded.entries,
            |entry| matches!(entry, SessionEntry::ModelChange(change) if change.provider == "anthropic" && change.model_id == "claude-test"),
            "ModelChange(provider=anthropic, model_id=claude-test)",
        );
    });
}

#[test]
fn save_round_trips_thinking_level_change_entry() {
    run_async_test(async {
        let harness = TestHarness::new("save_round_trips_thinking_level_change_entry");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        session.append_message(make_user_message("Hello"));
        session.append_thinking_level_change("high".to_string());

        let loaded = save_and_reopen(&harness, &mut session).await;
        assert_contains_entry(
            &loaded.entries,
            |entry| {
                matches!(
                    entry,
                    SessionEntry::ThinkingLevelChange(change) if change.thinking_level == "high"
                )
            },
            "ThinkingLevelChange(thinking_level=high)",
        );
    });
}

#[test]
fn save_round_trips_session_info_entry() {
    run_async_test(async {
        let harness = TestHarness::new("save_round_trips_session_info_entry");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        session.append_message(make_user_message("Hello"));
        session.append_session_info(Some("demo session".to_string()));

        let loaded = save_and_reopen(&harness, &mut session).await;
        assert_contains_entry(
            &loaded.entries,
            |entry| matches!(entry, SessionEntry::SessionInfo(info) if info.name.as_deref() == Some("demo session")),
            "SessionInfo(name=demo session)",
        );
    });
}

#[test]
fn save_round_trips_label_entry() {
    run_async_test(async {
        let harness = TestHarness::new("save_round_trips_label_entry");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        let target_id = session.append_message(make_user_message("Hello"));
        let label_id = session
            .add_label(&target_id, Some("checkpoint".to_string()))
            .expect("label created");

        let loaded = save_and_reopen(&harness, &mut session).await;
        assert_contains_entry(
            &loaded.entries,
            |entry| {
                matches!(
                    entry,
                    SessionEntry::Label(label) if label.base.id.as_deref() == Some(label_id.as_str())
                        && label.target_id == target_id
                        && label.label.as_deref() == Some("checkpoint")
                )
            },
            "Label(target_id=..., label=checkpoint)",
        );
    });
}

#[test]
fn save_round_trips_compaction_entry() {
    run_async_test(async {
        let harness = TestHarness::new("save_round_trips_compaction_entry");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        let first = session.append_message(make_user_message("Hello"));
        let keep = session.append_message(make_user_message("Keep me"));
        session.append_message(make_assistant_message("Ignore me"));
        session.append_compaction(
            "compacted".to_string(),
            keep.clone(),
            128,
            Some(json!({"from":"test"})),
            Some(false),
        );

        let loaded = save_and_reopen(&harness, &mut session).await;
        assert_contains_entry(
            &loaded.entries,
            |entry| {
                matches!(
                    entry,
                    SessionEntry::Compaction(compaction)
                        if compaction.summary == "compacted"
                            && compaction.first_kept_entry_id == keep
                            && compaction.tokens_before == 128
                            && compaction.details.as_ref().is_some_and(|v| v.get("from").and_then(|v| v.as_str()) == Some("test"))
                            && compaction.from_hook == Some(false)
                )
            },
            "Compaction(summary=compacted, firstKeptEntryId=..., tokensBefore=128)",
        );

        // Sanity: first entry remains in history, even if omitted from current path context.
        assert_contains_entry(
            &loaded.entries,
            |entry| entry.base().id.as_deref() == Some(first.as_str()),
            "first message entry id",
        );
    });
}

#[test]
fn save_round_trips_branch_summary_entry() {
    run_async_test(async {
        let harness = TestHarness::new("save_round_trips_branch_summary_entry");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        let root = session.append_message(make_user_message("Hello"));
        session.append_branch_summary(root.clone(), "branch summary".to_string(), None, None);

        let loaded = save_and_reopen(&harness, &mut session).await;
        assert_contains_entry(
            &loaded.entries,
            |entry| {
                matches!(
                    entry,
                    SessionEntry::BranchSummary(summary)
                        if summary.from_id == root && summary.summary == "branch summary"
                )
            },
            "BranchSummary(from_id=..., summary=branch summary)",
        );
    });
}

#[test]
fn save_round_trips_custom_entry() {
    run_async_test(async {
        let harness = TestHarness::new("save_round_trips_custom_entry");
        let base_dir = harness.temp_path("sessions");
        let mut session = Session::create_with_dir(Some(base_dir));
        session.append_message(make_user_message("Hello"));

        let custom_id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        let base = EntryBase::new(session.leaf_id.clone(), custom_id.clone());
        session.entries.push(SessionEntry::Custom(CustomEntry {
            base,
            custom_type: "note".to_string(),
            data: Some(json!({"tag":"demo"})),
        }));
        session.leaf_id = Some(custom_id.clone());

        let loaded = save_and_reopen(&harness, &mut session).await;
        assert_contains_entry(
            &loaded.entries,
            |entry| {
                matches!(
                    entry,
                    SessionEntry::Custom(custom)
                        if custom.custom_type == "note"
                            && custom.data.as_ref().is_some_and(|v| v.get("tag").and_then(|v| v.as_str()) == Some("demo"))
                )
            },
            "Custom(customType=note, data.tag=demo)",
        );
    });
}

#[test]
fn concurrent_saves_do_not_corrupt_session_file() {
    let harness = TestHarness::new("concurrent_saves_do_not_corrupt_session_file");
    let base_dir = harness.temp_path("sessions");

    let mut session = Session::create_with_dir(Some(base_dir));
    session.append_message(make_user_message("Hello"));

    run_async_test(async {
        session.save().await.expect("initial save");
    });
    let path = session.path.clone().expect("session path set");
    harness.record_artifact("session.jsonl", &path);

    let path1 = path.clone();
    let path2 = path.clone();

    let t1 = std::thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        runtime.block_on(async move {
            let mut s = Session::open(path1.to_string_lossy().as_ref())
                .await
                .expect("open session");
            s.append_message(make_user_message("From thread 1"));
            s.save().await
        })
    });

    let t2 = std::thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        runtime.block_on(async move {
            let mut s = Session::open(path2.to_string_lossy().as_ref())
                .await
                .expect("open session");
            s.append_message(make_user_message("From thread 2"));
            s.save().await
        })
    });

    let r1 = t1.join().expect("thread 1 join");
    let r2 = t2.join().expect("thread 2 join");

    assert!(
        r1.is_ok() || r2.is_ok(),
        "Expected at least one save to succeed: r1={r1:?} r2={r2:?}"
    );

    run_async_test(async {
        let loaded = Session::open(path.to_string_lossy().as_ref())
            .await
            .expect("open after concurrent saves");
        assert!(!loaded.entries.is_empty());
    });
}
