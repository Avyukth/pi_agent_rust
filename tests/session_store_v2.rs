#![forbid(unsafe_code)]

use pi::PiResult;
use pi::session_store_v2::{MigrationEvent, MigrationVerification, SessionStoreV2};
use serde_json::{Value, json};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::tempdir;

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn append_linear_entries(store: &mut SessionStoreV2, count: usize) -> PiResult<Vec<String>> {
    let mut ids = Vec::with_capacity(count);
    let mut parent: Option<String> = None;
    for n in 1..=count {
        let id = format!("entry_{n:08}");
        store.append_entry(
            id.clone(),
            parent.clone(),
            "message",
            json!({"kind":"message","ordinal":n}),
        )?;
        parent = Some(id.clone());
        ids.push(id);
    }
    Ok(ids)
}

fn frame_ids(frames: &[pi::session_store_v2::SegmentFrame]) -> Vec<String> {
    frames.iter().map(|frame| frame.entry_id.clone()).collect()
}

fn read_index_json_rows(path: &Path) -> PiResult<Vec<Value>> {
    let content = fs::read_to_string(path)?;
    let mut rows = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str::<Value>(line)?);
    }
    Ok(rows)
}

fn write_index_json_rows(path: &Path, rows: &[Value]) -> PiResult<()> {
    let mut output = String::new();
    for row in rows {
        output.push_str(&serde_json::to_string(row)?);
        output.push('\n');
    }
    fs::write(path, output)?;
    Ok(())
}

#[test]
fn segmented_append_and_index_round_trip() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    store.append_entry(
        "entry_00000001",
        None,
        "message",
        json!({"role":"user","text":"a"}),
    )?;
    store.append_entry(
        "entry_00000002",
        Some("entry_00000001".to_string()),
        "message",
        json!({"role":"assistant","text":"b"}),
    )?;

    let index = store.read_index()?;
    assert_eq!(index.len(), 2);
    assert_eq!(index[0].entry_seq, 1);
    assert_eq!(index[1].entry_seq, 2);

    let segment_one = store.read_segment(1)?;
    assert_eq!(segment_one.len(), 2);
    assert_eq!(segment_one[0].entry_id, "entry_00000001");
    assert_eq!(segment_one[1].entry_id, "entry_00000002");

    store.validate_integrity()?;
    Ok(())
}

#[test]
fn rotates_segment_when_threshold_is_hit() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 220)?;
    let payload = json!({
        "kind": "message",
        "text": "x".repeat(180)
    });

    store.append_entry("entry_00000001", None, "message", payload.clone())?;
    store.append_entry("entry_00000002", None, "message", payload)?;

    let index = store.read_index()?;
    assert_eq!(index.len(), 2);
    assert!(index[1].segment_seq > index[0].segment_seq);
    Ok(())
}

#[test]
fn append_path_preserves_prior_bytes_prefix() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    let first = store.append_entry(
        "entry_00000001",
        None,
        "message",
        json!({"kind":"message","text":"first"}),
    )?;
    let first_segment = store.segment_file_path(first.segment_seq);
    let before = fs::read(&first_segment)?;

    store.append_entry(
        "entry_00000002",
        Some("entry_00000001".to_string()),
        "message",
        json!({"kind":"message","text":"second"}),
    )?;
    let after = fs::read(&first_segment)?;

    assert!(
        after.starts_with(&before),
        "append should preserve existing segment prefix bytes"
    );
    Ok(())
}

#[test]
fn corruption_is_detected_from_indexed_checksum() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    let row = store.append_entry("entry_00000001", None, "message", json!({"text":"hello"}))?;
    let segment_path = store.segment_file_path(row.segment_seq);

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&segment_path)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(b"[")?;
    file.flush()?;

    let err = store
        .validate_integrity()
        .expect_err("checksum mismatch should be detected");
    assert!(
        err.to_string().contains("checksum mismatch"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test]
fn bootstrap_fails_if_index_points_to_missing_segment() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    let row = store.append_entry("entry_00000001", None, "message", json!({"text":"hello"}))?;

    let segment_path = store.segment_file_path(row.segment_seq);
    fs::remove_file(&segment_path)?;

    let err = SessionStoreV2::create(dir.path(), 4 * 1024)
        .expect_err("bootstrap should fail when active segment is missing");
    assert!(
        err.to_string().contains("failed to stat active segment"),
        "unexpected error: {err}"
    );
    Ok(())
}

// ── O(index+tail) resume path tests ──────────────────────────────────

use pi::session::{CustomEntry, EntryBase, SessionEntry, SessionInfoEntry};
use pi::session_store_v2::{frame_to_session_entry, session_entry_to_frame_args};

/// Helper: build a `SessionEntry::Custom` with the given id and parent.
fn make_custom_entry(id: &str, parent_id: Option<&str>) -> SessionEntry {
    SessionEntry::Custom(CustomEntry {
        base: EntryBase::new(parent_id.map(String::from), id.to_string()),
        custom_type: "test".to_string(),
        data: Some(json!({"id": id})),
    })
}

/// Helper: build a `SessionEntry::SessionInfo` with an optional name.
fn make_session_info_entry(id: &str, parent_id: Option<&str>, name: Option<&str>) -> SessionEntry {
    SessionEntry::SessionInfo(SessionInfoEntry {
        base: EntryBase::new(parent_id.map(String::from), id.to_string()),
        name: name.map(String::from),
    })
}

/// Append a `SessionEntry` to a V2 store via the conversion helpers.
fn append_session_entry(
    store: &mut SessionStoreV2,
    entry: &SessionEntry,
) -> PiResult<pi::session_store_v2::OffsetIndexEntry> {
    let (entry_id, parent_id, entry_type, payload) = session_entry_to_frame_args(entry)?;
    Ok(store.append_entry(entry_id, parent_id, entry_type, payload)?)
}

#[test]
fn read_tail_entries_returns_last_n() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    let ids = append_linear_entries(&mut store, 5)?;

    let tail = store.read_tail_entries(2)?;
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0].entry_id, ids[3]);
    assert_eq!(tail[1].entry_id, ids[4]);

    // Requesting more than available returns all.
    let all = store.read_tail_entries(100)?;
    assert_eq!(all.len(), 5);
    assert_eq!(frame_ids(&all), ids);

    // Zero returns empty.
    let zero = store.read_tail_entries(0)?;
    assert!(zero.is_empty());

    Ok(())
}

#[test]
fn read_active_path_linear_returns_all() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    let ids = append_linear_entries(&mut store, 5)?;

    let path = store.read_active_path(&ids[4])?;
    assert_eq!(frame_ids(&path), ids);
    Ok(())
}

#[test]
fn read_active_path_branching_returns_only_branch() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    // Build a tree:
    //   A → B → C (main branch)
    //        ↘ D → E (side branch)
    store.append_entry("A", None, "message", json!({"v":"A"}))?;
    store.append_entry("B", Some("A".to_string()), "message", json!({"v":"B"}))?;
    store.append_entry("C", Some("B".to_string()), "message", json!({"v":"C"}))?;
    store.append_entry("D", Some("B".to_string()), "message", json!({"v":"D"}))?;
    store.append_entry("E", Some("D".to_string()), "message", json!({"v":"E"}))?;

    // Active path from leaf E: E→D→B→A, reversed to A→B→D→E.
    let path = store.read_active_path("E")?;
    assert_eq!(frame_ids(&path), vec!["A", "B", "D", "E"]);

    // Active path from leaf C: C→B→A, reversed to A→B→C.
    let path = store.read_active_path("C")?;
    assert_eq!(frame_ids(&path), vec!["A", "B", "C"]);

    // Unknown leaf returns empty.
    let path = store.read_active_path("UNKNOWN")?;
    assert!(path.is_empty());

    Ok(())
}

#[test]
fn frame_to_session_entry_roundtrip() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    let entry = make_custom_entry("e1", None);
    append_session_entry(&mut store, &entry)?;

    let frames = store.read_all_entries()?;
    assert_eq!(frames.len(), 1);

    let recovered = frame_to_session_entry(&frames[0])?;
    assert_eq!(recovered.base_id(), entry.base_id());
    assert_eq!(recovered.base().parent_id, entry.base().parent_id);

    // Verify the payload round-trips correctly.
    let original_json = serde_json::to_value(&entry)?;
    let recovered_json = serde_json::to_value(&recovered)?;
    assert_eq!(original_json, recovered_json);

    Ok(())
}

#[test]
fn session_entry_to_frame_args_preserves_fields() -> PiResult<()> {
    let entry = make_custom_entry("my_id", Some("parent_id"));
    let (entry_id, parent_id, entry_type, payload) = session_entry_to_frame_args(&entry)?;

    assert_eq!(entry_id, "my_id");
    assert_eq!(parent_id.as_deref(), Some("parent_id"));
    assert_eq!(entry_type, "custom");
    assert!(payload.is_object());
    assert_eq!(payload["type"], "custom");

    // Entry without ID should fail.
    let mut no_id = make_custom_entry("x", None);
    no_id.base_mut().id = None;
    let err = session_entry_to_frame_args(&no_id);
    assert!(err.is_err());

    Ok(())
}

#[test]
fn read_tail_entries_on_1000_entry_store_reads_only_10_frames() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 64 * 1024 * 1024)?;
    let ids = append_linear_entries(&mut store, 1000)?;

    let tail = store.read_tail_entries(10)?;
    assert_eq!(tail.len(), 10);
    assert_eq!(frame_ids(&tail), ids[990..].to_vec());

    // Verify the frames are in entry_seq order.
    for window in tail.windows(2) {
        assert!(
            window[0].entry_seq < window[1].entry_seq,
            "tail entries must be in entry_seq order"
        );
    }

    Ok(())
}

#[test]
fn seeded_randomized_append_replay_invariants() -> PiResult<()> {
    const SEEDS: [u64; 6] = [
        0x00C0_FFEE_D15E_A5E5,
        0x0000_0000_DEAD_BEEF,
        0x0000_0000_1234_5678,
        0x0000_0000_0BAD_F00D,
        0x0000_0000_5EED_CAFE,
        0x0000_0000_A11C_EBAD,
    ];

    for seed in SEEDS {
        let dir = tempdir()?;
        let artifact_hint = dir.path().display().to_string();
        let mut state = seed;
        let max_segment_bytes = 320 + (lcg_next(&mut state) % 640);
        let mut store = SessionStoreV2::create(dir.path(), max_segment_bytes)?;

        let entry_count = 24 + usize::try_from(lcg_next(&mut state) % 32).unwrap_or(0);
        let mut expected_ids: Vec<String> = Vec::with_capacity(entry_count);
        for idx in 0..entry_count {
            let entry_id = format!("entry_{:08}", idx + 1);
            let parent_entry_id = if idx == 0 {
                None
            } else if lcg_next(&mut state) % 5 == 0 {
                let parent_index = usize::try_from(lcg_next(&mut state)).unwrap_or(0) % idx;
                Some(expected_ids[parent_index].clone())
            } else {
                Some(expected_ids[idx - 1].clone())
            };
            let entropy = lcg_next(&mut state);
            let payload = json!({
                "seed": format!("{seed:016x}"),
                "index": idx,
                "entropy": entropy,
                "parentHint": parent_entry_id,
            });

            let row = store.append_entry(
                entry_id.clone(),
                parent_entry_id.clone(),
                "message",
                payload,
            )?;
            assert_eq!(
                row.entry_seq,
                u64::try_from(idx + 1).unwrap_or(u64::MAX),
                "seed={seed:016x} artifact={artifact_hint}"
            );
            expected_ids.push(entry_id);
        }

        let integrity = store.validate_integrity();
        assert!(
            integrity.is_ok(),
            "seed={seed:016x} artifact={artifact_hint} err={}",
            integrity
                .err()
                .map_or_else(String::new, |err| err.to_string())
        );

        let index = store.read_index()?;
        assert_eq!(
            index.len(),
            entry_count,
            "seed={seed:016x} artifact={artifact_hint}"
        );
        for (idx, row) in index.iter().enumerate() {
            assert_eq!(
                row.entry_seq,
                u64::try_from(idx + 1).unwrap_or(u64::MAX),
                "seed={seed:016x} artifact={artifact_hint}"
            );
            let looked_up = store
                .lookup_entry(row.entry_seq)?
                .expect("entry should exist");
            assert_eq!(
                looked_up.entry_id, row.entry_id,
                "seed={seed:016x} artifact={artifact_hint}"
            );
        }

        let from_seq = 1 + (lcg_next(&mut state) % u64::try_from(entry_count).unwrap_or(1));
        let from_entries = store.read_entries_from(from_seq)?;
        assert_eq!(
            from_entries.len(),
            entry_count.saturating_sub(usize::try_from(from_seq).unwrap_or(1) - 1),
            "seed={seed:016x} artifact={artifact_hint}"
        );

        let tail_count = 1 + (usize::try_from(lcg_next(&mut state)).unwrap_or(0) % 8);
        let expected_tail = expected_ids[entry_count - tail_count..].to_vec();
        let tail_entries =
            store.read_tail_entries(u64::try_from(tail_count).unwrap_or(u64::MAX))?;
        assert_eq!(
            frame_ids(&tail_entries),
            expected_tail,
            "seed={seed:016x} artifact={artifact_hint}"
        );

        drop(store);
        let reopened = SessionStoreV2::create(dir.path(), max_segment_bytes)?;
        let replayed_ids = frame_ids(&reopened.read_all_entries()?);
        assert_eq!(
            replayed_ids, expected_ids,
            "seed={seed:016x} artifact={artifact_hint}"
        );
    }

    Ok(())
}

#[test]
fn corruption_corpus_index_bounds_violation_is_detected_and_recoverable() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    let expected_ids = append_linear_entries(&mut store, 6)?;

    let index_path = store.index_file_path();
    let mut rows = read_index_json_rows(&index_path)?;
    rows[0]["byteLength"] = json!(9_999_999_u64);
    write_index_json_rows(&index_path, &rows)?;

    let err = store
        .validate_integrity()
        .expect_err("bounds corruption must fail integrity validation");
    assert!(
        err.to_string().contains("index out of bounds"),
        "unexpected error: {err}"
    );

    let rebuilt = store.rebuild_index()?;
    assert_eq!(rebuilt, 6);
    store.validate_integrity()?;
    assert_eq!(frame_ids(&store.read_all_entries()?), expected_ids);

    Ok(())
}

#[test]
fn corruption_corpus_index_frame_mismatch_is_detected_and_recoverable() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    let expected_ids = append_linear_entries(&mut store, 5)?;

    let index_path = store.index_file_path();
    let mut rows = read_index_json_rows(&index_path)?;
    rows[0]["entryId"] = json!("entry_corrupted");
    write_index_json_rows(&index_path, &rows)?;

    let err = store
        .validate_integrity()
        .expect_err("entry_id tampering must fail integrity validation");
    assert!(
        err.to_string().contains("index/frame mismatch"),
        "unexpected error: {err}"
    );

    let rebuilt = store.rebuild_index()?;
    assert_eq!(rebuilt, 5);
    store.validate_integrity()?;
    assert_eq!(frame_ids(&store.read_all_entries()?), expected_ids);

    Ok(())
}

#[test]
fn checkpoint_replay_is_deterministic_after_reopen_and_rebuild() -> PiResult<()> {
    let dir = tempdir()?;
    let max_segment_bytes = 260;
    let mut store = SessionStoreV2::create(dir.path(), max_segment_bytes)?;
    let expected_ids = append_linear_entries(&mut store, 14)?;

    let checkpoint = store.create_checkpoint(1, "deterministic_replay_test")?;
    let baseline_ids = frame_ids(&store.read_all_entries()?);
    let tail_from = checkpoint.head_entry_seq.saturating_sub(4).max(1);
    let baseline_tail_ids = frame_ids(&store.read_entries_from(tail_from)?);

    assert_eq!(
        checkpoint.head_entry_id,
        expected_ids
            .last()
            .cloned()
            .expect("non-empty expected IDs"),
    );
    assert_eq!(baseline_ids, expected_ids);

    drop(store);
    let mut reopened = SessionStoreV2::create(dir.path(), max_segment_bytes)?;
    let reopened_checkpoint = reopened
        .read_checkpoint(1)?
        .expect("checkpoint should exist after reopen");
    assert_eq!(
        reopened_checkpoint.head_entry_seq,
        checkpoint.head_entry_seq
    );
    assert_eq!(reopened_checkpoint.head_entry_id, checkpoint.head_entry_id);
    assert_eq!(reopened_checkpoint.chain_hash, checkpoint.chain_hash);

    assert_eq!(frame_ids(&reopened.read_all_entries()?), baseline_ids);
    assert_eq!(
        frame_ids(&reopened.read_entries_from(tail_from)?),
        baseline_tail_ids
    );

    let rebuilt = reopened.rebuild_index()?;
    assert_eq!(
        rebuilt,
        u64::try_from(expected_ids.len()).unwrap_or(u64::MAX)
    );
    reopened.validate_integrity()?;
    assert_eq!(frame_ids(&reopened.read_all_entries()?), baseline_ids);

    Ok(())
}

#[test]
fn migration_events_roundtrip_via_ledger() -> PiResult<()> {
    let dir = tempdir()?;
    let store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    let event = MigrationEvent {
        schema: "pi.session_store_v2.migration_event.v1".to_string(),
        migration_id: "00000000-0000-0000-0000-000000000001".to_string(),
        phase: "completed".to_string(),
        at: "2026-02-15T20:00:00Z".to_string(),
        source_path: "sessions/legacy.jsonl".to_string(),
        target_path: "sessions/legacy.v2/".to_string(),
        source_format: "jsonl_v3".to_string(),
        target_format: "native_v2".to_string(),
        verification: MigrationVerification {
            entry_count_match: true,
            hash_chain_match: true,
            index_consistent: true,
        },
        outcome: "ok".to_string(),
        error_class: None,
        correlation_id: "mig_20260215_200000".to_string(),
    };

    store.append_migration_event(event.clone())?;
    let events = store.read_migration_events()?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], event);
    Ok(())
}

#[test]
fn rollback_to_checkpoint_truncates_tail_and_records_event() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 260)?;
    let all_ids = append_linear_entries(&mut store, 8)?;

    let checkpoint = store.create_checkpoint(1, "pre_migration")?;
    let mut parent = all_ids.last().cloned();
    for n in 9..=11 {
        let id = format!("entry_{n:08}");
        store.append_entry(
            id.clone(),
            parent.clone(),
            "message",
            json!({"kind":"message","ordinal":n}),
        )?;
        parent = Some(id);
    }

    let event = store.rollback_to_checkpoint(
        1,
        "00000000-0000-0000-0000-00000000000a",
        "rollback_20260215_204900",
    )?;
    assert_eq!(event.phase, "rollback");
    assert_eq!(event.outcome, "ok");
    assert!(event.verification.entry_count_match);
    assert!(event.verification.hash_chain_match);
    assert!(event.verification.index_consistent);
    assert_eq!(event.migration_id, "00000000-0000-0000-0000-00000000000a");

    let ids_after = frame_ids(&store.read_all_entries()?);
    assert_eq!(ids_after, all_ids);
    assert_eq!(store.entry_count(), checkpoint.head_entry_seq);
    assert_eq!(store.chain_hash(), checkpoint.chain_hash);
    store.validate_integrity()?;

    let ledger = store.read_migration_events()?;
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].phase, "rollback");
    assert_eq!(ledger[0].outcome, "ok");
    assert_eq!(ledger[0].correlation_id, "rollback_20260215_204900");
    Ok(())
}

// ── Manifest tests ──────────────────────────────────────────────────────

#[test]
fn manifest_write_and_read_round_trip() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    append_linear_entries(&mut store, 5)?;

    let manifest = store.write_manifest("test-session-id", "jsonl_v3")?;
    assert_eq!(manifest.store_version, 2);
    assert_eq!(manifest.session_id, "test-session-id");
    assert_eq!(manifest.source_format, "jsonl_v3");
    assert_eq!(manifest.counters.entries_total, 5);
    assert_eq!(manifest.head.entry_seq, 5);
    assert_eq!(manifest.head.entry_id, "entry_00000005");
    assert!(!manifest.integrity.chain_hash.is_empty());
    assert!(!manifest.integrity.manifest_hash.is_empty());

    let read_back = store.read_manifest()?.expect("manifest should exist");
    assert_eq!(read_back.session_id, manifest.session_id);
    assert_eq!(read_back.head.entry_seq, manifest.head.entry_seq);
    assert_eq!(
        read_back.integrity.chain_hash,
        manifest.integrity.chain_hash
    );

    Ok(())
}

#[test]
fn manifest_absent_returns_none() -> PiResult<()> {
    let dir = tempdir()?;
    let store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    assert!(store.read_manifest()?.is_none());
    Ok(())
}

#[test]
fn manifest_on_empty_store_has_zero_counters() -> PiResult<()> {
    let dir = tempdir()?;
    let store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    let manifest = store.write_manifest("empty-session", "native_v2")?;
    assert_eq!(manifest.counters.entries_total, 0);
    assert_eq!(manifest.head.entry_seq, 0);
    assert_eq!(manifest.head.entry_id, "");
    Ok(())
}

// ── Hash chain tests ────────────────────────────────────────────────────

#[test]
fn chain_hash_is_deterministic_across_reopens() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    append_linear_entries(&mut store, 10)?;
    let chain_after_write = store.chain_hash().to_string();

    drop(store);
    let reopened = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    assert_eq!(
        reopened.chain_hash(),
        chain_after_write,
        "chain hash must be deterministic after reopen"
    );
    Ok(())
}

#[test]
fn chain_hash_changes_with_each_append() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    let genesis = store.chain_hash().to_string();
    store.append_entry("e1", None, "message", json!({"text":"a"}))?;
    let after_one = store.chain_hash().to_string();
    assert_ne!(genesis, after_one);

    store.append_entry("e2", Some("e1".into()), "message", json!({"text":"b"}))?;
    let after_two = store.chain_hash().to_string();
    assert_ne!(after_one, after_two);

    Ok(())
}

// ── Head and accessor tests ─────────────────────────────────────────────

#[test]
fn head_and_entry_count_track_appends() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    assert!(store.head().is_none());
    assert_eq!(store.entry_count(), 0);
    assert_eq!(store.total_bytes(), 0);

    store.append_entry("e1", None, "message", json!({"text":"a"}))?;
    let head = store.head().expect("head after one append");
    assert_eq!(head.entry_seq, 1);
    assert_eq!(head.entry_id, "e1");
    assert_eq!(store.entry_count(), 1);
    assert!(store.total_bytes() > 0);

    Ok(())
}

// ── Index summary tests ─────────────────────────────────────────────────

#[test]
fn index_summary_empty_store() -> PiResult<()> {
    let dir = tempdir()?;
    let store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    assert!(store.index_summary()?.is_none());
    Ok(())
}

#[test]
fn index_summary_populated_store() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    append_linear_entries(&mut store, 12)?;

    let summary = store.index_summary()?.expect("should have summary");
    assert_eq!(summary.entry_count, 12);
    assert_eq!(summary.first_entry_seq, 1);
    assert_eq!(summary.last_entry_seq, 12);
    assert_eq!(summary.last_entry_id, "entry_00000012");
    Ok(())
}

// ── V2 sidecar discovery tests ──────────────────────────────────────────

#[test]
fn v2_sidecar_path_derivation() {
    use std::path::PathBuf;

    let p = PathBuf::from("/home/user/sessions/my-session.jsonl");
    let sidecar = pi::session_store_v2::v2_sidecar_path(&p);
    assert_eq!(sidecar, PathBuf::from("/home/user/sessions/my-session.v2"));

    let p2 = PathBuf::from("relative/path.jsonl");
    let sidecar2 = pi::session_store_v2::v2_sidecar_path(&p2);
    assert_eq!(sidecar2, PathBuf::from("relative/path.v2"));
}

#[test]
fn has_v2_sidecar_detection() -> PiResult<()> {
    let dir = tempdir()?;
    let jsonl_path = dir.path().join("test-session.jsonl");
    fs::write(&jsonl_path, "{}\n")?;

    assert!(!pi::session_store_v2::has_v2_sidecar(&jsonl_path));

    let sidecar_root = pi::session_store_v2::v2_sidecar_path(&jsonl_path);
    let mut store = SessionStoreV2::create(&sidecar_root, 4 * 1024)?;
    store.append_entry("e1", None, "message", json!({"text":"a"}))?;

    assert!(pi::session_store_v2::has_v2_sidecar(&jsonl_path));
    Ok(())
}

// ── Rebuild index from scratch ──────────────────────────────────────────

#[test]
fn rebuild_index_from_missing_index_file() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;
    let ids = append_linear_entries(&mut store, 8)?;
    let chain_before = store.chain_hash().to_string();

    let index_path = store.index_file_path();
    fs::remove_file(&index_path)?;

    let rebuilt = store.rebuild_index()?;
    assert_eq!(rebuilt, 8);
    assert_eq!(store.chain_hash(), chain_before);
    store.validate_integrity()?;
    assert_eq!(frame_ids(&store.read_all_entries()?), ids);
    Ok(())
}

// ── Multi-segment stress ────────────────────────────────────────────────

#[test]
fn many_segments_with_small_threshold() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 200)?;
    let ids = append_linear_entries(&mut store, 50)?;

    let index = store.read_index()?;
    assert_eq!(index.len(), 50);

    let max_seg = index.iter().map(|r| r.segment_seq).max().unwrap_or(0);
    assert!(
        max_seg >= 10,
        "50 entries with 200-byte threshold should produce many segments, got {max_seg}"
    );

    store.validate_integrity()?;
    assert_eq!(frame_ids(&store.read_all_entries()?), ids);
    Ok(())
}

// ── Rewrite amplification measurement ───────────────────────────────────

#[test]
fn v2_append_has_no_rewrite_amplification() -> PiResult<()> {
    let dir = tempdir()?;
    let mut store = SessionStoreV2::create(dir.path(), 4 * 1024)?;

    let mut cumulative_disk_bytes = Vec::new();
    for i in 1..=20 {
        let parent = if i == 1 {
            None
        } else {
            Some(format!("e{}", i - 1))
        };
        store.append_entry(
            format!("e{i}"),
            parent,
            "message",
            json!({"idx": i, "data": "x".repeat(50)}),
        )?;

        let seg_bytes: u64 = (1..=store.head().map_or(1, |h| h.segment_seq))
            .filter_map(|s| {
                let p = store.segment_file_path(s);
                fs::metadata(&p).ok().map(|m| m.len())
            })
            .sum();
        let idx_bytes = fs::metadata(store.index_file_path())
            .map(|m| m.len())
            .unwrap_or(0);
        cumulative_disk_bytes.push(seg_bytes + idx_bytes);
    }

    // V2 property: each append adds roughly constant bytes (no full rewrite).
    for window in cumulative_disk_bytes.windows(2) {
        let growth = window[1] - window[0];
        assert!(
            growth < 1024,
            "append growth {growth} bytes is too large; suggests rewrite amplification"
        );
    }

    Ok(())
}

// ─── V2 Resume Integration Tests ─────────────────────────────────────────────

/// Build a minimal JSONL session file with the given entries.
fn build_test_jsonl(dir: &Path, entries: &[pi::session::SessionEntry]) -> std::path::PathBuf {
    use std::io::Write;

    let path = dir.join("test_session.jsonl");
    let mut file = fs::File::create(&path).unwrap();

    // Write header (first line).
    let header = pi::session::SessionHeader::new();
    serde_json::to_writer(&mut file, &header).unwrap();
    file.write_all(b"\n").unwrap();

    // Write entries.
    for entry in entries {
        serde_json::to_writer(&mut file, entry).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.flush().unwrap();
    path
}

fn make_message_entry(id: &str, parent_id: Option<&str>, text: &str) -> pi::session::SessionEntry {
    pi::session::SessionEntry::Message(pi::session::MessageEntry {
        base: pi::session::EntryBase::new(parent_id.map(String::from), id.to_string()),
        message: pi::session::SessionMessage::User {
            content: pi::model::UserContent::Text(text.to_string()),
            timestamp: None,
        },
    })
}

#[test]
fn v2_sidecar_path_derives_from_jsonl_stem() {
    let jsonl = Path::new("/tmp/sessions/my_session.jsonl");
    let sidecar = pi::session_store_v2::v2_sidecar_path(jsonl);
    assert_eq!(sidecar, Path::new("/tmp/sessions/my_session.v2"));
}

#[test]
fn has_v2_sidecar_returns_false_for_bare_jsonl() {
    let dir = tempdir().unwrap();
    let jsonl = dir.path().join("session.jsonl");
    fs::write(&jsonl, "{}").unwrap();
    assert!(!pi::session_store_v2::has_v2_sidecar(&jsonl));
}

#[test]
fn create_v2_sidecar_round_trips_entries() -> PiResult<()> {
    let dir = tempdir()?;
    let entries = vec![
        make_message_entry("e1", None, "hello"),
        make_message_entry("e2", Some("e1"), "world"),
        make_message_entry("e3", Some("e2"), "foo"),
    ];
    let jsonl = build_test_jsonl(dir.path(), &entries);

    // Create sidecar.
    let store = pi::session::create_v2_sidecar_from_jsonl(&jsonl)?;

    // Verify sidecar was created.
    assert!(pi::session_store_v2::has_v2_sidecar(&jsonl));

    // Verify entry count.
    assert_eq!(store.entry_count(), 3);

    // Verify round-trip: read back frames and convert to entries.
    let frames = store.read_all_entries()?;
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].entry_id, "e1");
    assert_eq!(frames[1].entry_id, "e2");
    assert_eq!(frames[2].entry_id, "e3");
    assert_eq!(frames[1].parent_entry_id.as_deref(), Some("e1"));

    // Convert back to SessionEntry and verify content.
    for (frame, original) in frames.iter().zip(entries.iter()) {
        let recovered = pi::session_store_v2::frame_to_session_entry(frame)?;
        let recovered_id = recovered.base_id().unwrap();
        let original_id = original.base_id().unwrap();
        assert_eq!(recovered_id, original_id);
    }

    Ok(())
}

#[test]
fn v2_resume_loads_same_entries_as_jsonl() -> PiResult<()> {
    let dir = tempdir()?;
    let entries = vec![
        make_message_entry("msg1", None, "first message"),
        make_message_entry("msg2", Some("msg1"), "second message"),
        make_message_entry("msg3", Some("msg2"), "third message"),
        make_message_entry("msg4", Some("msg3"), "fourth message"),
        make_message_entry("msg5", Some("msg4"), "fifth message"),
    ];
    let jsonl = build_test_jsonl(dir.path(), &entries);

    // Create V2 sidecar.
    pi::session::create_v2_sidecar_from_jsonl(&jsonl)?;

    // Open via Session (will use V2 sidecar if detected) and assert inside
    // runtime harness, since run_test futures return ().
    let jsonl_str = jsonl
        .to_str()
        .expect("temporary jsonl path must be valid UTF-8")
        .to_string();
    asupersync::test_utils::run_test(|| async move {
        let (session, diag) = pi::session::Session::open_with_diagnostics(&jsonl_str)
            .await
            .expect("session open should succeed");

        assert_eq!(session.entries.len(), 5);
        assert!(diag.skipped_entries.is_empty());

        let ids: Vec<String> = session
            .entries
            .iter()
            .filter_map(|e| e.base_id().cloned())
            .collect();
        assert_eq!(ids, vec!["msg1", "msg2", "msg3", "msg4", "msg5"]);
    });

    // Verify the V2 sidecar path was used (the has_v2_sidecar check).
    assert!(pi::session_store_v2::has_v2_sidecar(&jsonl));

    Ok(())
}

#[test]
fn v2_sidecar_with_empty_entries_produces_empty_session() -> PiResult<()> {
    let dir = tempdir()?;
    let entries: Vec<pi::session::SessionEntry> = vec![];
    let jsonl = build_test_jsonl(dir.path(), &entries);

    // Create sidecar (empty).
    let store = pi::session::create_v2_sidecar_from_jsonl(&jsonl)?;
    assert_eq!(store.entry_count(), 0);

    // Verify sidecar directory exists.
    let sidecar_root = pi::session_store_v2::v2_sidecar_path(&jsonl);
    assert!(sidecar_root.join("index").exists());

    Ok(())
}

#[test]
fn v2_sidecar_preserves_entry_parent_chain() -> PiResult<()> {
    let dir = tempdir()?;
    let entries = vec![
        make_message_entry("root", None, "start"),
        make_message_entry("child1", Some("root"), "step 1"),
        make_message_entry("child2", Some("child1"), "step 2"),
    ];
    let jsonl = build_test_jsonl(dir.path(), &entries);
    let store = pi::session::create_v2_sidecar_from_jsonl(&jsonl)?;

    // Read active path from leaf to root.
    let path_frames = store.read_active_path("child2")?;
    assert_eq!(path_frames.len(), 3);
    assert_eq!(path_frames[0].entry_id, "root");
    assert_eq!(path_frames[1].entry_id, "child1");
    assert_eq!(path_frames[2].entry_id, "child2");

    Ok(())
}

#[test]
fn v2_sidecar_integrity_valid_after_migration() -> PiResult<()> {
    let dir = tempdir()?;
    let entries = vec![
        make_message_entry("a", None, "alpha"),
        make_message_entry("b", Some("a"), "beta"),
        make_message_entry("c", Some("b"), "gamma"),
        make_message_entry("d", Some("c"), "delta"),
    ];
    let jsonl = build_test_jsonl(dir.path(), &entries);
    let store = pi::session::create_v2_sidecar_from_jsonl(&jsonl)?;

    // Validate integrity — should not error.
    store.validate_integrity()?;

    Ok(())
}
