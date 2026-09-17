use super::*;
use serde_json::json;

#[test]
fn output_flood_never_displaces_a_stop_event() {
    let pending: PendingMap = Mutex::new(HashMap::new());
    let (events, rx) = std::sync::mpsc::sync_channel(1);
    let tail = Mutex::new(crate::lsp::jsonrpc::PublicTailBuffer::new());
    let writer = Mutex::new(Vec::<u8>::new());
    let sequence = AtomicU64::new(1);
    for _ in 0..2000 {
        assert!(dispatch(&json!({"type":"event","event":"output","body":{"output":"progress\n"}}),
            &pending, &events, &tail, &writer, &sequence));
    }
    assert!(dispatch(&json!({"type":"event","event":"stopped","body":{"threadId":9,"reason":"breakpoint"}}),
        &pending, &events, &tail, &writer, &sequence));
    assert_eq!(rx.try_recv().unwrap().body["threadId"], 9);
    assert!(rx.try_recv().is_err());
    assert!(lock(&tail).tail().contains("progress"));
}

#[test]
fn control_overflow_is_an_error_not_silent_state_loss() {
    let pending: PendingMap = Mutex::new(HashMap::new());
    let (events, _rx) = std::sync::mpsc::sync_channel(1);
    let tail = Mutex::new(crate::lsp::jsonrpc::PublicTailBuffer::new());
    let writer = Mutex::new(Vec::<u8>::new());
    let sequence = AtomicU64::new(1);
    let event = json!({"type":"event","event":"initialized","body":{}});
    assert!(dispatch(&event, &pending, &events, &tail, &writer, &sequence));
    assert!(!dispatch(&event, &pending, &events, &tail, &writer, &sequence));
}

#[test]
fn reverse_request_replies_observe_queue_backpressure() {
    let pending: PendingMap = Mutex::new(HashMap::new());
    let (events, _rx) = std::sync::mpsc::sync_channel(1);
    let tail = Mutex::new(crate::lsp::jsonrpc::PublicTailBuffer::new());
    let (tx, _writes) = std::sync::mpsc::sync_channel(1);
    let writer = Mutex::new(ReplyWriter(tx));
    let sequence = AtomicU64::new(1);
    let request = json!({"type":"request","seq":7,"command":"runInTerminal"});
    assert!(dispatch(&request, &pending, &events, &tail, &writer, &sequence));
    assert!(!dispatch(&request, &pending, &events, &tail, &writer, &sequence));
}

#[test]
fn sequence_exhaustion_is_not_wrapped_to_a_pending_request() {
    let sequence = AtomicU64::new(u64::MAX);
    assert!(next_sequence(&sequence).is_err());
    assert_eq!(sequence.load(Ordering::SeqCst), u64::MAX);
}

#[cfg(unix)]
#[test]
fn dropped_request_removes_pending_sender_and_revokes_queued_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let transport = DapTransport::spawn("sh", &["-c".into(), "exec sleep 30".into()], &[], temp.path()).unwrap();
    let phase = Arc::new(AtomicU8::new(QUEUED));
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);
    lock(&transport.pending).insert(42, tx);
    let lease = PendingLease { seq:42, life:Arc::clone(&transport.life), phase:Arc::clone(&phase), answered:false };
    drop(lease);
    assert!(lock(&transport.pending).is_empty());
    assert_eq!(phase.load(Ordering::SeqCst), CANCELLED);
    assert!(transport.is_alive(), "cancelling an unsent request does not kill the session");
    transport.kill();
}

#[cfg(unix)]
#[test]
fn blocked_stdin_deadline_does_not_block_runtime_and_retires_partial_frame() {
    let temp = tempfile::tempdir().unwrap();
    let transport = DapTransport::spawn("sh", &["-c".into(), "exec sleep 30".into()], &[], temp.path()).unwrap();
    let runtime = asupersync::runtime::RuntimeBuilder::new()
        .enable_parking(false).worker_threads(1).blocking_threads(1,8).build().unwrap();
    let start = std::time::Instant::now();
    let result = runtime.block_on(transport.request("large", json!({"data":"x".repeat(1024 * 1024)}), Duration::from_millis(150)));
    assert!(matches!(result, Err(DapError::Timeout { .. })), "{result:?}");
    assert!(start.elapsed() < Duration::from_secs(5), "pipe write blocked the async caller");
    assert!(!transport.is_alive());
    assert!(lock(&transport.pending).is_empty());
}

#[cfg(unix)]
#[test]
fn explicit_kill_fails_all_pending_waiters_immediately() {
    let temp = tempfile::tempdir().unwrap();
    let transport = DapTransport::spawn("sh", &["-c".into(), "exec sleep 30".into()], &[], temp.path()).unwrap();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    lock(&transport.pending).insert(1, tx);
    transport.kill();
    assert!(matches!(rx.try_recv().unwrap(), Err(DapError::Transport(_))));
    assert!(lock(&transport.pending).is_empty());
}

#[cfg(unix)]
#[test]
fn dropping_the_actual_request_future_removes_its_pending_entry() {
    let temp = tempfile::tempdir().unwrap();
    let transport = DapTransport::spawn("sh", &["-c".into(), "exec sleep 30".into()], &[], temp.path()).unwrap();
    let runtime = asupersync::runtime::RuntimeBuilder::new()
        .enable_parking(false).worker_threads(1).blocking_threads(1,8).build().unwrap();
    runtime.block_on(async {
        let mut request = Box::pin(transport.request("never", json!({}), Duration::from_secs(30)));
        assert!(futures::poll!(request.as_mut()).is_pending());
        assert_eq!(lock(&transport.pending).len(), 1);
        drop(request);
        assert!(lock(&transport.pending).is_empty());
    });
    transport.kill();
}

#[cfg(unix)]
#[test]
fn real_stdio_output_flood_preserves_the_following_stop() {
    if !std::process::Command::new("python3").arg("--version").stdout(Stdio::null()).stderr(Stdio::null())
        .status().is_ok_and(|status| status.success()) {
        assert!(std::env::var_os("PI_DEBUG_REQUIRE_PROTOCOL").is_none(), "python3 required for DAP protocol tests");
        eprintln!("skip: python3 absent; no real stdio flood probe ran");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("adapter.py");
    std::fs::write(&script, include_str!("../test_adapter.py")).unwrap();
    let transport = DapTransport::spawn("python3", &["-I".into(), "-u".into(), script.display().to_string()], &[], temp.path()).unwrap();
    let runtime = asupersync::runtime::RuntimeBuilder::new()
        .enable_parking(false).worker_threads(1).blocking_threads(1,8).build().unwrap();
    let session = runtime.block_on(super::super::session::DapSession::begin(transport)).unwrap();
    runtime.block_on(session.call("flood", json!({}))).unwrap();
    assert!(matches!(session.state(), super::super::session::ExecState::Stopped { thread_id:9, .. }));
    assert!(session.output_tail().contains("progress"));
    runtime.block_on(session.terminate());
}
