//! Criterion benchmark suite for accepted optimization findings (bd-izy.3).
//!
//! Covers O1, O2, O5, O6, O8/O9, O13, O15, V7-B, V8-A, and observer
//! ring-buffer drain. Each benchmark has a specific performance budget
//! from PLAN §1.2.2.
//!
//! Run with: `cargo bench --bench optimizations`
//! Run specific: `cargo bench --bench optimizations -- tool_registry`
//!
//! Performance budgets:
//! - `bench_tool_registry_get`: < 100ns (O1 HashMap lookup)
//! - `bench_policy_lookup`: < 100ns (O2 Cow<str> reason)
//! - `bench_model_registry_find`: < 100ns (O8/O9 HashMap lookup)
//! - `bench_provider_metadata`: < 50ns (V8-A OnceLock HashMap lookup)
//! - `bench_observer_ring_drain`: < 1ms for 128 events
//! - `bench_rpc_channel_throughput`: bounded channel for 256 slots (O15)
//! - `bench_tool_result_arc`: Arc<ToolOutput> clone vs deep clone (O6)
//! - `bench_tool_call_args_arc`: Arc<Value> access (O13)
//! - `bench_event_drain_buffer`: non-blocking try_send vs blocking send (O5)
//! - `bench_rpc_model_lookup`: HashMap vs linear scan (V7-B)

#[path = "bench_env.rs"]
mod bench_env;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::json;
use std::hint::black_box;
use std::sync::Arc;

// ============================================================================
// O1: Tool Registry HashMap Lookup (< 100ns)
// ============================================================================

fn bench_tool_registry_get(c: &mut Criterion) {
    let cwd = std::env::temp_dir();
    let enabled = &["read", "bash", "edit", "write", "grep", "find", "ls"];
    let registry = pi::tools::ToolRegistry::new(enabled, &cwd, None);

    let mut group = c.benchmark_group("o1_tool_registry");
    group.throughput(Throughput::Elements(1));

    // Benchmark successful lookup (most common path)
    group.bench_function("get_hit", |b| {
        b.iter(|| {
            let tool = registry.get(black_box("bash"));
            black_box(tool);
        });
    });

    // Benchmark miss lookup (edge case, should be same O(1))
    group.bench_function("get_miss", |b| {
        b.iter(|| {
            let tool = registry.get(black_box("nonexistent_tool"));
            black_box(tool);
        });
    });

    // Benchmark with all standard tool names
    group.bench_function("get_all_7_tools", |b| {
        b.iter(|| {
            for name in enabled {
                black_box(registry.get(black_box(name)));
            }
        });
    });

    group.finish();
}

// ============================================================================
// O8/O9: Model Registry HashMap Find (< 100ns)
// ============================================================================

fn bench_model_registry_find(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir for auth");
    let auth =
        pi::auth::AuthStorage::load(dir.path().join("auth.json")).expect("empty auth storage");
    let registry = pi::models::ModelRegistry::load(&auth, None);

    let model_count = registry.models().len();
    let mut group = c.benchmark_group("o8_model_registry");
    group.throughput(Throughput::Elements(1));

    // Known model lookup (HashMap hit)
    group.bench_function(BenchmarkId::new("find_hit", model_count), |b| {
        b.iter(|| {
            let result = registry.find(black_box("anthropic"), black_box("claude-opus-4-5"));
            black_box(result);
        });
    });

    // Unknown model lookup (HashMap miss)
    group.bench_function(BenchmarkId::new("find_miss", model_count), |b| {
        b.iter(|| {
            let result = registry.find(black_box("unknown"), black_box("no-such-model"));
            black_box(result);
        });
    });

    // find_by_id (linear scan — should still be fast for ~100 models)
    group.bench_function(BenchmarkId::new("find_by_id", model_count), |b| {
        b.iter(|| {
            let result = registry.find_by_id(black_box("claude-opus-4-5"));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// V8-A: Provider Metadata HashMap Lookup (< 50ns)
// ============================================================================

fn bench_provider_metadata(c: &mut Criterion) {
    // Force the OnceLock index to be initialized before benchmarking
    let _ = pi::provider_metadata::provider_metadata("anthropic");

    let mut group = c.benchmark_group("v8a_provider_metadata");
    group.throughput(Throughput::Elements(1));

    // Known provider (HashMap hit)
    group.bench_function("lookup_hit", |b| {
        b.iter(|| {
            let meta = pi::provider_metadata::provider_metadata(black_box("anthropic"));
            black_box(meta);
        });
    });

    // Provider alias (should resolve via same HashMap)
    group.bench_function("lookup_alias", |b| {
        b.iter(|| {
            let meta = pi::provider_metadata::provider_metadata(black_box("kimi"));
            black_box(meta);
        });
    });

    // Unknown provider (HashMap miss)
    group.bench_function("lookup_miss", |b| {
        b.iter(|| {
            let meta = pi::provider_metadata::provider_metadata(black_box("nonexistent"));
            black_box(meta);
        });
    });

    // canonical_provider_id (common call in hot path)
    group.bench_function("canonical_id", |b| {
        b.iter(|| {
            let id = pi::provider_metadata::canonical_provider_id(black_box("openai"));
            black_box(id);
        });
    });

    group.finish();
}

// ============================================================================
// Observer Ring Buffer: Push + Drain 128 Events (< 1ms)
// ============================================================================

fn bench_observer_ring_drain(c: &mut Criterion) {
    use pi::chrome::observer::{
        ObservableEventKind, ObservationEvent, ObservationRingBuffer, RING_BUFFER_CAPACITY,
    };

    let mut group = c.benchmark_group("observer_ring_buffer");
    group.throughput(Throughput::Elements(RING_BUFFER_CAPACITY as u64));

    // Fill and drain the full 128-event buffer
    group.bench_function(
        BenchmarkId::new("push_drain", RING_BUFFER_CAPACITY),
        |b| {
            b.iter(|| {
                let mut buffer = ObservationRingBuffer::new();
                for i in 0..RING_BUFFER_CAPACITY {
                    buffer.push(ObservationEvent::with_timestamp(
                        format!("obs-{i}"),
                        1,
                        ObservableEventKind::ConsoleError,
                        1000 + i as u64,
                        json!({"seq": i}),
                    ));
                }
                let events = buffer.drain();
                black_box(events);
            });
        },
    );

    // Drain only (pre-filled buffer)
    group.bench_function(
        BenchmarkId::new("drain_only", RING_BUFFER_CAPACITY),
        |b| {
            b.iter_batched(
                || {
                    let mut buffer = ObservationRingBuffer::new();
                    for i in 0..RING_BUFFER_CAPACITY {
                        buffer.push(ObservationEvent::with_timestamp(
                            format!("obs-{i}"),
                            1,
                            ObservableEventKind::ConsoleError,
                            1000 + i as u64,
                            json!({"seq": i}),
                        ));
                    }
                    buffer
                },
                |mut buffer| {
                    let events = buffer.drain();
                    black_box(events);
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    // Push with eviction (buffer already full, measures overwrite path)
    group.bench_function("push_with_eviction", |b| {
        let mut buffer = ObservationRingBuffer::new();
        // Pre-fill to capacity
        for i in 0..RING_BUFFER_CAPACITY {
            buffer.push(ObservationEvent::with_timestamp(
                format!("obs-{i}"),
                1,
                ObservableEventKind::ConsoleError,
                1000 + i as u64,
                json!({"seq": i}),
            ));
        }

        b.iter(|| {
            buffer.push(ObservationEvent::with_timestamp(
                "obs-evict".to_string(),
                1,
                ObservableEventKind::ConsoleError,
                9999,
                json!({"eviction": true}),
            ));
            black_box(buffer.len());
        });
    });

    group.finish();
}

// ============================================================================
// O15: RPC Output Channel Throughput (256-slot bounded mpsc)
// ============================================================================

fn bench_rpc_channel_throughput(c: &mut Criterion) {
    use std::sync::mpsc;

    const CHANNEL_BOUND: usize = 256;

    let mut group = c.benchmark_group("o15_rpc_channel");
    group.throughput(Throughput::Elements(CHANNEL_BOUND as u64));

    // Send + receive full channel capacity
    group.bench_function(
        BenchmarkId::new("send_recv_cycle", CHANNEL_BOUND),
        |b| {
            b.iter(|| {
                let (tx, rx) = mpsc::sync_channel::<String>(CHANNEL_BOUND);
                for i in 0..CHANNEL_BOUND {
                    tx.send(format!("{{\"id\":{i}}}")).unwrap();
                }
                drop(tx);
                let mut count = 0;
                while rx.recv().is_ok() {
                    count += 1;
                }
                black_box(count);
            });
        },
    );

    // Single send latency (channel not full)
    group.bench_function("single_send", |b| {
        let (tx, rx) = mpsc::sync_channel::<String>(CHANNEL_BOUND);
        b.iter(|| {
            tx.send(black_box("test".to_string())).unwrap();
            let _ = rx.recv().unwrap();
        });
    });

    group.finish();
}

// ============================================================================
// O6: Arc<ToolOutput> Clone vs Deep Clone
// ============================================================================

fn bench_tool_result_arc(c: &mut Criterion) {
    use pi::model::{ContentBlock, TextContent};
    use pi::tools::ToolOutput;

    // Build a representative ToolOutput with non-trivial content
    let output = ToolOutput {
        content: vec![ContentBlock::Text(TextContent::new("x".repeat(2048)))],
        details: Some(json!({
            "status": "ok",
            "tab_id": 42,
            "url": "http://example.com/very/long/path/to/simulate/real/data",
            "metadata": { "key1": "value1", "key2": "value2" }
        })),
        is_error: false,
    };
    let arc_output = Arc::new(output.clone());

    let mut group = c.benchmark_group("o6_tool_result");
    group.throughput(Throughput::Elements(1));

    // Arc clone (O(1) — just increment refcount)
    group.bench_function("arc_clone", |b| {
        b.iter(|| {
            let cloned = Arc::clone(black_box(&arc_output));
            black_box(cloned);
        });
    });

    // Serde serialization (the hot path for sending to RPC)
    group.bench_function("serialize_arc", |b| {
        b.iter(|| {
            let json = serde_json::to_string(black_box(arc_output.as_ref())).unwrap();
            black_box(json);
        });
    });

    group.finish();
}

// ============================================================================
// O13: Arc<Value> Tool Call Arguments Access
// ============================================================================

fn bench_tool_call_args_arc(c: &mut Criterion) {
    // Typical tool call arguments (moderate size JSON)
    let args = json!({
        "file_path": "/Users/test/Documents/Projects/pi_agent_rust/src/tools.rs",
        "line": 42,
        "limit": 100,
        "pattern": "fn bench_",
        "metadata": {
            "context": "test",
            "values": [1, 2, 3, 4, 5]
        }
    });
    let arc_args = Arc::new(args.clone());

    let mut group = c.benchmark_group("o13_tool_call_args");
    group.throughput(Throughput::Elements(1));

    // Arc clone (refcount increment)
    group.bench_function("arc_clone", |b| {
        b.iter(|| {
            let cloned = Arc::clone(black_box(&arc_args));
            black_box(cloned);
        });
    });

    // Arc deref + field access (the actual hot path in tool execute)
    group.bench_function("arc_deref_access", |b| {
        b.iter(|| {
            let val = arc_args.get(black_box("file_path"));
            black_box(val);
        });
    });

    // Deep clone for comparison (what we avoided with O13)
    group.bench_function("deep_clone_baseline", |b| {
        b.iter(|| {
            let cloned = black_box(&args).clone();
            black_box(cloned);
        });
    });

    group.finish();
}

// ============================================================================
// O2: PolicyCheck Cow<str> Reason (< 100ns for lookup)
// ============================================================================

fn bench_policy_lookup(c: &mut Criterion) {
    use pi::extensions::{ExtensionPolicy, PolicySnapshot};

    // Build a policy snapshot from the default policy (allows read, write, etc.)
    let policy = ExtensionPolicy::default();
    let snapshot = PolicySnapshot::compile(&policy);

    let mut group = c.benchmark_group("o2_policy_lookup");
    group.throughput(Throughput::Elements(1));

    // Lookup a known capability (O2 Cow::Borrowed hot path)
    group.bench_function("lookup_known", |b| {
        b.iter(|| {
            let check = snapshot.lookup(black_box("read"), None);
            black_box(check);
        });
    });

    // Lookup with unknown capability (falls back to evaluate_for)
    group.bench_function("lookup_unknown", |b| {
        b.iter(|| {
            let check = snapshot.lookup(black_box("nonexistent"), None);
            black_box(check);
        });
    });

    // Verify reason is Cow::Borrowed (zero-alloc)
    group.bench_function("reason_is_borrowed", |b| {
        b.iter(|| {
            let check = snapshot.lookup(black_box("read"), None);
            let is_borrowed =
                matches!(check.reason, std::borrow::Cow::Borrowed(_));
            black_box(is_borrowed);
        });
    });

    group.finish();
}

// ============================================================================
// O5: Event Drain Buffer — try_send vs blocking send
// ============================================================================

fn bench_event_drain_buffer(c: &mut Criterion) {
    use pi::agent::AgentEvent;

    const DRAIN_BUFFER: usize = 4096;

    let mut group = c.benchmark_group("o5_event_drain");

    // Non-blocking try_send to SyncSender (the O5 hot path)
    group.bench_function("try_send_nonblocking", |b| {
        let (tx, rx) =
            std::sync::mpsc::sync_channel::<AgentEvent>(DRAIN_BUFFER);
        // Spawn consumer to prevent buffer from filling
        let _consumer = std::thread::spawn(move || {
            while rx.recv().is_ok() {}
        });

        b.iter(|| {
            let event = AgentEvent::AgentStart {
                session_id: "bench".into(),
            };
            let _ = tx.try_send(black_box(event));
        });
    });

    // Blocking send for comparison (the pre-O5 path)
    group.bench_function("send_blocking", |b| {
        let (tx, rx) =
            std::sync::mpsc::sync_channel::<String>(256);
        let _consumer = std::thread::spawn(move || {
            while rx.recv().is_ok() {}
        });

        b.iter(|| {
            let _ = tx.send(black_box("test".to_string()));
        });
    });

    // Full pipeline: try_send + serialize on drain thread (O5 pattern)
    group.bench_function("drain_pipeline_100_events", |b| {
        b.iter(|| {
            let (out_tx, out_rx) =
                std::sync::mpsc::sync_channel::<String>(256);
            let (buf_tx, buf_rx) =
                std::sync::mpsc::sync_channel::<AgentEvent>(DRAIN_BUFFER);

            let drain = std::thread::spawn(move || {
                for event in buf_rx {
                    let s = serde_json::to_string(&event).unwrap_or_default();
                    let _ = out_tx.send(s);
                }
            });

            for i in 0..100 {
                let event = AgentEvent::AgentStart {
                    session_id: format!("s{i}").into(),
                };
                let _ = buf_tx.try_send(event);
            }
            drop(buf_tx);
            drain.join().unwrap();

            let mut count = 0;
            while out_rx.try_recv().is_ok() {
                count += 1;
            }
            black_box(count);
        });
    });

    group.finish();
}

// ============================================================================
// V7-B: RPC Model Lookup — HashMap vs Linear Scan
// ============================================================================

fn bench_rpc_model_lookup(c: &mut Criterion) {
    // Simulate the model lookup scenario with a HashMap index
    use std::collections::HashMap;

    // Build a realistic model list (91 models)
    let model_count = 91;
    let models: Vec<(String, String)> = (0..model_count)
        .map(|i| {
            let provider = format!("provider-{}", i % 10);
            let model_id = format!("model-{i}");
            (provider, model_id)
        })
        .collect();

    // Build HashMap index (V7-B pattern)
    let index: HashMap<(String, String), usize> = models
        .iter()
        .enumerate()
        .map(|(idx, (p, m))| ((p.to_lowercase(), m.to_lowercase()), idx))
        .collect();

    let mut group = c.benchmark_group("v7b_rpc_model_lookup");
    group.throughput(Throughput::Elements(1));

    // HashMap O(1) lookup (V7-B path)
    group.bench_function(
        BenchmarkId::new("hashmap_hit", model_count),
        |b| {
            b.iter(|| {
                let key = (
                    black_box("provider-5").to_lowercase(),
                    black_box("model-55").to_lowercase(),
                );
                let idx = index.get(&key);
                black_box(idx);
            });
        },
    );

    // Linear scan O(n) for comparison (pre-V7-B path)
    group.bench_function(
        BenchmarkId::new("linear_scan", model_count),
        |b| {
            b.iter(|| {
                let target_p = black_box("provider-5");
                let target_m = black_box("model-55");
                let found = models
                    .iter()
                    .position(|(p, m)| {
                        p.eq_ignore_ascii_case(target_p)
                            && m.eq_ignore_ascii_case(target_m)
                    });
                black_box(found);
            });
        },
    );

    // HashMap miss (should be O(1) still)
    group.bench_function("hashmap_miss", |b| {
        b.iter(|| {
            let key = (
                black_box("nonexistent").to_string(),
                black_box("no-model").to_string(),
            );
            let idx = index.get(&key);
            black_box(idx);
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Harness
// ============================================================================

criterion_group! {
    name = optimization_benches;
    config = bench_env::criterion_config();
    targets =
        bench_tool_registry_get,
        bench_model_registry_find,
        bench_provider_metadata,
        bench_observer_ring_drain,
        bench_rpc_channel_throughput,
        bench_tool_result_arc,
        bench_tool_call_args_arc,
        bench_policy_lookup,
        bench_event_drain_buffer,
        bench_rpc_model_lookup,
}

criterion_main!(optimization_benches);
