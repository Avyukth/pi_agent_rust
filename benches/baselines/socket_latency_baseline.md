# Unix Socket Latency Baseline (OQ2)

Captured: 1772013309463 (unix_ms)
Platform: macOS 26.3 / aarch64 / 12 cores
CPU: Apple M3 Pro
Rust: rustc 1.95.0-nightly (3c9faa0d0 2026-02-16)
Profile: bench
Noise Score: 0 (governor=unavailable, turbo=unavailable, aslr=unavailable, thp=unavailable)

## Round-trip latency (unix socket + protocol frame)

| Payload | Samples | Req frame | Resp frame | p50 | p95 | p99 | mean | max |
|---------|---------|-----------|------------|-----|-----|-----|------|-----|
| 256 B | 20 | 370 B | 110 B | 8.958 us | 16.917 us | 97.000 us | 13.387 us | 97.000 us |
| 1024 B | 20 | 1139 B | 111 B | 4.917 us | 12.208 us | 37.000 us | 7.093 us | 37.000 us |

## Decomposition notes

- `T_ser`: `protocol::encode_frame(request)` microbench on the same payload.
- `T_deser`: `protocol::decode_frame(response)` microbench on the same frame.
- `T_socket + T_sched`: included in round-trip and not isolated by this harness.
- This report excludes Chrome execution time (`includes_end_to_end_chrome=false`).

## Reference matrix status

- Local machine is reference target: true
- macOS Apple Silicon recorded: true
- Linux x86_64 recorded: false
- Remaining reference targets:
  - Linux x86_64

## Soft target check (socket layer)

- 1 KiB p95 = 12.208 us (target < 5.000 ms) => PASS
