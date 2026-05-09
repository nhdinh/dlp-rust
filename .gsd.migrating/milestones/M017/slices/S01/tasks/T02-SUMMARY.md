---
id: T02
parent: S01
milestone: M017
key_files:
  - dlp-agent/src/hook_ipc.rs
  - dlp-agent/src/lib.rs
  - dlp-agent/Cargo.toml
  - dlp-agent/src/ipc/frame.rs
key_decisions:
  - Reused existing crate::ipc::frame length-prefix framing with bincode payloads instead of inventing a new framing scheme
  - Used run_with_ready callback pattern (consistent with existing pipe1/pipe2/pipe3) for testability
  - Discovered and fixed existing write_all bug in frame.rs that caused all pipe writes to fail with empty slice
duration: 
verification_result: passed
completed_at: 2026-05-08T08:27:53.750Z
blocker_discovered: false
---

# T02: Created named-pipe hook IPC protocol (HookRequest/HookResponse over bincode) and agent-side server with 1000-round-trip test (p99 37.8µs); fixed existing frame.rs write_all bug.

**Created named-pipe hook IPC protocol (HookRequest/HookResponse over bincode) and agent-side server with 1000-round-trip test (p99 37.8µs); fixed existing frame.rs write_all bug.**

## What Happened

Created dlp-agent/src/hook_ipc.rs with HookRequest { path, action } and HookResponse { decision, reason } types, both Serialize + Deserialize via bincode. Implemented HookIpcServer::new(pipe_name, handler) and a blocking run() accept loop using CreateNamedPipeW + ConnectNamedPipeW on \\.\pipe\DlpHookPipe. The server reuses the existing crate::ipc::frame length-prefix framing and crate::ipc::pipe_security::PipeSecurity for DACL setup. handle_connection loops to service multiple requests per connection, matching the test profile. Added 6 unit tests: hook_ipc_roundtrip_test (1000 requests, p99 37.8µs), empty_path_boundary, zero_byte_payload, malformed_request, server_not_running, and oversized_path. Also added bincode = "1.3" to dlp-agent/Cargo.toml and pub mod hook_ipc to lib.rs. During implementation, discovered a pre-existing bug in dlp-agent/src/ipc/frame.rs write_all where slice_len = buf.len() - remaining computed 0 on the first iteration, causing WriteFile to receive an empty slice and fail. Fixed it to use offset + remaining.min(65536), matching read_exact's correct pattern.

## Verification

cargo test -p dlp-agent hook_ipc — 6/6 tests pass. hook_ipc_roundtrip_test sends 1000 request/response pairs over a single pipe connection and measures latency; p99 is 37.8µs, well under 50ms. Negative tests verify empty path, zero-byte payload, malformed bincode, missing server, and 40KB oversized path.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test -p dlp-agent hook_ipc -- --nocapture` | 0 | ✅ pass | 12300ms |

## Deviations

Server handles multiple requests per connection (looped handle_connection) rather than one-shot, because the 1000-round-trip test sends all requests over a single client handle. Synchronous per-connection handling instead of explicit tokio::task::spawn_blocking, because Win32 pipe APIs are inherently blocking and the handler is sync — the accept loop itself runs on a dedicated std::thread as planned.

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/hook_ipc.rs`
- `dlp-agent/src/lib.rs`
- `dlp-agent/Cargo.toml`
- `dlp-agent/src/ipc/frame.rs`
