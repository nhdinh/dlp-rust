---
estimated_steps: 36
estimated_files: 3
skills_used: []
---

# T02: Named pipe protocol and agent-side pipe server

Define the `HookRequest` / `HookResponse` protocol types in `dlp-agent/src/hook_ipc.rs`. Implement an agent-side named pipe server using `CreateNamedPipeW` + `ConnectNamedPipeW` on `\\.\pipe\DlpHookPipe`. The server runs on a dedicated `std::thread` and spawns a short-lived Tokio task per connection for classification. Write unit tests that spawn a pipe client in-process, send 1000 requests, and assert p99 latency is under 50ms.

## Failure Modes
| Dependency | On error | On timeout | On malformed response |
|------------|----------|-----------|----------------------|
| Named pipe server | Hook client fails-closed (DENY) | Same — fail-closed | bincode deserialization error logged, connection dropped |

## Load Profile
- **Shared resources**: Single named pipe instance handle per server thread.
- **Per-operation cost**: One `ReadFile`/`WriteFile` pair + bincode encode/decode.
- **10x breakpoint**: Pipe server thread pool exhaustion if each connection spawns a blocking thread; use async task per connection instead.

## Negative Tests
- **Malformed inputs**: Oversized path (>32KB), non-UTF-8 bytes in path field.
- **Error paths**: Pipe server not running — client connect fails with `ERROR_FILE_NOT_FOUND`.
- **Boundary conditions**: Empty path string, zero-byte payload.

## Steps
1. Create `dlp-agent/src/hook_ipc.rs` with `HookRequest { path: String, action: String }` and `HookResponse { decision: Decision, reason: String }`.
2. Implement `HookIpcServer::new(pipe_name, handler) -> Self` and `run(self)` blocking loop.
3. Use `bincode` for serialization (add to `dlp-agent/Cargo.toml`).
4. Write `hook_ipc_roundtrip_test` that measures 1000 request/response pairs.
5. Add `pub mod hook_ipc;` to `dlp-agent/src/lib.rs`.

## Must-Haves
- [ ] `HookRequest` and `HookResponse` are `Serialize` + `Deserialize` via `bincode`.
- [ ] Agent pipe server accepts connections and echoes back a test decision.
- [ ] 1000 round-trips complete with p99 < 50ms on local test.

## Verification
- `cargo test -p dlp-agent hook_ipc`

## Observability Impact
- Signals added: `tracing::info!` on pipe connect/disconnect; `tracing::warn!` on malformed request.
- How a future agent inspects this: `cargo test -p dlp-agent hook_ipc -- --nocapture` shows server logs.
- Failure state exposed: Connection refused when server thread is not running.

## Inputs
- `dlp-agent/src/lib.rs`
- `dlp-agent/src/ipc/` (existing IPC patterns)

## Expected Output
- `dlp-agent/src/hook_ipc.rs`
- `dlp-agent/src/lib.rs` (updated with `mod hook_ipc`)
- `dlp-agent/Cargo.toml` (if `bincode` added)

## Inputs

- `dlp-agent/src/lib.rs`
- `dlp-agent/src/ipc/`

## Expected Output

- `dlp-agent/src/hook_ipc.rs`
- `dlp-agent/src/lib.rs`
- `dlp-agent/Cargo.toml`

## Verification

cargo test -p dlp-agent hook_ipc
