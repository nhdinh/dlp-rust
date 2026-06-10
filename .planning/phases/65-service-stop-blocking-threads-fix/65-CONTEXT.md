# Phase 65: Service Stop Blocking Threads Fix — Context

## Phase Goal

Fix the dlp-agent Windows service stop hang by ensuring all blocking `std::thread`s are properly signalled, shut down, and joined before the service reports `STOPPED` to the SCM. Add panic safety to the password verification thread.

## Success Criteria

1. `sc stop dlp-agent` (with correct password) completes within 30 seconds and the service process exits.
2. `sc stop dlp-agent` with cancellation (wrong password x3 or Cancel) correctly reverts to `Running`.
3. A panic in `get_auth_hash()` or `bcrypt::verify()` does not permanently strand the service in `StopPending`.
4. `Manage-DlpAgentService.ps1 -Action Stop` handles the stop flow correctly and provides meaningful error messages.
5. All existing tests pass; new tests verify shutdown signal propagation.

## Requirements

- **STOP-01**: All blocking threads spawned in `run_service()` must be gracefully shut down and joined before reporting `STOPPED`.
- **STOP-02**: The shutdown mechanism must not introduce new deadlocks or race conditions.
- **STOP-03**: The password stop verification thread must be panic-safe (`catch_unwind`) and always call `abort_stop()` on failure.

## In Scope

- `dlp-agent/src/service.rs` — thread handle storage, shutdown sequence
- `dlp-agent/src/ipc/server.rs` — store and expose pipe thread handles
- `dlp-agent/src/ipc/pipe1.rs` — shutdown signal in accept_loop
- `dlp-agent/src/ipc/pipe2.rs` — shutdown signal in accept_loop
- `dlp-agent/src/ipc/pipe3.rs` — shutdown signal in accept_loop
- `dlp-agent/src/chrome/handler.rs` — shutdown signal in accept_loop
- `dlp-agent/src/health_monitor.rs` — shutdown signal for internal tokio runtime
- `dlp-agent/src/session_monitor.rs` — shutdown signal for session_loop
- `dlp-agent/src/password_stop.rs` — `catch_unwind` in initiate_stop thread
- `scripts/Manage-DlpAgentService.ps1` — better error handling for StopPending

## Out of Scope

- Process DACL hardening changes (`protection.rs`) — the DACL is a security feature, not part of this bug
- Service installation logic changes
- Password hashing algorithm changes
- UI binary changes

## Key Constraints

1. **Windows-only**: All code changes are in `#[cfg(windows)]` paths.
2. **No new dependencies**: Use only `std` and existing crate dependencies.
3. **Backward compatibility**: Existing pipe protocol, Chrome protocol, and heartbeat protocol remain unchanged.
4. **Thread safety**: Shutdown signal must be `Sync` (readable from any thread).
5. **Timeout bounds**: Total shutdown must complete within `SHUTDOWN_TIMEOUT` (10s currently, may need increase).

## Existing Patterns to Follow

From `dlp-agent/src/service.rs`:
- `SERVICE_STATE` uses `parking_lot::Mutex<ServiceState>`
- `SCM_HANDLE` uses `std::sync::OnceLock<ServiceStatusHandle>`
- `set_status()` and `report_scm_status()` are the canonical SCM reporting functions
- `run_loop_shutdown()` already has per-subsystem async shutdown logic

From `dlp-agent/src/health_monitor.rs`:
- `RESPAWN_TX` is a static `Mutex<Option<watch::Sender<...>>>`
- Internal tokio runtime built with `Builder::new_current_thread()`

## Risk Areas

1. **Named pipe cancellation**: `ConnectNamedPipeW` and `ReadFile` on named pipes are synchronous and cannot be cancelled from another thread without `CancelSynchronousIo` (which only works for I/O started in the calling thread). The worker thread must poll the shutdown flag between blocking calls.
2. **Health monitor tokio runtime**: Dropping the tokio runtime from within the thread (via signal) vs. from outside (via handle abort) has different semantics.
3. **Session monitor WTS calls**: `WTSEnumerateSessionsW` is a fast polling call (every 2s), so checking a shutdown flag between polls is sufficient.
4. **Password stop thread**: The thread polls a file every 500ms. The shutdown signal should also be checked in this loop.
