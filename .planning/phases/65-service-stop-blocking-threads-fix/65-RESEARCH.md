# Phase 65: Service Stop Blocking Threads Fix — Research

**Researched:** 2026-06-10 (via `/gsd-debug` session `dlp-agent-stop-001`)
**Domain:** Windows service lifecycle, SCM interaction, thread shutdown, named pipe cancellation
**Confidence:** HIGH

## Summary

The dlp-agent Windows service enters `StopPending` when `sc stop` is issued, and after the dlp-admin password is verified, `run_service()` reports `STOPPED` to the SCM and returns. However, the **service process never exits** because several blocking `std::thread`s spawned during startup are never shut down or joined. The SCM sees the process is still alive, leaving the service stuck in `StopPending` indefinitely.

Additionally, `password_stop::initiate_stop()` spawns a verification thread with **no `catch_unwind`**. If `get_auth_hash()` or `bcrypt::verify()` panics (e.g., on a malformed hash), the thread dies silently without calling `abort_stop()`, permanently orphaning the service in `StopPending`.

**Primary recommendation:** Add a global shutdown signal (`AtomicBool`), store all `JoinHandle`s in `RunLoopContext`, signal shutdown and join all threads before reporting `STOPPED`, and wrap the password verification thread in `catch_unwind`.

## Affected Threads

| Thread | Spawn Location | Blocking Operation | Shutdown Signal Needed |
|--------|---------------|-------------------|----------------------|
| Chrome pipe server | `service.rs:251` | `ConnectNamedPipeW` / `ReadFile` loop | Yes — break accept_loop |
| IPC pipe server (Pipe 1) | `ipc/server.rs:34` | `ConnectNamedPipeW` / `ReadFile` loop | Yes — break accept_loop |
| IPC pipe server (Pipe 2) | `ipc/server.rs:46` | `ConnectNamedPipeW` / `ReadFile` loop | Yes — break accept_loop |
| IPC pipe server (Pipe 3) | `ipc/server.rs:58` | `ConnectNamedPipeW` / `ReadFile` loop | Yes — break accept_loop |
| Health monitor | `service.rs:230` | Tokio `block_on` with `interval.tick()` loop | Yes — drop tokio runtime |
| Session monitor | `service.rs:265` | `WTSEnumerateSessionsW` poll loop | Yes — break session_loop |
| Password stop | `password_stop.rs:166` | File polling + bcrypt verify | Yes — `catch_unwind` + abort on panic |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Shutdown signal | `service.rs` (global `AtomicBool`) | Each subsystem reads it | Central signal avoids scattered state |
| Thread handle storage | `RunLoopContext` | `service.rs` joins | Handles must outlive tokio runtime shutdown |
| Pipe loop cancellation | `ipc/pipe*.rs` | Chrome `handler.rs` | Each accept_loop checks shutdown flag |
| Health monitor shutdown | `health_monitor.rs` | `service.rs` signals | Internal tokio runtime drop on signal |
| Session monitor shutdown | `session_monitor.rs` | `service.rs` signals | `session_loop` breaks on signal |
| Panic safety | `password_stop.rs` | `service.rs` state revert | `catch_unwind` ensures abort_stop on panic |

## Standard Stack

No new dependencies required. All functionality uses:
- `std::sync::atomic::AtomicBool` — shutdown signal
- `std::thread::JoinHandle` — thread management
- `std::panic::catch_unwind` — panic safety
- `parking_lot::Mutex` — already used for `SERVICE_STATE`

## Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `AtomicBool` shutdown signal | `tokio::sync::watch` or `crossbeam` channel | `AtomicBool` is simplest; no new deps; all threads already use `std` |
| `JoinHandle::join()` with timeout | `JoinHandle::join()` blocking | Timeout requires `thread::sleep` polling; simpler to just join and rely on signal to break loops quickly |
| `CancelSynchronousIo` (Windows) | `AtomicBool` | `CancelSynchronousIo` only cancels I/O started in same thread; our threads are worker threads, not the signaller. Overly complex. |
| `DisconnectNamedPipe` from main thread | Signal + loop break | DisconnectNamedPipe requires pipe handle from worker thread; sharing handles across threads adds complexity |

## Process DACL Implication

`protection::harden_agent_process()` (called at `service.rs:203`) applies a DENY ACE for `Everyone` on `PROCESS_TERMINATE`. Once the service is stuck, even `taskkill /F` from admin context fails. The only recovery is SYSTEM context (`psexec -s`) or reboot. This makes the bug **severity-critical**: it renders the service unrecoverable without elevated privileges.

## `CanStop = False` Is Expected Behavior

When the service enters `StopPending`, `ServiceControlAccept::empty()` is reported to the SCM. PowerShell's `CanStop` property reflects this correctly. The user-visible symptom (`CanStop = False`) is **not the bug** — it is the SCM accurately reporting that the service does not accept STOP controls while already stopping.
