---
status: root_cause_found
trigger: >
  Three related agent-user-ui lifecycle issues:
  1. Service stop/uninstall via Manage-DlpAgentService.ps1 enters a loop waiting for password
     instead of showing a password prompt window.
  2. dlp-user-ui keeps running as an orphan process after dlp-agent is killed via taskkill.
  3. dlp-agent does not respawn dlp-user-ui after the UI process is killed.
created: "2026-04-29T10:45:00+07:00"
updated: "2026-04-29T10:55:00+07:00"
---

# Debug Session: agent-ui-lifecycle-stop-respawn

## Symptoms

### Issue 1: Password prompt loop on service stop/uninstall
- **Expected**: dlp-agent + dlp-user-ui should fire up a window prompt for the stop password when the admin runs `./scripts/Manage-DlpAgentService.ps1 -Action stop/uninstall`
- **Actual**: The command shows a loop of waiting for password; no prompt window appears
- **Context**: Testing in debug mode

### Issue 2: Orphan dlp-user-ui after agent killed
- **Expected**: dlp-user-ui should self-kill when there is no running dlp-agent instance
- **Actual**: After `taskkill` on dlp-agent, dlp-user-ui continues running orphaned
- **Context**: Manual testing via taskkill

### Issue 3: No respawn of dlp-user-ui after UI killed
- **Expected**: dlp-agent should respawn a new dlp-user-ui instance for monitoring activities
- **Actual**: When dlp-user-ui is killed, dlp-agent does not respawn it
- **Context**: Manual testing via taskkill

## Current Focus

hypothesis: "Three distinct but related root causes identified in ui_spawner, session_monitor, and password_stop modules"
test: "Code review of lifecycle management paths"
expecting: "Fixes in: (1) debug mode stop bypass, (2) UI watchdog/heartbeat, (3) session monitor process liveness check"
next_action: "Apply fixes"

## Evidence

### Issue 1 Root Cause: Debug builds skip password challenge but PowerShell script still waits
- `dlp-agent/src/service.rs` line 812-817: In debug builds (`cfg!(debug_assertions)`), the service control handler calls `confirm_stop_immediate()` which sets `STOP_CONFIRMED=true` immediately.
- `dlp-agent/src/password_stop.rs` line 99-102: `confirm_stop_immediate()` sets the atomic flag.
- `dlp-agent/src/service.rs` line 640-651: The run_loop polls `is_stop_confirmed()` every 500ms and breaks on confirmation.
- **However**, the `initiate_stop()` function in `password_stop.rs` (line 146) spawns a background thread that:
  1. Spawns a stop-password UI process (line 179)
  2. Polls a response file in a loop (line 191-215)
  This thread runs REGARDLESS of whether `confirm_stop_immediate()` was called.
- The background thread writes to `stop-debug.log` but the main loop breaks immediately due to `STOP_CONFIRMED=true`.
- The PowerShell script `Manage-DlpAgentService.ps1` line 226 uses `Stop-Service -Name $ServiceName -Force`, which sends SCM STOP. The script then waits up to 120s for the service to reach Stopped state (line 228).
- **The actual problem**: The service transitions to `StopPending` (line 804), then the debug bypass sets `STOP_CONFIRMED=true`, the main loop breaks, and shutdown proceeds. But if the shutdown hangs (e.g., file monitor or IPC pipes don't clean up), the service stays in `StopPending`.
- **More critically**: In `password_stop.rs` line 812, debug builds skip the password challenge. But `initiate_stop()` is still called, which spawns the background thread. The thread tries to spawn a UI process. If the UI binary path is wrong (debug build path), or `CreateProcessAsUserW` fails, the thread calls `cancel_stop()` which calls `revert_stop()` — but the main loop may have already broken due to `STOP_CONFIRMED`.

**Refined Root Cause for Issue 1**: The debug-mode bypass (`confirm_stop_immediate`) and the `initiate_stop` background thread race. The main loop sees `STOP_CONFIRMED=true` and breaks, but the background thread is still running and may call `revert_stop()` or `cancel_stop()` after the main loop has already started shutdown. More importantly, in debug mode the PowerShell script uses `Stop-Service -Force` which may not properly trigger the SCM control handler path that sets `STOP_CONFIRMED`. The service may be force-killed by SCM before the password dialog ever appears.

Wait — re-reading: In debug builds, `confirm_stop_immediate()` IS called from the control handler. The main loop polls and breaks. The service should stop cleanly. The "loop waiting for password" symptom suggests the service is NOT stopping cleanly — it's stuck in StopPending.

Looking more carefully at `run_service()` line 170-177:
```rust
let rt = tokio::runtime::Runtime::new()?;
rt.block_on(run_loop(&status_handle, machine_name))?;
rt.shutdown_timeout(Duration::from_secs(2));
```

If `run_loop` returns (because `STOP_CONFIRMED=true` in debug mode), then `rt.shutdown_timeout(2s)` runs. But blocking threads (IPC pipes, session monitor, Chrome pipe) may not terminate within 2s. Then the service reports STOPPED and exits.

The "loop waiting for password" from the user's perspective is the PowerShell script's `Wait-ForServiceState` loop (line 94-109) printing status messages. The password dialog never appears because in debug mode, `confirm_stop_immediate()` skips it entirely.

**ACTUAL Root Cause for Issue 1**: In debug builds, the password challenge is intentionally skipped (`cfg!(debug_assertions)` bypass), but the PowerShell script still tells the user to expect a password dialog. The service stops without showing any dialog. If the service hangs during shutdown (IPC pipes, file monitor cleanup), the PowerShell loop continues waiting. The user sees "waiting for password" messages but no dialog because debug mode bypasses the dialog entirely.

Additionally, `initiate_stop()` spawns a background thread that tries to spawn a UI process even in debug mode. This thread may fail to spawn the UI (wrong binary path, no active sessions) and then loop polling for a response file that never appears, until the 120s timeout. Meanwhile the main service thread has already exited. This orphaned thread may keep the process alive.

### Issue 2 Root Cause: No agent-death watchdog in dlp-user-ui
- `dlp-user-ui/src/ipc/pipe1.rs` line 63-80: The Pipe 1 client connects to `\\.\pipe\DLPCommand` and runs a blocking read loop.
- `dlp-user-ui/src/ipc/pipe1.rs` line 105-108: On read error, the client loop breaks and closes the pipe handle.
- **But**: There is NO code that calls `std::process::exit()` when the pipe disconnects. The UI process simply exits the `client_loop` function and returns to the caller.
- In the full UI mode (`dlp_user_ui::run()`), Pipe 1 connection runs as a background Tokio task. When the pipe disconnects, that task ends but the iced application continues running.
- The UI process has no heartbeat or watchdog to detect that the agent has died. It relies solely on pipe disconnection, but even then it doesn't self-terminate.
- Additionally, `dlp-agent/src/protection.rs` line 44-67: The agent process DACL is hardened to deny `PROCESS_TERMINATE` to Everyone. The UI process is similarly hardened in `ui_spawner.rs` line 223 via `harden_ui_process()`. This means even if a watchdog wanted to kill the UI, external processes (including the user) cannot terminate it without SYSTEM privileges.

**Root Cause for Issue 2**: The dlp-user-ui has no agent-death detection mechanism. When the agent is killed via taskkill, the named pipe connection breaks, but the UI process continues running because:
1. The pipe disconnect is only detected in the Pipe 1 client loop, which runs in a background task
2. No code watches for pipe disconnection and calls `std::process::exit()`
3. The UI process is DACL-hardened, so the user cannot kill it manually either

### Issue 3 Root Cause: session_monitor only tracks session IDs, not process liveness
- `dlp-agent/src/session_monitor.rs` line 88-127: The `session_loop` compares `current_sessions` (active Windows session IDs) against `active_sessions` (sessions that have UIs).
- Line 117-125: New sessions spawn UIs. Line 106-114: Ended sessions clean up UIs.
- **Missing**: There is NO check whether the UI process for an existing session is still alive.
- `dlp-agent/src/ui_spawner.rs` line 60-61: `UI_HANDLES` stores process handles, but `session_monitor.rs` never checks them.
- If a UI process is killed (e.g., via taskkill), its session still exists in `active_sessions`, so the monitor never detects it as "gone" and never respawns it.

**Root Cause for Issue 3**: The session monitor tracks session IDs, not process handles. It detects logon/logoff events but not UI process death. A killed UI process leaves the session ID in `active_sessions`, preventing respawn.

## Eliminated

- Not a Pipe 1 deadlock: The stop-password flow uses file-based response, not Pipe 1 (explicitly documented in password_stop.rs line 168-169).
- Not a missing UI binary: The `resolve_ui_binary()` function in service.rs line 735-746 correctly resolves the path, and `try_spawn_password_ui()` checks existence (password_stop.rs line 281-288).
- Not a session enumeration failure: `WTSEnumerateSessionsW` is used correctly in both ui_spawner.rs and session_monitor.rs.

## Resolution

root_cause: >
  Three distinct root causes:
  1. Debug-mode password bypass races with initiate_stop background thread;
     PowerShell script expects a dialog that debug mode intentionally skips.
  2. dlp-user-ui has no agent-death watchdog; pipe disconnect is not wired to process exit.
  3. session_monitor tracks session IDs not process handles; killed UIs are not detected.
fix: >
  1. In debug mode, skip spawning the stop-password UI thread entirely when
     confirm_stop_immediate() is used. Or: make the PowerShell script aware
     of debug mode. Better: add a heartbeat/ping mechanism in Pipe 1 so the
     UI can detect agent death and self-terminate (fixes #2 too).
  2. Add a Pipe 1 heartbeat/ping from agent to UI. If the UI misses N pings,
     call std::process::exit(). Also add a UI watchdog thread that polls
     agent process liveness via OpenProcess.
  3. In session_loop, periodically check process liveness via OpenProcess
     + GetExitCodeProcess for each entry in UI_HANDLES. If a UI process has
     exited, remove its session from active_sessions and respawn.
verification: ""
files_changed: []
