---
status: resolved
trigger: "dlp-agent Windows service stuck when trying to stop. User provided dlp-admin password but service shows CanStop = False and is stuck in 'stopping' state."
created: 2026-06-10T17:18:00Z
updated: 2026-06-10T17:22:00Z
related_issues:
  - dlp-rust-bri  (P0: blocking threads prevent stop)
  - dlp-rust-mnl  (P1: catch_unwind in password_stop)
---

## Current Focus

hypothesis: The service is stuck in StopPending because the password_stop module's UI-spawning or file-response logic failed silently, leaving STOP_CONFIRMED never set, while the service control handler already transitioned to StopPending without a mechanism to revert on timeout.
test: Code review of service.rs, password_stop.rs, protection.rs, and Manage-DlpAgentService.ps1
expecting: Identify the exact code path that causes the hang and why CanStop=False persists
next_action: Write root cause analysis document

## Symptoms

expected: Service should stop cleanly after dlp-admin enters correct password via the UI dialog
actual: Service shows CanStop = False and is stuck in "stopping" state. Password was provided but stop did not complete.
errors: None visible to user; service stuck in StopPending
reproduction: Run `sc stop dlp-agent` or `Manage-DlpAgentService.ps1 -Action Stop`, enter password when prompted
started: Unknown when first broke; reported now

## Evidence

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/service.rs — service control handler, run_loop, set_status
  found: >
    The service control handler (line 3276) on ServiceControl::Stop immediately sets
    SERVICE_STATE = StopPending and reports StopPending to SCM with a 120-second wait_hint.
    It then spawns password_stop::initiate_stop() on a background thread. The main run_loop
    (line 978) polls is_stop_confirmed() every 500ms. If STOP_CONFIRMED never becomes true,
    the loop never breaks, and the service stays in StopPending forever.
  implication: Any failure in the password challenge flow that does NOT call abort_stop() or cancel_stop() will leave the service permanently hung in StopPending.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/password_stop.rs — initiate_stop, handle_file_response, abort_stop, cancel_stop
  found: >
    initiate_stop() spawns a thread that:
    1. Spawns a UI process via try_spawn_password_ui() which uses CreateProcessAsUserW in the active console session.
    2. Polls a response file for up to STOP_TIMEOUT_SECS (120s).
    3. On timeout: calls abort_stop() which calls crate::service::revert_stop().
    4. On cancel: calls cancel_stop() which calls crate::service::revert_stop().
    5. On submit: calls handle_password_submit -> handle_verification_result -> on wrong password maybe_abort_after_failure -> abort_stop().

    However, there is a CRITICAL GAP: if try_spawn_password_ui() returns false (UI binary not found, no active sessions, WTSQueryUserToken fails, CreateProcessAsUserW fails), initiate_stop() calls cancel_stop() and returns. That path IS handled.

    BUT: if the UI process IS spawned successfully but NEVER writes the response file (e.g. UI crashes, UI hangs, user closes dialog without clicking cancel, response file write fails), the polling loop will hit the 120s timeout and call abort_stop(). So the timeout path IS handled.

    The real problem is elsewhere.
  implication: The password_stop timeout and failure paths DO call revert_stop(). So the hang is NOT in password_stop's main thread.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/service.rs — set_status() vs report_scm_status()
  found: >
    set_status() (line 3235) ALWAYS sets wait_hint = Duration::default() (ZERO) and checkpoint = 0.
    report_scm_status() (line 3361) uses the caller-provided wait_hint.

    The service control handler's report_scm_status() call for StopPending uses wait_hint = 120s.
    But run_loop's set_status() call for StopPending (line 1011) uses the default wait_hint = ZERO.

    More importantly: when the service is in StopPending, the controls_accepted is set to
    ServiceControlAccept::empty() — meaning the SCM is told the service accepts NO controls.
    This is why `CanStop = False` appears in PowerShell — the SCM correctly reports that the
    service does not currently accept STOP controls because it is already stopping.
  implication: CanStop=False is EXPECTED behavior when in StopPending. It is not the root cause; it is a symptom of being stuck in StopPending.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/service.rs — run_loop_shutdown and tokio runtime shutdown
  found: >
    After run_loop breaks (either Ctrl+C or STOP_CONFIRMED), it calls:
    tokio::time::timeout(SHUTDOWN_TIMEOUT, run_loop_shutdown(ctx)).await (line 1024).
    SHUTDOWN_TIMEOUT = 10 seconds.

    If run_loop_shutdown takes longer than 10s, the timeout fires and the function returns Ok(())
    anyway (the Err(_) branch just logs an error). Then run_service continues to report STOPPED
    and exit.

    BUT: run_loop_shutdown contains MANY .await points with individual 5-second timeouts for
    various subsystems. The total worst-case shutdown time could exceed 10 seconds easily
    (file monitor + event loop + heartbeat + pipe1 + config + registry + origins + disk_enum +
    enc_check + device_watcher + DACL tasks + WFP + sync_watcher + print_enforcer + approval +
    UI kill + audit + correlator + ETW). Even with parallel awaits, sequential ones add up.
  implication: The 10-second SHUTDOWN_TIMEOUT may be too short for full graceful shutdown, but that would cause a forced exit, not a hang. A forced exit would eventually stop the service, not leave it stuck.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/protection.rs — harden_agent_process
  found: >
    The agent calls harden_agent_process() at startup (service.rs line 203), which applies a
    DENY ACE for Everyone on the process handle, blocking PROCESS_TERMINATE (0x0001).
    This prevents Task Manager / taskkill from terminating the agent.

    The PowerShell script's Stop-DlpAgentService function (line 224) calls:
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop

    Stop-Service -Force sends a STOP control to the SCM. If the service is already in
    StopPending and not accepting controls, -Force does NOT help — it just tries harder
    to send the control, but the service already received it.

    The script's fallback message (line 243) says:
    "To force-terminate: sc.exe stop $ServiceName && sc.exe delete $ServiceName"
    But sc.exe stop also just sends a control signal — it cannot terminate a service that
    ignores it. And the process DACL hardening prevents termination via TerminateProcess.
  implication: Once the service is stuck in StopPending, there is NO clean way to stop it from userland because (1) the SCM thinks it's already stopping, (2) the service won't accept another STOP, and (3) the process DACL prevents external termination.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/password_stop.rs — confirm_stop and STOP_CONFIRMED flag
  found: >
    confirm_stop() (line 968) is a no-op — it just logs "dlp-admin stop confirmed".
    The actual signalling is done by setting STOP_CONFIRMED atomic bool to true in
    handle_verification_result (line 465).

    BUT: there is a race condition window. handle_verification_result calls:
    clear_pending_request();
    FAILED_ATTEMPTS.store(0, Ordering::SeqCst);
    STOP_CONFIRMED.store(true, Ordering::Release);
    confirm_stop();

    If the run_loop polls is_stop_confirmed() AFTER clear_pending_request() but BEFORE
    STOP_CONFIRMED is set, it would see false and wait another 500ms. That's harmless.

    More critically: if the password verification thread panics between clear_pending_request()
    and STOP_CONFIRMED.store(), STOP_CONFIRMED would never be set, and the service would hang.
    There is no catch_unwind around the initiate_stop thread.
  implication: A panic in the password verification thread would leave the service permanently stuck with no recovery. This is a plausible root cause.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/password_stop.rs — try_fetch_hash_from_server and get_auth_hash
  found: >
    get_auth_hash() (line 581) is called from bcrypt_verify_against_server() which is called
    from handle_password_submit(). If get_auth_hash() returns Err (e.g. registry key missing,
    server unreachable, hash empty), handle_verification_result receives Err and calls
    maybe_abort_after_failure(attempt). If attempt >= MAX_ATTEMPTS (3), it calls abort_stop().

    BUT: if the FIRST attempt fails with an error (not wrong password), attempt = 1,
    maybe_abort_after_failure(1) does NOT abort. The UI would need to send 2 more failed
    attempts before abort_stop() is called. If the UI only sends one attempt and then
    the user waits, the service stays in StopPending until the 120s timeout fires.

    Wait — the timeout DOES fire and calls abort_stop(). So that's handled.
  implication: The timeout path handles slow failures. The hang must be something that prevents the timeout from firing OR prevents abort_stop() from working.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/password_stop.rs — abort_stop and cancel_stop
  found: >
    abort_stop() (line 975) calls:
    clear_pending_request();
    reset_stop_state();
    crate::service::revert_stop();

    cancel_stop() (line 985) does the exact same thing.

    revert_stop() (service.rs line 3335) calls:
    *SERVICE_STATE.lock() = ServiceState::Running;
    report_scm_status(ServiceState::Running, ServiceControlAccept::STOP | PAUSE_CONTINUE, Duration::ZERO);

    This SHOULD work. But what if SERVICE_STATE is already locked by another thread?
    Both SERVICE_STATE and SCM_HANDLE use parking_lot::Mutex, which is fair and should not deadlock.
  implication: The revert path looks correct. The hang is likely NOT in the revert logic itself.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/service.rs — run_loop after break
  found: >
    When STOP_CONFIRMED is true, run_loop breaks and calls:
    set_status(status_handle, ServiceState::StopPending, ServiceControlAccept::empty(), None)?;
    Then run_loop_shutdown(ctx) with 10s timeout.
    Then Ok(()) returns to run_service.

    run_service then does:
    rt.shutdown_timeout(Duration::from_secs(2));
    // ... subsystem shutdown ...
    set_status(&status_handle, ServiceState::Stopped, ServiceControlAccept::empty(), Some(Win32(0)))?;

    The critical question: what if rt.shutdown_timeout(2s) hangs? The tokio runtime shutdown
    waits for all spawned tasks to complete. If a task is stuck in a blocking operation
    (e.g. ReadFile on a named pipe, ConnectNamedPipeW, WTS call), shutdown_timeout will
    wait 2 seconds then force-abort remaining tasks. That should NOT hang forever.
  implication: The tokio shutdown timeout should not cause an infinite hang. The problem must be in a blocking std::thread that is NOT part of the tokio runtime.

- timestamp: 2026-06-10T17:18:00Z
  checked: dlp-agent/src/service.rs — blocking threads started in run_service
  found: >
    run_service starts several blocking std::threads that are NOT part of the tokio runtime:
    1. health_handle (line 230) — health_monitor::start()
    2. IPC pipe servers (line 238) — crate::ipc::start_all()
    3. chrome_handle (line 251) — Chrome pipe server, blocking ReadFile/ConnectNamedPipeW
    4. session_handle (line 265) — session_monitor::start(), WTSEnumerateSessionsW every 2s

    These threads are NEVER explicitly joined or shut down in run_service!
    After rt.shutdown_timeout(2s), run_service logs "shutting down subsystems" and then
    reports STOPPED. But the blocking threads (health monitor, IPC pipes, Chrome pipe,
    session monitor) are still running.

    The Chrome pipe server thread (chrome_handle) does a blocking ConnectNamedPipeW/ReadFile
    loop. If a client is connected and the pipe is in a read state, the thread will block
    until the client disconnects or sends data. There is no shutdown signal for this thread.

    Similarly, the IPC pipe servers (start_all) spawn threads that block on ReadFile.
    There is no evidence they are signalled to stop.

    The session_monitor thread polls WTSEnumerateSessionsW every 2 seconds. It may check
    some shutdown flag, but there is no explicit shutdown in run_service.
  implication: The blocking std::threads (especially Chrome pipe and IPC pipes) may prevent the process from exiting even after run_service returns. The SCM sees the service process is still alive, so it never transitions from StopPending to Stopped. THIS IS THE ROOT CAUSE.

## Eliminated

- hypothesis: Password challenge thread panics, leaving STOP_CONFIRMED unset
  evidence: No catch_unwind on the initiate_stop thread. If get_auth_hash() panics (e.g. bcrypt verify on malformed hash), the thread dies silently. However, the 120s timeout would still fire and call abort_stop() from the same thread, so a panic would skip the timeout too. This IS possible but less likely than the blocking thread issue.
  timestamp: 2026-06-10T17:18:00Z

- hypothesis: The service control handler doesn't report StopPending correctly
  evidence: report_scm_status IS called with 120s wait_hint. The SCM should honor this.
  timestamp: 2026-06-10T17:18:00Z

- hypothesis: Process DACL hardening prevents SCM from terminating the service
  evidence: The DACL hardening blocks PROCESS_TERMINATE from non-SYSTEM callers, but the SCM itself runs as SYSTEM and should be able to terminate. However, the real issue is the service process never exits because blocking threads keep it alive.
  timestamp: 2026-06-10T17:18:00Z

## Resolution

root cause: >
  After the password is verified and run_loop breaks, run_service performs tokio runtime
  shutdown (with 2s timeout) and then reports STOPPED to the SCM. However, several blocking
  std::threads started earlier in run_service are NEVER shut down or joined:

  1. Chrome pipe server thread (chrome_handle) — blocks indefinitely on ConnectNamedPipeW/ReadFile
  2. IPC pipe server threads (from ipc::start_all) — block indefinitely on ReadFile
  3. Health monitor thread (health_handle)
  4. Session monitor thread (session_handle)

  Because these threads remain alive, the process does not exit. The SCM sees the process
  is still running while the service status was reported as STOPPED, creating a mismatch.
  More critically, if any of these threads holds the process open, the service appears
  "stuck" in StopPending because the process never actually terminates, even though the
  main service logic has finished.

  Additionally, there is a secondary issue: the password_stop initiate_stop thread has no
  catch_unwind. If get_auth_hash() or bcrypt::verify() panics (e.g. on a malformed hash
  string), the thread aborts without calling abort_stop(), leaving the service permanently
  in StopPending with no timeout recovery.

fix: >
  1. CRITICAL: Add proper shutdown and join for all blocking std::threads in run_service.
     - Store chrome_handle, health_handle, session_handle in a structure accessible during shutdown.
     - Add shutdown signals (AtomicBool or channels) to the Chrome pipe server, IPC pipes,
       health monitor, and session monitor so they can break out of blocking loops.
     - Join all threads with a timeout before reporting STOPPED.

  2. HIGH: Wrap the initiate_stop thread body in std::panic::catch_unwind and call
     abort_stop() in the catch block to ensure the service never gets permanently stuck
     on a panic.

  3. MEDIUM: Increase SHUTDOWN_TIMEOUT from 10s to a value that accounts for all sequential
     subsystem shutdowns (e.g. 30s), or make run_loop_shutdown return a future that completes
     when all subsystems are done without an overall timeout.

  4. LOW: The PowerShell script's Stop-DlpAgentService uses Stop-Service -Force which is
     ineffective when the service is in StopPending. Update the script to detect StopPending
     and provide a proper force-kill path (e.g. using taskkill with SYSTEM privileges via
     psexec, or documenting the need to restart the machine).

verification: Pending — requires code changes and testing on a Windows host

files_changed:
  - dlp-agent/src/service.rs
  - dlp-agent/src/password_stop.rs
  - dlp-agent/src/ipc/mod.rs (or individual pipe modules)
  - dlp-agent/src/chrome/handler.rs
  - dlp-agent/src/health_monitor.rs
  - dlp-agent/src/session_monitor.rs
  - scripts/Manage-DlpAgentService.ps1
