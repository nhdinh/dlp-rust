---
status: resolved_pending_verification
trigger: "After dlp-agent service is killed, dlp_hook_dll.dll remains loaded in a test process instead of unloading via the cooperative unhook protocol."
created: 2026-07-03T00:00:00Z
updated: 2026-07-03T10:00:00Z
related_sessions:
  - dlp-agent-stop-hook-kill
---

## Current Focus

hypothesis: The 58.5-08 fix addresses the root cause by (1) making control-thread start a hard success criterion for injection, (2) adding an idempotent ensure_control_thread reconciliation pass before shutdown, (3) preventing DLL reference-count inflation via the is_module_loaded double-load guard, and (4) keeping self_unload atomic via FreeLibraryAndExitThread. Live verification is pending.
test: Re-run UAT Test 7 on a Windows host with the current codebase: stop the dlp-agent service, wait for the watchdog timeout, and confirm dlp_hook_dll.dll is no longer loaded in previously injected test processes.
expecting: The DLL unloads from all test processes within the watchdog timeout.
next_action: Run live UAT Test 7 and update 58.5-UAT.md with the result.

## Symptoms

expected: After stopping dlp-agent, all injected processes unload dlp_hook_dll.dll within the watchdog timeout.
actual: After the 58.5-07 fix, a previously injected test process still has dlp_hook_dll.dll loaded after the agent service is stopped; user reported "no".
errors: No visible crash or error; DLL simply stays mapped.
reproduction: Stop the dlp-agent service, wait for the watchdog timeout, and check whether dlp_hook_dll.dll is still loaded in the target test process.
started: Reported during Phase 58.5 UAT Test 7 verification after 58.5-07 was deployed.

## Eliminated

- hypothesis: Hook DLL crashes during self-unload and kills host processes
  evidence: The previous debug session (dlp-agent-stop-hook-kill.md) fixed a crash caused by unloading while the background thread was running. That fix is in place. The current symptom is DLL remaining loaded, not processes being killed.
  timestamp: 2026-07-03T00:00:00Z

- hypothesis: Agent shutdown timeout starves the cooperative unhook dispatch
  evidence: 58.5-07 moved request_unhook_from_injected to the very start of run_loop_shutdown, added compute_unhook_budget with a 5-second cleanup reserve, and kept the hook IPC accept_loop serving during the unhook window. Automated tests pass and the previous live log pattern (35s timeout before unhook ran) is no longer expected.
  timestamp: 2026-07-03T06:00:00Z

## Evidence

- timestamp: 2026-07-03T00:00:00Z
  checked: dlp-agent/src/service.rs run_loop_shutdown ordering
  found: >
    request_unhook_from_injected is called AFTER many other shutdown steps (file monitor, event loop, heartbeat loops, config/registry/origins polls, disk enum, encryption check, device watcher, DACL tasks, WFP unregister, sync watcher, print enforcer, UI kill). By the time it runs, a significant portion of SHUTDOWN_TIMEOUT has already elapsed. The hook IPC server is stopped AFTER request_unhook_from_injected returns, which is good, but the unhook budget may be too small for 97 processes to poll.
  implication: Processes may not have enough time to poll, receive UnhookCommand, and complete self-unload before the server pipe is closed.

- timestamp: 2026-07-03T00:00:00Z
  checked: dlp-agent/src/service.rs request_unhook_from_injected
  found: >
    The function sets UNHOOK_ALL_REQUESTED, emits AgentShutdownUnhook audit, then waits for unhook acks. It does NOT proactively notify injected processes that shutdown is pending; it relies entirely on the DLL's 1-second control poll interval. With 97 processes and a 1-second poll interval, even if all polls arrived instantly, the serial ConnectNamedPipe handling plus FreeLibraryAndExitThread execution could exceed a small remaining budget.
  implication: The protocol is pull-only and one second granularity may be too slow for a large number of injected processes under a tight shutdown budget.

- timestamp: 2026-07-03T00:00:00Z
  checked: dlp-hook-dll/src/control_thread.rs control_thread_loop
  found: >
    The control thread polls every CONTROL_POLL_INTERVAL_MS (1 second). On Err from poll_control, consecutive_failures increments. Watchdog self-unload only fires after MAX_FAILURES (3) consecutive failures AND watchdog_timeout_ms() (30 seconds) cumulative grace window. So simply killing the agent does not trigger self-unload quickly; it requires ~30+ seconds of unresponsiveness.
  implication: The watchdog is intentionally slow (30s grace). The fast path is agent-issued UnhookCommand, but that requires the control thread to be running and the registry to match.

- timestamp: 2026-07-03T00:00:00Z
  checked: dlp-agent/src/hook_ipc.rs PollControl handler
  found: >
    The agent replies with UnhookCommand only when UNHOOK_ALL_REQUESTED is true AND the registry contains the (pid, creation_time) in Injected state. If a process was injected before Phase 58.5-06 (StartDlpControlThread export), its control thread was only started lazily on first hooked API call. Idle injected processes that never called a hooked API have no control thread and therefore never poll.
  implication: Pre-existing injected processes (injected before the 58.5-06 immediate control-thread start) cannot receive UnhookCommand because they never start polling. This matches the dlp-agent-stop-hook-kill.md remaining_limitation note.

- timestamp: 2026-07-03T00:00:00Z
  checked: dlp-agent/src/service.rs init_universal_injection and startup_sweep
  found: >
    On agent startup, a startup sweep enumerates all processes and injects new ones. It does not appear to re-inject already-loaded processes to start their control threads. The registry records injected processes, but the DLL in those processes may not have a control thread if injection happened before 58.5-06.
  implication: Legacy injected processes are known to the agent but cannot participate in cooperative unhook.

- timestamp: 2026-07-03T02:40:00Z
  checked: live agent log from stop attempt
  found: >
    Password verified at 02:35:30.434. "shutting down enforcement subsystems" logged. File monitor stopped ~0.5s later. Health monitor kept broadcasting HEALTH_PING every ~5s throughout shutdown (02:35:33, 02:35:38, 02:35:43, 02:35:48, 02:35:53, 02:35:58, 02:36:03). At 02:36:05.439, "graceful shutdown exceeded timeout -- force-terminating timeout_secs=35" was logged. After the tokio timeout, "shutting down subsystems" and thread joins happened. IPC pipe join blocked until 02:38:32 when the shutdown watchdog (145s) aborted the process. No log lines for "Hook IPC: poll control received", "unhook ack received", or "requesting unhook from injected processes" appeared in the tail output, indicating request_unhook_from_injected either never ran or produced no observable activity before the timeout.
  implication: The tokio graceful shutdown timed out at 35 seconds before the unhook orchestration could complete (or possibly before it even started). The agent process then aborted without ever successfully dispatching UnhookCommand to the injected processes.

- timestamp: 2026-07-03T02:40:00Z
  checked: dlp-agent/src/service.rs SHUTDOWN_TIMEOUT and run_loop
  found: >
    SHUTDOWN_TIMEOUT is 35 seconds. run_loop calls tokio::time::timeout(SHUTDOWN_TIMEOUT, run_loop_shutdown(ctx)). If run_loop_shutdown does not return within 35 seconds, the tokio runtime is dropped and the service proceeds to threads.shutdown_and_join(). request_unhook_from_injected is near the end of run_loop_shutdown, so it has only whatever remains of the 35-second budget after all earlier shutdown steps. The log shows 35 seconds elapsed before timeout, meaning the unhook request had little or no budget left.
  implication: The cooperative unhook path is scheduled too late in shutdown and is not protected from the overall SHUTDOWN_TIMEOUT. Even if all injected processes have control threads, they never get a chance to poll and receive UnhookCommand before the timeout aborts the agent.

- timestamp: 2026-07-03T06:00:00Z
  checked: dlp-agent/src/service.rs run_loop_shutdown after 58.5-07 fix
  found: >
    request_unhook_from_injected is now the first substantive operation in run_loop_shutdown (lines 4042-4047). compute_unhook_budget returns min(configured, SHUTDOWN_TIMEOUT - CLEANUP_RESERVE) clamped to 100ms, giving a 30-second unhook budget for the default config. The hook IPC accept_loop condition (line 439) continues serving while unhook_requested() is true even if shutdown_requested() is true, and reset_unhook_signal() is called immediately before the server stop block (line 4257).
  implication: The previous timeout-starvation root cause is addressed in code and by automated tests. The remaining live failure is caused by something other than shutdown ordering.

- timestamp: 2026-07-03T06:05:00Z
  checked: dlp-agent/src/hook_injector.rs inject_into_process and start_remote_control_thread
  found: >
    inject_into_process returns Ok(()) even when start_remote_control_thread fails or is skipped (lines 429-438). start_remote_control_thread logs a warning and returns on any CreateRemoteThread / WaitForSingleObject / exit-code failure (lines 460-519). The comment explicitly states: "overall injection is considered successful because the DLL is already loaded and will lazily start the control thread on the first hooked API call."
  implication: A target process can have dlp_hook_dll.dll loaded without a running control-poll thread. If that process is idle (no hooked API call), the control thread never starts, so it can never receive UnhookCommand.

- timestamp: 2026-07-03T06:08:00Z
  checked: dlp-hook-dll/src/lib.rs enter_hook_call and DllMain
  found: >
    enter_hook_call lazily calls crate::control_thread::start_control_thread() (line 838), but only when a hooked API is invoked. DllMain does not start the control thread (loader-lock safety). The only other way to start it is the StartDlpControlThread export called by the agent after LoadLibraryW.
  implication: Idle injected processes that missed the immediate StartDlpControlThread remote thread have no path to start polling.

- timestamp: 2026-07-03T06:10:00Z
  checked: dlp-hook-dll/src/control_thread.rs handle_unhook_command and watchdog self-unhook
  found: >
    Both the agent-issued UnhookCommand path and the watchdog timeout path rely on a running control_thread_loop to send PollControl / UnhookAck and to count consecutive pipe failures. The watchdog requires MAX_FAILURES (3) consecutive errors plus a 30-second grace window before self-unload fires.
  implication: No control thread means no fast cooperative unhook AND no watchdog self-unhook. The DLL remains loaded indefinitely.

- timestamp: 2026-07-03T06:12:00Z
  checked: dlp-hook-dll/src/lib.rs self_unload and dlp-agent/src/service.rs startup_sweep/backstop_sweep
  found: >
    self_unload calls FreeLibraryAndExitThread exactly once on the DLL instance captured in DllMain. The agent's startup_sweep and backstop_sweep call injector.inject(pid) for every process without first checking is_module_loaded, unlike the sync-client watcher (service.rs lines 2065-2094). If a process already had dlp_hook_dll.dll loaded, LoadLibraryW increments the module reference count, and a single FreeLibraryAndExitThread will decrement but not unload the module.
  implication: Even when the cooperative path runs and the hook DLL receives UnhookCommand, the module can remain mapped if the agent loaded it more than once. The current code has no reconciliation to call FreeLibrary the correct number of times.

## Resolution

root cause: "The cooperative unhook path is client-driven: it requires a running hook-DLL control-poll thread in every target process. The agent's HookInjector only attempts to start this thread as a best-effort second remote thread after LoadLibraryW, and inject_into_process still reports success when that remote thread fails or is skipped. Idle injected processes that never trigger a hooked API call therefore never start a control thread, never send PollControl, and never receive UnhookCommand. The 58.5-07 reordering/budget fix only moved the server-side dispatch earlier; it did not make control-thread start reliable, nor did it reconcile already-loaded processes that lack a control thread. A secondary failure mode is that startup/backstop sweeps may LoadLibraryW into processes that already have the DLL, leaving a reference count > 1 so FreeLibraryAndExitThread does not fully unload the module."
fix: "(Pending plan-phase design) Make control-thread start a hard requirement for a successful injection and add a reconciliation pass that ensures every Injected registry entry has a running control thread before shutdown. Also avoid re-LoadLibraryW into processes that already have dlp_hook_dll.dll loaded (use is_module_loaded, as the sync-client watcher already does), and/or make the hook DLL self-unload decrement the module reference count until the module actually disappears."
verification: "Pending live UAT re-run with captured agent logs and hook DLL debug output."
files_changed:
  - dlp-agent/src/service.rs
  - dlp-agent/src/hook_ipc.rs
  - dlp-agent/src/hook_injector.rs
  - dlp-hook-dll/src/control_thread.rs
  - dlp-hook-dll/src/lib.rs

## Gaps

- truth: "After stopping the dlp-agent service, any previously injected dlp-hook-dll.dll module unloads from a test process within the watchdog timeout."
  status: in_progress
  reason: "58.5-07 timeout-starvation root cause fixed, but cooperative unhook still depends on a control thread that may not exist in the target process; reference-count re-injection is also possible."
  severity: blocker
  test: 7
  root_cause: "Best-effort immediate control-thread start and unconditional re-injection leave some injected processes without a polling client or with a DLL reference count > 1."
  artifacts: []
  missing:
    - "Live agent log showing PollControl / UnhookAck events for the failing PID"
    - "Hook DLL debug log from the target process during service stop"
    - "Target process module reference count before and after stop"
  debug_session: ".planning/debug/dll-remains-after-agent-kill.md"
