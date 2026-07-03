---
status: investigating
trigger: "After dlp-agent service is killed, dlp_hook_dll.dll remains loaded in 97 processes instead of unloading via the cooperative unhook protocol."
created: 2026-07-03T00:00:00Z
updated: 2026-07-03T02:45:00Z
related_sessions:
  - dlp-agent-stop-hook-kill
---

## Current Focus

hypothesis: The agent shutdown path hits SHUTDOWN_TIMEOUT before request_unhook_from_injected can do meaningful work. The hook IPC server is terminated by the tokio timeout, blocking threads remain alive, and the process eventually aborts, leaving DLLs loaded in all 97 injected processes.
test: Verify ordering by moving request_unhook_from_injected earlier in run_loop_shutdown and/or making the cooperative unhook path independent of the tokio SHUTDOWN_TIMEOUT.
expecting: Either (a) injected processes receive UnhookCommand and self-unload, or (b) the root cause is confirmed as the timeout consuming the unhook budget.
next_action: Plan and implement fix: move unhook request to the start of shutdown and protect it from earlier subsystem timeouts.

## Symptoms

expected: After stopping dlp-agent, all injected processes unload dlp_hook_dll.dll within the watchdog timeout.
actual: 5 seconds after dlp-agent is killed, 97 processes still have dlp_hook_dll.dll loaded.
errors: No visible crash or error; DLL simply stays mapped.
reproduction: Kill dlp-agent service, wait 5 seconds, run `(get-Process | Where-Object { $_.Modules.ModuleName -contains "dlp_hook_dll.dll" }).Count`.
started: Reported during Phase 58.5 UAT Test 7.

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

## Eliminated

- hypothesis: Hook DLL crashes during self-unload and kills host processes
  evidence: The previous debug session (dlp-agent-stop-hook-kill.md) fixed a crash caused by unloading while the background thread was running. That fix is in place. The current symptom is DLL remaining loaded, not processes being killed.
  timestamp: 2026-07-03T00:00:00Z

- hypothesis: Control thread not running in most processes
  evidence: Cannot be ruled out entirely, but the log shows the agent never even reached the unhook request phase before the 35s timeout. Therefore the absence/presence of control threads is not the dominant cause in this observed failure. The primary failure mode is the timeout aborting shutdown before request_unhook_from_injected can run effectively.
  timestamp: 2026-07-03T02:40:00Z

## Resolution

root cause: ""
fix: ""
verification: ""
files_changed: []

## Gaps

- truth: "After stopping the dlp-agent service, any previously injected dlp-hook-dll.dll module unloads from a test process within the watchdog timeout."
  status: failed
  reason: "User reported: After 5 sec from dlp-agent is killed, the dlp_hook_dll.dll still not unhook from processes. Command `(get-Process | Where-Object { $_.Modules.ModuleName -contains 'dlp_hook_dll.dll' }).Count` return 97"
  severity: blocker
  test: 7
  root_cause: ""
  artifacts: []
  missing: []
  debug_session: ""
