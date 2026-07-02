---
status: resolved
trigger: "When stopping dlp-agent service, the processes which hooked by dlp_hook_dll.dll will be killed, included claude, dlp-server,.... This is not as expected"
created: 2026-07-02T00:00:00Z
updated: 2026-07-02T00:00:00Z
related_sessions:
  - dlp-agent-stop-001
---

## Current Focus

hypothesis: The hook DLL unloads itself (FreeLibraryAndExitThread) while its background thread is still running; the unmapped DLL code then faults and kills the host process.
test: Review dlp-hook-dll self-unload, background thread lifecycle, and agent unhook orchestration.
expecting: Confirm that no hook-DLL thread is shut down before self_unload, and that the agent does not terminate hooked processes itself.
next_action: Verify fix location and present options

## Symptoms

expected: dlp-agent service stops and dlp_hook_dll.dll unhooks from processes
actual: Some processes are killed, and many processes are still hooked (not yet released). Checked with `Get-Process | Where-Object { $_.Modules.ModuleName -contains "dlp_hook_dll.dll" } | Select-Object Id, Name, Path`
errors: Processes that should remain alive (Claude, dlp-server, etc.) are terminated during service stop
reproduction: Run the PowerShell stop script (`Manage-DlpAgentService.ps1 -Action Stop`)
started: Unknown when first broke; reported now

## Evidence

- timestamp: 2026-07-02T00:00:00Z
  checked: dlp-hook-dll/src/lib.rs — unhook_all_internal and self_unload
  found: >
    unhook_all_internal() restores IAT entries and unpatches ntdll stubs, but it never
    shuts down the background thread started by start_background_thread().
    self_unload() then calls FreeLibraryAndExitThread while the background thread is
    still alive and will return into DLL code after WaitForSingleObject timeouts.
  implication: Unmapping the DLL image while a DLL-owned thread is still executing in it causes an access violation in the host process, which Windows terminates.

- timestamp: 2026-07-02T00:00:00Z
  checked: dlp-hook-dll/src/control_thread.rs — handle_unhook_command and watchdog self-unhook
  found: >
    Both the AgentShutdown path (handle_unhook_command) and the watchdog timeout path
    call unhook_all_internal() and then, on success, call crate::self_unload().
    Neither path calls shutdown_background_thread() before freeing the DLL image.
  implication: Every injected process that successfully receives and processes an UnhookCommand during service stop is at risk of being killed by the resulting crash.

- timestamp: 2026-07-02T00:00:00Z
  checked: dlp-agent/src/service.rs — request_unhook_from_injected
  found: >
    The agent only sets UNHOOK_ALL_REQUESTED and waits for PollControl/UnhookAck.
    It emits audit events for failures but does not call TerminateProcess or any
    other host-killing API for processes that fail to unhook.
  implication: The process deaths are not caused by the agent deliberately killing hosts; they originate on the hook-DLL side during self-unload.

- timestamp: 2026-07-02T00:00:00Z
  checked: dlp-agent/src/hook_injector.rs and dlp-hook-dll/src/control_thread.rs
  found: >
    StartDlpControlThread is only started automatically at the moment of DLL injection
    (Phase 58.5). There is no agent-side sweep that starts control threads in processes
    that were injected before this mechanism existed.
  implication: Idle injected processes that never started a control thread cannot poll for UnhookCommand and therefore remain hooked after service stop.

## Eliminated

## Resolution

root cause: >
  The hook DLL's cooperative self-unload path (dlp-hook-dll/src/control_thread.rs)
  called FreeLibraryAndExitThread in `handle_unhook_command` and in the watchdog
  timeout path without first stopping the hook DLL background thread. The
  background thread, started lazily from the trampoline hot path, was still
  executing DLL code (sleeping in WaitForSingleObject and returning to
  `background_thread_loop`). When `FreeLibraryAndExitThread` unmapped the DLL
  image, that thread faulted on return, producing an access violation that
  killed the host process. Active injected processes such as Claude and
  dlp-server that polled during shutdown received `UnhookCommand`, unhooked
  themselves, and then crashed during unload.

fix: >
  In `dlp-hook-dll/src/control_thread.rs`, both `handle_unhook_command` and the
  watchdog self-unhook path now call
  `crate::background_thread::shutdown_background_thread()` *before* calling
  `unhook_all_internal()` or `self_unload()`. `shutdown_background_thread()` was
  extended to return a `bool` indicating whether the thread exited within its
  join timeout. If the background thread cannot be stopped, the DLL remains
  loaded (and, in the watchdog path, remains hooked) rather than freeing the
  image while a DLL-owned thread is still running. This prevents the host
  process crash.

verification: >
  - `cargo check -p dlp-hook-dll` passed
  - `cargo check -p dlp-agent` passed
  - `cargo clippy --all-targets -p dlp-agent -p dlp-hook-dll -- -D warnings` passed
  - `cargo fmt --check -p dlp-agent -p dlp-hook-dll` passed
  - `cargo test -p dlp-hook-dll --lib` passed (343 passed)
  - `cargo test -p dlp-agent --lib` passed (923 passed)
  - `cargo test -p dlp-agent --test hook_ipc_integration` passed (17 passed)
  - Live Windows service stop / DLL unload test pending (requires physical/VM endpoint)

files_changed:
  - dlp-hook-dll/src/control_thread.rs
  - dlp-hook-dll/src/background_thread.rs

remaining_limitation: >
  Idle injected processes that never started a hook-DLL control thread (e.g.,
  pre-Phase 58.5 injections) still cannot receive `UnhookCommand` and will
  remain hooked until they exit. This is a separate coverage gap, not a crash.
