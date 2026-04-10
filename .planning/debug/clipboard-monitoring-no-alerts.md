---
status: verifying
trigger: "clipboard-monitoring-no-alerts — copying sensitive content produces no audit event, agent tracing log is 0 bytes"
created: 2026-04-10T00:00:00Z
updated: 2026-04-10T16:00:00Z
---

## Current Focus

hypothesis: H8-CONFIRMED — tracing_appender::non_blocking worker thread silently discards every write via the Err(_) => {} branch in worker.rs:81, producing a 0-byte log file while the subscriber appears installed and healthy
test: Replace non_blocking with direct synchronous RollingFileAppender MakeWriter in both dlp-agent and dlp-user-ui; add debug_log probes around each init_logging step in service.rs
expecting: After rebuild/restart, stop-debug.log shows "init_logging: try_init OK" AND dlp-agent.log.<date> has non-zero bytes with startup messages
next_action: CHECKPOINT — user to rebuild release binaries, reinstall service, restart, copy credit card number, check logs

## Symptoms

expected: Copying "4111 1111 1111 1111" produces audit.jsonl entry with event_type=Alert, classification=T4, action_attempted=PASTE within 2 seconds
actual: Nothing happens. No audit.jsonl entry, no dlp-user-ui.log update (stale since Apr 3), dlp-agent.log.2026-04-10 is 0 bytes
errors: |
  - dlp-agent.log.2026-04-10: 0 bytes (service running since 13:58, confirmed by stop-debug.log)
  - dlp-user-ui.log: last modified Apr 3 (7 days stale — UI not running in long-lived mode)
  - audit.jsonl: last clipboard-related entry never existed; last entry Apr 10 09:46 file WRITE BLOCK
reproduction: |
  1. sc query dlp-agent (running)
  2. Copy "4111 1111 1111 1111" in interactive desktop session 1
  3. Tail audit.jsonl — no new line
  4. dlp-user-ui.log unchanged, dlp-agent.log.2026-04-10 is 0 bytes
started: Clipboard monitoring never produced a runtime alert. Tracing log went 0 bytes on 2026-04-10.

## Eliminated

- hypothesis: H1 — UI not spawned in long-lived session mode
  evidence: tasklist shows dlp-user-ui (PID 36524) running in session 1; stop-debug.log had stale info
  timestamp: 2026-04-10T00:10:00Z

- hypothesis: RUST_LOG filter blocking agent logs (service env has dlp_endpoint=debug)
  evidence: RUST_LOG is only set in current user bash shell (dlp_endpoint=debug), NOT in HKLM or HKCU registry. Service runs as LocalSystem with no RUST_LOG set. Filter uses default INFO level which should pass all INFO+ events.
  timestamp: 2026-04-10T00:15:00Z

- hypothesis: FILE_FLAG_NO_BUFFERING on pipe client causes write failures
  evidence: Integration tests pass using same send_clipboard_alert code path with FILE_FLAG_NO_BUFFERING. Windows docs state this is valid for named pipes.
  timestamp: 2026-04-10T00:20:00Z

- hypothesis: H3 — UI crashing before tracing is initialized
  evidence: No dlp-user-ui-crash.log exists; UI process (PID 36524) has 22MB working set and is alive; no crash file written by panic hook.
  timestamp: 2026-04-10T00:12:00Z

- hypothesis: H2 — WorkerGuard being dropped at end of init_logging (mem::forget variant)
  evidence: Fix applied in commit c038173: replaced mem::forget with OnceLock<WorkerGuard>. However the post-rebuild log file was STILL 0 bytes. This fix was necessary but not sufficient — the root cause is deeper than guard lifetime.
  timestamp: 2026-04-10T16:00:00Z

- hypothesis: H4 — subscriber already installed before init_logging (try_init returning Err)
  evidence: No "[init_logging ERROR]" or "init_logging: tracing subscriber already installed" line appears in stop-debug.log after the fix added that probe. Main call chain is: main() -> service_dispatcher::start -> ffi_entry (macro-generated) -> service_main -> run_service() -> init_logging(). No other try_init/set_global_default call exists in dlp-agent. H7 (second subscriber) therefore also eliminated.
  timestamp: 2026-04-10T16:00:00Z

- hypothesis: H9/H10 — RUST_LOG in service env, wrong LOG_DIR path, or SYSTEM permission issue
  evidence: System environment (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment) has no RUST_LOG key. LOG_DIR = r"C:\ProgramData\DLP\logs" matches observed file location. ICACLS shows NT AUTHORITY\SYSTEM:(I)(F) on both the directory and the dlp-agent.log.2026-04-10 file.
  timestamp: 2026-04-10T16:00:00Z

## Evidence

- timestamp: 2026-04-10T00:05:00Z
  checked: tasklist for dlp-agent.exe and dlp-user-ui.exe
  found: dlp-agent PID 104312 session 0; dlp-user-ui PID 36524 session 1 (32 threads)
  implication: Both processes running. H1 (UI not spawned) is ELIMINATED.

- timestamp: 2026-04-10T00:06:00Z
  checked: dlp-user-ui.log content (first and last entries)
  found: Apr 3 entries — UI ran in debug/redirected mode, wrote to stderr which was captured. Current run has no log because app.rs uses tracing_subscriber::fmt() (stderr only) and windows_subsystem=windows suppresses stderr in release builds.
  implication: UI LOGGING IS BROKEN — all UI tracing (clipboard_monitor warnings, pipe3 errors) is silently discarded at runtime.

- timestamp: 2026-04-10T00:07:00Z
  checked: app.rs tracing subscriber setup (lines 136-144)
  found: tracing_subscriber::fmt().init() — writes to stderr only, no file appender configured.
  implication: Fix needed: add rolling file appender to UI tracing subscriber.

- timestamp: 2026-04-10T00:08:00Z
  checked: service.rs init_logging() (lines 627-664)
  found: Uses non_blocking(file_appender) with mem::forget(_guard). Worker thread stays alive. File exists (0 bytes, created at 8:42 AM). Service started at 13:58 (per stop-debug.log). File should have appended entries after 13:58.
  implication: Agent tracing log is broken. Most likely cause: NonBlocking worker thread can't open/write the file, OR subscriber init() panicked and panic crossed extern "system" boundary silently.

- timestamp: 2026-04-10T00:09:00Z
  checked: environment variables (RUST_LOG at machine, user, process scope)
  found: RUST_LOG=dlp_endpoint=debug in current bash process only. Machine-level (HKLM) and user-level (HKCU) RUST_LOG not set. Service SYSTEM account gets no RUST_LOG.
  implication: Agent EnvFilter gets default INFO directive — all INFO+ events should pass. Filter is NOT the cause of 0-byte log.

- timestamp: 2026-04-10T00:11:00Z
  checked: ui_spawner.rs spawn_ui_in_session, get_session_user_token
  found: CreateProcessAsUserW called with user token from WTSQueryUserToken. No stdout/stderr redirect in STARTUPINFOW (hStdOutput/hStdError both null). lpDesktop = "WinSta0\\Default". Process creation flags = 0.
  implication: UI spawned correctly in interactive desktop. No output redirection — confirms UI stderr goes nowhere.

- timestamp: 2026-04-10T00:13:00Z
  checked: clipboard_monitor.rs message loop (PeekMessageW + WM_CLIPBOARDUPDATE check)
  found: PeekMessageW(None, 0, 0, PM_REMOVE) picks up all messages on the clipboard-monitor thread, including those to the registered hwnd. WM_CLIPBOARDUPDATE check is correct. Structure is sound.
  implication: Clipboard monitor logic is correct IF the monitor thread and iced run on separate threads. Confirmed: start() spawns a dedicated thread.

- timestamp: 2026-04-10T00:14:00Z
  checked: pipe3.rs send_clipboard_alert — open_pipe() uses FILE_FLAG_NO_BUFFERING
  found: Integration tests pass with this flag. FILE_FLAG_NO_BUFFERING is valid for named pipes per Windows docs. Not the cause of failure.
  implication: Pipe 3 client code is correct.

- timestamp: 2026-04-10T00:16:00Z
  checked: windows-service 0.8.0 define_windows_service! macro
  found: Generated ffi_entry is extern "system" fn, calls service_main_handler(arguments) directly — NO panic catching. If init_logging() panics, panic crosses extern "system" boundary = UB, typically kills the service thread silently. BUT service IS running (status=Running, stop-debug.log has run_loop entry), so service_control_handler::register DID succeed. This means run_service() got past init_logging() without panic.
  implication: init_logging() does NOT panic. The subscriber IS initialized. But writes go nowhere.

- timestamp: 2026-04-10T00:17:00Z
  checked: tracing_appender 0.2.4 non_blocking behavior with mem::forget
  found: mem::forget(_guard) leaks the WorkerGuard. The WorkerGuard Drop impl: (a) drops the sender (signaling channel close), (b) joins the worker thread. Forgetting the guard means: (a) sender is NOT dropped via guard (but the NonBlocking writer also holds a sender clone), (b) worker thread never joined. The worker thread runs: while let Ok(msg) = receiver.recv() { write(msg) }. With guard forgotten, one sender (in guard) is leaked, one sender (NonBlocking writer) is alive. Channel stays open. Worker thread keeps running. BUT: when mem::forget is called, the leaked sender's memory is never freed, so the channel capacity appears consumed? NO — mem::forget doesn't consume channel capacity, the sender value is simply never dropped.
  implication: Worker thread should be running and processing messages. YET log is 0 bytes. This suggests the worker thread fails silently when trying to write to the file — possibly due to a file lock, SYSTEM account permissions for a file that was already created by a different principal, or an internal tracing_appender bug.

- timestamp: 2026-04-10T16:00:00Z
  checked: Post-rebuild log state after commit c038173 (OnceLock fix)
  found: Binary mtimes confirmed new build (agent +47KB, UI +281KB). dlp-agent.log.2026-04-10 still 0 bytes, mtime unchanged at 08:42. dlp-user-ui.log.2026-04-10 created at 15:15 (new) but also 0 bytes. No "[init_logging ERROR]" line in stop-debug.log. stop-debug.log shows service ran from 15:15:07 to 15:17:21 normally.
  implication: OnceLock fix was necessary but insufficient. try_init() returned Ok (no error probe fired). Subscriber IS installed. But BOTH log files (agent and UI) stayed at 0 bytes despite non_blocking being used in both. Root cause is in the non_blocking worker thread itself.

- timestamp: 2026-04-10T16:00:00Z
  checked: tracing_appender 0.2.4 worker.rs source at ~/.cargo/registry
  found: Worker::worker_thread loop: on Err(_) from work() (i.e., IO error from write_all), the loop CONTINUES with a // TODO comment — the error is silently swallowed. The worker thread does not exit or signal the error. If every write_all to RollingFileAppender fails with an IO error, the file stays at 0 bytes permanently with no observable signal.
  implication: The non_blocking worker IS running but every write fails silently. The exact IO error is unknown but the behavior matches perfectly. Both agent (Session 0, LocalSystem) and UI (Session 1, user token) exhibit the same symptom — suggesting the issue is not session/token specific but is inherent to how non_blocking opens/writes files in this environment.

- timestamp: 2026-04-10T16:00:00Z
  checked: ICACLS on log directory and log files
  found: C:\ProgramData\DLP\logs: NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F). dlp-agent.log.2026-04-10: NT AUTHORITY\SYSTEM:(I)(F). dlp-user-ui.log.2026-04-10: NT AUTHORITY\SYSTEM:(I)(F), HUNGDINH-PC\nhdinh:(I)(F).
  implication: Permissions are not the cause. Both accounts have full control at both directory and file level.

- timestamp: 2026-04-10T16:00:00Z
  checked: System environment variables (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment)
  found: No RUST_LOG key present. No unusual vars that would affect tracing.
  implication: EnvFilter defaults to INFO correctly. Filter is not blocking events.

- timestamp: 2026-04-10T16:00:00Z
  checked: tracing_appender non_blocking default configuration
  found: NonBlockingBuilder::default() sets is_lossy=true and buffered_lines_limit=128_000. When is_lossy=true, try_send() is used — if channel is full, events are silently dropped. However the channel capacity of 128,000 lines makes overflow extremely unlikely for a service that emits a handful of log lines.
  implication: Lossy mode is not dropping events due to channel overflow. The failure is at the write_all layer inside the worker thread.

## Resolution

root_cause: tracing_appender::non_blocking 0.2.4 — the background writer thread silently discards all IO errors from write_all() via an unimplemented TODO branch (worker.rs:81-84: Err(_) => {}). The exact underlying IO error is unknown but reproducible: BOTH dlp-agent (Session 0, LocalSystem) and dlp-user-ui (Session 1, interactive user) produce 0-byte log files despite the subscriber being installed and try_init() returning Ok. Replacing non_blocking with a direct synchronous RollingFileAppender MakeWriter eliminates the worker thread and the channel entirely, making writes synchronous on the calling thread.
fix: |
  dlp-agent/src/service.rs:
  - Removed non_blocking() call and LOG_WORKER_GUARD static
  - RollingFileAppender used directly as MakeWriter (synchronous)
  - Added debug_log probes around each init_logging step for diagnostics
  dlp-user-ui/src/app.rs:
  - Removed non_blocking() call and LOG_WORKER_GUARD static
  - RollingFileAppender used directly as MakeWriter (synchronous)
verification: (awaiting human verification after rebuild/restart)
files_changed:
  - dlp-agent/src/service.rs
  - dlp-user-ui/src/app.rs
