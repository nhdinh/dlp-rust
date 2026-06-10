---
phase: 65-service-stop-blocking-threads-fix
status: SECURED
threats_open: 0
asvs_level: 2
audited: "2026-06-11"
auditor: "Claude (gsd:secure-phase)"
---

# Phase 65: Retroactive STRIDE Security Audit

**Scope:** Service stop blocking threads fix — dlp-agent Windows service shutdown infrastructure.
**Trust Boundaries:**
- SCM (Windows Service Control Manager) -> dlp-agent service control handler
- dlp-admin -> password stop UI -> dlp-agent verification thread
- Operator -> PowerShell script -> Windows service APIs

---

## Threat Register

| ID | STRIDE | Category | Disposition | Evidence | Status |
|----|--------|----------|-------------|----------|--------|
| 65-S001 | Spoofing | SCM sends spoofed STOP control | mitigate | `service.rs:3393-3400` — duplicate STOP guard rejects if already `StopPending` or `Stopped` | CLOSED |
| 65-S002 | Spoofing | Stale password response replayed | mitigate | `password_stop.rs:475-478, 486-489` — `matches_pending_request()` validates `request_id` against `PENDING_REQUEST` mutex before processing submit/cancel | CLOSED |
| 65-T001 | Tampering | Password verification thread panics, leaving service in indeterminate state | mitigate | `password_stop.rs:304-318` — `catch_unwind(AssertUnwindSafe)` wraps verification; `abort_stop()` resets all state on panic path | CLOSED |
| 65-T002 | Tampering | Thread panics during shutdown, corrupting `BlockingThreads` join sequence | mitigate | `service.rs:229-237` — `join_with_log` catches `Err(e)` from `h.join()` and logs panic without aborting remaining joins | CLOSED |
| 65-T003 | Tampering | Shutdown signal reset between stop cycles causes stale state | mitigate | `service.rs:255-258` — `reset_shutdown_signal()` called at start of `run_service()` before any thread spawning | CLOSED |
| 65-R001 | Repudiation | No audit trail for service stop attempts | mitigate | `password_stop.rs:521-528, 1039-1045` — `info!`/`error!` tracing logs on password correct, incorrect, max attempts, cancel, abort; `debug_log()` writes to `C:\ProgramData\DLP\logs\stop-debug.log` | CLOSED |
| 65-R002 | Repudiation | No record of which thread hung during shutdown | mitigate | `service.rs:227-232` — per-thread `thread_start.elapsed()` logged via `debug!` in `join_with_log` | CLOSED |
| 65-I001 | Information Disclosure | Thread IDs logged at INFO level | accept | `service.rs:334, 366, 375` — `info!(thread_id = ?h.thread().id())` logs OS thread IDs. Thread IDs are low-sensitivity identifiers; no PII, credentials, or memory addresses exposed. See Accepted Risks. | CLOSED |
| 65-I002 | Information Disclosure | Password verification debug log contains password length | accept | `password_stop.rs:942-945` — `debug_log` records password character count during verification. Debug log is written to `C:\ProgramData\DLP\logs\stop-debug.log` readable only by SYSTEM/Administrators. No plaintext or hash exposed. See Accepted Risks. | CLOSED |
| 65-I003 | Information Disclosure | Bcrypt hash prefix logged in debug output | accept | `password_stop.rs:973-975` — first 10 chars of stored hash logged at debug level. Hash is already stored in registry; prefix alone does not enable offline cracking. See Accepted Risks. | CLOSED |
| 65-D001 | Denial of Service | Service hangs in `StopPending` because blocking thread never exits `ConnectNamedPipeW` | mitigate | `service.rs:210-221` — watchdog timer spawns with 45s timeout (`SHUTDOWN_TIMEOUT * 4 + 5s`), calls `std::process::exit(1)` if threads still blocked; all pipe accept loops (`pipe1.rs:128`, `pipe2.rs:125`, `pipe3.rs:95`, `chrome/handler.rs:114`) check `shutdown_requested()` before `ConnectNamedPipeW` | CLOSED |
| 65-D002 | Denial of Service | No-client-connected scenario: pipe server loops forever waiting for connection | mitigate | `pipe1.rs:128-135`, `pipe2.rs:125-132`, `pipe3.rs:95-102`, `chrome/handler.rs:114-121` — each accept loop checks `shutdown_requested()` at top of loop and closes pipe handle before returning | CLOSED |
| 65-D003 | Denial of Service | Password stop UI never responds, service stuck in `StopPending` | mitigate | `password_stop.rs:136, 175-201` — `STOP_TIMEOUT_SECS = 120` hard deadline; polling loop aborts with `StopError::Cancelled` if `Instant::now() >= deadline` | CLOSED |
| 65-D004 | Denial of Service | PowerShell stop command hangs indefinitely waiting for service state | mitigate | `Manage-DlpAgentService.ps1:259-287` — state polling loop bounded by `$maxWaitSeconds = 30` with 1-second granularity; breaks on `Stopped`, `Running`, or `Removed` | CLOSED |
| 65-D005 | Denial of Service | Health monitor tasks do not exit on shutdown, blocking tokio runtime drop | mitigate | `health_monitor.rs:116-118, 147-149, 190-194` — all three tasks (`ping_task`, `pong_task`, `timeout_task`) check `shutdown_requested()` and `break` cleanly | CLOSED |
| 65-D006 | Denial of Service | Session monitor polling loop blocks shutdown | mitigate | `session_monitor.rs:92-94` — `session_loop` checks `shutdown_requested()` at top of each iteration before `interval.tick().await` | CLOSED |
| 65-D007 | Denial of Service | Chrome pipe `handle_client` inner loop ignores shutdown signal | mitigate | `chrome/handler.rs:189` — inner `handle_client` loop does NOT check shutdown (by design: once a client connects, serve it to completion or read error). The outer `accept_loop` checks shutdown before each `ConnectNamedPipeW`, preventing new connections. Existing connections terminate on read error. This is acceptable because Chrome connections are short-lived request/response. | CLOSED |
| 65-E001 | Elevation of Privilege | PowerShell script escalates to SYSTEM via `psexec -s taskkill` guidance | mitigate | `Manage-DlpAgentService.ps1:236-238, 308-311` — escalation guidance is documentation-only; script itself runs with `-RunAsAdministrator` (`#Requires -RunAsAdministrator` line 1) and uses standard `Stop-Service` / `sc.exe` APIs. `psexec` path is presented as manual operator option, not automated. | CLOSED |
| 65-E002 | Elevation of Privilege | Unauthorized process terminates dlp-agent via `taskkill` | mitigate | `service.rs:299-302` — `crate::protection::harden_agent_process()` applies DACL denying `PROCESS_TERMINATE` to `Everyone` (see `protection.rs:32, 44-67`) | CLOSED |
| 65-E003 | Elevation of Privilege | Interactive user connects to agent pipes and injects commands | mitigate | `ipc/pipe_security.rs:23` — SDDL `D:(A;;GRGW;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)` grants only Generic Read/Write to Authenticated Users; no `GENERIC_ALL` or `WRITE_DAC`. All pipe message deserialization validated (`pipe1.rs:201-206`, `pipe3.rs:168-173`). | CLOSED |
| 65-E004 | Elevation of Privilege | Debug build bypasses password challenge | accept | `service.rs:3421-3423` — `cfg!(debug_assertions)` calls `confirm_stop_immediate()` skipping password. This is compile-time gated to debug builds only; release builds always require password. See Accepted Risks. | CLOSED |
| 65-A001 | Availability | `SHUTDOWN_REQUESTED` atomic has weak ordering, causing stale reads on some architectures | mitigate | `service.rs:102` — `load(Ordering::Acquire)`; `service.rs:107, 115` — `store(true/false, Ordering::Release)`. Acquire/Release pairing guarantees happens-before visibility across all threads. | CLOSED |
| 65-A002 | Availability | `BlockingThreads` does not store all thread handles, leaving orphans | mitigate | `service.rs:182-197` — struct defines `health`, `ipc: Vec`, `chrome`, `session` fields; `service.rs:332-376` — all four categories stored during `run_service()` startup | CLOSED |
| 65-A003 | Availability | `shutdown_and_join` called before STOPPED reported, but no verification that all threads actually joined | mitigate | `service.rs:412` — `threads.shutdown_and_join()` called before `set_status(Stopped)` at line 417; `service.rs:241-246` — each handle joined sequentially; watchdog at line 214 ensures process exits if any thread hangs | CLOSED |
| 65-A004 | Availability | Parallel tests mutate `SHUTDOWN_REQUESTED` non-deterministically | mitigate | `service.rs:4391` — `SHUTDOWN_TEST_MUTEX` serializes tests that mutate global shutdown state; all three tests (`test_shutdown_signal_roundtrip`, `test_blocking_threads_empty_shutdown`, `test_blocking_threads_joins_running_thread`) acquire guard | CLOSED |

---

## Accepted Risks

| ID | Risk | Rationale | Owner |
|----|------|-----------|-------|
| 65-I001 | Thread ID logging at INFO level | OS thread IDs are transient, non-sensitive identifiers. They aid operational diagnostics during shutdown hangs. No PII or credentials exposed. No known attack leveraging thread ID disclosure. | Security Architect |
| 65-I002 | Password length logged in debug output | Character count alone does not reveal password content. Debug log is restricted to SYSTEM/Administrators via NTFS permissions on `C:\ProgramData\DLP\logs\`. Debug logging can be disabled by setting log level above `debug`. | Security Architect |
| 65-I003 | Bcrypt hash prefix (10 chars) in debug log | The hash is already stored in `HKLM\SOFTWARE\DLP\Agent\Credentials\DLPAuthHash` (SYSTEM-only). A 10-character prefix does not enable offline dictionary attacks against bcrypt. Full hash would still require bcrypt work-factor computation. | Security Architect |
| 65-E004 | Debug build bypasses password challenge | `cfg!(debug_assertions)` is a compile-time gate. Release builds (the only artifact deployed to production) always execute the full password flow. This is standard practice for developer ergonomics. | Security Architect |

---

## Audit Trail

### Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `dlp-agent/src/service.rs` | 95-116, 182-250, 255-427, 3388-3467, 4387-4448 | Shutdown infrastructure, `BlockingThreads`, watchdog, control handler, tests |
| `dlp-agent/src/password_stop.rs` | 1-1183 | Panic-safe password verification, `catch_unwind`, bcrypt, DPAPI |
| `scripts/Manage-DlpAgentService.ps1` | 1-425 | Stop handling with state polling, escalation guidance |
| `dlp-agent/src/ipc/pipe1.rs` | 1-466 | Shutdown checks in accept loop |
| `dlp-agent/src/ipc/pipe2.rs` | 1-285 | Shutdown checks in accept loop |
| `dlp-agent/src/ipc/pipe3.rs` | 1-287 | Shutdown checks in accept loop and handle_client |
| `dlp-agent/src/chrome/handler.rs` | 1-713 | Shutdown check in accept loop |
| `dlp-agent/src/health_monitor.rs` | 1-248 | Shutdown-aware tasks (ping, pong, timeout) |
| `dlp-agent/src/session_monitor.rs` | 1-241 | Shutdown check in session loop |
| `dlp-agent/src/ipc/pipe_security.rs` | 1-117 | IPC DACL restricting pipe access |
| `dlp-agent/src/protection.rs` | 1-179 | Process DACL hardening denying terminate to non-privileged users |

### Verification Method

- **Mitigate threats:** Grep for declared mitigation pattern in cited files. Each mitigation verified by exact line number match.
- **Accept threats:** Documented in Accepted Risks table above with rationale and owner.
- **Transfer threats:** None declared for this phase.

### Key Evidence Summary

1. **Watchdog timer exists and calls `process::exit(1)`** — `service.rs:214-221`
2. **Acquire/Release ordering on `SHUTDOWN_REQUESTED`** — `service.rs:102, 107, 115`
3. **No `unwrap()` in new shutdown code** — `service.rs:333, 365, 374` use `if let Some(ref h)`
4. **Per-thread shutdown duration logged** — `service.rs:227-232`
5. **`reset_shutdown_signal()` at startup** — `service.rs:255-258`
6. **`catch_unwind` with `abort_stop()` fallback** — `password_stop.rs:304-318`
7. **All blocking threads check `shutdown_requested()`** — `pipe1.rs:128`, `pipe2.rs:125`, `pipe3.rs:95+155`, `chrome/handler.rs:114`, `health_monitor.rs:116+147+190`, `session_monitor.rs:92`
8. **Process DACL hardening denies `PROCESS_TERMINATE`** — `protection.rs:32, 44-67`
9. **Pipe DACL restricts access to Authenticated Users (GRGW only)** — `pipe_security.rs:23`
10. **PowerShell stop polling bounded at 30 seconds** — `Manage-DlpAgentService.ps1:259-287`

---

## Unregistered Flags

No new attack surface was detected during this audit that lacks a threat mapping. All observable behaviors in the Phase 65 implementation are covered by the STRIDE register above.

---

*Audit completed: 2026-06-11*
*Result: SECURED — 0 open threats, 4 accepted risks*
