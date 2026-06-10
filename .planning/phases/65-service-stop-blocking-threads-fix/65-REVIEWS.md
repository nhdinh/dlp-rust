---
phase: 65
reviewers: [codex, opencode]
reviewed_at: 2026-06-10T10:53:42Z
plans_reviewed:
  - 65-01-PLAN.md
  - 65-02-PLAN.md
  - 65-03-PLAN.md
  - 65-04-PLAN.md
---

# Cross-AI Plan Review — Phase 65

## Codex Review (gpt-5.5)

### Summary

The plans identify the right root cause, but the current design is not sufficient to guarantee service shutdown. The biggest flaw is assuming `AtomicBool` polling can stop threads blocked inside `ConnectNamedPipeW` or `ReadFile`. It cannot, unless those calls return. A shutdown flag checked only between accepts will not wake a thread already blocked in a named-pipe wait, so `join()` can still hang forever and the phase goal may remain unmet. There is also a serious ordering risk in Plan 65-04: requesting global shutdown immediately in the service Stop control path could interfere with password verification and cancellation semantics.

---

### Plan 65-01: Shutdown Signal Infrastructure + Thread Handle Storage

#### Strengths

- Centralizing shutdown state is a reasonable foundation.
- Storing `JoinHandle<()>` ownership in the service runtime is the right direction.
- Joining before reporting `STOPPED` matches SCM expectations.
- `Option<JoinHandle<()>>` is a practical pattern for one-shot joins.
- Keeping this in `service.rs` avoids spreading ownership across unrelated modules.

#### Concerns

- **HIGH:** `std::thread::JoinHandle::join()` has no timeout. If any thread remains blocked in `ConnectNamedPipeW`, `ReadFile`, WTS polling, or an internal loop, the service can still hang forever.
- **HIGH:** Atomic polling alone does not wake blocking Win32 calls. The plan needs an explicit wake/cancel strategy.
- **HIGH:** "Join before STOPPED" is correct, but without bounded joins this risks replacing the current StopPending hang with another StopPending hang.
- **MEDIUM:** A global static shutdown flag must be reset at service startup, especially for tests or any in-process restart-style execution.
- **MEDIUM:** `SeqCst` is safe but probably stronger than needed. `Acquire`/`Release` would be enough for a boolean shutdown signal, though this is not a major issue.
- **MEDIUM:** If `ipc::start_all()` currently has callers besides `run_service()`, changing it to return handles may have wider compile/API impact.
- **LOW:** The plan does not specify logging around per-thread shutdown duration, which would be useful for diagnosing future hangs.

#### Suggestions

- Add a bounded shutdown coordinator instead of directly calling `join()` serially.
- Each blocking thread should have either:
  - a cancellable/blocking primitive,
  - a wake mechanism, such as connecting a local dummy client to each pipe to unblock `ConnectNamedPipeW`,
  - overlapped I/O plus cancellation,
  - or `CancelSynchronousIo` against the target thread handle if using synchronous Win32 I/O.
- Track thread names and shutdown deadlines so logs can say exactly which thread failed to exit.
- Reset `SHUTDOWN_REQUESTED.store(false, ...)` at the beginning of service startup.
- Define behavior if a thread does not exit within the shutdown budget: log critical details and decide whether to report `STOPPED`, abort, or continue waiting. The plan currently implies "wait forever."

#### Risk Assessment

**HIGH.** The ownership model is good, but the shutdown mechanism is incomplete for blocking Win32 pipe threads. As written, it may not fix the StopPending hang.

---

### Plan 65-02: IPC Pipe Shutdown Signal

#### Strengths

- Checking shutdown between accept iterations is useful for idle/recycled loops.
- Letting in-flight requests complete preserves existing pipe protocol behavior.
- Minimal protocol impact and no new dependencies.

#### Concerns

- **HIGH:** This does not stop a thread currently blocked in `ConnectNamedPipeW`. If no client connects after shutdown, the thread never observes the flag.
- **HIGH:** It also does not address blocking `ReadFile` inside `handle_client`. A connected but silent client could keep the thread alive.
- **MEDIUM:** Closing the pipe handle only after observing shutdown does not help if the thread is blocked before it can observe shutdown.
- **MEDIUM:** If multiple pipe instances are created inside the loop, shutdown needs clear ownership of which handle is closed and when.
- **LOW:** Returning `Ok(())` on shutdown is fine, but logs should distinguish intentional shutdown from client disconnect or I/O failure.

#### Suggestions

- Add an explicit wake path per pipe during shutdown. Common options:
  - connect a local client to each pipe to unblock `ConnectNamedPipeW`,
  - use overlapped named-pipe I/O with an event that can be signalled,
  - or use a cancellation API appropriate for the blocked thread.
- Add shutdown checks before and after client handling.
- Consider read timeouts or cancellable reads for `handle_client`, otherwise shutdown can still wait on inactive clients.
- Add tests or a manual verification script that stops the service while no IPC clients are connected.

#### Risk Assessment

**HIGH.** This plan does not actually guarantee pipe server shutdown. It only works when a connection happens after shutdown is requested.

---

### Plan 65-03: Chrome + Health Monitor + Session Monitor Shutdown

#### Strengths

- Health monitor changes are directionally sound: async tasks can naturally observe a shutdown flag at interval boundaries.
- Session monitor polling every 2 seconds should exit quickly if shutdown is checked inside the loop.
- Keeping Chrome behavior aligned with IPC pipe behavior is consistent.

#### Concerns

- **HIGH:** Chrome pipe server has the same `ConnectNamedPipeW` problem as IPC. Polling before accept does not wake a blocked accept.
- **MEDIUM:** `tokio::join!` only completes when all tasks exit. If any health task awaits something other than `interval.tick()` or blocks internally, the thread may still hang.
- **MEDIUM:** Session monitor depends on whether `WTSEnumerateSessionsW` is bounded. If it can block or hang under Windows service/session edge cases, polling alone is not enough.
- **LOW:** Checking shutdown "before tick" means the task may wait up to one interval before exiting. Likely acceptable, but should be counted in the 10-second shutdown budget.

#### Suggestions

- Treat Chrome pipe shutdown the same as IPC: add a real unblock/cancel mechanism.
- For health monitor tasks, prefer `tokio::select!` between interval work and a shutdown notification if possible. With only std allowed, polling is acceptable, but make every loop path check it.
- Make sure each health task exits independently and does not wait on a channel receive/send forever.
- Add tracing at task exit so shutdown logs confirm all three health tasks completed.
- Verify session monitor shutdown latency under no-user-session and locked-session conditions.

#### Risk Assessment

**MEDIUM-HIGH.** Health/session changes are likely adequate if loops are truly interval-bound. Chrome remains a high-risk blocker because named-pipe accept cannot be stopped by polling alone.

---

### Plan 65-04: Panic Safety + PowerShell Stop Handling

#### Strengths

- `catch_unwind` around the password verification thread is the right mitigation for preventing silent thread death.
- Calling `abort_stop()` on panic aligns with the requirement to avoid orphaning StopPending.
- Improving PowerShell behavior is valuable because this bug has poor operational recovery due to process hardening.
- Testing the panic path is important and should be included.

#### Concerns

- **HIGH:** Calling `request_shutdown()` immediately in the service control handler's Stop arm is probably wrong. Password verification has not succeeded yet. If the stop is cancelled or fails, the service must return to `Running`; global shutdown may already have torn down IPC, health, Chrome, and session threads.
- **HIGH:** Adding `shutdown_requested()` to the password polling loop can conflict with the above. If Stop sets shutdown immediately, the verification thread may exit/abort before the user can complete password verification.
- **HIGH:** `AssertUnwindSafe` is acceptable only if the closure does not leave shared mutable state in a logically corrupted state. The plan should specify exactly what is captured.
- **MEDIUM:** `catch_unwind` does not catch aborting panics if the binary is built with `panic = "abort"`.
- **MEDIUM:** The test "catch_unwind calls abort_stop on panic" may be hard if `abort_stop()` mutates global service state or talks to SCM directly. The plan should introduce a test seam without changing production behavior too much.
- **MEDIUM:** PowerShell guidance recommending `psexec -s taskkill /F` is operationally useful but should be phrased carefully. It is destructive and depends on Sysinternals being installed.
- **LOW:** The script should distinguish timeout, access denied, missing service, wrong password/cancel, and already stopped states.

#### Suggestions

- Do not set the global shutdown flag when StopPending begins. Split the lifecycle:
  - `stop_requested/password_pending`
  - `stop_authorized`
  - `shutdown_requested`
- Only request shutdown after password verification succeeds.
- On wrong password/cancel/panic, call `abort_stop()` and ensure the global shutdown flag remains false or is reset before reporting `Running`.
- Wrap only the verification body in `catch_unwind`, and ensure the panic path always logs and aborts stop.
- Consider a helper like `run_verification_with_abort_on_unwind(...)` that can be unit-tested without SCM.
- PowerShell should wait for final state and report:
  - stopped successfully,
  - returned to running,
  - still StopPending after timeout,
  - failed due to permissions/service missing.

#### Risk Assessment

**HIGH.** Panic safety is necessary, but the proposed shutdown ordering risks breaking the required cancellation behavior. This needs redesign before implementation.

---

### Codex: Cross-Plan Risks

- **HIGH:** AtomicBool polling is not enough for synchronous named-pipe servers. This is the central technical gap.
- **HIGH:** Shutdown authorization and shutdown execution are conflated. The service should not start tearing down worker threads until the password stop is approved.
- **HIGH:** Blocking joins can still hang indefinitely. The plan needs a bounded strategy.
- **MEDIUM:** Tests should include "no clients connected" pipe shutdown, not just signal propagation.
- **MEDIUM:** Global static state can leak between tests unless explicitly reset.
- **MEDIUM:** The shutdown timeout budget should be allocated per subsystem or enforced globally; otherwise serial waits can exceed the advertised 10 or 30 seconds.
- **LOW:** `SeqCst` is conservative but acceptable.

### Codex: Recommended Changes Before Execution

1. Redesign shutdown state into at least two phases: stop requested/auth pending vs shutdown authorized.
2. Add a real unblock/cancel mechanism for named-pipe threads.
3. Replace unbounded direct joins with bounded join coordination and clear timeout behavior.
4. Add explicit tests/manual verification for:
   - stop with no IPC/Chrome clients connected,
   - stop with a connected but idle client,
   - wrong password/cancel returns to Running,
   - panic in verification returns to Running,
   - all worker threads exit before STOPPED.
5. Make PowerShell report final service state instead of only command success/failure.

### Codex: Overall Risk Assessment

**HIGH.** The plans target the correct failure mode and have a good ownership direction, but the current AtomicBool-plus-polling design does not reliably interrupt the actual blocking operations causing the hang. The phase should not proceed as written until named-pipe cancellation and stop authorization ordering are addressed.

---

## OpenCode Review

### Plan 65-01: Shutdown Signal Infrastructure + Thread Handle Storage

**Summary:** Solid foundation design. The `AtomicBool` + `BlockingThreads` pattern is the correct primitive for this problem. However, the lack of a join timeout is a real risk — if any thread ignores the signal (e.g., stuck in `ReadFile` on a broken pipe), shutdown hangs forever.

**Strengths:**
- `AtomicBool` with `SeqCst` is sound for cross-thread signalling; no data race possible
- `BlockingThreads` using `Option<JoinHandle<()>>` with `take()` is idiomatic
- Separates signal (AtomicBool) from handle storage (struct), keeping ownership clear

**Concerns:**
- **HIGH:** No join timeout — Plan text says "relies on signal breaking loops quickly" and "no native join timeout". This is optimistic. If a thread is stuck in a blocking I/O call (e.g., `ConnectNamedPipe` after a client crashes without connecting), the signal isn't checked, and the join blocks forever. The SCM will eventually kill the process after `SERVICE_WAIT_TIMEOUT` (20s on modern Windows), leaving the hung state visible in Event Log.
- **MEDIUM:** `SeqCst` over `Release/Acquire` — `SeqCst` is unnecessarily strong for this pattern. `AtomicBool` with `Ordering::Release` on store and `Ordering::Acquire` on load is correct and cheaper.

**Suggestions:**
- Add timeout to join loop: Spawn a watchdog timer thread that sleeps for `SHUTDOWN_TIMEOUT + 5s` and calls `std::process::exit(1)` if still alive. This ensures the process always dies.
- Change to `Ordering::Release` / `Ordering::Acquire` ordering.
- Consider `AtomicBool` from `std::sync::atomic` (not `parking_lot`) — it's the correct tool and already in std.

**Risk Assessment:** MEDIUM — foundation is sound but the no-timeout join is a single-point-of-failure that recreates the exact problem we're trying to fix (process won't die).

---

### Plan 65-02: IPC Pipe Shutdown Signal

**Summary:** Minimal and correct. The between-connection check is the right place — you can't safely cancel a blocking `ConnectNamedPipeW` without `CancelSynchronousIo` (complex) or `CreateNamedPipeW` with `PIPE_REFUSED` (unnecessary). However, the "in-flight requests complete" behavior is a design decision that needs consideration.

**Strengths:**
- Correct placement of signal check (between connections, not inside client handling)
- `CloseHandle` on shutdown is the right cleanup call
- Consistent across all three pipes

**Concerns:**
- **MEDIUM:** Hung client connection: If a client connects but never sends data (or sends partial data), `ReadFile` in `handle_client` blocks indefinitely. The signal won't be checked until the client disconnects. This blocks the join.
- **MEDIUM:** `CloseHandle` on named pipe: Closing the pipe instance handle while `ConnectNamedPipeW` is pending on another thread has well-defined behavior on Windows (the pending call completes with `ERROR_OPERATION_ABORTED`), but this isn't mentioned in the plan. Should be documented.

**Suggestions:**
- Add a bounded wait inside `handle_client` — use `ReadFile` with a short timeout or a separate mechanism (though this may be out of scope).
- Document that `CloseHandle` after `shutdown_requested()` will abort any pending `ConnectNamedPipeW` on that handle.

**Risk Assessment:** LOW — the risk of a hung client connection already exists today; this plan doesn't make it worse.

---

### Plan 65-03: Chrome + Health Monitor + Session Monitor Shutdown

**Summary:** Good overall approach. The health monitor plan is the most complex and the one most likely to have subtle bugs.

**Strengths:**
- Session monitor and health monitor both use async loops where a simple `if shutdown_requested() { break }` works cleanly
- Chrome handler follows the IPC pipe pattern (consistent design)
- `tokio::join!` returning when all tasks exit is the correct understanding

**Concerns:**
- **MEDIUM-HIGH:** Health monitor timing: The plan says "add shutdown check in each task's loop". But `ping_task`, `pong_task`, and `timeout_task` all tick at different intervals. If `pong_task` checks every 5 seconds and the other two exit immediately, the join won't complete for up to 5 seconds. This adds unpredictable latency to shutdown.
- **MEDIUM-HIGH:** Health monitor block_on: `rt.block_on(tokio::join!(...))` blocks the host thread. If the inner future never returns (because a task doesn't check the signal promptly), the join in `BlockingThreads` also blocks. Combined with the no-timeout issue in 65-01, this is a vulnerability.
- **MEDIUM:** Session monitor edge case: `WTSEnumerateSessionsW` can block for seconds on a domain controller timeout if the DC is unreachable. The 2-second poll interval check doesn't protect against this.

**Suggestions:**
- Spawn a shared internal tokio channel/cancel token for the health monitor tasks rather than polling an external AtomicBool from inside each async task — a single `tokio_util::sync::CancellationToken` is cleaner.
- Alternatively, add `tokio::select!` with a timeout to `WTSEnumerateSessionsW` so the session monitor doesn't block shutdown.
- Document that health monitor shutdown may take up to the max interval of any task.

**Risk Assessment:** MEDIUM — functionally correct but shutdown latency is unpredictable.

---

### Plan 65-04: Panic Safety + PowerShell Stop Handling

**Summary:** The `catch_unwind` strategy is correct; the PowerShell changes are essential but under-specified.

**Strengths:**
- `std::panic::catch_unwind(AssertUnwindSafe(...))` is the right incantation for this pattern
- `abort_stop()` on panic is the correct fallback
- Adding `request_shutdown()` in the `Stop` control handler arm is critical
- The 500ms poll loop check for shutdown is appropriate

**Concerns:**
- **MEDIUM-HIGH:** `AssertUnwindSafe` soundness: The plan doesn't discuss the data inside the closure. If `initiate_stop` captures references that are `!UnwindSafe`, `AssertUnwindSafe` is a promise that panicking won't cause UB. Need to verify that `initiate_stop` only uses thread-local data (the password buffer, the hash) and doesn't hold a `MutexGuard` or similar RAII guard across a panic point.
- **MEDIUM-HIGH:** PowerShell "wait up to 30 seconds": The plan says "wait up to 30 seconds for service to actually stop" but doesn't specify polling interval or timeout semantics. A naive `Start-Sleep 30` followed by a check is wrong.
- **MEDIUM-HIGH:** PowerShell error message for stuck service: The plan mentions providing guidance, but the specific error message format isn't defined. It needs to tell the user:
  - The service is stuck in StopPending
  - Reset password verification (the service may be waiting on password file polling)
  - Escalation: `psexec -s taskkill /F /IM dlp-agent.exe`
  - Last resort: reboot
- **MEDIUM:** Unit test for catch_unwind: Testing that `catch_unwind` calls `abort_stop` is important but difficult — you need to inject a panic into `get_auth_hash` or `bcrypt::verify`. The plan should mention dependency injection (e.g., a test-only flag to simulate hash corruption) or restructuring the thread body to be testable.

**Suggestions:**
- Document the `AssertUnwindSafe` safety justification explicitly.
- PowerShell loop should use `Get-Service` + `WaitForStatus` or manual polling with `Start-Sleep 1` and a max iteration count.
- For the unit test, restructure the verification thread body into a function that takes the hash and password as arguments — then test with a deliberately corrupt hash.

**Risk Assessment:** MEDIUM — `catch_unwind` is correct but the AssertUnwindSafe justification is undocumented; PowerShell changes need more detail.

---

### OpenCode: Global Assessment

**Overall Phase Risk: MEDIUM-HIGH**

The four plans collectively achieve the phase goal, but two systemic issues cross-cut all plans:

1. **No timeout on join** (Plan 65-01) undermines the entire effort. The shutdown signal is checked only between I/O operations. If any thread is stuck in a blocking I/O that doesn't return between polls, the join blocks. A watchdog timer or `std::process::exit` fallback is essential.

2. **Missing CancelSynchronousIo consideration** — Windows provides `CancelSynchronousIo` for exactly this scenario (cancelling a blocking `ReadFile` in another thread). While it's complex to use correctly, it should at least be mentioned as a future improvement.

3. **Dependency ordering:** Plans 65-02/03 depend on 65-01's `shutdown_requested()` being available, but none of them also depend on the `BlockingThreads` struct being fully wired. This is fine — they can be implemented in parallel as long as 65-01 lands first.

4. **No test plan beyond the catch_unwind test:** The plans mention "all existing tests pass" but don't propose integration tests for the service stop flow. Given the severity of the bug, an automated smoke test (start service, wait for ready, `sc stop`, verify process exits within 30s) would be valuable.

**Key Recommendation:** Add a watchdog timer that calls `process::exit(1)` after `SHUTDOWN_TIMEOUT + 5s` as a safety net. This is a small change with zero downside that eliminates the "hung thread blocks join" risk entirely.

---

## Consensus Summary

### Agreed Strengths

- Both reviewers agree the root-cause diagnosis is correct (blocking threads never joined).
- Both agree `AtomicBool` + `BlockingThreads` is the right primitive direction.
- Both agree `catch_unwind` + `abort_stop()` is the correct panic-safety pattern.
- Both agree joining before reporting `STOPPED` matches SCM expectations.
- Both agree PowerShell improvements are operationally valuable.

### Agreed Concerns (Highest Priority)

1. **HIGH — No join timeout / unbounded joins:** Both reviewers flag that `JoinHandle::join()` with no timeout is a single point of failure. If any thread is blocked in `ConnectNamedPipeW`, `ReadFile`, or an internal loop, the service can still hang. Codex rates this HIGH per-plan; OpenCode suggests a watchdog timer calling `process::exit(1)`.

2. **HIGH — AtomicBool polling cannot wake blocked named-pipe threads:** Codex is explicit: "AtomicBool polling is not enough for synchronous named-pipe servers." A thread blocked in `ConnectNamedPipeW` will never see the flag until a client connects. OpenCode notes the same but rates it lower per-plan because the risk "already exists today."

3. **HIGH — Shutdown authorization vs execution conflated (Plan 65-04):** Codex flags that calling `request_shutdown()` immediately in the Stop control handler is wrong — password verification hasn't succeeded yet. If cancelled, the service must return to Running, but global shutdown may have already torn down worker threads. OpenCode does not flag this ordering issue, creating a divergent view worth investigating.

4. **MEDIUM — AssertUnwindSafe justification undocumented:** Both reviewers note the plan doesn't specify what the closure captures or why `AssertUnwindSafe` is sound.

5. **MEDIUM — PowerShell under-specified:** Both reviewers want clearer polling semantics, state reporting, and error-message formatting.

6. **MEDIUM — Test gaps:** Both reviewers note missing integration/smoke tests for the full stop flow (no clients connected, idle client, wrong password, panic recovery).

### Divergent Views

- **Codex** rates Plan 65-02 (IPC pipes) as **HIGH** risk because the polling design "does not actually guarantee pipe server shutdown." **OpenCode** rates it **LOW** because "the risk of a hung client connection already exists today; this plan doesn't make it worse."
- **Codex** explicitly calls for a two-phase shutdown lifecycle (stop_requested vs shutdown_authorized). **OpenCode** does not raise this ordering concern and instead focuses on the watchdog timer as the primary safety net.
- **Codex** wants overlapped I/O or `CancelSynchronousIo` as the proper fix. **OpenCode** suggests a dummy-client connect to unblock `ConnectNamedPipeW` or a watchdog `process::exit` fallback.

### Synthesis

The plans are directionally correct but have a **critical design gap** around unblocking blocked named-pipe threads. The Codex review is more stringent and identifies an additional lifecycle-ordering bug in Plan 65-04 that OpenCode missed. Both agree a watchdog/fallback mechanism is essential. The phase should be replanned with:

1. A bounded join strategy (watchdog timer or per-thread timeout).
2. An explicit named-pipe unblock mechanism (dummy client connect, `CancelSynchronousIo`, or overlapped I/O).
3. Separation of "stop requested" from "shutdown authorized" lifecycle states.
4. Documented `AssertUnwindSafe` safety justification.
5. Expanded test plan covering no-client, idle-client, wrong-password, and panic-recovery scenarios.
6. More detailed PowerShell stop-handling specification.
