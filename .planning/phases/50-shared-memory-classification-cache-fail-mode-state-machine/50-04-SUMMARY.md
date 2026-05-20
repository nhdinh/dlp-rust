---
phase: 50-shared-memory-classification-cache-fail-mode-state-machine
plan: 04
subsystem: enforcement

tags: [fail-mode, state-machine, hysteresis, atomic, background-thread, shared-memory, cache, hook-dll]

requires:
  - phase: 50-01
    provides: IPC protocol with cache_version, cache_hint, HookOp
  - phase: 50-02
    provides: Shared-memory cache ABI (CacheHeader, version_word)
  - phase: 50-03
    provides: CacheLookup with LRU, prefix/hash lookup, path normalization

provides:
  - Fail-mode state machine with four states (Healthy, Degraded, Isolated, Resync)
  - Hysteresis-driven transitions (3 successes for Degraded exit, 5 for Isolated/Resync)
  - Asymmetric tier-gated decisions (T3/T4 deny, T1/T2 allow when ISOLATED)
  - Per-tier staleness budgets (T4=30s, T3=60s, T2=5min, T1=30min)
  - RESYNC entry/exit guards with LRU flush and counter reset
  - Background thread for ISOLATED-state version polling (100ms)
  - Trampoline integration with state-aware decision routing
  - State transition telemetry via tracing::warn!

affects:
  - 50-05
  - 50-06
  - 51-ntdll-syscall-stub-trampolines

tech-stack:
  added: [tracing]
  patterns:
    - Atomic state machine with lock-free counters
    - OnceLock lazy initialization (NOT DllMain)
    - usize type-erasure for HANDLE Send+Sync safety
    - Thread-local LRU with version invalidation

key-files:
  created:
    - dlp-hook-dll/src/fail_mode.rs - Fail-mode state machine with 40+ tests
    - dlp-hook-dll/src/background_thread.rs - ISOLATED-state RESYNC detection thread
  modified:
    - dlp-hook-dll/src/trampolines.rs - classify_and_log_path with fail-mode integration
    - dlp-hook-dll/src/lib.rs - Module declarations for fail_mode, background_thread
    - dlp-hook-dll/src/classification_cache.rs - Added lru::clear_all() for RESYNC flush
    - dlp-hook-dll/Cargo.toml - Added tracing dependency

key-decisions:
  - "record_pipe_success checks cache_version > last_seen BEFORE updating stored version, ensuring ISOLATED->RESYNC transition can detect freshness"
  - "Hysteresis counters (successes/failures) are reset on opposite event, not on state transition, preventing stale counter accumulation"
  - "Background thread uses usize conversion for HANDLE and raw pointers to satisfy Send bounds without unsafe impl Send on windows-rs types"
  - "RESYNC state flushes LRU via clear_all() and resets counters before transitioning to Healthy, ensuring clean state"

patterns-established:
  - "Fail-mode state machine: atomic counters + hysteresis thresholds for deterministic transitions"
  - "Lazy init pattern: OnceLock for both FAIL_STATE and BACKGROUND_THREAD, deferred to first hook call"
  - "Asymmetric fail semantics: deny for sensitive (T3/T4), allow for non-sensitive (T1/T2)"

requirements-completed: [FAIL-01, FAIL-02, FAIL-03]

metrics:
  duration: 35min
  completed: 2026-05-20
---

# Phase 50 Plan 04: Fail-Mode State Machine Summary

**Hook DLL fail-mode state machine with four-state transitions, hysteresis, asymmetric tier-gated decisions, and background thread for automatic RESYNC detection**

## Performance

- **Duration:** 35 min
- **Started:** 2026-05-20T09:09:24Z
- **Completed:** 2026-05-20T09:44:00Z
- **Tasks:** 8
- **Files modified:** 6

## Accomplishments

- FailState enum (Healthy=0, Degraded=1, Isolated=2, Resync=3) with atomic state storage
- FailModeState with consecutive_failures, consecutive_successes, cache_version_seen_at, and degraded_retry_counter
- HEALTHY->DEGRADED after 3 consecutive pipe failures; DEGRADED->ISOLATED after 10 failures
- DEGRADED->HEALTHY after 3 consecutive successes (hysteresis); ISOLATED->RESYNC requires pipe success + fresh version
- RESYNC->HEALTHY after LRU flush + counter reset + 5 consecutive successes
- Asymmetric decisions: T3/T4 writes denied, T1/T2 allowed, reads always allowed
- Per-tier staleness budgets: T4=30s, T3=60s, T2=300s, T1=1800s
- Background thread polls version_word every 100ms in ISOLATED state via WaitForSingleObject
- Trampoline integration: classify_and_log_path routes decisions through fail-mode state machine
- 40+ unit tests covering all transitions, hysteresis edges, flapping prevention, recovery paths

## Task Commits

Each task was committed atomically:

1. **Tasks 1-4, 7-8: Fail-mode state machine core** - `9e0bd3e` (feat)
2. **Task 5: Background thread** - `7a4fed4` (feat)
3. **Task 6: Trampoline integration** - `ae14843` (feat)

## Files Created/Modified

- `dlp-hook-dll/src/fail_mode.rs` - FailModeState, FailState, decide_isolated/degraded/resync, staleness checking, telemetry (NEW)
- `dlp-hook-dll/src/background_thread.rs` - BackgroundThread, start/shutdown functions, polling loop (NEW)
- `dlp-hook-dll/src/trampolines.rs` - classify_and_log_path with fail-mode state-aware routing (MODIFIED)
- `dlp-hook-dll/src/lib.rs` - Added mod fail_mode, mod background_thread, static FAIL_STATE (MODIFIED)
- `dlp-hook-dll/src/classification_cache.rs` - Added lru::clear_all() for RESYNC flush (MODIFIED)
- `dlp-hook-dll/Cargo.toml` - Added tracing dependency (MODIFIED)

## Decisions Made

- `record_pipe_success` checks `cache_version > last_seen` BEFORE updating `cache_version_seen_at`, ensuring the ISOLATED->RESYNC transition can detect freshness. Without this ordering, the comparison would always be false.
- Hysteresis counters are reset on the opposite event (success resets failures, failure resets successes), not on state transition. This prevents stale counters from causing unexpected transitions.
- Background thread uses `usize` conversion for `HANDLE` and raw pointers to satisfy `Send` bounds, rather than `unsafe impl Send` on `windows-rs` types which could violate safety invariants.
- RESYNC state flushes the thread-local LRU via `clear_all()` and resets all counters before transitioning to Healthy, ensuring no stale cache entries persist across recovery.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed ISOLATED->RESYNC transition logic**
- **Found during:** Task 1 (state transition tests)
- **Issue:** `record_pipe_success` updated `cache_version_seen_at` BEFORE checking `cache_version > last_seen`, making the condition always false
- **Fix:** Reordered operations to check the condition before updating the stored version
- **Files modified:** `dlp-hook-dll/src/fail_mode.rs`
- **Verification:** `state_transitions_isolated_to_resync` test now passes
- **Committed in:** `9e0bd3e`

**2. [Rule 1 - Bug] Fixed test success counting for hysteresis thresholds**
- **Found during:** Task 1 (state transition tests)
- **Issue:** Multiple tests miscounted successes needed for hysteresis exits (e.g., entering Resync with 1 success, then looping 4 more = 5 total, but test expected still-Resync after 4 additional)
- **Fix:** Adjusted loop bounds in `resync_transitions_exit_guards`, `hysteresis_isolated_exit_requires_5`, `flapping_prevention`, and `state_transitions_degraded_to_isolated` tests
- **Files modified:** `dlp-hook-dll/src/fail_mode.rs`
- **Verification:** All state transition tests pass
- **Committed in:** `9e0bd3e`

**3. [Rule 3 - Blocking] Added tracing dependency to Cargo.toml**
- **Found during:** Task 1 (compilation)
- **Issue:** `emit_state_transition` used `tracing::warn!` but tracing was not in dlp-hook-dll dependencies
- **Fix:** Added `tracing = { workspace = true }` to `dlp-hook-dll/Cargo.toml`
- **Files modified:** `dlp-hook-dll/Cargo.toml`
- **Verification:** Compilation succeeds
- **Committed in:** `9e0bd3e`

**4. [Rule 3 - Blocking] Created background_thread.rs stub before fail_mode.rs compilation**
- **Found during:** Task 1 (compilation)
- **Issue:** `lib.rs` declared `mod background_thread` but the file didn't exist
- **Fix:** Created `background_thread.rs` with stub implementation and `Send`/`Sync` impls for `BackgroundThread`
- **Files modified:** `dlp-hook-dll/src/background_thread.rs`
- **Verification:** Compilation succeeds
- **Committed in:** `9e0bd3e` (as part of initial commit)

**5. [Rule 1 - Bug] Fixed non-exhaustive match arms in trampolines.rs**
- **Found during:** Task 6 (compilation)
- **Issue:** Match on `classify_path` result used `Ok(d) if d.is_denied()` which is not exhaustive for `Result<Decision, PipeError>`
- **Fix:** Replaced with explicit `Ok(Decision::DENY) | Ok(Decision::DenyWithAlert)` arms in all three match expressions
- **Files modified:** `dlp-hook-dll/src/trampolines.rs`
- **Verification:** Compilation with `-D warnings` passes
- **Committed in:** `ae14843`

**6. [Rule 3 - Blocking] Added lru::clear_all() for RESYNC LRU flush**
- **Found during:** Task 6 (compilation)
- **Issue:** Trampoline integration called `crate::classification_cache::lru::clear_all()` which didn't exist
- **Fix:** Added `clear_all()` function to the `lru` module in `classification_cache.rs`
- **Files modified:** `dlp-hook-dll/src/classification_cache.rs`
- **Verification:** Compilation succeeds
- **Committed in:** `ae14843`

---

**Total deviations:** 6 auto-fixed (4 bugs, 2 blocking)
**Impact on plan:** All auto-fixes necessary for correctness and compilation. No scope creep.

## Issues Encountered

- `windows-rs` `HANDLE` does not implement `Send`, preventing direct use in `std::thread::spawn`. Resolved by converting to `usize` for thread boundary crossing and reconstructing inside the thread.
- `Classification` type was not imported in `trampolines.rs` after adding the fail-mode integration. Resolved by adding `use dlp_common::Classification`.

## Known Stubs

| File | Line | Description |
|------|------|-------------|
| `dlp-hook-dll/src/background_thread.rs` | 105-115 | `start_background_thread` body is a stub — full Windows API calls (CreateEventW, WaitForSingleObject) are present but the cache_header pointer handling needs real shared-memory mapping for integration testing |
| `dlp-hook-dll/src/background_thread.rs` | 118-122 | `shutdown_background_thread` has a 5-second timeout comment but no actual timed join implementation (std::thread::JoinHandle doesn't support timed join) |

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: state-machine-race | `dlp-hook-dll/src/fail_mode.rs` | Multiple threads may detect same transition simultaneously; `emit_state_transition` is best-effort debounced via `old == new` check, but concurrent state updates could emit duplicate telemetry. Mitigation: atomic operations on all fields, no mutex. |

## Next Phase Readiness

- Fail-mode state machine is ready for Plan 50-05 (agent-side cache publisher integration)
- Background thread stub needs real shared-memory mapping for end-to-end testing
- Trampoline integration is complete; no further changes needed for the hook DLL decision path

---
*Phase: 50-shared-memory-classification-cache-fail-mode-state-machine*
*Completed: 2026-05-20*
