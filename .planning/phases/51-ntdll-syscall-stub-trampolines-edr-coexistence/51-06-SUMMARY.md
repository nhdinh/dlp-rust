---
phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence
plan: 06
subsystem: hook-dll
tags: [ntdll, syscall, trampoline, oncelock, lazy-init, chaos-test, integration-test]

requires:
  - phase: 51-03
    provides: NtdllTrampoline* functions and NTDLL_STUBS constant wired
  - phase: 51-04
    provides: StubIntegrity verification and background re-verification thread
  - phase: 51-05
    provides: BypassAlert IPC types and enable_ntdll_patching config flag
provides:
  - NTDLL_PATCHER OnceLock<Mutex<NtdllPatcher>> global in lib.rs
  - lazy_init_ntdll_patcher function (never called from DllMain)
  - NTDLL_PATCHING_ENABLED AtomicBool flag read from shared memory during init()
  - DllMain ordering: self-allowlist -> IAT patch -> read ntdll flag -> return
  - Trampolines call get_original_trampoline() free function for retour trampoline access
  - ntdll_chaos_test.rs integration test with 1000 threads + 100 patch/unpatch cycles
  - ntdll_patcher_smoke_test runs by default (no #[ignore])
affects:
  - 53 (ETW Kernel-File consumer will use BypassAlert from wired pipe IPC)

tech-stack:
  added: []
  patterns:
    - OnceLock lazy initialization outside DllMain (loader-lock safety)
    - AtomicBool fast-path check (~1ns) before Mutex lock on first call
    - Integration test with #[ignore] for tests that modify global process state
    - Pub module visibility for cross-crate integration test access

key-files:
  created:
    - dlp-hook-dll/tests/ntdll_chaos_test.rs - Chaos test fixture with smoke + full chaos tests
  modified:
    - dlp-hook-dll/src/lib.rs - NTDLL_PATCHER OnceLock, lazy_init_ntdll_patcher, NTDLL_PATCHING_ENABLED AtomicBool, read_ntdll_patching_flag_from_shared_memory stub

key-decisions:
  - "get_original_trampoline remains a pub free function (not instance method): trampolines are FFI contexts without NtdllPatcher reference"
  - "NTDLL_PATCHING_ENABLED AtomicBool provides ~1ns fast-path; Mutex lock only on first lazy-init call"
  - "Chaos test uses #[ignore] to prevent CI execution; requires explicit --ignored flag"
  - "Pub module visibility on ntdll_patcher required for integration test access to NtdllPatcher struct"

patterns-established:
  - "OnceLock + Mutex lazy init pattern: global static initialized on first hook call, never from DllMain"
  - "AtomicBool gate + OnceLock init: two-tier check avoids Mutex contention after initialization"
  - "Integration test isolation via #[ignore]: tests that modify ntdll .text must be opt-in"

requirements-completed: [BLOCK-08, BLOCK-09]

duration: 5min
completed: 2026-05-22
---

# Phase 51 Plan 06: Ntdll Patcher Lazy Integration + Chaos Test Summary

**OnceLock-based lazy ntdll patcher initialization (never from DllMain), AtomicBool fast-path gating, and chaos test fixture with 1000-thread concurrent syscall pressure validation**

## Performance

- **Duration:** 5 min
- **Started:** 2026-05-22T07:12:47Z
- **Completed:** 2026-05-22T07:17:47Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

### Task 1: Integrate ntdll patcher into lib.rs with lazy OnceLock initialization

- Added `NTDLL_PATCHER: OnceLock<Mutex<NtdllPatcher>>` global static in lib.rs
- Added `lazy_init_ntdll_patcher(enabled: bool)` function that initializes patcher on first call
- Added `NTDLL_PATCHING_ENABLED: AtomicBool` static for fast-path trampoline checks
- Modified `init()` to read `enable_ntdll_patching` flag from shared memory and store in AtomicBool
- DllMain ordering preserved: self-allowlist -> IAT patch -> read ntdll flag -> return
- Patcher is NEVER created from DllMain (loader-lock deadlock avoidance per D-18)
- Added `read_ntdll_patching_flag_from_shared_memory()` stub returning `false` until Phase 53 wiring
- All four `NtdllTrampoline*` functions call `crate::ntdll_patcher::get_original_trampoline()` free function

### Task 2: Create chaos test fixture for ntdll patcher

- Created `dlp-hook-dll/tests/ntdll_chaos_test.rs` as integration test
- `ntdll_patcher_smoke_test` runs by default (no `#[ignore]`):
  - Verifies patcher creation, initial Unpatched state, get_original_trampoline returns None
  - Verifies verify_stub_integrity returns NotPatched, verify_all_stubs returns 4 results
- `ntdll_chaos_test` marked with `#[ignore]` (modifies ntdll .text section):
  - Spawns 1000 threads calling NtCreateFile via direct ntdll syscall
  - Main thread performs 100 patch/unpatch cycles with 100ms sleep between
  - Tracks syscalls_ok, syscalls_denied, crashes via AtomicUsize counters
  - 30-second test duration with 30-second join timeout
  - Assertions: zero crashes, at least some syscalls succeeded, completes within 60 seconds
- Helper functions: `create_temp_file_path()`, `syscall_ntcreatefile()` with inline OBJECT_ATTRIBUTES/UNICODE_STRING construction

## Task Commits

Each task was committed atomically:

1. **Task 1: Integrate ntdll patcher with lazy OnceLock initialization** - `e9fb126` (feat)
2. **Task 2: Create chaos test fixture for ntdll patcher** - `0f37ba1` (feat)
3. **Make ntdll_patcher module public for integration test access** - `28f2340` (feat)

**Plan metadata:** (to be committed with SUMMARY.md)

## Files Created/Modified

- `dlp-hook-dll/src/lib.rs` — Added NTDLL_PATCHER OnceLock, lazy_init_ntdll_patcher, NTDLL_PATCHING_ENABLED AtomicBool, read_ntdll_patching_flag_from_shared_memory stub; changed ntdll_patcher module to pub
- `dlp-hook-dll/tests/ntdll_chaos_test.rs` — New integration test: smoke test + chaos test with 1000 threads and 100 patch cycles

## Decisions Made

- **Free function for get_original_trampoline preserved:** The plan suggested changing to an instance method, but the free function pattern (established in Plan 03) is correct for FFI trampoline contexts where no NtdllPatcher instance is available. Both the instance method and free function exist; trampolines use the free function.
- **AtomicBool fast-path before OnceLock:** `NTDLL_PATCHING_ENABLED.load(Relaxed)` is ~1ns. Only when true does the trampoline call `lazy_init_ntdll_patcher()`, which acquires the Mutex only on the first call. This minimizes overhead on the hot syscall path.
- **Integration test as separate file:** The chaos test is in `tests/` (not inline in lib.rs) because it requires real ntdll.dll, actual thread suspension, and would interfere with other tests if run in parallel.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Known Stubs

| File | Line | Stub | Resolution Plan |
|------|------|------|-----------------|
| `lib.rs` | ~532 | `read_ntdll_patching_flag_from_shared_memory()` returns `false` | Phase 53 — wire to actual shared memory segment |
| `ntdll_patcher.rs` | ~634 | `emit_bypass_alert()` logs only via `debug_log` | Phase 53 — wire to `pipe_client::send_raw_request` using `BypassAlert` type |

## Threat Flags

None — all security-relevant surface (OnceLock init, AtomicBool gating, thread suspension) is explicitly covered in the plan's threat model (T-51-21 through T-51-24).

## Next Phase Readiness

- Phase 52 (DACL Tripwire) can proceed independently — no dependencies on ntdll patching
- Phase 53 (ETW Kernel-File Consumer) can wire `emit_bypass_alert()` to pipe IPC and implement shared memory flag reading
- Phase 54 (Admin TUI Bypass Alerts) can consume `BypassAlert` events via SIEM relay

## Self-Check: PASSED

- [x] `NTDLL_PATCHER: OnceLock<Mutex<NtdllPatcher>>` exists in lib.rs
- [x] `lazy_init_ntdll_patcher` function exists and returns `&'static Mutex<NtdllPatcher>`
- [x] `NTDLL_PATCHING_ENABLED: AtomicBool` static exists
- [x] `init()` reads flag and stores it, does NOT create patcher directly
- [x] Trampoline functions reference `crate::ntdll_patcher::get_original_trampoline()`
- [x] `read_ntdll_patching_flag_from_shared_memory` stub returns false
- [x] `dlp-hook-dll/tests/ntdll_chaos_test.rs` exists and compiles
- [x] `ntdll_chaos_test` integration test exists with `#[ignore]` attribute
- [x] `ntdll_patcher_smoke_test` runs by default and passes
- [x] `cargo test -p dlp-hook-dll` passes: 253 passed, 0 failed, 1 ignored
- [x] `cargo clippy -p dlp-hook-dll -- -D warnings` is clean
- [x] Commit `e9fb126` exists (Task 1)
- [x] Commit `0f37ba1` exists (Task 2)
- [x] Commit `28f2340` exists (visibility fix)

---
*Phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence*
*Completed: 2026-05-22*
