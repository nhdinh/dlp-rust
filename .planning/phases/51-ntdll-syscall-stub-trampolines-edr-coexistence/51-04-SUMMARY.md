---
phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence
plan: 04
subsystem: hook-dll
tags: [ntdll, trampoline, verification, edr, background-thread, integrity]

requires:
  - phase: 51-02
    provides: NtdllPatcher with per-stub state machine, retour integration, DETOURS static array
  - phase: 51-03
    provides: NtdllTrampoline* functions and NTDLL_STUBS constant wired
  - phase: 50
    provides: Background thread with 100ms WaitForSingleObject timer loop
provides:
  - StubIntegrity enum (Clean, Overwritten, NotPatched, Unknown)
  - verify_stub_integrity method on NtdllPatcher
  - mark_stub_overwritten method (sets Overwritten state + emits BypassAlert)
  - verify_all_stubs method (per-stub granularity per D-13)
  - is_target_in_our_trampoline_range helper (64KB window check)
  - TRAMPOLINE_VERIFY_INTERVAL_MS (30s) and TRAMPOLINE_VERIFY_TICKS (300)
  - start_background_thread with optional verify_fn callback
  - background_thread_loop with tick counter calling verify_fn every 300 ticks
affects:
  - 51-05 (BypassAlert IPC wiring)
  - 51-06 (chaos test + callback wiring)

tech-stack:
  added: []
  patterns:
    - Per-stub integrity verification: read 5 bytes, check 0xE9 + rel32 target in trampoline range
    - Tick-counter based scheduling inside existing 100ms timer loop
    - Optional callback parameter for backward-compatible background thread extension

key-files:
  created: []
  modified:
    - dlp-hook-dll/src/ntdll_patcher.rs - StubIntegrity enum, verify_stub_integrity, mark_stub_overwritten, verify_all_stubs, is_target_in_our_trampoline_range
    - dlp-hook-dll/src/background_thread.rs - TRAMPOLINE_VERIFY constants, verify_fn callback, tick counter
    - dlp-hook-dll/src/trampolines.rs - Updated start_background_thread call site to pass None

key-decisions:
  - "64KB trampoline window for target validation: generous enough to cover all four NtdllTrampoline* functions regardless of code layout, small enough to reject EDR module ranges"
  - "Optional fn() callback for background thread: avoids global static complexity, keeps backward compatibility, defers NtdllPatcher wiring to Plan 06"
  - "No re-patching on Overwritten detection per D-07: emit alert and mark permanently skipped to avoid EDR arms race"

patterns-established:
  - "Tick-counter scheduling inside WaitForSingleObject loop: add periodic tasks without additional threads"
  - "Two-phase JMP validation: check 0xE9 byte first, then verify rel32 target falls in expected range"

requirements-completed: [BLOCK-09]

duration: 12min
completed: 2026-05-22
---

# Phase 51 Plan 04: Background Re-verification Thread Summary

**StubIntegrity enum with 0xE9+rel32 target verification, mark_stub_overwritten alert emission, and 30-second tick-counter scheduling in the existing background thread loop**

## Performance

- **Duration:** 12 min
- **Started:** 2026-05-22T06:45:00Z
- **Completed:** 2026-05-22T06:57:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added `StubIntegrity` enum with `Clean`, `Overwritten`, `NotPatched`, `Unknown` variants per D-12/D-13
- Implemented `verify_stub_integrity`: reads first 5 bytes, validates 0xE9 JMP prefix, calculates rel32 target, checks target falls within our trampoline range (64KB window)
- Implemented `mark_stub_overwritten`: sets `StubPatchState::Overwritten`, logs via `debug_log`, emits `BypassAlert(HookOverwritten)` per D-07
- Implemented `verify_all_stubs`: iterates all 4 stubs independently, returns `Vec<(&str, StubIntegrity)>` per D-13
- Added `is_target_in_our_trampoline_range`: compares JMP target against all four `NtdllTrampoline*` function addresses
- Added `TRAMPOLINE_VERIFY_INTERVAL_MS = 30_000` and `TRAMPOLINE_VERIFY_TICKS = 300` constants
- Extended `start_background_thread` with optional `verify_fn: Option<fn()>` parameter
- Extended `background_thread_loop` with tick counter that calls `verify_fn` every 300 iterations
- Existing ISOLATED/RESYNC cache polling logic unchanged per D-11
- Updated `trampolines.rs` call site to pass `None` for `verify_fn` (wiring deferred to Plan 06)
- 12 new tests across both modules (7 in ntdll_patcher + 5 in background_thread)
- All 253 dlp-hook-dll tests pass; clippy clean (-D warnings)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add verify_stub_integrity to ntdll_patcher.rs** - `f9e4692` (feat)
2. **Task 2: Extend background_thread.rs with trampoline verification** - `7c90620` (feat)

**Plan metadata:** (to be committed with SUMMARY.md)

## Files Created/Modified

- `dlp-hook-dll/src/ntdll_patcher.rs` — Added `StubIntegrity` enum, `verify_stub_integrity`, `mark_stub_overwritten`, `verify_all_stubs`, `is_target_in_our_trampoline_range`, and 7 tests
- `dlp-hook-dll/src/background_thread.rs` — Added `TRAMPOLINE_VERIFY_INTERVAL_MS`, `TRAMPOLINE_VERIFY_TICKS`, `verify_fn` callback parameter, tick counter in loop, and 2 constant tests
- `dlp-hook-dll/src/trampolines.rs` — Updated `start_background_thread` call site to pass `None` for `verify_fn`

## Decisions Made

- **64KB trampoline window:** The four `NtdllTrampoline*` functions are compiled into the same module's `.text` section. A 64KB window is generous enough to cover any code layout variation while being far smaller than typical EDR module address ranges, making it an effective discriminator.
- **Optional `fn()` callback instead of global static:** Storing a reference to `NtdllPatcher` in the background thread would require `Send + Sync` bounds and global static complexity. An optional function pointer keeps the thread generic and defers the actual wiring to Plan 06 where the patcher lifecycle is established.
- **No re-patching on detection per D-07:** When EDR overwrites our trampoline, re-patching would trigger an arms race. The correct response is to emit an alert and permanently skip the stub, falling back to IAT hooks for that function.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Known Stubs

| File | Line | Stub | Resolution Plan |
|------|------|------|-----------------|
| `ntdll_patcher.rs` | ~520 | `emit_bypass_alert()` logs only via `debug_log` | Plan 05 — wire to `pipe_client::send_raw_request` |
| `background_thread.rs` | ~60 | `verify_fn` is always `None` at call site | Plan 06 — wire to closure that calls `NtdllPatcher::verify_all_stubs` |

## Threat Flags

None — all security-relevant surface (stub byte reading, alert emission, state transitions) is explicitly covered in the plan's threat model (T-51-13 through T-51-16).

## Next Phase Readiness

- Plan 05 can define `BypassAlert` struct in `dlp-common/src/hook_ipc.rs` and wire `emit_bypass_alert()` to pipe IPC
- Plan 06 can wire the `verify_fn` callback to a closure that calls `NtdllPatcher::verify_all_stubs()` and handles `Overwritten` results
- Plan 06 can build the chaos test fixture that exercises `patch_all_stubs()` / `unpatch_all_stubs()` cycles under thread load

---
*Phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence*
*Completed: 2026-05-22*
