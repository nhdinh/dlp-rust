---
phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence
plan: 02
subsystem: hook-dll
tags: [retour, ntdll, syscall, detour, edr, thread-suspend, windows]

requires:
  - phase: 51-01
    provides: EDR detection module (edr_detector.rs) and thread suspender (thread_suspender.rs)
provides:
  - retour 0.4.0-alpha.4 dependency in dlp-hook-dll
  - HookDescriptor extended with ntdll_stub_addr and original_ntdll_bytes fields
  - NtdllPatcher struct with per-stub state machine
  - StubPatchState enum (Unpatched, Patched, SkippedEdr, SkippedRaced, Overwritten)
  - StubName enum for 4 ntdll functions with as_str() and index()
  - patch_all_stubs() with EDR detection consultation before each patch
  - patch_stub() using with_suspended_threads for thread safety
  - unpatch_all_stubs() calling detour.disable() (never from disk)
  - get_original_trampoline() returning retour's trampoline pointer
  - Static DETOURS Mutex array for RawDetour handle storage
affects:
  - 51-03 (ntdll-specific trampolines NtdllTrampolineNtCreateFile etc.)
  - 51-05 (BypassAlert IPC wiring)
  - 51-06 (chaos test)

tech-stack:
  added: [retour 0.4.0-alpha.4]
  patterns:
    - Per-stub state machine with independent failure handling
    - Static Mutex array for non-Copy types (RawDetour)
    - Thread-suspend protocol for atomic in-memory patching
    - Two-phase EDR detection before patch (module enum + stub prologue)

key-files:
  created:
    - dlp-hook-dll/src/ntdll_patcher.rs - Ntdll patcher core with retour integration
  modified:
    - dlp-hook-dll/Cargo.toml - Added retour dependency
    - dlp-hook-dll/src/lib.rs - Extended HookDescriptor, added mod ntdll_patcher, NTDLL_STUBS constant
    - dlp-hook-dll/src/edr_detector.rs - Formatting consistency
    - dlp-hook-dll/src/thread_suspender.rs - Formatting consistency

key-decisions:
  - "RawDetour is not Copy/Clone: store detour handles in static Mutex array instead of HookDescriptor"
  - "HookDescriptor keeps Copy derive by excluding detour field; metadata and runtime state are separated"
  - "NTDLL_STUBS constant uses #[cfg(any())] to stay compilable until Plan 03 defines NtdllTrampoline* functions"
  - "find_detour_for_stub returns Err(DetourFailed) as placeholder; will be wired to NTDLL_STUBS in Plan 03"
  - "emit_bypass_alert logs via debug_log as placeholder; will use pipe IPC in Plan 05"

patterns-established:
  - "Static Mutex for non-Copy runtime state: when a const table cannot hold a type, use a parallel static"
  - "Per-stub granularity: each of 4 stubs has independent state; one failure does not affect others"
  - "Placeholder functions with clear comments indicating which future plan wires them"

requirements-completed: [BLOCK-08, BLOCK-09]

duration: 15min
completed: 2026-05-22
---

# Phase 51 Plan 02: Ntdll Patcher Core with retour Integration Summary

**retour-based Detours-style 5-byte JMP trampolines on ntdll syscall stubs with per-stub state machine, EDR detection, and thread-suspend safety**

## Performance

- **Duration:** 15 min
- **Started:** 2026-05-22T06:15:09Z
- **Completed:** 2026-05-22T06:30:14Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added retour 0.4.0-alpha.4 dependency for cross-architecture Detours-style trampolines
- Extended HookDescriptor with ntdll_stub_addr and original_ntdll_bytes (Copy-compatible)
- Created NtdllPatcher with per-stub state machine (StubPatchState enum)
- Implemented patch_all_stubs() that consults EDR detector before each patch attempt
- Implemented patch_stub() using thread_suspender::with_suspended_threads for atomic safety
- Implemented unpatch_all_stubs() calling detour.disable() — never reads from disk (D-06)
- Implemented get_original_trampoline() returning retour's trampoline pointer
- Created static DETOURS Mutex array to store RawDetour handles (not Copy/Clone)
- Added 12 unit tests covering state transitions, per-stub granularity, and error paths
- All 239 dlp-hook-dll tests pass; clippy clean (-D warnings); cargo fmt clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Add retour dependency and extend HookDescriptor** - `d9d38e5` (feat)
2. **Task 2: Create ntdll_patcher.rs — Patcher core with retour integration** - `a56028d` (feat)

**Plan metadata:** (to be committed with SUMMARY.md)

## Files Created/Modified

- `dlp-hook-dll/Cargo.toml` - Added `retour = "0.4.0-alpha.4"` with Phase 51 comment
- `dlp-hook-dll/src/lib.rs` - Extended HookDescriptor with ntdll fields; added `mod ntdll_patcher;`; added `NTDLL_STUBS` constant (conditionally compiled out until Plan 03)
- `dlp-hook-dll/src/ntdll_patcher.rs` - New module: NtdllPatcher, StubPatchState, StubName, PatchError, BypassReason, detour storage, and 12 tests
- `dlp-hook-dll/src/edr_detector.rs` - cargo fmt formatting consistency
- `dlp-hook-dll/src/thread_suspender.rs` - cargo fmt formatting consistency

## Decisions Made

- **RawDetour storage outside HookDescriptor:** The plan assumed `detour: Option<retour::RawDetour>` could live in HookDescriptor with Clone derive. RawDetour implements neither Copy nor Clone, so detour handles are stored in a separate `static DETOURS: Mutex<[Option<RawDetour>; 4]>` array. HookDescriptor remains Copy-able for the const HOOKS table.
- **Placeholder functions with clear plan references:** `find_detour_for_stub()` and `emit_bypass_alert()` are stubs that will be wired in Plans 03 and 05 respectively. Each has a comment indicating the future plan.
- **NTDLL_STUBS uses #[cfg(any())]:** The constant references `NtdllTrampoline*` functions that do not exist yet. Using `#[cfg(any())]` keeps it compilable independently while making the mapping visible for Plan 03.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] RawDetour does not implement Clone**
- **Found during:** Task 1 (HookDescriptor extension)
- **Issue:** Plan instructed removing Copy from HookDescriptor and keeping Clone, but `retour::RawDetour` implements neither `Copy` nor `Clone`. A `const` array cannot contain non-Copy types.
- **Fix:** Removed the `detour` field from HookDescriptor entirely. Created a separate `static DETOURS: Mutex<[Option<retour::RawDetour>; 4]>` array for detour handle storage. HookDescriptor keeps `#[derive(Clone, Copy)]` and only stores metadata fields (`ntdll_stub_addr`, `original_ntdll_bytes`).
- **Files modified:** `dlp-hook-dll/src/lib.rs`, `dlp-hook-dll/src/ntdll_patcher.rs`
- **Verification:** `cargo check -p dlp-hook-dll` passes; all tests pass
- **Committed in:** `d9d38e5` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** The deviation was necessary for compilation. The architectural outcome is cleaner — metadata (HookDescriptor) and runtime state (DETOURS Mutex) are properly separated.

## Issues Encountered

- **retour::RawDetour API discovery:** Had to read the crate source to confirm `trampoline()` returns `&()` (not `*const ()`), requiring a dereference in `get_detour_trampoline()`. Resolved by inspecting `~/.cargo/registry/src/.../retour-0.4.0-alpha.4/src/detours/raw.rs`.
- **cargo fmt on pre-existing files:** Running `cargo fmt` reformatted `edr_detector.rs` and `thread_suspender.rs` from Plan 51-01. These are formatting-only changes with no functional impact.

## Known Stubs

| File | Line | Stub | Resolution Plan |
|------|------|------|-----------------|
| `ntdll_patcher.rs` | 464 | `find_detour_for_stub()` returns `Err(DetourFailed)` | Plan 03 — wire to `NTDLL_STUBS` constant |
| `ntdll_patcher.rs` | 473 | `emit_bypass_alert()` logs only via `debug_log` | Plan 05 — wire to `pipe_client::send_raw_request` |

## Threat Flags

None — all security-relevant surface (EDR detection, thread suspend, atomic writes) is explicitly covered in the plan's threat model.

## Next Phase Readiness

- Plan 03 can define `NtdllTrampolineNtCreateFile` etc. in `trampolines.rs` and wire `find_detour_for_stub()` to `NTDLL_STUBS`
- Plan 05 can define `BypassAlert` struct in `dlp-common/src/hook_ipc.rs` and wire `emit_bypass_alert()` to pipe IPC
- Plan 06 can build the chaos test fixture that exercises `patch_all_stubs()` / `unpatch_all_stubs()` cycles under thread load

---
*Phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence*
*Completed: 2026-05-22*
