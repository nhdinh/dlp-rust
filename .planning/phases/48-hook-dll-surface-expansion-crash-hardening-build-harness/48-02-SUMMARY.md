---
phase: 48-hook-dll-surface-expansion-crash-hardening-build-harness
plan: 02
subsystem: windows-hook
 tags: [pe32, pe32+, iat-patching, trampoline, catch_unwind, reentrancy-guard, handle-based-ipc, u64, no_mangle, windows-rs]

# Dependency graph
requires:
  - phase: 48-hook-dll-surface-expansion-crash-hardening-build-harness
    plan: 01
    provides: crash_guard.rs (guard_trampoline, with_reentrancy_guard), fail_closed.rs (fail_closed! macro)
provides:
  - pe_utils.rs with cfg(target_arch) PE parsing and MAX_IMPORT_DESCRIPTORS=512 bounds limit
  - trampolines.rs with 12 file-I/O hook trampolines (CreateFileW, NtCreateFile, WriteFile, WriteFileEx, MoveFileExW, CopyFileExW, DeleteFileW, ReplaceFileW, SetFileInformationByHandle, NtOpenFile, NtWriteFile, NtSetInformationFile)
  - HandleHookRequest in dlp-common with u64 handle_value for cross-architecture safety
  - classify_handle stub in lib.rs (returns ALLOW until Phase 49/50 handle tracker)
affects:
  - 48-03 (init()/UnhookAll() wiring of ORIGINAL_* and IAT_* statics)
  - 49 (agent-side handle tracker for classify_handle)
  - 50 (agent-side handle tracker for classify_handle)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Architecture-aware PE parsing via cfg(target_arch) constants"
    - "Bounds-limited IAT scanning (MAX_IMPORT_DESCRIPTORS=512)"
    - "Layered crash protection: guard_trampoline (catch_unwind) + with_reentrancy_guard (Cell<bool>)"
    - "Handle-based IPC using u64 for cross-architecture safety"
    - "Multi-path operation evaluation (MoveFileExW, CopyFileExW, ReplaceFileW)"
    - "Selective information-class blocking (SetFileInformationByHandle classes 4, 6, 10)"

key-files:
  created:
    - dlp-hook-dll/src/pe_utils.rs
    - dlp-hook-dll/src/trampolines.rs
  modified:
    - dlp-common/src/hook_ipc.rs (added HandleHookRequest)
    - dlp-hook-dll/src/lib.rs (added ORIGINAL_*, IAT_* statics, classify_handle stub)
    - dlp-hook-dll/src/crash_guard.rs (fixed BOOL import, SEH infinite loop)
    - dlp-hook-dll/src/fail_closed.rs (fixed BOOL import)
    - dlp-hook-dll/src/pipe_client.rs (dead_code fixes)

key-decisions:
  - "u64 for handle_value in HandleHookRequest to avoid architecture ambiguity between 32-bit hook DLL and 64-bit agent"
  - "MAX_IMPORT_DESCRIPTORS=512 prevents unbounded reads on malformed PE files while being generous for typical executables (<50 DLLs)"
  - "SetFileInformationByHandle only blocks classes 4, 6, 10 to avoid breaking legitimate operations"
  - "CopyFile2 excluded as known limitation (COM-based, no IAT entry); covered indirectly via NtCreateFile/NtWriteFile"
  - "classify_handle returns ALLOW as stub until agent-side handle tracker (Phase 49/50)"

patterns-established:
  - "Trampoline pattern: guard_trampoline(fn_name, || with_reentrancy_guard(|| classify..., || original(...)), || original(...))"
  - "Path-based ops evaluate all paths; deny on any path blocks the operation"
  - "Handle-based ops send u64 handle_value to agent for path resolution"

requirements-completed: [BLOCK-02]

# Metrics
duration: 20min
completed: 2026-05-15
---

# Phase 48: Hook DLL Surface Expansion Plan 02 Summary

**Expanded hook DLL from 2 to 12 file-I/O functions with architecture-aware PE parsing, bounds-checked IAT scanning, and handle-based IPC using u64 for cross-architecture safety.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-05-15T23:10:00Z
- **Completed:** 2026-05-15T23:30:00Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments

- Extracted PE parsing into `pe_utils.rs` with `cfg(target_arch)` constants (PE_MAGIC 0x20B/0x10B, DATA_DIRECTORY_OFFSET 112/96)
- Added `MAX_IMPORT_DESCRIPTORS = 512` bounds limit to prevent unbounded reads on malformed PEs
- Created 12 trampolines covering all major file-I/O APIs with `#[unsafe(no_mangle)]` and `extern "system"` signatures
- Each trampoline wrapped in `guard_trampoline` (catch_unwind) + `with_reentrancy_guard` (thread-local Cell<bool>)
- Added `HandleHookRequest` with `handle_value: u64` for cross-architecture handle-based classification
- Multi-path operations (MoveFileExW, CopyFileExW, ReplaceFileW) evaluate all paths before allowing
- Selective blocking in SetFileInformationByHandle (only classes 4, 6, 10)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create pe_utils.rs with cfg(target_arch) PE parsing and bounds checking** - `7d3467a` (feat)
2. **Task 2: Extend hook_ipc.rs with HandleHookRequest using u64** - `64d1382` (feat) — executed before Task 3 due to dependency
3. **Task 3: Create trampolines.rs with all 12 file-I/O hook trampolines** - `5ed1fb4` (feat)
4. **Fix: add allow(dead_code) to pe_utils and new statics until Plan 03 wiring** - `661809e` (fix)

## Files Created/Modified

- `dlp-hook-dll/src/pe_utils.rs` (NEW, 434 lines) — PE32/PE32+ IAT parsing with bounds checking
- `dlp-hook-dll/src/trampolines.rs` (NEW, 1326 lines) — All 12 trampoline implementations
- `dlp-common/src/hook_ipc.rs` — Added `HandleHookRequest` struct with `handle_value: u64`
- `dlp-hook-dll/src/lib.rs` — Added 10 new `ORIGINAL_*` statics, 10 new `IAT_*` statics, `classify_handle` stub
- `dlp-hook-dll/src/crash_guard.rs` — Fixed `BOOL` import (`windows::core::BOOL`), fixed SEH infinite AV loop
- `dlp-hook-dll/src/fail_closed.rs` — Fixed `BOOL` import for windows 0.62 compatibility
- `dlp-hook-dll/src/pipe_client.rs` — Dead code fixes

## Decisions Made

- Used `u64` for `handle_value` in `HandleHookRequest` to avoid architecture ambiguity when a 32-bit hook DLL talks to a 64-bit agent service.
- Set `MAX_IMPORT_DESCRIPTORS = 512` as a generous upper bound — typical executables import from fewer than 50 DLLs.
- `classify_handle` returns `ALLOW` as a stub until the agent-side handle tracker is implemented (Phase 49/50).
- `CopyFile2` is documented as a known limitation (COM-based, no IAT entry) and excluded from the hook table.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed crash_guard.rs compilation errors against windows 0.62**
- **Found during:** Task 1 (pe_utils.rs creation)
- **Issue:** `BOOL` not in `windows::Win32::Foundation` in windows 0.62 crate; SEH handler returned `EXCEPTION_CONTINUE_EXECUTION` causing infinite AV loop
- **Fix:** Changed `BOOL` import to `windows::core::BOOL`; changed SEH handler return from `EXCEPTION_CONTINUE_EXECUTION` (1) to `EXCEPTION_CONTINUE_SEARCH` (0)
- **Files modified:** `dlp-hook-dll/src/crash_guard.rs`, `dlp-hook-dll/src/fail_closed.rs`
- **Verification:** `cargo test -p dlp-hook-dll` passes; `cargo clippy` clean for our changes
- **Committed in:** `7d3467a` (Task 1 commit)

**2. [Rule 3 - Blocking] Fixed fake PE test alignment issue**
- **Found during:** Task 1 (bounds limit test)
- **Issue:** `std::alloc::alloc_zeroed` with align 8 returned unaligned memory on Windows, causing the fake PE test to fail
- **Fix:** Switched to `VirtualAlloc` which guarantees page alignment
- **Files modified:** `dlp-hook-dll/src/pe_utils.rs`
- **Verification:** `find_iat_entry_respects_max_descriptors_bound` test passes
- **Committed in:** `7d3467a` (Task 1 commit)

**3. [Rule 3 - Blocking] Fixed fake PE descriptor/string overlap**
- **Found during:** Task 1 (bounds limit test refinement)
- **Issue:** Name string at offset 0x300 overlapped with descriptor `FirstThunk` field at offset 16 for later descriptors
- **Fix:** Allocated larger buffer (0x4000) and placed name string at 0x3000, well past descriptor array
- **Files modified:** `dlp-hook-dll/src/pe_utils.rs`
- **Verification:** Bounds limit test passes consistently
- **Committed in:** `7d3467a` (Task 1 commit)

**4. [Rule 1 - Bug] Fixed clippy dead_code errors on new statics**
- **Found during:** Task 3 (trampolines.rs creation)
- **Issue:** New `ORIGINAL_*` and `IAT_*` statics not yet wired into `init()`/`UnhookAll()` (Plan 03), causing clippy `-D warnings` to fail
- **Fix:** Added `#[allow(dead_code)]` to all new statics and `classify_handle` stub; added `#![allow(dead_code)]` to `pe_utils.rs` module
- **Files modified:** `dlp-hook-dll/src/lib.rs`, `dlp-hook-dll/src/pe_utils.rs`
- **Verification:** `cargo clippy -p dlp-hook-dll` passes for our changes
- **Committed in:** `661809e` (fix commit)

**5. [Rule 3 - Blocking] Reordered Task 2 and Task 3 execution**
- **Found during:** Task 2 planning
- **Issue:** Trampolines require `HandleHookRequest` from Task 3, but Task 2 was scheduled before Task 3
- **Fix:** Executed Task 3 (hook_ipc.rs) before Task 2 (trampolines.rs)
- **Files modified:** None — execution order change only
- **Verification:** Trampolines compile with `HandleHookRequest` in scope
- **Committed in:** `64d1382` then `5ed1fb4`

---

**Total deviations:** 5 auto-fixed (3 blocking, 1 bug, 1 execution order)
**Impact on plan:** All auto-fixes necessary for correctness and compilation. No scope creep.

## Issues Encountered

- `crash_guard.rs` and `fail_closed.rs` existed from parallel agent (Plan 48-01) but had compilation errors against windows 0.62. Fixed inline per deviation Rule 3.
- Pre-existing clippy errors in `lib.rs` (transmute annotations, type complexity), `pipe_client.rs` (unnecessary cast, unused Timeout variant), and `crash_guard.rs` (thread_local const, Result<(), ()>) are out of scope for this plan — they existed before our changes.

## Known Stubs

| Stub | File | Line | Reason |
|------|------|------|--------|
| `classify_handle` returns `ALLOW` | `dlp-hook-dll/src/lib.rs` | 641 | Agent-side handle tracker not yet implemented (Phase 49/50) |

## Threat Flags

No new threat surface introduced beyond what is documented in the plan's `<threat_model>`.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- **Plan 48-03** can now wire `init()` and `UnhookAll()` to populate the 10 new `ORIGINAL_*` and `IAT_*` statics
- **Phase 49/50** should implement agent-side handle tracker so `classify_handle` can resolve paths from HANDLE values
- All 12 trampolines are ready for IAT patching once `init()` is extended

---
*Phase: 48-hook-dll-surface-expansion-crash-hardening-build-harness*
*Completed: 2026-05-15*
