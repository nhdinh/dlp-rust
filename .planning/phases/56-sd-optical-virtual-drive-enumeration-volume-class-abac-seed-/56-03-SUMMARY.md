---
phase: 56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed
plan: 03
subsystem: enforcement

tags:
  - volume-class
  - thread-local-cache
  - named-pipe
  - trampoline
  - fail-closed
  - abac
  - hook-dll

requires:
  - phase: 56-01
    provides: VolumeClass enum, AbacContext volume class fields, resolve_volume_class_from_path
  - phase: 56-02
    provides: VolumeDetector with WMI queries, VolumeClassQuery/VolumeClassResponse IPC types

provides:
  - Thread-local volume class cache with 10s TTL in hook DLL
  - Path-based volume class resolution at trampoline time (no WMI in hot path)
  - Cache invalidation on device removal (invalidate_cache, invalidate_cache_for_letter)
  - Volume class populated into HookRequest/AbacContext before pipe round-trip
  - CopyFileExW and MoveFileExW resolve both source and destination volume classes
  - Named pipe query to agent on cache miss

affects:
  - 56-04
  - 56-05
  - 56-06

tech-stack:
  added: []
  patterns:
    - "Thread-local RefCell<HashMap> cache pattern (from classification_cache.rs)"
    - "Fail-closed: pipe failure returns None, never LocalNTFS"
    - "Volume class resolution after allowlist check, before pipe round-trip"
    - "Named pipe IPC for cache miss queries (no shared-memory cache for volume classes)"

key-files:
  created:
    - dlp-hook-dll/src/volume_class_cache.rs
  modified:
    - dlp-hook-dll/src/trampolines.rs
    - dlp-hook-dll/src/lib.rs
    - dlp-common/src/hook_ipc.rs

key-decisions:
  - "Extended HookRequest with source_volume_class and destination_volume_class fields (not AbacContext, which is server-side only) to carry volume class context from hook DLL to agent"
  - "Made VOLUME_CLASS_CACHE pub(crate) to enable test pre-warming without exposing to external callers"
  - "Volume class resolution happens after allowlist check but before pipe round-trip, minimizing hot-path overhead for allowlisted paths"

patterns-established:
  - "Thread-local cache with TTL: thread_local! { RefCell<HashMap<K, (V, Instant)>> } — same pattern as classification_cache.rs"
  - "Fail-closed volume classification: any error returns None, never defaults to LocalNTFS"
  - "Dual-volume-class trampolines: CopyFileExW and MoveFileExW resolve both source and destination paths"

requirements-completed:
  - DRIVE-03

# Metrics
duration: 45min
completed: 2026-05-29
---

# Phase 56 Plan 03: Hook DLL Volume-Class Resolution Summary

**Thread-local volume class cache with 10s TTL, named pipe queries on miss, and full trampoline integration for source/destination volume class population into ABAC context**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-29T00:00:00Z
- **Completed:** 2026-05-29T00:45:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Thread-local volume class cache (`VOLUME_CLASS_CACHE`) with 10-second TTL eliminates WMI queries from the hot path
- `resolve_volume_class_from_path` handles UNC paths (NetworkShare), drive letters (cache/agent lookup), and volume GUIDs (None/fail-closed)
- Cache invalidation functions (`invalidate_cache`, `invalidate_cache_for_letter`) for device removal events
- `classify_and_log_path` resolves volume class after allowlist check, before pipe round-trip
- CopyFileExW and MoveFileExW trampolines resolve both source and destination volume classes
- All other trampolines auto-resolve source volume class from path
- `HookRequest` extended with `source_volume_class` and `destination_volume_class` for IPC to agent
- 12 unit tests covering cache TTL, invalidation, UNC paths, pipe failure, volume GUIDs, case insensitivity, and trampoline integration

## Task Commits

Each task was committed atomically:

1. **Task 1: Create volume_class_cache.rs with thread-local cache, path resolution, and cache invalidation** - `2c87c23` (feat)
2. **Task 2: Wire volume class into trampolines.rs classify_and_log_path and copy/move trampolines** - `b6c64d6` (feat)

**Plan metadata:** `TBD` (docs: complete plan)

## Files Created/Modified

- `dlp-hook-dll/src/volume_class_cache.rs` (created) - Thread-local volume class cache with TTL, path resolution, cache invalidation, named pipe queries
- `dlp-hook-dll/src/trampolines.rs` (modified) - Volume class resolution in classify_and_log_path; CopyFileExW/MoveFileExW resolve both source and destination
- `dlp-hook-dll/src/lib.rs` (modified) - Added `pub mod volume_class_cache;`, extended classify_path signature with volume class params
- `dlp-common/src/hook_ipc.rs` (modified) - Added `source_volume_class` and `destination_volume_class` to `HookRequest`

## Decisions Made

- Extended `HookRequest` (not `AbacContext`) with volume class fields because `AbacContext` is server-side only; `HookRequest` is the IPC type that carries context from hook DLL to agent
- Made `VOLUME_CLASS_CACHE` `pub(crate)` (not `pub`) to enable test pre-warming without exposing cache internals to external callers
- Volume class resolution happens after allowlist check but before pipe round-trip: allowlisted paths skip even the cache lookup, minimizing overhead

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Private VOLUME_CLASS_CACHE inaccessible from trampoline tests**
- **Found during:** Task 2 (trampoline integration)
- **Issue:** Tests in trampolines.rs needed to pre-warm the cache but `VOLUME_CLASS_CACHE` was private
- **Fix:** Changed `static VOLUME_CLASS_CACHE` to `pub(crate) static VOLUME_CLASS_CACHE` inside the `thread_local!` macro
- **Files modified:** `dlp-hook-dll/src/volume_class_cache.rs`
- **Verification:** Trampoline tests compile and pass
- **Committed in:** `b6c64d6` (Task 2 commit)

**2. [Rule 1 - Bug] Unused import VolumeClassResponse in volume_class_cache.rs**
- **Found during:** Task 1 (cache module creation)
- **Issue:** `VolumeClassResponse` was imported but unused (response is deserialized as `IpcPayloadV1::VolumeClassResponse` via pattern matching)
- **Fix:** Removed the unused import
- **Files modified:** `dlp-hook-dll/src/volume_class_cache.rs`
- **Verification:** `cargo clippy -- -D warnings` passes
- **Committed in:** `2c87c23` (Task 1 commit)

**3. [Rule 3 - Blocking] Doc comment on thread_local! macro caused rustdoc warning**
- **Found during:** Task 1 (cache module creation)
- **Issue:** Rustdoc does not generate documentation for macro invocations; `///` comments above `thread_local!` are invalid
- **Fix:** Changed `///` to `//` comments above the `thread_local!` macro
- **Files modified:** `dlp-hook-dll/src/volume_class_cache.rs`
- **Verification:** `cargo clippy -- -D warnings` passes
- **Committed in:** `2c87c23` (Task 1 commit)

**4. [Rule 3 - Blocking] Link error LNK1104 from concurrent test binary lock**
- **Found during:** Task 2 verification
- **Issue:** Test binary locked by background process from prior run, preventing compilation
- **Fix:** Killed the locking process with `taskkill /F /IM dlp-hook-dll-*.exe` and retried
- **Files modified:** None
- **Verification:** `cargo test -p dlp-hook-dll --lib` passes (271 tests)
- **Committed in:** N/A (environment issue, not code change)

---

**Total deviations:** 4 auto-fixed (3 Rule 1 bugs, 1 Rule 3 blocking)
**Impact on plan:** All auto-fixes necessary for correctness and compilation. No scope creep.

## Issues Encountered

- **Link error LNK1104**: Test binary locked by concurrent background process. Resolved by killing the process and retrying. This is an environment issue, not a code issue.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Hook DLL volume class resolution is complete and ready for agent-side ABAC evaluation
- Agent service can now receive `source_volume_class` and `destination_volume_class` in `HookRequest`
- Volume class cache invalidation hooks are ready for WM_DEVICECHANGE integration (if device notification handler exists)
- Ready for Plan 56-04 (agent-side volume class ABAC condition evaluation)

---
*Phase: 56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed*
*Completed: 2026-05-29*
