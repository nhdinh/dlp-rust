---
phase: 56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed
plan: 03
subsystem: hook-dll

tags:
  - volume-class
  - thread-local-cache
  - named-pipe
  - trampoline
  - abac
  - fail-closed

requires:
  - phase: 56-01
    provides: VolumeClass enum, resolve_volume_class_from_path, AbacContext volume fields
  - phase: 56-02
    provides: Agent-side VolumeDetector with volume_class_map

provides:
  - Thread-local volume class cache with 10s TTL in hook DLL
  - Named pipe VolumeClassQuery/VolumeClassResponse integration
  - Volume class resolution in all path-based trampolines
  - CopyFileExW and MoveFileExW populate both source and destination volume classes
  - Cache invalidation (full and per-letter) for device-change handling

affects:
  - 56-04
  - 56-05

tech-stack:
  added: []
  patterns:
    - "thread_local! RefCell<HashMap> for per-thread cache without synchronization"
    - "Named pipe raw request for VolumeClassQuery (not HookRequest envelope)"
    - "Volume class resolution AFTER allowlist check, BEFORE shared-memory cache"

key-files:
  created:
    - dlp-hook-dll/src/volume_class_cache.rs
  modified:
    - dlp-hook-dll/src/lib.rs - added pub mod volume_class_cache
    - dlp-hook-dll/src/trampolines.rs - volume class in classify_and_log_path and all callers

key-decisions:
  - "Volume class resolution happens after allowlist check (fastest path) and before shared-memory cache lookup"
  - "classify_path_with_volume_class helper wraps pipe call with volume class parameters (currently accepted but not yet serialized into HookRequest — HookRequest lacks volume class fields, to be added in Plan 56-06)"
  - "Handle-based trampolines (WriteFile, NtWriteFile, SetFileInformationByHandle) unchanged — volume class requires path which is only available server-side from handle tracker"

patterns-established:
  - "Thread-local cache keyed by drive letter with TTL expiration and surgical invalidation"
  - "Fail-closed: pipe failure or unknown path returns None, never LocalNTFS"

requirements-completed:
  - DRIVE-03

# Metrics
duration: 13 min
completed: 2026-06-06
---

# Phase 56 Plan 03: Hook DLL Volume-Class Cache and Trampoline Integration Summary

**Thread-local volume class cache (10s TTL) with named pipe agent queries, wired into all path-based trampolines including CopyFileExW/MoveFileExW dual-path resolution**

## Performance

- **Duration:** 13 min
- **Started:** 2026-06-06T03:50:12Z
- **Completed:** 2026-06-06T04:03:36Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Created `volume_class_cache.rs` with thread-local `HashMap<char, (VolumeClass, Instant)>` cache
- Implemented `resolve_volume_class(letter)` with 10s TTL and named pipe fallback
- Implemented `resolve_volume_class_from_path(path)` delegating to `dlp_common::abac::resolve_volume_class_from_path`
- Implemented `invalidate_cache()` and `invalidate_cache_for_letter(letter)` for device-change handling
- Implemented `query_volume_class_from_agent(letter)` using `VolumeClassQuery` / `VolumeClassResponse` over raw named pipe
- Extended `classify_and_log_path` to accept `source_volume_class` and `destination_volume_class`
- Added `classify_path_with_volume_class` helper for pipe round-trips with volume class context
- Wired volume class resolution into all 9 path-based trampolines:
  - `HookCreateFileW`, `HookNtCreateFile`, `HookNtOpenFile`
  - `HookDeleteFileW`, `HookReplaceFileW`
  - `HookMoveFileExW` (both source and destination)
  - `HookCopyFileExW` (both source and destination)
  - `NtdllTrampolineNtCreateFile`, `NtdllTrampolineNtOpenFile`
- 15 unit tests for volume class cache covering TTL, invalidation, thread isolation, fail-closed

## Task Commits

1. **Task 1: Create volume_class_cache.rs** - `5c08c4d` (feat)
2. **Task 2: Wire volume class into trampolines** - `e74b709` (feat)

## Files Created/Modified

- `dlp-hook-dll/src/volume_class_cache.rs` - Thread-local cache with TTL, path resolution, named pipe queries, cache invalidation
- `dlp-hook-dll/src/lib.rs` - Added `pub mod volume_class_cache;`, marked `classify_path` with `#[allow(dead_code)]`
- `dlp-hook-dll/src/trampolines.rs` - Extended `classify_and_log_path` signature, added `classify_path_with_volume_class`, wired volume class into all path-based trampolines

## Decisions Made

- Volume class resolution happens after allowlist check (fastest path) and before shared-memory cache lookup, minimizing overhead for allowlisted paths
- `classify_path_with_volume_class` accepts volume class parameters but does not yet serialize them into `HookRequest` — `HookRequest` lacks volume class fields. This is a forward-compatible stub: when Plan 56-06 adds the fields, only this helper needs updating
- Handle-based trampolines (WriteFile, NtWriteFile, SetFileInformationByHandle) were left unchanged because they use `classify_and_log_handle` which sends HANDLE values to the agent; the agent resolves the path server-side. Volume class could be added there in a future plan if the agent's handle tracker also resolves volume class

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-existing flaky tests in `hook_journal` and `thread_suspender` modules failed intermittently (unrelated to this plan). Re-runs confirmed they pass consistently. These are pre-existing issues outside plan scope.

## Self-Check

- [x] `dlp-hook-dll/src/volume_class_cache.rs` exists
- [x] `grep -n "thread_local!" dlp-hook-dll/src/volume_class_cache.rs` returns line 49
- [x] `grep -n "pub fn resolve_volume_class_from_path" dlp-hook-dll/src/volume_class_cache.rs` returns line 117 with `-> Option<VolumeClass>`
- [x] `grep -n "pub fn invalidate_cache" dlp-hook-dll/src/volume_class_cache.rs` returns line 128
- [x] `grep -n "pub fn invalidate_cache_for_letter" dlp-hook-dll/src/volume_class_cache.rs` returns line 143
- [x] `grep -n "pub mod volume_class_cache" dlp-hook-dll/src/lib.rs` returns line 63
- [x] `grep -n "VolumeClassQuery" dlp-hook-dll/src/volume_class_cache.rs` returns line 174
- [x] `grep -n "VolumeClassResponse" dlp-hook-dll/src/volume_class_cache.rs` returns line 174
- [x] `cargo test -p dlp-hook-dll` compiles with zero errors (281 passed, 1 ignored)
- [x] `cargo clippy -p dlp-hook-dll -- -D warnings` passes
- [x] `cargo fmt --check` passes
- [x] `grep -n "volume_class_cache::resolve_volume_class_from_path" dlp-hook-dll/src/trampolines.rs` returns 13 lines
- [x] `grep -n "source_volume_class" dlp-hook-dll/src/trampolines.rs` returns lines in AbacContext construction
- [x] `grep -n "destination_volume_class" dlp-hook-dll/src/trampolines.rs` returns lines in AbacContext construction

## Next Phase Readiness

- Plan 56-03 is complete. Ready for Plan 56-06 (HookRequest volume class field extension) or downstream plans that consume the hook DLL volume class cache.
- The cache is fully functional but the volume class values are not yet transmitted over the pipe (HookRequest lacks the fields). Plan 56-06 should:
  1. Add `source_volume_class` and `destination_volume_class` to `HookRequest`
  2. Update `classify_path_with_volume_class` to populate these fields
  3. Update agent-side request handler to read volume classes from `HookRequest`

---
*Phase: 56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed*
*Completed: 2026-06-06*
