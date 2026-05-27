---
phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
plan: 03
subsystem: dlp-common + dlp-hook-dll
tags: [path-normalization, fnv1a, hash, etw, shared-module]
dependency_graph:
  requires: []
  provides: [normalize_path, path_hash, fnv1a_64, nt_path_to_dos_path]
  affects: [dlp-common, dlp-hook-dll, dlp-agent]
tech_stack:
  added: []
  patterns: [shared-module-extraction, cross-crate-reuse]
key_files:
  created:
    - dlp-common/src/path_hash.rs
  modified:
    - dlp-common/src/lib.rs
    - dlp-hook-dll/src/classification_cache.rs
    - dlp-agent/src/lib.rs
    - dlp-hook-dll/src/hook_journal.rs
decisions:
  - "Extracted normalize_path into dlp-common to ensure byte-identical normalization across hook DLL and bypass correlator (D-06)"
  - "Used pub use crate::hash::fnv1a_64 re-export pattern to avoid code duplication"
  - "nt_path_to_dos_path uses QueryDosDeviceW on Windows, compile stub on non-Windows"
  - "Commented out etw_kernel_file module declaration in dlp-agent/src/lib.rs since module file does not yet exist"
metrics:
  duration_minutes: 45
  completed_date: "2026-05-27T16:54:00Z"
  tasks_completed: 3
  tests_passed: 79
---

# Phase 53 Plan 03: Extract path normalization and FNV-1a hashing into shared dlp-common module

## Summary

Extracted hardened Windows path normalization and FNV-1a 64-bit hashing from
`dlp-hook-dll/src/classification_cache.rs` into a shared `dlp-common/src/path_hash.rs`
module. Added NT device path-to-DOS path conversion for ETW consumer use. Both the
hook DLL and the future bypass correlator will now use identical normalization,
eliminating the risk of path-hash mismatch and false bypass alerts (Pitfall 5 in
RESEARCH.md, review concern WR-09).

## One-liner

Shared path normalization + FNV-1a hashing module with NT path conversion, extracted
from hook DLL into dlp-common for cross-boundary hash consistency.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create dlp-common/src/path_hash.rs | b74ff0f | dlp-common/src/path_hash.rs, dlp-common/src/lib.rs |
| 2 | Update classification_cache.rs to import from dlp-common | b44eba5 | dlp-hook-dll/src/classification_cache.rs, dlp-agent/src/lib.rs, dlp-hook-dll/src/hook_journal.rs |
| 3 | Unit tests for path_hash.rs | (part of Task 1) | dlp-common/src/path_hash.rs |

## Verification Results

- `cargo test -p dlp-common path_hash` — 32 passed, 0 failed
- `cargo test -p dlp-hook-dll classification_cache` — 47 passed, 0 failed
- `cargo clippy -p dlp-common -p dlp-hook-dll -- -D warnings` — clean
- `cargo build --workspace` — succeeded
- No `.unwrap()` in library code paths (only in doc examples and test code)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed QueryDosDeviceW return type handling**
- **Found during:** Task 1
- **Issue:** `QueryDosDeviceW` in `windows` crate 0.62 returns `u32` directly (not `Result<u32, _>`)
- **Fix:** Changed from `match result { Ok(len) => ..., Err(_) => ... }` to direct `u32` comparison
- **Files modified:** dlp-common/src/path_hash.rs
- **Commit:** b74ff0f (amended in same commit)

**2. [Rule 3 - Blocking] Fixed dlp-agent etw_kernel_file module declaration**
- **Found during:** Task 2
- **Issue:** `dlp-agent/src/lib.rs` had an uncommented `pub mod etw_kernel_file;` but the module file did not exist, causing workspace build failure
- **Fix:** Commented out the module declaration with a note that it will be enabled when the module is created in a future plan
- **Files modified:** dlp-agent/src/lib.rs
- **Commit:** b44eba5

**3. [Rule 1 - Bug] Fixed unused UnmapViewOfFile import in hook_journal.rs**
- **Found during:** Task 2
- **Issue:** `UnmapViewOfFile` was imported but unused, causing clippy `-D warnings` failure
- **Fix:** Removed `UnmapViewOfFile` from the import list
- **Files modified:** dlp-hook-dll/src/hook_journal.rs
- **Commit:** b44eba5

## Auth Gates

None.

## Known Stubs

| File | Line | Description | Reason |
|------|------|-------------|--------|
| dlp-agent/src/lib.rs | 155-156 | `etw_kernel_file` module commented out | Module will be created in Plan 53-01 |

## Threat Flags

None. The shared module extraction reduces threat surface by eliminating normalization
drift between hook DLL and correlator (T-53-09 disposition: mitigate).

## Self-Check: PASSED

- [x] `dlp-common/src/path_hash.rs` exists
- [x] `dlp-common/src/lib.rs` contains `pub mod path_hash;`
- [x] `normalize_path` produces identical output to original classification_cache.rs version
- [x] `path_hash` convenience function normalizes then hashes
- [x] `fnv1a_64` re-exported from hash.rs
- [x] `nt_path_to_dos_path` handles NT device paths on Windows
- [x] `classification_cache.rs` imports `normalize_path` from dlp-common
- [x] All 32 path_hash unit tests pass
- [x] All 47 classification_cache tests pass (no regression)
- [x] Clippy clean (-D warnings)
- [x] Workspace builds successfully
- [x] No unwrap in library code paths
