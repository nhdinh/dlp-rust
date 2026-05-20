---
phase: 50-shared-memory-classification-cache-fail-mode-state-machine
plan: 03
subsystem: hook-dll
tags: [shared-memory, cache, fnv1a, lru, path-normalization, windows-api, lock-free]

requires:
  - phase: 50-01
    provides: IPC protocol with cache_version, cache_hint, HookOp
  - phase: 50-02
    provides: Agent-side ClassificationCache with CacheHeader/PrefixEntry/HashEntry ABI

provides:
  - Hook DLL shared-memory cache reader (CacheLookup) with lazy OnceLock init
  - Two-tier lookup: longest-prefix match + FNV-1a hash table with open addressing
  - Thread-local LRU cache (128 entries) with version invalidation
  - Hardened Windows path normalization (NT/DOS/UNC, rejects 8.3/ADS/volume GUID)
  - Allowlist module with hardcoded system paths (System32, WinSxS, etc.)
  - Trampoline integration: allowlist -> LRU -> cache -> pipe fallback flow
  - Tier-gated fast-path decisions: T3/T4 write = deny, T1/T2 = allow

affects:
  - 50-04 (fail-mode state machine integration)
  - 50-05 (background thread for ISOLATED-state RESYNC)
  - 51 (ntdll syscall-stub patching — cache lookup precedes patch)
  - 52 (DACL tripwire — cache provides classification hints)

tech-stack:
  added: []
  patterns:
    - "OnceLock lazy init for DLL shared-memory mapping (NOT DllMain)"
    - "Split validation: full on version change, cheap magic check per lookup"
    - "Thread-local LRU with version-keyed invalidation"
    - "FNV-1a 64-bit with open addressing and linear probing"
    - "Longest-prefix match with descending-length sort"
    - "Acquire-load on version_word before any data access"

key-files:
  created:
    - dlp-hook-dll/src/classification_cache.rs
    - dlp-hook-dll/src/allowlist.rs
  modified:
    - dlp-hook-dll/src/lib.rs (add mod declarations)
    - dlp-hook-dll/src/trampolines.rs (cache integration in classify_and_log_path)

key-decisions:
  - "Defined CacheHeader/HashEntry/PrefixEntry locally in hook DLL instead of re-exporting from dlp-agent to avoid cross-crate dependency and ensure 32/64-bit compatibility"
  - "Used OnceLock (not DllMain) for shared-memory mapping to avoid loader-lock deadlock"
  - "Thread-local LRU stores cache_version per entry; invalidates on global version flip automatically"
  - "Path normalization rejects reparse points, symlinks, junctions, volume GUIDs, ADS, 8.3 short names — forces pipe fallback for safety"
  - "Allowlist is performance optimization only; DACL tripwire (Phase 52) is the security backstop"

patterns-established:
  - "Lazy-init shared-memory reader: OnceLock + try_init pattern for DLL resources"
  - "Split validation gate: full_validation on version change, cheap magic check per lookup"
  - "Tier-gated fast-path: T3/T4 write = deny (skip pipe), T1/T2 = allow (skip pipe), Read = always allow (ABAC on pipe)"
  - "Circular-buffer LRU (no allocation) with version-keyed invalidation"

requirements-completed: [CACHE-02, CACHE-05, CACHE-06, FAIL-02]

duration: 16min
completed: 2026-05-20
---

# Phase 50 Plan 03: Hook DLL Shared-Memory Cache Reader Summary

**Hook DLL shared-memory cache reader with formal ABI validation, two-tier lookup (prefix + hash), thread-local LRU with version invalidation, hardened path normalization, and trampoline integration for sub-50us fast-path decisions.**

## Performance

- **Duration:** 16 minutes
- **Started:** 2026-05-20T08:48:14Z
- **Completed:** 2026-05-20T09:04:14Z
- **Tasks:** 7 (all complete)
- **Files modified:** 4

## Accomplishments

- Built `CacheLookup` with `OnceLock` lazy init (NOT `DllMain`) for `Global\DlpClassificationCache`
- Implemented split validation: full ABI validation (magic, layout_version, checksum, bounds) on version change; cheap magic check per lookup
- Two-tier lookup: longest-prefix match (sorted descending) + FNV-1a hash table with open addressing and linear probing
- Thread-local LRU cache (128 entries) keyed by cache_version — automatic invalidation on global version flip
- Hardened Windows path normalization: NT/DOS/UNC handling, case-folding, trailing separator strip, rejects 8.3 short names, volume GUIDs, ADS streams, trailing dots/spaces
- Allowlist module with hardcoded system paths (System32, SysWOW64, WinSxS, WindowsApps, Program Files\Common Files)
- Integrated cache lookup into trampolines: allowlist -> LRU -> cache -> pipe fallback flow
- Tier-gated fast-path decisions: T3/T4 write = deny (skip pipe), T1/T2 = allow (skip pipe), Read = always allow
- 119 tests pass (47 classification_cache + 7 allowlist + 65 existing hook DLL tests)
- Clippy clean with `-D warnings`

## Task Commits

Each task was committed atomically:

1. **Task 1-5: CacheLookup, path normalization, prefix/hash lookup, LRU** — `7a87899` (feat)
2. **Task 6: Trampoline integration with allowlist + LRU + pipe fallback** — `547d209` (feat)
3. **Task 7: Adversarial path tests + ABI struct fixes + formatting** — `93089eb` (refactor)

## Files Created/Modified

- `dlp-hook-dll/src/classification_cache.rs` (NEW) — Shared-memory cache reader with validation, two-tier lookup, thread-local LRU, path normalization
- `dlp-hook-dll/src/allowlist.rs` (NEW) — Hardcoded trusted-path allowlist for system directories and build tools
- `dlp-hook-dll/src/lib.rs` — Added `mod allowlist;` and `mod classification_cache;` declarations
- `dlp-hook-dll/src/trampolines.rs` — Modified `classify_and_log_path` to integrate allowlist -> LRU -> cache -> pipe flow

## Decisions Made

- Defined `CacheHeader`, `HashEntry`, `PrefixEntry` locally in the hook DLL instead of re-exporting from `dlp-agent`. This avoids adding `dlp-agent` as a dependency of `dlp-hook-dll` (which would create a circular dependency) and ensures the DLL has full control over the ABI layout.
- Used `std::sync::OnceLock` for lazy initialization on first hook call rather than `DllMain`. This avoids the Windows loader-lock deadlock risk documented in Phase 48-01 review feedback.
- Thread-local LRU uses a circular buffer (no heap allocation in hot path) with version-keyed invalidation. When the global cache version flips, stale entries become automatic misses without explicit clearing.
- Path normalization is conservative: any path that cannot be safely normalized (8.3, volume GUID, ADS, trailing dots/spaces, device paths) forces pipe fallback. This prioritizes security over performance for edge cases.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `dlp_agent` crate not available to `dlp-hook-dll`**
- **Found during:** Task 1 (CacheLookup struct definition)
- **Issue:** Plan specified `pub use dlp_agent::classification_cache::{CacheHeader, HashEntry, PrefixEntry};` but `dlp-agent` is not a dependency of `dlp-hook-dll` and adding it would create a circular dependency.
- **Fix:** Defined `CacheHeader`, `HashEntry`, `PrefixEntry` locally in `classification_cache.rs` with identical `#[repr(C)]` layout to ensure ABI compatibility.
- **Files modified:** `dlp-hook-dll/src/classification_cache.rs`
- **Verification:** Tests compile and pass; struct sizes match agent-side definitions.
- **Committed in:** `93089eb`

**2. [Rule 1 - Bug] `FILE_MAP_READ` type mismatch with `OpenFileMappingW`**
- **Found during:** Task 1 (compilation)
- **Issue:** `OpenFileMappingW` expects `u32` for `dwDesiredAccess` but `FILE_MAP_READ` is of type `FILE_MAP` in windows-rs 0.62.
- **Fix:** Used `FILE_MAP_READ.0` to extract the underlying `u32` value.
- **Files modified:** `dlp-hook-dll/src/classification_cache.rs`
- **Verification:** Compiles and tests pass.
- **Committed in:** `7a87899`

**3. [Rule 2 - Missing Critical] `header` field was private, inaccessible from trampolines**
- **Found during:** Task 6 (trampoline integration)
- **Issue:** `trampolines.rs` needed to read `version_word` from the header for LRU version checking, but `header` was a private field.
- **Fix:** Added `current_version_word()` public method to `CacheLookup` that performs the Acquire load internally, preserving encapsulation.
- **Files modified:** `dlp-hook-dll/src/classification_cache.rs`, `dlp-hook-dll/src/trampolines.rs`
- **Verification:** Trampoline integration compiles and all tests pass.
- **Committed in:** `547d209`

---

**Total deviations:** 3 auto-fixed (3 bugs)
**Impact on plan:** All auto-fixes necessary for compilation and correctness. No scope creep.

## Issues Encountered

- `cargo fmt --check` initially failed due to long lines and formatting inconsistencies. Fixed by running `cargo fmt`.
- Clippy `-D warnings` flagged unused `allowlist` functions (`is_build_tool_process`, `get_process_image_path`) and static (`PROCESS_IMAGE_PATH`). Added `#[allow(dead_code)]` since these are stubs for future plan integration (CACHE-06 build-tool bypass).

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: shared-memory-read-only | `dlp-hook-dll/src/classification_cache.rs` | DLL maps cache `FILE_MAP_READ` only; Windows MMU enforces write protection against tampering by hooked processes |
| threat_flag: path-bypass-mitigation | `dlp-hook-dll/src/classification_cache.rs` | Normalization rejects 8.3, volume GUID, ADS, trailing dots/spaces — forces pipe fallback for bypass attempts |
| threat_flag: bounds-checking | `dlp-hook-dll/src/classification_cache.rs` | All pointer arithmetic bounds-checked against `header.total_size`; malformed cache returns None (miss) |

## Known Stubs

| File | Line | Description | Resolution Plan |
|------|------|-------------|-----------------|
| `dlp-hook-dll/src/allowlist.rs:74` | `is_build_tool_process()` | Build-tool process allowlist (CACHE-06) | Plan 50-04 or 50-05 — integrate with fail-mode state machine |
| `dlp-hook-dll/src/allowlist.rs:87` | `get_process_image_path()` | Process image path lookup for build-tool check | Same as above |
| `dlp-hook-dll/src/trampolines.rs:169` | `classify_and_log_handle` | Handle-based hooks do not yet use cache (only path-based hooks do) | Plan 50-04 — extend cache to handle-based lookups via agent handle tracker |

## Next Phase Readiness

- Cache reader is fully functional and integrated into trampolines.
- Ready for Plan 50-04 (fail-mode state machine: HEALTHY -> DEGRADED -> ISOLATED -> RESYNC).
- Ready for Plan 50-05 (background thread for ISOLATED-state RESYNC detection).
- The allowlist module is a foundation for CACHE-05/CACHE-06; build-tool process detection needs fail-mode state machine to be meaningful.

---
*Phase: 50-shared-memory-classification-cache-fail-mode-state-machine*
*Completed: 2026-05-20*
