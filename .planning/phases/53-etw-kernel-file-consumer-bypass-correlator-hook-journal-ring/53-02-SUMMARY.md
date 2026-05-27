---
phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
plan: 02
subsystem: dlp-hook-dll
tags: [hook-journal, shared-memory, ring-buffer, trampolines, bypass-correlator]
dependency_graph:
  requires: [53-03]
  provides: [53-04]
  affects: [dlp-hook-dll/src/hook_journal.rs, dlp-hook-dll/src/trampolines.rs, dlp-hook-dll/src/lib.rs]
tech_stack:
  added: []
  patterns: [CreateFileMappingW, MapViewOfFile, PAGE_READWRITE, FILE_MAP_ALL_ACCESS, write_volatile, atomic::fence(Release)]
key_files:
  created:
    - dlp-hook-dll/src/hook_journal.rs
  modified:
    - dlp-hook-dll/src/trampolines.rs
    - dlp-hook-dll/src/lib.rs
decisions:
  - "Increased _pad from [u8; 7] to [u8; 15] to achieve 56-byte JournalEntry size (plan math was inconsistent; 48 bytes calculated vs 56 stated)"
  - "Used local namespace (no Global\\ prefix) for test journal names to avoid SeCreateGlobalPrivilege requirement in CI"
  - "Fixed test_error_already_exists_opens_existing to keep first view mapped during second call (mapping is destroyed when last view is unmapped)"
  - "Single journal_write call at end of classify_and_log_path/handle covers all return paths (allowlist, cache hit, pipe, fail-closed)"
metrics:
  duration_seconds: 1528
  completed_date: "2026-05-27T16:36:28Z"
  tasks_completed: 3
  tests_added: 13
---

# Phase 53 Plan 02: Hook DLL Journal Ring Buffer Summary

**One-liner:** Per-process shared-memory journal (`Global\DlpHookJournal_<pid>`) with Release-fence SPSC synchronization, written before every trampoline return for bypass correlator ground truth.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create hook_journal.rs with shared-memory ring buffer and Release fence | e2ffe83 | dlp-hook-dll/src/hook_journal.rs, dlp-hook-dll/src/lib.rs |
| 2 | Integrate journal_write into all trampolines | 73e2a61 | dlp-hook-dll/src/trampolines.rs |
| 3 | Unit tests for hook_journal.rs | (included in e2ffe83 via b44eba5) | dlp-hook-dll/src/hook_journal.rs |

## Verification Results

- `cargo test -p dlp-hook-dll hook_journal -- --test-threads=1`: **13/13 passed**
- `cargo test -p dlp-hook-dll trampolines -- --test-threads=1`: **19/19 passed**
- `cargo clippy -p dlp-hook-dll -- -D warnings`: **clean**
- `grep "\.unwrap()" dlp-hook-dll/src/hook_journal.rs dlp-hook-dll/src/trampolines.rs`: **none found**

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] JournalEntry size mismatch between plan specification and actual layout**
- **Found during:** Task 3 (test execution)
- **Issue:** Plan specified `_pad: [u8; 7]` and claimed total size of 56 bytes, but actual `size_of::<JournalEntry>()` was 48 bytes (8+8+1+7+8+8+8 = 48)
- **Fix:** Increased `_pad` to `[u8; 15]` to achieve 56-byte struct size. Updated layout test offsets accordingly. ENTRY_CAPACITY corrected to 1170 (was 1169 in plan, which was mathematically incorrect for 56-byte entries)
- **Files modified:** dlp-hook-dll/src/hook_journal.rs
- **Commit:** e2ffe83 (amended in working tree before commit)

**2. [Rule 1 - Bug] Windows tests failed with "Access is denied" for Global namespace**
- **Found during:** Task 3 (test execution)
- **Issue:** `CreateFileMappingW` with `Global\DlpHookJournal_Test` requires `SeCreateGlobalPrivilege`, unavailable in test runner context
- **Fix:** Changed `TEST_JOURNAL_NAME` from `Global\DlpHookJournal_Test` to `DlpHookJournal_Test` (local namespace)
- **Files modified:** dlp-hook-dll/src/hook_journal.rs
- **Commit:** e2ffe83

**3. [Rule 1 - Bug] test_error_already_exists_opens_existing failed due to mapping destruction**
- **Found during:** Task 3 (test execution)
- **Issue:** Test unmapped and closed the first handle before the second call, causing Windows to destroy the mapping object. Second call then created a fresh mapping instead of getting ERROR_ALREADY_EXISTS.
- **Fix:** Removed premature unmap/close of first view; kept it mapped during the second call to simulate the real-world scenario where the hook DLL holds the mapping for the process lifetime.
- **Files modified:** dlp-hook-dll/src/hook_journal.rs
- **Commit:** e2ffe83

### Pre-existing Issues (Out of Scope)

- `dlp-agent/src/etw_kernel_file.rs` (untracked, from prior session): Compilation errors in ferrisetw API usage. Temporarily moved aside and `mod etw_kernel_file` commented out in `dlp-agent/src/lib.rs` to allow workspace build during verification. Restored after verification.
- `thread_suspender` tests fail intermittently when run multi-threaded (pre-existing race condition, unrelated to this plan).

## Known Stubs

None. All journal fields are fully written and read back in tests. `etw_timestamp` is set to 0 by the hook DLL (per design — the correlator backfills from ETW events).

## Threat Flags

None introduced beyond the planned threat model. The existing mitigations are in place:
- Agent opens journal with `FILE_MAP_READ` only; DLL creates with `PAGE_READWRITE`
- All failure paths in `try_init()` return `None` silently (no crash)
- Path hashes are one-way FNV-1a; no reversible path data in journal

## Self-Check: PASSED

- [x] `dlp-hook-dll/src/hook_journal.rs` exists and compiles
- [x] `JournalHeader` is 8 bytes (verified by test)
- [x] `JournalEntry` is 56 bytes (verified by test)
- [x] `ENTRY_CAPACITY` is 1170 entries
- [x] `HookJournal::try_init()` creates shared memory with correct name format
- [x] On `ERROR_ALREADY_EXISTS`, falls through to `OpenFileMappingW`
- [x] `journal_write()` uses `atomic::fence(Ordering::Release)` before write_index bump
- [x] `JournalEntry` contains `etw_timestamp` field
- [x] All failure paths return `None` silently
- [x] `lib.rs` contains `mod hook_journal;`
- [x] Every trampoline calls journal_write before returning
- [x] All unit tests pass
- [x] Clippy clean (-D warnings)
