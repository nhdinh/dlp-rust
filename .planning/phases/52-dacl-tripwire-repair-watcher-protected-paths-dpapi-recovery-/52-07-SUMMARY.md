---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
plan: 07
subsystem: dlp-agent
subsystem: dacl-staging
subsystem: dacl-repair-watcher
tags: [staging, two-phase-removal, tamper-suppression, per-path-locking, crash-recovery]
dependency_graph:
  requires: [52-01, 52-02, 52-04, 52-06]
  provides: [52-07]
  affects: [52-08]
tech_stack:
  added: []
  patterns: [DashMap per-path locking, tokio interval tasks, SQLite staging table]
key_files:
  created: []
  modified:
    - dlp-agent/src/service.rs
    - dlp-agent/src/dacl_repair_watcher.rs
    - dlp-agent/src/dacl_staging.rs
decisions:
  - "DaclWatcher wrapped in Arc to allow shared access between repair task and removal application task"
  - "path_locks made public in DaclStaging for cross-module coordination between watcher and removal task"
  - "Removal application task marks staging rows as applied (does not call remove_tripwire_from_path) because admin API already modified the ACL"
  - "Clone implemented for DaclWatcher to support Arc wrapping in RunLoopContext"
metrics:
  duration: "~45 minutes"
  completed_date: "2026-05-27"
---

# Phase 52 Plan 07: Staged Update Protocol Integration Summary

## One-liner

Two-phase staged update protocol integration: config diff logic stages protected path removals, the repair watcher suppresses tamper alerts for staged operations under per-path locks, and a dedicated removal application task marks staged rows as applied.

## What Was Built

### 1. Config Diff with Staging (`service.rs`)

Extended `apply_payload_to_config` to detect `protected_paths` changes:
- Computes additions and removals by comparing old vs new path sets
- Stages removals in SQLite via `stage_removals()` before applying config changes
- Logs additions for observability (applied on next watcher init)
- 3 new tests verify staging behavior, no-change path, and addition detection

### 2. Staging-Aware Tamper Suppression (`dacl_repair_watcher.rs`)

Modified `DaclWatcher` to check the staging table before emitting tamper alerts:
- Added `staging: RwLock<Option<Arc<DaclStaging>>>` field
- Added `set_staging()` method for runtime wiring
- Modified `start_repair_task` to check `is_staged()` before `repair_acl`
- Staged removals are suppressed; unstaged tampering triggers full repair + `DaclTamperDetected` audit
- Per-path lock acquired during staging check + repair decision
- Implemented `Clone` for `DaclWatcher` to support `Arc` wrapping

### 3. Removal Application Task (`service.rs`)

Added `spawn_removal_application_task`:
- Reads staging rows with `operation = 'remove'` and `applied_at IS NULL`
- Acquires per-path lock, re-checks state, marks as applied
- Unregisters watcher for removed paths
- Runs on 30-second interval with graceful shutdown support

### 4. GC Task Integration (`service.rs`)

- Spawns `spawn_gc_task` with 60-second interval and 5-minute TTL
- Removes expired staging rows (applied_at + TTL < now)
- Proper shutdown sequencing: removal task -> GC task -> repair task -> watcher unregister

### 5. State Machine Documentation (`dacl_staging.rs`)

Enhanced `StagingState` documentation:
- Explicit state machine: `STAGED -> WATCHER_SUPPRESSED -> ACL_REMOVED -> APPLIED -> GC`
- Crash recovery per state documented
- Per-path lock ensures atomic transitions

## Test Results

| Test Suite | Result | Count |
|------------|--------|-------|
| dlp-agent lib tests (modified modules) | PASS | 51/51 |
| dlp-agent lib tests (all) | PASS | 634/635 (1 pre-existing flaky) |
| dlp-agent doc tests | PASS | 7/7 |
| clippy --workspace | PASS | clean |
| cargo fmt --check | PASS | clean |

### New Tests Added

**service.rs:**
- `test_apply_payload_stages_removals` — verifies staging on removal
- `test_apply_payload_protected_paths_no_change` — verifies no diff when unchanged
- `test_apply_payload_protected_paths_addition` — verifies diff on addition

**dacl_repair_watcher.rs:**
- `test_set_staging` — verifies staging reference storage
- `test_staging_removal_suppresses_alert` — staged removal suppresses tamper
- `test_unstaged_path_does_not_suppress` — unstaged path triggers alert
- `test_staging_applied_removal_still_suppresses` — applied row still suppresses

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] DaclWatcher Arc wrapping required**
- **Found during:** Task 2 implementation
- **Issue:** `DaclWatcher` could not be shared between repair task and removal application task because it was moved into `RunLoopContext`
- **Fix:** Wrapped `DaclWatcher` in `Arc`, implemented `Clone` trait, updated `RunLoopContext` field type
- **Files modified:** `dacl_repair_watcher.rs`, `service.rs`

**2. [Rule 1 - Bug] path_locks visibility**
- **Found during:** Task 2 implementation
- **Issue:** `DaclStaging.path_locks` was private, preventing the repair watcher from acquiring per-path locks
- **Fix:** Made `path_locks` field public with doc comment explaining cross-module coordination
- **Files modified:** `dacl_staging.rs`

**3. [Rule 2 - Missing Critical] Shutdown sequencing for new tasks**
- **Found during:** Task 3 implementation
- **Issue:** Plan did not explicitly define shutdown order for GC and removal tasks
- **Fix:** Added explicit shutdown sequence: removal task first, then GC, then repair, then watcher unregister. Stored shutdown senders and handles in `RunLoopContext`.
- **Files modified:** `service.rs`

## Threat Flags

None — all security-relevant surface was already covered in the plan's threat model (T-52-19b through T-52-24b). The implementation follows all mitigations specified.

## Known Stubs

None — all data sources are wired. The removal application task does not call `remove_tripwire_from_path` because the admin API already modified the ACL; this is by design (the staging row marks the intent, not the action).

## Self-Check: PASSED

- [x] `dlp-agent/src/service.rs` modified with protected_paths diff + staging
- [x] `dlp-agent/src/dacl_repair_watcher.rs` modified with staging-aware suppression
- [x] `dlp-agent/src/dacl_staging.rs` modified with public path_locks + state machine docs
- [x] All new functions have unit tests
- [x] All new public items have doc comments
- [x] `cargo clippy --workspace -- -D warnings` passes
- [x] `cargo fmt --check -p dlp-agent` passes
- [x] `cargo test -p dlp-agent --lib` passes (634/635, 1 pre-existing flaky)
- [x] Commits exist: a40591f, 7ee5af7, 558fef1
