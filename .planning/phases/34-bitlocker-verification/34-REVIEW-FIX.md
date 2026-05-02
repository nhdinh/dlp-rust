---
phase: 34-bitlocker-verification
fixed_at: 2026-05-03T00:00:00Z
review_path: .planning/phases/34-bitlocker-verification/34-REVIEW.md
iteration: 1
findings_in_scope: 8
fixed: 8
skipped: 0
status: all_fixed
---

# Phase 34: Code Review Fix Report

**Fixed at:** 2026-05-03T00:00:00Z
**Source review:** .planning/phases/34-bitlocker-verification/34-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 8 (3 Critical, 5 Warning; Info excluded by fix_scope)
- Fixed: 8
- Skipped: 0

## Fixed Issues

### CR-01: JoinSet Task-Panic Path Silently Discards Disk Status

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commits:** `cc208ef`, `773734e`
**Applied fix:** Replaced `JoinSet<(id, letter, result)>` with `Vec<(String, Option<char>, JoinHandle<Result<...>>)>`. The instance_id is stored in the outer Vec alongside each handle, so it is always recoverable in the `Err(join_err)` panic arm. The panic arm now inserts `EncryptionStatus::Unknown` into `new_statuses` and pushes to `failed`, preventing silent status drops (D-14/D-16). Note: an intermediate commit (cc208ef) used an Arc approach that compiled but had a scoping bug; 773734e is the correct revision.

### CR-02: Blocking Registry I/O Executed on Async Executor Thread

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commit:** `5687501` (refined in `773734e`)
**Applied fix:** Wrapped `try_registry_fallback` call in `tokio::task::spawn_blocking` with a 2-second `tokio::time::timeout`. This matches the protection already applied to the WMI path in `check_one_disk` (Pitfall A). The fallback returns `EncryptionStatus::Unknown` on join error or timeout.

### CR-03: `classify_wmi_connection_error` Applied to `conn.query()` Errors

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commit:** `c7bebb9`
**Applied fix:** Changed `conn.query().map_err(classify_wmi_connection_error)?` to `conn.query().map_err(|e| EncryptionError::WmiQueryFailed(e.to_string()))?`. `WmiQueryFailed.warrants_registry_fallback()` returns `false`, so query errors no longer trigger the registry fallback via the namespace-string heuristic.

### WR-01: `encryption_checked_at` Updated Even for Disks Absent from `new_statuses`

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commit:** `cc208ef`
**Applied fix:** Wrapped `d.encryption_checked_at = Some(now)` in `if new_statuses.contains_key(&d.instance_id)` guard. Only disks that were actually checked this cycle (present in `new_statuses`) receive an updated timestamp.

### WR-02: `all_failed` Vacuous-Truth Bug on Empty `new_statuses`

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commit:** `cc208ef`
**Applied fix:** Added `&& !new_statuses.is_empty()` guard to the `all_failed` predicate. If all tasks panicked and `new_statuses` is empty, `.all()` on an empty iterator would return vacuously-true; the guard prevents a misleading total-failure alert with no per-disk diagnostics.

### WR-03: `mark_first_check_complete` Writes Two Separate RwLocks — TOCTOU Window

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commit:** `8511765`
**Applied fix:** Added an inline comment block documenting: (a) the TOCTOU window between the two sequential lock acquisitions, (b) why the window is safe (readers see `is_ready() == false` conservatively), and (c) the chosen write order (clear `is_first_check` before setting `check_complete`). No structural refactor was applied — the single-writer context makes the comment sufficient per the reviewer's guidance.

### WR-04: Unnecessary `unsafe impl Send/Sync` for `EncryptionChecker`

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commit:** `5dabc86`
**Applied fix:** Removed both `unsafe impl Send for EncryptionChecker {}` and `unsafe impl Sync for EncryptionChecker {}` lines along with the preceding SAFETY comment. `parking_lot::RwLock<T>` already derives `Send + Sync` when `T: Send + Sync`; the manual unsafe impls bypassed the compiler's unsoundness check.

### WR-05: `derive_encryption_status` Missing Case `(ProtectionStatus=1, ConversionStatus=0)`

**Files modified:** `dlp-agent/src/detection/encryption.rs`
**Commit:** `09fec07`
**Applied fix:** Added explicit `(Some(1), Some(0)) => EncryptionStatus::Unknown` match arm with a comment explaining the transient WMI state (BitLocker key-protector re-enablement on a partially decrypted volume). Also added a corresponding test assertion to the `test_derive_encryption_status_truth_table` test.

## Skipped Issues

None — all in-scope findings were fixed.

## Build and Test Verification

- `cargo build -p dlp-agent`: **PASSED** (0 warnings in modified file)
- `cargo test -p dlp-agent --lib detection::encryption`: **PASSED** (12/12 tests)
- Pre-existing failure in `config::tests::test_effective_config_path_env_override` is unrelated to these fixes

---

_Fixed: 2026-05-03T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
