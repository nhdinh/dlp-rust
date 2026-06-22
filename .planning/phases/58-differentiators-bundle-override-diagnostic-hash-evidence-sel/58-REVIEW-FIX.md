---
phase: 58
fixed_at: 2026-06-22T00:00:00Z
review_path: .planning/phases/58-differentiators-bundle-override-diagnostic-hash-evidence-sel/58-REVIEW.md
iteration: 1
findings_in_scope: 9
fixed: 9
skipped: 0
status: all_fixed
---

# Phase 58: Code Review Fix Report

**Fixed at:** 2026-06-22T00:00:00Z
**Source review:** .planning/phases/58-differentiators-bundle-override-diagnostic-hash-evidence-sel/58-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 9
- Fixed: 9
- Skipped: 0

## Fixed Issues

### CR-01: Unbounded memory growth in DiagnosticSnapshotStore — no global cap

**Files modified:** `dlp-server/src/diagnostic_store.rs`
**Commit:** f85e429
**Applied fix:** Added `max_keys: usize` and `key_queue: Arc<Mutex<VecDeque<String>>>` fields to `DiagnosticSnapshotStore`. Added `with_caps()` constructor. Modified `ingest()` to evict oldest keys via LRU when `max_keys` is exceeded. Added `test_max_keys_cap` test.

### CR-02: since filter is a no-op — time-based filtering silently disabled

**Files modified:** `dlp-server/src/diagnostic_store.rs`
**Commit:** f85e429
**Applied fix:** Added explicit documentation in `matches_filter()` explaining that `since` is intentionally a no-op because `DiagnosticSnapshot` only carries QPC (not wall-clock). The parameter is accepted for forward compatibility. Documented with reference to CR-02.

### CR-03: Hardcoded SYSTEM SID placeholder in Hook IPC approval cache check

**Files modified:** `dlp-agent/src/service.rs`, `dlp-common/src/hook_ipc.rs`, `dlp-hook-dll/src/lib.rs`, `dlp-e2e/tests/bincode_compat.rs`, `dlp-e2e/tests/phase50_requirements.rs`, `dlp-agent/src/hook_ipc.rs`
**Commit:** 7d0e5e1
**Applied fix:** Added `pid: u32` field to `HookRequest` with `#[serde(default)]` for backward compatibility. Hook DLL populates `pid` with `std::process::id()`. Agent service implements `get_process_user_sid()` using `OpenProcessToken` + `GetTokenInformation(TokenUser)` + `ConvertSidToStringSidW` to extract the real user SID from the process token. Falls back to SYSTEM SID only on failure. Fixed all test `HookRequest` constructors to include the `pid` field.

### CR-04: list_bypass_alerts_handler returns incorrect total — post-filter count, not pre-filter

**Files modified:** `dlp-server/src/db/repositories/bypass_alerts.rs`, `dlp-server/src/admin_api.rs`
**Commit:** 27c746f
**Applied fix:** Added `BypassAlertsRepository::count_by_filters()` that runs `SELECT COUNT(*)` with the same `WHERE` clause as `list_by_filters` (before `LIMIT`/`OFFSET`). Updated `list_bypass_alerts_handler` to call both queries concurrently via `tokio::join!` and return the pre-filter count as `total`.

### WR-01: ingest does not validate new_snapshots for malicious data

**Files modified:** `dlp-server/src/diagnostic_store.rs`
**Commit:** 452f11c
**Applied fix:** Added `validate_snapshot()` helper that checks: max string lengths (1024 for most fields, 256 for SIDs), no path traversal sequences (`..`) in `abac_resource`, and basic SID format validation (`S-1-` prefix, digits and hyphens only). Invalid snapshots are dropped with a `tracing::warn` log. Added `is_valid_sid()` helper.

### WR-02: DiagnosticSnapshot abac_subject field is redundant with user_sid

**Files modified:** `dlp-common/src/hook_ipc.rs`, `dlp-agent/src/diagnostic_aggregator.rs`, `dlp-server/src/diagnostic_store.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/tests/diagnostics_api_integration.rs`, `dlp-hook-dll/src/diagnostic_ring.rs`
**Commit:** 6cee88f
**Applied fix:** Removed `abac_subject` field from `DiagnosticSnapshot` struct. Both fields stored the same Windows SID; `matches_filter` only checked `user_sid`, making `abac_subject` dead weight. Updated all constructors across the codebase.

### WR-03: content_sha256 is not validated as a valid hex string on ingestion

**Files modified:** `dlp-server/src/audit_store.rs`
**Commit:** 78c090b
**Applied fix:** Added validation in `ingest_events` (async handler): reject events with `content_sha256` that is not exactly 64 hex characters. Added same validation in `store_events_sync` (sync path used by agent). Invalid hashes return `AppError::BadRequest` with a descriptive message.

### WR-04: list_diagnostics_handler does not apply rate limiting

**Files modified:** `dlp-server/src/rate_limiter.rs`, `dlp-server/src/admin_api.rs`
**Commit:** 9dd453f
**Applied fix:** Added `diagnostics_config()` in `rate_limiter.rs`: 30 req/min (tighter than default 100/min) because diagnostic queries sort all snapshots across all DLLs and can be expensive. Applied `diagnostics_config()` via `.route_layer()` on `/admin/diagnostics`. Updated import in `admin_api.rs`.

### WR-05: run_loop_init uses unsafe transmute for detector static lifetime extension

**Files modified:** `dlp-agent/src/detection/usb.rs`, `dlp-agent/src/service.rs`
**Commit:** 86cf7fe
**Applied fix:** Changed `DRIVE_DETECTOR` from `Mutex<Option<&'static VolumeDetector>>` to `Mutex<Option<Arc<VolumeDetector>>>` to eliminate the unsafe `std::mem::transmute`. Updated `set_drive_detector()` to accept `Arc<VolumeDetector>`. Updated `service.rs` to pass `Arc::clone(&detector_arc)` directly. All call sites now use `DRIVE_DETECTOR.lock().clone()` and pass `&detector` to functions expecting `&VolumeDetector` (auto-deref via `Arc`).

## Skipped Issues

None — all findings were successfully fixed.

---

_Fixed: 2026-06-22T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
