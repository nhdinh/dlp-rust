---
status: issues_found
depth: standard
files_reviewed: 17
critical: 4
warning: 5
info: 5
total: 14
---

# Phase 58: Code Review Report

**Reviewed:** 2026-06-22T00:00:00Z
**Depth:** standard
**Files Reviewed:** 17
**Status:** issues_found

## Summary

Reviewed Phase 58 changes across the DLP-RUST project: `diagnostic_store.rs` (new in-memory store for hook DLL diagnostics), `admin_api.rs` (GET /admin/diagnostics endpoint with JWT auth and pagination), `audit_events.rs` (content_sha256 column for evidence integrity), `audit_store.rs` (content_sha256 field propagation), `lib.rs`/`main.rs` (diagnostic_store wiring), `db/mod.rs` (migration), `dlp-agent/src/service.rs` (DiagnosticAggregator, HealthAggregator, Hook IPC server wiring), and 10 integration test files. Found 4 critical issues and 5 warnings across correctness, security, and maintainability.

## Critical Issues

### CR-01: Unbounded memory growth in `DiagnosticSnapshotStore` — no global cap

**File:** `dlp-server/src/diagnostic_store.rs:39-44`
**Issue:** The `DiagnosticSnapshotStore` caps per-DLL entries (`max_entries_per_dll = 1000`) but does NOT cap the number of DLL keys. An attacker (or misbehaving agent) can create arbitrarily many `{pid}_{agent_id}` keys by varying `agent_id` or `pid`, causing unbounded memory growth and potential OOM. The `DashMap` key count is never bounded.
**Fix:** Add a global key cap (e.g., LRU eviction) or require key registration/whitelisting:
```rust
// Add to DiagnosticSnapshotStore:
max_keys: usize,
// In ingest(), if snapshots.len() > max_keys, evict oldest key.
```

### CR-02: `since` filter is a no-op — time-based filtering silently disabled

**File:** `dlp-server/src/diagnostic_store.rs:151-161`
**Issue:** The `matches_filter` function accepts a `since: Option<DateTime<Utc>>` parameter but explicitly ignores it with a comment: "For now, we skip time-based filtering since DiagnosticSnapshot only has QPC (not wall-clock)." This means the admin API's `since` query parameter is silently ignored, violating the API contract and potentially returning sensitive snapshots outside the requested time window. The `_` prefix on `since` is a dead giveaway.
**Fix:** Either (a) add a wall-clock timestamp field to `DiagnosticSnapshot` and implement the filter, or (b) remove the `since` parameter from the API and document that time filtering is unsupported. Silently ignoring a filter parameter is a correctness bug.

### CR-03: Hardcoded SYSTEM SID placeholder in Hook IPC approval cache check

**File:** `dlp-agent/src/service.rs:1639`
**Issue:** The Hook IPC server's ABAC evaluation stub uses a hardcoded `"S-1-5-18"` (SYSTEM SID) as the subject SID for approval cache lookups, with a comment admitting this is a placeholder: "SYSTEM SID placeholder — real SID from process token in full impl". This means ALL hook DLL requests are evaluated against the SYSTEM SID regardless of the actual user, breaking the ABAC model's user-based policy enforcement. In a multi-user environment, this causes false positives (denying legitimate users) or false negatives (allowing unauthorized users).
**Fix:** Extract the real user SID from the process token of the hooked process (via `OpenProcessToken` + `GetTokenInformation` with `TokenUser`) and pass it to the approval cache lookup.

### CR-04: `list_bypass_alerts_handler` returns incorrect `total` — post-filter count, not pre-filter

**File:** `dlp-server/src/admin_api.rs:5476-5480`
**Issue:** The `list_bypass_alerts_handler` sets `total = rows.len()` where `rows` is the ALREADY-filtered and paginated result set from `list_by_filters`. The API contract (used by the TUI and other consumers) expects `total` to be the total count BEFORE pagination, so clients can compute page counts. This is inconsistent with the `DiagnosticListResponse` (which correctly returns pre-pagination total) and breaks pagination UI for bypass alerts.
**Fix:** Change `BypassAlertsRepository::list_by_filters` to return `(Vec<BypassAlertRow>, usize)` where the second element is the total pre-filter count, or add a separate `count_by_filters` query.

## Warnings

### WR-01: `ingest` does not validate `new_snapshots` for malicious data

**File:** `dlp-server/src/diagnostic_store.rs:77-87`
**Issue:** The `ingest` method blindly appends `new_snapshots` without validating field lengths, character encoding, or semantic constraints. A malicious agent could send extremely long `user_sid` (e.g., 10MB), `abac_resource` paths with path traversal sequences, or invalid `enforcement_mode` strings. While this is in-memory only, it could cause memory pressure or downstream issues when snapshots are serialized to JSON for the admin API response.
**Fix:** Add validation in `ingest` or at the API boundary: max string lengths, valid SID format, no path traversal in `abac_resource`.

### WR-02: `DiagnosticSnapshot` `abac_subject` field is redundant with `user_sid`

**File:** `dlp-server/src/diagnostic_store.rs:190-205` (test helper), `dlp_common::hook_ipc::DiagnosticSnapshot`
**Issue:** The `DiagnosticSnapshot` struct contains both `abac_subject` and `user_sid` fields that appear to hold the same value (the Windows SID). The test helper sets both to the same string. This redundancy is a data model smell that could lead to inconsistency if one field is updated and the other is not. The `matches_filter` only checks `user_sid`, so `abac_subject` may be dead weight.
**Fix:** Verify if `abac_subject` is semantically distinct (e.g., could be a group SID while `user_sid` is the user SID). If they are always the same, remove one field. If distinct, document the difference and ensure filters check both.

### WR-03: `content_sha256` is not validated as a valid hex string on ingestion

**File:** `dlp-server/src/audit_store.rs:81-186`
**Issue:** The `content_sha256` field from `AuditEvent` is passed directly to the database without validating that it is a valid hex-encoded SHA-256 hash (64 characters, 0-9a-f). A malformed or truncated hash could be stored, undermining the evidence integrity claim. The test `test_store_events_sync_content_sha256` uses `"abc123def456"` (12 chars, not 64), which is accepted without validation.
**Fix:** Add validation in `store_events_sync` or `ingest_events`:
```rust
if let Some(ref hash) = event.content_sha256 {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid content_sha256".to_string()));
    }
}
```

### WR-04: `list_diagnostics_handler` does not apply rate limiting

**File:** `dlp-server/src/admin_api.rs:1276`
**Issue:** The `/admin/diagnostics` route is added to `protected_routes` with the default `default_config()` rate limiter (100/min), but diagnostic queries can be expensive (sorting all snapshots across all DLLs, cloning every snapshot). Unlike `/policies` which has a dedicated `policy_config()` (60/min), diagnostics shares the generic limit. A single admin could exhaust the shared limit and starve other admin endpoints.
**Fix:** Add a dedicated, tighter rate limit config for diagnostics (e.g., 30/min) and apply it via `.route_layer()` on the diagnostics route.

### WR-05: `run_loop_init` uses `unsafe { std::mem::transmute }` for detector static lifetime extension

**File:** `dlp-agent/src/service.rs:1188-1190`
**Issue:** The code uses `unsafe { std::mem::transmute(detector_arc.as_ref()) }` to create a `&'static` reference to the `VolumeDetector` stored in `detector_arc`. While the comment claims this is safe because `RunLoopContext` outlives the service loop, the transmute bypasses Rust's borrow checker. If `detector_arc` is dropped early (e.g., during a panic in shutdown), the static reference becomes dangling. This is a latent use-after-free risk.
**Fix:** Instead of a static reference, pass the `Arc` directly to consumers or use a thread-local `OnceLock` that holds the `Arc` and returns a cloned reference. Avoid `unsafe` transmute for lifetime extension.

## Info

### IN-01: `DiagnosticSnapshotStore::get_snapshots` clones every snapshot on every call

**File:** `dlp-server/src/diagnostic_store.rs:100-112`
**Issue:** `get_snapshots` calls `.flat_map(|entry| entry.value().clone())` which clones the entire Vec of every DLL key on every query. For large stores (many DLLs * 1000 entries), this is expensive. The pagination method then clones again via `all.into_iter()`. Consider returning references or using `Arc<DiagnosticSnapshot>` for shared ownership.

### IN-02: `list_diagnostics_handler` uses `spawn_blocking` for in-memory data

**File:** `dlp-server/src/admin_api.rs:5430-5434`
**Issue:** The handler wraps `get_snapshots_paginated` in `spawn_blocking` even though `DiagnosticSnapshotStore` is entirely in-memory and lock-free (DashMap). There is no blocking I/O here; the `spawn_blocking` adds unnecessary overhead and context switching. The operation could be done directly in the async task.

### IN-03: Integration test harnesses duplicate `test_app()` / `build_test_app()` across 10 files

**File:** Multiple test files (e.g., `admin_audit_integration.rs`, `device_registry_integration.rs`, `managed_origins_integration.rs`, etc.)
**Issue:** The `test_app()` / `build_test_app()` helper and `mint_jwt()` / `seed_admin_user()` functions are copy-pasted verbatim across 10+ integration test files. This is a DRY violation that makes maintenance painful (e.g., adding a new `AppState` field requires editing every test file). The comment in `mode_end_to_end.rs` even admits: "Harness is copied verbatim from `admin_audit_integration.rs`".
**Fix:** Extract a shared `test_harness` module in `dlp-server/tests/common/mod.rs` and import it in all test files.

### IN-04: `audit_store.rs` uses `serde_json::to_value(...)?.as_str().unwrap_or_default()` for enum serialization

**File:** `dlp-server/src/audit_store.rs:157-184`
**Issue:** The `ingest_events` handler serializes enums via `serde_json::to_value(event.event_type)?.as_str().unwrap_or_default().to_string()`. This is fragile: if the enum's serde representation changes to a non-string (e.g., an object), the `as_str()` returns `""` silently, losing data. The `store_events_sync` function uses `serde_json::to_string(&event.event_type)?` which correctly produces quoted strings (e.g., `"ADMIN_ACTION"`). The two paths are inconsistent.
**Fix:** Use `serde_json::to_string` in `ingest_events` as well, or define a dedicated `to_db_string` helper for enums.

### IN-05: `dlp-agent/src/service.rs` `override_handle` channel has no backpressure or timeout on `recv()`

**File:** `dlp-agent/src/service.rs:1541-1594`
**Issue:** The override request processing task uses `while let Some(req) = override_rx.recv().await` with no timeout. If the channel sender is dropped or the task hangs on `send_to_ui` or `submit_approval_request`, the task could block indefinitely. The `try_send` on the channel is good (line 1627), but the consumer side has no graceful degradation for slow operations.
**Fix:** Add a timeout to the async operations inside the loop, or use `tokio::select!` with a timeout branch.

---

_Reviewed: 2026-06-22T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
