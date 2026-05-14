---
phase: 62-syslog-forwarder
plan: 02
type: execute
subsystem: dlp-server
wave: 2
depends_on:
  - 62-01
requires:
  - SYSLOG-01
  - SYSLOG-02
key-files:
  created:
    - dlp-server/src/observability.rs
  modified:
    - dlp-server/src/admin_api.rs
    - dlp-server/src/lib.rs
    - dlp-server/src/main.rs
    - dlp-server/src/audit_store.rs
    - dlp-server/src/db/repositories/syslog_queue.rs
    - dlp-server/tests/admin_audit_integration.rs
    - dlp-server/tests/device_registry_integration.rs
    - dlp-server/tests/ldap_config_api.rs
    - dlp-server/tests/managed_origins_integration.rs
    - dlp-server/tests/mode_end_to_end.rs
    - dlp-server/tests/secrets_encryption_integration.rs
    - dlp-server/tests/secrets_log_scan_integration.rs
tech-stack:
  added:
    - once_cell = "1"
  patterns:
    - peek-confirm-delete queue semantics for at-least-once delivery
    - durable-first queuing (enqueue before external forward)
    - exponential backoff with deterministic jitter for retry scheduling
    - tokio::select! with broadcast channel for graceful shutdown
    - in-memory rate limiter with Lazy<Arc<Mutex<HashMap>>>
decisions:
  - "Rate limiter uses in-memory HashMap (sufficient for single-instance dlp-server); distributed cache deferred to multi-node deployment"
  - "Deterministic jitter derived from nanosecond timestamp (avoids rand dependency)"
  - "Corrupt queue events marked with far-future retry (2099-01-01) to prevent infinite loops"
  - "No secret masking on syslog config GET (syslog config has no secrets per D-10/D-11)"
metrics:
  duration: "~45 minutes"
  completed_date: "2026-05-14"
---

# Phase 62 Plan 02: Syslog Forwarder Integration Summary

End-to-end syslog forwarding from audit ingestion to TLS transmission, with durable-first queuing, admin config API, background drain loop with peek-confirm-delete semantics, graceful shutdown, and observability metrics.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add admin API handlers for syslog config with validation and rate limiting | d217ed7 | dlp-server/src/admin_api.rs |
| 2 | Wire SyslogConnector into AppState, main.rs, and audit_store.rs (durable-first) | 20ce1ae | dlp-server/src/lib.rs, dlp-server/src/main.rs, dlp-server/src/audit_store.rs |
| 3 | Spawn background drain loop with graceful shutdown, peek-confirm-delete, and observability | f9fdc2d | dlp-server/src/main.rs, dlp-server/src/observability.rs |
| Fix | Add missing syslog field to all integration test AppState constructions | e595bdc | 7 integration test files |

## Key Changes

### Admin API (dlp-server/src/admin_api.rs)
- `SyslogConfigPayload` struct with all syslog config fields (serde Serialize/Deserialize)
- `GET /admin/syslog-config` - returns current config, no masking needed (no secrets)
- `PUT /admin/syslog-config` - validates port (1-65535), facility_code (16-23), severity (0-7), queue_policy enum, tls_min_version enum before persisting
- `POST /admin/syslog-config/test` - sends synthetic AuditEvent through connector, rate limited to 1 per 10s per session via `Lazy<Arc<Mutex<HashMap<String, Instant>>>>`
- 9 unit tests covering GET defaults, PUT round-trip, validation rejections, rate limiting, auth requirements

### AppState Integration (dlp-server/src/lib.rs)
- Added `pub mod observability;`
- Added `pub syslog: syslog_connector::SyslogConnector` to AppState
- Updated Debug impl to redact syslog as `"SyslogConnector(...)"`

### Main.rs Initialization & Drain Loop (dlp-server/src/main.rs)
- Initialize SyslogConnector: `SyslogConnector::new(Arc::clone(&pool), Arc::clone(&crypto))`
- Background drain loop spawned before server starts:
  - `tokio::select!` with interval tick and shutdown receiver for graceful shutdown
  - `peek_oldest` reads batches without removing (peek-confirm-delete)
  - `delete` called only after confirmed successful `SyslogConnector::forward`
  - `mark_failed` with `next_attempt_at` scheduling on forward failure
  - `count_ready` respects time-based retry scheduling
  - Exponential backoff: min(2^failures, 60s) + deterministic jitter
  - Backoff resets on success or empty queue
- `compute_next_attempt(consecutive_failures: u32) -> String` helper for retry scheduling
- Graceful shutdown: broadcast channel `(shutdown_tx, mut shutdown_rx)`, send before exit, `drain_handle.await.ok()`

### Durable-First Queuing (dlp-server/src/audit_store.rs)
- After DB persistence, events are enqueued to `syslog_queue` via `spawn_blocking` BEFORE HTTP response returns
- Uses `Arc<Vec<AuditEvent>>` to avoid double-cloning
- Reads config hot from DB to get `queue_max_size` for tail-drop policy
- Fire-and-forget spawn (best-effort, logs warnings on failure)

### Observability (dlp-server/src/observability.rs)
- Atomic counters: QUEUE_DEPTH, SEND_LATENCY_MS, RETRY_COUNT, DROP_COUNT, TLS_ERROR_COUNT
- Functions: `record_syslog_queue_depth`, `record_syslog_send_latency`, `record_syslog_retry`, `record_syslog_drop`, `record_syslog_tls_error`, `get_syslog_metrics`
- `SyslogMetrics` struct with `serde::Serialize` for external consumption
- 6 unit tests for each metric function and serde round-trip

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Missing `syslog` field in 7 integration test files**
- **Found during:** Post-Task 3 verification (cargo test)
- **Issue:** Integration tests construct `AppState` directly and were missing the new `syslog` field
- **Fix:** Added `SyslogConnector::new(...)` initialization to all 7 integration test files
- **Files modified:** `tests/admin_audit_integration.rs`, `tests/device_registry_integration.rs`, `tests/ldap_config_api.rs`, `tests/managed_origins_integration.rs`, `tests/mode_end_to_end.rs`, `tests/secrets_encryption_integration.rs`, `tests/secrets_log_scan_integration.rs`
- **Commit:** e595bdc

**2. [Rule 1 - Bug] `db::UnitOfWork` unresolved in audit_store.rs**
- **Found during:** Task 2 compilation
- **Issue:** `db::UnitOfWork::new` failed because `db` module path was incorrect in the spawn_blocking closure
- **Fix:** Changed to `UnitOfWork::new` (already imported at module level)
- **Files modified:** `dlp-server/src/audit_store.rs`
- **Commit:** 20ce1ae

**3. [Rule 1 - Bug] `syslog` moved value in main.rs**
- **Found during:** Task 2 compilation
- **Issue:** `syslog` was moved into AppState construction, then used again for drain loop spawn
- **Fix:** Cloned before AppState construction: `syslog: syslog.clone()`
- **Files modified:** `dlp-server/src/main.rs`
- **Commit:** 20ce1ae

## Verification Results

- `cargo test -p dlp-server`: 460 passed, 5 ignored (12 suites)
- `cargo clippy -p dlp-server -- -D warnings`: No issues found
- `cargo fmt -p dlp-server -- --check`: Clean
- `cargo build -p dlp-server`: Success

## Threat Surface Scan

No new threat flags introduced beyond those already documented in the plan's threat model. All mitigations are in place:
- T-62-08 (config validation): mitigated via PUT handler validation
- T-62-10 (DoS via test handler): mitigated via rate limiting
- T-62-17 (drain loop CPU exhaustion): mitigated via exponential backoff cap and MissedTickBehavior::Skip
- T-62-18 (queue overflow): mitigated via tail-drop logging and observability metrics
- T-62-19 (unbounded task spawning): mitigated via spawn_blocking (bounded by Tokio blocking pool)

## Self-Check: PASSED

- [x] All created files exist: `dlp-server/src/observability.rs`
- [x] All commits exist: d217ed7, 20ce1ae, f9fdc2d, e595bdc
- [x] All acceptance criteria from plan verified
- [x] No stubs or placeholder data found
