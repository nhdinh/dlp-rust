---
phase: 62-syslog-forwarder
plan: 02
wave: 2
status: complete
completed_at: "2026-05-21T08:55:00Z"
---

# 62-02 Summary: Application Wiring

## Objective
Wire the SyslogConnector into the application: admin API handlers for config CRUD and test (with validation and rate limiting), AppState integration, main.rs initialization with graceful shutdown, audit_store.rs durable-first queuing, a background drain loop with peek-confirm-delete semantics, and observability metrics.

## Tasks Completed

### Task 1: Admin API handlers for syslog config
- Already implemented in prior session: GET/PUT/test handlers with validation
- Tests passing: 8 admin API syslog tests

### Task 2: AppState integration
- `AppState` contains `pub syslog: syslog_connector::SyslogConnector`
- Initialized in main.rs alongside siem and alert

### Task 3: Background drain loop in main.rs
- Updated to use `peek_and_claim` with 300-second lease (atomic claim prevents double-send)
- On forward failure: `mark_failed` + `release_lease` so events can be reclaimed sooner
- Graceful shutdown via `tokio::select!` with broadcast channel
- Exponential backoff with jitter on consecutive failures

### Task 4: audit_store.rs durable-first queuing
- Already implemented: enqueues to `syslog_queue` before returning HTTP response
- Uses `spawn_blocking` for SQLite operations

### Task 5: Observability metrics
- `record_syslog_queue_depth`, `record_syslog_send_latency`, `record_syslog_retry`, `record_syslog_drop`, `record_syslog_tls_error`

## Files Modified
- `dlp-server/src/main.rs` — drain loop updated to `peek_and_claim` + `release_lease`
- `dlp-server/src/lib.rs` — AppState with syslog field (pre-existing)
- `dlp-server/src/admin_api.rs` — admin handlers (pre-existing)
- `dlp-server/src/audit_store.rs` — durable-first enqueue (pre-existing)
- `dlp-server/src/observability.rs` — syslog metrics (pre-existing)

## Deviations
- None

## Test Results
- `cargo test -p dlp-server --lib` — 502 passed, 3 ignored
- `cargo clippy -p dlp-server -- -D warnings` — clean

## Verification
- [x] Admin API GET/PUT/test handlers work with validation
- [x] Drain loop uses `peek_and_claim` with atomic lease
- [x] Forward failure releases lease + marks failed with backoff
- [x] Graceful shutdown works via broadcast channel
- [x] Observability metrics are recorded
