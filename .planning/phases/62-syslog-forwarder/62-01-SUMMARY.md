---
phase: 62-syslog-forwarder
plan: 01
wave: 1
status: complete
completed_at: "2026-05-21T08:45:00Z"
---

# 62-01 Summary: Server-Side Core

## Objective
Build the server-side core of the RFC 5424 syslog forwarder: database schema, encrypted config repository, encrypted queue repository (with pre-insert tail-drop and peek-confirm-delete semantics), and the TLS-capable SyslogConnector service.

## Tasks Completed

### Task 1: Add syslog_config and syslog_queue tables to init_tables()
- Added `syslog_config` single-row table with CHECK (id = 1), seeded with defaults
  - facility_code 20 (LOCAL4), protocol 'tls', batching_enabled 1
  - severity_alert=3, severity_block=4, severity_audit=6 per D-03
  - queue_policy='fifo_tail_drop', queue_max_size=100000 per D-08/D-09
  - tls_min_version='1.2' per D-11
- Added `syslog_queue` multi-row table with KEK-encrypted envelope columns
  - `event_json_encrypted` + `event_json_nonce` for AES-GCM envelope (R-62-01)
  - `retry_count`, `last_error`, `next_attempt_at` for time-based retry (R-62-07)
  - `leased_until` column for peek-and-claim atomic lease semantics
  - Indexes: `idx_syslog_queue_created_at`, `idx_syslog_queue_next_attempt_at`, `idx_syslog_queue_leased_until`

### Task 2: Create SyslogConfigRepository and SyslogQueueRepository
- `SyslogConfigRepository`: `get()` and `update()` with validation helpers
  - `validate_facility_code()` enforces 16-23 (R-62-06)
  - `validate_severity()` enforces 0-7 (R-62-06)
- `SyslogQueueRepository`: `enqueue()`, `peek_oldest()`, `peek_and_claim()`, `delete()`, `mark_failed()`, `count()`, `count_ready()`, `release_lease()`
  - `enqueue`: pre-insert tail-drop capacity check (R-62-03)
  - `peek_and_claim`: atomic SELECT + UPDATE of `leased_until` to prevent double-send
  - `release_lease`: clears lease so events can be reclaimed sooner

### Task 3: Create SyslogConnector with RFC 5424 formatting and TLS transport
- `SyslogConnector::forward()` is transport-only: on failure returns Err, caller owns queue state
- RFC 5424 formatting: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG\n`
- JSON payload in MSG field with newline escaping (D-01/D-02)
- TLS 1.2+ with system CA store (D-10/D-11)
- ServerName resolution handles DNS hostnames and IP addresses (R-62-04)
- Severity mapping: Alert->ERROR, Block->WARNING, others->INFO (D-03)
- Facility code validated at config time (R-62-06)

## Files Modified
- `dlp-server/src/db/mod.rs` — schema additions
- `dlp-server/src/db/repositories/syslog_config.rs` — new file
- `dlp-server/src/db/repositories/syslog_queue.rs` — new file
- `dlp-server/src/db/repositories/mod.rs` — exports
- `dlp-server/src/syslog_connector.rs` — new file
- `dlp-server/src/policy_store.rs` — removed unused import (clippy)

## Deviations
- None

## Test Results
- `cargo test -p dlp-server --lib` — 502 passed, 3 ignored
- `cargo clippy -p dlp-server -- -D warnings` — clean

## Verification
- [x] `syslog_config` and `syslog_queue` tables created by `new_pool(":memory:")`
- [x] `syslog_config` seeded with exactly one row (id = 1)
- [x] `idx_syslog_queue_created_at`, `idx_syslog_queue_next_attempt_at`, `idx_syslog_queue_leased_until` indexes exist
- [x] `SyslogQueueRepository::peek_and_claim` atomically sets lease
- [x] `SyslogQueueRepository::release_lease` clears lease for re-claim
- [x] `SyslogConnector::forward` is transport-only (no enqueue on failure)
