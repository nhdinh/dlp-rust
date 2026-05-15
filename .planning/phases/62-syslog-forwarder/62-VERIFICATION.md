---
phase: 62-syslog-forwarder
verified: 2026-05-14T12:30:00Z
status: gaps_found
score: 17/19 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: null
  previous_score: null
  gaps_closed: []
  gaps_remaining:
    - "Agent audit_emitter does not enqueue to offline_audit_queue on server unreachable"
    - "Agent does not emit synthetic queue_overflow audit event on AtCapacity"
  regressions: []
gaps:
  - truth: "Agent audit_emitter enqueues events to offline_audit_queue when server is unreachable"
    status: failed
    reason: "offline_audit_queue module exists with full implementation but is NOT wired into audit_emitter.rs or any runtime code path. No code calls offline_audit_queue::enqueue, init_table, drain, or try_acquire_drain_lock outside the module's own unit tests."
    artifacts:
      - path: "dlp-agent/src/offline_audit_queue.rs"
        issue: "Module exists and is exported but never called from production code"
      - path: "dlp-agent/src/audit_emitter.rs"
        issue: "No integration with offline_audit_queue; events only go to JSONL file and AUDIT_BUFFER (server relay)"
    missing:
      - "Call offline_audit_queue::init_table during agent startup"
      - "Call offline_audit_queue::enqueue when AUDIT_BUFFER relay fails or server is unreachable"
      - "Call offline_audit_queue::drain on heartbeat success with try_acquire_drain_lock guard"
      - "Pass SQLite connection to offline_audit_queue functions"
  - truth: "Queue overflow emits synthetic queue_overflow audit event once connectivity returns"
    status: failed
    reason: "R-62-16 requires synthetic queue_overflow audit event when AtCapacity error occurs. The AtCapacity error is returned by enqueue() but no caller handles it to emit a synthetic event."
    artifacts:
      - path: "dlp-agent/src/offline_audit_queue.rs"
        issue: "AtCapacity error returned but never consumed by caller to emit synthetic event"
    missing:
      - "When enqueue returns AtCapacity, emit synthetic AuditEvent with event_type indicating queue_overflow"
deferred: []
human_verification:
  - test: "Admin TUI SyslogConfig screen navigation and picker cycling"
    expected: "Up/Down cycles through 16 rows, Enter on picker cycles values, Enter on text field enters edit mode, Esc returns to SystemMenu, Save calls PUT API, Test calls POST API"
    why_human: "TUI behavior requires interactive terminal verification; automated tests only verify rendering helpers and state transitions, not actual key handling flow"
  - test: "RFC 5424 message format against real syslog collector"
    expected: "Messages are accepted by a real syslog collector (e.g., rsyslog, Splunk HEC) with correct PRI, TIMESTAMP, and JSON payload parsing"
    why_human: "No real syslog collector available in test environment; TLS connection tests use mock/no-op patterns"
  - test: "Agent offline queue DPAPI encryption on Windows"
    expected: "Events encrypted with CryptProtectData (LocalMachine) can be decrypted with CryptUnprotectData after agent restart on same machine"
    why_human: "DPAPI is Windows-only; tests on non-Windows use plaintext stubs. Windows-specific DPAPI round-trip tests exist but require Windows host to execute"
---

# Phase 62: Syslog Forwarder Verification Report

**Phase Goal:** Build RFC 5424 Syslog Forwarder with encrypted offline queue
**Verified:** 2026-05-14T12:30:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #   | Truth | Status | Evidence |
| --- | ----- | ------ | -------- |
| 1 | Syslog forwarding can be enabled/disabled via admin configuration | VERIFIED | `syslog_config` table with `enabled` field; admin API GET/PUT handlers; defaults to disabled (0) |
| 2 | Failed syslog forwards are queued securely for later retry | VERIFIED | `audit_store.rs` enqueues to `syslog_queue` via `SyslogQueueRepository::enqueue` with KEK encryption; background drain loop retries |
| 3 | Syslog configuration persists across server restarts | VERIFIED | `syslog_config` single-row table with CHECK(id=1); seeded on init; SQLite persistence |
| 4 | Queued events drained in order, removed only after successful delivery | VERIFIED | `peek_oldest` returns FIFO without deleting; `delete` called only after `forward()` succeeds; 13 queue tests pass |
| 5 | SyslogConnector formats RFC 5424 with correct PRI, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, MSG | VERIFIED | `format_rfc5424` produces `<PRI>1 TIMESTAMP HOSTNAME DLP-AUDIT PROCID MSGID - JSON\n`; 15 connector tests pass |
| 6 | SyslogConnector connects over TLS 1.2+ using system CA store | VERIFIED | `build_tls_config` loads `rustls_native_certs` + `webpki_roots` fallback; `tokio-rustls` 0.26 dependency; TLS 1.3 config path exists |
| 7 | Configurable severity mapping and facility code | VERIFIED | `map_severity` uses config fields; `validate_facility_code(16-23)` and `validate_severity(0-7)` enforced; defaults per D-03/D-04 |
| 8 | Batched newline-delimited JSON by default | VERIFIED | `batching_enabled` default=1; `forward()` iterates events and writes each as separate RFC 5424 message with LF terminator |
| 9 | JSON-in-MSG only (D-01/D-02) | VERIFIED | `serde_json::to_string(event)` produces flat JSON with all AuditEvent fields; newlines escaped |
| 10 | Server queue uses KEK encryption with per-column AAD (R-62-01) | VERIFIED | `aad_for("syslog_queue", "event_json")` used in `enqueue` and `peek_oldest`; `Envelope` with nonce + ciphertext |
| 11 | Queue uses peek-confirm-delete (R-62-02) | VERIFIED | `peek_oldest` does not delete; `delete` called after confirmed forward; `mark_failed` on error |
| 12 | Pre-insert tail-drop (R-62-03) | VERIFIED | `enqueue` checks `count >= max_size` before encrypting/inserting; returns `AppError::BadRequest` |
| 13 | TLS ServerName handles DNS and IP addresses (R-62-04) | VERIFIED | `resolve_server_name` uses `IpAddress` variant for IPs, `try_from` for DNS; tests for both |
| 14 | Admin API has validation, rate limiting, auth (R-62-09, R-62-10) | VERIFIED | PUT validates port/facility/severity/policy/tls; test handler has `TEST_RATE_LIMITER` (1 per 10s); routes under `require_auth` middleware |
| 15 | Drain loop has graceful shutdown, backoff, observability | VERIFIED | `tokio::select!` with `shutdown_rx`; `MissedTickBehavior::Skip`; exponential backoff capped at 60s; `record_syslog_*` metrics |
| 16 | DPAPI functions in dlp-common with LocalMachine scope (R-62-14) | VERIFIED | `dlp-common/src/crypto/dpapi.rs` has `dpapi_protect_machine`/`dpapi_unprotect_machine` with `CRYPTPROTECT_LOCAL_MACHINE`; non-Windows stubs |
| 17 | Agent queue uses INTEGER created_at, single drain worker (R-62-13, R-62-15) | VERIFIED | `created_at INTEGER NOT NULL` in schema; `DRAIN_IN_PROGRESS` atomic flag with `compare_exchange`; 9 queue tests pass |
| 18 | Agent audit_emitter enqueues to offline_audit_queue when server unreachable | **FAILED** | `offline_audit_queue` module exists but is NOT called from `audit_emitter.rs` or any runtime path. Events only go to JSONL file and server relay buffer. |
| 19 | Queue overflow emits synthetic queue_overflow audit event (R-62-16) | **FAILED** | `AtCapacity` error returned by `enqueue()` but no caller handles it to emit a synthetic event. Requirement not implemented. |

**Score:** 17/19 truths verified

### Deferred Items

No deferred items — all gaps are real and require action.

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `dlp-server/src/db/mod.rs` | syslog_config + syslog_queue tables | VERIFIED | Tables with indexes, seed row, retry metadata |
| `dlp-server/src/db/repositories/syslog_config.rs` | Config CRUD + validation | VERIFIED | 6 tests pass; facility/severity validation |
| `dlp-server/src/db/repositories/syslog_queue.rs` | KEK-encrypted queue + peek-confirm-delete | VERIFIED | 8 tests pass; FIFO, tail-drop, mark_failed, count_ready |
| `dlp-server/src/syslog_connector.rs` | RFC 5424 + TLS transport | VERIFIED | 15 tests pass; PRI calc, ServerName, TLS config, newline escaping |
| `dlp-server/src/admin_api.rs` | GET/PUT/test handlers | VERIFIED | 12 admin API tests pass; auth, validation, rate limiting |
| `dlp-server/src/lib.rs` | AppState with syslog field | VERIFIED | `pub syslog: syslog_connector::SyslogConnector` |
| `dlp-server/src/main.rs` | Drain loop + graceful shutdown | VERIFIED | `tokio::select!`, `shutdown_rx`, `compute_next_attempt`, backoff |
| `dlp-server/src/audit_store.rs` | Durable-first queuing | VERIFIED | `spawn_blocking` + `SyslogQueueRepository::enqueue` before HTTP response |
| `dlp-server/src/observability.rs` | Metrics | VERIFIED | 6 tests pass; queue_depth, latency, retry, drop, tls_error |
| `dlp-common/src/crypto/dpapi.rs` | DPAPI machine-scope | VERIFIED | 3 tests pass (Windows); non-Windows stub |
| `dlp-common/src/crypto/mod.rs` | Module exports | VERIFIED | Re-exports `dpapi_protect_machine`, `dpapi_unprotect_machine`, `DpapiError` |
| `dlp-agent/src/offline_audit_queue.rs` | Agent queue with DPAPI | VERIFIED | 9 tests pass; init, enqueue, drain, delete, count, lock, created_at INTEGER |
| `dlp-admin-cli/src/screens/syslog_config.rs` | TUI screen | VERIFIED | 12 tests pass; 16 rows, picker cycling, inline validation, Test/Save/Back |
| `dlp-admin-cli/src/app.rs` | Screen::SyslogConfig variant | VERIFIED | Variant with config/selected/editing/buffer fields |
| `dlp-admin-cli/src/screens/dispatch.rs` | Navigation wiring | VERIFIED | `handle_syslog_config`, `action_load_syslog_config`, SystemMenu index 10 |
| `dlp-admin-cli/src/screens/render.rs` | Render wiring | VERIFIED | `draw_syslog_config` match arm |
| `dlp-e2e/src/lib.rs` | AppState construction | VERIFIED | `SyslogConnector::new` included in AppState |
| `dlp-agent/src/audit_emitter.rs` | Queue integration | **FAILED** | No calls to `offline_audit_queue` functions |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | --- | --- | ------ | ------- |
| audit_store.rs | syslog_queue.rs | `SyslogQueueRepository::enqueue` in `spawn_blocking` | WIRED | Durable-first queuing before HTTP response |
| admin_api.rs | syslog_config.rs | `SyslogConfigRepository::get/update` | WIRED | GET/PUT handlers call repository |
| main.rs | AppState | `syslog: SyslogConnector::new` | WIRED | Initialized and passed to AppState |
| main.rs drain loop | syslog_queue.rs | `peek_oldest` + `forward` + `delete`/`mark_failed` | WIRED | Full peek-confirm-delete cycle |
| main.rs drain loop | observability.rs | `record_syslog_*` calls | WIRED | Metrics recorded at each step |
| audit_emitter.rs | offline_audit_queue.rs | `offline_audit_queue::enqueue` | **NOT_WIRED** | No integration exists |
| dlp-agent | dlp-common crypto | `dpapi_protect_machine` | WIRED | Agent queue uses dlp-common DPAPI |
| dlp-admin-cli dispatch | syslog_config.rs | `handle_syslog_config` | WIRED | Screen routing in place |
| dlp-admin-cli render | syslog_config.rs | `draw_syslog_config` | WIRED | Render match arm in place |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| -------- | ------------- | ------ | ------------------ | ------ |
| audit_store.rs | `syslog_events` (Arc<Vec<AuditEvent>>) | HTTP request events | Yes — real audit events | FLOWING |
| audit_store.rs | `config.queue_max_size` | `SyslogConfigRepository::get` | Yes — DB query | FLOWING |
| main.rs drain loop | `batch` (Vec<QueuedEvent>) | `SyslogQueueRepository::peek_oldest` | Yes — DB query + KEK decrypt | FLOWING |
| main.rs drain loop | `events` (Vec<AuditEvent>) | `serde_json::from_str` on batch | Yes — deserialized from queue | FLOWING |
| offline_audit_queue.rs | `event_json_dpapi` blob | `dpapi_protect_machine` | Yes — DPAPI encrypted on Windows | FLOWING (module only) |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| dlp-server tests pass | `cargo test -p dlp-server --lib` | 424 passed, 3 ignored | PASS |
| dlp-agent tests pass | `cargo test -p dlp-agent --lib` | 512 passed | PASS |
| dlp-common tests pass | `cargo test -p dlp-common --lib` | 176 passed | PASS |
| dlp-admin-cli tests pass | `cargo test -p dlp-admin-cli --lib` | 133 passed | PASS |
| Full workspace tests pass | `cargo test --all --lib` | 1285 passed, 3 ignored | PASS |
| Clippy clean on modified crates | `cargo clippy -p dlp-server -p dlp-common -p dlp-agent -p dlp-admin-cli -- -D warnings` | Clean | PASS |
| Full workspace build | `cargo build --all` | Success (1 unrelated warning in dlp-hook-dll) | PASS |
| Syslog connector tests | `cargo test -p dlp-server --lib syslog_connector` | 15 passed | PASS |
| Syslog queue tests | `cargo test -p dlp-server --lib syslog_queue` | 13 passed | PASS |
| Syslog config tests | `cargo test -p dlp-server --lib syslog_config` | 17 passed | PASS |
| Admin API syslog tests | `cargo test -p dlp-server --lib admin_api::tests::test_syslog` | 12 passed | PASS |
| Agent queue tests | `cargo test -p dlp-agent --lib offline_audit_queue` | 9 passed | PASS |
| DPAPI crypto tests | `cargo test -p dlp-common --lib crypto::dpapi` | 2 passed (Windows), 1 stub (non-Windows) | PASS |
| TUI syslog screen tests | `cargo test -p dlp-admin-cli --lib screens::syslog_config` | 12 passed | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ----------- | ----------- | ------ | -------- |
| SYSLOG-01 | 62-01, 62-02 | RFC 5424 forwarding over TLS | SATISFIED | `syslog_connector.rs` with `format_rfc5424`, TLS via `tokio-rustls`, 15 tests |
| SYSLOG-02 | 62-01, 62-02 | Stable JSON payload with all fields | SATISFIED | `serde_json::to_string(event)` in `format_rfc5424`; newline escaping |
| SYSLOG-03 | 62-03 | Agent-side encrypted queue | PARTIAL | Module exists with DPAPI encryption, FIFO drain, tail-drop, single worker. **NOT wired into runtime.** |
| SYSLOG-04 | 62-03 | Admin TUI syslog config screen | SATISFIED | `syslog_config.rs` with 16 rows, picker cycling, inline validation, Test/Save/Back, 12 tests |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| `dlp-agent/src/offline_audit_queue.rs` | N/A | Module exported but never called from production code | Warning | Queue exists but is not used at runtime |
| `dlp-admin-cli/src/screens/syslog_config.rs` | 37 | `#[allow(dead_code)]` on `BOOL_FIELDS` and `NUMERIC_FIELDS` | Info | Compiler appeasement for const arrays used in tests but not all production paths |

### Human Verification Required

1. **Admin TUI SyslogConfig screen navigation and picker cycling**
   - Test: Launch dlp-admin-cli, navigate to SystemMenu, select Syslog Config, verify all 16 rows render, picker fields cycle on Enter, text fields enter edit mode, Esc returns to SystemMenu
   - Expected: Full interactive navigation works as designed
   - Why human: TUI behavior requires interactive terminal verification

2. **RFC 5424 message format against real syslog collector**
   - Test: Configure syslog forwarder pointing to real collector (rsyslog/Splunk), trigger audit event, verify message received and parsed
   - Expected: Collector accepts PRI, TIMESTAMP, JSON payload correctly
   - Why human: No real syslog collector in test environment

3. **Agent offline queue DPAPI encryption on Windows**
   - Test: On Windows host, verify `dpapi_protect_machine` encrypts and `dpapi_unprotect_machine` decrypts correctly after service restart
   - Expected: Events survive agent restart on same machine
   - Why human: DPAPI is Windows-only; CI runs on non-Windows

### Gaps Summary

Two gaps prevent full goal achievement:

1. **Agent queue not wired into runtime (BLOCKER):** The `offline_audit_queue` module is fully implemented with DPAPI encryption, FIFO drain, tail-drop, and single-worker locking. However, it is never called from `audit_emitter.rs` or any other production code path. The agent's audit events continue to go only to the local JSONL file and the server relay buffer. To close this gap:
   - Call `offline_audit_queue::init_table` during agent startup (requires SQLite connection)
   - Call `offline_audit_queue::enqueue` when the server relay fails or is unreachable
   - Call `offline_audit_queue::drain` on heartbeat success with `try_acquire_drain_lock` guard
   - Delete successfully forwarded events after server confirms receipt

2. **Synthetic queue_overflow event not implemented (BLOCKER):** R-62-16 requires emitting a synthetic `queue_overflow` audit event when the queue reaches capacity. The `AtCapacity` error is returned by `enqueue()`, but no caller exists to handle it and emit the synthetic event. This gap is coupled with gap #1 — once `enqueue` is called from `audit_emitter.rs`, the `AtCapacity` error should be caught and a synthetic event emitted.

Both gaps stem from the same root cause: the agent-side queue module was built but not integrated into the agent's event emission pipeline. The SUMMARY.md for Plan 03 explicitly documents this as a "Known Stub" ("Queue drain integration into heartbeat not yet wired"), but the verification treats it as a real gap because the phase goal includes "agent-side encrypted offline queue" which implies operational integration, not just module existence.

---

_Verified: 2026-05-14T12:30:00Z_
_Verifier: Claude (gsd-verifier)_
