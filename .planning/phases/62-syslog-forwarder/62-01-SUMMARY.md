---
phase: 62-syslog-forwarder
plan: 01
subsystem: infra
tags: [syslog, rfc5424, tls, rustls, tokio-rustls, sqlite, encryption, kek, queue]

requires:
  - phase: 47-secrets-encryption-at-rest
    provides: SecretCrypto, KEK encryption, aad_for, Envelope, secrets_migration
  - phase: 61-approval-workflow-engine
    provides: AuditEvent type with EventType variants (Block, Alert, Access, etc.)

provides:
  - syslog_config and syslog_queue SQLite tables with indexes
  - SyslogConfigRepository for encrypted-config read/write with validation
  - SyslogQueueRepository for KEK-encrypted event queue with peek-confirm-delete
  - SyslogConnector for RFC 5424 formatting and TLS transport to syslog collectors

affects:
  - 62-syslog-forwarder (plan 02: admin API endpoints for syslog config)
  - 62-syslog-forwarder (plan 03: queue drain scheduler and retry loop)
  - 62-syslog-forwarder (plan 04: admin TUI syslog configuration screen)

tech-stack:
  added: [tokio-rustls 0.26, rustls-native-certs 0.8, rustls-pki-types 1.14, webpki-roots 1.0]
  patterns:
    - "Mirror SiemConnector pattern: hot-reload config, batched relay, fire-and-forget"
    - "KEK-encrypted queue with per-column AAD (aad_for)"
    - "Peek-confirm-delete for at-least-once delivery semantics"
    - "Pre-insert tail-drop for queue capacity enforcement"

key-files:
  created:
    - dlp-server/src/db/repositories/syslog_config.rs - SyslogConfigRepository with validation helpers
    - dlp-server/src/db/repositories/syslog_queue.rs - SyslogQueueRepository with peek-confirm-delete
    - dlp-server/src/syslog_connector.rs - SyslogConnector with RFC 5424 formatting and TLS transport
  modified:
    - dlp-server/src/db/mod.rs - syslog_config and syslog_queue CREATE TABLE statements
    - dlp-server/src/db/repositories/mod.rs - module exports for syslog_config and syslog_queue
    - dlp-server/src/lib.rs - pub mod syslog_connector
    - dlp-server/Cargo.toml - tokio-rustls, rustls-native-certs, rustls-pki-types, webpki-roots

key-decisions:
  - "No secrets in syslog_config table: system CA store only (D-10/D-11), no custom CA or mTLS"
  - "Crypto parameter kept in SyslogConfigRepository for API consistency with SiemConfigRepository"
  - "Connection pooling deferred: each forward() opens a new TCP+TLS connection (noted as future optimization)"
  - "LF (\\n) terminator instead of CRLF for broader syslog collector compatibility"
  - "JSON newlines escaped via replace in format_rfc5424 to prevent RFC 5424 framing issues"
  - "ring crypto provider installed in test context (rustls 0.23 requirement)"

patterns-established:
  - "RFC 5424 MSG field contains flat JSON-serialized AuditEvent (D-01/D-02)"
  - "Facility code 20 = LOCAL4 default, configurable 16-23 (LOCAL0-LOCAL7)"
  - "Severity mapping: Alert->ERROR(3), Block->WARNING(4), other->INFO(6) per D-03"
  - "ServerName resolution handles both DNS hostnames and IP addresses (R-62-04)"

requirements-completed: [SYSLOG-01, SYSLOG-02]

duration: 34min
completed: 2026-05-14
---

# Phase 62 Plan 01: Syslog Forwarder Core Summary

**Server-side RFC 5424 syslog infrastructure with KEK-encrypted offline queue, TLS transport, and validated config repository**

## Performance

- **Duration:** 34 min
- **Started:** 2026-05-14T07:56:53Z
- **Completed:** 2026-05-14T08:30:56Z
- **Tasks:** 3
- **Files modified:** 7 (3 created, 4 modified)

## Accomplishments

- Added `syslog_config` and `syslog_queue` tables to database schema with proper indexes
- Created `SyslogConfigRepository` with get/update and validation helpers (facility 16-23, severity 0-7)
- Created `SyslogQueueRepository` with KEK-encrypted enqueue, peek-confirm-delete, retry metadata
- Created `SyslogConnector` with RFC 5424 formatting and TLS transport over tokio-rustls
- All 409 dlp-server tests pass, clippy clean with zero warnings

## Task Commits

Each task was committed atomically:

1. **Task 1: Add syslog_config and syslog_queue tables to init_tables()** - `29e0a38` (feat)
2. **Task 2: Create SyslogConfigRepository and SyslogQueueRepository** - `ee374de` (feat)
3. **Task 3: Create SyslogConnector with RFC 5424 formatting and TLS transport** - `bade47a` (feat)

## Files Created/Modified

- `dlp-server/src/db/mod.rs` - Added syslog_config (single-row config) and syslog_queue (multi-row encrypted queue) tables with indexes
- `dlp-server/src/db/repositories/mod.rs` - Added module declarations and pub use for syslog_config and syslog_queue
- `dlp-server/src/db/repositories/syslog_config.rs` - SyslogConfigRepository with get/update, validate_facility_code, validate_severity
- `dlp-server/src/db/repositories/syslog_queue.rs` - SyslogQueueRepository with enqueue (pre-insert tail-drop), peek_oldest, delete, mark_failed, count, count_ready
- `dlp-server/src/syslog_connector.rs` - SyslogConnector with RFC 5424 format_rfc5424, TLS connect, severity/msgid mapping
- `dlp-server/src/lib.rs` - Added pub mod syslog_connector
- `dlp-server/Cargo.toml` - Added tokio-rustls, rustls-native-certs, rustls-pki-types, webpki-roots

## Decisions Made

- No secrets in syslog_config: system CA store only (D-10/D-11). The crypto parameter is kept for API consistency with SiemConfigRepository even though no columns are encrypted.
- Each forward() call opens a new TCP+TLS connection. Connection pooling is deferred as a future optimization.
- LF terminator (not CRLF) for broader syslog collector compatibility.
- HOSTNAME resolved from HOSTNAME/COMPUTERNAME env vars with "localhost" fallback, avoiding Win32 API complexity in tests.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed rustls-native-certs 0.8 API change**
- **Found during:** Task 3 (SyslogConnector TLS config build)
- **Issue:** `load_native_certs()` in 0.8 returns `CertificateResult` struct (not an iterator), with `.certs` and `.errors` fields
- **Fix:** Updated `build_tls_config()` to iterate over `cert_result.certs` instead of treating the result as an iterator
- **Files modified:** `dlp-server/src/syslog_connector.rs`
- **Verification:** TLS config tests pass after fix
- **Committed in:** `bade47a` (Task 3 commit)

**2. [Rule 3 - Blocking] Added webpki-roots as explicit dependency**
- **Found during:** Task 3 (compilation)
- **Issue:** `webpki_roots::TLS_SERVER_ROOTS` used in code but webpki-roots was only a transitive dep via reqwest, not explicitly declared
- **Fix:** Added `webpki-roots = "1.0"` to dlp-server/Cargo.toml
- **Files modified:** `dlp-server/Cargo.toml`
- **Verification:** Compilation succeeds
- **Committed in:** `bade47a` (Task 3 commit)

**3. [Rule 3 - Blocking] Fixed rustls crypto provider requirement**
- **Found during:** Task 3 (test execution)
- **Issue:** rustls 0.23 requires a crypto provider to be installed before use; tests panicked with "Could not automatically determine the process-level CryptoProvider"
- **Fix:** Added `rustls::crypto::ring::default_provider().install_default()` in TLS config test functions
- **Files modified:** `dlp-server/src/syslog_connector.rs` (tests)
- **Verification:** TLS config tests pass
- **Committed in:** `bade47a` (Task 3 commit)

**4. [Rule 1 - Bug] Fixed gethostname approach**
- **Found during:** Task 3 (compilation)
- **Issue:** Used `gethostname` crate which is not in dependencies; attempted Win32 API path was incorrect
- **Fix:** Replaced with simple env var lookup (`HOSTNAME` or `COMPUTERNAME`, fallback to "localhost")
- **Files modified:** `dlp-server/src/syslog_connector.rs`
- **Verification:** Tests pass, no external crate needed
- **Committed in:** `bade47a` (Task 3 commit)

**5. [Rule 1 - Bug] Fixed newline escaping test assertion**
- **Found during:** Task 3 (test execution)
- **Issue:** Test checked for `\\n` (escaped backslash-n) in MSG, but serde_json encodes `\n` as two characters (backslash + n) in the JSON string, which appears as `\n` in the raw output
- **Fix:** Updated test to check that no raw newlines exist in the payload (excluding the LF terminator) and that the original text is preserved
- **Files modified:** `dlp-server/src/syslog_connector.rs` (tests)
- **Verification:** Test passes
- **Committed in:** `bade47a` (Task 3 commit)

**6. [Rule 3 - Blocking] Fixed query_map iteration pattern**
- **Found during:** Task 2 (compilation)
- **Issue:** `stmt.query_map()` returns `MappedRows` which doesn't implement `Iterator` directly for `.collect()`
- **Fix:** Used `while let Some(row) = rows.next()` pattern (later simplified to `for row in rows` per clippy)
- **Files modified:** `dlp-server/src/db/repositories/syslog_queue.rs`
- **Verification:** Queue repository tests pass
- **Committed in:** `ee374de` (Task 2 commit)

**7. [Rule 1 - Bug] Fixed ExposeSecret trait import**
- **Found during:** Task 2 (compilation)
- **Issue:** `plaintext.expose_secret()` called without importing `secrecy::ExposeSecret`
- **Fix:** Added `use secrecy::ExposeSecret;` to syslog_queue.rs
- **Files modified:** `dlp-server/src/db/repositories/syslog_queue.rs`
- **Verification:** Compilation succeeds
- **Committed in:** `ee374de` (Task 2 commit)

**8. [Rule 1 - Bug] Fixed future-dated test in mark_failed**
- **Found during:** Task 2 (test execution)
- **Issue:** `mark_failed_updates_retry_metadata` used `2026-05-14T01:00:00Z` as next_attempt_at, which was in the past relative to test execution time
- **Fix:** Changed to `2099-01-01T00:00:00Z` (far future)
- **Files modified:** `dlp-server/src/db/repositories/syslog_queue.rs` (tests)
- **Verification:** Test passes
- **Committed in:** `ee374de` (Task 2 commit)

---

**Total deviations:** 8 auto-fixed (4 bugs, 4 blocking)
**Impact on plan:** All auto-fixes were necessary for compilation and test correctness. No scope creep.

## Issues Encountered

- rustls-native-certs 0.8 API differs from 0.7: returns `CertificateResult` struct instead of iterator. Required reading the crate source to discover the `.certs` field.
- rustls 0.23 requires explicit crypto provider installation (ring or aws-lc-rs). The `reqwest` crate with `rustls-tls` feature pulls in ring but does not auto-install the provider. Tests need `rustls::crypto::ring::default_provider().install_default()`.
- `Classification` is re-exported at `dlp_common::Classification` (via `pub use classification::*`), not `dlp_common::abac::Classification` as the plan's `<interfaces>` block suggested.

## Known Stubs

| File | Line | Description | Reason |
|------|------|-------------|--------|
| `dlp-server/src/syslog_connector.rs` | 240-260 | `enqueue_events` reads config from DB for max_size on every failure | Acceptable: failure path is cold, config read is cheap |
| `dlp-server/src/syslog_connector.rs` | 310 | Connection pooling not implemented | Deferred per plan: noted as future optimization |

## Next Phase Readiness

- Server-side syslog infrastructure is complete and tested
- Ready for Plan 02: Admin API endpoints for syslog config CRUD
- Ready for Plan 03: Background queue drain scheduler with retry backoff
- Ready for Plan 04: Admin TUI syslog configuration screen
- No blockers

## Self-Check: PASSED

- [x] `dlp-server/src/db/mod.rs` contains syslog_config and syslog_queue tables
- [x] `dlp-server/src/db/repositories/syslog_config.rs` exists and exports SyslogConfigRepository
- [x] `dlp-server/src/db/repositories/syslog_queue.rs` exists and exports SyslogQueueRepository
- [x] `dlp-server/src/syslog_connector.rs` exists and exports SyslogConnector
- [x] `cargo test -p dlp-server --lib` passes (409 passed, 3 ignored)
- [x] `cargo clippy -p dlp-server -- -D warnings` is clean
- [x] All commits exist: 29e0a38, ee374de, bade47a

---
*Phase: 62-syslog-forwarder*
*Plan: 01*
*Completed: 2026-05-14*
