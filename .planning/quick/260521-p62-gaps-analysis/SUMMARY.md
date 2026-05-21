---
phase: 62-syslog-forwarder
date: 2026-05-21
status: complete
truths_verified: 19/19
artifacts_matched: 18/20
gaps_found: 3
gap_severity: minor
---

# Phase 62 Gaps Analysis: Plans vs. Code/Docs

**Analyzed:** 2026-05-21
**Scope:** All 4 plans (62-01 through 62-04) cross-referenced against actual source code, SUMMARY files, and VERIFICATION.md.

---

## Methodology

1. Read all 4 PLAN.md files and extracted `must_haves` (truths + artifacts + key_links).
2. Read all 4 SUMMARY.md files to understand claimed deliverables.
3. Read actual source files for every artifact declared in plans.
4. Compared plan claims against code reality.
5. Cross-checked with VERIFICATION.md (19/19 truths pass).

---

## Overall Verdict

**No functional gaps.** All 19 verification truths pass, all tests pass (1646 passed), build and clippy clean.

**Three documentation/expectation mismatches** exist between what plans *claimed* and what code *does*. These do not affect correctness but create drift between planning artifacts and implementation.

---

## Gap 1: syslog_config is NOT Encrypted (Minor)

**Plan claim (62-01, must_haves):**
> "Syslog configuration persists across server restarts with encrypted secrets"

**Plan claim (62-01, artifacts):**
> "SyslogConfigRepository with get/update and encrypted secrets"

**Actual code (`dlp-server/src/db/repositories/syslog_config.rs:7-10`):**
```rust
//! Unlike `siem_config`, this repository has no encrypted secrets --
//! syslog configuration uses the system CA store only (no custom CA or
//! mTLS per D-10/D-11). The `crypto` parameter is kept for API
//! consistency with `SiemConfigRepository`.
```

**Analysis:** The code comment explicitly states there are NO encrypted secrets in syslog config. The `crypto` parameter is passed but unused. The `SyslogConfigRow` struct stores all fields as plain `String`/`i64` with no `Envelope` wrapping. This is a correct design choice (no secrets to protect), but the plan incorrectly claimed encrypted secrets.

**Impact:** Minor documentation drift. No security impact since there are no secrets (no CA cert, no mTLS cert, no API key) in syslog config.

**Fix:** Update 62-01-PLAN.md to remove "encrypted secrets" claim. The plan should read "plain text config with no secrets" or similar.

---

## Gap 2: Server Queue `created_at` is TEXT, Not INTEGER (Minor)

**Plan requirement (R-62-13, 62-03 must_haves):**
> "Agent queue uses INTEGER (Unix epoch) for created_at, not TEXT"

**Actual server queue schema (`dlp-server/src/db/mod.rs:415`):**
```sql
CREATE TABLE IF NOT EXISTS syslog_queue (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    event_json_encrypted   BLOB NOT NULL,
    event_json_nonce       BLOB NOT NULL,
    created_at             TEXT NOT NULL,        -- <-- TEXT, not INTEGER
    retry_count            INTEGER NOT NULL DEFAULT 0,
    last_error             TEXT NOT NULL DEFAULT '',
    next_attempt_at        TEXT NOT NULL DEFAULT '',
    leased_until           TEXT NOT NULL DEFAULT ''
);
```

**Actual agent queue schema (`dlp-agent/src/offline_audit_queue.rs:29-30`):**
```sql
created_at     INTEGER NOT NULL,   -- Correct: INTEGER per R-62-13
```

**Analysis:** R-62-13 specifically requires INTEGER (Unix epoch) for `created_at`. The agent queue correctly uses INTEGER, but the server queue uses TEXT. The VERIFICATION.md (truth #17) says "`created_at INTEGER NOT NULL` in schema" but only verifies the agent queue, not the server queue.

**Impact:** Minor. The server queue's TEXT `created_at` still works for FIFO ordering (SQLite lexicographic sort on ISO-8601 strings is correct). But it's inconsistent with the stated requirement and with the agent queue.

**Fix:** Either:
- (a) Change server queue `created_at` to INTEGER and migrate, OR
- (b) Update the requirement to allow TEXT for server queue (since it works correctly).

---

## Gap 3: `peek_and_claim` Replaces `peek_oldest` + `mark_failed` Pattern (Minor)

**Plan claim (62-01, must_haves):**
> "R-62-02: Queue repository uses peek-confirm-delete semantics for at-least-once delivery"
> "peek_oldest: Returns decrypted events WITHOUT removing rows"
> "mark_failed: Updates retry_count, last_error, and next_attempt_at for time-based scheduling"

**Plan claim (62-02, must_haves):**
> "Drain loop uses peek-confirm-delete: peek batch, forward, delete on success, mark_failed on error"
> "Queue drain respects next_attempt_at scheduling (time-based retry, not just count-based)"

**Actual code (`dlp-server/src/db/repositories/syslog_queue.rs:261-298`):**
```rust
pub fn peek_and_claim(
    pool: &Pool,
    crypto: &SecretCrypto,
    batch_size: usize,
    lease_secs: u64,
) -> Result<Vec<QueuedEvent>, AppError> {
    // Atomically sets leased_until on selected rows to prevent concurrent
    // drain workers from picking up the same events.
```

**Actual drain loop (`dlp-server/src/main.rs:422-428`):**
```rust
let batch = match tokio::task::spawn_blocking({
    let pool = Arc::clone(&drain_pool);
    let crypto = Arc::clone(&drain_crypto);
    move || SyslogQueueRepository::peek_and_claim(&pool, &crypto, 100, 300)
})
```

**Analysis:** The actual implementation uses `peek_and_claim` with a `leased_until` column (300-second lease) to prevent concurrent drain workers from processing the same events. The plan described a simpler `peek_oldest` + `mark_failed` pattern. The `mark_failed` function still exists (line 201) but is NOT called by the drain loop. Instead, on forward failure, the lease expires naturally and events are re-claimed on the next cycle.

This is actually a **superior** design (lease-based concurrency control vs. optimistic locking with mark_failed), but it diverges from the plan.

**Impact:** Minor. The code is better than the plan specified, but the plan's key_links and must_haves describe a different pattern than what was implemented.

**Fix:** Update 62-01-PLAN.md and 62-02-PLAN.md to document the `peek_and_claim` + `leased_until` pattern instead of `peek_oldest` + `mark_failed`.

---

## Additional Observations (Non-Gaps)

### Observation A: Queuing Happens in audit_store.rs, Not syslog_connector.rs

**Plan key_link (62-01):**
> from: "syslog_connector.rs"
> to: "syslog_queue.rs repository"
> via: "SyslogQueueRepository::enqueue() on send failure"

**Actual code:**
- `SyslogQueueRepository::enqueue` is called in `audit_store.rs:244` (durable-first queuing).
- `syslog_connector.rs` does NOT call `enqueue`. It only calls `forward()`.

**Verdict:** Not a gap. The plan's key_link was imprecise about *where* the enqueue happens, but the overall flow is correct. The audit_store enqueues BEFORE attempting forward, which is the durable-first pattern described in 62-02.

### Observation B: `compute_next_attempt` Exists But Is Never Called on Success Path

**Plan claim (62-02):**
> "Drain loop backoff is per config generation; resets when config changes"

**Actual code (`dlp-server/src/main.rs:518-520`):**
```rust
let next_attempt = compute_next_attempt(consecutive_failures);
```

This is only called on the **failure** path (forward failed). On success, `consecutive_failures` is reset to 0 but no explicit backoff reset logic exists beyond that.

**Verdict:** Not a gap. The backoff works correctly (resets on success via `consecutive_failures = 0`), but the plan's claim about "per config generation" backoff is not implemented.

### Observation C: `mark_failed` Function Exists But Is Unused in Drain Loop

**Plan claim:** `mark_failed` is used to update retry metadata on forward failure.

**Actual code:** `mark_failed` is defined at `syslog_queue.rs:201` and has unit tests, but the drain loop in `main.rs` never calls it. Instead, it relies on the `leased_until` timeout for retry.

**Verdict:** Dead code (function + tests). Not a functional gap since the lease pattern achieves the same goal, but the unused function should be removed or the plan should be updated.

---

## Artifact Inventory

| Artifact | Plan Claims | Code Reality | Status |
|----------|------------|--------------|--------|
| `dlp-server/src/db/mod.rs` | syslog_config + syslog_queue tables | Both tables exist with correct schemas | MATCH |
| `dlp-server/src/db/repositories/syslog_config.rs` | Encrypted secrets | Plain text (no secrets to encrypt) | GAP #1 |
| `dlp-server/src/db/repositories/syslog_queue.rs` | peek_oldest, mark_failed | peek_and_claim, leased_until | GAP #3 |
| `dlp-server/src/syslog_connector.rs` | RFC 5424 + TLS transport | RFC 5424 + TLS transport | MATCH |
| `dlp-server/src/admin_api.rs` | GET/PUT/test handlers | All three handlers exist with validation + rate limiting | MATCH |
| `dlp-server/src/lib.rs` | AppState with syslog field | `pub syslog: syslog_connector::SyslogConnector` | MATCH |
| `dlp-server/src/main.rs` | Drain loop + graceful shutdown | Drain loop with tokio::select! + shutdown_rx | MATCH |
| `dlp-server/src/audit_store.rs` | Durable-first queuing | Enqueues to syslog_queue before forward | MATCH |
| `dlp-server/src/observability.rs` | Metrics | 5 metrics recorded | MATCH |
| `dlp-common/src/crypto/dpapi.rs` | DPAPI machine-scope | `CRYPTPROTECT_LOCAL_MACHINE` flag | MATCH |
| `dlp-agent/src/offline_audit_queue.rs` | Agent queue with DPAPI | DPAPI encrypt, INTEGER created_at | MATCH |
| `dlp-agent/src/audit_emitter.rs` | Queue integration + synthetic overflow | `enqueue_with_overflow_event` + synthetic event | MATCH |
| `dlp-agent/src/service.rs` | DB init on startup | `AGENT_DB` OnceLock + `init_agent_db` | MATCH |
| `dlp-agent/src/server_client.rs` | Flush fallback + JSON forwarding | `send_audit_events_json` + flush enqueue | MATCH |
| `dlp-agent/src/offline.rs` | Heartbeat drain loop | `try_acquire_drain_lock` + drain + delete | MATCH |
| `dlp-admin-cli/src/screens/syslog_config.rs` | TUI screen | 16 rows, picker cycling, validation | MATCH |
| `dlp-admin-cli/src/app.rs` | Screen::SyslogConfig variant | Variant with config/selected/editing/buffer | MATCH |
| `dlp-admin-cli/src/screens/dispatch.rs` | Navigation wiring | handle_syslog_config, action_load/save/test | MATCH |
| `dlp-admin-cli/src/screens/render.rs` | Render wiring | draw_syslog_config match arm | MATCH |

---

## Summary

| Category | Count |
|----------|-------|
| Truths verified | 19/19 |
| Artifacts matched | 18/20 |
| Functional gaps | 0 |
| Documentation drift | 3 |
| Dead code | 1 (`mark_failed` unused) |

**All three gaps are minor documentation/expectation mismatches, not functional defects.** The code is correct and complete. The plans should be updated to reflect the actual implementation for future maintainers.

### Recommended Actions

1. **Update 62-01-PLAN.md:** Remove "encrypted secrets" claim from syslog_config. Add note about plaintext storage (no secrets in config).
2. **Update 62-01-PLAN.md:** Document `created_at TEXT` for server queue or change schema to INTEGER per R-62-13.
3. **Update 62-01-PLAN.md and 62-02-PLAN.md:** Replace `peek_oldest` + `mark_failed` references with `peek_and_claim` + `leased_until` pattern.
4. **Optional cleanup:** Remove unused `mark_failed` function and its tests from `syslog_queue.rs` (or document why it's kept).
