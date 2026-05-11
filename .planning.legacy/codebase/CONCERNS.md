# Codebase Concerns

**Analysis Date:** 2026-04-10

## Tech Debt

### JWT Secret Fallback to Hardcoded Dev Secret (RESOLVED)

**Issue:** `dlp-server/src/admin_auth.rs::resolve_jwt_secret()` previously fell back to a hardcoded dev secret (`"dlp-server-dev-secret-change-me"`) when `JWT_SECRET` env var was unset.

**Status:** RESOLVED in Phase 2. The fallback now requires explicit `--dev` flag at startup, with prominent warning logging. Without `--dev`, server refuses to start and prints instructions to set `JWT_SECRET`. Production deployments cannot run with known secrets.

**Files:** `dlp-server/src/admin_auth.rs` (lines 37-55), `dlp-server/src/main.rs`

**Resolution approach:** Phase 2 implementation complete. Verify via `cargo test --package dlp-server --lib`.

---

### Unsafe Code in Clipboard Listener (ACCEPTED)

**Issue:** `dlp-agent/src/clipboard/listener.rs` uses extensive `unsafe` blocks for Windows API calls:
- Line 207: `unsafe { RegisterClassW(&wc) }`
- Lines 243-254: `unsafe { GetModuleHandleW(None).ok()? }` → `SetWindowsHookExW(...)`
- Lines 279-286: `unsafe { GetMessageW(...) }` / `TranslateMessage` / `DispatchMessageW` loop
- Lines 539-547: `unsafe { *ptr.add(len) }` for UTF-16 string parsing

**Impact:** If any safety invariant is violated, the listener could crash or expose memory corruption.

**Current mitigation:**
- All `unsafe` blocks are documented with SAFETY comments (lines 206-207, 214-215, 241-242, 276-277, 431-432, 441-442, 456-457).
- Windows API calls follow documented SAFETY invariants (valid pointers, correct window handles).
- The hook procedure (`hook_procedure` at line 515) runs on a dedicated thread — no cross-thread clipboard access.
- `read_wide_string` includes a sanity limit (1M characters) to prevent infinite loops.

**Risk:** Low. The Windows API surface is well-tested and the code follows established patterns from the `windows` crate examples.

**Files:** `dlp-agent/src/clipboard/listener.rs`

---

### Serialization .expect() Calls in Tests (ACCEPTABLE)

**Issue:** `dlp-server/src/admin_api.rs::tests` module contains 11 `.expect()` calls on `serde_json` operations (lines 615, 630, 639, 649, 652, 656, etc.):
```rust
let json = serde_json::to_string(&resp).expect("serialize");
let p: PolicyPayload = serde_json::from_str(json).expect("deserialize");
```

**Impact:** Test panics if serialization fails. Not a production issue (tests only), but indicates assumptions about JSON format.

**Current mitigation:**
- Tests are unit tests in `#[cfg(test)]` blocks — panics do not affect production.
- JSON shapes are statically verified by Rust's `Serialize` + `Deserialize` derives.
- Failures indicate broken JSON impl, not runtime data corruption.

**Risk:** Very low for production; acceptable for test code.

**Files:** `dlp-server/src/admin_api.rs` (lines 615–660+)

---

### bcrypt::verify() Returns Result but Code Calls .unwrap_or(false)

**Issue:** `dlp-server/src/admin_auth.rs` lines 149, 241:
```rust
let valid = tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
```

**Impact:** Errors during bcrypt verification (e.g., invalid hash format, algorithm mismatch) silently map to `false` instead of being logged.

**Current mitigation:**
- The code treats hash-format errors and password mismatches identically: failed auth.
- This is a conservative approach — any verification error means "deny access".
- Hashes in the database are bcrypt-hashed by `bcrypt::hash(password, 12)`, so format errors should not occur in practice.

**Risk:** Medium. If a hash is corrupted, the legitimate admin cannot log in and must rebuild the admin account. No error indication.

**Recommendation:** Log at WARN level when `bcrypt::verify` returns an error before mapping to `false`. Would help diagnose DB corruption or hash format issues.

**Files:** `dlp-server/src/admin_auth.rs` (lines 149, 241)

---

## Known Gaps & Deferred Work

### Phase 2: JWT_SECRET Validation — Startup Check

**Status:** COMPLETE. Server now validates `JWT_SECRET` on startup and refuses to run without it (unless `--dev`).

---

### Phase 3.1: SIEM Config Moved to Database

**Status:** COMPLETE. SIEM connector now loads config from SQLite on every `relay_events()` call (hot-reload). Environment variables deprecated. Admin API routes implemented.

---

### Phase 4: Alert Router Integration (BLOCKED)

**Issue:** `dlp-server/src/alert_router.rs` is fully implemented but **dead code**:
- `AlertRouter::from_env()` is never called in `main.rs`.
- `AppState` has no `alert` field.
- `dlp-server/src/audit_store.rs` does NOT hook alerts into the ingestion pipeline.
- Events with `Decision::DenyWithAlert` are never routed to SMTP or webhooks.

**Status:** Documented in Phase 4 CONTEXT.md. Work is blocked pending Phase 4 execution.

**Impact:** Users cannot configure email/webhook alerting today. Alerts in policies have no effect.

**Files affected:**
- `dlp-server/src/alert_router.rs` — struct exists, config parsing works, but no integration
- `dlp-server/src/main.rs` — AlertRouter not instantiated
- `dlp-server/src/audit_store.rs::ingest_events()` — no alert relay spawn
- `dlp-server/src/lib.rs` — AppState has no alert field

**Fix approach:** Execute Phase 4 plan. Mirror Phase 3.1 (SIEM config) pattern exactly:
1. Create `alert_router_config` table in SQLite (single row, seeded).
2. Rewrite `AlertRouter` to hold `Arc<Database>` and reload config on every send.
3. Add `AppState.alert` field.
4. Hook alert relay into `audit_store.rs::ingest_events()` after SIEM relay.
5. Add admin API routes (`GET/PUT /admin/alert-config`).
6. Add dlp-admin-cli TUI screen for alert configuration.

**Phase Reference:** `.planning/phases/04-wire-alert-router-into-server/04-CONTEXT.md`

---

### Phase 5: SHA-256 Audit Hash Chain (DEFERRED)

**Issue:** Audit events are signed with SIDs/usernames but not cryptographically hashed for tamper detection.

**Status:** Documented as a future phase (Phase 5, N-SEC-07) in `dlp-agent/src/audit_emitter.rs` line 49:
```rust
// TODO (Phase 5, N-SEC-07): compute SHA-256 hash of the executable
// as part of the append-only hash chain on the audit log.
```

**Impact:** Audit logs can be replayed or modified offline without detection (though Windows file ACLs and the agent's PROCESS_TERMINATE hardening provide some protection).

**Risk:** Medium. Compliance frameworks (SOC2, HIPAA) may require tamper-evident audit logging.

**Fix approach:** Implement append-only hash chain:
1. Compute SHA-256 of each audit event.
2. Chain successive hashes (current = SHA256(prev_hash || current_event)).
3. Store chain hash in each event.
4. Verify chain integrity on SIEM ingestion.

---

### HMAC Signing of Webhook Payloads (DEFERRED)

**Issue:** `dlp-server/src/alert_router.rs` has a `webhook_secret` field in `WebhookConfig`, but the `send_webhook()` function does not sign the payload.

**Status:** Documented as deferred in Phase 4 CONTEXT.md (line 213–215).

**Impact:** Webhook recipients cannot verify that alerts came from the DLP server (SSRF/spoofing risk).

**Risk:** Medium. External systems could mistake spoofed webhooks for real alerts.

**Fix approach:** Before sending webhook, compute `HMAC-SHA256(payload, webhook_secret)` and add as `X-DLP-Signature` header. Recipient verifies signature before processing.

**Files:** `dlp-server/src/alert_router.rs::send_webhook()`

---

### Password-Protected Service Stop Not Tested End-to-End

**Issue:** `dlp-agent/src/password_stop.rs` implements password challenge on `sc stop`, but integration tests are in `dlp-agent/tests/comprehensive.rs` and require:
- Running the agent as a Windows Service (SYSTEM).
- Actual `sc stop` invocation.
- UI prompt interaction via Pipe 1.

**Status:** Unit tests for registry reads and bcrypt verification exist, but E2E test is manual.

**Impact:** Regressions in `password_stop.rs` (e.g., registry key lookup, bcrypt logic) are not caught by CI.

**Risk:** Low-medium. The feature is critical for agent security but rarely exercised in automated tests.

**Recommendation:** Add integration test that:
1. Mocks the registry via in-memory state.
2. Simulates UI password submission.
3. Verifies stop is confirmed only after valid password.

**Files:** `dlp-agent/src/password_stop.rs`

---

### Integration Tests Previously Broken (RESOLVED)

**Issue:** `dlp-agent/tests/integration.rs` and `dlp-agent/tests/comprehensive.rs` referenced removed `dlp_server` modules (Phase 1).

**Status:** RESOLVED. Phase 1 replaced real engine with mock server. Phase 1 Addendum fixed `AgentConfig` struct literals.

**Verification:** Last check shows `cargo test --workspace` returns 364/364 passing across 15 test binaries. See `.planning/phases/01-fix-integration-tests/VERIFICATION.md`.

---

## Security Considerations

### Credential Handling — DPAPI-Wrapped Passwords

**Area:** Password-protected service stop (`dlp-agent/src/password_stop.rs`)

**Risk:** Plaintext password transmitted from UI to agent over Pipe 1.

**Current mitigation:**
- Pipe 1 uses SDDL security descriptor granting access only to Authenticated Users + SYSTEM.
- Password is DPAPI-encrypted (`CryptProtectData`) by the UI before transmission.
- Agent unwraps via `CryptUnprotectData` in a secure context (password_stop.rs line 300+).
- Plaintext is never stored; only bcrypt hash is cached.

**Accepted residual risk:** DPAPI protects against offline file-system theft. Live process memory inspection (if attacker has SYSTEM) could reveal plaintext after unwrap.

**Files:** `dlp-agent/src/password_stop.rs`, `dlp-agent/src/ipc/pipe1.rs`

---

### Named-Pipe IPC Security

**Area:** Three named pipes (Pipe 1, 2, 3) for agent-to-UI communication.

**Risk:** Unauthorized process connects to pipe and impersonates the UI or injects commands.

**Current mitigation:**
- SDDL security descriptor (`dlp-agent/src/ipc/pipe_security.rs`) grants write access only to Authenticated Users + SYSTEM.
- Non-SYSTEM processes can only write; cannot read agent state.
- Frame protocol includes length-prefix guard: max 64 MiB per frame (line 27 in frame.rs) prevents memory exhaustion.
- JSON parsing via `serde_json` — invalid frames rejected.

**Accepted residual risk:** An Authenticated User (any AD user on the machine) can connect and send frames. The agent validates all message types before acting.

**Files:** `dlp-agent/src/ipc/pipe_security.rs`, `dlp-agent/src/ipc/frame.rs`

---

### Audit Log Integrity (Append-Only)

**Area:** Local JSONL audit log written by `dlp-agent/src/audit_emitter.rs`.

**Risk:** If a user with local admin (but not DLP admin) gains access, they could modify or delete audit events.

**Current mitigation:**
- Log file opened with `FILE_APPEND_DATA` only (no truncate, no seek).
- NTFS ACL (set by `harden_agent_process`) denies write to Everyone, allows to SYSTEM only.
- Size-based rotation with 9 generations — event history preserved.
- Relay to dlp-server (best-effort) provides off-box copy.

**Accepted residual risk:** A user with SYSTEM privileges (or local admin who escalates) can modify or clear logs. SIEM relay is the primary audit trail.

**Files:** `dlp-agent/src/audit_emitter.rs` (lines 332–343)

---

### Secrets Storage

**Area:** Agent auth hash caching and credential handling.

**Risk:** Bcrypt hash and secrets stored in registry + memory.

**Current mitigation:**
- Hash stored in `HKLM\SOFTWARE\DLP\Agent\Credentials` — requires admin write.
- Plaintext password never persisted; only hash cached.
- Environment variable `JWT_SECRET` passed at server startup, not stored.
- SIEM credentials (`splunk_token`, `elk_api_key`) and alert credentials (`smtp_password`, `webhook_secret`) stored in SQLite with DB ACL as boundary.

**Accepted residual risk:** Low-privilege user with read access to registry can read the auth hash (but not plaintext password). SQLite file requires admin read. No encryption at rest (consistent with Phase 3.1 decision).

**Files:** `dlp-agent/src/password_stop.rs`, `dlp-server/src/admin_auth.rs`, `dlp-server/src/db.rs`

---

### Clipboard Content Classification

**Area:** Sensitive data in clipboard is classified and could be logged.

**Risk:** Clipboard preview (max 200 chars, line 387 in listener.rs) included in audit events could contain PII or secrets.

**Current mitigation:**
- Preview is truncated (200 chars max) and truncate_preview function respects UTF-8 boundaries.
- Audit events are written to a file with NTFS ACL restricting to SYSTEM.
- SIEM relay goes over HTTPS (configured).
- Classification tier (T1–T4) indicates sensitivity level in the event.

**Accepted residual risk:** If an attacker exfiltrates the audit log or SIEM database, clipboard previews could leak sensitive data. Event itself is append-only and signed (when hash chain is implemented in Phase 5).

**Files:** `dlp-agent/src/clipboard/listener.rs` (lines 385–415)

---

## Performance Bottlenecks

### Synchronous bcrypt Verification Blocks Tokio Reactor

**Issue:** Admin login (`dlp-server/src/admin_auth.rs` lines 149, 240) calls `bcrypt::verify()` on a blocking task, which is correct, but:
- Each failed login request spawns a `tokio::task::spawn_blocking()`.
- bcrypt deliberately uses 2^12 (4096) iterations of blowfish for CPU cost.
- Multiple failed login attempts can pile up blocking task threads.

**Current mitigation:**
- `tokio::task::spawn_blocking()` is used (correct).
- bcrypt cost is hardcoded to 12 (standard, necessary).
- No rate limiting on login endpoint.

**Risk:** Low-medium. A bruteforce attack with 1000 simultaneous requests could exhaust blocking task pool threads and slow other operations.

**Recommendation:** Add rate limiting middleware to `/auth/login` (e.g., per-IP, per-username). Deferred to Phase 8 (middleware).

**Files:** `dlp-server/src/admin_auth.rs`

---

### Audit Event Relay Spawns Unbounded Tasks

**Issue:** `dlp-server/src/audit_store.rs::ingest_events()` will spawn a background task for SIEM relay (Phase 3.1) and alert relay (Phase 4, not yet integrated):
```rust
tokio::spawn(async move { /* SIEM relay */ });
tokio::spawn(async move { /* alert relay */ });  // Phase 4
```

**Current mitigation:**
- Each event batch is one `tokio::spawn` (not one per event).
- Network requests have 5-second timeouts.
- No limit on concurrent spawns (could pile up if remote is slow).

**Risk:** Low. Event ingestion rate is bounded by agent batching (100 events or 1 second flush, see `dlp-agent/src/server_client.rs`). Relay operations are best-effort.

**Recommendation:** Consider adding a bounded semaphore or bounded queue for relay tasks in Phase 8 (rate limiting).

**Files:** `dlp-server/src/audit_store.rs`

---

### Clipboard Listener Frame Payload Size Limit

**Issue:** Named-pipe frame protocol allows up to 64 MiB per frame (`dlp-agent/src/ipc/frame.rs` line 27).

**Current mitigation:**
- 64 MiB is a reasonable limit (prevents memory exhaustion from malformed frames).
- Clipboard text is typically <1 MiB (even with large pastes).
- No scenario requires clipboard data >64 MiB in Phase 1.

**Risk:** Very low. Limit is enforced; OOM is not possible from clipboard frames.

**Files:** `dlp-agent/src/ipc/frame.rs`

---

## Fragile Areas

### Session Identity Resolution (No Fallback)

**Issue:** `dlp-agent/src/session_identity.rs` resolves AD user identity by SID lookup via Windows API. If AD is unreachable, the user name is left empty.

**Current mitigation:**
- Fallback to SID string (e.g., "S-1-5-21-...") for audit trail (not empty).
- Policy evaluation doesn't require resolved user name; SID alone is sufficient for ABAC.
- Log at WARN level when lookup fails.

**Risk:** Low. Policies should be written to use SID, not display name. Audit trail is complete (has SID).

**Safe modification:** Do NOT add a dependency on live AD connectivity at startup. If AD is required, fail early (currently not). Instead, cache user→SID mappings locally.

**Test coverage:** Gaps exist for "AD unreachable" scenarios. New tests should mock Windows API failures.

**Files:** `dlp-agent/src/session_identity.rs`

---

### Network Share Detection via WNet Polling

**Issue:** `dlp-agent/src/detection/network_share.rs` polls `WNetOpenEnumW` / `WNetEnumResourceW` every 30 seconds to enumerate SMB shares.

**Current mitigation:**
- Polling interval is 30 seconds (not too aggressive).
- Whitelist is checked before blocking (secure by default).
- Failures in enumeration are logged at WARN; do not block agent.

**Risk:** Low. A user could briefly connect to a non-whitelisted share before the next poll cycle (30-second window). Blocking happens at the next cycle.

**Safe modification:** Do NOT reduce poll interval below 10 seconds (Windows API overhead). Instead, add event-based detection via WMI or ETW if lower latency is required.

**Test coverage:** Mock `WNetOpenEnumW` to return various share states and verify whitelist matching.

**Files:** `dlp-agent/src/detection/network_share.rs`

---

### No Input Validation on Admin API Payloads

**Issue:** Admin API handlers in `dlp-server/src/admin_api.rs` accept JSON payloads and insert directly into DB without validation:
- Policy conditions (JSON) — not validated as valid ABAC expressions.
- SIEM URLs — not validated as valid URLs.
- SMTP host — not validated as resolvable.
- Port numbers — not validated as u16 range.

**Current mitigation:**
- JWT authentication required on all config endpoints.
- Invalid configs fail gracefully (SIEM relay doesn't send, alerts don't send).
- No SQL injection risk (prepared statements).

**Risk:** Medium. Admin can set invalid config that silently fails at runtime with no warning.

**Recommendation:** Add validation layer:
1. Validate policy conditions JSON against ABAC schema.
2. Validate URLs and email addresses.
3. Validate port as 1–65535.
4. Return 400 Bad Request with helpful error message.

**Files:** `dlp-server/src/admin_api.rs`

---

### SQLite Database Lock Contention

**Issue:** All database access uses `Arc<Mutex<Connection>>` (single lock for the entire DB). Multiple requests serialize on a global lock.

**Current mitigation:**
- `tokio::task::spawn_blocking()` prevents reactor blocking.
- SQLite is single-writer (by design); a lock is necessary.
- Most operations are fast reads (SELECT).

**Risk:** Low-medium. High-throughput audit ingestion (1000s of events/sec) could cause lock contention. Not a Phase 1 concern but worth noting.

**Recommendation:** Consider connection pooling (e.g., `rusqlite::Connection` per thread) or a dedicated DB thread + channels in Phase 6+ if throughput becomes an issue.

**Files:** `dlp-server/src/db.rs`, `dlp-agent/src/audit_emitter.rs`

---

## Test Coverage Gaps

### USB Detection Not Tested

**Issue:** `dlp-agent/src/detection/usb.rs` registers a hidden window for `WM_DEVICECHANGE` notifications. Logic for detecting USB insert/eject exists but is not exercised in unit tests.

**What's not tested:**
- Device change message routing.
- Drive type detection via `GetDriveTypeW`.
- Existing drives scan on startup.

**Files:** `dlp-agent/src/detection/usb.rs`

**Risk:** Medium. USB detection is in-scope for Phase 1 but is critical for preventing exfiltration to removable media.

**Recommendation:** Add integration tests that:
1. Mock `GetDriveTypeW` to return `DRIVE_REMOVABLE`.
2. Simulate `WM_DEVICECHANGE` message.
3. Verify detector emits `UsbEvent::Attached`.

---

### SMB Share Matching Logic Not Tested Against Edge Cases

**Issue:** `dlp-agent/src/detection/network_share.rs::matches_whitelist()` performs case-insensitive prefix matching. Not tested for:
- UNC paths with mixed case.
- Paths with trailing slashes.
- Empty share names.

**Files:** `dlp-agent/src/detection/network_share.rs`

**Risk:** Low-medium. Edge cases could cause false positives/negatives in share blocking.

**Recommendation:** Add parametrized unit tests:
```rust
#[test_matrix(
    vec![
        (r"\\server\share", r"\\SERVER\SHARE", true),
        (r"\\server\share\", r"\\server\share", true),
        (r"\\server\sh", r"\\server\share", false),
    ]
)]
fn test_whitelist_matching(unc: &str, pattern: &str, expected: bool) { ... }
```

---

### Clipboard Classification Accuracy Not Validated

**Issue:** `dlp-agent/src/clipboard/classifier.rs` classifies clipboard content by pattern matching. No test validates accuracy against known PII/sensitive data.

**Files:** `dlp-agent/src/clipboard/classifier.rs`

**Risk:** Medium. False negatives (missing T4 data) could allow exfiltration; false positives (blocking legitimate data) could frustrate users.

**Recommendation:** Add test dataset with:
- Real-world SSNs, credit card numbers, database connection strings (PII/secrets).
- Expected classification tier for each.
- Run classifier and assert accuracy.

---

## Scaling Limits

### Single-Row Database Tables

**Issue:** `siem_config` and (future) `alert_router_config` are single-row tables with `CHECK (id = 1)` constraint.

**Current capacity:** 1 SIEM config, 1 alert config per deployment.

**Limit:** If the system needs multiple SIEM backends or alert destinations, the schema must be rewritten to support N rows.

**Risk:** Low for Phase 1 (single SIEM, single alert destination). Could become a blocker in Phase 6+.

**Scaling path:** Rename tables to `siem_connectors` / `alert_destinations`, remove CHECK constraint, add `name` field, allow multiple rows. Update admin API to CRUD by ID, not assume single row.

---

### Agent Registry Size

**Issue:** `dlp-server/src/agent_registry.rs` stores all agents in memory (`Arc<RwLock<HashMap>>`). No persistence; agents re-register on restart.

**Current capacity:** Unbounded; scales to ~100k agents before memory becomes an issue (each agent entry is ~1 KB).

**Limit:** Enterprise deployments with 50k+ agents might see O(n) lookup times in heartbeat processing.

**Risk:** Very low for Phase 1. Typically deployments are <10k agents.

**Scaling path:** Persist agent registry in SQLite. Add per-agent heartbeat timestamp and clean up inactive agents (e.g., >7 days no heartbeat).

---

## Missing Critical Features

### No Encryption of Secrets at Rest in SQLite

**Issue:** `JWT_SECRET` is passed via env var (not stored). But `smtp_password`, `webhook_secret`, `splunk_token`, `elk_api_key` are stored plaintext in SQLite.

**Current mitigation:** SQLite file has NTFS ACL restricting to SYSTEM (set in `db.rs`).

**Risk:** If someone with local admin (but no DLP admin credential) copies the SQLite file, they can extract secrets.

**Impact:** Low-medium. Compliance frameworks may require encryption at rest.

**Fix approach:** Implement key derivation (e.g., PBKDF2 with machine-scoped key) and encrypt secrets before storage. Decrypt on load. Deferred to a dedicated "key management" phase.

---

### No Rate Limiting on Public Endpoints

**Issue:** Unauthenticated endpoints accept unlimited requests:
- `POST /agents/register` — agent registration.
- `POST /agents/:id/heartbeat` — agent heartbeat.
- `POST /audit/events` — audit event ingestion.
- `POST /auth/login` — admin login (brute-force vector).

**Current mitigation:** None (no middleware).

**Risk:** Medium. Attackers could:
1. Spam agent registrations (DoS).
2. Flood audit ingestion (resource exhaustion).
3. Brute-force admin password.

**Fix approach:** Add rate limiting middleware (Phase 8) with per-IP limits and exponential backoff. Phase 4 CONTEXT.md acknowledges this (line 26–27).

---

### No Request Timeout Enforcement on Long-Running Handlers

**Issue:** `dlp-server` handlers can run indefinitely if dependent services hang (e.g., SIEM relay timeout is 5 seconds, but no global handler timeout).

**Current mitigation:** Network timeouts (5 seconds on HTTP client). No handler-level timeout.

**Risk:** Low. Audit ingestion is fire-and-forget; handlers return immediately.

**Fix approach:** Add `tower::timeout` middleware with a reasonable default (e.g., 30 seconds) per route.

---

## Deferred Security Enhancements

### HMAC Signing of Webhook Payloads

**Status:** Deferred. `webhook_secret` field exists but is unused.

**Phase:** Future security hardening.

**Files:** `dlp-server/src/alert_router.rs`

---

### Encryption of Sensitive Fields at Rest

**Status:** Deferred. Secrets stored plaintext in SQLite (consistent with Phase 3.1).

**Phase:** Dedicated key management phase.

**Files:** `dlp-server/src/db.rs`

---

### Audit Log Hash Chain (SHA-256)

**Status:** Deferred to Phase 5 (N-SEC-07).

**Rationale:** Adds tamper detection but requires schema change and archive rotation.

**Files:** `dlp-agent/src/audit_emitter.rs` (line 49)

---

## Summary of Action Items

| Item | Priority | Phase | Owner |
|------|----------|-------|-------|
| Phase 2: JWT_SECRET validation | DONE | 2 | Complete |
| Phase 3.1: SIEM config in DB | DONE | 3.1 | Complete |
| Phase 4: Alert router integration | BLOCKED | 4 | Waiting for phase execution |
| bcrypt error logging | Medium | Future | Monitor login failures |
| Input validation on admin API | Medium | Future | Validation middleware |
| Rate limiting | Medium | 8 | Defer to phase 8 |
| USB detection E2E tests | Medium | Future | Expand test suite |
| Encryption at rest | Low | Future | Key management phase |
| Audit hash chain | Low | 5 | N-SEC-07 phase |

---

*Concerns audit: 2026-04-10*
