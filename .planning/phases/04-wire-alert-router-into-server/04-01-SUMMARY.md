---
phase: 04-wire-alert-router-into-server
plan: 01
subsystem: dlp-server / alert routing
tags: [security, siem-like, hot-reload, ssrf-hardening, tm-01, tm-02, tm-03, tm-04]
dependency_graph:
  requires:
    - Phase 3.1 (siem_config in DB — structural template)
    - dlp_common::Decision::DenyWithAlert (enum variant, existed pre-phase)
    - dlp_common::AuditEvent (existed pre-phase, no content fields today)
  provides:
    - alert_router_config SQLite table (single-row, CHECK id=1)
    - AlertRouter::new(Arc<Database>) — DB-backed hot-reload constructor
    - AppState.alert field (alert_router::AlertRouter, Clone)
    - GET /admin/alert-config (JWT protected)
    - PUT /admin/alert-config (JWT protected, TM-02 webhook_url validation)
    - pub(crate) validate_webhook_url — reusable SSRF hardening helper
    - AlertError::Database variant
  affects:
    - dlp-server/src/audit_store.rs::ingest_events — now spawns alert task
tech-stack:
  added:
    - url = "2" (direct dep; was transitively in graph but Rust rejects
      transitive use — deviation Rule 3, documented below)
  patterns:
    - Fire-and-forget tokio::spawn after ingest (mirrors SIEM relay)
    - Hot-reload on every send_alert (mirrors SiemConnector::relay_events)
    - Single-row CHECK(id=1) DB pattern (mirrors siem_config)
    - spawn_blocking for SQLite admin handlers (mirrors siem handlers)
key-files:
  created: []
  modified:
    - dlp-server/Cargo.toml
    - dlp-server/src/db.rs
    - dlp-server/src/alert_router.rs
    - dlp-server/src/lib.rs
    - dlp-server/src/main.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/audit_store.rs
decisions:
  - "TM-01 accepted: smtp_password + webhook_secret stored plaintext in SQLite (Phase 3.1 precedent, trust boundary is Windows ACL on dlp-server.db)"
  - "TM-02 enforced: validate_webhook_url https-only, blocks loopback + link-local (IPv4 + IPv6), allows RFC1918, textual-only no DNS"
  - "TM-03 documented: send_email serializes full AuditEvent as-is (no content fields today); forward-compat reviewer rule in alert_router.rs module doc"
  - "TM-04 enforced: exactly 2 tracing::warn! calls in alert_router.rs, zero metrics/counters"
  - "url = \"2\" added as direct dep — plan's G5 claim that url was transitively usable is incorrect; Rust rejects transitive dep use regardless of graph presence"
  - "Integration tests share a constant TEST_JWT_SECRET matching admin_auth::DEV_JWT_SECRET literal because OnceLock silently ignores duplicate set_jwt_secret calls"
metrics:
  duration: "~25 minutes"
  completed: "2026-04-10"
  tasks_completed: 5
  commits: 6
---

# Phase 4 Plan 01: Wire Alert Router into Server Summary

One-liner: DB-backed hot-reload `AlertRouter` with JWT-protected
`GET/PUT /admin/alert-config`, TM-02 SSRF-hardened `validate_webhook_url`,
and a fire-and-forget `tokio::spawn` in `audit_store::ingest_events` that
routes `Decision::DenyWithAlert` events to SMTP + webhook without adding
any latency to the HTTP ingest path.

## Overview

Phase 4 Plan 1 converts the env-var-based `AlertRouter` into a
DB-backed, hot-reloading router that reads `alert_router_config` on
every `send_alert` call. It wires the router into `AppState` and into
`ingest_events` as a fire-and-forget spawn, adds JWT-protected admin
endpoints for reading/updating the config, and enforces TM-02 SSRF
hardening on `webhook_url` via a textual `validate_webhook_url` helper.

All four ratified threat-model decisions (TM-01 plaintext secrets,
TM-02 SSRF block, TM-03 send-full-event with forward-compat rule,
TM-04 warn-only observability) are honored verbatim.

## Tasks Completed

| # | Wave | Task                                                         | Commit    |
| - | ---- | ------------------------------------------------------------ | --------- |
| 1 | 0    | Stubs + Decision::DenyWithAlert verification                 | `732ef2d` |
| 2 | 1    | alert_router_config DDL + seed row                           | `ceb17b1` |
| 3 | 2    | AlertRouter DB-backed rewrite + AppState.alert + main wiring | `1332edc` |
| 4 | 3    | admin_api: payload + validate_webhook_url + handlers + tests | `eb2e675` |
| 5 | 4    | audit_store fire-and-forget alert spawn                      | `b9ce746` |
| — | —    | `cargo fmt --check` compliance                               | `413b7b5` |

Total: 6 commits (5 waves + 1 style fix). All on branch
`worktree-agent-ae8d8a79`.

## Key Changes by File

### `dlp-server/Cargo.toml`
- **Added** `url = "2"` as a direct dependency. Deviation (Rule 3): the
  plan's G5 assumed `url` was transitively usable via `reqwest`, but
  Rust's edition system rejects `use url::...` unless the crate is
  declared directly. Since `url v2.5.8` is already in the dependency
  graph (via `lettre` + `reqwest`), this adds zero compile time.

### `dlp-server/src/db.rs`
- **Added** `alert_router_config` DDL inside `init_tables`:
  - `CREATE TABLE IF NOT EXISTS alert_router_config` with 11 columns
    (smtp_* × 7, webhook_* × 3, updated_at), `id INTEGER PRIMARY KEY
    CHECK (id = 1)`.
  - `INSERT OR IGNORE INTO alert_router_config (id) VALUES (1)` seeds
    the single row with both channels disabled by default.
- **Extended** `test_tables_created` with `alert_router_config` assertion.
- **Added** `test_alert_router_config_seed_row` — verifies the table,
  seed row, and default-off flags.

### `dlp-server/src/alert_router.rs` (rewritten)
- **DELETED**: `from_env`, `load_smtp_config`, `load_webhook_config`,
  `test_from_env_no_vars`, and the per-field `std::env::var` logic.
- **DELETED**: `tracing::error!` at the send_webhook non-2xx path
  (TM-04 caps the file at exactly 2 warn calls).
- **Added** `AlertRouterConfigRow` private snapshot struct.
- **Rewrote** `pub struct AlertRouter` as `{ db: Arc<Database>, client: Client }`.
- **Added** `AlertRouter::new(db: Arc<Database>)` constructor.
- **Added** `fn load_config(&self) -> Result<..., AlertError>` — single
  SELECT with `u16::try_from` overflow check (lifts the row reader
  shape verbatim from `siem_connector::load_config`).
- **Rewrote** `send_alert` to:
  1. Call `load_config()` every invocation (hot-reload — no caching).
  2. SMTP path active iff `smtp_enabled && !smtp_host.empty() && !smtp_to.empty()`.
     Splits comma-separated `smtp_to` string into `Vec<String>`, trims,
     filters empties (G4).
  3. Webhook path active iff `webhook_enabled && !webhook_url.empty()`.
  4. On per-channel failure, logs `tracing::warn!(error = %e, "…")`
     with the exact TM-04 message format.
- **Extended** `AlertError` with a `Database(#[from] rusqlite::Error)`
  variant.
- **KEPT** `SmtpConfig`, `WebhookConfig`, `send_email`, `send_webhook`
  function bodies unchanged (send_webhook only lost the non-2xx
  `tracing::error!` line).
- **Added** module-level doc comment with TM-03 forward-compat rule
  listing all 15 banned content-field names reviewers should grep for.
- **Added** 4 new tests: `test_alert_router_disabled_default`,
  `test_load_config_roundtrip`, `test_load_config_port_overflow`,
  `test_hot_reload` — all passing.

### `dlp-server/src/lib.rs`
- **Added** `pub alert: alert_router::AlertRouter` to `AppState`.
  `AlertRouter` already derives `Debug, Clone`.

### `dlp-server/src/main.rs`
- **Added** `use dlp_server::alert_router::AlertRouter;`.
- **Added** `let alert = AlertRouter::new(Arc::clone(&db));` after the
  SIEM connector construction.
- **Changed** `AppState { db, siem }` to `AppState { db, siem, alert }`.

### `dlp-server/src/admin_api.rs`
- **Added** `pub struct AlertRouterConfigPayload` — 10 editable columns,
  derives `Debug, Clone, Serialize, Deserialize, PartialEq` (PartialEq
  is intentional — enables `assert_eq!(rt, p)` in the round-trip test,
  a deliberate deviation from `SiemConfigPayload`).
- **Added** `pub(crate) fn validate_webhook_url(url: &str) -> Result<(), String>`:
  - `url::Url::parse` for parsing (TM-02).
  - Requires `scheme == "https"`; rejects http/ftp/file with "scheme must be https".
  - IPv4: `Ipv4Addr::is_loopback` blocks 127/8; `Ipv4Addr::is_link_local`
    blocks 169.254/16 (both stable in rustc).
  - IPv6: `Ipv6Addr::is_loopback` blocks `::1`; manual segment bitmask
    `(first_segment & 0xffc0) == 0xfe80` blocks fe80::/10 (G3:
    `is_unicast_link_local` is unstable).
  - RFC1918 (10/8, 172.16/12, 192.168/16) intentionally falls through
    to `Ok(())`.
  - Domain hosts accepted textually — no DNS lookup (TM-02 ratified).
- **Added** `get_alert_config_handler` — `spawn_blocking` SELECT with
  `u16::try_from` overflow check; returns `Json<AlertRouterConfigPayload>`.
- **Added** `update_alert_config_handler` — calls `validate_webhook_url`
  BEFORE any DB write (skipped when `webhook_url` is empty), then
  `spawn_blocking` UPDATE with `updated_at = Utc::now().to_rfc3339()`.
  Returns the written payload.
- **Registered** two new routes in `admin_router`'s protected group:
  `GET /admin/alert-config`, `PUT /admin/alert-config`.
- **Extended** the doc-comment route table with the two new routes.
- **Added** 7 new tests (all Wave 0 stubs replaced):
  1. `test_alert_router_config_payload_roundtrip` — JSON serde symmetry.
  2. `test_validate_webhook_url` — 26-case table-driven test (see below).
  3. `test_put_alert_config_rejects_http` — spot check.
  4. `test_put_alert_config_rejects_loopback` — spot check.
  5. `test_put_alert_config_accepts_rfc1918` — spot check.
  6. `test_get_alert_config_requires_auth` — builds full `admin_router`,
     sends unauth GET, asserts `401 UNAUTHORIZED` (exercises JWT middleware).
  7. `test_put_alert_config_roundtrip` — builds full router, mints a
     valid JWT inline via `jsonwebtoken::encode + admin_auth::Claims`,
     PUTs payload, GETs it back, asserts `assert_eq!`.

The 26 table-driven cases in `test_validate_webhook_url` cover: empty
string, http, ftp, file, parse failure, IPv4 loopback (+ range +
port), IPv6 loopback (+ port), 169.254.169.254 cloud metadata,
169.254/16 range, IPv6 fe80::/10 (lower + upper edge), site-local
(fec0:: — accepted), RFC1918 × 3 + edges, public IPv4/IPv6, public
hostname, internal hostname, URL with path + query.

### `dlp-server/src/audit_store.rs`
- **Added** `let alert_events: Vec<AuditEvent> = relay_events.iter()
  .filter(|e| matches!(e.decision, dlp_common::Decision::DenyWithAlert))
  .cloned().collect();` **before** the existing SIEM spawn (G7 — so
  `relay_events` can still be moved into the SIEM closure).
- **Added** a second `tokio::spawn` guarded by `!alert_events.is_empty()`
  after the SIEM spawn. The task iterates and awaits `alert.send_alert`
  per event, logging outer failures with `tracing::warn!(error = %e,
  "alert delivery failed (best-effort)")`.
- The HTTP response path is NEVER awaited on alert I/O — latency is
  unchanged even when SMTP or webhook delivery is slow.
- No new `use` statement — `dlp_common::Decision` is fully qualified at
  the filter site to keep the diff minimal.

## Threat Model Verification

All four ratified threat-model decisions verified by grep + test:

| ID    | Mitigation                                       | Verification                                                                    | Status |
| ----- | ------------------------------------------------ | ------------------------------------------------------------------------------- | ------ |
| TM-01 | Plaintext smtp_password (Phase 3.1 precedent)    | Documented in SUMMARY; schema locked                                            | PASS   |
| TM-02 | validate_webhook_url https-only + ll/lp blocks   | `test_validate_webhook_url` (26 cases) + handler call site                      | PASS   |
| TM-03 | Full AuditEvent serialization, forward-compat    | `grep -l 'sample_content\|…' dlp-common/src/audit.rs` → empty                   | PASS   |
| TM-04 | Exactly 2 tracing::warn!, zero metrics           | `grep -c 'tracing::warn' → 2`; `grep -cE 'AtomicU64\|counter\|…' → 0`           | PASS   |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] Added `url = "2"` as direct dependency**
- **Found during:** Wave 3 (admin_api.rs compile attempt)
- **Issue:** Plan G5 claimed `url` was transitively available via
  `reqwest` and did not need to be added to `dlp-server/Cargo.toml`.
  This is incorrect — Rust's edition system requires crates be
  declared as direct dependencies before `use url::…` is allowed,
  regardless of whether they appear in the compiled dependency graph.
- **Fix:** Added `url = "2"` under `[dependencies]` in
  `dlp-server/Cargo.toml`. The crate (`url v2.5.8`) was already in the
  graph via `lettre` and `reqwest`, so this adds zero compile time.
- **Files modified:** `dlp-server/Cargo.toml`
- **Commit:** `eb2e675`

**2. [Rule 1 — Bug] Integration tests must share JWT secret with admin_auth tests**
- **Found during:** Wave 3 (test_put_alert_config_roundtrip first run)
- **Issue:** The first test failed with 401 instead of 200 because
  `admin_auth::set_jwt_secret` is backed by a `std::sync::OnceLock`
  that silently ignores duplicate set calls. The `admin_auth::tests`
  module's `ensure_test_secret` runs first in the suite and sets the
  OnceLock to its private `DEV_JWT_SECRET` constant. Our test
  constructed a token with a DIFFERENT secret, so the JWT middleware
  rejected it.
- **Fix:** Defined a module-local constant
  `const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";`
  matching the literal value of `admin_auth::DEV_JWT_SECRET`. All
  integration tests in the `admin_api::tests` module use this constant
  for both the `set_jwt_secret` call and the `EncodingKey::from_secret`
  call so all cross-module tests converge on a single secret.
- **Files modified:** `dlp-server/src/admin_api.rs`
- **Commit:** `b9ce746`

**3. [Rule 1 — Bug] TM-04 false-positive grep hits in doc comments**
- **Found during:** Wave 2 verification
- **Issue:** Initial alert_router.rs draft had two doc-comment lines
  mentioning "encountered" (matches `counter`) and "tracing::error!"
  (mentioned a forbidden token in prose). The TM-04 grep acceptance
  checks `grep -c 'tracing::error'` and
  `grep -cE 'AtomicU64\|counter\|metrics\|…'` returned 1 each.
- **Fix:** Rephrased doc comments. "returns the first error
  encountered" → "returns the first error seen". "Non-2xx responses
  are silent (no tracing::error!)" → "Non-2xx responses are treated as
  silent successes at this layer". Zero semantic change; same
  behavior.
- **Files modified:** `dlp-server/src/alert_router.rs`
- **Commit:** `1332edc` (folded into Wave 2)

**4. [Rule 1 — Bug] Worktree branch base was incorrect**
- **Found during:** Initial `<worktree_branch_check>` on startup
- **Issue:** Branch was rooted at `68b6f8b6...` (a later commit on
  main) instead of the expected base `9008ac72...`. The branch had
  stale prior-run artifacts piled on (codebase/ARCHITECTURE.md, an
  orphan PLAN.md, etc.).
- **Fix:** `git reset --soft 9008ac72...` then `git reset HEAD` then
  `git checkout 9008ac72... -- .planning/` to restore the correct
  plan files from the base commit, then removed the orphan
  `.planning/phases/04-wire-alert-router-into-server/PLAN.md` stale
  untracked file.
- **Files modified:** None permanently — this was a pre-execution
  cleanup. No commit.

## Authentication Gates

None encountered — no external services required during this plan.

## Known Stubs

None. Every module touched has real, working implementations. The
`send_alert` code path wires all the way from `ingest_events` through
the DB config read to the SMTP + webhook sends.

## Deferred Items (out of scope for this plan)

Carried forward from CONTEXT.md Deferred Ideas (no new additions):
- HMAC signing of webhook payloads (field exists; plumb in a future
  security phase).
- Rate limiting of alerts.
- Encryption-at-rest for `smtp_password` / `webhook_secret` (covered
  by a future key-management phase for ALL secret columns together).
- SMTP/webhook mock test harness (would exercise the real send paths).
- Alert delivery metrics / counters / dashboards (TM-04 ratified out).
- DNS-based `webhook_url` validation (TM-02 ratified textual-only).
- dlp-admin-cli typed client methods + TUI Alert Config screen —
  **Plan 04-02** scope; Plan 04-01 intentionally ships only the
  server-side routes.

## Phase-Level Verification (Plan §<verification> block)

```bash
# 1. Full workspace tests
cargo test --workspace
# Result: all suites ok; exit 0. Key counts:
#   dlp-server lib: 42 passed, 0 failed
#   dlp-agent lib:  136 passed
#   dlp-common lib: 106 passed
#   dlp-common comprehensive: 41 passed
#   dlp-common integration:   7 passed
#   dlp-common negative:      28 passed
#   dlp-admin-cli: 8 passed
#   dlp-user-ui:   1 passed + 1 clipboard integration passed

# 2. Clippy must be clean
cargo clippy --workspace -- -D warnings
# Result: clean — Finished `dev` profile [unoptimized + debuginfo]

# 3. Formatting
cargo fmt --check
# Result: clean after commit 413b7b5

# 4. TM-04: exactly 2 warn! calls in alert_router.rs
grep -c 'tracing::warn' dlp-server/src/alert_router.rs
# Result: 2 (EXPECTED)

# 5. TM-04: no metrics/counters
grep -cE 'AtomicU64|counter|metrics|prometheus|opentelemetry' dlp-server/src/alert_router.rs
# Result: 0 (EXPECTED)

# 6. TM-02: validate_webhook_url exists and is called
grep -c 'validate_webhook_url' dlp-server/src/admin_api.rs
# Result: 17 (definition + doc-comment refs + call in update handler + 12 test refs across 26-case table and spot checks; plan expected "at least 3")

# 7. TM-03 forward-compat grep — must be empty
grep -l 'sample_content\|content_preview\|matched_text\|snippet\|payload_content\|clipboard_text\|file_excerpt\|plaintext' dlp-common/src/audit.rs
# Result: (empty output — EXPECTED)

# 8. Fire-and-forget: alert.send_alert must be INSIDE a tokio::spawn
grep -B3 'alert\.send_alert' dlp-server/src/audit_store.rs
# Result: shows `tokio::spawn(async move {` on the immediate prior lines

# 9. from_env and all env-var helpers are deleted
grep -cE 'from_env|load_smtp_config|load_webhook_config|test_from_env_no_vars' dlp-server/src/alert_router.rs
# Result: 0 (EXPECTED)

# 10. Decision::DenyWithAlert is the filter variant
grep -c 'Decision::DenyWithAlert' dlp-server/src/audit_store.rs
# Result: 2 — one in the matches! filter code, one in the nearby
#         comment explaining what is / isn't alerted on. Plan expected 1;
#         the extra comment occurrence does not affect correctness.
```

## Self-Check

| # | must_have claim                                      | Verification command                                                                            | Status |
| - | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------ |
| 1 | alert_router_config table with CHECK(id=1), seed row | `cargo test -p dlp-server --lib db::tests::test_alert_router_config_seed_row`                    | PASS   |
| 2 | AlertRouter holds Arc<Database> + hot-reload         | `cargo test -p dlp-server --lib alert_router::tests::test_hot_reload`                            | PASS   |
| 3 | AppState.alert populated in main.rs                  | `grep -c 'AppState { db, siem, alert }' dlp-server/src/main.rs` → 1                              | PASS   |
| 4 | ingest_events fire-and-forget DenyWithAlert spawn    | `grep -B3 'alert\.send_alert' dlp-server/src/audit_store.rs` shows tokio::spawn above            | PASS   |
| 5 | GET + PUT /admin/alert-config JWT-protected + RT     | `cargo test -p dlp-server --lib admin_api::tests::test_put_alert_config_roundtrip`               | PASS   |
| 6 | validate_webhook_url blocks ll/lp, allows RFC1918    | `cargo test -p dlp-server --lib admin_api::tests::test_validate_webhook_url` (26 cases)          | PASS   |
| 7 | tracing::warn! only (no metrics)                     | `grep -c 'tracing::warn' … → 2` AND `grep -cE 'AtomicU64\|counter\|…' → 0`                       | PASS   |
| 8 | send_email sends full AuditEvent as-is               | TM-03 grep against dlp-common/src/audit.rs returns empty                                         | PASS   |
| 9 | from_env et al deleted                               | `grep -cE 'from_env\|load_smtp_config\|load_webhook_config\|test_from_env_no_vars' … → 0`        | PASS   |
| 10 | cargo fmt + clippy + workspace tests clean          | `cargo fmt --check` (exit 0) + `cargo clippy --workspace -- -D warnings` + `cargo test --workspace` | PASS   |

## Self-Check: PASSED

All 10 must-have claims verified. File existence + commit existence:

```
FOUND: dlp-server/src/db.rs
FOUND: dlp-server/src/alert_router.rs
FOUND: dlp-server/src/lib.rs
FOUND: dlp-server/src/main.rs
FOUND: dlp-server/src/admin_api.rs
FOUND: dlp-server/src/audit_store.rs
FOUND: dlp-server/Cargo.toml

FOUND: 732ef2d (Wave 0 stubs)
FOUND: ceb17b1 (Wave 1 DDL)
FOUND: 1332edc (Wave 2 AlertRouter rewrite)
FOUND: eb2e675 (Wave 3 admin_api)
FOUND: b9ce746 (Wave 4 audit_store spawn)
FOUND: 413b7b5 (cargo fmt style fix)
```
