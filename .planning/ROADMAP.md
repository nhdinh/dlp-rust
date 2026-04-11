# ROADMAP.md — v0.2.0 Feature Completion

## Milestone: v0.2.0

### Phase 0.1: Fix clipboard monitoring runtime pipeline [COMPLETED]
**Status:** Resolved via `/gsd-debug` — see `.planning/debug/clipboard-monitoring-no-alerts.md`
**Files:** `dlp-agent/src/service.rs`, `dlp-user-ui/src/app.rs`, `dlp-user-ui/src/ipc/pipe3.rs`
**Description:** Urgent bugfix — clipboard monitoring was wired in code and passed Phase 99 integration tests, but produced no runtime alerts. Four compounding root causes: (A) WorkerGuard lifetime bug + `.init()` panics in agent logging; (B) UI subscriber wrote to stderr only under `windows_subsystem="windows"`; (C) `tracing_appender::non_blocking` 0.2.4 silently swallows IO errors; (D) Pipe 3 `PIPE_NAME_DEFAULT` was missing one backslash (`r"\.\pipe\..."` vs `r"\\.\pipe\..."`), which Phase 99 tests bypassed via `DLP_PIPE3_NAME`.
**UAT:** Copying `4111 1111 1111 1111` produces a new line in `C:\ProgramData\DLP\logs\audit.jsonl` within 2 seconds with `event_type=Alert`, `classification=T4`, `action_attempted=PASTE`. **Verified 2026-04-10.**
**Commits:** `c038173`, `6244ac1`, `62be9ef`

### Phase 1: Fix integration tests [COMPLETED]
**Requirement:** R-06
**Status:** Resolved — see `.planning/phases/01-fix-integration-tests/SUMMARY.md`
**Files:** `dlp-agent/tests/integration.rs`, `dlp-agent/tests/comprehensive.rs`, `dlp-agent/Cargo.toml`
**Description:** Update broken integration tests that reference removed dlp_server modules. Make `cargo test --workspace` compile cleanly.
**UAT:** `cargo test --workspace` passes with zero compilation errors. **Verified 2026-04-10** (364/364 tests passing across 15 binaries + doc tests).
**Commits:** `8c62fec`, `5d60f6a`

### Phase 2: Require JWT_SECRET in production [COMPLETED]
**Requirement:** R-08
**Status:** Resolved — see `.planning/phases/02-require-jwt-secret-in-production/SUMMARY.md`
**Files:** `dlp-server/src/admin_auth.rs`, `dlp-server/src/main.rs`
**Description:** Remove hardcoded dev fallback. Add `--dev` flag to allow insecure secret in development only. Fail on startup otherwise.
**UAT:** Server refuses to start without JWT_SECRET (no --dev flag). Server starts with --dev flag and warns. **Verified 2026-04-10** (31/31 dlp-server lib tests passing).
**Commits:** `664c528`

### Phase 3: Wire SIEM connector into server startup [COMPLETED]
**Requirement:** R-01
**Status:** Resolved — see `.planning/phases/03-wire-siem-connector-into-server-startup/SUMMARY.md`
**Files:** `dlp-server/src/lib.rs`, `dlp-server/src/main.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/src/admin_auth.rs`, `dlp-server/src/agent_registry.rs`, `dlp-server/src/audit_store.rs`, `dlp-server/src/exception_store.rs`
**Description:** Phase 3 delivered the foundation work — `AppState { db, siem }` shared axum state, handler refactor from `State<Arc<Database>>` to `State<Arc<AppState>>`, and best-effort background SIEM relay spawned after audit event DB commit. The config-loading mechanism (env vars) was **superseded the same day by Phase 3.1** (DB-backed config); see Phase 3's PLAN.md addendum.
**UAT:** Audit events ingested via `POST /audit/events` are relayed to configured backends; SIEM relay failures are logged but don't fail the ingest request. **Verified 2026-04-10** (31/31 dlp-server lib tests passing).
**Commits:** `30ccaaf`

### Phase 3.1: SIEM config in DB via dlp-admin-cli [COMPLETED]
**Requirement:** R-01
**Status:** Resolved — see `.planning/phases/03.1-siem-config-in-db/SUMMARY.md`
**Supersedes:** Phase 3 config loading mechanism (env vars → DB)
**Files:** `dlp-server/src/db.rs`, `dlp-server/src/siem_connector.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/src/main.rs`, `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
**Description:** Move SIEM connector configuration from environment variables to the SQLite `siem_config` table (single-row, CHECK-constrained, hot-reloaded on every relay). Add JWT-protected `GET/PUT /admin/siem-config` endpoints and a dedicated dlp-admin-cli TUI screen under the System menu for managing Splunk/ELK settings. **Decision:** operator-tunable config lives in DB, not env vars — same pattern will apply to Phase 4 (alert router) and Phase 6 (config push) per user directive in CONTEXT.md.
**UAT:** `siem_config` table + seed row exist; `GET/PUT /admin/siem-config` work (JWT); server hot-reloads config without restart; dlp-admin-cli TUI shows "SIEM Config" under System menu with Splunk/ELK edit and save. **Verified 2026-04-10** (31/31 dlp-server lib tests + 5/5 dlp-admin-cli tests passing).
**Commits:** `8911669`

### Phase 4: Wire alert router into server
**Requirement:** R-02
**Files:** `dlp-server/src/main.rs`, `dlp-server/src/lib.rs`, `dlp-server/src/alert_router.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/src/audit_store.rs`, `dlp-server/src/db.rs`, `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
**Description:** Wire AlertRouter into server startup and into the audit ingestion path, **and** move alert configuration from env vars to the SQLite `alert_router_config` table — mirroring Phase 3.1. JWT-protected `GET/PUT /admin/alert-config` endpoints, dlp-admin-cli TUI screen under the System menu, hot-reload on every `send_alert`. Route DenyWithAlert audit events to configured email (SMTP via lettre) and/or webhook destinations via fire-and-forget background tasks. Webhook URL is validated at PUT time (https-only, loopback/link-local blocked). See `.planning/phases/04-wire-alert-router-into-server/04-CONTEXT.md` for the full threat model and `04-PLAN.md` for the executable plan.
**UAT:** After admin sets SMTP/webhook config via dlp-admin-cli, DenyWithAlert events trigger email/webhook notifications. Settings persist in DB across restarts. Webhook URL validation rejects loopback/link-local. No HTTP-ingest latency impact (fire-and-forget).

**Plans:** 2 plans

Plans:
- [x] 04-01-PLAN.md — Server-side: DB schema + AlertRouter rewrite + admin_api handlers + validate_webhook_url + audit_store fire-and-forget spawn
- [x] 04-02-PLAN.md — dlp-admin-cli TUI: Screen::AlertConfig variant + draw_alert_config + 5-item System menu + handle_alert_config dispatch

### Phase 5: Wire policy sync for multi-replica
**Requirement:** R-03
**Files:** `dlp-server/src/main.rs`, `dlp-server/src/policy_sync.rs`, `dlp-server/src/admin_api.rs`
**Description:** Initialize PolicySyncer from env vars. Call sync on policy create/update/delete.
**UAT:** Policy changes propagate to peer servers listed in DLP_REPLICA_URLS.

### Phase 6: Wire config push for agent config distribution
**Requirement:** R-04
**Files:** `dlp-server/src/main.rs`, `dlp-server/src/config_push.rs`, `dlp-server/src/admin_api.rs`
**Description:** Add admin API endpoint for pushing config updates. Agents poll for config changes on heartbeat.
**UAT:** Admin can push updated monitored_paths via API; agent picks up changes.

### Phase 7: Active Directory LDAP integration
**Requirement:** R-05
**Depends on:** Phase 2
**Files:** `dlp-agent/src/identity.rs`, `dlp-common/src/abac.rs`, new `dlp-agent/src/ad_client.rs`
**Description:** Implement LDAP client using `ldap3` crate. Query AD for user group membership, device trust level, and network location. Replace placeholder values in ABAC evaluation requests.
**UAT:** ABAC evaluation uses real AD group membership for policy decisions.

### Phase 8: Rate limiting middleware
**Requirement:** R-07
**Files:** `dlp-server/src/main.rs`, `dlp-server/Cargo.toml`
**Description:** Add tower-governor or custom rate limiting middleware. Apply to /auth/login (strict), heartbeat (moderate), event ingestion (per-agent).
**UAT:** Rapid-fire login attempts are throttled with 429 responses.

### Phase 9: Admin operation audit logging
**Requirement:** R-09
**Files:** `dlp-server/src/admin_api.rs`, `dlp-server/src/audit_store.rs`
**Description:** Emit audit events for policy CRUD and admin password changes. Store in audit_events table with EventType::AdminAction.
**UAT:** Policy create/update/delete appear as audit events queryable via GET /audit/events.

### Phase 10: SQLite connection pool
**Requirement:** R-10
**Files:** `dlp-server/src/db.rs`, `dlp-server/Cargo.toml`
**Description:** Replace Mutex<Connection> with r2d2-sqlite connection pool. Update all handlers to use pool.get() instead of conn().lock().
**UAT:** Concurrent API requests execute without serializing on a single mutex. Existing tests pass.
