# Phase 4: Wire Alert Router into Server — Context

**Gathered:** 2026-04-10
**Status:** Ready for planning
**Source:** Derived from user's prior decision "all three connectors use DB config style" + inspection of Phase 3.1 as the reference pattern + current `dlp-server/src/alert_router.rs` code.

<domain>
## Phase Boundary

Phase 4 has two coupled responsibilities that must land together:

1. **Wire AlertRouter into the server startup + audit ingestion path.** The type exists in `dlp-server/src/alert_router.rs` with full SMTP + webhook logic, but `AlertRouter::from_env()` is never constructed in `main.rs` and `AppState` has no `alert` field. No DenyWithAlert events trigger any email or webhook today — the router is dead code.

2. **Move alert config from env vars to the SQLite database**, mirroring Phase 3.1 (`03.1-siem-config-in-db`). Admins manage it via the dlp-admin-cli TUI, not by editing environment variables or restarting the server.

In scope:
- New `alert_router_config` DB table (single row, CHECK id=1, seeded)
- Rewrite `AlertRouter` to hold `Arc<Database>` and reload config on every `send_alert()` call (same hot-reload pattern as `SiemConnector::relay_events`)
- `AppState.alert: AlertRouter` field alongside `AppState.siem`
- Admin API: `GET /admin/alert-config`, `PUT /admin/alert-config` (JWT protected)
- Audit ingestion hook: after SIEM relay, for each event with `decision == Decision::DenyWithAlert`, fire-and-forget call to `alert.send_alert(event)` in a background task
- dlp-admin-cli: new `AlertConfig` Screen variant, "Alert Config" item in System menu, render/dispatch wiring, client methods
- Tests: extend `db::tests::test_tables_created`, add a seed-row test, add handler smoke tests

Out of scope (deferred):
- HMAC signing of webhook payloads (`secret` field already exists in WebhookConfig, but using it is a separate security phase)
- Rate limiting of alerts (separate Phase 8)
- Alert templates / customization
- Multiple email recipients per role
- Alternative channels (Slack, Teams, PagerDuty)
- Rotation of credentials stored in DB (future key management phase)
- Test coverage of the actual SMTP send path — existing alert_router.rs tests already cover config parsing; the new tests should cover the DB load path, not real SMTP I/O

</domain>

<decisions>
## Implementation Decisions (LOCKED)

### Pattern: mirror Phase 3.1 exactly
The user already ran Phase 3.1 (SIEM config in DB) and confirmed it works. Phase 4 is a mechanical mirror of that pattern applied to alerts. The planner should reuse structural decisions from `.planning/phases/03.1-siem-config-in-db/PLAN.md` rather than re-deriving them. Any deviation from the 3.1 pattern must be justified in the plan.

### Database schema
Single-row table with `CHECK (id = 1)`, seeded via `INSERT OR IGNORE`. Mirror `siem_config` columns structurally. Concrete fields:

```sql
CREATE TABLE IF NOT EXISTS alert_router_config (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    smtp_host         TEXT NOT NULL DEFAULT '',
    smtp_port         INTEGER NOT NULL DEFAULT 587,
    smtp_username     TEXT NOT NULL DEFAULT '',
    smtp_password     TEXT NOT NULL DEFAULT '',
    smtp_from         TEXT NOT NULL DEFAULT '',
    smtp_to           TEXT NOT NULL DEFAULT '',    -- comma-separated list, same format as SMTP_TO env var was
    smtp_enabled      INTEGER NOT NULL DEFAULT 0,
    webhook_url       TEXT NOT NULL DEFAULT '',
    webhook_secret    TEXT NOT NULL DEFAULT '',
    webhook_enabled   INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO alert_router_config (id) VALUES (1);
```

### Hot-reload on every send
Mirror `SiemConnector::relay_events` — `AlertRouter::send_alert` calls a private `load_config()` that SELECTs the row every time. No caching. Admins change settings in the TUI and the next alert picks them up without restart. This is consistent with Phase 3.1 and is the same trade-off: one extra cheap SQLite SELECT per alert (alerts are rare) for zero config-staleness risk.

### Struct rewrite
Replace:
```rust
pub struct AlertRouter {
    smtp: Option<SmtpConfig>,
    webhook: Option<WebhookConfig>,
    client: Client,
}
```
with:
```rust
pub struct AlertRouter {
    db: Arc<Database>,
    client: Client,
}
```
Add an internal `AlertRouterConfigRow` struct for the SELECT result. Derive effective `Option<SmtpConfig>` / `Option<WebhookConfig>` from the row inside `send_alert`, only returning Some if the `*_enabled` flag is 1 AND the required URL/host fields are non-empty. This keeps the existing `send_email` / `send_webhook` private helpers untouched — they still take `&SmtpConfig` / `&WebhookConfig`.

### `from_env()` removal
Delete `AlertRouter::from_env()` entirely. Delete `load_smtp_config()` / `load_webhook_config()`. Delete the `test_from_env_no_vars` unit test. Add a new test `test_alert_router_disabled_when_both_off` that constructs `AlertRouter::new(Arc::new(Database::open_in_memory()?))` with the default seed row (both enabled=0) and asserts `send_alert(...)` returns `Ok(())` without attempting network I/O.

### Audit-ingestion hook
In `dlp-server/src/audit_store.rs::ingest_events`, add a second background `tokio::spawn` AFTER the existing SIEM relay spawn:

```rust
let alert = state.alert.clone();
let alert_events: Vec<AuditEvent> = events
    .iter()
    .filter(|e| matches!(e.decision, dlp_common::Decision::DenyWithAlert))
    .cloned()
    .collect();
if !alert_events.is_empty() {
    tokio::spawn(async move {
        for event in alert_events {
            if let Err(e) = alert.send_alert(&event).await {
                tracing::warn!(error = %e, "alert delivery failed (best-effort)");
            }
        }
    });
}
```

Fire-and-forget, same pattern as SIEM relay. Must never delay the HTTP response. Filter to only `DenyWithAlert` decisions — do NOT alert on `Deny` or `AllowWithLog`.

### AppState extension
Add a field:
```rust
pub struct AppState {
    pub db: Arc<db::Database>,
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,   // NEW
}
```
`AlertRouter` must derive `Clone` (it already does). Constructed in `main.rs` via `AlertRouter::new(Arc::clone(&db))`.

### Admin API surface
Exactly mirror Phase 3.1's SIEM admin routes:
- `GET /admin/alert-config` — JWT protected — returns `AlertRouterConfigPayload` JSON
- `PUT /admin/alert-config` — JWT protected — accepts `AlertRouterConfigPayload` JSON, UPDATEs row, returns 200

`AlertRouterConfigPayload` struct is public in `admin_api.rs`, has 11 fields matching the DB schema (excluding `id` and `updated_at`), derives `Debug, Clone, Serialize, Deserialize, PartialEq`. Handlers use `spawn_blocking` for SQLite access. Update the route doc-comment table in `admin_api.rs` if one exists.

### Secret handling in TUI
`smtp_password` and `webhook_secret` are SECRETS. In the TUI render:
- Display as `*****` when NOT in edit mode, regardless of length
- Show the full buffer when the user is actively editing that field
- Never log the value via `tracing::info!` — only log whether the field is empty/non-empty
- `GET /admin/alert-config` returns the real value (admin already has JWT, DB access is already privileged); do not mask server-side

This matches what Phase 3.1 did for `splunk_token` / `elk_api_key`.

### dlp-admin-cli screen
Mirror Phase 3.1's `SiemConfig` screen structure. New `Screen::AlertConfig` variant with the same shape (config, selected, editing, buffer). 11 editable fields + Save + Back = 13 rows.

Field order (must match the render order for predictable navigation):
1. SMTP host
2. SMTP port (integer — validate on save, not on edit)
3. SMTP username
4. SMTP password (masked)
5. SMTP from
6. SMTP to (comma-separated)
7. SMTP enabled (bool, toggle on Enter)
8. Webhook URL
9. Webhook secret (masked)
10. Webhook enabled (bool, toggle on Enter)
11. [Save]
12. [Back]

Add an "Alert Config" item to the System menu AFTER "SIEM Config". New order: Server Status, Agent List, SIEM Config, Alert Config, Back.

### Claude's Discretion (decisions the planner makes)
- Exact handler function names and module layout — follow the Phase 3.1 naming style (`get_alert_config_handler`, `update_alert_config_handler`, `load_config`, `AlertRouterConfigRow`).
- Exact wording of tracing log messages at INFO / WARN level.
- Exact wording of TUI footer hints and status messages — match Phase 3.1 style.
- Whether to add a single inserting test `test_alert_config_seed_row` or reuse the existing `test_tables_created`-style assertion. Recommendation: add the explicit seed test.
- How port is validated (u16 vs i64 with cast) — mirror Phase 3.1 if it has precedent; otherwise store as `INTEGER NOT NULL DEFAULT 587` and parse as u16 in the row loader, returning a helpful error if out of range.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Reference implementation — Phase 3.1 (mirror this)
- `.planning/phases/03.1-siem-config-in-db/PLAN.md` — the structural template. Phase 4 is this plan with `siem_config` replaced by `alert_router_config` and different column names.
- `.planning/phases/03.1-siem-config-in-db/CONTEXT.md` — decisions from the 3.1 discuss round, many of which apply verbatim to Phase 4.

### Current code to modify
- `dlp-server/src/alert_router.rs` — rewrite `AlertRouter` struct + constructor + helpers. Keep the private `send_email` / `send_webhook` bodies.
- `dlp-server/src/audit_store.rs` lines 140-154 — add the alert routing background spawn after the SIEM relay spawn.
- `dlp-server/src/lib.rs` lines 27-32 — add `pub alert` field to `AppState`.
- `dlp-server/src/main.rs` — construct `AlertRouter::new(Arc::clone(&db))` and include in `AppState`.
- `dlp-server/src/admin_api.rs` — add `AlertRouterConfigPayload`, two handlers, two routes.
- `dlp-server/src/db.rs` — add `alert_router_config` table schema + seed + table-creation test.
- `dlp-admin-cli/src/client.rs` — add `get_alert_config()` and `update_alert_config()` methods.
- `dlp-admin-cli/src/app.rs` — add `Screen::AlertConfig` variant.
- `dlp-admin-cli/src/screens/render.rs` — add `draw_alert_config` function.
- `dlp-admin-cli/src/screens/dispatch.rs` — extend System menu, add load/save actions, add key handler.

### Project conventions
- `CLAUDE.md` §9 — Rust Coding Standards. Notably: no `.unwrap()` in production paths, `thiserror` for errors, `tracing` for logs (not println), 100-char lines, 4-space indent, no emoji, derive `Debug, Clone, PartialEq` where appropriate.
- `.planning/REQUIREMENTS.md` — R-02 is the requirement this phase satisfies ("Route DenyWithAlert audit events to configured email/webhook destinations").

### Threat model inputs (MANDATORY for Phase 4 PLAN.md — security gate is enabled)
- SMTP credentials stored in SQLite — consider whether `smtp_password` should be encrypted at rest. SIEM Phase 3.1 stored `splunk_token` and `elk_api_key` in plaintext under the same DB ACL rationale; Phase 4 should be consistent and cite that precedent. If the planner believes encryption is justified, it should propose it explicitly; otherwise the plan should document the accepted residual risk.
- Webhook URL could be user-controlled SSRF vector — `AlertRouter` posts JSON to whatever URL is in the DB. Document that only an authenticated DLP admin can set this, and the DB is a trusted boundary.
- Email body includes full audit event JSON which may contain PII or file paths — document that alerts go to ADMIN mailboxes only by policy, and the DB config is the only place to set recipients.
- Fire-and-forget alert spawn means delivery failures are invisible to the client — acceptable; the tracing::warn log is the observability surface.

</canonical_refs>

<specifics>
## Specific Details

- **R-02 is the requirement.** PLAN.md must cite it.
- **Response time:** alerts should not add ANY latency to the `POST /audit/events` HTTP response. Use `tokio::spawn`, not `.await`, for every alert send.
- **Enabled flag semantics:** `smtp_enabled = 1 AND smtp_host != "" AND smtp_to != ""` → SMTP is active. Webhook parallel: `webhook_enabled = 1 AND webhook_url != ""` → webhook is active. Both can be active simultaneously; neither needs to be active for `send_alert` to return Ok (it just does nothing).
- **Tests required:**
  - `db::tests` — assert `alert_router_config` table exists, assert seed row present
  - `alert_router::tests` — `test_alert_router_disabled_default` constructs from an in-memory DB and calls `send_alert`, expects Ok with no I/O
  - `admin_api::tests` — `test_alert_router_config_payload_roundtrip` for JSON serde
  - Existing tests that constructed `AlertRouter { smtp: None, webhook: None, client: ... }` directly must be updated to use `AlertRouter::new(Arc::new(Database::open_in_memory()?))`

</specifics>

<deferred>
## Deferred Ideas

- **HMAC signing of webhook payloads** using `webhook_secret`. The field exists and can be stored, but the `send_webhook` implementation doesn't sign anything today. Leave it untouched for Phase 4. Plant a todo for a future security phase.
- **Rate limiting of alerts** — prevent alert floods during mass DenyWithAlert events. Belongs to Phase 8 (rate limiting middleware) or its own phase.
- **Alert acknowledgment / escalation** — tracking whether admins read/responded to alerts. New capability, out of scope.
- **Encryption of `smtp_password` at rest in SQLite** — matches the same decision Phase 3.1 deferred. Belongs to a dedicated key-management phase.
- **Test the actual SMTP send path** against a mock server (lettre has a `file` transport for tests). Consider for a later test-hardening phase.

</deferred>

---

*Phase: 04-wire-alert-router-into-server*
*Context gathered: 2026-04-10 (inline, derived from prior user decision + Phase 3.1 reference pattern)*
