# Phase 4: Wire Alert Router into Server — Research

**Researched:** 2026-04-10
**Domain:** Rust / axum / rusqlite / lettre / reqwest — internal pattern replication
**Confidence:** HIGH (all claims verified against codebase)
**Scope note:** This is a **pattern-replication** phase. The canonical template is already implemented in
the repository (Phase 3.1 SIEM config in DB). Research is not open-ended — it is a mechanical
extraction of the 3.1 shapes so the planner can write tasks that copy them verbatim.

## Summary

Phase 4 mirrors Phase 3.1 exactly. Phase 3.1's code is live in `dlp-server/src/siem_connector.rs`,
`dlp-server/src/db.rs::init_tables`, `dlp-server/src/admin_api.rs` (SIEM handlers + payload), and the
`dlp-admin-cli` SIEM config screen. Phase 4 replicates each of those shapes for `AlertRouter` plus
adds one extra deliverable Phase 3.1 did not need: `validate_webhook_url` (TM-02 SSRF hardening).
All four threat-model decisions (TM-01..TM-04) are locked in `04-CONTEXT.md` and not open for
re-litigation.

The existing `AlertRouter` in `dlp-server/src/alert_router.rs` already contains a working `send_email`
(lettre STARTTLS) and `send_webhook` (reqwest POST). These bodies are KEPT as-is. Only the struct,
constructor, and config-load path are rewritten to read from SQLite instead of env vars.

**Primary recommendation:** Treat the 3.1 files as canonical templates. Each Phase 4 task is
"copy 3.1 file X, rename `siem` → `alert`, substitute column names, delete env-var code paths,
add `validate_webhook_url` at PUT time." Do not introduce new crates, new observability, or new
validation strategies.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Pattern: mirror Phase 3.1 exactly.** Phase 4 is a mechanical mirror of Phase 3.1
(`.planning/phases/03.1-siem-config-in-db/`) applied to alerts. Any deviation from the 3.1 pattern
must be justified in the plan.

**Database schema.** Single-row `alert_router_config` table, `CHECK (id = 1)`, seeded via
`INSERT OR IGNORE`. Columns:
```sql
CREATE TABLE IF NOT EXISTS alert_router_config (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    smtp_host         TEXT NOT NULL DEFAULT '',
    smtp_port         INTEGER NOT NULL DEFAULT 587,
    smtp_username     TEXT NOT NULL DEFAULT '',
    smtp_password     TEXT NOT NULL DEFAULT '',
    smtp_from         TEXT NOT NULL DEFAULT '',
    smtp_to           TEXT NOT NULL DEFAULT '',
    smtp_enabled      INTEGER NOT NULL DEFAULT 0,
    webhook_url       TEXT NOT NULL DEFAULT '',
    webhook_secret    TEXT NOT NULL DEFAULT '',
    webhook_enabled   INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO alert_router_config (id) VALUES (1);
```

**Hot-reload on every send.** `AlertRouter::send_alert` calls a private `load_config()` that
SELECTs the row on every invocation (same pattern as `SiemConnector::relay_events`). No caching.

**Struct rewrite.** Replace the current `AlertRouter { smtp: Option<SmtpConfig>, webhook:
Option<WebhookConfig>, client: Client }` with `AlertRouter { db: Arc<Database>, client: Client }`.
Keep `send_email` / `send_webhook` private helper bodies untouched. Derive effective `SmtpConfig` /
`WebhookConfig` from the row inside `send_alert`, only constructing them if the `*_enabled` flag is
1 AND required fields are non-empty.

**`from_env()` removal.** Delete `AlertRouter::from_env()`, `load_smtp_config()`,
`load_webhook_config()`, and the `test_from_env_no_vars` unit test.

**Audit-ingestion hook.** In `dlp-server/src/audit_store.rs::ingest_events`, add a second
background `tokio::spawn` AFTER the existing SIEM relay spawn. Filter to `DenyWithAlert` decisions
only. Fire-and-forget — must never delay the HTTP response.

**AppState extension.** Add `pub alert: alert_router::AlertRouter` field alongside `db` and `siem`.
`AlertRouter` already derives `Clone`. Constructed in `main.rs` via
`AlertRouter::new(Arc::clone(&db))`.

**Admin API surface.** `GET /admin/alert-config` and `PUT /admin/alert-config`, both JWT-protected,
mirror Phase 3.1 SIEM handlers. `AlertRouterConfigPayload` public struct in `admin_api.rs` with 11
fields (DB schema minus `id` and `updated_at`). Handlers use `spawn_blocking` for SQLite access.

**Secret handling in TUI.** `smtp_password` and `webhook_secret` are masked as `*****` outside edit
mode. Full value shown while actively editing. Never log via `tracing::info!`. `GET` returns real
value (admin already has JWT — same as `splunk_token` in 3.1).

**dlp-admin-cli screen.** `Screen::AlertConfig` variant mirrors `Screen::SiemConfig` shape. 11
editable fields + Save + Back = 13 rows. Field order:
1. SMTP host, 2. SMTP port, 3. SMTP username, 4. SMTP password (masked), 5. SMTP from,
6. SMTP to, 7. SMTP enabled (bool), 8. Webhook URL, 9. Webhook secret (masked),
10. Webhook enabled (bool), 11. [Save], 12. [Back]

"Alert Config" added to System menu after "SIEM Config". New order: Server Status, Agent List,
SIEM Config, Alert Config, Back.

**Threat-model ratifications:**
- **TM-01 (SMTP password storage):** Plaintext in SQLite, same as `splunk_token` in 3.1. Document
  residual risk in PLAN.md Threat Model section. No new crypto dependency. Encryption-at-rest for
  all secret columns deferred to a future key-management phase.
- **TM-02 (Webhook SSRF):** `PUT /admin/alert-config` MUST call `validate_webhook_url(url: &str)
  -> Result<(), String>` before accepting the update. Rules: `scheme == "https"`, reject loopback
  (127.0.0.0/8, ::1), reject link-local (169.254.0.0/16, fe80::/10), ALLOW RFC1918
  (10/8, 172.16/12, 192.168/16). Textual-only (no DNS). Empty string is permitted (disables
  webhook). Table-driven unit tests. Error message format: `"webhook_url rejected: {reason}"`.
  Returns HTTP 400 on failure.
- **TM-03 (Email body PII):** `send_email` serializes `AuditEvent` as-is. `AuditEvent` has no
  content-snippet fields today (verified). PLAN.md MUST include a forward-compatible code-review
  rule: any future phase adding a content/sample/preview/matched_text/snippet/body/raw/
  payload_content/clipboard_text/file_excerpt/plaintext field to `AuditEvent` MUST update
  `send_email` in the same phase.
- **TM-04 (Observability):** `tracing::warn!` only. NO metrics, NO counters, NO admin-status
  endpoints, NO Server Status line, NO audit-event backchannel. Exact messages:
  `tracing::warn!(error = %e, "alert email delivery failed (best-effort)")` and
  `tracing::warn!(error = %e, "alert webhook delivery failed (best-effort)")`.

### Claude's Discretion
- Exact handler function names (follow Phase 3.1 style: `get_alert_config_handler`,
  `update_alert_config_handler`, `load_config`, `AlertRouterConfigRow`).
- Exact tracing INFO / WARN message wording (except TM-04 WARN messages which are locked).
- TUI footer hints and status messages — match Phase 3.1 style.
- Whether to add a dedicated `test_alert_config_seed_row` or reuse `test_tables_created` style.
  **Recommendation: add the explicit seed test.**
- SMTP port validation style (u16 vs i64 with cast). **Recommendation:** store as
  `INTEGER NOT NULL DEFAULT 587`, parse as `u16` in the row loader with a helpful error on
  out-of-range.

### Deferred Ideas (OUT OF SCOPE)
- HMAC signing of webhook payloads using `webhook_secret`.
- Rate limiting of alerts.
- Alert acknowledgment / escalation.
- Encryption-at-rest for DB secret columns (key-management phase).
- Mock-SMTP test path.
- Alert delivery metrics / counters / dashboards.
- DNS-based `webhook_url` validation.
- `http://` webhook support with a `--dev` flag.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| R-02 | Route DenyWithAlert audit events to configured email/webhook destinations. Hot-reload on every send. Webhook URL validated at PUT time (https-only, loopback/link-local blocked). | Phase 3.1 SIEM connector provides the hot-reload pattern (`load_config` per relay call). Existing `send_email`/`send_webhook` helpers in `alert_router.rs` provide the delivery mechanics. `audit_store::ingest_events` has an established fire-and-forget spawn pattern at lines 143-150 that Phase 4 replicates. `url` crate is transitively available via reqwest for `validate_webhook_url`. |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

| # | Directive | How it applies to Phase 4 |
|---|-----------|---------------------------|
| 1 | No `.unwrap()` in production paths — use `.expect()` only for invariant violations with descriptive message | Row-loader conversions (e.g., `u16` parse from `i64` port), `load_config` SELECT, validate_webhook_url: all must return `Result`. |
| 2 | Use `thiserror` for custom error types | Keep existing `AlertError` enum; do not introduce `anyhow::Error` inside library code. |
| 3 | Use `tracing` (not `println!` / `log::`) | All log sites must be `tracing::warn!` / `tracing::info!` macros with structured fields. |
| 4 | 4-space indent, `snake_case` functions, `PascalCase` types | Applies verbatim. |
| 5 | 100-char line limit | Applies to all new code. |
| 6 | Doc comments on all public items | `AlertRouterConfigPayload`, `AlertRouter::new`, `AlertRouter::send_alert`, `validate_webhook_url`, `Screen::AlertConfig`. |
| 7 | No emoji / unicode emoji emulation | Applies to tracing messages, TUI labels, doc comments. |
| 8 | No secrets logged | TUI render and tracing sites MUST NOT log `smtp_password` / `webhook_secret` values — log only "empty" vs "present". |
| 9 | `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `sonar-scanner` gates before commit | Standard pre-commit checklist applies. |
| 10 | `#[derive(Debug, Clone, PartialEq)]` where appropriate | `AlertRouterConfigPayload` gets `Debug, Clone, Serialize, Deserialize, PartialEq`. |
| 11 | Prefer borrowing over ownership | `validate_webhook_url(&str)`, `send_alert(&self, event: &AuditEvent)`. |

## Phase 3.1 Pattern Reference (the template)

### DB schema DDL (copied verbatim from `dlp-server/src/db.rs:129-140`)

```sql
CREATE TABLE IF NOT EXISTS siem_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    splunk_url      TEXT NOT NULL DEFAULT '',
    splunk_token    TEXT NOT NULL DEFAULT '',
    splunk_enabled  INTEGER NOT NULL DEFAULT 0,
    elk_url         TEXT NOT NULL DEFAULT '',
    elk_index       TEXT NOT NULL DEFAULT '',
    elk_api_key     TEXT NOT NULL DEFAULT '',
    elk_enabled     INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO siem_config (id) VALUES (1);
```

**Notes the planner needs:**
- The SIEM DDL is appended inside the single `conn.execute_batch(...)` call in
  `Database::init_tables()` (`dlp-server/src/db.rs:61-146`). Phase 4 appends its DDL as another
  block inside the same `execute_batch` string, right after the `siem_config` block. Keep both
  `CREATE TABLE` and `INSERT OR IGNORE` inside the same batch.
- Seed-row test lives in `dlp-server/src/db.rs::tests::test_tables_created` (lines 160-190). It
  (1) asserts the table appears in `sqlite_master`, and (2) does a
  `SELECT COUNT(*) FROM siem_config` assertion equal to 1. Phase 4 adds parallel assertions for
  `alert_router_config`.
- `INTEGER` boolean convention: store as `i64` in SQLite, convert with `r.get::<_, i64>(n)? != 0`
  on read (see `siem_connector.rs:123`, `admin_api.rs:549`), and with `bool as i64` on write
  (see `admin_api.rs:588`).
- **Phase 4's `smtp_port` column:** store as `INTEGER NOT NULL DEFAULT 587`. Read as `i64` then
  `u16::try_from(port_i64).map_err(|_| AlertError::Config(format!("smtp_port out of range: {port_i64}")))`.

### `admin_api.rs` pattern for SIEM GET/PUT (the structural template Phase 4 mirrors)

**Payload struct** (lines 94-115):
```rust
/// Read/write payload for SIEM connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfigPayload {
    pub splunk_url: String,
    pub splunk_token: String,
    pub splunk_enabled: bool,
    pub elk_url: String,
    pub elk_index: String,
    pub elk_api_key: String,
    pub elk_enabled: bool,
}
```
Note: Phase 3.1 did NOT derive `PartialEq` on the payload. CONTEXT.md locks Phase 4 to derive
`PartialEq` — planner should note this as a minor pattern deviation and justify it as enabling
round-trip assertion tests.

**Route registration** (lines 191-192):
```rust
.route("/admin/siem-config", get(get_siem_config_handler))
.route("/admin/siem-config", put(update_siem_config_handler))
```
Both live in the `protected_routes` sub-router that has
`.layer(middleware::from_fn(admin_auth::require_auth))` applied at line 193. Phase 4 adds two
sibling routes in the same `protected_routes` builder.

**GET handler** (`get_siem_config_handler`, lines 534-562):
```rust
async fn get_siem_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let db = Arc::clone(&state.db);
    let payload = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.query_row(
            "SELECT splunk_url, splunk_token, splunk_enabled, \
                    elk_url, elk_index, elk_api_key, elk_enabled \
             FROM siem_config WHERE id = 1",
            [],
            |row| { Ok(SiemConfigPayload { /* field mapping */ }) },
        )
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    Ok(Json(payload))
}
```

**PUT handler** (`update_siem_config_handler`, lines 569-603):
```rust
async fn update_siem_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SiemConfigPayload>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let db = Arc::clone(&state.db);

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = db.conn().lock();
        conn.execute(
            "UPDATE siem_config SET \
                splunk_url = ?1, splunk_token = ?2, splunk_enabled = ?3, \
                elk_url = ?4, elk_index = ?5, elk_api_key = ?6, \
                elk_enabled = ?7, updated_at = ?8 \
             WHERE id = 1",
            rusqlite::params![
                p.splunk_url, p.splunk_token, p.splunk_enabled as i64,
                p.elk_url, p.elk_index, p.elk_api_key,
                p.elk_enabled as i64, now,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("SIEM config updated");
    Ok(Json(payload))
}
```

**Phase 4 divergence — TM-02 SSRF check must be the FIRST thing in the PUT handler, BEFORE the
`spawn_blocking` call:**
```rust
async fn update_alert_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AlertRouterConfigPayload>,
) -> Result<Json<AlertRouterConfigPayload>, AppError> {
    // TM-02: validate webhook_url before accepting. Empty string is allowed
    // (means webhook delivery is disabled).
    if !payload.webhook_url.is_empty() {
        validate_webhook_url(&payload.webhook_url)
            .map_err(|reason| AppError::BadRequest(format!("webhook_url rejected: {reason}")))?;
    }
    // ... rest mirrors update_siem_config_handler
}
```

**Existing SIEM payload test** (`test_siem_config_payload_roundtrip`, lines 654-671) — Phase 4
clones this for `test_alert_router_config_payload_roundtrip`.

**Doc-comment route table:** `admin_router` has a big doc comment at lines 130-163 listing every
route. Phase 4 adds two new lines under the "Authenticated" section:
```
/// - `GET /admin/alert-config` — get alert router configuration
/// - `PUT /admin/alert-config` — update alert router configuration
```

### `audit_store.rs` fire-and-forget spawn (the sibling-spawn template)

**File:** `dlp-server/src/audit_store.rs`
**Existing SIEM spawn:** lines 143-150 (immediately after the `spawn_blocking` DB write completes,
just before the final `tracing::info!` + `Ok(StatusCode::CREATED)` return).

Existing code (exact):
```rust
    // Best-effort SIEM relay — fire-and-forget in a background task
    // so the HTTP response is not delayed by external SIEM latency.
    let siem = state.siem.clone();
    tokio::spawn(async move {
        if let Err(e) = siem.relay_events(&relay_events).await {
            tracing::warn!(error = %e, "SIEM relay failed (best-effort)");
        }
    });

    tracing::info!(count, "ingested audit events");
    Ok(StatusCode::CREATED)
```

**Phase 4 insertion point:** immediately after line 150 (after the closing `});` of the SIEM
spawn, before the `tracing::info!(count, "ingested audit events");` line). Use `relay_events`
(already cloned at line 77 as `let relay_events = events.clone();`) — no second clone needed
because `relay_events` is consumed by `.iter()` into a filtered `Vec`.

Planner pseudo-code for the new sibling spawn (follows TM-04's exact warn! format):
```rust
    // Best-effort alert routing — fire-and-forget, filters to DenyWithAlert only.
    let alert = state.alert.clone();
    let alert_events: Vec<AuditEvent> = relay_events
        .iter()
        .filter(|e| matches!(e.decision, dlp_common::Decision::DenyWithAlert))
        .cloned()
        .collect();
    if !alert_events.is_empty() {
        tokio::spawn(async move {
            for event in alert_events {
                if let Err(e) = alert.send_alert(&event).await {
                    // NOTE: alert_router itself logs per-channel warn! messages
                    // (see TM-04). This catches the outer error path only.
                    tracing::warn!(error = %e, "alert delivery failed (best-effort)");
                }
            }
        });
    }
```

**Critical ordering note:** `relay_events` must still be alive at this point. The existing SIEM
spawn at line 145 does `let siem = state.siem.clone();` then `tokio::spawn(async move { ...
siem.relay_events(&relay_events).await })`. The `relay_events` value is moved into the SIEM async
closure. **The new alert spawn MUST be constructed BEFORE the SIEM spawn** (or else the planner
must introduce a second clone: `let relay_events_for_alerts = relay_events.clone();`). Recommended
approach: the planner inserts the alert filtering + spawn **before** the existing SIEM spawn, so
both async blocks can co-exist. Alternatively, do `let alert_events: Vec<_> = relay_events.iter()
.filter(...).cloned().collect();` before the SIEM spawn, and then only the filtered
`alert_events` is moved into the alert async block while `relay_events` is moved into the SIEM
async block.

**Planner guidance — recommended layout:**
```rust
    // 1. Filter alert-eligible events out of relay_events first (cloning only what's needed).
    let alert_events: Vec<AuditEvent> = relay_events
        .iter()
        .filter(|e| matches!(e.decision, dlp_common::Decision::DenyWithAlert))
        .cloned()
        .collect();

    // 2. Existing SIEM spawn — consumes relay_events.
    let siem = state.siem.clone();
    tokio::spawn(async move {
        if let Err(e) = siem.relay_events(&relay_events).await {
            tracing::warn!(error = %e, "SIEM relay failed (best-effort)");
        }
    });

    // 3. New alert spawn — consumes alert_events.
    if !alert_events.is_empty() {
        let alert = state.alert.clone();
        tokio::spawn(async move {
            for event in alert_events {
                if let Err(e) = alert.send_alert(&event).await {
                    tracing::warn!(error = %e, "alert delivery failed (best-effort)");
                }
            }
        });
    }
```

### `dlp-admin-cli` TUI Screen / draw / dispatch pattern

**Screen variant** (`dlp-admin-cli/src/app.rs:104-119`):
```rust
/// SIEM connector configuration form.
///
/// Navigable list of 9 rows (7 editable fields + Save + Back). When
/// `editing` is true, keystrokes append to `buffer`; Enter commits
/// the buffer into the selected field of `config`.
SiemConfig {
    /// Currently loaded config as a JSON object.
    config: serde_json::Value,
    /// Index of the selected row (0..=8).
    selected: usize,
    /// Whether the selected text field is in edit mode.
    editing: bool,
    /// Buffered input while editing.
    buffer: String,
},
```

Phase 4 adds a structurally identical `AlertConfig` variant. Row range becomes `0..=12`
(13 rows total: 11 editable + Save + Back).

**System menu rendering** (`dlp-admin-cli/src/screens/render.rs:66-74`):
```rust
Screen::SystemMenu { selected } => {
    draw_menu(
        frame,
        area,
        "System",
        &["Server Status", "Agent List", "SIEM Config", "Back"],
        *selected,
    );
}
```
Phase 4 adds `"Alert Config"` between `"SIEM Config"` and `"Back"`. New array:
`&["Server Status", "Agent List", "SIEM Config", "Alert Config", "Back"]` (5 items).

**System menu dispatch** (`dlp-admin-cli/src/screens/dispatch.rs:167-184`):
```rust
fn handle_system_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::SystemMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 4, key.code),
        KeyCode::Enter => match *selected {
            0 => action_server_status(app),
            1 => action_agent_list(app),
            2 => action_load_siem_config(app),
            3 => app.screen = Screen::MainMenu { selected: 2 },
            _ => {}
        },
        KeyCode::Esc => app.screen = Screen::MainMenu { selected: 2 },
        _ => {}
    }
}
```
Phase 4 changes: `nav(selected, 4, ...)` → `nav(selected, 5, ...)`; insert
`3 => action_load_alert_config(app),`; shift Back to `4`.

**SIEM screen constants** (`dispatch.rs:613-634`):
```rust
const SIEM_KEYS: [&str; 7] = [
    "splunk_url", "splunk_token", "splunk_enabled",
    "elk_url", "elk_index", "elk_api_key", "elk_enabled",
];
const SIEM_SAVE_ROW: usize = 7;
const SIEM_BACK_ROW: usize = 8;
const SIEM_ROW_COUNT: usize = 9;
fn siem_is_bool(index: usize) -> bool { matches!(index, 2 | 6) }
```

Phase 4 clones these as:
```rust
const ALERT_KEYS: [&str; 11] = [
    "smtp_host", "smtp_port", "smtp_username", "smtp_password",
    "smtp_from", "smtp_to", "smtp_enabled",
    "webhook_url", "webhook_secret", "webhook_enabled",
    // NOTE: only 10 editable data keys — the 11th slot is intentionally
    // unused if you preserve 11 editable rows. Recommendation: use 10
    // editable rows and make ALERT_KEYS length 10, aligning with CONTEXT.md
    // field order items 1-10.
];
```

**Clarification:** CONTEXT.md field order lists 10 editable data fields (items 1-10) + Save (11) +
Back (12). The "11 editable fields" phrase in CONTEXT.md's "Admin API surface" section refers to
the JSON payload which has 11 fields = 10 DB columns minus `id`/`updated_at` PLUS the `smtp_port`
counted as its own editable row. Count is actually **10 editable rows + Save + Back = 12 total rows**.
Planner should use:
```rust
const ALERT_KEYS: [&str; 10] = [
    "smtp_host", "smtp_port", "smtp_username", "smtp_password",
    "smtp_from", "smtp_to", "smtp_enabled",
    "webhook_url", "webhook_secret", "webhook_enabled",
];
const ALERT_SAVE_ROW: usize = 10;
const ALERT_BACK_ROW: usize = 11;
const ALERT_ROW_COUNT: usize = 12;
fn alert_is_bool(index: usize) -> bool { matches!(index, 6 | 9) }   // smtp_enabled, webhook_enabled
fn alert_is_secret(index: usize) -> bool { matches!(index, 3 | 8) } // smtp_password, webhook_secret
fn alert_is_numeric(index: usize) -> bool { matches!(index, 1) }    // smtp_port
```
**Planner must surface this row-count reconciliation in PLAN.md so the CONTEXT.md "11 editable
fields" phrasing is not a blocker.** The correct count is 10 editable, matching the 10 user-facing
DB columns.

**SIEM label array** (`render.rs:116-126`):
```rust
const SIEM_FIELD_LABELS: [&str; 9] = [
    "Splunk URL", "Splunk Token", "Splunk Enabled",
    "ELK URL", "ELK Index", "ELK API Key", "ELK Enabled",
    "[ Save ]", "[ Back ]",
];
fn is_siem_secret(index: usize) -> bool { matches!(index, 1 | 5) }
fn is_siem_bool(index: usize) -> bool { matches!(index, 2 | 6) }
```

Phase 4 parallel:
```rust
const ALERT_FIELD_LABELS: [&str; 12] = [
    "SMTP Host", "SMTP Port", "SMTP Username", "SMTP Password",
    "SMTP From", "SMTP To", "SMTP Enabled",
    "Webhook URL", "Webhook Secret", "Webhook Enabled",
    "[ Save ]", "[ Back ]",
];
```

**`draw_siem_config`** (`render.rs:140-220`) — Phase 4's `draw_alert_config` has the same shape.
Secret rendering (lines 173-180):
```rust
} else if is_siem_secret(i) {
    let v = config[key].as_str().unwrap_or("");
    if v.is_empty() { "(empty)".to_string() } else { "*****".to_string() }
}
```
Phase 4 mirrors this for `smtp_password` (row 3) and `webhook_secret` (row 8).

**SMTP port special-case:** Row 1 stores an integer. In JSON the TUI stores it as a
`serde_json::Value::Number`. Read as `config["smtp_port"].as_i64().unwrap_or(587).to_string()`.
On commit from edit buffer, parse `buffer.parse::<u16>()` and set as `Number`. **Planner MUST
include a non-panicking validation branch that sets a status-bar error and stays in edit mode if
the parse fails.** This is the one deviation from the 3.1 pattern — SIEM config has no numeric
fields.

**SIEM dispatch entry point** (`dispatch.rs:25`): `Screen::SiemConfig { .. } => handle_siem_config(app, key),`
**Router match** (`dispatch.rs:19-28`): the `match &app.screen` statement that dispatches to
per-screen handlers. Phase 4 adds one arm: `Screen::AlertConfig { .. } => handle_alert_config(app, key),`.

**SIEM action handlers** (`dispatch.rs:639-772`):
- `action_load_siem_config(app: &mut App)` — calls
  `app.client.get::<serde_json::Value>("admin/siem-config")` via
  `app.rt.block_on(...)` and switches to `Screen::SiemConfig`. Phase 4 clones to
  `action_load_alert_config` calling `admin/alert-config`.
- `action_save_siem_config(app: &mut App)` — clones the in-memory config, calls
  `app.client.put::<serde_json::Value, _>("admin/siem-config", &payload)`, returns to
  `Screen::SystemMenu { selected: 2 }` on success.  Phase 4 clones to `action_save_alert_config`
  targeting `admin/alert-config` and returning to `Screen::SystemMenu { selected: 3 }`.
- `handle_siem_config` / `handle_siem_config_editing` / `handle_siem_config_nav` —
  lines 676-772. Phase 4 clones all three with the `_alert_` suffix and swaps in the ALERT_*
  constants.

**Return-to-System-menu index:** Existing SIEM config returns to `Screen::SystemMenu { selected: 2 }`
(SIEM Config's index in the original 4-item menu). After Phase 4 adds "Alert Config" at index 3,
the menu becomes 5 items and the SIEM Config index stays at 2. So SIEM's return index is unchanged;
Alert Config's return index is **3**.

**No typed client.rs helpers exist for SIEM config.** `dlp-admin-cli/src/client.rs` has only
generic `get<T>`, `post<T,B>`, `put<T,B>`, `delete`. The SIEM config screen calls these directly
with `serde_json::Value` as the type parameter. Phase 4 does NOT need to add typed helpers — it
reuses the same generic flow. **This is a direct contradiction to CONTEXT.md's Canonical
References line "`dlp-admin-cli/src/client.rs` — add `get_alert_config()` and
`update_alert_config()` methods."** The planner should follow the actual Phase 3.1 pattern
(generic `get`/`put` with `serde_json::Value`), not CONTEXT.md's line. Document this pattern
deviation in PLAN.md.

## Current AlertRouter State (what exists, what's deleted, what's kept)

**File:** `dlp-server/src/alert_router.rs` (277 lines total)

### KEPT (do not modify)

| Item | Lines | Notes |
|------|-------|-------|
| `pub struct SmtpConfig { host, port, username, password, from, to: Vec<String> }` | 12-27 | Fields unchanged. Still constructed by `send_alert` from the DB row. |
| `pub struct WebhookConfig { url: String, secret: Option<String> }` | 29-36 | Fields unchanged. `secret` is still unused in `send_webhook` (HMAC signing deferred). |
| `pub enum AlertError` with variants `Email(String)`, `Webhook(#[from] reqwest::Error)`, `Serialization(#[from] serde_json::Error)` | 52-66 | Unchanged. Phase 4 adds one new variant: `Database(#[from] rusqlite::Error)` — see below. |
| `fn send_email(&self, config: &SmtpConfig, event: &AuditEvent) -> Result<(), AlertError>` | 162-210 | Body unchanged. Uses lettre `AsyncSmtpTransport::<Tokio1Executor>::starttls_relay`, `Credentials::new`, `Message::builder`, serializes event via `serde_json::to_string_pretty(event)?`. TM-03 ratifies this as correct. |
| `fn send_webhook(&self, config: &WebhookConfig, event: &AuditEvent) -> Result<(), AlertError>` | 213-235 | Body unchanged. Uses `self.client.post(&config.url).header("Content-Type", "application/json").json(event).send().await?`. `webhook_secret` still not used (HMAC signing deferred). |

### DELETED (remove entirely)

| Item | Lines |
|------|-------|
| `pub fn from_env() -> Self` | 75-84 |
| `fn load_smtp_config() -> Option<SmtpConfig>` | 122-148 |
| `fn load_webhook_config() -> Option<WebhookConfig>` | 151-159 |
| `#[test] fn test_from_env_no_vars()` | 266-276 |
| The `smtp: Option<SmtpConfig>` and `webhook: Option<WebhookConfig>` fields in `AlertRouter` | 44-47 |

### REPLACED (new code)

**Struct** (replaces lines 42-50):
```rust
/// Routes real-time alerts to email and/or webhook destinations.
///
/// Construct via `AlertRouter::new(db)`. On every `send_alert` call, the
/// router re-reads the single row from the `alert_router_config` table so
/// that configuration changes made via the admin API take effect
/// immediately without restarting the server.
#[derive(Debug, Clone)]
pub struct AlertRouter {
    /// Shared database handle for reading the alert router config row.
    db: Arc<crate::db::Database>,
    /// Shared HTTP client for outbound webhook requests.
    client: Client,
}
```

**New internal row struct** (add near top):
```rust
/// Snapshot of the single `alert_router_config` row loaded from the database.
#[derive(Debug, Clone)]
struct AlertRouterConfigRow {
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    smtp_from: String,
    smtp_to: String,
    smtp_enabled: bool,
    webhook_url: String,
    webhook_secret: String,
    webhook_enabled: bool,
}
```

**Constructor** (replaces `from_env`):
```rust
impl AlertRouter {
    /// Constructs an `AlertRouter` backed by the given database.
    ///
    /// The router reads alert configuration from the `alert_router_config`
    /// table on each `send_alert` call. No caching is performed, so admin
    /// updates via the API take effect on the next alert.
    pub fn new(db: Arc<crate::db::Database>) -> Self {
        Self { db, client: Client::new() }
    }
    // ...
}
```

**New `load_config` method:**
```rust
/// Loads the current alert router configuration from the database.
///
/// # Errors
///
/// Returns [`AlertError::Database`] if the row cannot be read.
fn load_config(&self) -> Result<AlertRouterConfigRow, AlertError> {
    let conn = self.db.conn().lock();
    let row = conn.query_row(
        "SELECT smtp_host, smtp_port, smtp_username, smtp_password, \
                smtp_from, smtp_to, smtp_enabled, \
                webhook_url, webhook_secret, webhook_enabled \
         FROM alert_router_config WHERE id = 1",
        [],
        |r| {
            let port_i64: i64 = r.get(1)?;
            let smtp_port = u16::try_from(port_i64).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    format!("smtp_port out of range: {port_i64}").into(),
                )
            })?;
            Ok(AlertRouterConfigRow {
                smtp_host: r.get(0)?,
                smtp_port,
                smtp_username: r.get(2)?,
                smtp_password: r.get(3)?,
                smtp_from: r.get(4)?,
                smtp_to: r.get(5)?,
                smtp_enabled: r.get::<_, i64>(6)? != 0,
                webhook_url: r.get(7)?,
                webhook_secret: r.get(8)?,
                webhook_enabled: r.get::<_, i64>(9)? != 0,
            })
        },
    )?;
    Ok(row)
}
```

**Rewritten `send_alert`** (replaces lines 97-119 — matches SIEM's hot-reload pattern from
`siem_connector.rs:147-192`):
```rust
/// Sends an alert for a single audit event to all configured destinations.
///
/// Re-reads the alert router config from the database on each call so
/// that admin updates take effect immediately (hot-reload).
///
/// # Errors
///
/// Returns the first error encountered. Both destinations are attempted
/// even if one fails.
pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
    let row = self.load_config()?;

    let mut errors: Vec<AlertError> = Vec::new();

    // SMTP path: active iff enabled AND host non-empty AND to non-empty.
    if row.smtp_enabled && !row.smtp_host.is_empty() && !row.smtp_to.is_empty() {
        let to: Vec<String> = row
            .smtp_to
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !to.is_empty() {
            let cfg = SmtpConfig {
                host: row.smtp_host.clone(),
                port: row.smtp_port,
                username: row.smtp_username.clone(),
                password: row.smtp_password.clone(),
                from: row.smtp_from.clone(),
                to,
            };
            if let Err(e) = self.send_email(&cfg, event).await {
                tracing::warn!(error = %e, "alert email delivery failed (best-effort)");
                errors.push(e);
            }
        }
    }

    // Webhook path: active iff enabled AND url non-empty.
    if row.webhook_enabled && !row.webhook_url.is_empty() {
        let cfg = WebhookConfig {
            url: row.webhook_url.clone(),
            secret: if row.webhook_secret.is_empty() {
                None
            } else {
                Some(row.webhook_secret.clone())
            },
        };
        if let Err(e) = self.send_webhook(&cfg, event).await {
            tracing::warn!(error = %e, "alert webhook delivery failed (best-effort)");
            errors.push(e);
        }
    }

    if let Some(e) = errors.into_iter().next() {
        return Err(e);
    }

    Ok(())
}
```

**New `AlertError` variant:**
```rust
#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    #[error("email alert error: {0}")]
    Email(String),
    #[error("webhook alert error: {0}")]
    Webhook(#[from] reqwest::Error),
    #[error("alert serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// NEW — reading alert config from the database failed.
    #[error("alert config DB error: {0}")]
    Database(#[from] rusqlite::Error),
}
```

**`use` statements to add:**
```rust
use std::sync::Arc;
use crate::db::Database;
```

**`use` statements to remove:** none — all current imports stay (`dlp_common::AuditEvent`, the
lettre imports, `reqwest::Client`).

## AuditEvent Struct Confirmation (per TM-03)

**Verified against `dlp-common/src/audit.rs:92-156`.**

Current `AuditEvent` fields (18 total):

| Field | Type | Content-risk? |
|-------|------|----------------|
| `timestamp` | `DateTime<Utc>` | Metadata |
| `event_type` | `EventType` (enum) | Metadata |
| `user_sid` | `String` (Windows SID) | Identity |
| `user_name` | `String` | Identity |
| `resource_path` | `String` (file path) | Routing metadata — path, no contents |
| `classification` | `Classification` (enum) | Metadata |
| `action_attempted` | `Action` (enum) | Metadata |
| `decision` | `Decision` (enum) | Metadata |
| `policy_id` | `Option<String>` | Metadata |
| `policy_name` | `Option<String>` | Metadata |
| `agent_id` | `String` | Metadata |
| `session_id` | `u32` | Metadata |
| `device_trust` | `Option<String>` | Metadata |
| `network_location` | `Option<String>` | Metadata |
| `justification` | `Option<String>` — user-supplied override reason | Operator-useful text, NOT file content |
| `override_granted` | `bool` | Metadata |
| `access_context` | `AuditAccessContext` (enum) | Metadata |
| `correlation_id` | `Option<String>` (UUID) | Metadata |
| `application_path` | `Option<String>` | Process path — metadata |
| `application_hash` | `Option<String>` | SHA-256 hex | Metadata |
| `resource_owner` | `Option<String>` (SID) | Metadata |

**Conclusion:** No content-snippet / sample / preview / matched_text / snippet / body / raw /
payload_content / clipboard_text / file_excerpt / plaintext field exists. TM-03 ratification
stands: `send_email` can serialize the full event as-is.

**Forward-compatible grep list for PLAN.md code-review checklist** (reject future PRs that add any
of these to `AuditEvent` without updating `send_email` in the same PR):
```
sample_content | content_preview | matched_text | snippet | body | raw |
payload_content | clipboard_text | file_excerpt | plaintext | content_sample |
file_content | text_sample | excerpt | preview_text
```

## validate_webhook_url Implementation Guidance

### `url` crate availability

**Verified** via `cargo tree -p dlp-server`: `url v2.5.8` is a transitive dependency of reqwest
(reqwest 0.12 → hyper / url). **No need to add `url` to `dlp-server/Cargo.toml`.** The planner
can `use url::{Url, Host};` directly.

**Source:** [VERIFIED: `cargo tree -p dlp-server 2>&1 | grep "url v"` → `url v2.5.8` (2 occurrences,
both transitive through reqwest)]

### Exact parsing API the planner should use

```rust
use url::{Url, Host};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Validates a webhook URL for SSRF hardening (TM-02).
///
/// Textual validation only — no DNS lookup.
///
/// # Rules
///
/// 1. Must parse as a URL.
/// 2. Scheme must be `https` (no http, file, ftp, etc.).
/// 3. If the host is a literal IPv4, reject `127.0.0.0/8` and `169.254.0.0/16`.
/// 4. If the host is a literal IPv6, reject `::1` and any address in `fe80::/10`.
/// 5. RFC1918 private IPv4 ranges (10/8, 172.16/12, 192.168/16) are ALLOWED.
/// 6. Public hostnames (e.g., `internal.corp.example.com`) are ALLOWED.
///
/// # Errors
///
/// Returns a human-readable reason string on rejection.
pub fn validate_webhook_url(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    if parsed.scheme() != "https" {
        return Err("scheme must be https".to_string());
    }

    match parsed.host() {
        Some(Host::Ipv4(ip)) => {
            if ip.is_loopback() {
                return Err("loopback addresses not allowed".to_string());
            }
            if ip.is_link_local() {
                // is_link_local() covers 169.254.0.0/16 on stable Rust.
                return Err("link-local addresses not allowed".to_string());
            }
            // RFC1918 (10/8, 172.16/12, 192.168/16) intentionally ALLOWED.
            Ok(())
        }
        Some(Host::Ipv6(ip)) => {
            if ip.is_loopback() {
                return Err("loopback addresses not allowed".to_string());
            }
            // Ipv6Addr::is_unicast_link_local is unstable on Rust 1.94,
            // so do the fe80::/10 check manually: first 10 bits == 1111111010
            // i.e. first segment in 0xfe80..=0xfebf.
            let first_segment = ip.segments()[0];
            if (first_segment & 0xffc0) == 0xfe80 {
                return Err("link-local addresses not allowed".to_string());
            }
            Ok(())
        }
        Some(Host::Domain(_)) => {
            // Textual hostname — accept. No DNS lookup (TM-02 ratified).
            Ok(())
        }
        None => Err("URL has no host".to_string()),
    }
}
```

**Critical API notes:**
- `url::Url::parse(&str) -> Result<Url, url::ParseError>` — primary entry point. [CITED: docs.rs/url/2.5]
- `Url::scheme(&self) -> &str` — returns lowercase scheme without `://`. [CITED: docs.rs/url/2.5]
- `Url::host(&self) -> Option<Host<&str>>` — returns `Some(Host::Domain(&str))`,
  `Some(Host::Ipv4(Ipv4Addr))`, or `Some(Host::Ipv6(Ipv6Addr))`. For "file:///" scheme hosts,
  returns `None`. For `https://[::1]:8080`, returns `Some(Host::Ipv6(::1))`. [CITED: docs.rs/url/2.5]
- `std::net::Ipv4Addr::is_loopback()` — stable since 1.0. Covers `127.0.0.0/8`.
  [CITED: doc.rust-lang.org std::net::Ipv4Addr]
- `std::net::Ipv4Addr::is_link_local()` — stable since 1.0. Covers `169.254.0.0/16`.
  [CITED: doc.rust-lang.org std::net::Ipv4Addr]
- `std::net::Ipv4Addr::is_private()` — stable since 1.0. Covers `10/8`, `172.16/12`, `192.168/16`.
  **Phase 4 does NOT call this** — RFC1918 is explicitly allowed per TM-02.
- `std::net::Ipv6Addr::is_loopback()` — stable since 1.0. Covers `::1`.
  [CITED: doc.rust-lang.org std::net::Ipv6Addr]
- `std::net::Ipv6Addr::is_unicast_link_local()` — **UNSTABLE on Rust 1.94**, gated behind
  `#![feature(ip)]`. Planner MUST use the manual segment-check approach above.
  [VERIFIED: rustc 1.94.1 feature gating; see https://github.com/rust-lang/rust/issues/27709]

### Complete positive/negative test case table (for table-driven unit tests)

| # | Input | Expected result | Reason |
|---|-------|-----------------|--------|
| 1 | `""` | Err("invalid URL: ...") | Empty string fails `Url::parse`. **Note:** the handler calls `validate_webhook_url` only when payload is non-empty, so this case documents the function's behavior in isolation. |
| 2 | `"http://example.com"` | Err("scheme must be https") | TM-02 rule 2 |
| 3 | `"ftp://example.com"` | Err("scheme must be https") | TM-02 rule 2 |
| 4 | `"file:///etc/passwd"` | Err — either scheme or host | TM-02 rule 2 (scheme is checked before host) |
| 5 | `"not a url"` | Err("invalid URL: ...") | Parse failure |
| 6 | `"https://127.0.0.1"` | Err("loopback addresses not allowed") | IPv4 loopback |
| 7 | `"https://127.0.0.1:8443"` | Err("loopback addresses not allowed") | Port is irrelevant |
| 8 | `"https://127.1.2.3"` | Err("loopback addresses not allowed") | Any address in 127.0.0.0/8 |
| 9 | `"https://[::1]"` | Err("loopback addresses not allowed") | IPv6 loopback |
| 10 | `"https://[::1]:8080"` | Err("loopback addresses not allowed") | IPv6 loopback with port |
| 11 | `"https://169.254.169.254"` | Err("link-local addresses not allowed") | AWS/GCP/Azure metadata endpoint |
| 12 | `"https://169.254.1.1"` | Err("link-local addresses not allowed") | Any address in 169.254.0.0/16 |
| 13 | `"https://[fe80::1]"` | Err("link-local addresses not allowed") | IPv6 link-local (fe80::/10) |
| 14 | `"https://[fe80::dead:beef]"` | Err("link-local addresses not allowed") | IPv6 link-local |
| 15 | `"https://[febf::1]"` | Err("link-local addresses not allowed") | IPv6 link-local upper edge (fe80::/10 is fe80-febf) |
| 16 | `"https://[fec0::1]"` | **Ok(())** | Just outside fe80::/10 — technically site-local (deprecated), but NOT link-local. This is a negative edge case that verifies the bit-mask math. |
| 17 | `"https://10.0.0.1"` | **Ok(())** | RFC1918 — allowed (internal webhooks) |
| 18 | `"https://10.255.255.255"` | **Ok(())** | RFC1918 upper edge — allowed |
| 19 | `"https://172.16.5.5"` | **Ok(())** | RFC1918 — allowed |
| 20 | `"https://172.31.255.255"` | **Ok(())** | RFC1918 172.16/12 upper edge — allowed |
| 21 | `"https://192.168.1.1"` | **Ok(())** | RFC1918 — allowed |
| 22 | `"https://8.8.8.8"` | **Ok(())** | Public IPv4 — allowed |
| 23 | `"https://example.com"` | **Ok(())** | Public hostname — allowed |
| 24 | `"https://internal.corp.example.com"` | **Ok(())** | Internal hostname — allowed (no DNS) |
| 25 | `"https://example.com:8443/path?query=1"` | **Ok(())** | Non-default port and path are fine |
| 26 | `"https://[2001:db8::1]"` | **Ok(())** | Public IPv6 — allowed |

**Planner MUST include cases 1-26 in the table-driven unit test.** Cases 16 and 15 specifically
guard against off-by-one errors in the `fe80::/10` bitmask check.

## AppState + main.rs Wiring

### Current AppState (`dlp-server/src/lib.rs:26-32`)

```rust
#[derive(Debug, Clone)]
pub struct AppState {
    /// Shared database handle for SQLite operations.
    pub db: Arc<db::Database>,
    /// SIEM relay connector (Splunk HEC / ELK).
    pub siem: siem_connector::SiemConnector,
}
```

### Phase 4 modification

```rust
#[derive(Debug, Clone)]
pub struct AppState {
    /// Shared database handle for SQLite operations.
    pub db: Arc<db::Database>,
    /// SIEM relay connector (Splunk HEC / ELK).
    pub siem: siem_connector::SiemConnector,
    /// Alert router for DenyWithAlert email/webhook notifications.
    pub alert: alert_router::AlertRouter,
}
```

`AlertRouter` already derives `Clone` (line 42 of `alert_router.rs`). No derive changes needed.

### main.rs construction (`dlp-server/src/main.rs:144-149`)

Current:
```rust
// Initialise the SIEM relay connector. Configuration is loaded on
// every relay call from the `siem_config` table (hot-reload).
let siem = SiemConnector::new(Arc::clone(&db));

// Build shared application state.
let state = Arc::new(AppState { db, siem });
```

Phase 4:
```rust
// Initialise the SIEM relay connector. Configuration is loaded on
// every relay call from the `siem_config` table (hot-reload).
let siem = SiemConnector::new(Arc::clone(&db));

// Initialise the alert router. Configuration is loaded on every
// send_alert call from the `alert_router_config` table (hot-reload).
let alert = AlertRouter::new(Arc::clone(&db));

// Build shared application state.
let state = Arc::new(AppState { db, siem, alert });
```

**New use statement** near the top (line 34): `use dlp_server::alert_router::AlertRouter;`

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | built-in `#[test]` / `#[tokio::test]` with `cargo test` |
| Config file | none — `Cargo.toml` workspace default |
| Quick run command | `cargo test -p dlp-server --lib alert_router` |
| Unit run (all Phase 4 modules) | `cargo test -p dlp-server --lib alert_router db::tests admin_api::tests` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R-02 | `alert_router_config` table is created on DB init | unit | `cargo test -p dlp-server --lib db::tests::test_tables_created` | Exists — extend existing |
| R-02 | `alert_router_config` seed row exists after init | unit | `cargo test -p dlp-server --lib db::tests::test_alert_router_config_seed_row` | Wave 0 — new test |
| R-02 | Default config (both disabled) yields Ok from send_alert with no I/O | unit | `cargo test -p dlp-server --lib alert_router::tests::test_alert_router_disabled_default` | Wave 0 — new test |
| R-02 | Row-load round-trip: UPDATE then SELECT yields modified values | unit | `cargo test -p dlp-server --lib alert_router::tests::test_load_config_round_trip` | Wave 0 — new test |
| R-02 | `AlertRouterConfigPayload` JSON serde round-trip | unit | `cargo test -p dlp-server --lib admin_api::tests::test_alert_router_config_payload_roundtrip` | Wave 0 — new test |
| R-02 TM-02 | `validate_webhook_url` accepts all 26 table cases correctly | unit | `cargo test -p dlp-server --lib admin_api::tests::test_validate_webhook_url` | Wave 0 — new test (table-driven) |
| R-02 | `from_env`, `load_smtp_config`, `load_webhook_config` no longer exist | compile-time | `cargo build -p dlp-server` (deleted items cannot be referenced) | Delete-and-compile verification |
| R-02 | SMTP port parses correctly including u16 overflow rejection | unit | `cargo test -p dlp-server --lib alert_router::tests::test_load_config_port_overflow` | Wave 0 — new test |
| R-02 | `GET /admin/alert-config` returns 401 without JWT | integration | `cargo test -p dlp-server --lib admin_api::tests::test_get_alert_config_requires_auth` | Wave 0 — new test; model after admin_api existing auth tests if present, otherwise manual-only for Phase 4 |
| R-02 | `PUT /admin/alert-config` rejects `http://` with 400 | integration | `cargo test -p dlp-server --lib admin_api::tests::test_put_alert_config_rejects_http` | Wave 0 — new test |
| R-02 | `PUT /admin/alert-config` rejects `https://127.0.0.1` with 400 | integration | `cargo test -p dlp-server --lib admin_api::tests::test_put_alert_config_rejects_loopback` | Wave 0 — new test |
| R-02 | `PUT /admin/alert-config` accepts RFC1918 `https://10.0.0.1` with 200 | integration | `cargo test -p dlp-server --lib admin_api::tests::test_put_alert_config_accepts_rfc1918` | Wave 0 — new test |
| R-02 | Hot-reload — modify row then call `send_alert`, verify new config used | integration | `cargo test -p dlp-server --lib alert_router::tests::test_hot_reload` | Wave 0 — new test (uses in-memory DB; does not actually send email/webhook — asserts load_config returns updated row after an UPDATE) |
| R-02 | Fire-and-forget: `ingest_events` returns before `send_alert` completes | integration | manual or `cargo test -p dlp-server --lib audit_store::tests::test_ingest_events_nonblocking` | Manual-only — requires injecting a slow mock alert path; recommendation: assert via code review that `state.alert` is consumed by `tokio::spawn` and not `.await` in the handler path. |
| R-02 TM-03 | `AuditEvent` has no content-snippet field (forward-compat) | repo grep | `grep -E "(sample_content\|content_preview\|matched_text\|snippet\|payload_content)" dlp-common/src/audit.rs` must return empty | Grep check in CI |
| R-02 TM-04 | Exactly 2 `tracing::warn!` call sites for alert delivery failures | repo grep | `grep -c 'alert .* delivery failed' dlp-server/src/alert_router.rs` must return 2 | Grep check in CI |
| R-02 TM-04 | No new metrics crates added | Cargo.toml diff | `grep -E "(metrics\|prometheus\|opentelemetry)" dlp-server/Cargo.toml` must return empty | Diff review |
| R-02 TUI | AlertConfig screen variant compiles and matches SiemConfig shape | compile + unit | `cargo build -p dlp-admin-cli && cargo test -p dlp-admin-cli` | Wave 0 — new tests |

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-server --lib alert_router db::tests` (fast)
- **Per wave merge:** `cargo test -p dlp-server --lib && cargo test -p dlp-admin-cli`
- **Phase gate:** `cargo test --workspace && cargo clippy -- -D warnings && cargo fmt --check &&
  sonar-scanner` (full — per CLAUDE.md §9.17)

### Wave 0 Gaps

- [ ] `dlp-server/src/alert_router.rs` — delete existing `test_from_env_no_vars` test; update
      `test_smtp_config_fields` / `test_webhook_config_fields` if they assume old struct shape
      (they currently construct only the field structs, so should survive unchanged)
- [ ] `dlp-server/src/alert_router.rs::tests::test_alert_router_disabled_default` — new
- [ ] `dlp-server/src/alert_router.rs::tests::test_load_config_round_trip` — new
- [ ] `dlp-server/src/alert_router.rs::tests::test_load_config_port_overflow` — new
- [ ] `dlp-server/src/alert_router.rs::tests::test_hot_reload` — new
- [ ] `dlp-server/src/admin_api.rs::tests::test_alert_router_config_payload_roundtrip` — new
- [ ] `dlp-server/src/admin_api.rs::tests::test_validate_webhook_url` (table-driven, 26 cases) — new
- [ ] `dlp-server/src/admin_api.rs::tests` — integration tests for auth/validation (see
      Observability verification below; these may need to be implemented as direct handler calls
      rather than full router tests depending on Phase 3.1 precedent)
- [ ] `dlp-server/src/db.rs::tests::test_tables_created` — extend with `alert_router_config`
      table and seed assertion
- [ ] `dlp-admin-cli/src/screens/dispatch.rs::tests` — add `handle_alert_config` tests following
      whatever SIEM tests exist (check if any — if not, compile-only is acceptable for TUI)

### Observability Verification Steps

1. **Grep for exactly two warn! call sites** in the alert_router after Phase 4 completes:
   ```bash
   grep -nE 'tracing::warn!.*alert .* delivery failed' dlp-server/src/alert_router.rs | wc -l
   # Expected: 2 (one for email, one for webhook)
   ```
2. **Confirm no metrics crates added**:
   ```bash
   grep -E '^(metrics|prometheus|opentelemetry|statsd)' dlp-server/Cargo.toml
   # Expected: (empty)
   ```
3. **Confirm no new admin endpoints**:
   ```bash
   grep -n 'alert-status\|alert_failures\|AtomicU64' dlp-server/src/admin_api.rs dlp-server/src/lib.rs
   # Expected: (empty)
   ```
4. **Confirm no new Server Status line** in dlp-admin-cli:
   ```bash
   grep -n 'alert.*failures\|Alert failures' dlp-admin-cli/src/screens/render.rs
   # Expected: (empty)
   ```
5. **Confirm send_alert is spawned, not awaited**:
   ```bash
   grep -B1 'alert.send_alert' dlp-server/src/audit_store.rs
   # Expected: must appear inside a tokio::spawn async move { ... } block,
   # NOT at the top level of ingest_events.
   ```
6. **Confirm validate_webhook_url is called in PUT handler**:
   ```bash
   grep -n 'validate_webhook_url' dlp-server/src/admin_api.rs
   # Expected: at least 2 matches — the fn definition and the call site in
   # update_alert_config_handler.
   ```

## Gotchas & Notes

### 1. `SiemConnector` uses a **shared `Arc<Database>`**, NOT a short-lived connection.

**Verified** from `dlp-server/src/siem_connector.rs:55-60`:
```rust
pub struct SiemConnector {
    /// Shared database handle for reading the SIEM config row.
    db: Arc<Database>,
    /// Shared HTTP client for outbound requests.
    client: Client,
}
```

And `siem_connector.rs:112-132` (`load_config`):
```rust
fn load_config(&self) -> Result<SiemConfigRow, SiemError> {
    let conn = self.db.conn().lock();
    let row = conn.query_row(...)?;
    Ok(row)
}
```

**Phase 4 mirrors this exactly.** `AlertRouter` holds `Arc<Database>`; `load_config` locks the
mutex, does the SELECT, and releases. The SIEM comment at lines 152-153 explicitly notes
`"Load config synchronously — the mutex lock is brief and this avoids the overhead of
spawn_blocking for a single row read."` — Phase 4 uses the same rationale.

### 2. `SmtpConfig.to` is `Vec<String>`, but the DB column is `smtp_to TEXT`.

The DB stores a comma-separated string (`"admin@corp.com, alerts@corp.com"`). `send_alert` must
split on `','`, trim, and filter out empties — exactly what `load_smtp_config` used to do at
lines 129-134. Phase 4 moves this splitting logic from `load_smtp_config` into `send_alert`'s
row→SmtpConfig derivation (shown in the `send_alert` code block above).

### 3. lettre STARTTLS transport is unchanged.

`dlp-server/Cargo.toml:36`: `lettre = { version = "0.11", default-features = false, features =
["tokio1-rustls-tls", "smtp-transport", "builder"] }`

The existing `send_email` at `alert_router.rs:184-188` uses:
```rust
let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
    .map_err(|e| AlertError::Email(format!("SMTP relay error: {e}")))?
    .port(config.port)
    .credentials(creds)
    .build();
```

**Phase 4 does NOT touch this.** The body of `send_email` is kept verbatim. The planner must NOT
accidentally schedule a task to "rewrite SMTP send logic" — it's a pure replacement of how
`SmtpConfig` is *constructed*, not how it's *used*.

### 4. `reqwest` version check

`dlp-server/Cargo.toml:33`: `reqwest = { version = "0.12", features = ["json", "rustls-tls"],
default-features = false }`

reqwest 0.12 requires `rustls-tls` feature to be explicit when `default-features = false`.
Already configured. `.json(event)` method on `RequestBuilder` requires the `json` feature —
already enabled. Phase 4 does not change reqwest configuration.

### 5. `tracing::warn!` vs `tracing::error!` — existing code uses `error!` in places

Current `alert_router.rs:102` and `alert_router.rs:109`:
```rust
tracing::error!("email alert failed: {e}");
tracing::error!("webhook alert failed: {e}");
```
And `alert_router.rs:227-230`:
```rust
tracing::error!(
    status = resp.status().as_u16(),
    "webhook returned non-success"
);
```

**TM-04 ratifies `tracing::warn!` (not `error!`)** for alert delivery failures. The planner MUST
downgrade these to `warn!` to match the SIEM relay pattern. The non-2xx webhook logging on line
227 should also become `tracing::warn!`.

### 6. `Decision::DenyWithAlert` variant name

The audit_store hook filters with `matches!(e.decision, dlp_common::Decision::DenyWithAlert)`.
**CONTEXT.md uses this name.** The planner should `grep` `dlp-common/src/` to confirm this is the
exact variant name before writing the filter — if the codebase uses `DENY_WITH_ALERT` or
`Deny_With_Alert` the case must match.

**Verification:** see `dlp-common/src/audit.rs:33` — `EventType::Alert` is the event type, not
the decision. The `Decision` enum lives elsewhere (`dlp-common/src/lib.rs` or similar). Planner
MUST verify the exact `Decision::DenyWithAlert` identifier before writing the filter, or the
`matches!` macro will silently fail to match. **This is a Wave 0 verification step.**

### 7. `AppState` derives `Debug, Clone`

Check at `dlp-server/src/lib.rs:26`: `#[derive(Debug, Clone)]`. `AlertRouter` already derives
`Debug, Clone` (`alert_router.rs:42`). Adding the `alert` field does not break the derive.

### 8. Phase 3.1's client.rs has NO typed helpers

CONTEXT.md line "`dlp-admin-cli/src/client.rs` — add `get_alert_config()` and
`update_alert_config()` methods" is **incorrect relative to the actual Phase 3.1 implementation**.
Phase 3.1 did NOT add typed client methods — it uses the generic `get::<serde_json::Value>` and
`put::<serde_json::Value, _>` directly from `dispatch.rs:642, 665`. Phase 4 should follow the
actual codebase pattern, not the CONTEXT.md text. Planner must surface this in PLAN.md Threat
Model / Canonical References section as "CONTEXT.md overspecifies — actual 3.1 uses generic
client methods."

### 9. Row count in CONTEXT.md is ambiguous

CONTEXT.md §"dlp-admin-cli screen" lists "11 editable fields + Save + Back = 13 rows" but then
numbers only 10 editable fields (1 SMTP host … 10 Webhook enabled) followed by "11. [Save]" and
"12. [Back]". The correct count is **10 editable + Save + Back = 12 rows**. The "11 editable
fields" phrase was a slip — there are 10 editable rows. Planner must reconcile this in PLAN.md.

### 10. `Database::open_in_memory` does not exist

CONTEXT.md line 85 says: "constructs `AlertRouter::new(Arc::new(Database::open_in_memory()?))`".
**There is no `open_in_memory` method** on `Database`. The actual API (verified at
`dlp-server/src/db.rs:34-47`) is `Database::open(path: &str)` — tests pass `":memory:"` as the
path. Phase 4 tests must use `Database::open(":memory:")`, same as `siem_connector.rs:300` and
`db.rs:156`.

### 11. `AlertError::Database` variant addition means downstream `?` propagation works

Because `AlertError` gets `#[from] rusqlite::Error`, `load_config`'s `?` operator automatically
converts `rusqlite::Error` into `AlertError::Database`. The planner must add the variant; clippy
will NOT warn if it's omitted but the `?` inside `load_config` will fail to compile.

### 12. `validate_webhook_url` placement — `admin_api.rs` not `alert_router.rs`

CONTEXT.md locks the function location as `admin_api.rs`. Do NOT put it in `alert_router.rs`
(which would create a dependency inversion: the module that sends alerts should not know about
HTTP validation).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `Decision::DenyWithAlert` is the exact variant name in `dlp-common`. | Audit-ingestion hook, Gotcha #6 | Silent no-op — the `matches!` macro will never match, no alerts will ever fire. **Wave 0 MUST verify the exact variant name before writing the filter.** |

All other claims in this research document are `[VERIFIED]` against the codebase via direct file
reads, `cargo tree`, or `rustc --version`.

## Open Questions

None blocking. The one verification item (A1: `Decision::DenyWithAlert` exact spelling) is a
simple grep that takes 5 seconds in Wave 0.

## Sources

### Primary (HIGH confidence) — direct codebase reads

- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\src\db.rs` (lines 1-199) — SIEM config DDL, seed row, test pattern
- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\src\siem_connector.rs` (lines 1-341) — hot-reload pattern,
  `Arc<Database>` shared handle, load_config signature, spawn_blocking policy
- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\src\admin_api.rs` (lines 1-692) — SiemConfigPayload,
  GET/PUT handlers, route wiring, protected_routes layer
- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\src\audit_store.rs` (lines 64-154) — ingest_events flow,
  SIEM spawn at lines 143-150 (exact insertion point for Phase 4 sibling spawn)
- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\src\lib.rs` (lines 26-32) — AppState current shape
- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\src\main.rs` (lines 137-149) — SiemConnector construction
  pattern in startup
- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\src\alert_router.rs` (lines 1-277) — KEPT / DELETED /
  REPLACED inventory
- `C:\Users\nhdinh\dev\dlp-rust\dlp-common\src\audit.rs` (lines 92-156) — AuditEvent struct TM-03
  confirmation
- `C:\Users\nhdinh\dev\dlp-rust\dlp-admin-cli\src\app.rs` (lines 60-119) — Screen enum including
  SiemConfig variant
- `C:\Users\nhdinh\dev\dlp-rust\dlp-admin-cli\src\client.rs` (lines 1-270) — generic get/put/delete
  (no typed SIEM methods)
- `C:\Users\nhdinh\dev\dlp-rust\dlp-admin-cli\src\screens\render.rs` (lines 30-220) — System menu,
  draw_siem_config, label/secret/bool helpers
- `C:\Users\nhdinh\dev\dlp-rust\dlp-admin-cli\src\screens\dispatch.rs` (lines 19-772) —
  handle_system_menu, action_load_siem_config, handle_siem_config + editing + nav, constants
- `C:\Users\nhdinh\dev\dlp-rust\dlp-server\Cargo.toml` — lettre 0.11, reqwest 0.12 (+ rustls-tls),
  rusqlite 0.31 (bundled), parking_lot, tracing
- `cargo tree -p dlp-server` output — confirmed `url v2.5.8` transitively available via reqwest
- `rustc --version` → rustc 1.94.1 — confirms `Ipv6Addr::is_unicast_link_local` is still unstable,
  requires manual `fe80::/10` bitmask check

### Secondary (MEDIUM confidence) — verified external references

- `docs.rs/url/2.5` — `Url::parse`, `Url::scheme`, `Url::host`, `Host::{Domain,Ipv4,Ipv6}`
- `doc.rust-lang.org std::net::Ipv4Addr` — `is_loopback`, `is_link_local`, `is_private` all stable
- `doc.rust-lang.org std::net::Ipv6Addr` — `is_loopback` stable; `is_unicast_link_local` unstable
  behind `#![feature(ip)]` (tracking issue rust-lang/rust#27709)

### Tertiary (LOW confidence)

None. All Phase 4 research is from direct codebase reads and stable Rust API documentation.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in Cargo.toml, all patterns verified in live code
- Architecture: HIGH — template is in-repo and already shipping
- Pitfalls: HIGH — gotchas extracted from direct inspection
- The one ASSUMED item (A1) is a one-grep verification that Wave 0 must execute

**Research date:** 2026-04-10
**Valid until:** 2026-05-10 (30 days — code patterns in this repo are stable)

## RESEARCH COMPLETE

Produced `04-RESEARCH.md` containing: (1) the exact Phase 3.1 templates (DDL, payload, GET/PUT
handlers, audit_store spawn site, TUI Screen/render/dispatch constants) that Phase 4 must clone
with `siem`→`alert` rename; (2) a full `validate_webhook_url` implementation including the `url`
crate availability confirmation, the manual `fe80::/10` bitmask work-around for unstable
`Ipv6Addr::is_unicast_link_local`, and a 26-case table-driven test matrix; (3) twelve gotchas
including three direct CONTEXT.md corrections (row count 12 not 13, no `Database::open_in_memory`
method, no typed client.rs helpers needed) that the planner must reconcile in PLAN.md.
