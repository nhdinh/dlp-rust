# Phase 4 Plan: Wire Alert Router into Server

**Requirement:** R-02 — Route `DenyWithAlert` audit events to configured
email (SMTP) and webhook destinations.

## Summary

Two coupled responsibilities shipped together:

1. **Wire the existing `AlertRouter` type into server startup and into
   the audit ingestion path.** Today `AlertRouter::from_env()` is never
   called; `AppState` has no `alert` field; no `DenyWithAlert` event
   triggers any email or webhook. The router is dead code.

2. **Move alert configuration from environment variables to the SQLite
   database**, mirroring Phase 3.1 (`siem_config`). Admins manage it via
   the dlp-admin-cli TUI; no server restart needed.

The result must be functionally equivalent to Phase 3.1 for alert
routing: one new DB table (`alert_router_config`), a rewritten
`AlertRouter` that hot-reloads config on every `send_alert()`, two JWT-
protected admin API routes, an "Alert Config" TUI screen under the
System menu, and a fire-and-forget spawn in `audit_store::ingest_events`
that never adds latency to the ingest response.

## Files to Modify

### dlp-server
- `src/db.rs` — add `alert_router_config` table schema + seed row;
  extend `test_tables_created`; add `test_alert_router_config_seed_row`
- `src/alert_router.rs` — rewrite `AlertRouter` struct to hold
  `Arc<Database>`; delete `from_env`, `load_smtp_config`,
  `load_webhook_config`, `test_from_env_no_vars`; add `load_config`,
  `AlertRouterConfigRow`, `test_alert_router_disabled_default`. Keep
  `SmtpConfig`, `WebhookConfig`, `AlertError`, `send_email`,
  `send_webhook` unchanged.
- `src/audit_store.rs` — in `ingest_events`, after the existing SIEM
  relay spawn (lines 143-150), add a second fire-and-forget spawn that
  filters `events` to `Decision::DenyWithAlert` and calls
  `state.alert.send_alert(event)` for each.
- `src/lib.rs` — add `pub alert: alert_router::AlertRouter` field to
  `AppState` (line 27-32).
- `src/main.rs` — construct `AlertRouter::new(Arc::clone(&db))` and
  pass into `AppState { db, siem, alert }`.
- `src/admin_api.rs` — add `AlertRouterConfigPayload` struct, two
  handlers (`get_alert_config_handler`, `update_alert_config_handler`),
  two protected routes, and a payload-serde test.

### dlp-admin-cli
- `src/app.rs` — add `Screen::AlertConfig { config, selected, editing,
  buffer }` variant.
- `src/screens/render.rs` — add `draw_alert_config` function; wire into
  the top-level render match; update the System menu label list to
  include `"Alert Config"`.
- `src/screens/dispatch.rs` — extend System menu from 4 items to 5
  (`Server Status`, `Agent List`, `SIEM Config`, `Alert Config`,
  `Back`); add `handle_alert_config`, `action_load_alert_config`,
  `action_save_alert_config`, and supporting constants/helpers mirroring
  the SIEM config screen pattern.

## Implementation Steps

### Step 1: Database schema

In `dlp-server/src/db.rs::init_tables()`, append the new table to the
`execute_batch` SQL block (after `siem_config`):

```sql
CREATE TABLE IF NOT EXISTS alert_router_config (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    smtp_host         TEXT    NOT NULL DEFAULT '',
    smtp_port         INTEGER NOT NULL DEFAULT 587,
    smtp_username     TEXT    NOT NULL DEFAULT '',
    smtp_password     TEXT    NOT NULL DEFAULT '',
    smtp_from         TEXT    NOT NULL DEFAULT '',
    smtp_to           TEXT    NOT NULL DEFAULT '',
    smtp_enabled      INTEGER NOT NULL DEFAULT 0,
    webhook_url       TEXT    NOT NULL DEFAULT '',
    webhook_secret    TEXT    NOT NULL DEFAULT '',
    webhook_enabled   INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT    NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO alert_router_config (id) VALUES (1);
```

`smtp_to` stores a comma-separated list of recipient addresses
(identical format to the former `SMTP_TO` env var). Single-row table,
enforced by `CHECK (id = 1)`, same idempotent `INSERT OR IGNORE` pattern
as `siem_config`.

**Tests** (in `dlp-server/src/db.rs::tests`):

1. Extend `test_tables_created` to assert `alert_router_config` is
   listed by `sqlite_master`:
   ```rust
   assert!(tables.contains(&"alert_router_config".to_string()));
   ```

2. Add a new test:
   ```rust
   #[test]
   fn test_alert_router_config_seed_row() {
       let db = Database::open(":memory:").expect("open in-memory db");
       let conn = db.conn().lock();
       let count: i64 = conn
           .query_row("SELECT COUNT(*) FROM alert_router_config", [], |r| r.get(0))
           .expect("count alert_router_config rows");
       assert_eq!(count, 1, "alert_router_config should have exactly one seed row");

       // Default enabled flags must be 0.
       let (smtp_en, webhook_en): (i64, i64) = conn
           .query_row(
               "SELECT smtp_enabled, webhook_enabled \
                FROM alert_router_config WHERE id = 1",
               [],
               |r| Ok((r.get(0)?, r.get(1)?)),
           )
           .expect("read enabled flags");
       assert_eq!(smtp_en, 0);
       assert_eq!(webhook_en, 0);
   }
   ```

### Step 2: Rewrite AlertRouter

In `dlp-server/src/alert_router.rs`:

1. **Delete** `AlertRouter::from_env`, `load_smtp_config`,
   `load_webhook_config`, and the `test_from_env_no_vars` test.

2. **Replace** the struct and imports. Add `use std::sync::Arc;` and
   `use crate::db::Database;`. Add a `Database` variant to `AlertError`
   for config-load failures.

   ```rust
   use std::sync::Arc;

   use crate::db::Database;

   /// Routes real-time alerts to email and/or webhook destinations.
   ///
   /// Construct via `AlertRouter::new(db)`. On every `send_alert` call,
   /// the router re-reads the single `alert_router_config` row so that
   /// admin updates made via the API take effect immediately without a
   /// server restart (hot-reload, same pattern as `SiemConnector`).
   #[derive(Debug, Clone)]
   pub struct AlertRouter {
       /// Shared database handle for reading the alert config row.
       db: Arc<Database>,
       /// Shared HTTP client for webhook calls.
       client: Client,
   }

   /// Snapshot of the single `alert_router_config` row.
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

3. **Add a `Database` variant to `AlertError`:**

   ```rust
   #[derive(Debug, thiserror::Error)]
   pub enum AlertError {
       #[error("email alert error: {0}")]
       Email(String),

       #[error("webhook alert error: {0}")]
       Webhook(#[from] reqwest::Error),

       #[error("alert serialization error: {0}")]
       Serialization(#[from] serde_json::Error),

       /// Reading alert config from the database failed.
       #[error("alert config DB error: {0}")]
       Database(#[from] rusqlite::Error),
   }
   ```

4. **Add the constructor and loader:**

   ```rust
   impl AlertRouter {
       /// Constructs an `AlertRouter` backed by the given database.
       pub fn new(db: Arc<Database>) -> Self {
           Self {
               db,
               client: Client::new(),
           }
       }

       /// Loads the current alert configuration row from the database.
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
                   // `smtp_port` is stored as INTEGER; clamp to u16.
                   let port_i64: i64 = r.get(1)?;
                   let smtp_port: u16 = u16::try_from(port_i64).unwrap_or(587);
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

5. **Rewrite `send_alert`** to (a) load the row, (b) derive
   `Option<SmtpConfig>` and `Option<WebhookConfig>` locally, (c) invoke
   the existing `send_email` / `send_webhook` helpers unchanged, and
   (d) aggregate errors the same way the current implementation does
   (collect all, return the first):

   ```rust
       /// Sends an alert for a single audit event to all configured
       /// destinations.
       ///
       /// Re-reads the alert config from the database on each call so
       /// that admin updates take effect immediately (hot-reload).
       ///
       /// # Errors
       ///
       /// Returns the first error encountered. Both destinations are
       /// attempted even if one fails.
       pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
           let row = self.load_config()?;

           // Derive effective SMTP config: enabled AND minimum fields set.
           let smtp: Option<SmtpConfig> = if row.smtp_enabled
               && !row.smtp_host.is_empty()
               && !row.smtp_to.is_empty()
           {
               let to: Vec<String> = row
                   .smtp_to
                   .split(',')
                   .map(|s| s.trim().to_string())
                   .filter(|s| !s.is_empty())
                   .collect();
               if to.is_empty() {
                   None
               } else {
                   Some(SmtpConfig {
                       host: row.smtp_host.clone(),
                       port: row.smtp_port,
                       username: row.smtp_username.clone(),
                       password: row.smtp_password.clone(),
                       from: row.smtp_from.clone(),
                       to,
                   })
               }
           } else {
               None
           };

           // Derive effective webhook config: enabled AND URL set.
           let webhook: Option<WebhookConfig> = if row.webhook_enabled
               && !row.webhook_url.is_empty()
           {
               let secret = if row.webhook_secret.is_empty() {
                   None
               } else {
                   Some(row.webhook_secret.clone())
               };
               Some(WebhookConfig {
                   url: row.webhook_url.clone(),
                   secret,
               })
           } else {
               None
           };

           let mut errors: Vec<AlertError> = Vec::new();

           if let Some(ref cfg) = smtp {
               if let Err(e) = self.send_email(cfg, event).await {
                   tracing::error!("email alert failed: {e}");
                   errors.push(e);
               }
           }

           if let Some(ref cfg) = webhook {
               if let Err(e) = self.send_webhook(cfg, event).await {
                   tracing::error!("webhook alert failed: {e}");
                   errors.push(e);
               }
           }

           if let Some(e) = errors.into_iter().next() {
               return Err(e);
           }

           Ok(())
       }
   ```

6. **Keep `send_email` and `send_webhook` unchanged** — they still take
   `&SmtpConfig` / `&WebhookConfig` by reference and contain all the
   lettre / reqwest logic. Do not touch their bodies or signatures.

7. **Keep** `SmtpConfig`, `WebhookConfig`, and the existing tests
   `test_smtp_config_fields` and `test_webhook_config_fields` unchanged
   — they exercise the public struct shape, which survives the rewrite.

8. **Add a new test** that exercises the default-disabled path using an
   in-memory database:

   ```rust
   #[tokio::test]
   async fn test_alert_router_disabled_default() {
       use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

       let db = Arc::new(Database::open(":memory:").expect("open db"));
       let router = AlertRouter::new(Arc::clone(&db));

       let event = AuditEvent::new(
           EventType::Block,
           "S-1-5-21-1".to_string(),
           "tester".to_string(),
           r"C:\Data\File.txt".to_string(),
           Classification::T3,
           Action::COPY,
           Decision::DenyWithAlert,
           "AGENT-001".to_string(),
           1,
       );

       // Both destinations disabled by default -> no network I/O, Ok(()).
       router.send_alert(&event).await.expect("disabled default should be ok");
   }
   ```

### Step 3: Audit-ingestion hook

In `dlp-server/src/audit_store.rs::ingest_events`, immediately AFTER the
existing SIEM relay spawn (currently at lines 143-150, preserving it
verbatim), add the alert spawn:

```rust
    // Best-effort SIEM relay — fire-and-forget in a background task
    // so the HTTP response is not delayed by external SIEM latency.
    let siem = state.siem.clone();
    tokio::spawn(async move {
        if let Err(e) = siem.relay_events(&relay_events).await {
            tracing::warn!(error = %e, "SIEM relay failed (best-effort)");
        }
    });

    // Best-effort alert routing — fire-and-forget background task.
    // Only events with `Decision::DenyWithAlert` trigger alerts; all
    // other decisions (Allow, Deny, AllowWithLog) are filtered out.
    // The HTTP response MUST NOT be delayed by SMTP / webhook latency.
    let alert_events: Vec<AuditEvent> = relay_events
        .iter()
        .filter(|e| matches!(e.decision, dlp_common::Decision::DenyWithAlert))
        .cloned()
        .collect();
    if !alert_events.is_empty() {
        let alert = state.alert.clone();
        tokio::spawn(async move {
            for event in &alert_events {
                if let Err(e) = alert.send_alert(event).await {
                    tracing::warn!(error = %e, "alert delivery failed (best-effort)");
                }
            }
        });
    }
```

Notes for the executor:

- The filter must guard with `if !alert_events.is_empty()` so a no-op
  task is never spawned.
- Reuse `relay_events` (the clone already made for the SIEM spawn).
  Do NOT clone `events` a second time — it has been moved into the
  `spawn_blocking` closure above.
- The filter closure uses `matches!` on `e.decision` (an owned enum,
  `Copy` in `dlp_common`). Verify `dlp_common::Decision` is already in
  scope at the top of `audit_store.rs`; if not, add
  `use dlp_common::Decision;` and match on `Decision::DenyWithAlert`.

### Step 4: AppState extension

In `dlp-server/src/lib.rs`, update the `AppState` struct:

```rust
/// Shared application state passed to all HTTP handlers via axum's
/// `State` extractor.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Shared database handle for SQLite operations.
    pub db: Arc<db::Database>,
    /// SIEM relay connector (Splunk HEC / ELK).
    pub siem: siem_connector::SiemConnector,
    /// Alert router (SMTP email + webhook for DenyWithAlert events).
    pub alert: alert_router::AlertRouter,
}
```

`AlertRouter` already derives `Clone` (verified in current source). No
other changes to `lib.rs` are required.

### Step 5: main.rs wiring

In `dlp-server/src/main.rs`, add the import and construct the alert
router alongside the SIEM connector:

```rust
use dlp_server::alert_router::AlertRouter;
```

Inside `main()`, after the `SiemConnector::new` line:

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

No env var reads, no `from_env` calls, no fallbacks. The server must no
longer reference `SMTP_*` or `ALERT_WEBHOOK_*` environment variables
anywhere.

### Step 6: Admin API surface

In `dlp-server/src/admin_api.rs`:

1. **Add the payload type** next to `SiemConfigPayload` (after line
   ~115). Derive the same traits and include all 11 configurable
   fields:

   ```rust
   // -----------------------------------------------------------------
   // Alert router config request / response types
   // -----------------------------------------------------------------

   /// Read/write payload for alert router configuration.
   ///
   /// Represents the single row of the `alert_router_config` table.
   /// Both the `GET /admin/alert-config` response body and the
   /// `PUT /admin/alert-config` request body use this shape.
   #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
   pub struct AlertRouterConfigPayload {
       /// SMTP server hostname (e.g., `smtp.example.com`).
       pub smtp_host: String,
       /// SMTP server port (commonly 587 for STARTTLS).
       pub smtp_port: u16,
       /// SMTP auth username.
       pub smtp_username: String,
       /// SMTP auth password (secret; masked in TUI).
       pub smtp_password: String,
       /// Sender address (e.g., `dlp@example.com`).
       pub smtp_from: String,
       /// Comma-separated list of recipient addresses.
       pub smtp_to: String,
       /// Whether the SMTP backend is active.
       pub smtp_enabled: bool,
       /// Webhook endpoint URL.
       pub webhook_url: String,
       /// Optional shared secret for webhook HMAC (reserved; unused).
       pub webhook_secret: String,
       /// Whether the webhook backend is active.
       pub webhook_enabled: bool,
   }
   ```

2. **Register routes** in `admin_router` inside the `protected_routes`
   block, adjacent to the existing SIEM config routes:

   ```rust
           .route("/admin/siem-config", get(get_siem_config_handler))
           .route("/admin/siem-config", put(update_siem_config_handler))
           .route("/admin/alert-config", get(get_alert_config_handler))
           .route("/admin/alert-config", put(update_alert_config_handler))
   ```

   Also append to the doc-comment route table in `admin_router`:

   ```text
   /// - `GET /admin/alert-config` — get alert router configuration
   /// - `PUT /admin/alert-config` — update alert router configuration
   ```

3. **Add the handlers** at the end of the `SIEM config handlers`
   section (after `update_siem_config_handler`):

   ```rust
   // -----------------------------------------------------------------
   // Alert router config handlers
   // -----------------------------------------------------------------

   /// `GET /admin/alert-config` — returns the current alert router config.
   ///
   /// Reads the single row from `alert_router_config` and returns it as
   /// a JSON [`AlertRouterConfigPayload`]. The row is guaranteed to
   /// exist because it is seeded during `Database::open`.
   async fn get_alert_config_handler(
       State(state): State<Arc<AppState>>,
   ) -> Result<Json<AlertRouterConfigPayload>, AppError> {
       let db = Arc::clone(&state.db);
       let payload = tokio::task::spawn_blocking(move || {
           let conn = db.conn().lock();
           conn.query_row(
               "SELECT smtp_host, smtp_port, smtp_username, smtp_password, \
                       smtp_from, smtp_to, smtp_enabled, \
                       webhook_url, webhook_secret, webhook_enabled \
                FROM alert_router_config WHERE id = 1",
               [],
               |row| {
                   let port_i64: i64 = row.get(1)?;
                   let smtp_port: u16 = u16::try_from(port_i64).unwrap_or(587);
                   Ok(AlertRouterConfigPayload {
                       smtp_host: row.get(0)?,
                       smtp_port,
                       smtp_username: row.get(2)?,
                       smtp_password: row.get(3)?,
                       smtp_from: row.get(4)?,
                       smtp_to: row.get(5)?,
                       smtp_enabled: row.get::<_, i64>(6)? != 0,
                       webhook_url: row.get(7)?,
                       webhook_secret: row.get(8)?,
                       webhook_enabled: row.get::<_, i64>(9)? != 0,
                   })
               },
           )
       })
       .await
       .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

       Ok(Json(payload))
   }

   /// `PUT /admin/alert-config` — updates the alert router config.
   ///
   /// Overwrites the single row in `alert_router_config` with the
   /// provided values and stamps `updated_at` with the current time.
   /// Returns the payload that was written so clients can refresh their
   /// local copy.
   async fn update_alert_config_handler(
       State(state): State<Arc<AppState>>,
       Json(payload): Json<AlertRouterConfigPayload>,
   ) -> Result<Json<AlertRouterConfigPayload>, AppError> {
       let now = Utc::now().to_rfc3339();
       let p = payload.clone();
       let db = Arc::clone(&state.db);

       tokio::task::spawn_blocking(move || -> Result<(), AppError> {
           let conn = db.conn().lock();
           conn.execute(
               "UPDATE alert_router_config SET \
                   smtp_host = ?1, smtp_port = ?2, smtp_username = ?3, \
                   smtp_password = ?4, smtp_from = ?5, smtp_to = ?6, \
                   smtp_enabled = ?7, webhook_url = ?8, \
                   webhook_secret = ?9, webhook_enabled = ?10, \
                   updated_at = ?11 \
                WHERE id = 1",
               rusqlite::params![
                   p.smtp_host,
                   p.smtp_port as i64,
                   p.smtp_username,
                   p.smtp_password,
                   p.smtp_from,
                   p.smtp_to,
                   p.smtp_enabled as i64,
                   p.webhook_url,
                   p.webhook_secret,
                   p.webhook_enabled as i64,
                   now,
               ],
           )?;
           Ok(())
       })
       .await
       .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

       tracing::info!(
           smtp_enabled = payload.smtp_enabled,
           webhook_enabled = payload.webhook_enabled,
           "alert router config updated"
       );
       Ok(Json(payload))
   }
   ```

   Note: the INFO log deliberately records only the boolean flags, NOT
   the password or secret fields (see Threat Model T-04-03).

4. **Add the payload roundtrip test** in the `admin_api::tests` module:

   ```rust
   #[test]
   fn test_alert_router_config_payload_roundtrip() {
       let p = AlertRouterConfigPayload {
           smtp_host: "smtp.example.com".to_string(),
           smtp_port: 587,
           smtp_username: "alerts@example.com".to_string(),
           smtp_password: "s3cret".to_string(),
           smtp_from: "dlp@example.com".to_string(),
           smtp_to: "admin@example.com,soc@example.com".to_string(),
           smtp_enabled: true,
           webhook_url: "https://hooks.example.com/alert".to_string(),
           webhook_secret: "hmac-key".to_string(),
           webhook_enabled: false,
       };
       let json = serde_json::to_string(&p).expect("serialize");
       let rt: AlertRouterConfigPayload =
           serde_json::from_str(&json).expect("deserialize");
       assert_eq!(rt, p);
       assert_eq!(rt.smtp_port, 587);
       assert!(rt.smtp_enabled);
       assert!(!rt.webhook_enabled);
   }
   ```

### Step 7: dlp-admin-cli — screen, render, dispatch

Mirror the SIEM config screen exactly. The dlp-admin-cli's HTTP client
already exposes generic `get::<T>` / `put::<T, B>` methods, so no
dedicated `get_alert_config` / `update_alert_config` wrappers are
needed — the dispatch actions call them inline just like the SIEM
actions do (see `src/screens/dispatch.rs:639-673`). This matches Phase
3.1's actual pattern in the repo.

**7a. `src/app.rs`** — add a new variant to `Screen` (after
`SiemConfig`):

```rust
    /// Alert router configuration form.
    ///
    /// Navigable list of 13 rows (11 editable fields + Save + Back).
    /// When `editing` is true, keystrokes append to `buffer`; Enter
    /// commits the buffer into the selected field of `config`.
    AlertConfig {
        /// Currently loaded config as a JSON object.
        config: serde_json::Value,
        /// Index of the selected row (0..=12).
        selected: usize,
        /// Whether the selected text field is in edit mode.
        editing: bool,
        /// Buffered input while editing.
        buffer: String,
    },
```

**7b. `src/screens/render.rs`** — three edits:

(1) Update the System menu label array to include `"Alert Config"`:

```rust
        Screen::SystemMenu { selected } => {
            draw_menu(
                frame,
                area,
                "System",
                &[
                    "Server Status",
                    "Agent List",
                    "SIEM Config",
                    "Alert Config",
                    "Back",
                ],
                *selected,
            );
        }
```

(2) Add a render arm for the new screen after the `SiemConfig` arm:

```rust
        Screen::AlertConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_alert_config(frame, area, config, *selected, *editing, buffer);
        }
```

(3) Add a `draw_alert_config` function mirroring `draw_siem_config`.
Row layout is 13 items (11 fields + Save + Back). Secret rows are 3
(`smtp_password`) and 8 (`webhook_secret`). Bool rows are 6
(`smtp_enabled`) and 9 (`webhook_enabled`). The port field (row 1) is
rendered as a string — the port value is kept as a JSON number in the
`config` value, so display it with `.as_u64().map(|n| n.to_string())`:

The form has 10 editable fields + Save + Back = 12 rows total.
The labels array must be `[&str; 12]` (not 13). Concrete shape:

```rust
const ALERT_FIELD_LABELS: [&str; 12] = [
    "SMTP Host",
    "SMTP Port",
    "SMTP Username",
    "SMTP Password",
    "SMTP From",
    "SMTP To (comma-separated)",
    "SMTP Enabled",
    "Webhook URL",
    "Webhook Secret",
    "Webhook Enabled",
    "[ Save ]",
    "[ Back ]",
];

/// Returns `true` when a row index is a masked secret field.
fn is_alert_secret(index: usize) -> bool {
    matches!(index, 3 | 8)
}

/// Returns `true` when a row index is a boolean (toggle) field.
fn is_alert_bool(index: usize) -> bool {
    matches!(index, 6 | 9)
}

/// Returns `true` when a row index is the integer port field.
fn is_alert_port(index: usize) -> bool {
    index == 1
}

/// Draws the alert router configuration form.
fn draw_alert_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: &str,
) {
    // Map row index -> JSON key for the 10 editable data fields.
    const KEYS: [&str; 10] = [
        "smtp_host",
        "smtp_port",
        "smtp_username",
        "smtp_password",
        "smtp_from",
        "smtp_to",
        "smtp_enabled",
        "webhook_url",
        "webhook_secret",
        "webhook_enabled",
    ];

    let mut items: Vec<ListItem> = Vec::with_capacity(ALERT_FIELD_LABELS.len());
    for (i, label) in ALERT_FIELD_LABELS.iter().enumerate() {
        let line = if i < KEYS.len() {
            let key = KEYS[i];
            let value_display = if editing && i == selected {
                format!("[{buffer}_]")
            } else if is_alert_bool(i) {
                let b = config[key].as_bool().unwrap_or(false);
                if b { "[x]".to_string() } else { "[ ]".to_string() }
            } else if is_alert_secret(i) {
                let v = config[key].as_str().unwrap_or("");
                if v.is_empty() {
                    "(empty)".to_string()
                } else {
                    "*****".to_string()
                }
            } else if is_alert_port(i) {
                // Port is stored as JSON number; fall back to string
                // when a buffered edit has not yet been committed.
                match config[key].as_u64() {
                    Some(n) => n.to_string(),
                    None => config[key]
                        .as_str()
                        .unwrap_or("(empty)")
                        .to_string(),
                }
            } else {
                let v = config[key].as_str().unwrap_or("");
                if v.is_empty() {
                    "(empty)".to_string()
                } else {
                    v.to_string()
                }
            };
            format!("{label}: {value_display}")
        } else {
            (*label).to_string()
        };
        items.push(ListItem::new(Line::from(line)));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Alert Config ")
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, area, &mut state);

    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: edit/toggle | Esc: back"
    };
    draw_hints(frame, area, hints);
}
```

**7c. `src/screens/dispatch.rs`** — four edits:

(1) Add a top-level dispatch arm for the new screen (alongside the
existing `Screen::SiemConfig { .. } => handle_siem_config(...)` entry
near line 25):

```rust
        Screen::AlertConfig { .. } => handle_alert_config(app, key),
```

(2) Update `handle_system_menu` to handle 5 items instead of 4, with
the new ordering `Server Status / Agent List / SIEM Config / Alert
Config / Back`:

```rust
fn handle_system_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::SystemMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 5, key.code),
        KeyCode::Enter => match *selected {
            0 => action_server_status(app),
            1 => action_agent_list(app),
            2 => action_load_siem_config(app),
            3 => action_load_alert_config(app),
            4 => app.screen = Screen::MainMenu { selected: 2 },
            _ => {}
        },
        KeyCode::Esc => app.screen = Screen::MainMenu { selected: 2 },
        _ => {}
    }
}
```

(3) Add the alert config constants, actions, and handlers mirroring
the SIEM ones (place them after the `SIEM config screen` section near
line 772). The port field requires `u16` validation at save time — a
malformed buffer blocks the save and surfaces a status error; it must
NOT be sent to the server.

```rust
// -------------------------------------------------------------------
// Alert config screen
// -------------------------------------------------------------------

/// JSON keys for the alert config form, indexed by row.
const ALERT_KEYS: [&str; 10] = [
    "smtp_host",
    "smtp_port",
    "smtp_username",
    "smtp_password",
    "smtp_from",
    "smtp_to",
    "smtp_enabled",
    "webhook_url",
    "webhook_secret",
    "webhook_enabled",
];

/// Row index of the Save button.
const ALERT_SAVE_ROW: usize = 10;
/// Row index of the Back button.
const ALERT_BACK_ROW: usize = 11;
/// Total number of rows in the alert config form.
const ALERT_ROW_COUNT: usize = 12;

/// Returns `true` if the row index is a bool (toggle) field.
fn alert_is_bool(index: usize) -> bool {
    matches!(index, 6 | 9)
}

/// Returns `true` if the row index is the `smtp_port` integer field.
fn alert_is_port(index: usize) -> bool {
    index == 1
}

/// Fetches the current alert config from the server and switches to
/// the `AlertConfig` screen.
fn action_load_alert_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/alert-config"))
    {
        Ok(config) => {
            app.screen = Screen::AlertConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Persists the in-memory alert config to the server.
///
/// Validates that `smtp_port` parses as `u16` before sending. If the
/// port is missing or invalid, shows a status error and leaves the
/// form state untouched.
fn action_save_alert_config(app: &mut App) {
    let payload = match &app.screen {
        Screen::AlertConfig { config, .. } => config.clone(),
        _ => return,
    };

    // Validate smtp_port -> u16 before the PUT.
    let port_ok = match payload.get("smtp_port") {
        Some(v) if v.is_u64() => v.as_u64().and_then(|n| u16::try_from(n).ok()).is_some(),
        Some(v) if v.is_string() => v
            .as_str()
            .and_then(|s| s.parse::<u16>().ok())
            .is_some(),
        _ => false,
    };
    if !port_ok {
        app.set_status(
            "SMTP port must be an integer 0-65535",
            StatusKind::Error,
        );
        return;
    }

    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/alert-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("Alert config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 3 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Handles key events while the alert config form is active.
fn handle_alert_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::AlertConfig {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_alert_config_editing(app, key, selected);
    } else {
        handle_alert_config_nav(app, key, selected);
    }
}

/// Handles key events while editing a text field in the alert config form.
fn handle_alert_config_editing(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::AlertConfig { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::AlertConfig { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            // Commit buffer into the selected field. Port is coerced
            // to a JSON number if it parses as u16; otherwise the raw
            // string is retained and validation happens at Save time.
            if let Screen::AlertConfig {
                config,
                buffer,
                editing,
                ..
            } = &mut app.screen
            {
                let key_name = ALERT_KEYS[selected];
                if alert_is_port(selected) {
                    match buffer.parse::<u16>() {
                        Ok(n) => {
                            config[key_name] = serde_json::Value::from(n);
                        }
                        Err(_) => {
                            config[key_name] =
                                serde_json::Value::String(buffer.clone());
                        }
                    }
                } else {
                    config[key_name] = serde_json::Value::String(buffer.clone());
                }
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            if let Screen::AlertConfig {
                buffer, editing, ..
            } = &mut app.screen
            {
                buffer.clear();
                *editing = false;
            }
        }
        _ => {}
    }
}

/// Handles key events while navigating the alert config form.
fn handle_alert_config_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::AlertConfig { selected: sel, .. } = &mut app.screen {
                nav(sel, ALERT_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => {
            if selected == ALERT_SAVE_ROW {
                action_save_alert_config(app);
            } else if selected == ALERT_BACK_ROW {
                app.screen = Screen::SystemMenu { selected: 3 };
            } else if alert_is_bool(selected) {
                if let Screen::AlertConfig { config, .. } = &mut app.screen {
                    let key_name = ALERT_KEYS[selected];
                    let cur = config[key_name].as_bool().unwrap_or(false);
                    config[key_name] = serde_json::Value::Bool(!cur);
                }
            } else {
                // Enter text-edit mode with current value pre-filled.
                if let Screen::AlertConfig {
                    config,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let key_name = ALERT_KEYS[selected];
                    *buffer = if alert_is_port(selected) {
                        match config[key_name].as_u64() {
                            Some(n) => n.to_string(),
                            None => config[key_name]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                        }
                    } else {
                        config[key_name].as_str().unwrap_or("").to_string()
                    };
                    *editing = true;
                }
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 3 };
        }
        _ => {}
    }
}
```

Note the `SystemMenu { selected: 3 }` return — index 3 is the new
"Alert Config" row, so the user lands back on the menu item they just
came from.

## Verification

```
cargo check --package dlp-server
cargo check --package dlp-admin-cli
cargo test --package dlp-server --lib
cargo test --package dlp-admin-cli --lib
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

`cargo test --workspace` must stay at the pre-phase green baseline
(364/364 or whatever the current count is) PLUS the three new tests
added in this phase:

- `db::tests::test_alert_router_config_seed_row`
- `alert_router::tests::test_alert_router_disabled_default`
- `admin_api::tests::test_alert_router_config_payload_roundtrip`

Plus the extended assertion in `db::tests::test_tables_created`.

The removed `alert_router::tests::test_from_env_no_vars` must be
deleted — it references the removed `from_env` / `smtp: None` shape.

## UAT Criteria

- [ ] `alert_router_config` table exists after DB init with exactly one
      seed row (id = 1, both `*_enabled` flags default to 0)
- [ ] `GET /admin/alert-config` returns the current settings as JSON
      (JWT required; 401 without token)
- [ ] `PUT /admin/alert-config` updates the row and stamps `updated_at`
      (JWT required)
- [ ] `AlertRouter::send_alert` re-reads the config row from the DB on
      every invocation; no restart needed for admin edits
- [ ] `dlp-server` no longer reads `SMTP_HOST`, `SMTP_PORT`,
      `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO`,
      `ALERT_WEBHOOK_URL`, or `ALERT_WEBHOOK_SECRET` environment
      variables anywhere
- [ ] A `DenyWithAlert` audit event posted to `POST /audit/events`
      triggers an SMTP send (if SMTP is enabled and configured) AND a
      webhook POST (if webhook is enabled and configured), both
      fire-and-forget
- [ ] Events with any decision other than `DenyWithAlert` do NOT
      trigger alerts (no SMTP, no webhook)
- [ ] `POST /audit/events` response latency is not affected by alert
      dispatch (background `tokio::spawn`)
- [ ] `dlp-admin-cli` has an "Alert Config" entry under the System menu,
      positioned after "SIEM Config" and before "Back"
- [ ] Admin can view SMTP + webhook settings via the TUI; the
      `smtp_password` and `webhook_secret` rows show `*****` outside
      edit mode
- [ ] Admin can edit any field and Save; the change is persisted via
      `PUT /admin/alert-config`
- [ ] Entering a non-numeric value in the SMTP Port field and hitting
      Save shows a status error and leaves the form on-screen without
      sending a malformed payload
- [ ] All previously existing tests pass (no regressions)
- [ ] `cargo clippy --workspace -- -D warnings` is clean
- [ ] `cargo fmt --check` is clean
- [ ] R-02 is satisfied — `DenyWithAlert` events are routed to
      configured email/webhook destinations, and configuration is
      manageable at runtime via the admin TUI

## Threat Model

### Trust boundaries

| Boundary | Description |
|----------|-------------|
| Network -> `POST /audit/events` | Agents submit signed audit events via JWT/agent-auth. Untrusted content in event fields crosses here. |
| TUI admin -> `PUT /admin/alert-config` | Authenticated admin (JWT) writes SMTP creds + webhook URL into the SQLite DB. Trusted-after-auth. |
| dlp-server -> SMTP relay | Outbound TLS (STARTTLS) to an admin-controlled mail server. |
| dlp-server -> Webhook endpoint | Outbound HTTPS POST to an admin-configured URL. |
| DB file on disk | LocalSystem-only ACL on the server host. Trusted after OS boundary. |

### STRIDE threat register

| ID        | Category         | Component                                   | Severity | Disposition                     | Mitigation / Rationale |
|-----------|------------------|---------------------------------------------|----------|----------------------------------|------------------------|
| T-04-01   | Information Disclosure | `smtp_password` stored plaintext in `alert_router_config` | Low | Accepted residual risk | Same rationale as Phase 3.1 `splunk_token` / `elk_api_key` (see Phase 3.1 PLAN.md threat notes): DB file is LocalSystem-only, no multi-tenant boundary inside the server. Key management / encryption-at-rest is deferred to a dedicated future security phase. |
| T-04-02   | Tampering / Spoofing | SSRF via admin-controlled `webhook_url` | Low | Accepted residual risk | The only writer of `webhook_url` is an authenticated admin holding a valid JWT for `PUT /admin/alert-config`. The DB is a trusted boundary once the admin is authenticated. No additional URL allow-listing in Phase 4; document the assumption and leave it to a future hardening phase if operational need arises. |
| T-04-03   | Information Disclosure | PII / paths in email body (`serde_json::to_string_pretty(event)`) | Medium | Mitigated (policy + scope) | Alert emails are addressed exclusively to `smtp_to` which only a DLP admin can configure. The email body is the same JSON already stored in the audit log, which the admin is already authorized to read. Tracing log in `update_alert_config_handler` records only boolean flags, never secrets or recipients. No broader mitigation required in Phase 4. |
| T-04-04   | Repudiation / Denial of Service | Fire-and-forget `tokio::spawn` — delivery failures invisible to the agent POSTing the event | Low | Accepted residual risk | By design: ingest latency MUST NOT depend on external SMTP/webhook availability (R-02 acceptance criterion). Observability surface is `tracing::warn!` on every failed `send_alert`. The failure is also implicitly visible because the audit event itself is persisted successfully. |
| T-04-05   | Denial of Service | Alert flood DoS (mass `DenyWithAlert` events spawn unbounded SMTP sends) | Medium | Deferred to Phase 8 | No per-sender or per-event-type rate limiting in Phase 4. Each batch spawns ONE background task that iterates sequentially over its filtered events, so within a single batch there is natural serialization, but concurrent batches are unbounded. Full rate-limiting middleware (R-07) is Phase 8 scope. Document the accepted risk window between Phase 4 ship and Phase 8 ship. |
| T-04-06   | Information Disclosure | `smtp_password` / `webhook_secret` logged via `tracing` | Low | Mitigated (code review) | `update_alert_config_handler` explicitly logs only `smtp_enabled` / `webhook_enabled` boolean flags — see the INFO log in Step 6. The `load_config` path in `alert_router.rs` does not log secrets. Executors MUST NOT add any `tracing::info!` or `tracing::debug!` that includes `smtp_password`, `webhook_secret`, or the raw `AlertRouterConfigRow`. |

**Security gate status:** no `high` severity unmitigated threats. All
entries are either mitigated, accepted residual risk with documented
rationale consistent with Phase 3.1 precedent, or explicitly deferred
to a named later phase (Phase 8 for rate limiting).
