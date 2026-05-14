# Phase 62: Syslog Forwarder - Pattern Map

**Mapped:** 2026-05-14
**Files analyzed:** 11
**Analogs found:** 11 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-server/src/syslog_connector.rs` | service | request-response + streaming | `dlp-server/src/siem_connector.rs` | exact |
| `dlp-server/src/db/repositories/syslog_config.rs` | repository | CRUD | `dlp-server/src/db/repositories/siem_config.rs` | exact |
| `dlp-server/src/db/repositories/syslog_queue.rs` | repository | CRUD + batch | `dlp-server/src/db/repositories/siem_config.rs` (encrypt pattern) + `dlp-server/src/db/repositories/audit_events.rs` (batch query) | role-match |
| `dlp-server/src/admin_api.rs` (add routes) | controller | request-response | `dlp-server/src/admin_api.rs` siem-config handlers | exact |
| `dlp-server/src/db/mod.rs` (add tables) | config | schema | `dlp-server/src/db/mod.rs` existing tables | exact |
| `dlp-server/src/main.rs` (add to AppState) | config | wiring | `dlp-server/src/main.rs` siem/alert init | exact |
| `dlp-server/src/lib.rs` (add to AppState) | config | wiring | `dlp-server/src/lib.rs` AppState | exact |
| `dlp-server/src/audit_store.rs` (integration) | controller | event-driven | `dlp-server/src/audit_store.rs` SIEM spawn | exact |
| `dlp-agent/src/syslog_queue.rs` | service | CRUD + batch | `dlp-server/src/db/repositories/siem_config.rs` (encrypt pattern) | role-match |
| `dlp-agent/src/audit_emitter.rs` (integration) | service | event-driven | `dlp-agent/src/audit_emitter.rs` AUDIT_BUFFER enqueue | exact |
| `dlp-admin-cli/src/screens/syslog_config.rs` | component | request-response | `dlp-admin-cli/src/screens/dispatch.rs` + `render.rs` siem_config | exact |
| `dlp-admin-cli/src/app.rs` (add Screen variant) | config | wiring | `dlp-admin-cli/src/app.rs` Screen::SiemConfig | exact |

## Pattern Assignments

### `dlp-server/src/syslog_connector.rs` (service, request-response + streaming)

**Analog:** `dlp-server/src/siem_connector.rs`

**Imports pattern** (lines 15-26):
```rust
use std::sync::Arc;

use dlp_common::AuditEvent;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::crypto::SecretCrypto;
use crate::db;
use crate::db::repositories::SiemConfigRepository;
use crate::AppError;
```

**Struct pattern** (lines 82-99):
```rust
#[derive(Clone)]
pub struct SiemConnector {
    pool: Arc<db::Pool>,
    crypto: Arc<SecretCrypto>,
    client: Client,
}

impl std::fmt::Debug for SiemConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiemConnector")
            .field("pool", &self.pool)
            .field("crypto", &"<SecretCrypto>")
            .field("client", &self.client)
            .finish()
    }
}
```

**Error type pattern** (lines 109-157):
```rust
#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    #[error("SIEM HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("SIEM serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("SIEM config DB error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("SIEM backend returned {status}: {body}")]
    BackendError { status: u16, body: String },
}

impl From<r2d2::Error> for SiemError {
    fn from(e: r2d2::Error) -> Self {
        SiemError::Database(rusqlite::Error::InvalidParameterName(format!("pool error: {e}")))
    }
}

impl SiemError {
    fn from_app_error(e: AppError) -> Self {
        match e {
            AppError::Database(db) => SiemError::Database(db),
            other => SiemError::Database(rusqlite::Error::InvalidParameterName(format!(
                "siem config load: {other}"
            ))),
        }
    }
}
```

**Hot-reload config + fire-and-forget core pattern** (lines 159-268):
```rust
impl SiemConnector {
    pub fn new(pool: Arc<db::Pool>, crypto: Arc<SecretCrypto>) -> Self {
        Self { pool, crypto, client: Client::new() }
    }

    fn load_config(&self) -> Result<SiemConfigRow, SiemError> {
        let repo_row = SiemConfigRepository::get(&self.pool, &self.crypto)
            .map_err(SiemError::from_app_error)?;
        // ... map repo row to internal row
        Ok(SiemConfigRow { /* ... */ })
    }

    pub async fn relay_events(&self, events: &[AuditEvent]) -> Result<(), SiemError> {
        if events.is_empty() { return Ok(()); }
        let row = self.load_config()?;
        let mut errors: Vec<SiemError> = Vec::new();
        // ... attempt each backend, collect errors
        if let Some(e) = errors.into_iter().next() { return Err(e); }
        Ok(())
    }
}
```

**Test pattern** (lines 356-472):
- `migrated_pool_and_crypto()` helper builds temp pool + KEK
- Tests for debug redaction, empty slice short-circuit, config round-trip

---

### `dlp-server/src/db/repositories/syslog_config.rs` (repository, CRUD)

**Analog:** `dlp-server/src/db/repositories/siem_config.rs`

**Imports pattern** (lines 19-24):
```rust
use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::{aad_for, Envelope, SecretCrypto};
use crate::db::{Pool, UnitOfWork};
use crate::AppError;
```

**Single-row config table pattern** (lines 49-77):
```rust
#[derive(Debug, Clone)]
pub struct SiemConfigRow {
    pub splunk_url: String,
    pub splunk_token: Option<SecretString>,
    pub splunk_enabled: i64,
    // ... etc
    pub updated_at: String,
}

pub struct SiemConfigRepository;

impl SiemConfigRepository {
    pub fn get(pool: &Pool, crypto: &SecretCrypto) -> Result<SiemConfigRow, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let raw: SiemRawRow = conn
            .query_row(
                "SELECT splunk_url, splunk_token_encrypted, splunk_token_nonce, \
                 splunk_enabled, elk_url, elk_index, \
                 elk_api_key_encrypted, elk_api_key_nonce, \
                 elk_enabled, updated_at \
                 FROM siem_config WHERE id = 1",
                [],
                |row| { Ok((row.get(0)?, row.get(1)?, /* ... */)) },
            )
            .map_err(AppError::Database)?;
        // decrypt_optional for each secret column
        Ok(SiemConfigRow { /* ... */ })
    }

    pub fn update(uow: &UnitOfWork<'_>, record: &SiemConfigRow, crypto: &SecretCrypto)
        -> Result<(), AppError> {
        let (splunk_ct, splunk_nonce, splunk_ver) = encrypt_optional(
            "siem_config", "splunk_token", record.splunk_token.as_ref(), crypto)?;
        // ... same for elk_api_key
        uow.tx.execute(
            "UPDATE siem_config SET splunk_url = ?1, ... WHERE id = 1",
            params![/* ... */],
        ).map_err(AppError::Database)?;
        Ok(())
    }
}
```

**encrypt_optional / decrypt_optional helpers** (lines 246-310):
- `decrypt_optional(table, column, ciphertext, nonce, crypto)` returns `Result<Option<SecretString>, AppError>`
- `encrypt_optional(table, column, plaintext, crypto)` returns `Result<EncryptedTriple, AppError>`
- Both use `aad_for(table, column)` for per-column AAD binding

---

### `dlp-server/src/db/repositories/syslog_queue.rs` (repository, CRUD + batch)

**Analog:** `dlp-server/src/db/repositories/siem_config.rs` (encrypt pattern) + `dlp-server/src/db/repositories/audit_events.rs` (batch insert/query)

**Core queue pattern** (from RESEARCH.md Pattern 3, adapted from `crypto/mod.rs`):
```rust
// Server-side: KEK-encrypted
pub fn enqueue(
    uow: &UnitOfWork,
    event_json: &str,
    crypto: &SecretCrypto,
) -> Result<(), AppError> {
    let aad = aad_for("syslog_queue", "event_json");
    let envelope = crypto.encrypt(event_json.as_bytes(), &aad)?;
    uow.tx.execute(
        "INSERT INTO syslog_queue (event_json_encrypted, event_json_nonce, created_at, retry_count) \
         VALUES (?1, ?2, ?3, 0)",
        params![envelope.ciphertext, envelope.nonce.as_slice(), Utc::now().to_rfc3339()],
    )?;
    Ok(())
}
```

**Drain pattern** (from `audit_events.rs` batch query):
```rust
// SELECT oldest N rows, decrypt, delete on success
let rows = conn.prepare(
    "SELECT id, event_json_encrypted, event_json_nonce FROM syslog_queue \
     ORDER BY created_at LIMIT ?"
)?;
```

---

### `dlp-server/src/admin_api.rs` (controller, request-response)

**Analog:** `dlp-server/src/admin_api.rs` siem-config handlers (lines 1380-1491)

**GET handler pattern** (lines 1390-1422):
```rust
async fn get_siem_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        SiemConfigRepository::get(&pool, &crypto)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Mask secrets on output
    let splunk_token_out = if row.splunk_token.is_some() {
        ALERT_SECRET_MASK.to_string()
    } else {
        String::new()
    };

    Ok(Json(SiemConfigPayload { /* ... masked fields ... */ }))
}
```

**PUT handler pattern** (lines 1435-1491):
```rust
async fn update_siem_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SiemConfigPayload>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let existing = SiemConfigRepository::get(&pool, &crypto).ok();
        let splunk_token = resolve_secret_field(
            p.splunk_token.as_str(),
            existing.as_ref().and_then(|r| r.splunk_token.clone()),
        );
        // ... build record, update, commit
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Re-mask response
    let mut masked = payload;
    if !masked.splunk_token.is_empty() {
        masked.splunk_token = ALERT_SECRET_MASK.to_string();
    }
    Ok(Json(masked))
}
```

**Route registration pattern** (from grep, lines 872-873):
```rust
.route("/admin/siem-config", get(get_siem_config_handler))
.route("/admin/siem-config", put(update_siem_config_handler))
```

**Test alert pattern** (from alert_router, lines 337-371):
```rust
pub async fn send_test_alert(&self) -> Result<(), AlertError> {
    let event = AuditEvent {
        timestamp: chrono::Utc::now(),
        event_type: dlp_common::EventType::Alert,
        // ... synthetic fields
        ..Default::default() // or explicit fields
    };
    self.send_alert(&event).await
}
```

---

### `dlp-server/src/db/mod.rs` (config, schema)

**Analog:** `dlp-server/src/db/mod.rs` existing tables

**CREATE TABLE pattern** (lines 170-181):
```rust
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

**Index pattern** (from labels/approvals examples):
```rust
CREATE INDEX IF NOT EXISTS idx_syslog_queue_created_at ON syslog_queue(created_at);
```

---

### `dlp-server/src/main.rs` + `lib.rs` (config, wiring)

**Analog:** `dlp-server/src/main.rs` siem/alert init + `lib.rs` AppState

**AppState addition pattern** (`lib.rs` lines 39-62):
```rust
#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<db::Pool>,
    pub crypto: Arc<crypto::SecretCrypto>,
    pub policy_store: Arc<PolicyStore>,
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,
    pub ad: Option<AdClient>,
    pub label_service: Arc<label_service::LabelService>,
    pub approval_token_service: Arc<approval_token::ApprovalTokenService>,
    // ADD: pub syslog: syslog_connector::SyslogConnector,
}
```

**Main init pattern** (`main.rs` lines 204-214):
```rust
let siem = SiemConnector::new(Arc::clone(&pool), Arc::clone(&crypto));
let alert = AlertRouter::new(Arc::clone(&pool), Arc::clone(&crypto));
// ADD: let syslog = SyslogConnector::new(Arc::clone(&pool), Arc::clone(&crypto));
```

---

### `dlp-server/src/audit_store.rs` (controller, event-driven)

**Analog:** `dlp-server/src/audit_store.rs` SIEM spawn (lines 207-214)

**Fire-and-forget integration pattern** (lines 207-214):
```rust
// Best-effort SIEM relay — fire-and-forget in a background task
let siem = state.siem.clone();
tokio::spawn(async move {
    if let Err(e) = siem.relay_events(&relay_events).await {
        tracing::warn!(error = %e, "SIEM relay failed (best-effort)");
    }
});
```

**Syslog integration** (to add after SIEM spawn):
```rust
let syslog = state.syslog.clone();
tokio::spawn(async move {
    if let Err(e) = syslog.forward(&relay_events).await {
        tracing::warn!(error = %e, "syslog forward failed (best-effort)");
    }
});
```

---

### `dlp-agent/src/syslog_queue.rs` (service, CRUD + batch)

**Analog:** `dlp-server/src/db/repositories/siem_config.rs` (encrypt pattern) + `dlp-agent/src/audit_emitter.rs`

**Agent-side DPAPI encrypt pattern** (from RESEARCH.md):
```rust
#[cfg(windows)]
pub fn enqueue_dpapi(conn: &Connection, event_json: &str) -> Result<(), AppError> {
    let encrypted = dpapi_protect(event_json.as_bytes())?;
    conn.execute(
        "INSERT INTO agent_syslog_queue (event_json_dpapi, created_at, retry_count) \
         VALUES (?1, ?2, 0)",
        params![encrypted, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}
```

---

### `dlp-agent/src/audit_emitter.rs` (service, event-driven)

**Analog:** `dlp-agent/src/audit_emitter.rs` AUDIT_BUFFER enqueue (lines 345-352)

**Best-effort enqueue pattern** (lines 345-352):
```rust
#[cfg(windows)]
if let Some(buffer) = AUDIT_BUFFER.get() {
    buffer.enqueue(event.clone());
}
```

---

### `dlp-admin-cli/src/screens/syslog_config.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/dispatch.rs` + `render.rs` siem_config

**Screen variant pattern** (`app.rs` lines 607-616):
```rust
SiemConfig {
    config: serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: String,
},
```

**Dispatch handler pattern** (`dispatch.rs` lines 1044-1141):
```rust
fn handle_siem_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::SiemConfig { selected, editing, .. } => (*selected, *editing),
        _ => return,
    };
    if editing { handle_siem_config_editing(app, key, selected); }
    else { handle_siem_config_nav(app, key, selected); }
}

fn action_load_siem_config(app: &mut App) {
    match app.rt.block_on(app.client.get::<serde_json::Value>("admin/siem-config")) {
        Ok(config) => {
            app.screen = Screen::SiemConfig { config, selected: 0, editing: false, buffer: String::new() };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

fn action_save_siem_config(app: &mut App) {
    let payload = match &app.screen {
        Screen::SiemConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(app.client.put::<serde_json::Value, _>("admin/siem-config", &payload)) {
        Ok(_) => { app.set_status("SIEM config saved", StatusKind::Success); }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}
```

**Render pattern** (`render.rs` lines 1047-1112):
```rust
fn draw_siem_config(frame: &mut Frame, area: Rect, config: &serde_json::Value, selected: usize, editing: bool, buffer: &str) {
    const KEYS: [&str; 7] = ["splunk_url", "splunk_token", "splunk_enabled", "elk_url", "elk_index", "elk_api_key", "elk_enabled"];
    // ... build ListItem rows, highlight selected, draw hints
}
```

**Constants pattern** (`dispatch.rs` lines 983-999):
```rust
const SIEM_KEYS: [&str; 7] = ["splunk_url", "splunk_token", "splunk_enabled", "elk_url", "elk_index", "elk_api_key", "elk_enabled"];
const SIEM_SAVE_ROW: usize = 7;
const SIEM_BACK_ROW: usize = 8;
const SIEM_ROW_COUNT: usize = 9;
```

---

## Shared Patterns

### Authentication
**Source:** `dlp-server/src/admin_auth.rs`
**Apply to:** All admin API handlers (syslog-config GET/PUT/test)
All admin routes use `require_auth` middleware; no change needed for syslog endpoints.

### Error Handling
**Source:** `dlp-server/src/lib.rs` lines 86-204
**Apply to:** All server-side controller and service files
```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("bad request: {0}")]
    BadRequest(String),
    // ... etc
}
```

### Secret Masking (TOCTOU-safe)
**Source:** `dlp-server/src/admin_api.rs` lines 1501-1541
**Apply to:** `syslog_config` PUT handler
```rust
fn resolve_secret_field(
    incoming: &str,
    existing: Option<secrecy::SecretString>,
) -> Option<secrecy::SecretString> {
    if incoming.is_empty() { None }
    else if incoming == ALERT_SECRET_MASK { existing }
    else { Some(secrecy::SecretString::new(incoming.to_string())) }
}
```

### spawn_blocking for DB ops
**Source:** `dlp-server/src/admin_api.rs` lines 1395-1399
**Apply to:** All handlers that read/write syslog_config
```rust
let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    SyslogConfigRepository::get(&pool, &crypto)
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

### Fire-and-forget background task
**Source:** `dlp-server/src/audit_store.rs` lines 207-214
**Apply to:** `audit_store.rs` syslog integration
```rust
tokio::spawn(async move {
    if let Err(e) = syslog.forward(&events).await {
        tracing::warn!(error = %e, "syslog forward failed (best-effort)");
    }
});
```

### KEK Encryption (server-side queue)
**Source:** `dlp-server/src/crypto/mod.rs` lines 136-156
**Apply to:** `syslog_queue.rs` enqueue
```rust
pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Envelope, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(self.kek.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::EncryptFailed)?;
    let nonce_arr: [u8; envelope::NONCE_LEN] = nonce.into();
    Envelope::new(self.version, nonce_arr, ciphertext)
}
```

### DPAPI Encryption (agent-side queue)
**Source:** `dlp-server/src/crypto/dpapi.rs` (re-exported in `crypto/mod.rs` line 56)
**Apply to:** `dlp-agent/src/syslog_queue.rs`
```rust
#[cfg(windows)]
pub use dpapi::{dpapi_protect, dpapi_unprotect, MachineSecret};
```

### RFC 5424 Formatting
**Source:** `62-RESEARCH.md` Pattern 2
**Apply to:** `syslog_connector.rs`
```rust
fn format_rfc5424(event: &AuditEvent, config: &SyslogConfigRow, hostname: &str, procid: &str)
    -> Result<String, SyslogError> {
    let severity = map_severity(event.event_type, &config.severity_mapping);
    let priority = config.facility_code * 8 + severity;
    let timestamp = event.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let msgid = event_type_to_msgid(event.event_type);
    let json_payload = serde_json::to_string(event)?;
    Ok(format!(
        "<{priority}>1 {timestamp} {hostname} DLP-AUDIT {procid} {msgid} - {json_payload}\n"
    ))
}
```

### TLS Client Config
**Source:** `62-RESEARCH.md` Code Examples
**Apply to:** `syslog_connector.rs`
```rust
fn build_tls_config() -> Result<ClientConfig, SyslogError> {
    let mut root_store = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs()
        .map_err(|e| SyslogError::Tls(format!("failed to load native certs: {e}")))?;
    for cert in native_certs { root_store.add(cert)?; }
    if root_store.is_empty() {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(config)
}
```

## No Analog Found

No files with no close match — all Phase 62 files have strong analogs in the existing codebase.

## Metadata

**Analog search scope:**
- `dlp-server/src/` (all .rs files)
- `dlp-admin-cli/src/screens/` (all .rs files)
- `dlp-agent/src/` (audit_emitter.rs)
- `dlp-common/src/audit.rs`

**Files scanned:** 30+
**Pattern extraction date:** 2026-05-14
