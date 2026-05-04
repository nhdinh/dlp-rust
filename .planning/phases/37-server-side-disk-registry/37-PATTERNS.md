# Phase 37: Server-Side Disk Registry - Pattern Map

**Mapped:** 2026-05-04
**Files analyzed:** 8 new/modified files
**Analogs found:** 8 / 8

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dlp-common/src/abac.rs` | model (enum extension) | — | `dlp-common/src/abac.rs` (existing `Action` enum) | exact |
| `dlp-server/src/db/repositories/disk_registry.rs` | repository | CRUD | `dlp-server/src/db/repositories/device_registry.rs` | exact |
| `dlp-server/src/db/repositories/mod.rs` | config | — | `dlp-server/src/db/repositories/mod.rs` (existing) | exact |
| `dlp-server/src/db/mod.rs` | config (schema) | — | `dlp-server/src/db/mod.rs` (`init_tables`) | exact |
| `dlp-server/src/admin_api.rs` | controller | request-response | `dlp-server/src/admin_api.rs` (device-registry handlers) | exact |
| `dlp-agent/src/server_client.rs` | model (struct extension) | request-response | `dlp-agent/src/server_client.rs` (existing `AgentConfigPayload`) | exact |
| `dlp-agent/src/service.rs` | service | event-driven | `dlp-agent/src/service.rs` (`config_poll_loop` macro) | exact |
| `dlp-agent/src/detection/disk.rs` | service | event-driven | `dlp-agent/src/detection/disk.rs` (`instance_id_map` writes) | exact |

---

## Pattern Assignments

### `dlp-common/src/abac.rs` — Add `DiskRegistryAdd` / `DiskRegistryRemove` to `Action` enum

**Analog:** same file, lines 11-33

**Existing enum tail** (lines 26-33):
```rust
    /// Admin changed own password via the admin API.
    PasswordChange,
}
```

**Target edit — insert two variants after `PasswordChange`:**
```rust
    /// Admin changed own password via the admin API.
    PasswordChange,
    /// Admin added a disk to the server-side disk allowlist (Phase 37).
    DiskRegistryAdd,
    /// Admin removed a disk from the server-side disk allowlist (Phase 37).
    DiskRegistryRemove,
}
```

**No other changes to `abac.rs`.** The enum derives `Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default` — all of these continue to work after adding plain unit variants.

---

### `dlp-server/src/db/repositories/disk_registry.rs` — New repository file

**Analog:** `dlp-server/src/db/repositories/device_registry.rs` (entire file, lines 1-319)

**Imports pattern** (from analog, lines 1-10):
```rust
//! Repository for the `disk_registry` table.
use rusqlite::params;
use crate::db::{Pool, UnitOfWork};
```

**Row struct** (adapt `DeviceRegistryRow` lines 14-29 — swap fields):
```rust
/// Plain data row returned by disk registry reads.
#[derive(Debug, Clone)]
pub struct DiskRegistryRow {
    pub id: String,
    pub agent_id: String,
    pub instance_id: String,
    pub bus_type: String,
    pub encryption_status: String,
    pub model: String,
    pub registered_at: String,
}
```

**Repository struct declaration** (copy line 36 verbatim, rename):
```rust
pub struct DiskRegistryRepository;
```

**`list_all` with optional agent_id filter** (adapted from `DeviceRegistryRepository::list_all` lines 48-70 — add filter branching):
```rust
pub fn list_all(
    pool: &Pool,
    agent_id_filter: Option<&str>,
) -> rusqlite::Result<Vec<DiskRegistryRow>> {
    let conn = pool
        .get()
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    match agent_id_filter {
        None => {
            let mut stmt = conn.prepare(
                "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, registered_at \
                 FROM disk_registry ORDER BY registered_at ASC",
            )?;
            let rows = stmt.query_map([], |row| Ok(DiskRegistryRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                instance_id: row.get(2)?,
                bus_type: row.get(3)?,
                encryption_status: row.get(4)?,
                model: row.get(5)?,
                registered_at: row.get(6)?,
            }))?;
            rows.collect()
        }
        Some(id) => {
            let mut stmt = conn.prepare(
                "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, registered_at \
                 FROM disk_registry WHERE agent_id = ?1 ORDER BY registered_at ASC",
            )?;
            let rows = stmt.query_map(params![id], |row| Ok(DiskRegistryRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                instance_id: row.get(2)?,
                bus_type: row.get(3)?,
                encryption_status: row.get(4)?,
                model: row.get(5)?,
                registered_at: row.get(6)?,
            }))?;
            rows.collect()
        }
    }
}
```

**`list_by_agent`** (convenience method for `get_agent_config_for_agent` — wraps `list_all` with `Some`):
```rust
pub fn list_by_agent(pool: &Pool, agent_id: &str) -> rusqlite::Result<Vec<DiskRegistryRow>> {
    Self::list_all(pool, Some(agent_id))
}
```

**`insert` — pure INSERT, NOT `ON CONFLICT DO UPDATE`** (NEVER copy `DeviceRegistryRepository::upsert` lines 88-107; write fresh SQL):
```rust
pub fn insert(uow: &UnitOfWork<'_>, row: &DiskRegistryRow) -> rusqlite::Result<()> {
    uow.tx.execute(
        "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.id,
            row.agent_id,
            row.instance_id,
            row.bus_type,
            row.encryption_status,
            row.model,
            row.registered_at,
        ],
    )?;
    Ok(())
}
```

**`delete_by_id`** (copy `DeviceRegistryRepository::delete_by_id` lines 165-168 verbatim, change table name):
```rust
pub fn delete_by_id(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> {
    uow.tx.execute("DELETE FROM disk_registry WHERE id = ?1", params![id])
}
```

**Test module structure** (copy `#[cfg(test)]` module from `device_registry.rs` lines 171-318):

- `make_pool()` helper — `new_pool(":memory:")` identical
- `make_row()` helper — adapt field names to `DiskRegistryRow`
- `test_list_all_empty` — verbatim structure, rename table/type
- `test_insert_and_list` — use `insert` not `upsert`; verify 409 path via `insert` returning `Err`
- `test_unique_constraint` — verify second insert on same `(agent_id, instance_id)` returns `Err` containing `"UNIQUE constraint failed"`
- `test_check_constraint` — INSERT with `encryption_status = 'bad_value'` must return `Err` containing `"CHECK constraint failed"`
- `test_delete_by_id_removes_row` — copy lines 281-303 verbatim, change table/type
- `test_delete_by_id_nonexistent_returns_zero` — copy lines 305-317 verbatim, change table/type

---

### `dlp-server/src/db/repositories/mod.rs` — Add `disk_registry` module declaration

**Analog:** same file, lines 1-30

**Exact additions to make** (after line 12 `pub mod device_registry;`, after line 25 `pub use device_registry::...`):
```rust
pub mod disk_registry;
// ...
pub use disk_registry::{DiskRegistryRepository, DiskRegistryRow};
```

---

### `dlp-server/src/db/mod.rs` — Add `disk_registry` table DDL to `init_tables`

**Analog:** same file, lines 139-151 (`device_registry` block inside `init_tables`)

**Insertion point:** Append after the `managed_origins` block (line 228), still inside the `execute_batch` string, before the closing `"`):
```sql
-- disk_registry: server-side disk allowlist managed by dlp-admin.
-- Entries are scoped per (agent_id, instance_id) pair — a disk allowed on
-- machine-A is NOT allowed on machine-B (physical relocation attack prevention).
-- UNIQUE(agent_id, instance_id) enforces one allowlist entry per machine-disk pair.
CREATE TABLE IF NOT EXISTS disk_registry (
    id                 TEXT PRIMARY KEY,
    agent_id           TEXT NOT NULL,
    instance_id        TEXT NOT NULL,
    bus_type           TEXT NOT NULL,
    encryption_status  TEXT NOT NULL
                       CHECK(encryption_status IN
                             ('fully_encrypted', 'partially_encrypted',
                              'unencrypted', 'unknown')),
    model              TEXT NOT NULL DEFAULT '',
    registered_at      TEXT NOT NULL,
    UNIQUE(agent_id, instance_id)
);
```

**Test additions to `db/mod.rs` `#[cfg(test)]` module** (copy pattern from `test_device_registry_table_exists` lines 435-447 and `test_device_registry_check_constraint` lines 479-498):

- `test_disk_registry_table_exists` — query `sqlite_master WHERE name='disk_registry'`
- `test_disk_registry_columns` — `PRAGMA table_info(disk_registry)` checks all 7 column names
- `test_disk_registry_check_constraint` — INSERT invalid `encryption_status` must fail CHECK
- `test_disk_registry_unique_constraint` — second INSERT same `(agent_id, instance_id)` must fail UNIQUE

---

### `dlp-server/src/admin_api.rs` — New request/response types and three handlers

**Analog:** Same file — `DeviceRegistryRequest` (lines 290-302), `DeviceRegistryResponse` (lines 308-323), `From<DeviceRegistryRow>` (lines 325-337), `upsert_device_registry_handler` (lines 1617-1677), `delete_device_registry_handler` (lines 1690-1713), `list_device_registry_full_handler` (lines 1591-1602), `create_managed_origin_handler` (lines 1753-1788), `create_policy` audit block (lines 784-808).

**Imports addition** (line 25-29 block — add `DiskRegistryRepository, DiskRegistryRow` to imports):
```rust
use crate::db::repositories::{
    AgentConfigRepository, AlertRouterConfigRepository, CredentialsRepository,
    DiskRegistryRepository, DiskRegistryRow,   // Phase 37 addition
    LdapConfigRepository, ManagedOriginRow, ManagedOriginsRepository, PolicyRepository,
    SiemConfigRepository,
};
```

**`AgentConfigPayload` extension** (lines 268-277 — add field):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    pub monitored_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub offline_cache_enabled: bool,
    pub ldap_config: Option<LdapConfigPayload>,
    // Phase 37: disk allowlist scoped to this agent, queried from disk_registry table.
    // Uses serde(default) for backward compatibility with older server deployments.
    #[serde(default)]
    pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
}
```

**Request/response struct pair** (adapt `DeviceRegistryRequest` lines 290-302 and `DeviceRegistryResponse` lines 308-337 — swap fields, rename types):
```rust
/// Request body for `POST /admin/disk-registry`.
#[derive(Debug, Clone, Deserialize)]
pub struct DiskRegistryRequest {
    pub agent_id: String,
    pub instance_id: String,
    pub bus_type: String,
    /// Must be one of: `"fully_encrypted"`, `"partially_encrypted"`, `"unencrypted"`, `"unknown"`.
    pub encryption_status: String,
    #[serde(default)]
    pub model: String,
}

/// Response body returned by `GET` and `POST /admin/disk-registry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskRegistryResponse {
    pub id: String,
    pub agent_id: String,
    pub instance_id: String,
    pub bus_type: String,
    pub encryption_status: String,
    pub model: String,
    pub registered_at: String,
}

impl From<DiskRegistryRow> for DiskRegistryResponse {
    fn from(row: DiskRegistryRow) -> Self {
        Self {
            id: row.id,
            agent_id: row.agent_id,
            instance_id: row.instance_id,
            bus_type: row.bus_type,
            encryption_status: row.encryption_status,
            model: row.model,
            registered_at: row.registered_at,
        }
    }
}
```

**`list_disk_registry_handler`** (adapt `list_device_registry_full_handler` lines 1591-1602 — add `Query` extractor for optional `agent_id` filter):
```rust
#[derive(serde::Deserialize, Default)]
pub struct DiskRegistryFilter {
    pub agent_id: Option<String>,
}

async fn list_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(filter): axum::extract::Query<DiskRegistryFilter>,
) -> Result<Json<Vec<DiskRegistryResponse>>, AppError> {
    let pool = Arc::clone(&state.pool);
    let agent_id_filter = filter.agent_id.clone();
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        DiskRegistryRepository::list_all(&pool, agent_id_filter.as_deref())
            .map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    let response: Vec<DiskRegistryResponse> = rows.into_iter().map(Into::into).collect();
    Ok(Json(response))
}
```

**`insert_disk_registry_handler`** — validation pattern from `upsert_device_registry_handler` lines 1621-1635; UNIQUE conflict detection from `create_managed_origin_handler` lines 1763-1778; audit event from `create_policy` lines 784-808:
```rust
async fn insert_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, Json<DiskRegistryResponse>), AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let Json(body): Json<DiskRegistryRequest> = Json::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    // Length guard (D-12): valid values are at most 21 chars ("partially_encrypted"); 32 is generous.
    if body.encryption_status.len() > 32 {
        return Err(AppError::UnprocessableEntity(
            "encryption_status exceeds maximum length".to_string(),
        ));
    }
    // Allowlist check (D-12) — same pattern as VALID_TIERS in upsert_device_registry_handler.
    const VALID_STATUSES: &[&str] = &[
        "fully_encrypted",
        "partially_encrypted",
        "unencrypted",
        "unknown",
    ];
    if !VALID_STATUSES.contains(&body.encryption_status.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid encryption_status '{}'; must be one of: fully_encrypted, \
             partially_encrypted, unencrypted, unknown",
            body.encryption_status
        )));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let registered_at = chrono::Utc::now().to_rfc3339();
    let row = DiskRegistryRow {
        id: id.clone(),
        agent_id: body.agent_id.clone(),
        instance_id: body.instance_id.clone(),
        bus_type: body.bus_type.clone(),
        encryption_status: body.encryption_status.clone(),
        model: body.model.clone(),
        registered_at,
    };

    let pool = Arc::clone(&state.pool);
    let agent_id_for_audit = body.agent_id.clone();
    let instance_id_for_audit = body.instance_id.clone();

    // spawn_blocking — all SQLite writes must leave the async reactor (CLAUDE.md).
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        DiskRegistryRepository::insert(&uow, &row).map_err(|e| {
            // Detect UNIQUE(agent_id, instance_id) violation — same string check as
            // create_managed_origin_handler uses extended_code 2067, but string check
            // is the most robust cross-version approach per RESEARCH.md Pattern 2.
            if let rusqlite::Error::SqliteFailure(ref fe, _) = e {
                if fe.extended_code == 2067 {
                    return AppError::Conflict(format!(
                        "disk (agent_id={}, instance_id={}) already registered",
                        row.agent_id, row.instance_id
                    ));
                }
            }
            AppError::Database(e)
        })?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Second spawn_blocking for audit event (D-10) — separate transaction from DB write.
    // Audit failure MUST NOT roll back the registry change.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("disk:{}@{}", instance_id_for_audit, agent_id_for_audit),
        dlp_common::Classification::T3,
        dlp_common::Action::DiskRegistryAdd,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool2 = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool2.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(
        agent_id = %body.agent_id,
        instance_id = %body.instance_id,
        "disk registry add"
    );
    // Re-read the inserted row to build the response.
    let pool3 = Arc::clone(&state.pool);
    let resp_id = id.clone();
    let inserted = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        // NOTE: DiskRegistryRepository has no get_by_id — build inline or add helper.
        let conn = pool3.get().map_err(AppError::from)?;
        conn.query_row(
            "SELECT id, agent_id, instance_id, bus_type, encryption_status, model, registered_at \
             FROM disk_registry WHERE id = ?1",
            rusqlite::params![resp_id],
            |row| Ok(DiskRegistryRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                instance_id: row.get(2)?,
                bus_type: row.get(3)?,
                encryption_status: row.get(4)?,
                model: row.get(5)?,
                registered_at: row.get(6)?,
            }),
        )
        .map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok((StatusCode::CREATED, Json(inserted.into())))
}
```

**`delete_disk_registry_handler`** — copy `delete_device_registry_handler` lines 1690-1713 verbatim, change repository and resource name, add audit event (D-10) after rows_deleted > 0 check:
```rust
async fn delete_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,  // needed for username extraction
) -> Result<StatusCode, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let id: String = /* extract Path<String> from req */ ...;

    let pool = Arc::clone(&state.pool);
    let disk_id = id.clone();
    // Query the row BEFORE delete to capture agent_id + instance_id for audit.
    let (agent_id_for_audit, instance_id_for_audit, rows_deleted) =
        tokio::task::spawn_blocking(move || -> Result<(String, String, usize), AppError> {
            let conn = pool.get().map_err(AppError::from)?;
            // Read agent_id / instance_id before deleting (need for audit resource).
            let (aid, iid): (String, String) = conn
                .query_row(
                    "SELECT agent_id, instance_id FROM disk_registry WHERE id = ?1",
                    rusqlite::params![disk_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| {
                    if e == rusqlite::Error::QueryReturnedNoRows {
                        AppError::NotFound(format!("disk entry {disk_id} not found"))
                    } else {
                        AppError::Database(e)
                    }
                })?;
            drop(conn); // release read conn before write
            let mut write_conn = pool.get().map_err(AppError::from)?;
            let uow = db::UnitOfWork::new(&mut write_conn).map_err(AppError::Database)?;
            let n = DiskRegistryRepository::delete_by_id(&uow, &disk_id)
                .map_err(AppError::Database)?;
            uow.commit().map_err(AppError::Database)?;
            Ok((aid, iid, n))
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows_deleted == 0 {
        return Err(AppError::NotFound(format!("disk entry {id} not found")));
    }

    // Second spawn_blocking for audit (D-10) — separate from delete transaction.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("disk:{}@{}", instance_id_for_audit, agent_id_for_audit),
        dlp_common::Classification::T3,
        dlp_common::Action::DiskRegistryRemove,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool2 = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool2.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(
        agent_id = %agent_id_for_audit,
        instance_id = %instance_id_for_audit,
        "disk registry remove"
    );
    Ok(StatusCode::NO_CONTENT)
}
```

**`get_agent_config_for_agent` extension** (lines 1247-1280 — add `disk_allowlist` field to both `AgentConfigPayload` constructions):
```rust
// In both the override branch and the global-fallback branch, add:
disk_allowlist: DiskRegistryRepository::list_by_agent(&pool, &id)
    .unwrap_or_default()
    .into_iter()
    .map(|r| dlp_common::DiskIdentity {
        instance_id: r.instance_id,
        bus_type: r.bus_type.parse().unwrap_or_default(),
        // model, drive_letter, is_boot_disk, encryption_status filled from row
        // (see DiskIdentity fields from dlp-common)
    })
    .collect(),
```

**Route wiring addition in `admin_router`** (after line 613 `delete(delete_device_registry_handler)`):
```rust
// Phase 37: disk registry endpoints (all JWT-protected)
.route(
    "/admin/disk-registry",
    get(list_disk_registry_handler).post(insert_disk_registry_handler),
)
.route(
    "/admin/disk-registry/{id}",
    delete(delete_disk_registry_handler),
)
```

---

### `dlp-agent/src/server_client.rs` — Extend `AgentConfigPayload` with `disk_allowlist`

**Analog:** Same file, lines 118-132

**Current struct** (lines 118-132):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    pub monitored_paths: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub offline_cache_enabled: bool,
    pub ldap_config: Option<LdapConfigPayload>,
}
```

**Target edit — add field at end of struct:**
```rust
    /// Disk allowlist scoped to this agent, pushed from the server-side disk_registry table.
    /// Defaults to empty for backward compatibility when connecting to an older server.
    #[serde(default)]
    pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
```

---

### `dlp-agent/src/service.rs` — Extend `config_poll_loop` to apply `disk_allowlist`

**Analog:** Same file, lines 244-335 (`do_poll!` macro body)

**Insertion point:** After the `excluded_paths` diff block (lines 274-278), still inside the `{ let mut cfg = config.lock(); ... }` scope:
```rust
// Phase 37 (D-03): apply server-pushed disk allowlist.
// Only apply if the payload contains entries (non-empty or changed).
// The diff compares the raw string lists; duplicate-free by UNIQUE DB constraint.
let server_instance_ids: Vec<String> = payload
    .disk_allowlist
    .iter()
    .map(|d| d.instance_id.clone())
    .collect();
let local_instance_ids: Vec<String> = cfg
    .disk_allowlist
    .iter()
    .map(|d| d.instance_id.clone())
    .collect();
if server_instance_ids != local_instance_ids {
    changed_fields.push("disk_allowlist");
    cfg.disk_allowlist = payload.disk_allowlist.clone();
    // Update the in-memory enforcement map (DiskEnumerator.instance_id_map).
    // Must hold only the enumerator lock, not the config lock, to avoid
    // lock-order inversions with Phase 36 enforcement code.
    drop(cfg); // release config lock before acquiring enumerator lock
    if let Some(enumerator) = crate::detection::disk::get_disk_enumerator() {
        let mut instance_map = enumerator.instance_id_map.write();
        // Remove entries that were in the previous allowlist but absent now.
        for id in &local_instance_ids {
            if !server_instance_ids.contains(id) {
                instance_map.remove(id);
            }
        }
        // Insert new entries from the server allowlist.
        for disk in &payload.disk_allowlist {
            instance_map
                .entry(disk.instance_id.clone())
                .or_insert_with(|| disk.clone());
        }
    }
    // Re-acquire config lock to write-back TOML.
    let mut cfg = config.lock();
    // cfg.disk_allowlist was already updated above before drop.
    // save() below will persist it.
}
```

**TOML persist** — the existing `cfg.save(config_path)` call at lines 289-296 covers the new field automatically because `AgentConfig` derives `Serialize` and `disk_allowlist` is a `Vec<DiskIdentity>` that serializes as a TOML array of tables.

---

## Shared Patterns

### `spawn_blocking` + `UnitOfWork` for all writes
**Source:** `dlp-server/src/admin_api.rs` lines 1657-1673 (`upsert_device_registry_handler`)
**Apply to:** `insert_disk_registry_handler`, `delete_disk_registry_handler`
```rust
tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    {
        // Explicit scope: pooled connection returned before re-acquire below.
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        // ... write ...
        uow.commit().map_err(AppError::Database)?;
    } // conn dropped here — returns to pool
    // optional re-read here
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

### Two-`spawn_blocking` audit pattern
**Source:** `dlp-server/src/admin_api.rs` lines 784-808 (`create_policy`)
**Apply to:** `insert_disk_registry_handler` (Action::DiskRegistryAdd), `delete_disk_registry_handler` (Action::DiskRegistryRemove)
```rust
// AFTER first spawn_blocking's uow.commit() completes:
let audit_event = dlp_common::AuditEvent::new(
    dlp_common::EventType::AdminAction,
    String::new(),               // session_id: N/A for server-side admin ops
    username,
    format!("disk:{}@{}", instance_id, agent_id),
    dlp_common::Classification::T3,
    dlp_common::Action::DiskRegistryAdd,  // or DiskRegistryRemove
    dlp_common::Decision::ALLOW,
    "server".to_string(),
    0,
);
let pool2 = Arc::clone(&state.pool);
tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    let mut conn = pool2.get().map_err(AppError::from)?;
    let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
    audit_store::store_events_sync(&uow, &[audit_event])?;
    uow.commit().map_err(AppError::Database)?;
    Ok(())
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

### Validation — length guard + const allowlist
**Source:** `dlp-server/src/admin_api.rs` lines 1621-1635 (`upsert_device_registry_handler`)
**Apply to:** `insert_disk_registry_handler`
```rust
if body.encryption_status.len() > 32 {
    return Err(AppError::UnprocessableEntity("...".to_string()));
}
const VALID_STATUSES: &[&str] = &[
    "fully_encrypted", "partially_encrypted", "unencrypted", "unknown",
];
if !VALID_STATUSES.contains(&body.encryption_status.as_str()) {
    return Err(AppError::UnprocessableEntity(format!("invalid encryption_status '{}'...", body.encryption_status)));
}
```

### UNIQUE conflict detection
**Source:** `dlp-server/src/admin_api.rs` lines 1766-1774 (`create_managed_origin_handler`)
**Apply to:** `insert_disk_registry_handler`
```rust
.map_err(|e| {
    if let rusqlite::Error::SqliteFailure(ref fe, _) = e {
        if fe.extended_code == 2067 {
            return AppError::Conflict("...".to_string());
        }
    }
    AppError::Database(e)
})?;
```

### AdminUsername extraction
**Source:** `dlp-server/src/admin_api.rs` line 732 (`create_policy`)
**Apply to:** `insert_disk_registry_handler`, `delete_disk_registry_handler`
```rust
let username = AdminUsername::extract_from_headers(req.headers())?;
```

### JWT protected route placement
**Source:** `dlp-server/src/admin_api.rs` lines 552-624 (`protected_routes`)
**Apply to:** All three disk-registry routes — placed inside `protected_routes`, NOT `public_routes`. The USB `GET /admin/device-registry` is public (line 546) but disk allowlist data is more sensitive; per D-07 all three disk-registry endpoints are JWT-protected.

### Pool connection scope guard
**Source:** `dlp-server/src/admin_api.rs` lines 1658-1668 — mandatory explicit `{ }` block
**Apply to:** Any `spawn_blocking` closure that acquires two connections (write then read).
```rust
tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    {
        let mut conn = pool.get().map_err(AppError::from)?;
        // ... write ...
    } // conn DROPPED here — returns to pool before re-acquire
    let conn2 = pool.get()...;
    // ... read ...
})
```

---

## No Analog Found

All files in this phase have direct analogs. No entries.

---

## Critical Anti-Patterns (do not copy)

| What to avoid | Why | Correct source |
|---|---|---|
| `DeviceRegistryRepository::upsert` (lines 88-107) | Uses `ON CONFLICT DO UPDATE`; violates D-05 | Write fresh `INSERT` SQL with no conflict clause |
| `GET /admin/device-registry` in `public_routes` (line 546) | Disk allowlist is sensitive; must be JWT-protected | Place in `protected_routes` |
| Single `spawn_blocking` for both registry write and audit | Audit failure would roll back registry change (violates D-10) | Two separate `spawn_blocking` + `UnitOfWork` calls |
| Replacing `instance_id_map` wholesale in agent | Loses live-enumerated disks not in server registry | Merge: add new entries, remove only entries absent from new allowlist |

---

## Metadata

**Analog search scope:** `dlp-server/src/`, `dlp-agent/src/`, `dlp-common/src/`
**Files scanned:** 8 source files read directly (device_registry.rs, db/mod.rs, admin_api.rs, db/repositories/mod.rs, abac.rs, server_client.rs, service.rs, detection/disk.rs)
**Pattern extraction date:** 2026-05-04
