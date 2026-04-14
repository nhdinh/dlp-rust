---
wave: 1
depends_on:
  - "01-ad-client-crate"
requirements:
  - R-05
files_modified:
  - dlp-server/src/db.rs
  - dlp-server/src/admin_api.rs
  - dlp-server/Cargo.toml
autonomous: false
---

# Plan 02: DB Schema + Admin API (`dlp-server`)

## Goal

Add the `ldap_config` SQLite table and `GET/PUT /admin/ldap-config` admin API handlers to `dlp-server`, following the identical pattern used for `siem_config` (Phase 3.1) and `alert_router_config` (Phase 4).

---

## must_haves

- `ldap_config` table created on DB init with `CHECK (id = 1)` and `INSERT OR IGNORE` seed row
- `GET /admin/ldap-config` (JWT required) returns current LDAP config as JSON
- `PUT /admin/ldap-config` (JWT required) updates the LDAP config in the DB and returns the updated record
- Both handlers follow the exact same guard and response pattern as `GET/PUT /admin/siem-config`
- `dlp-server` builds without warnings or errors
- Unit tests verify table creation and seed row

---

## Tasks

### Task 1: Cargo dependencies (`dlp-server/Cargo.toml`)

<read_first>
`dlp-server/Cargo.toml`
</read_first>

<action>
Verify that `dlp-server/Cargo.toml` already contains `ldap3 = "0.11"` in its `[dependencies]` section. If not present, add it. Also verify `dlp-server` does NOT need `ipnetwork` directly — it only stores the config string; the agent parses it.
</action>

<acceptance_criteria>
- If `ldap3` is added to `dlp-server/Cargo.toml`, it uses version `"0.11"`
- `cargo build -p dlp-server --lib` compiles without ldap3-related errors
</acceptance_criteria>

---

### Task 2: DB schema — add `ldap_config` table (`dlp-server/src/db.rs`)

<read_first>
`dlp-server/src/db.rs` — full file (entire file)
</read_first>

<action>
In `dlp-server/src/db.rs`'s `init_tables()` function, add the following SQL block to the `conn.execute_batch(...)` call inside `init_tables`. Place it after the `alert_router_config` block and before `agent_config_overrides`:

```sql
CREATE TABLE IF NOT EXISTS ldap_config (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    ldap_url         TEXT NOT NULL DEFAULT 'ldaps://dc.corp.internal:636',
    base_dn          TEXT NOT NULL DEFAULT '',
    require_tls      INTEGER NOT NULL DEFAULT 1,
    cache_ttl_secs   INTEGER NOT NULL DEFAULT 300,
    vpn_subnets      TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO ldap_config (id) VALUES (1);
```

The SQL must be added as a continuation of the existing `conn.execute_batch(...)` string (there is no separate call — add it as another SQL statement in the existing batch string).
</action>

<acceptance_criteria>
- `dlp-server/src/db.rs` contains `CREATE TABLE IF NOT EXISTS ldap_config`
- `dlp-server/src/db.rs` contains `INSERT OR IGNORE INTO ldap_config (id) VALUES (1)`
- `dlp-server/src/db.rs` contains `CHECK (id = 1)` for the `ldap_config` table
- `grep -n "ldap_config" dlp-server/src/db.rs` returns at least 3 lines
</acceptance_criteria>

---

### Task 3: Unit test for `ldap_config` table seed row (`dlp-server/src/db.rs`)

<read_first>
`dlp-server/src/db.rs` — bottom of file (tests module)
</read_first>

<action>
In the `#[cfg(test)]` module at the bottom of `db.rs`, add a new test function:

```rust
#[test]
fn test_ldap_config_seed_row() {
    let db = Database::open(":memory:").expect("open in-memory db");
    let conn = db.conn().lock();

    // Table must exist.
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type='table' AND name='ldap_config'",
        )
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .filter_map(|r| r.ok())
        .collect();
    assert!(
        tables.contains(&"ldap_config".to_string()),
        "ldap_config table must exist after init"
    );

    // Seed row must exist.
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ldap_config", [], |r| r.get(0))
        .expect("count ldap_config rows");
    assert_eq!(count, 1, "ldap_config must have exactly one seed row");

    // Defaults: TLS required, 5-minute cache.
    let (ldap_url, base_dn, require_tls, cache_ttl_secs): (String, String, i64, i64) = conn
        .query_row(
            "SELECT ldap_url, base_dn, require_tls, cache_ttl_secs \
             FROM ldap_config WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("read seed row");
    assert_eq!(ldap_url, "ldaps://dc.corp.internal:636", "default ldap_url");
    assert_eq!(require_tls, 1, "require_tls default must be 1");
    assert_eq!(cache_ttl_secs, 300, "cache_ttl_secs default must be 300");
    assert_eq!(base_dn, "", "default base_dn must be empty string");
}
```
</action>

<acceptance_criteria>
- `cargo test -p dlp-server -- db::tests::test_ldap_config_seed_row` → exit code 0 (test passes)
- `grep -n "test_ldap_config_seed_row" dlp-server/src/db.rs` returns the test function
</acceptance_criteria>

---

### Task 4: `GET /admin/ldap-config` handler (`dlp-server/src/admin_api.rs`)

<read_first>
`dlp-server/src/admin_api.rs` — first 120 lines (module doc, imports, AppState, error types)
`dlp-server/src/admin_api.rs` — look for `siem_config` GET handler pattern (search for "siem_config" or "GET /admin/siem")
</read_first>

<action>
In `dlp-server/src/admin_api.rs`, add the following types and handler:

**Step A**: Add a new request/response struct near the top of the file (after `AlertRouterConfigPayload` if it exists, or in the types section):

```rust
/// LDAP connection configuration stored in the DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfigPayload {
    pub ldap_url: String,
    pub base_dn: String,
    pub require_tls: bool,
    pub cache_ttl_secs: u64,
    pub vpn_subnets: String,
}
```

**Step B**: Add a `GET /admin/ldap-config` handler in the same file. Find the section that handles `GET /admin/siem-config` and add a matching handler. The handler should:
- Accept `State(state): State<Arc<AppState>>`
- Call `tokio::task::spawn_blocking` to query the DB
- Query `SELECT ldap_url, base_dn, require_tls, cache_ttl_secs, vpn_subnets FROM ldap_config WHERE id = 1`
- Map `require_tls` (INTEGER 0/1) to bool
- Return `Json(ldap_config_payload)` with HTTP 200
- On DB error: return `Err(AppError::Database(e))`

```rust
/// GET /admin/ldap-config — returns current LDAP connection configuration.
async fn get_ldap_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<LdapConfigPayload>, AppError> {
    let config = tokio::task::spawn_blocking({
        let conn = state.db.conn().lock();
        conn.query_row(
            "SELECT ldap_url, base_dn, require_tls, cache_ttl_secs, vpn_subnets \
             FROM ldap_config WHERE id = 1",
            [],
            |row| {
                Ok(LdapConfigPayload {
                    ldap_url: row.get(0)?,
                    base_dn: row.get(1)?,
                    require_tls: row.get::<_, i64>(2)? != 0,
                    cache_ttl_secs: row.get::<_, i64>(3)? as u64,
                    vpn_subnets: row.get(4)?,
                })
            },
        )
        .map_err(AppError::Database)
    })
    .await
    .map_err(AppError::Internal)?
    .map_err(AppError::Database)?;

    Ok(Json(config))
}
```

**Step C**: Add the route to the router in the `admin_router()` function. Find where `get(siem_config)` is registered and add:
```rust
.get("/ldap-config", get(get_ldap_config))
```
</action>

<acceptance_criteria>
- `grep -n "get_ldap_config" dlp-server/src/admin_api.rs` returns the handler function
- `grep -n "LdapConfigPayload" dlp-server/src/admin_api.rs` returns the struct definition
- `grep -n "/ldap-config" dlp-server/src/admin_api.rs` returns a route registration line
- `grep -n "pub struct LdapConfigPayload" dlp-server/src/admin_api.rs` returns the struct
</acceptance_criteria>

---

### Task 5: `PUT /admin/ldap-config` handler (`dlp-server/src/admin_api.rs`)

<read_first>
`dlp-server/src/admin_api.rs` — search for `put_siem_config` handler pattern to replicate
</read_first>

<action>
Add a `PUT /admin/ldap-config` handler in `dlp-server/src/admin_api.rs`:

```rust
/// PUT /admin/ldap-config — updates LDAP connection configuration.
async fn put_ldap_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LdapConfigPayload>,
) -> Result<Json<LdapConfigPayload>, AppError> {
    let updated_at = chrono::Utc::now().to_rfc3339();

    tokio::task::spawn_blocking({
        let conn = state.db.conn().lock();
        conn.execute(
            "UPDATE ldap_config SET \
             ldap_url = ?1, base_dn = ?2, require_tls = ?3, \
             cache_ttl_secs = ?4, vpn_subnets = ?5, updated_at = ?6 \
             WHERE id = 1",
            rusqlite::params![
                payload.ldap_url,
                payload.base_dn,
                payload.require_tls as i64,
                payload.cache_ttl_secs as i64,
                payload.vpn_subnets,
                updated_at,
            ],
        )
        .map_err(AppError::Database)?;

        Ok(payload)
    })
    .await
    .map_err(AppError::Internal)?
}
```

Add the route to the admin router:
```rust
.put("/ldap-config", put(put_ldap_config))
```

Validate `cache_ttl_secs` at PUT time:
- If `cache_ttl_secs < 60`, return `Err(AppError::BadRequest("cache_ttl_secs must be at least 60".to_string()))`
- If `cache_ttl_secs > 3600`, return `Err(AppError::BadRequest("cache_ttl_secs must be at most 3600".to_string()))`
</action>

<acceptance_criteria>
- `grep -n "put_ldap_config" dlp-server/src/admin_api.rs` returns the handler function
- `grep -n "cache_ttl_secs must be at least 60" dlp-server/src/admin_api.rs` returns validation error
- `grep -n "cache_ttl_secs must be at most 3600" dlp-server/src/admin_api.rs` returns validation error
- `grep -n "put.*ldap-config" dlp-server/src/admin_api.rs` returns the route registration
</acceptance_criteria>

---

## Verification

After all tasks complete:
- `cargo build -p dlp-server` → exit code 0, no warnings
- `cargo test -p dlp-server -- db::tests::test_ldap_config_seed_row` → test passes
- Plan 02 is complete when all acceptance criteria pass