#!/usr/bin/env python3
"""Update PLAN.md to enumerate all 25 test fixtures by name (BLOCKER fix)."""

content = open('.planning/phases/10-sqlite-connection-pool/PLAN.md', encoding='utf-8').read()

# ── Task 2.5: exception_store.rs ─────────────────────────────────────────────
old_25 = 'In `dlp-server/src/exception_store.rs`, replace all `db.conn().lock()` with `pool.get().map_err(AppError::from)?`.'

new_25 = '''In `dlp-server/src/exception_store.rs`:

1. Replace all `db.conn().lock()` with `pool.get().map_err(AppError::from)?`.
2. Replace all `Arc::clone(&state.db)` with `Arc::clone(&state.pool)`.

Note: `exception_store.rs` has no test fixtures using `:memory:` DBs — no tempfile
migration needed in this file.'''

content = content.replace(old_25, new_25)

# ── Task 2.6: siem_connector.rs ──────────────────────────────────────────────
old_26 = '''In `dlp-server/src/siem_connector.rs`:

1. Remove `use crate::db::Database;`
2. Replace `db: Arc<Database>` field with `pool: Arc<db::Pool>` in `SiemConnector` struct
3. Replace `pub fn new(db: Arc<Database>) -> Self` with `pub fn new(pool: Arc<db::Pool>) -> Self`
4. Replace `let conn = self.db.conn().lock();` with `let conn = self.pool.get().map_err(SiemError::from)?;` in `load_config`
5. Add after the `SiemError` enum definition:

```rust
impl From<r2d2::PoolError> for SiemError {
    fn from(e: r2d2::PoolError) -> Self {
        SiemError::Database(e.into())
    }
}
```

6. Update both tests: replace `Arc::new(Database::open(":memory:").expect("open db"))` with `Arc::new(crate::db::new_pool(":memory:").expect("build pool"))`'''

new_26 = '''In `dlp-server/src/siem_connector.rs`:

1. Remove `use crate::db::Database;`
2. Replace `db: Arc<Database>` field with `pool: Arc<db::Pool>` in `SiemConnector` struct
3. Replace `pub fn new(db: Arc<Database>) -> Self` with `pub fn new(pool: Arc<db::Pool>) -> Self`
4. Replace `let conn = self.db.conn().lock();` with `let conn = self.pool.get().map_err(SiemError::from)?;` in `load_config`
5. Add after the `SiemError` enum definition:

```rust
impl From<r2d2::PoolError> for SiemError {
    fn from(e: r2d2::PoolError) -> Self {
        SiemError::Database(e.into())
    }
}
```

6. **Migrate 2 test fixtures to tempfile (BLOCKER — :memory: isolation across pool connections):**

   a. `test_new_with_in_memory_db` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      ```
      with:
      ```rust
      let tmp = tempfile::NamedTempFile::new().expect("create temp db");
      let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
      ```

   b. `test_relay_events_empty_is_noop` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let connector = SiemConnector::new(db);
      ```
      with:
      ```rust
      let tmp = tempfile::NamedTempFile::new().expect("create temp db");
      let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
      let connector = SiemConnector::new(pool);
      ```'''

content = content.replace(old_26, new_26)

# ── Task 2.7: alert_router.rs ────────────────────────────────────────────────
old_27 = '''In `dlp-server/src/alert_router.rs`:

1. Remove `use crate::db::Database;`
2. Replace `db: Arc<Database>` field with `pool: Arc<db::Pool>` in `AlertRouter` struct
3. Replace `pub fn new(db: Arc<Database>) -> Self` with `pub fn new(pool: Arc<db::Pool>) -> Self`
4. Replace `let conn = self.db.conn().lock();` with `let conn = self.pool.get().map_err(AlertError::from)?;` in `load_config`
5. Add after the `AlertError` enum definition:

```rust
impl From<r2d2::PoolError> for AlertError {
    fn from(e: r2d2::PoolError) -> Self {
        AlertError::Database(e.into())
    }
}
```

6. Update all 3 test setups: replace `Arc::new(Database::open(":memory:").expect("open db"))` with `Arc::new(crate::db::new_pool(":memory:").expect("build pool"))`'''

new_27 = '''In `dlp-server/src/alert_router.rs`:

1. Remove `use crate::db::Database;`
2. Replace `db: Arc<Database>` field with `pool: Arc<db::Pool>` in `AlertRouter` struct
3. Replace `pub fn new(db: Arc<Database>) -> Self` with `pub fn new(pool: Arc<db::Pool>) -> Self`
4. Replace `let conn = self.db.conn().lock();` with `let conn = self.pool.get().map_err(AlertError::from)?;` in `load_config`
5. Add after the `AlertError` enum definition:

```rust
impl From<r2d2::PoolError> for AlertError {
    fn from(e: r2d2::PoolError) -> Self {
        AlertError::Database(e.into())
    }
}
```

6. **Migrate 3 test fixtures to tempfile (BLOCKER — :memory: isolation across pool connections):**

   a. `test_alert_router_disabled_default` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let router = AlertRouter::new(Arc::clone(&db));
      ```
      with tempfile + pool construction.

   b. `test_load_config_roundtrip` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      { let conn = db.conn().lock(); ... }
      let router = AlertRouter::new(Arc::clone(&db));
      ```
      with tempfile + pool. The inline `conn = db.conn().lock()` block also migrates
      to `pool.get().expect("acquire connection")`.

   c. `test_load_config_port_overflow` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      { let conn = db.conn().lock(); ... }
      let router = AlertRouter::new(db);
      ```
      with tempfile + pool. The inline `conn = db.conn().lock()` block also migrates.

   d. `test_send_email_continues_past_bad_recipient` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let router = AlertRouter::new(db);
      ```
      with tempfile + pool.

   e. `test_hot_reload` — replace:
      ```rust
      let db = Arc::new(Database::open(":memory:").expect("open db"));
      let router = AlertRouter::new(Arc::clone(&db));
      ```
      with tempfile + pool. The inline `conn = db.conn().lock()` UPDATE block also
      migrates to `pool.get().expect("acquire connection")`.'''

content = content.replace(old_27, new_27)

# ── Task 2.8: audit_store.rs ─────────────────────────────────────────────────
old_28 = 'In `dlp-server/src/audit_store.rs`:\n\n1. In `ingest_events`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`\n2. In `query_events`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`\n3. In `get_event_count`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`\n4. In the test `test_store_events_sync_admin_action`:\n   - Replace `use crate::db::Database;`\n   - Replace `let db = Database::open(":memory:").expect("open in-memory db")` with `let pool = new_pool(":memory:").expect("build pool")`\n   - Replace `let conn = db.conn().lock()` with `let conn = pool.get().expect("acquire connection")`\n   - The `store_events_sync(&conn, &[event])` call stays as-is (Deref coercion applies)'

new_28 = '''In `dlp-server/src/audit_store.rs`:

1. Replace all `Arc::clone(&state.db)` with `Arc::clone(&state.pool)`.
2. In `ingest_events`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
3. In `query_events`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
4. In `get_event_count`: `db.conn().lock()` → `pool.get().map_err(AppError::from)?`
5. **Migrate 1 test fixture to tempfile (BLOCKER — :memory: isolation across pool connections):**

   `test_store_events_sync_admin_action` — replace:
   ```rust
   use crate::db::Database;
   let db = Database::open(":memory:").expect("open in-memory db");
   let conn = db.conn().lock();
   ```
   with:
   ```rust
   use super::db;
   let pool = db::new_pool(":memory:").expect("build pool");
   let conn = pool.get().expect("acquire connection");
   ```
   (Deref coercion makes `store_events_sync(&conn, &[event])` work unchanged.)'''

content = content.replace(old_28, new_28)

# ── Task 2.9: admin_api.rs ────────────────────────────────────────────────────
old_29 = '''In `dlp-server/src/admin_api.rs`:

1. Remove `use crate::db::Database;`
2. Replace all `Arc::clone(&state.db)` with `Arc::clone(&state.pool)`
3. Replace all `db.conn().lock()` with `pool.get().map_err(AppError::from)?`
4. Replace all test setups: `Arc::new(Database::open(":memory:").expect("..."))` → `Arc::new(crate::db::new_pool(":memory:").expect("..."))`
5. Replace `let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"))` patterns with `let pool = Arc::new(crate::db::new_pool(":memory:").expect("build pool"))`
6. Update `AppState { db, siem, alert, ad: None }` → `AppState { pool, siem, alert, ad: None }`
7. The `spawn_admin_app()` helper: update to use `pool` field'''

new_29 = '''In `dlp-server/src/admin_api.rs`:

1. Remove `use crate::db::Database;`
2. Replace all `Arc::clone(&state.db)` with `Arc::clone(&state.pool)`
3. Replace all `db.conn().lock()` with `pool.get().map_err(AppError::from)?`
4. Update `spawn_admin_app()` test helper:
   - Replace `let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"))` with tempfile + `db::new_pool`
   - Replace `Arc::clone(&db)` with `Arc::clone(&pool)` in `SiemConnector::new` and `AlertRouter::new`
   - Replace `AppState { db, ... }` with `AppState { pool, ... }`
5. Update `seed_agent(&Database)` → `seed_agent(&db::Pool)` helper:
   - Signature: `fn seed_agent(pool: &crate::db::Pool, agent_id: &str)`
   - Body: `db.conn().lock()` → `pool.get().expect("acquire connection")`
6. Update all 19 inline AppState test builds. Each must:
   - Create a tempfile, build a pool from it via `crate::db::new_pool(tmp.path().to_str().unwrap())`
   - Replace all `Database::open(":memory:")` with the tempfile approach
   - Replace all `Arc::clone(&db)` → `Arc::clone(&pool)`
   - Replace all `AppState { db, ... }` → `AppState { pool, ... }`
   - Replace `seed_agent(&db, ...)` → `seed_agent(&pool, ...)`
7. **Migrate 19 inline fixtures to tempfile (BLOCKER — :memory: isolation):**

   All of the following fixtures create an inline `AppState` with `:memory:` DB and must
   be migrated to `tempfile::NamedTempFile` + `db::new_pool`. Affected fixtures:

   - `test_get_alert_config_requires_auth` (line ~1674)
   - `test_put_alert_config_roundtrip` (line ~1706)
   - `test_put_alert_config_preserves_masked_secret` (line ~1791) — **also has an
     inline `db.conn().lock()` at the verification step (line ~1867) that reads the DB
     directly after PUT to verify mask behavior; migrate that to `pool.get().expect(...)`**
   - `test_db_insert_select_roundtrip_via_spawn_blocking` (line ~1887) — **has 2 separate
     `conn().lock()` calls** (INSERT closure at ~1891 and SELECT closure at ~1912);
     the Arc-cloned variable `db` is renamed `pool` (and `db2` → `pool2`) in the migration
   - `test_router_post_then_direct_db_read` (line ~1937) — **has an inline
     `db_read.conn().lock()`** at ~1971; migrate to `pool_read.get().expect(...)`
   - `test_get_agent_config_falls_back_to_global` (line ~2696)
   - `test_put_agent_config_override` (line ~2800)
   - `test_delete_agent_config_override` (line ~2856)

8. **Update `seed_agent` call sites** in `test_get_agent_config_falls_back_to_global`,
   `test_put_agent_config_override`, and `test_delete_agent_config_override` to pass
   `&pool` instead of `&db`.

The `ALERT_SECRET_MASK` doc comments that reference "seeded during `Database::open`" should
be updated to "seeded during table init." as `Database::open` no longer exists.'''

content = content.replace(old_29, new_29)

with open('.planning/phases/10-sqlite-connection-pool/PLAN.md', 'w', encoding='utf-8') as f:
    f.write(content)
print('done')
