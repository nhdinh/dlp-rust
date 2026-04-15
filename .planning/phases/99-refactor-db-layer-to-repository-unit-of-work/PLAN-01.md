# Plan 01: Build db/ Submodule (Stubs, UnitOfWork, Pool Alias)

**Phase:** 99 -- Refactor DB Layer to Repository + Unit of Work
**Wave:** 1
**Prereq:** Phase 10 complete (r2d2 pool exists in db.rs)

## Goal

Create the `dlp-server/src/db/` submodule structure that replaces the flat `db.rs` file.
This wave delivers: the `Pool` type alias and `new_pool()` moved into `db/mod.rs`, the
`UnitOfWork<'conn>` struct in `db/unit_of_work.rs` with RAII rollback semantics, and all
10 repository stub files under `db/repositories/` with at least one read and one write
method each. The existing `db.rs` is deleted and replaced by the `db/` directory module.
No handler call sites change -- handlers still use `pool.get()` directly. The crate must
compile and all existing tests must pass at the end of this wave.

Additionally, `main.rs::load_ldap_config` is migrated to use `LdapConfigRepository` since
it contains raw SQL outside `db/repositories/` (violates Decision A).

## Threat Model

| Threat | Severity | Mitigation |
|--------|----------|------------|
| SQL injection via string interpolation in repository stubs | medium | All repository methods use `rusqlite::params![]` macro exclusively; no `format!()` in SQL strings. Code review during Wave 2/3 migration. |
| Transaction isolation -- UoW commit/rollback correctness | medium | Unit test `test_uow_rollback_on_drop` verifies that dropping without `.commit()` rolls back. Unit test `test_uow_commit` verifies committed data persists. |
| Sensitive data in error messages | low | Repository methods return `rusqlite::Result<T>` which contains DB error text only, never user data. No `format!("{password}")` in any error path. |

## Tasks

### Task 1-01: Convert db.rs to db/ directory module

**Files:**
- DELETE: `dlp-server/src/db.rs`
- CREATE: `dlp-server/src/db/mod.rs`

**Action:** CREATE + DELETE
**Why:** The flat `db.rs` must become a directory module to hold `repositories/` and `unit_of_work.rs`.

Move the entire contents of `db.rs` (Pool type alias, Connection type alias, `new_pool()`,
`init_tables()`, and all `#[cfg(test)]` tests) into `db/mod.rs`. Add `pub mod repositories;`
and `pub mod unit_of_work;` declarations at the top. Add a `pub use unit_of_work::UnitOfWork;`
re-export for convenience.

The `pub mod db;` declaration in `lib.rs` already resolves to either `db.rs` or `db/mod.rs`
-- no change needed in `lib.rs`.

Important: Rust module resolution means `db.rs` and `db/mod.rs` cannot coexist. Delete
`db.rs` first, then create the `db/` directory with `mod.rs`.

```rust
// db/mod.rs -- top of file additions (rest is unchanged from db.rs)
pub mod repositories;
pub mod unit_of_work;

pub use unit_of_work::UnitOfWork;

// ... existing Pool type alias, Connection type alias, new_pool(), init_tables(), tests ...
```

<verify>
cargo check -p dlp-server 2>&1 | tail -5
</verify>

---

### Task 1-02: Create UnitOfWork with RAII rollback

**File:** `dlp-server/src/db/unit_of_work.rs`
**Action:** CREATE
**Why:** Per Decision B -- UnitOfWork<'conn> wraps rusqlite::Transaction with RAII semantics.

Create the `UnitOfWork` struct exactly as specified in CONTEXT.md Decision B:

```rust
//! RAII transaction wrapper for SQLite write operations.
//!
//! Dropping a `UnitOfWork` without calling [`UnitOfWork::commit`] automatically
//! rolls back the transaction (rusqlite's `Transaction` does this on drop).

use rusqlite;

/// RAII transaction wrapper. All write-side repository methods accept
/// `&UnitOfWork` and execute SQL against `self.tx`.
///
/// Dropping without calling `.commit()` auto-rolls back -- this is enforced
/// by rusqlite's `Transaction::drop` implementation.
pub struct UnitOfWork<'conn> {
    /// The underlying rusqlite transaction. Repository write methods
    /// access this field directly (crate-visible).
    pub(crate) tx: rusqlite::Transaction<'conn>,
}

impl<'conn> UnitOfWork<'conn> {
    /// Begins a new transaction on the given connection.
    ///
    /// # Arguments
    ///
    /// * `conn` - Mutable reference to a `rusqlite::Connection`. Typically
    ///   obtained via `&mut *pooled_conn` where `pooled_conn` is a
    ///   `PooledConnection<SqliteConnectionManager>`.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the BEGIN TRANSACTION statement fails.
    pub fn new(conn: &'conn mut rusqlite::Connection) -> rusqlite::Result<Self> {
        let tx = conn.transaction()?;
        Ok(Self { tx })
    }

    /// Commits the transaction, consuming the `UnitOfWork`.
    ///
    /// If this method is not called, the transaction is rolled back when
    /// the `UnitOfWork` is dropped.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the COMMIT statement fails.
    pub fn commit(self) -> rusqlite::Result<()> {
        self.tx.commit()
    }
}
```

Add unit tests in the same file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uow_commit() {
        let mut conn = rusqlite::Connection::open_in_memory()
            .expect("open in-memory connection");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .expect("create table");

        {
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            uow.tx.execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("insert");
            uow.commit().expect("commit");
        }

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 1, "committed row must persist");
    }

    #[test]
    fn test_uow_rollback_on_drop() {
        let mut conn = rusqlite::Connection::open_in_memory()
            .expect("open in-memory connection");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .expect("create table");

        {
            let uow = UnitOfWork::new(&mut conn).expect("begin transaction");
            uow.tx.execute("INSERT INTO t (id) VALUES (1)", [])
                .expect("insert");
            // uow is dropped here without commit -- should rollback
        }

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0, "uncommitted row must be rolled back");
    }
}
```

<verify>
cargo test -p dlp-server --lib unit_of_work 2>&1 | tail -10
</verify>

---

### Task 1-03: Create all repository stubs under db/repositories/

**Files:**
- CREATE: `dlp-server/src/db/repositories/mod.rs`
- CREATE: `dlp-server/src/db/repositories/agents.rs`
- CREATE: `dlp-server/src/db/repositories/policies.rs`
- CREATE: `dlp-server/src/db/repositories/audit_events.rs`
- CREATE: `dlp-server/src/db/repositories/exceptions.rs`
- CREATE: `dlp-server/src/db/repositories/admin_users.rs`
- CREATE: `dlp-server/src/db/repositories/ldap_config.rs`
- CREATE: `dlp-server/src/db/repositories/siem_config.rs`
- CREATE: `dlp-server/src/db/repositories/alert_router_config.rs`
- CREATE: `dlp-server/src/db/repositories/agent_config.rs`
- CREATE: `dlp-server/src/db/repositories/credentials.rs`

**Action:** CREATE
**Why:** Per Decision A -- one repository struct per entity, all SQL encapsulated. Per Decision F
-- Wave 1 creates stubs with at least one read and one write method per repository. The
`credentials.rs` file covers the `agent_credentials` table (missing from CONTEXT.md but
present in the schema and referenced by `admin_api.rs::set_agent_auth_hash`/`get_agent_auth_hash`).

Each repository struct is zero-field (stateless) since all state comes from the `&Pool` or
`&UnitOfWork` argument. Each stub must include:

1. Doc comments on the struct and each method
2. One read method that takes `pool: &Pool` and returns `rusqlite::Result<T>`
3. One write method that takes `uow: &UnitOfWork<'_>` and returns `rusqlite::Result<()>`
4. All SQL uses `rusqlite::params![]` -- no string interpolation

**repositories/mod.rs** re-exports all repository structs:

```rust
//! Repository modules -- one per database entity.
//!
//! All raw SQL is encapsulated within these modules. No `conn.execute()`
//! or `conn.query_row()` should appear outside `db/repositories/`.

pub mod admin_users;
pub mod agent_config;
pub mod agents;
pub mod alert_router_config;
pub mod audit_events;
pub mod credentials;
pub mod exceptions;
pub mod ldap_config;
pub mod policies;
pub mod siem_config;

pub use admin_users::AdminUserRepository;
pub use agent_config::AgentConfigRepository;
pub use agents::AgentRepository;
pub use alert_router_config::AlertRouterConfigRepository;
pub use audit_events::AuditEventRepository;
pub use credentials::CredentialsRepository;
pub use exceptions::ExceptionRepository;
pub use ldap_config::LdapConfigRepository;
pub use policies::PolicyRepository;
pub use siem_config::SiemConfigRepository;
```

**Canonical method signature patterns for ALL stubs:**

Read methods (take `&Pool`):
```rust
use crate::db::Pool;

pub struct FooRepository;

impl FooRepository {
    /// Reads ... from the database.
    pub fn get(pool: &Pool) -> rusqlite::Result<T> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        // SELECT using params![]
    }
}
```

Write methods (take `&UnitOfWork`):
```rust
use crate::db::UnitOfWork;

impl FooRepository {
    /// Writes ... to the database.
    pub fn insert(uow: &UnitOfWork<'_>, ...) -> rusqlite::Result<()> {
        uow.tx.execute("INSERT INTO ...", rusqlite::params![...])?;
        Ok(())
    }
}
```

**Pool error mapping convention:** Repository read methods map `r2d2::Error` to
`rusqlite::Error::ToSqlConversionFailure(Box::new(e))` to stay within the
`rusqlite::Result<T>` return type (Decision G). This is a pragmatic mapping -- the
handler layer converts to `AppError` anyway.

**Specific stubs to implement (one read + one write each, minimum):**

| File | Struct | Read stub | Write stub |
|------|--------|-----------|------------|
| agents.rs | AgentRepository | `list(pool) -> Vec<AgentRow>` | `upsert(uow, record) -> ()` |
| policies.rs | PolicyRepository | `list(pool) -> Vec<PolicyRow>` | `insert(uow, record) -> ()` |
| audit_events.rs | AuditEventRepository | `count(pool) -> i64` | `insert_batch(uow, rows) -> ()` |
| exceptions.rs | ExceptionRepository | `list(pool) -> Vec<ExceptionRow>` | `insert(uow, record) -> ()` |
| admin_users.rs | AdminUserRepository | `get_password_hash(pool, username) -> String` | `insert(uow, username, hash, created_at) -> ()` |
| ldap_config.rs | LdapConfigRepository | `get(pool) -> LdapConfigRow` | `update(uow, record) -> ()` |
| siem_config.rs | SiemConfigRepository | `get(pool) -> SiemConfigRow` | `update(uow, record) -> ()` |
| alert_router_config.rs | AlertRouterConfigRepository | `get(pool) -> AlertRouterConfigRow` | `update(uow, record) -> ()` |
| agent_config.rs | AgentConfigRepository | `get_global(pool) -> GlobalAgentConfigRow` | `update_global(uow, record) -> ()` |
| credentials.rs | CredentialsRepository | `get(pool, key) -> CredentialRow` | `upsert(uow, key, value) -> ()` |

Each repository file must define its own `Row` struct for the return type (e.g.,
`AgentRow`, `PolicyRow`). These are plain data structs with `#[derive(Debug, Clone)]`.
They do NOT derive Serialize/Deserialize -- that stays in the handler layer types.

**IMPORTANT:** The `audit_events.rs` `insert_batch` method receives pre-serialized
string fields (event_type, classification, action_attempted, decision, access_context).
The caller is responsible for JSON serialization of enum fields. This is per the
`store_events_sync` special case noted in the plan format rules.

**IMPORTANT:** `admin_users.rs` must have an additional sync method
`has_any(pool) -> rusqlite::Result<bool>` for the startup check and
`count(pool) -> rusqlite::Result<i64>` to support `has_admin_users`. These methods
use `&Pool` (read pattern).

<verify>
cargo check -p dlp-server 2>&1 | tail -5
</verify>

---

### Task 1-04: Migrate main.rs::load_ldap_config to use LdapConfigRepository

**File:** `dlp-server/src/main.rs`
**Action:** EDIT
**Why:** Per Decision A -- no raw SQL outside db/repositories/. load_ldap_config at line 42
reads ldap_config with raw SQL. After Wave 1, LdapConfigRepository::get(&pool) exists.

Replace the raw SQL in `load_ldap_config` with a call to `LdapConfigRepository::get(pool)`:

```rust
use dlp_server::db::repositories::LdapConfigRepository;

fn load_ldap_config(pool: &db::Pool) -> Option<LdapConfig> {
    let row = LdapConfigRepository::get(pool).ok()?;
    Some(LdapConfig {
        ldap_url: row.ldap_url,
        base_dn: row.base_dn,
        require_tls: row.require_tls,
        cache_ttl_secs: row.cache_ttl_secs,
        vpn_subnets: row.vpn_subnets,
    })
}
```

The `LdapConfigRow` struct from the repository must have fields that match the
existing `LdapConfig` struct's needs: `ldap_url: String`, `base_dn: String`,
`require_tls: bool`, `cache_ttl_secs: u64`, `vpn_subnets: String`.

Note: `require_tls` is stored as `i64` in the DB (0/1). The repository's `get()`
method must convert `i64 != 0` to `bool` and `i64` to `u64` for `cache_ttl_secs`.

<verify>
cargo check -p dlp-server 2>&1 | tail -5
cargo test -p dlp-server --lib 2>&1 | tail -5
</verify>

---

## Verification

After all 4 tasks:

```
cargo check -p dlp-server                        # compiles with no errors
cargo test -p dlp-server --lib unit_of_work       # UoW tests pass
cargo test -p dlp-server --lib                    # all existing tests pass
cargo clippy -p dlp-server -- -D warnings         # no clippy warnings
```

## Success Criteria

- `dlp-server/src/db.rs` no longer exists; replaced by `dlp-server/src/db/mod.rs`
- `dlp-server/src/db/unit_of_work.rs` exists with `UnitOfWork<'conn>` struct
- `dlp-server/src/db/repositories/` contains 10 repository files + `mod.rs`
- Each repository has at least one read method (takes `&Pool`) and one write method (takes `&UnitOfWork`)
- `main.rs::load_ldap_config` uses `LdapConfigRepository::get()` instead of raw SQL
- `cargo test -p dlp-server --lib` passes all existing tests (no regressions)
- `cargo clippy -p dlp-server -- -D warnings` passes
- No `.unwrap()` in library code (only in test code)
- All public items have doc comments
