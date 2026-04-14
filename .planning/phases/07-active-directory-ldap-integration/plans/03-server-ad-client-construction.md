---
wave: 2
depends_on:
  - "01-ad-client-crate"
  - "02-db-schema-and-admin-api"
requirements:
  - R-05
files_modified:
  - dlp-server/src/main.rs
  - dlp-server/src/lib.rs
autonomous: false
---

# Plan 03: Server-Side AD Client Construction

## Goal

Construct the `AdClient` at `dlp-server` startup from the DB-loaded `ldap_config` and make it available via `AppState` for Phase 9's admin SID resolution (admin login → resolve username → SID → store in `admin_users.user_sid`).

---

## must_haves

- `dlp-server/src/lib.rs` adds `ad` field to `AppState` of type `Option<dlp_common::AdClient>`
- `dlp-server/src/main.rs` loads `ldap_config` from DB at startup, constructs `AdClient::new(config)`, and stores it in `AppState.ad`
- `dlp-server` compiles without errors
- Server starts successfully when AD is unreachable (fail-open — `AppState.ad = None` if construction fails)

---

## Tasks

### Task 1: Extend `AppState` with `ad` field (`dlp-server/src/lib.rs`)

<read_first>
`dlp-server/src/lib.rs`
</read_first>

<action>
Add the `ad` field to `AppState` in `dlp-server/src/lib.rs`. Import `dlp_common::AdClient` at the top:

```rust
use dlp_common::AdClient;
```

Add to the `AppState` struct:
```rust
/// Active Directory LDAP client for group resolution and admin SID lookup.
/// None when AD is unreachable (fail-open at startup).
pub ad: Option<AdClient>,
```
</action>

<acceptance_criteria>
- `grep -n "use dlp_common::AdClient" dlp-server/src/lib.rs` returns the import
- `grep -n "pub ad:" dlp-server/src/lib.rs` returns the field declaration
- `grep -n "Option<AdClient>" dlp-server/src/lib.rs` returns the field type
</acceptance_criteria>

---

### Task 2: Construct `AdClient` at startup (`dlp-server/src/main.rs`)

<read_first>
`dlp-server/src/main.rs` — full file (needed to find the AppState construction block)
</read_first>

<action>
In `dlp-server/src/main.rs`, after the database is opened and before (or alongside) `AppState` is constructed:

**Step A**: Add the import for `LdapConfig` at the top of the file (with the other `dlp_server` imports):
```rust
use dlp_common::ad_client::{AdClient, LdapConfig};
```

**Step B**: Add a helper function to load `LdapConfig` from the database:

```rust
/// Loads the LDAP configuration from the SQLite database.
///
/// Returns `None` if the config cannot be read (DB not yet initialized).
fn load_ldap_config(db: &db::Database) -> Option<LdapConfig> {
    let conn = db.conn().lock();
    conn.query_row(
        "SELECT ldap_url, base_dn, require_tls, cache_ttl_secs, vpn_subnets \
         FROM ldap_config WHERE id = 1",
        [],
        |row| {
            Ok(LdapConfig {
                ldap_url: row.get(0).ok()?,
                base_dn: row.get(1).ok()?,
                require_tls: row.get::<_, i64>(2).ok()? != 0,
                cache_ttl_secs: row.get::<_, i64>(3).ok()? as u64,
                vpn_subnets: row.get(4).ok()?,
            })
        },
    )
    .ok()
}
```

**Step C**: Construct the `AdClient` in `main()` before building `AppState`. Replace the direct `AppState` construction with:

```rust
// Attempt to construct the AD client from DB config.
// Fail-open: server starts even if AD is unreachable.
let ad_config = load_ldap_config(&db);
let ad_client = ad_config.and_then(|config| {
    tracing::info!(ldap_url = %config.ldap_url, base_dn = %config.base_dn, "initializing AD client");
    AdClient::new(config)
        .inspect_err(|e| tracing::warn!(error = %e, "AD client initialization failed — AD features disabled"))
        .ok()
});

let state = Arc::new(AppState {
    db: Arc::new(db),
    siem,
    alert,
    ad: ad_client,
});
```

**Step D**: Remove the old direct `AppState { db, siem, alert }` construction that currently exists. The new block (Step C) replaces it entirely.
</action>

<acceptance_criteria>
- `grep -n "use dlp_common::ad_client" dlp-server/src/main.rs` returns the import line
- `grep -n "load_ldap_config" dlp-server/src/main.rs` returns the helper function
- `grep -n "AdClient::new" dlp-server/src/main.rs` returns the construction call
- `grep -n "ad: ad_client" dlp-server/src/main.rs` returns the AppState field assignment
- `cargo build -p dlp-server` → exit code 0, no warnings
</acceptance_criteria>

---

## Verification

After all tasks complete:
- `cargo build -p dlp-server` → exit code 0
- `grep -n "AppState {" dlp-server/src/main.rs` shows `ad: ad_client` in the struct literal
- `grep -n "ad:" dlp-server/src/lib.rs` confirms the field is in `AppState`
- Plan 03 is complete when all acceptance criteria pass