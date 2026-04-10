# Phase 3.1 Plan: SIEM Config in DB (via dlp-admin-cli)

## Summary

Move SIEM connector configuration from environment variables to the
SQLite database. Add an `admin` REST API for reading/updating SIEM
config, and a TUI screen in dlp-admin-cli for admins to manage it.

## Files to Modify

### dlp-server
- `src/db.rs` — add `siem_config` table schema
- `src/siem_connector.rs` — remove `from_env()`, add DB-backed loader
- `src/admin_api.rs` — add `GET /admin/siem-config` and `PUT /admin/siem-config` routes
- `src/main.rs` — drop `SiemConnector::from_env()`, construct with `Arc<Database>`

### dlp-admin-cli
- `src/client.rs` — add `get_siem_config()` + `update_siem_config()` methods
- `src/app.rs` — add `SiemConfigView` and `SiemConfigEdit` to `Screen` enum
- `src/screens/render.rs` — render the SIEM config form (read + edit modes)
- `src/screens/dispatch.rs` — handle navigation, loading, saving, System menu wiring

## Implementation Steps

### Step 1: Database schema

In `dlp-server/src/db.rs::init_tables()`, add:

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

Single-row table (CHECK constraint enforces id=1). Seed row inserted.

Update `test_tables_created` to assert `siem_config` exists.

### Step 2: Rewrite SiemConnector

In `siem_connector.rs`:

1. Remove `from_env()`.
2. Change `SiemConnector` struct to hold `Arc<Database>` instead of
   `Option<SplunkConfig>` / `Option<ElkConfig>`.
3. Add `pub fn new(db: Arc<Database>) -> Self`.
4. In `relay_events()`, call a new private `load_config(&self) ->
   SiemConfigRow` that reads the single row from DB on each call.
5. Derive effective Splunk/ELK config from the row (only relay if
   enabled flag is true AND URL is non-empty).

Add a `SiemConfigRow` struct with all columns for internal use.

### Step 3: Server API endpoints

In `admin_api.rs`, add to protected routes:

```rust
.route("/admin/siem-config", get(get_siem_config_handler))
.route("/admin/siem-config", put(update_siem_config_handler))
```

Request/response types:

```rust
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

Handlers:
- `get_siem_config_handler` — SELECT from siem_config WHERE id=1, return JSON
- `update_siem_config_handler` — UPDATE siem_config SET ... WHERE id=1

Both use `spawn_blocking` for SQLite access.

Update route doc comment.

### Step 4: main.rs — construct from DB

Replace:
```rust
let siem = SiemConnector::from_env();
```
with:
```rust
let siem = SiemConnector::new(Arc::clone(&db));
```

### Step 5: dlp-admin-cli client methods

In `client.rs`, add:

```rust
pub async fn get_siem_config(&self) -> Result<serde_json::Value> {
    self.get("admin/siem-config").await
}

pub async fn update_siem_config(
    &self,
    payload: &serde_json::Value,
) -> Result<serde_json::Value> {
    self.put("admin/siem-config", payload).await
}
```

### Step 6: dlp-admin-cli TUI screens

In `app.rs`, add Screen variants:

```rust
SiemConfig {
    /// Currently loaded config.
    config: serde_json::Value,
    /// Which field is selected (0..=6).
    selected: usize,
    /// Currently in edit mode for the selected field?
    editing: bool,
    /// Buffered input while editing.
    buffer: String,
},
```

7 fields in order: splunk_url, splunk_token, splunk_enabled, elk_url,
elk_index, elk_api_key, elk_enabled + Save + Back (so 9 rows total).

In `screens/render.rs`, add `draw_siem_config()`:
- Render each field on its own line: `Label: value` (or `[input]` if editing)
- Bool fields show `[x]` / `[ ]`
- Secret fields (splunk_token, elk_api_key) show `*****` unless editing
- Highlighted row shows selected field
- Footer: `Up/Down: navigate | Enter: edit/toggle | Esc: back`

In `screens/dispatch.rs`:

1. Add "SIEM Config" item to the System menu (currently: Server Status,
   Agent List, Back). New order: Server Status, Agent List, SIEM Config, Back.
2. Update `handle_system_menu` to handle 4 items and new dispatch:
   - 0 -> action_server_status
   - 1 -> action_agent_list
   - 2 -> action_load_siem_config (new)
   - 3 -> back to MainMenu
3. Add `action_load_siem_config(app)` — block_on get_siem_config, switch
   to Screen::SiemConfig
4. Add `handle_siem_config(app, key)` — navigation, edit mode, save:
   - Up/Down: move selected
   - Enter on bool field: toggle
   - Enter on text field: enter edit mode (buffer input)
   - Enter on Save row: call update_siem_config, show status
   - Esc: exit edit mode / back to SystemMenu
   - Char/Backspace in edit mode: buffer manipulation

### Step 7: Tests

- Extend `db::tests::test_tables_created` — assert `siem_config` exists
- Add a new test `test_siem_config_seed_row` — verify the seed row is
  present after `Database::open`

## Verification

```
cargo check --package dlp-server
cargo check --package dlp-admin-cli
cargo test --package dlp-server --lib
cargo test --package dlp-admin-cli --lib
cargo clippy --workspace -- -D warnings
```

## UAT Criteria

- [ ] `siem_config` table exists after DB init with one seed row
- [ ] `GET /admin/siem-config` returns current settings as JSON (JWT required)
- [ ] `PUT /admin/siem-config` updates settings (JWT required)
- [ ] Server reads config from DB on every relay (no restart needed)
- [ ] dlp-server no longer reads `SPLUNK_HEC_*` / `ELK_*` env vars
- [ ] dlp-admin-cli has "SIEM Config" under the System menu
- [ ] Admin can view Splunk/ELK settings via TUI (secrets masked)
- [ ] Admin can edit and save settings via TUI
- [ ] Save triggers the backend update via PUT /admin/siem-config
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] All existing tests pass
