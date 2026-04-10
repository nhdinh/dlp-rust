# Phase 3.1 Context: SIEM Config in DB (via dlp-admin-cli)

## Origin

Phase 3 wired the SIEM connector using env vars. User requested moving
SIEM configuration out of env vars and into the database, configurable
via dlp-admin-cli TUI.

## Decisions (locked)

### Storage
- **New `siem_config` table** with typed columns:
  - `splunk_url` TEXT
  - `splunk_token` TEXT
  - `splunk_enabled` INTEGER (0/1)
  - `elk_url` TEXT
  - `elk_index` TEXT
  - `elk_api_key` TEXT
  - `elk_enabled` INTEGER (0/1)
  - `updated_at` TEXT
- Single-row table (one config per server).
- Secrets stored **plaintext** (consistent with admin password hash and
  agent credentials — `dlp-server.db` is admin-only access).

### Runtime reload
- **Hot reload** — server re-reads config from DB on every audit event
  relay. No caching, no restart required. Slight per-request overhead
  is acceptable for admin-frequency operations.

### Env vars
- **Remove env vars entirely** — DB is the only source of truth.
  Delete the `SiemConnector::from_env()` path.
- `SiemConnector` becomes `SiemConnector::new()` and holds an
  `Arc<Database>` to read config on demand.

### TUI placement
- **Under System menu** in dlp-admin-cli. New item: "SIEM Config".
- Navigation: Main Menu -> System -> SIEM Config -> form with
  Splunk + ELK sections.

### Scope
- **All three connectors** (SIEM, alert router, config push) will move
  from env vars to DB config in consistent style.
- Replan Phase 4 (alerts) and Phase 6 (config push) to follow same pattern.
- This phase (3.1) only handles SIEM.

## New API Endpoints

- `GET /admin/siem-config` (JWT required) — returns current config
- `PUT /admin/siem-config` (JWT required) — updates config

## Files to Touch (estimate)

1. `dlp-server/src/db.rs` — add `siem_config` table
2. `dlp-server/src/siem_connector.rs` — remove `from_env()`, add
   `load_from_db(db) -> Config` + make `relay_events` re-read config
3. `dlp-server/src/admin_api.rs` — add GET/PUT routes + handlers
4. `dlp-server/src/main.rs` — drop `SiemConnector::from_env()`, build
   from DB
5. `dlp-admin-cli/src/app.rs` — add `SiemConfig` screen variants
6. `dlp-admin-cli/src/screens/render.rs` — render SIEM config form
7. `dlp-admin-cli/src/screens/dispatch.rs` — handle GET/PUT via
   EngineClient

## Acceptance Criteria

- [ ] `siem_config` table created on DB init
- [ ] `GET /admin/siem-config` returns stored config (or empty defaults)
- [ ] `PUT /admin/siem-config` updates config
- [ ] dlp-server re-reads config on every audit event relay (hot reload)
- [ ] dlp-admin-cli System menu has "SIEM Config" item
- [ ] Admin can view and edit Splunk/ELK settings via TUI
- [ ] All env var references to `SPLUNK_HEC_*` and `ELK_*` are removed
- [ ] Existing tests pass
