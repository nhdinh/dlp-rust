# Phase 6: Wire Config Push for Agent Config Distribution — Research

**Researched:** 2026-04-12
**Domain:** Axum HTTP API, SQLite (rusqlite), Tokio timers, TOML persistence
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

1. **Delivery model:** Agent calls `GET /agent-config/{id}` on a separate timer — NOT bundled into
   heartbeat response, NOT server-push. Server returns the resolved config for that agent.

2. **Config storage:** Two new DB tables:
   - `global_agent_config` — single-row default (CHECK id = 1), seeded on DB init.
   - `agent_config_overrides` — multi-row, TEXT PRIMARY KEY = agent_id, FK to agents.agent_id.
   Fallback: agent gets global default when no override row exists.

3. **Configurable fields only:**
   | Field | Type | Notes |
   |-------|------|-------|
   | `monitored_paths` | `Vec<String>` (JSON array in DB) | Directories the agent monitors |
   | `heartbeat_interval_secs` | `u64` (min 10s) | Heartbeat cadence |
   | `offline_cache_enabled` | `bool` | Whether offline cache is active |
   `server_url` is explicitly excluded.

4. **Agent-side persistence:** On config change → apply in-memory immediately → write back to
   `C:\ProgramData\DLP\agent-config.toml`. Log at INFO level which fields changed (not values).
   Poll timer uses the *previously applied* interval, not the newly received one.

5. **Auth:** `GET /agent-config/{id}` is unauthenticated (public_routes). Admin management
   endpoints (`GET/PUT /admin/agent-config`, `GET/PUT/DELETE /admin/agent-config/{agent_id}`)
   are JWT-protected (protected_routes).

6. **Poll timer cadence:** Default to `heartbeat_interval_secs` seconds. Independent timer
   from heartbeat — they must not block each other.

### Claude's Discretion

- Whether to delete `config_push.rs` or stub it cleanly. CONTEXT.md says "planner must decide."
- Exact Rust type for the in-memory config signal (Arc<tokio::sync::watch::Sender<AgentConfigPayload>>,
  or polling approach via shared Arc<Mutex<...>>).

### Deferred Ideas (OUT OF SCOPE)

- TUI screen in dlp-admin-cli for managing agent config — separate phase.
- `server_url` as a pushable field — not in scope.
- Push notification / webhooks for immediate refresh — not in scope.
- Rate limiting on `/agent-config/{id}` — Phase 7.
</user_constraints>

---

## Summary

Phase 6 wires a poll-based agent config distribution system. The server stores a global default
and optional per-agent overrides in SQLite; agents periodically poll `GET /agent-config/{id}` and
apply changes in-memory and to their TOML file. No new crate dependencies are needed — all required
libraries are already in Cargo.toml.

The implementation follows the Phase 3.1 / 4 pattern for DB-backed config with GET/PUT admin
endpoints. The primary complexity is the agent side: a new independent timer in `run_loop` that
polls the server, compares received config against in-memory state, hot-reloads on change, and
writes back to TOML — all without blocking the existing heartbeat or event loops.

The existing `config_push.rs` module implements a server-push model (server calls agent HTTP
endpoints) that is architecturally incompatible with the decided poll model. It has no usages in
the codebase outside its own `#[cfg(test)]` block. The planner should delete it to eliminate dead
code and avoid Clippy warnings, then remove the `pub mod config_push;` declaration from `lib.rs`.

**Primary recommendation:** Follow the siem_config / alert_router_config pattern exactly. Every
new piece — DB tables, payload structs, handler functions, router wiring — has a direct precedent
in the existing codebase.

---

## Project Constraints (from CLAUDE.md)

- **Error handling:** `thiserror` for all custom error types. Never `.unwrap()` in production paths.
  Use `?` propagation. `anyhow::Context` at application boundaries.
- **Async + blocking DB:** All `rusqlite` calls inside `tokio::task::spawn_blocking`.
- **Axum state:** Use `State<Arc<AppState>>` extractor — never global mutable state.
- **Logging:** `tracing::info!` / `tracing::error!` — never `println!`.
- **No sensitive data in logs:** Log field *names* changed, not path values.
- **Tests:** `#[cfg(test)]` modules, `#[test]` attribute, Arrange-Act-Assert.
  All new DB operations need unit tests. All new HTTP handlers need integration tests.
- **Style:** `rustfmt`, `clippy -D warnings`, no commented-out code, doc comments on all
  public items.
- **Security:** Never log sensitive information. `server_url` excluded from pushed config.
- **Before commit checklist:** `cargo test`, `cargo build --all`, `cargo clippy -- -D warnings`,
  `cargo fmt --check`, `sonar-scanner`.

---

## Standard Stack

### Core (all already in Cargo.toml — no new dependencies needed)

| Library | Version | Purpose | Source |
|---------|---------|---------|--------|
| `axum` | 0.7 | HTTP handler for `GET /agent-config/{id}` and admin endpoints | [VERIFIED: dlp-server/Cargo.toml] |
| `rusqlite` | 0.31 | SQLite access for new config tables | [VERIFIED: dlp-server/Cargo.toml] |
| `tokio` | workspace | Timer (`tokio::time::interval`) for agent poll loop | [VERIFIED: dlp-agent/Cargo.toml] |
| `serde_json` | workspace | Serialize `monitored_paths: Vec<String>` as JSON text column in DB | [VERIFIED: both Cargo.toml files] |
| `toml` | 0.8 | Serialize updated AgentConfig back to TOML file | [VERIFIED: dlp-agent/Cargo.toml] |
| `tracing` | workspace | Structured logging of config changes | [VERIFIED: both Cargo.toml files] |
| `chrono` | 0.4 | `updated_at` timestamps | [VERIFIED: both Cargo.toml files] |

**Installation:** No new dependencies. Zero Cargo.toml changes required.

---

## Architecture Patterns

### Pattern 1: Single-Row Config Table (global_agent_config)

Identical to `siem_config` and `alert_router_config` in `db.rs`. [VERIFIED: dlp-server/src/db.rs lines 129-156]

```sql
CREATE TABLE IF NOT EXISTS global_agent_config (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    monitored_paths         TEXT NOT NULL DEFAULT '[]',
    heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
    offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
    updated_at              TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO global_agent_config (id) VALUES (1);
```

- `monitored_paths` stored as JSON text (e.g. `'["C:\\Data\\","D:\\Shared\\"]'`).
- `heartbeat_interval_secs` stored as INTEGER, validated >= 10 at PUT time.
- `offline_cache_enabled` stored as INTEGER 0/1, mapped to bool in Rust.

### Pattern 2: Multi-Row Per-Agent Override Table (agent_config_overrides)

```sql
CREATE TABLE IF NOT EXISTS agent_config_overrides (
    agent_id                TEXT PRIMARY KEY
                            REFERENCES agents(agent_id) ON DELETE CASCADE,
    monitored_paths         TEXT NOT NULL DEFAULT '[]',
    heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
    offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
    updated_at              TEXT NOT NULL DEFAULT ''
);
```

- FK to `agents.agent_id` with `ON DELETE CASCADE` — if an agent is deregistered, its
  override is automatically removed.
- No seed row — rows are inserted by `PUT /admin/agent-config/{agent_id}`.

### Pattern 3: Server-Side Payload Struct

Mirrors `SiemConfigPayload` / `AlertRouterConfigPayload` in `admin_api.rs`.
[VERIFIED: dlp-server/src/admin_api.rs lines 97-161]

```rust
/// Read/write payload for agent configuration.
///
/// Used by both `GET/PUT /admin/agent-config` (global) and
/// `GET/PUT /admin/agent-config/{agent_id}` (per-agent override).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    /// Directory paths the agent should monitor (empty = all drives).
    pub monitored_paths: Vec<String>,
    /// Heartbeat interval in seconds (minimum 10).
    pub heartbeat_interval_secs: u64,
    /// Whether offline caching is active.
    pub offline_cache_enabled: bool,
}
```

**Note on naming conflict:** `config_push.rs` already defines `pub struct AgentConfig` with
`server_url: String`. Deleting `config_push.rs` removes this conflict. The new payload struct
in `admin_api.rs` is named `AgentConfigPayload` to avoid any collision with `dlp-agent`'s
own `AgentConfig` struct (different crate, no shared type needed — they are serialized over HTTP).

### Pattern 4: Fallback Resolution (GET /agent-config/{id})

The public endpoint resolves the config for a given agent_id: per-agent override if present,
global default otherwise. This logic belongs in `admin_api.rs` as a private helper called by
the handler.

```rust
// Pseudocode for resolution logic inside spawn_blocking:
let override_row = conn.query_row(
    "SELECT monitored_paths, heartbeat_interval_secs, offline_cache_enabled
     FROM agent_config_overrides WHERE agent_id = ?1",
    params![agent_id],
    |row| { ... }
);
match override_row {
    Ok(payload) => payload,
    Err(rusqlite::Error::QueryReturnedNoRows) => {
        // fall back to global default
        conn.query_row("SELECT ... FROM global_agent_config WHERE id = 1", ...)
    }
    Err(e) => return Err(AppError::Database(e)),
}
```

### Pattern 5: Agent Poll Loop (dlp-agent/src/service.rs)

The new config poll timer is added inside `run_loop` in `service.rs`, immediately after the
existing heartbeat setup. [VERIFIED: dlp-agent/src/service.rs lines 282-287]

```rust
// Pattern from the existing heartbeat spawn:
let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
let offline_hb = offline.clone();
let _heartbeat_handle = tokio::spawn(async move {
    offline_hb.heartbeat_loop(shutdown_rx).await;
});

// New config poll (added after, same pattern):
// Arc<AgentConfigState> holds Arc<Mutex<AgentConfig>> + poll interval.
// The task reads the current interval from *its own snapshot*, not the new one.
```

The config poll task needs access to:
1. `ServerClient` (already constructed in `run_loop` — pass a clone).
2. A `Arc<Mutex<AgentConfig>>` shared with the `InterceptionEngine` and the TOML write path.
3. A `tokio::sync::watch::Receiver<bool>` for clean shutdown.

### Pattern 6: TOML Write-Back (dlp-agent/src/config.rs)

`AgentConfig` already derives `Serialize`. `toml` crate is already a dependency. Add a `save`
method to `AgentConfig`:

```rust
/// Persists the current config to a TOML file.
///
/// # Arguments
/// * `path` - Destination path (typically DEFAULT_CONFIG_PATH).
///
/// # Errors
/// Returns an error if serialization or file write fails.
pub fn save(&self, path: &Path) -> anyhow::Result<()> {
    // server_url and machine_name are excluded: server_url is never pushed,
    // machine_name is #[serde(skip)].
    let toml_str = toml::to_string(self)
        .context("failed to serialize AgentConfig to TOML")?;
    std::fs::write(path, toml_str)
        .with_context(|| format!("failed to write config to {}", path.display()))?;
    Ok(())
}
```

`machine_name` is already `#[serde(skip)]` so it will not be written. `server_url` is an
`Option<String>` and will be preserved in the round-trip (agent never changes it via poll).

### Pattern 7: AgentConfig Hot-Reload

The `InterceptionEngine` is constructed with `agent_config` in `run_loop` (line 290). To support
hot-reload of `monitored_paths`, the engine needs to be told to update its watch set when the
config changes.

**Key constraint:** The CONTEXT.md decision is to apply changes in-memory immediately. However,
the `InterceptionEngine` owns its `notify` watcher with paths fixed at construction time. True
hot-reload of watched directories requires a redesign of `InterceptionEngine` that is out of scope
for Phase 6.

**Practical scope for Phase 6:**
- `heartbeat_interval_secs` and `offline_cache_enabled` can be hot-reloaded in-memory immediately
  (the poll timer reads the interval from the shared config each tick; `OfflineManager` reads the
  cache flag on each decision).
- `monitored_paths` change is written to `agent-config.toml` so it takes effect on the next
  agent restart — this matches the UAT criterion ("agent picks up changes") without requiring
  live watcher manipulation.
- Log at INFO level: "config changed: fields=[heartbeat_interval_secs, offline_cache_enabled]"
  (field names only, no values).

This is the correct, scoped interpretation: persist all three fields to TOML on any change;
only heartbeat_interval_secs and offline_cache_enabled take effect without a restart.

### Pattern 8: Validation at PUT Time

`heartbeat_interval_secs < 10` is rejected with `AppError::BadRequest`. This mirrors the
webhook URL validation in `update_alert_config_handler`. [VERIFIED: admin_api.rs line 824-828]

```rust
if payload.heartbeat_interval_secs < 10 {
    return Err(AppError::BadRequest(
        "heartbeat_interval_secs must be >= 10".to_string(),
    ));
}
```

### Recommended File Structure

```
dlp-server/src/
    db.rs                    -- ADD two CREATE TABLE statements + seed row
    admin_api.rs             -- ADD AgentConfigPayload struct + 6 new handlers + route wiring
    config_push.rs           -- DELETE (dead code, server-push model is not viable)
    lib.rs                   -- REMOVE pub mod config_push declaration

dlp-agent/src/
    config.rs                -- ADD AgentConfig::save() method + new fields for heartbeat/offline
    server_client.rs         -- ADD ServerClient::fetch_agent_config() method
    service.rs               -- ADD config poll timer task in run_loop
```

### Anti-Patterns to Avoid

- **Bundling config into heartbeat response:** Decided against — heartbeat semantics stay clean.
- **Using tokio::time::sleep in the poll loop:** Use `tokio::time::interval` + `select!` with
  a shutdown watch receiver, identical to the offline heartbeat loop pattern.
- **Applying the new interval immediately:** The poll timer reads the interval from the
  *previously applied* config snapshot — see CONTEXT.md decision 4.
- **Logging path values:** Log field names changed, not the monitored_paths list contents.
- **Foreign key on agent_config_overrides without enabling FK enforcement:** rusqlite does not
  enforce FK constraints unless `PRAGMA foreign_keys = ON` is set per connection. Since the
  `ON DELETE CASCADE` is a safety net (not a correctness invariant for the phase), this is
  acceptable — but note it in code comments.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JSON array in SQLite | Custom serializer | `serde_json::to_string` / `serde_json::from_str` | Already used project-wide; handles escaping correctly |
| TOML serialization | Manual string building | `toml::to_string` | toml crate already in dlp-agent/Cargo.toml |
| Async timer | sleep loop | `tokio::time::interval` + `select!` | Proper cancellation; matches heartbeat_loop pattern |
| Shutdown coordination | Atomic flags | `tokio::sync::watch::Receiver<bool>` | Already established pattern in run_loop |

---

## Common Pitfalls

### Pitfall 1: config_push.rs Name Conflict

**What goes wrong:** `config_push.rs` defines `pub struct AgentConfig` with `server_url: String`.
If `config_push.rs` is not deleted, any new `AgentConfig` or `AgentConfigPayload` in `admin_api.rs`
will coexist, but a maintainer may confuse the two types.

**How to avoid:** Delete `config_push.rs` and remove `pub mod config_push;` from `lib.rs`. The
existing test `test_agent_config_serde` and `test_config_pusher_default` in that file are lost —
they test a now-dead model and do not need replacement.

**Warning signs:** Clippy `dead_code` warnings on `ConfigPusher` and `ConfigPushError` if the
module is retained.

### Pitfall 2: monitored_paths Stored as JSON Text

**What goes wrong:** The DB column is `TEXT`. If the writer uses `format!("{:?}", vec)` instead
of `serde_json::to_string`, the stored value will use Rust debug formatting, not valid JSON.

**How to avoid:** Always use `serde_json::to_string(&payload.monitored_paths)?` when writing and
`serde_json::from_str::<Vec<String>>(&raw)?` when reading. Add a unit test that round-trips an
empty vec and a non-empty vec through the JSON column.

### Pitfall 3: Poll Timer Using New Interval Immediately

**What goes wrong:** If the agent reads `heartbeat_interval_secs` from the newly received config
to reset its timer, a push from 30s -> 5s would cause immediate tight polling.

**How to avoid:** Per CONTEXT.md decision 4: the timer re-arms using the interval from the
*previously applied config snapshot*. The new interval takes effect after the next tick completes.
This is implemented by capturing the pre-update interval before applying the new config.

### Pitfall 4: rusqlite Bool Mapping

**What goes wrong:** rusqlite does not natively map SQLite INTEGER to Rust `bool`. Using
`row.get::<_, bool>(n)?` panics at runtime with a type mismatch.

**How to avoid:** Always use `row.get::<_, i64>(n)? != 0` for bool columns. [VERIFIED: pattern
in admin_api.rs line 682 — `row.get::<_, i64>(2)? != 0`].

### Pitfall 5: heartbeat_interval_secs u64 in rusqlite

**What goes wrong:** rusqlite does not natively support `u64`. Values > `i64::MAX` would overflow.
In practice heartbeat intervals are small, but using `i64` throughout and converting with
`u64::try_from(val)?` at the Rust boundary is cleaner than storing as TEXT.

**How to avoid:** Store as `INTEGER` in DB. Read as `i64`. Convert to `u64` with:
```rust
let interval_secs = u64::try_from(row.get::<_, i64>(1)?).unwrap_or(30);
```

### Pitfall 6: AgentConfig::save() Overwrites server_url

**What goes wrong:** If `AgentConfig` is serialized and written back to TOML, the `server_url`
field (if present) will be written. This is correct behavior — only *pushed fields* change, the
rest of the struct is preserved from the in-memory copy that was loaded at startup.

**How to avoid:** The config poll loop updates only the three pushed fields on the in-memory
`AgentConfig` struct. It does not replace the entire struct. Then calls `save()` on the updated
struct. Since `server_url` was loaded from TOML at startup and lives in the struct, it will be
preserved correctly.

---

## Code Examples

### Adding Tables in db.rs

```rust
// Source: dlp-server/src/db.rs lines 129-156 (siem_config / alert_router_config pattern)
// Add inside the execute_batch string in init_tables():

CREATE TABLE IF NOT EXISTS global_agent_config (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    monitored_paths         TEXT NOT NULL DEFAULT '[]',
    heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
    offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
    updated_at              TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO global_agent_config (id) VALUES (1);

CREATE TABLE IF NOT EXISTS agent_config_overrides (
    agent_id                TEXT PRIMARY KEY
                            REFERENCES agents(agent_id) ON DELETE CASCADE,
    monitored_paths         TEXT NOT NULL DEFAULT '[]',
    heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
    offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
    updated_at              TEXT NOT NULL DEFAULT ''
);
```

### GET /agent-config/{id} Handler Pattern

```rust
// Source: admin_api.rs lines 662-694 (get_siem_config_handler pattern)
// This is a public (unauthenticated) handler — placed in public_routes.
async fn get_agent_config_for_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    let id = agent_id.clone();
    let db = Arc::clone(&state.db);
    let payload = tokio::task::spawn_blocking(move || -> Result<AgentConfigPayload, AppError> {
        let conn = db.conn().lock();
        // Try per-agent override first.
        let result = conn.query_row(
            "SELECT monitored_paths, heartbeat_interval_secs, offline_cache_enabled
             FROM agent_config_overrides WHERE agent_id = ?1",
            rusqlite::params![id],
            |row| parse_config_row(row),
        );
        match result {
            Ok(p) => Ok(p),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Fall back to global default.
                conn.query_row(
                    "SELECT monitored_paths, heartbeat_interval_secs, offline_cache_enabled
                     FROM global_agent_config WHERE id = 1",
                    [],
                    |row| parse_config_row(row),
                ).map_err(AppError::Database)
            }
            Err(e) => Err(AppError::Database(e)),
        }
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    Ok(Json(payload))
}
```

### ServerClient::fetch_agent_config() Pattern

```rust
// Source: dlp-agent/src/server_client.rs lines 254-276 (fetch_auth_hash pattern)
/// Fetches the resolved agent config from dlp-server.
///
/// Calls `GET /agent-config/{agent_id}`. Returns the resolved payload
/// (per-agent override if set, global default otherwise). Returns an error
/// if the server is unreachable — callers should log and retain current config.
pub async fn fetch_agent_config(&self) -> Result<AgentConfigPayload, ServerClientError> {
    let url = format!("{}/agent-config/{}", self.base_url, self.agent_id);
    let resp = self.client.get(&url).send().await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_else(|_| "<no body>".to_string());
        return Err(ServerClientError::ServerError { status, body });
    }
    let payload: AgentConfigPayload = resp.json().await?;
    debug!(agent_id = %self.agent_id, "agent config fetched from server");
    Ok(payload)
}
```

### Config Poll Task in service.rs run_loop

```rust
// Source: dlp-agent/src/service.rs lines 283-287 (heartbeat spawn pattern)
// The shared config is an Arc<Mutex<AgentConfig>> created before run_loop spawns tasks.
// The poll task reads the current interval, ticks, fetches, diffs, applies, writes TOML.

let config_arc = Arc::new(parking_lot::Mutex::new(agent_config));
let config_for_poll = Arc::clone(&config_arc);
let sc_for_poll = server_client.clone(); // Option<ServerClient>
let (config_shutdown_tx, config_shutdown_rx) = tokio::sync::watch::channel(false);

let _config_poll_handle = if let Some(sc) = sc_for_poll {
    Some(tokio::spawn(async move {
        config_poll_loop(sc, config_for_poll, config_shutdown_rx).await;
    }))
} else {
    None
};
```

### Route Wiring in admin_router

```rust
// Source: admin_api.rs lines 296-327 (router construction pattern)
// In public_routes — add:
.route("/agent-config/:id", get(get_agent_config_for_agent))

// In protected_routes — add:
.route("/admin/agent-config", get(get_global_agent_config_handler))
.route("/admin/agent-config", put(update_global_agent_config_handler))
.route("/admin/agent-config/:agent_id", get(get_agent_config_override_handler))
.route("/admin/agent-config/:agent_id", put(update_agent_config_override_handler))
.route("/admin/agent-config/:agent_id", delete(delete_agent_config_override_handler))
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `config_push.rs` server-push model | Agent poll via `GET /agent-config/{id}` | Phase 6 decision | Agents have no HTTP listener; push is not viable |
| `AgentConfig` with `server_url` | `AgentConfigPayload` with 3 fields, no `server_url` | Phase 6 decision | Prevents self-referential cut-off |

**Deprecated/outdated:**
- `config_push.rs` (`ConfigPusher`, `ConfigPushError`, `AgentConfig` with `server_url`): entire
  module is dead code under the new poll architecture. Delete it.

---

## Open Questions (RESOLVED)

1. **Should `InterceptionEngine` support live path updates?**
   - What we know: `monitored_paths` is one of the three pushed fields. `InterceptionEngine` is
     constructed with fixed paths.
   - What's unclear: Phase 6 CONTEXT.md says "apply in-memory immediately" — but the UAT says
     "agent picks up changes", not "changes take effect within N seconds without restart."
   - Recommendation: Scope to write-back only for `monitored_paths`; live watcher update is a
     follow-on. The TOML write-back ensures changes survive the next restart. Document this
     limitation in code comments on the config poll task.
   - **RESOLVED:** Scoped to TOML write-back only. Plan 02 Task 3 documents this limitation
     in code comments. Live watcher update deferred to a follow-on phase.

2. **Should `AgentConfig` in `dlp-agent` gain `heartbeat_interval_secs` and
   `offline_cache_enabled` TOML fields?**
   - What we know: The current `AgentConfig` struct only has `server_url`, `monitored_paths`,
     `excluded_paths`, `machine_name`. The new fields need to be stored somewhere.
   - Recommendation: YES — add `heartbeat_interval_secs: Option<u64>` and
     `offline_cache_enabled: Option<bool>` to `AgentConfig` in `config.rs`, with `#[serde(default)]`
     and sensible defaults. This allows TOML round-trip and avoids a separate data structure.
   - **RESOLVED:** YES. Plan 02 Task 1 adds both fields as `Option<T>` with `#[serde(default)]`
     for backwards-compatible TOML parsing.

---

## Environment Availability

Step 2.6: SKIPPED — Phase 6 is purely code/config changes. No external tools, services, runtimes,
or CLI utilities beyond the project's own code are required. All libraries are already in Cargo.toml.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `tokio::test` |
| Config file | None (inline `#[cfg(test)]` modules) |
| Quick run command | `cargo test -p dlp-server` / `cargo test -p dlp-agent` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| R-04-S | `global_agent_config` table created + seed row | unit | `cargo test -p dlp-server test_tables_created` | Wave 0 — extend existing test |
| R-04-S | `agent_config_overrides` table created | unit | `cargo test -p dlp-server test_tables_created` | Wave 0 — extend existing test |
| R-04-S | `AgentConfigPayload` round-trips through JSON | unit | `cargo test -p dlp-server test_agent_config_payload_serde` | Wave 0 |
| R-04-S | `GET /agent-config/{id}` returns global default when no override | integration | `cargo test -p dlp-server test_get_agent_config_falls_back_to_global` | Wave 0 |
| R-04-S | `GET /agent-config/{id}` returns per-agent override when set | integration | `cargo test -p dlp-server test_get_agent_config_returns_override` | Wave 0 |
| R-04-S | `PUT /admin/agent-config` rejects heartbeat_interval_secs < 10 | unit | `cargo test -p dlp-server test_put_global_config_rejects_low_interval` | Wave 0 |
| R-04-S | `PUT /admin/agent-config/{id}` upserts override row | integration | `cargo test -p dlp-server test_put_agent_config_override` | Wave 0 |
| R-04-S | `DELETE /admin/agent-config/{id}` removes override | integration | `cargo test -p dlp-server test_delete_agent_config_override` | Wave 0 |
| R-04-A | `AgentConfig::save()` writes valid TOML | unit | `cargo test -p dlp-agent test_agent_config_save` | Wave 0 |
| R-04-A | `fetch_agent_config` returns error on unreachable server | unit | `cargo test -p dlp-agent test_fetch_agent_config_unreachable` | Wave 0 |
| R-04-A | Config diff detects changed fields | unit | `cargo test -p dlp-agent test_config_diff_detects_changes` | Wave 0 |

### Wave 0 Gaps

- [ ] `test_agent_config_payload_serde` — new test in `dlp-server/src/admin_api.rs` `#[cfg(test)]`
- [ ] `test_get_agent_config_falls_back_to_global` — new integration test
- [ ] `test_get_agent_config_returns_override` — new integration test
- [ ] `test_put_global_config_rejects_low_interval` — new unit test
- [ ] `test_put_agent_config_override` — new integration test
- [ ] `test_delete_agent_config_override` — new integration test
- [ ] `test_agent_config_save` — new test in `dlp-agent/src/config.rs` `#[cfg(test)]`
- [ ] `test_fetch_agent_config_unreachable` — new test in `dlp-agent/src/server_client.rs` `#[cfg(test)]`
- [ ] `test_config_diff_detects_changes` — new unit test (location TBD: `service.rs` or new module)
- [ ] Extend `test_tables_created` in `dlp-server/src/db.rs` for both new tables

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | `GET /agent-config/{id}` is intentionally unauthenticated (agent_id is not a secret); admin endpoints require JWT via `require_auth` middleware |
| V3 Session Management | no | No new sessions |
| V4 Access Control | yes | Admin config endpoints are in `protected_routes` behind `require_auth` middleware [VERIFIED: admin_api.rs line 325] |
| V5 Input Validation | yes | `heartbeat_interval_secs >= 10` enforced at PUT; `monitored_paths` is a JSON array of strings (no path traversal enforced at server — server stores what admin sends) |
| V6 Cryptography | no | No new crypto |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Unauthorized config write | Tampering | JWT on all PUT/DELETE admin routes |
| Path injection via monitored_paths | Tampering | Server stores verbatim (admin-controlled). Agent applies paths locally. Paths are only watched, not accessed by server. Low risk. |
| Agent impersonation on `GET /agent-config/{id}` | Spoofing | Endpoint is deliberately unauthenticated — any caller who knows an agent_id gets that agent's config. Config contains no secrets. Acceptable per CONTEXT.md design decision. |
| `heartbeat_interval_secs = 0` DoS | DoS | Minimum 10s enforced at PUT time |

---

## Sources

### Primary (HIGH confidence)
- [VERIFIED: dlp-server/src/db.rs] — Table creation pattern, `CHECK (id = 1)`, seed row
- [VERIFIED: dlp-server/src/admin_api.rs] — Handler pattern, route wiring, payload structs,
  `spawn_blocking`, `validate_webhook_url` validation pattern
- [VERIFIED: dlp-agent/src/config.rs] — `AgentConfig` struct, `load()` pattern, TOML serde,
  `DEFAULT_CONFIG_PATH`
- [VERIFIED: dlp-agent/src/server_client.rs] — `ServerClient` methods, `fetch_auth_hash` pattern,
  `ServerClientError` variants
- [VERIFIED: dlp-agent/src/service.rs] — `run_loop` structure, heartbeat task spawn, shutdown
  watch channel pattern
- [VERIFIED: dlp-server/src/lib.rs] — `AppState` fields, module declarations
- [VERIFIED: dlp-server/src/agent_registry.rs] — `agents` table schema (for FK reference)
- [VERIFIED: dlp-server/Cargo.toml] — all dependencies confirmed present
- [VERIFIED: dlp-agent/Cargo.toml] — `toml = "0.8"` confirmed present

### Secondary (MEDIUM confidence)
- [ASSUMED] rusqlite u64 limitation: rusqlite INTEGER maps to i64 natively; u64 requires
  manual conversion. Consistent with rusqlite 0.31 behavior.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | rusqlite does not natively map `u64` — must use `i64` and convert | Code Examples, Pitfalls | If wrong: no impact (defensive coding is still correct); `i64` is always safe |
| A2 | `ON DELETE CASCADE` FK not enforced without `PRAGMA foreign_keys = ON` per connection | Architecture Patterns | If wrong: FK would be enforced, which is actually stricter and still correct behavior |
| A3 | `monitored_paths` live hot-reload requires `InterceptionEngine` redesign | Architecture Patterns, Open Questions | If wrong (engine can be updated): the plan would need an additional task to call engine.update_paths(); still a valid follow-on |

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries confirmed in Cargo.toml
- Architecture: HIGH — all patterns verified in existing codebase; no new libraries introduced
- Pitfalls: HIGH — verified from existing code patterns and rusqlite known behavior

**Research date:** 2026-04-12
**Valid until:** 2026-05-12 (stable libraries; no fast-moving dependencies)
