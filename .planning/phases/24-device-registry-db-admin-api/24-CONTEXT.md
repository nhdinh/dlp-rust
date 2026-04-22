# Phase 24: Device Registry DB + Admin API - Context

**Gathered:** 2026-04-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a `device_registry` table to the dlp-server SQLite DB and expose three JWT-protected admin endpoints (`GET`, `POST`, `DELETE /admin/device-registry`) so admins can manage per-device trust tiers. Extend dlp-agent with a background poller that fetches the registry and caches it in `RwLock<HashMap>` keyed by `(vid, pid, serial)` for Phase 26 enforcement use.

No enforcement changes in this phase — that is Phase 26's job.

</domain>

<decisions>
## Implementation Decisions

### Admin API Authentication

- **D-01:** `GET /admin/device-registry` is **unauthenticated** — agents poll it without stored credentials, matching the existing config poll endpoint pattern. The server listens on localhost only, so network exposure is minimal.
- **D-02:** `POST /admin/device-registry` and `DELETE /admin/device-registry/{id}` **require JWT Bearer auth** — admin-only mutations, same JWT middleware already applied to all other write endpoints.

### Registry Row Shape and Uniqueness

- **D-03:** Primary key is a **UUID string** — consistent with the `policies` table pattern. The UUID is generated server-side on INSERT and returned in the `GET` response so the admin TUI can reference it for DELETE.
- **D-04:** `(vid, pid, serial)` has a **UNIQUE constraint**. `POST` with a duplicate triple performs an **upsert** (UPDATE trust tier and description on conflict) rather than returning 409. One row per physical device identity.
- **D-05:** Trust tier column is enforced with a **DB CHECK constraint**: `CHECK(trust_tier IN ('blocked', 'read_only', 'full_access'))` — invalid values are rejected at the DB layer; the API returns 422 for tier values outside this set.

### Delete Route Identifier

- **D-06:** The delete route is `DELETE /admin/device-registry/{id}` where `{id}` is the **UUID** from D-03. This is consistent with the policy delete pattern and avoids URL-encoding issues with composite keys.

### Agent Cache Refresh

- **D-07:** The agent maintains a `RwLock<HashMap<(String, String, String), UsbTrustTier>>` keyed by `(vid, pid, serial)`. The values are trust tiers from the DB, not `DeviceIdentity` structs (those live in Phase 23's `device_identities` map keyed by drive letter).
- **D-08:** Cache refresh is **timer-based: every 30 seconds**. The agent spawns a background task (matches the `server_client.rs` flush loop pattern) that calls `GET /admin/device-registry` and replaces the map atomically.
- **D-09:** On USB device arrival (WM_DEVICECHANGE), the agent triggers an **immediate refresh** of the registry cache as an optimization — reduces enforcement latency on the hot path. This is additive to the 30-second timer, not a replacement.
- **D-10:** If the server is unreachable, the agent keeps its stale cache rather than clearing it — fail-safe behavior consistent with the existing offline module.

### Repository Structure

- **D-11:** A new `DeviceRegistryRepository` struct follows the stateless repository pattern in `db/repositories/`. A new `DeviceRegistryRow` (for reads) is defined in the same file.
- **D-12:** The agent-side module lives in a new `dlp-agent/src/device_registry.rs` — it owns the cache type, the polling loop, and a `trust_tier_for(vid, pid, serial)` accessor used by Phase 26.

### Claude's Discretion

- Whether to add a `description` field as optional or required in the POST body — Claude decides based on what's most ergonomic (recommended: optional, defaults to empty string).
- Exact polling interval configuration (env var vs hardcoded 30s constant) — Claude decides (recommended: hardcoded constant; configurable polling adds complexity not yet needed).
- Whether the upsert uses `INSERT OR REPLACE` or `INSERT ... ON CONFLICT DO UPDATE` — Claude decides based on rusqlite compatibility.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Requirements
- `.planning/REQUIREMENTS.md` — USB-02 requirement definition (GET/POST/DELETE endpoints, trust tier values, agent cache)
- `.planning/ROADMAP.md` §Phase 24 — 4 success criteria

### Existing Type Definitions (Phase 22)
- `dlp-common/src/endpoint.rs` — `UsbTrustTier` enum (`Blocked`, `ReadOnly`, `FullAccess`; serializes as `"blocked"`, `"read_only"`, `"full_access"`); `DeviceIdentity` struct (vid, pid, serial, description all `String`)
- `dlp-common/src/lib.rs` — re-exports

### Existing Repository Pattern (mirror for DeviceRegistryRepository)
- `dlp-server/src/db/repositories/policies.rs` — stateless `PolicyRepository` with `PolicyRow`/`PolicyUpdateRow`; this is the exact pattern to follow
- `dlp-server/src/db/repositories/mod.rs` — where to register the new module and re-exports

### Existing Admin API (where new routes are added)
- `dlp-server/src/admin_api.rs` — JWT middleware wiring, route registration pattern, `AppState` shared state; new device registry routes go here
- `dlp-server/src/db/mod.rs` — schema initialization; new `CREATE TABLE device_registry` goes here alongside existing tables

### Existing Agent Polling Pattern
- `dlp-agent/src/server_client.rs` — `AuditBuffer` flush loop (background `tokio::spawn` with interval); device registry poller follows the same structure
- `dlp-agent/src/cache.rs` — `RwLock` + TTL cache pattern; device registry cache is simpler (no TTL, timer-driven refresh)
- `dlp-agent/src/detection/usb.rs` — Phase 23 `device_identities: RwLock<HashMap<char, DeviceIdentity>>`; Phase 24 adds a separate `RwLock<HashMap<(String,String,String), UsbTrustTier>>` (different key, different purpose)

### Prior Phase Context
- `.planning/phases/23-usb-enumeration-in-dlp-agent/23-CONTEXT.md` — D-09/D-10 describe Phase 23 in-memory map; Phase 24 cache is distinct and must not replace it

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `UsbTrustTier` from `dlp-common::endpoint` — use directly as the trust tier type in both DB row and cache value; no new enum needed
- `DeviceIdentity` from `dlp-common::endpoint` — contains vid/pid/serial/description fields; use field names as the canonical column names in `device_registry` table
- `PolicyRepository` stateless struct pattern — copy structure exactly for `DeviceRegistryRepository`
- JWT middleware in `admin_api.rs` — already wired; new POST/DELETE routes just join the existing protected router layer

### Established Patterns
- Schema changes: `CREATE TABLE IF NOT EXISTS` in `db::open` alongside existing tables; no migration framework, matches ALTER TABLE pattern used elsewhere
- Route registration: `Router::new().route(path, method(handler)).with_state(state)` merged into the main router in `admin_api.rs`
- Agent background tasks: `tokio::spawn(async move { loop { ... tokio::time::sleep(interval).await; } })` matching the audit flush loop

### Integration Points
- `dlp-server/src/db/mod.rs` — add `CREATE TABLE device_registry` in the schema init block
- `dlp-server/src/admin_api.rs` — register `GET/POST/DELETE /admin/device-registry` routes; GET joins the public router, POST/DELETE join the JWT-protected router
- `dlp-agent/src/service.rs` — spawn the registry polling loop at agent startup alongside existing background tasks
- `dlp-agent/src/detection/usb.rs` — trigger immediate cache refresh from `WM_DEVICECHANGE` arrival handler (D-09)

</code_context>

<specifics>
## Specific Ideas

- No specific UI references for this phase — the admin TUI screen is Phase 28's job. Phase 24 only delivers the API layer.
- The agent cache accessor `trust_tier_for(vid, pid, serial) -> UsbTrustTier` should return `UsbTrustTier::Blocked` (the default) when a device is not in the registry — consistent with `UsbTrustTier::default()`.

</specifics>

<deferred>
## Deferred Ideas

- Per-user device registry (USB-06: owner_user column) — explicitly deferred in REQUIREMENTS.md; per-machine registry sufficient for v0.6.0
- USB audit events including device identity (USB-05) — deferred to post-USB-03
- Admin TUI screen for device registry — Phase 28
- Version-gated cache refresh (server embeds registry_version in heartbeat) — noted as a future optimization; 30-second timer is sufficient for v0.6.0
- Configurable polling interval via env var — unnecessary complexity for now

</deferred>

---

*Phase: 24-device-registry-db-admin-api*
*Context gathered: 2026-04-22*
