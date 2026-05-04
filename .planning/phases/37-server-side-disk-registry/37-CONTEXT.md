# Phase 37: Server-Side Disk Registry - Context

**Gathered:** 2026-05-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Admin can centrally manage the disk allowlist across the fleet via REST API. The server stores a `disk_registry` SQLite table with entries scoped per `(agent_id, instance_id)` pair. Admin lists, adds, and removes disk entries; add/remove operations immediately push an updated config to the target agent for live enforcement reload without restart. Add/remove actions emit `EventType::AdminAction` audit events. Covers ADMIN-01, ADMIN-02, ADMIN-03, AUDIT-03.

**In scope:**
- `disk_registry` table in SQLite with `id`, `agent_id`, `instance_id`, `bus_type`, `encryption_status`, `model`, `registered_at`; unique constraint on `(agent_id, instance_id)`
- `DiskRegistryRepository` in `dlp-server/src/db/repositories/disk_registry.rs` — `insert`, `list_all` (with optional agent_id filter), `delete_by_id`
- `GET /admin/disk-registry` with optional `?agent_id=` query param filter
- `POST /admin/disk-registry` — pure INSERT; returns 409 Conflict if `(agent_id, instance_id)` already exists
- `DELETE /admin/disk-registry/{id}` — delete by server-generated UUID
- Immediate config push to target agent after POST/DELETE (wired into handlers)
- Agent live reload of `instance_id_map` from received config push — no service restart
- New `DiskRegistryAdd` / `DiskRegistryRemove` Action enum variants in `dlp-common/src/abac.rs`
- `EventType::AdminAction` audit events for add/remove, emitted after DB commit

**Out of scope:**
- Admin TUI for disk registry (Phase 38)
- Disk block enforcement at agent level (Phase 36 — already implemented)
- Automatic registration of disks from agent discovery events
- Batch import of disk registry entries
- Filtering beyond `?agent_id=` (search by model, bus_type, etc.)

</domain>

<decisions>
## Implementation Decisions

### Agent sync mechanism
- **D-01:** Disk registry entries are scoped to `(agent_id, instance_id)`. A disk allowlisted on `machine-A` is NOT allowlisted on `machine-B` — even if it's the same physical disk. This closes the physical relocation attack: a disk removed from a decommissioned (previously-allowed) machine must be explicitly re-registered for the new machine by an admin.
- **D-02:** The POST and DELETE handlers trigger an **immediate config push** to the target agent_id after the DB write completes. The existing `config_push` mechanism is reused. Admin's add/remove action takes effect on the target machine without waiting for the next heartbeat cycle.
- **D-03:** When the agent receives a config push containing an updated `disk_allowlist`, it reloads `DiskEnumerator.instance_id_map` **in memory** and writes the new TOML to disk. No service restart is required. Enforcement changes immediately for subsequent file operations.

### Table schema and POST semantics
- **D-04:** Primary key is a server-generated UUID string (`id`). Unique constraint on `(agent_id, instance_id)` — one allowlist entry per machine-disk pair.
- **D-05:** POST `/admin/disk-registry` performs a pure INSERT. If `(agent_id, instance_id)` already exists, the handler returns 409 Conflict. Admin must DELETE then re-add to update any fields. No silent upsert — security allowlists should fail loudly on duplicates.
- **D-06:** No FK validation on `agent_id` at POST time. Server accepts any `agent_id` string. This allows admin to pre-register disks for a machine before the agent first connects. Orphan entries are acceptable.

### GET endpoint filtering
- **D-07:** `GET /admin/disk-registry` supports an optional `?agent_id=` query param. When provided, returns only entries for that agent. When absent, returns all fleet entries ordered by `registered_at ASC`. The TUI (Phase 38) can call either form.

### Audit events (AUDIT-03)
- **D-08:** Two new variants added to the `Action` enum in `dlp-common/src/abac.rs`: `DiskRegistryAdd` (admin added a disk to the allowlist) and `DiskRegistryRemove` (admin removed a disk). Naming mirrors `DiskDiscovery` convention and avoids premature generalization to "DeviceRegistry".
- **D-09:** Audit event resource field format: `"disk:{instance_id}@{agent_id}"`. Enables SIEM rules to filter `event_type = AdminAction AND resource LIKE 'disk:%'` for all disk registry changes without cross-referencing the registry table.
- **D-10:** Audit events emitted in a separate `tokio::task::spawn_blocking` **after** the main DB commit (same pattern as `PolicyCreate`/`PolicyDelete` audit events in `admin_api.rs`). The DB write and the audit write are in separate transactions — audit failure does not roll back the registry change.

### encryption_status field
- **D-11:** ADMIN-01 specifies a column named `encrypted` — this is renamed to `encryption_status` in the actual schema. The column stores string values matching the `EncryptionStatus` enum from Phase 34: `'fully_encrypted'`, `'partially_encrypted'`, `'unencrypted'`, `'unknown'`. A DB-layer CHECK constraint enforces the allowed values.
- **D-12:** The REST payload uses the same string values. The handler validates `encryption_status` with a server-side allowlist check before any DB access — same pattern as `trust_tier` validation in the USB `device_registry` handler (`const VALID_STATUSES: &[&str] = &[...]`). Invalid values return 422 Unprocessable Entity.

### Claude's Discretion
- Exact column order in the `CREATE TABLE` statement — recommended: `id, agent_id, instance_id, bus_type, encryption_status, model, registered_at`, mirroring ADMIN-01 field order.
- Whether `registered_at` uses UTC RFC-3339 format (recommended: yes, consistent with `created_at` in `device_registry` and all other timestamp fields).
- Config push content: whether to send the full `AgentConfig` or only the `disk_allowlist` section — recommended: send the full config (existing `config_push` mechanism already serializes the full `AgentConfig`; extracting just one field adds complexity without benefit).
- Whether the `GET /admin/disk-registry` endpoint is authenticated (protected) or public like the USB `GET /admin/device-registry` — recommended: protected (JWT required), since disk allowlist data is more sensitive than USB device IDs and there is no known agent-side read path that requires unauthenticated access.
- `tracing::info!` log line content on successful add/remove — recommended: `agent_id`, `instance_id`, and action (`"disk registry add"` / `"disk registry remove"`).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements and Roadmap
- `.planning/ROADMAP.md` — Phase 37 goal, success criteria (5 items), depends-on Phase 34
- `.planning/REQUIREMENTS.md` — ADMIN-01, ADMIN-02, ADMIN-03, AUDIT-03 definitions; note ADMIN-01 says `encrypted` column — this phase renames it to `encryption_status` per D-11
- `.planning/PROJECT.md` — Architecture, tech stack, key design decisions

### Prior Phase Context
- `.planning/phases/33-disk-enumeration/33-CONTEXT.md` — `DiskIdentity` schema (`instance_id` as canonical key, `bus_type`, `model`, `drive_letter`, `is_boot_disk`)
- `.planning/phases/34-bitlocker-verification/34-CONTEXT.md` — `EncryptionStatus` enum values (`fully_encrypted`, `partially_encrypted`, `unencrypted`, `unknown`) used by D-11/D-12
- `.planning/phases/35-disk-allowlist-persistence/35-CONTEXT.md` — `disk_allowlist` field on `AgentConfig`, TOML merge algorithm, `DiskEnumerator.instance_id_map` as frozen allowlist (D-09/D-13)
- `.planning/phases/36-disk-enforcement/36-CONTEXT.md` — D-09 (frozen allowlist invariant), D-10 (live drive_letter_map), why Phase 37/38 are the only way to add entries to `instance_id_map` after startup

### Key Source Files (read before touching)
- `dlp-server/src/db/repositories/device_registry.rs` — Direct template for `DiskRegistryRepository`. Copy `list_all` / `delete_by_id` patterns; replace `upsert` with `insert` (pure insert — no ON CONFLICT DO UPDATE, per D-05).
- `dlp-server/src/db/mod.rs` — `run_migrations` and the `CREATE TABLE` block; add `disk_registry` table here following `device_registry` pattern. Add `CHECK(encryption_status IN (...))` constraint (per D-11).
- `dlp-server/src/admin_api.rs` — `admin_router()` (add disk-registry routes to protected_routes); `upsert_device_registry_handler` (template for POST handler — adapt `trust_tier` allowlist validation pattern for `encryption_status`); `delete_device_registry_handler` (template for DELETE handler); policy create handler at ~line 785 (template for `AdminAction` audit event emission after DB commit, per D-10).
- `dlp-server/src/db/repositories/mod.rs` — Add `pub mod disk_registry; pub use disk_registry::DiskRegistryRepository;`
- `dlp-common/src/abac.rs` — `Action` enum (add `DiskRegistryAdd` and `DiskRegistryRemove` variants after `PasswordChange`, per D-08)
- `dlp-agent/src/detection/disk.rs` — `DiskEnumerator.instance_id_map` and `set_disk_enumerator()` — the live reload on config push (D-03) updates this map
- `dlp-agent/src/config.rs` — `AgentConfig::load()` / `AgentConfig::save()`, `disk_allowlist: Vec<DiskIdentity>` field added in Phase 35 — config push delivers a new `AgentConfig` JSON; agent parses and calls `set_disk_enumerator()` with the new allowlist
- `dlp-server/src/config_push.rs` — Existing config push mechanism; reuse to deliver updated config to agent after disk registry add/remove (per D-02)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DeviceRegistryRepository` (`dlp-server/src/db/repositories/device_registry.rs`) — Direct template. `list_all` and `delete_by_id` patterns copy verbatim; `insert` replaces `upsert` (no `ON CONFLICT DO UPDATE` — D-05).
- `DeviceRegistryRow` shape — Template for `DiskRegistryRow` struct. Swap `vid/pid/serial/description/trust_tier` for `agent_id/instance_id/bus_type/encryption_status/model`.
- `DeviceRegistryRequest` / `DeviceRegistryResponse` (`dlp-server/src/admin_api.rs:283-360`) — Template for `DiskRegistryRequest` / `DiskRegistryResponse` payload types.
- `upsert_device_registry_handler` (`dlp-server/src/admin_api.rs:1617`) — Template for POST handler. Adapt `trust_tier` validation to `encryption_status` allowlist check. Replace upsert with insert + 409 on conflict.
- `delete_device_registry_handler` (`dlp-server/src/admin_api.rs:1690`) — Template for DELETE handler. Copy verbatim, referencing `DiskRegistryRepository::delete_by_id`.
- Policy create audit event (`dlp-server/src/admin_api.rs:784-805`) — Template for `AdminAction` audit event emission after DB commit (D-10). Substitute `Action::DiskRegistryAdd` / `Action::DiskRegistryRemove` and `resource = format!("disk:{}@{}", instance_id, agent_id)`.
- `config_push.rs` — Existing push mechanism; call after DB commit in POST/DELETE handlers (D-02).

### Established Patterns
- `tokio::task::spawn_blocking` with explicit conn scope for pool deadlock prevention — used in every admin_api.rs handler; mandatory here too.
- `UnitOfWork` for all writes — `UnitOfWork::new(&mut conn)` + `uow.commit()` wraps the INSERT/DELETE.
- `AppError::UnprocessableEntity` (422) for invalid enum values; `AppError::NotFound` (404) for delete on missing UUID; `AppError::Conflict` (409) for duplicate insert — all already defined in `dlp-server/src/lib.rs`.
- `#[serde(rename_all = "snake_case")]` on request/response structs — consistent with all existing payload types.
- Audit emit in a second `spawn_blocking` after the first commit — guarantees audit failure does not roll back the data write.

### Integration Points
- `dlp-server/src/db/mod.rs::run_migrations()` — Add `disk_registry` CREATE TABLE statement inside the existing `execute_batch` call. Append after the `device_registry` block.
- `dlp-server/src/admin_api.rs::admin_router()` — Add three routes to `protected_routes`:
  - `GET /admin/disk-registry` → `list_disk_registry_handler`
  - `POST /admin/disk-registry` → `insert_disk_registry_handler`
  - `DELETE /admin/disk-registry/{id}` → `delete_disk_registry_handler`
- `dlp-common/src/abac.rs::Action` enum — Add `DiskRegistryAdd` and `DiskRegistryRemove` after `PasswordChange`.
- `dlp-agent/src/detection/disk.rs` — Agent-side live reload: when config push arrives with updated `disk_allowlist`, parse new `DiskIdentity` entries and call `set_disk_enumerator()` with an updated `DiskEnumerator` reflecting the new `instance_id_map`.

</code_context>

<specifics>
## Specific Requirements

### disk_registry table schema
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

### REST payload shapes (target)
```rust
/// Request body for `POST /admin/disk-registry`.
pub struct DiskRegistryRequest {
    pub agent_id: String,
    pub instance_id: String,
    pub bus_type: String,
    pub encryption_status: String,  // one of: fully_encrypted / partially_encrypted / unencrypted / unknown
    pub model: String,
}

/// Response body for `GET` and `POST /admin/disk-registry`.
pub struct DiskRegistryResponse {
    pub id: String,            // server-generated UUID
    pub agent_id: String,
    pub instance_id: String,
    pub bus_type: String,
    pub encryption_status: String,
    pub model: String,
    pub registered_at: String, // RFC-3339 UTC
}
```

### POST handler — key behavior
```
1. Length-guard: reject encryption_status > 32 chars before heap allocation
2. Allowlist check: const VALID_STATUSES = ["fully_encrypted", "partially_encrypted", "unencrypted", "unknown"]
3. Generate UUID + registered_at = Utc::now().to_rfc3339()
4. spawn_blocking: INSERT INTO disk_registry ... (UnitOfWork); if UNIQUE conflict → return 409
5. spawn_blocking: emit AdminAction audit event (resource = "disk:{instance_id}@{agent_id}", action = DiskRegistryAdd)
6. Trigger config_push to agent_id with updated disk_allowlist
7. Return 201 Created + DiskRegistryResponse
```

### Audit event (AUDIT-03)
```rust
let audit_event = dlp_common::AuditEvent::new(
    dlp_common::EventType::AdminAction,
    String::new(),           // session_id: not applicable for server-side admin ops
    username,                // extracted from JWT via AdminUsername::extract_from_headers
    format!("disk:{}@{}", instance_id, agent_id),  // resource
    dlp_common::Classification::T3,
    dlp_common::Action::DiskRegistryAdd,  // or DiskRegistryRemove
    dlp_common::Decision::ALLOW,
    "server".to_string(),    // machine
    0,                       // pid
);
```

</specifics>

<deferred>
## Deferred Ideas

- **Automatic disk pre-registration from discovery events** — when an agent emits a `DiskDiscovery` audit event, auto-create a `disk_registry` entry in draft/pending state for admin approval. Deferred — requires a workflow and UI that doesn't exist yet.
- **Batch import of disk registry entries** — useful for large fleet migrations. Deferred to v0.7.1+.
- **Additional GET filters** (bus_type, encryption_status, model search) — useful for large fleets. Deferred to Phase 38 or later; admin can filter in the TUI client-side.
- **FK constraint on agent_id** — REFERENCES agents(agent_id) ON DELETE CASCADE. Not added now (D-06 allows pre-registration). Could be added as a Phase 38 migration if needed.
- **Retroactive audit events for USB device registry** — USB device registry currently emits no `AdminAction` events. Adding them would be good hygiene but is out of scope here; separate cleanup task.

</deferred>

---

*Phase: 37-server-side-disk-registry*
*Context gathered: 2026-05-04*
