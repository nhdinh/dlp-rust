# Phase 37: Server-Side Disk Registry - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-04
**Phase:** 37-server-side-disk-registry
**Areas discussed:** Agent sync mechanism, Unique key & POST semantics, Audit Action enum variants, encrypted field representation

---

## Agent sync mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| Server-only, no sync yet | Phase 37 is pure server-side storage. Agents still enforce from local TOML. | |
| Include config push to agents | POST/DELETE handlers trigger config_push to agent_id after DB write. Live enforcement update. | ✓ |
| Agent polls server at enforcement time | Agent calls GET /admin/disk-registry on every disk I/O check. Breaks offline-first design. | |

**User's choice:** Include config push to agents (immediate push on add/remove).

**Notes:** User clarified a critical security invariant: disk registry entries MUST be scoped per `(agent_id, instance_id)`. The motivation is preventing a physical relocation attack — someone taking a disk from a decommissioned (previously-allowed) machine, plugging it into a new machine, and copying data. A disk allowed on machine-A is NOT allowed on machine-B. Agent must reload `instance_id_map` live (no restart) when the config push arrives.

---

### Agent sync — push trigger

| Option | Description | Selected |
|--------|-------------|----------|
| Immediate push on add/remove | Handler triggers config_push right after DB write. | ✓ |
| Scheduled push / agent polls | Server queues change; agent picks up on next heartbeat (30s delay). | |

**User's choice:** Immediate push on add/remove.

---

### Agent sync — agent-side reload

| Option | Description | Selected |
|--------|-------------|----------|
| Reload instance_id_map live, no restart | Agent updates DiskEnumerator.instance_id_map in memory + writes TOML. | ✓ |
| Write TOML only, enforce on next restart | Agent writes TOML; new allowlist takes effect after service restart. | |

**User's choice:** Live reload — no restart required.

---

## Unique key & POST semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Return 409 Conflict | Pure INSERT — reject with 409 if (agent_id, instance_id) already exists. | ✓ |
| Upsert — update fields on conflict | ON CONFLICT DO UPDATE, same as USB DeviceRegistry. Silent updates allowed. | |

**User's choice:** 409 Conflict on duplicate (pure INSERT).

---

### GET filtering

| Option | Description | Selected |
|--------|-------------|----------|
| Always return all, no filter | Single response with all fleet entries. | |
| Optional ?agent_id= query param | GET /admin/disk-registry?agent_id=hostname returns per-machine entries. | ✓ |

**User's choice:** Optional `?agent_id=` filter.

---

### POST agent_id validation

| Option | Description | Selected |
|--------|-------------|----------|
| Validate agent_id exists in agents table | Reject with 404 if agent not registered. Prevents orphan entries. | |
| Accept any agent_id string | No FK check — allows pre-registering disks before agent connects. | ✓ |

**User's choice:** Accept any agent_id string (no FK validation).

---

## Audit Action enum variants

| Option | Description | Selected |
|--------|-------------|----------|
| DiskRegistryAdd / DiskRegistryRemove | Disk-specific names; clear in SIEM filters; mirrors DiskDiscovery convention. | ✓ |
| DeviceRegistryAdd / DeviceRegistryRemove | Generic names; could apply to USB registry retroactively (which currently has no audit events). | |

**User's choice:** `DiskRegistryAdd` / `DiskRegistryRemove`.

---

### Audit event resource field

| Option | Description | Selected |
|--------|-------------|----------|
| disk:{instance_id}@{agent_id} | Encodes disk + machine. SIEM can filter resource LIKE 'disk:%'. | ✓ |
| disk-registry:{row_uuid} | Opaque UUID — requires cross-reference to interpret. | |

**User's choice:** `"disk:{instance_id}@{agent_id}"`.

---

## encrypted field representation

| Option | Description | Selected |
|--------|-------------|----------|
| Simple boolean | SQLite INTEGER 0/1; JSON true/false. ADMIN-01 literal interpretation. | |
| String matching EncryptionStatus enum | Stores 'fully_encrypted', 'partially_encrypted', 'unencrypted', 'unknown'. | ✓ |

**User's choice:** String matching `EncryptionStatus` enum from Phase 34.

---

### Column name

| Option | Description | Selected |
|--------|-------------|----------|
| Rename to encryption_status | Honest about stored string type; matches DiskIdentity.encryption_status naming. | ✓ |
| Keep name 'encrypted' as in ADMIN-01 | Preserves requirement literal but misleading for string storage. | |

**User's choice:** Rename to `encryption_status` (ADMIN-01 named it `encrypted` before the string-vs-bool decision was made).

---

## Claude's Discretion

- Config push content: full `AgentConfig` vs only `disk_allowlist` section — recommended full config (existing push mechanism already handles this).
- Whether GET `/admin/disk-registry` is protected or public — recommended protected (JWT required), unlike the unauthenticated USB device registry list.
- `registered_at` timestamp format — recommended UTC RFC-3339, consistent with all other timestamp fields.
- Column order in `CREATE TABLE` — recommended follow ADMIN-01 field order: `id, agent_id, instance_id, bus_type, encryption_status, model, registered_at`.

## Deferred Ideas

- Automatic disk pre-registration from `DiskDiscovery` audit events (draft/pending state for admin approval) — new workflow not yet designed.
- Batch import of disk registry entries for large fleet migrations — v0.7.1+.
- Additional GET filters (bus_type, encryption_status, model) — Phase 38 TUI can filter client-side.
- FK constraint `REFERENCES agents(agent_id) ON DELETE CASCADE` — deferred per D-06 (pre-registration allowed).
- Retroactive `AdminAction` audit events for USB device registry — separate cleanup task, out of scope here.
