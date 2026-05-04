---
phase: 37-server-side-disk-registry
verified: 2026-05-04T00:00:00Z
status: passed
score: 5/5 must-haves verified
overrides_applied: 0
overrides:
  - must_have: "Server stores disk registry in SQLite with agent_id, instance_id, bus_type, encrypted, model, and registered_at columns"
    reason: "ROADMAP SC #1 uses 'encrypted' as shorthand for the column; the implementation uses 'encryption_status' which is the correct semantic name. The column stores a multi-value status string ('encrypted', 'suspended', 'unencrypted', 'unknown'), not a boolean. The plan, code, tests, and documentation all use 'encryption_status' consistently. The ROADMAP entry is a documentation shorthand, not a literal column-name requirement."
    accepted_by: "gsd-verifier"
    accepted_at: "2026-05-04T00:00:00Z"
---

# Phase 37: Server-Side Disk Registry Verification Report

**Phase Goal:** Admin can centrally manage disk allowlist across the fleet via REST API
**Verified:** 2026-05-04
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Server stores disk registry in SQLite with required columns + UNIQUE + CHECK constraints | VERIFIED (override applied for column name 'encrypted' -> 'encryption_status') | `disk_registry` table in `dlp-server/src/db/mod.rs` lines 239-251: 7 columns (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at), UNIQUE(agent_id, instance_id), CHECK(encryption_status IN ('encrypted','suspended','unencrypted','unknown')). 5 schema tests pass. |
| 2 | Admin can list all registered disks across the fleet via GET /admin/disk-registry | VERIFIED | `list_disk_registry_handler` at `admin_api.rs:1753` wired at `/admin/disk-registry` (GET) in `protected_routes`. Returns JSON array ordered by registered_at ASC. Supports `?agent_id=X` filter. 4 tests pass. |
| 3 | Admin can add a disk to the allowlist via POST /admin/disk-registry | VERIFIED | `insert_disk_registry_handler` at `admin_api.rs:1794` returns 201/409/422. Pure INSERT semantics (no ON CONFLICT clause). `extended_code == 2067` -> 409. Length guard + `VALID_STATUSES` allowlist before DB access. 5 handler tests pass. |
| 4 | Admin can remove a disk from the allowlist via DELETE /admin/disk-registry/{id} | VERIFIED | `delete_disk_registry_handler` at `admin_api.rs:1944`. Uses `DELETE ... RETURNING` for atomic read+delete (TOCTOU-safe). Returns 204 on success, 404 when UUID missing. 3 delete tests pass. |
| 5 | Admin override actions emitted as EventType::AdminAction audit events | VERIFIED | POST handler emits `AuditEvent` with `Action::DiskRegistryAdd`, resource `format!("disk:{}@{}", instance_id, agent_id)`, Classification::T3, Decision::ALLOW, machine="server", pid=0. DELETE handler emits same with `Action::DiskRegistryRemove`. Both in second spawn_blocking after main DB commit (D-10). Audit emission test passes. |

**Score:** 5/5 truths verified

### Deferred Items

None.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dlp-common/src/abac.rs` | Action::DiskRegistryAdd, DiskRegistryRemove variants | VERIFIED | Lines 33-36: both variants present with correct derives. No `#[serde(rename)]` -- serialize as literal variant names. 4 phase37_action_tests pass. |
| `dlp-server/src/db/mod.rs` | disk_registry CREATE TABLE inside init_tables | VERIFIED | Lines 239-251: full DDL block with 7 columns, UNIQUE, CHECK. 5 schema tests pass. |
| `dlp-server/src/db/repositories/disk_registry.rs` | DiskRegistryRepository with list_all, insert, delete_by_id, list_by_agent | VERIFIED | 560 lines. All 4 public methods present. Pure INSERT (0 ON CONFLICT occurrences). 10 repo tests pass. |
| `dlp-server/src/db/repositories/mod.rs` | pub mod disk_registry; pub use re-exports | VERIFIED | Line 13: `pub mod disk_registry;`, line 27: `pub use disk_registry::{DiskRegistryRepository, DiskRegistryRow};` -- alphabetical between device_registry and exceptions. |
| `dlp-server/src/admin_api.rs` | DiskRegistryRequest, Response, Filter types; 3 handlers; AgentConfigPayload.disk_allowlist; routes wired | VERIFIED | All types present (lines 349-408). All 3 handlers implemented (lines 1753, 1794, 1944). `disk_allowlist: Vec<dlp_common::DiskIdentity>` with `#[serde(default)]` in AgentConfigPayload (line 282). Routes wired in protected_routes only (lines 686-694). 18 handler tests pass. |
| `dlp-agent/src/server_client.rs` | AgentConfigPayload.disk_allowlist with #[serde(default)] | VERIFIED | Lines 137-138: `#[serde(default)] pub disk_allowlist: Vec<dlp_common::DiskIdentity>`. 3 serde tests pass. |
| `dlp-agent/src/service.rs` | apply_payload_to_config + merge_disk_allowlist_into_map; lock-order invariant | VERIFIED | `apply_payload_to_config` at line 252, `merge_disk_allowlist_into_map` at line 330. Config lock acquired then RELEASED before `instance_id_map.write()` (T-37-13). 5 config_poll tests pass. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| POST /admin/disk-registry handler | DiskRegistryRepository::insert | spawn_blocking + UnitOfWork | WIRED | `admin_api.rs:1877`: `DiskRegistryRepository::insert(&uow, &row_for_insert)` |
| POST/DELETE handler audit emission | audit_store::store_events_sync | second spawn_blocking after main commit (D-10) | WIRED | `admin_api.rs:1913, 2008`: both handlers call `audit_store::store_events_sync` in independent spawn_blocking after registry write commits |
| get_agent_config_for_agent | DiskRegistryRepository::list_by_agent | synchronous inside spawn_blocking | WIRED | `admin_api.rs:1378-1409`: `DiskRegistryRepository::list_by_agent` called, result mapped through `disk_row_to_identity`, assigned to `payload.disk_allowlist` |
| admin_router protected_routes | list/insert/delete_disk_registry_handler | axum Router::route | WIRED | `admin_api.rs:686-694`: routes wired in `protected_routes` block, behind `admin_auth::require_auth` middleware layer |
| config_poll_loop | DiskEnumerator.instance_id_map | apply_payload_to_config + merge_disk_allowlist_into_map | WIRED | `service.rs:400-411`: apply inside config lock scope, merge called after lock drops |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `list_disk_registry_handler` | `rows: Vec<DiskRegistryRow>` | `DiskRegistryRepository::list_all` -> `SELECT FROM disk_registry` | Yes -- real DB query | FLOWING |
| `get_agent_config_for_agent` (disk_allowlist) | `disk_allowlist: Vec<DiskIdentity>` | `DiskRegistryRepository::list_by_agent` -> `SELECT FROM disk_registry WHERE agent_id = ?1` | Yes -- filtered DB query | FLOWING |
| `insert_disk_registry_handler` | body -> DiskRegistryRow -> DB | `INSERT INTO disk_registry` with server-generated UUID + timestamp | Yes -- real write | FLOWING |
| `AgentConfigPayload.disk_allowlist` (agent-side) | `payload.disk_allowlist` from `fetch_agent_config()` | HTTP response from server `GET /agent-config/{id}` | Yes -- real HTTP response deserialized | FLOWING |
| `merge_disk_allowlist_into_map` | `instance_id_map` | `disk_merge_data` from `apply_payload_to_config` | Yes -- real allowlist entries written to enforcement map | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| 4 dlp-common Action enum serde tests | `cargo test -p dlp-common phase37_action_tests` | 4 passed, 0 failed | PASS |
| 5 schema tests (disk_registry DDL) | `cargo test -p dlp-server --lib -- test_disk_registry_` | 5 passed, 0 failed | PASS |
| 10 repository unit tests | `cargo test -p dlp-server --lib -- db::repositories::disk_registry` | 10 passed, 0 failed | PASS |
| 18 admin_api handler tests (list + insert + delete + wiring) | `cargo test -p dlp-server --lib -- test_list_disk_registry test_insert_disk_registry test_delete_disk_registry test_agent_config_payload_disk_allowlist test_get_agent_config_for_agent test_admin_router_disk_registry test_get_admin_disk_registry` | 18 passed, 0 failed | PASS |
| Full dlp-server lib suite | `cargo test -p dlp-server --lib` | 204 passed, 0 failed | PASS |
| 8 agent-side tests (3 serde + 5 config_poll) | `cargo test -p dlp-agent --lib -- test_agent_config_payload_disk_allowlist test_config_poll_` | 8 passed, 0 failed | PASS |
| Full dlp-agent lib suite | `cargo test -p dlp-agent --lib` | 261 passed, 0 failed | PASS |
| ON CONFLICT clause absent | `grep -c "ON CONFLICT" dlp-server/src/db/repositories/disk_registry.rs` | 0 | PASS |
| Disk-registry routes NOT in public_routes | `grep -B5 "list_disk_registry_handler" admin_api.rs admin_router` | wired in `protected_routes` block (lines 686-694) behind `require_auth` middleware | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| ADMIN-01 | 37-01 | Server stores disk registry in SQLite with agent_id, instance_id, bus_type, encrypted/encryption_status, model, registered_at | SATISFIED | `disk_registry` table with 7 columns, UNIQUE(agent_id, instance_id), CHECK constraint. Column uses `encryption_status` (semantic name) rather than literal `encrypted` from ROADMAP shorthand -- see override. |
| ADMIN-02 | 37-02 | Admin can list all registered disks via GET /admin/disk-registry | SATISFIED | `list_disk_registry_handler` wired at GET /admin/disk-registry in protected_routes. Supports fleet-wide and per-agent filtered listing. |
| ADMIN-03 | 37-02 (primary) + 37-03 (agent reload) | Admin can add via POST (201/409/422) and remove via DELETE (204/404); agent applies within one poll cycle | SATISFIED | Both REST handlers verified. Agent-side `config_poll_loop` applies changes via `apply_payload_to_config` + `merge_disk_allowlist_into_map` within one poll interval. |
| AUDIT-03 | 37-02 | Admin override actions emitted as EventType::AdminAction audit events | SATISFIED | POST emits `Action::DiskRegistryAdd`, DELETE emits `Action::DiskRegistryRemove`, both with resource `disk:{instance_id}@{agent_id}`, Classification::T3, Decision::ALLOW, machine="server", pid=0, in second spawn_blocking after DB commit. |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `dlp-server/src/db/mod.rs` | 234-238 | SQL comment documenting breaking change requirement ("Deployments that stored fully_encrypted/partially_encrypted must drop + recreate disk_registry before upgrading") | Info | The CHECK constraint values deviated from PLAN's specified `fully_encrypted/partially_encrypted` to use canonical EncryptionStatus serde names (`encrypted/suspended`). This is correct and documented. Breaking change note in the comment is accurate. |

No TODO/FIXME/placeholder patterns found in Phase 37 files. No empty return values flowing to user-visible output. No `unwrap()` in library code (only in tests with descriptive expect messages).

### Human Verification Required

None. All truths and behaviors are programmatically verifiable and all checks passed.

### Gaps Summary

No gaps. All 5 ROADMAP success criteria are met. The single column-name discrepancy between ROADMAP SC #1 (`encrypted`) and the implementation (`encryption_status`) is a ROADMAP documentation shorthand, not a behavioral gap -- the column stores multi-value encryption status data, making `encryption_status` the correct and only sensible name. An override has been recorded.

#### Notable Deviations from Plans (auto-fixed by executor, all correct)

1. **CHECK constraint values changed**: PLAN 37-01 specified `fully_encrypted, partially_encrypted, unencrypted, unknown` but the implementation uses `encrypted, suspended, unencrypted, unknown` (canonical serde names of `EncryptionStatus` enum). This was discovered in Plan 02 execution when the serde roundtrip failed, and was correctly fixed. The `VALID_STATUSES` allowlist in the handler and the DB CHECK constraint both use the same canonical values.

2. **EncryptionStatus conversion uses manual match**: PLAN 37-02 specified `serde_json::from_str` roundtrip for `disk_row_to_identity`, but a manual match was implemented because DB names differ from Rust enum serde names. Correct fix.

3. **BusType custom Deserialize**: PLAN 37-03 discovered that BusType lacked forward-compatible deserialization. A custom `Deserialize` impl was added to `dlp-common/src/disk.rs` mapping unknown strings to `BusType::Unknown`. Correct fix.

4. **DELETE handler uses `DELETE ... RETURNING`**: PLAN 37-02 specified a two-step SELECT + DELETE to retrieve audit metadata, but the implementation uses a single atomic `DELETE FROM disk_registry WHERE id = ?1 RETURNING agent_id, instance_id`. This is strictly better (eliminates TOCTOU race). Correct improvement.

5. **Audit emission is best-effort (warn, not error)**: Both POST and DELETE audit blocks use `if let Err(e) = ... { tracing::warn!(...) }` instead of propagating the error. This correctly implements D-10 (audit failure must NOT roll back the registry write).

All deviations improve correctness, security, or reliability over the plan specification. Phase 37 goal is fully achieved.

---

_Verified: 2026-05-04_
_Verifier: Claude (gsd-verifier)_
