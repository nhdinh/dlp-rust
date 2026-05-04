---
phase: 37
plan: 02
subsystem: server-api
tags: [disk-registry, rest-api, admin, audit, jwt, abac, tdd]
dependency_graph:
  requires:
    - dlp-common::Action::DiskRegistryAdd (Phase 37 Plan 01)
    - dlp-common::Action::DiskRegistryRemove (Phase 37 Plan 01)
    - disk_registry SQLite table (Phase 37 Plan 01)
    - DiskRegistryRepository (list_all, list_by_agent, insert, delete_by_id) (Phase 37 Plan 01)
  provides:
    - GET /admin/disk-registry (JWT-protected list endpoint)
    - POST /admin/disk-registry (JWT-protected insert endpoint with 409/422 validation)
    - DELETE /admin/disk-registry/{id} (JWT-protected delete endpoint)
    - AdminAction audit events for DiskRegistryAdd and DiskRegistryRemove
    - AgentConfigPayload.disk_allowlist field (server-side)
    - get_agent_config_for_agent populates disk_allowlist from disk_registry
  affects:
    - dlp-server/src/admin_api.rs (handlers, types, route wiring, AgentConfigPayload extension)
    - dlp-server/src/alert_router.rs (pre-existing clippy fix)
    - dlp-server/src/db/repositories/disk_registry.rs (minor additions)
tech_stack:
  added: []
  patterns:
    - Two-spawn_blocking audit pattern: first for DB write, second for audit emit (D-10)
    - Length guard then allowlist check before any DB access (D-12, T-37-05)
    - UNIQUE conflict detection via rusqlite extended_code 2067 (D-05, T-37-06)
    - Explicit conn scope release to avoid max_size=1 pool deadlock in delete handler
    - serde JSON roundtrip for BusType enum parsing from DB string
    - Manual match mapping for EncryptionStatus (DB names differ from enum serde names)
key_files:
  created: []
  modified:
    - dlp-server/src/admin_api.rs (before 4177 lines; after 5415 lines; +1238 lines)
    - dlp-server/src/alert_router.rs (before 821 lines; after 820 lines; -1 line clippy fix)
    - dlp-server/src/db/repositories/disk_registry.rs (before 484 lines; after 560 lines; +76 lines)
decisions:
  - "Disk-registry routes placed in protected_routes (JWT required), NOT public_routes -- per T-37-08 and CONTEXT.md Claude's Discretion"
  - "Audit emission uses a second spawn_blocking AFTER the main DB commit (D-10) -- audit failure does NOT roll back the registry write"
  - "EncryptionStatus conversion uses manual match (not serde JSON roundtrip) because DB stores fully_encrypted/partially_encrypted while Rust enum serializes as encrypted/suspended"
  - "delete_disk_registry_handler reads (agent_id, instance_id) then DELETEs in one spawn_blocking using explicit conn scope guard to prevent max_size=1 pool deadlock"
metrics:
  duration: "22 minutes"
  completed: "2026-05-04"
  tasks_completed: 3
  files_changed: 3
---

# Phase 37 Plan 02: Disk Registry REST API with Audit Emission Summary

JWT-protected GET/POST/DELETE REST endpoints for the disk registry, AdminAction audit events on every add/remove (AUDIT-03), and AgentConfigPayload.disk_allowlist populated from the per-agent disk registry for polling agents.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add request/response types and list_disk_registry_handler (GET endpoint) | f165804 | dlp-server/src/admin_api.rs |
| 2 | Implement insert_disk_registry_handler and delete_disk_registry_handler with audit emission | 2d30cf4 | dlp-server/src/admin_api.rs |
| 3 | Wire routes, extend AgentConfigPayload with disk_allowlist, populate from get_agent_config_for_agent | e02dd53 | dlp-server/src/admin_api.rs, dlp-server/src/alert_router.rs, dlp-server/src/db/repositories/disk_registry.rs |

## Test Results

| Test Suite | Pass | Fail |
|-----------|------|------|
| list handler tests (4 tests) | 4 | 0 |
| insert handler tests (5 tests) | 5 | 0 |
| delete handler tests (3 tests) | 3 | 0 |
| Task 3 wiring tests (6 tests) | 6 | 0 |
| dlp-server lib full suite | 204 | 0 |
| **Total new** | **18** | **0** |

## Files Created / Modified

| File | Status | Lines |
|------|--------|-------|
| dlp-server/src/admin_api.rs | MODIFIED | 5415 (+1238 from 4177) |
| dlp-server/src/alert_router.rs | MODIFIED | 820 (-1 clippy fix) |
| dlp-server/src/db/repositories/disk_registry.rs | MODIFIED | 560 (+76) |

## Security Verification

| Threat ID | Mitigation | Status |
|-----------|-----------|--------|
| T-37-04 | All three handlers wired into protected_routes; JWT enforced by admin_auth::require_auth middleware | CONFIRMED |
| T-37-05 | Length guard (>32 chars) + const VALID_STATUSES allowlist BEFORE any DB access | CONFIRMED |
| T-37-06 | Pure INSERT; rusqlite extended_code 2067 maps to 409 Conflict | CONFIRMED |
| T-37-07 | Audit emission in second spawn_blocking AFTER main DB commit; separate transactions | CONFIRMED |
| T-37-08 | GET /admin/disk-registry in protected_routes only; disk_allowlist in agent-config scoped to agent_id | CONFIRMED |
| T-37-09 | list_by_agent filter in get_agent_config_for_agent ensures per-agent scoping | CONFIRMED |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] EncryptionStatus serde roundtrip does not work -- manual match required**
- **Found during:** Task 3 implementation
- **Issue:** The plan specified `serde_json::from_str(&format!("\"{}\"", row.encryption_status)).ok()` for encryption_status parsing. This fails because the DB stores `"fully_encrypted"` / `"partially_encrypted"` but the `EncryptionStatus` Rust enum serializes as `"encrypted"` / `"suspended"` (serde rename). The roundtrip would always return None for the two most common states.
- **Fix:** Replaced with a manual match mapping: `"fully_encrypted" -> Encrypted`, `"partially_encrypted" -> Suspended`, `"unencrypted" -> Unencrypted`, `"unknown" -> Unknown`, `_ -> None` (treat unrecognized as unverified).
- **Files modified:** dlp-server/src/admin_api.rs (disk_row_to_identity function)
- **Commit:** e02dd53

**2. [Rule 1 - Bug] Pre-existing clippy warning in alert_router.rs**
- **Found during:** Task 3 (cargo clippy -- -D warnings run)
- **Issue:** alert_router.rs:202 had `"error".to_string().into()` -- useless conversion from String to String. This pre-existing issue caused clippy to fail with -D warnings.
- **Fix:** Removed the redundant `.into()` call.
- **Files modified:** dlp-server/src/alert_router.rs
- **Commit:** e02dd53

### Pre-existing Issues (Out of Scope)

- Integration test binaries fail to link with "paging file too small" (OS error 1455) in the worktree environment when building external integration test binaries. This is a Windows virtual memory exhaustion issue in parallel worktree builds, not a code defect. All unit tests (`--lib`) pass.

## Threat Surface Scan

No new threat surfaces beyond what was enumerated in the plan's threat model. All three endpoints are JWT-protected. The disk_allowlist exposure on the public GET /agent-config/{id} endpoint is restricted to entries scoped to the requested agent_id only -- no cross-agent information disclosure.

## Known Stubs

None. The AgentConfigPayload.disk_allowlist field is fully populated from disk_registry via DiskRegistryRepository::list_by_agent. No placeholder or empty values flow to the agent.

## Handoff Note

Plan 03 may now extend the agent-side configuration handling:

1. The server-side wire format is settled: `AgentConfigPayload.disk_allowlist: Vec<DiskIdentity>` with `#[serde(default)]` for backward compatibility with older server builds.
2. The agent-side `AgentConfigPayload` mirror in dlp-agent should add `#[serde(default)] pub disk_allowlist: Vec<DiskIdentity>` for back-compat deserialization.
3. The agent's `config_poll_loop` should apply the received `disk_allowlist` to `DiskEnumerator.instance_id_map` on receipt (D-03 live reload without restart).
4. The EncryptionStatus DB-to-enum mapping is: `fully_encrypted -> Encrypted`, `partially_encrypted -> Suspended`, `unencrypted -> Unencrypted`, `unknown -> Unknown`. Plan 03 should be aware of this if it reads disk_registry entries directly.

## Self-Check: PASSED

- dlp-server/src/admin_api.rs: FOUND (5415 lines)
- dlp-server/src/alert_router.rs: FOUND (820 lines)
- dlp-server/src/db/repositories/disk_registry.rs: FOUND (560 lines)
- Commit f165804: FOUND (Task 1)
- Commit 2d30cf4: FOUND (Task 2)
- Commit e02dd53: FOUND (Task 3)
- 18/18 new tests pass
- 204/204 full dlp-server lib tests pass
- cargo build --workspace exits 0 with no warnings
- cargo clippy -p dlp-server --lib -- -D warnings exits 0
- /admin/disk-registry routes in protected_routes only (0 occurrences in public_routes)
