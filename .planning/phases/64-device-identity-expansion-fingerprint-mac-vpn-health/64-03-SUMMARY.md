---
phase: 64-device-identity-expansion-fingerprint-mac-vpn-health
plan: 03
type: execute
wave: 2
status: complete
completed_at: "2026-06-07T02:30:00Z"
---

# Phase 64 Plan 03 — Heartbeat Integration with Device Identity Persistence

## What Was Done

Extended the agent heartbeat mechanism to carry full device identity (fingerprint, MACs, VPN state, domain join, health status) and persist it server-side in the agents table.

### Files Modified

| File | Changes |
|------|---------|
| `dlp-server/src/db/repositories/agents.rs` | AgentRow +5 fields; list/upsert/get_by_id/update_heartbeat/mark_stale_offline updated |
| `dlp-server/src/db/mod.rs` | Phase 64 migration: 5 run_alter calls in BEGIN/COMMIT; health_status CHECK constraint |
| `dlp-server/src/agent_registry.rs` | HeartbeatRequest/AgentInfoResponse extended; validate_device_identity; handler wiring |
| `dlp-agent/src/server_client.rs` | send_heartbeat already extended in prior wip commit |

### Key Implementation Details

- **AgentRow** now carries `fingerprint`, `mac_addresses` (JSON string), `vpn_active`, `domain_joined`, `health_status`
- **update_heartbeat** accepts `Option<&EndpointIdentity>` — matches existing agent_registry.rs call site. Extracts fields via serde JSON for MACs and health_status snake_case string
- **mark_stale_offline** sets `health_status = 'offline'` alongside `status = 'offline'`
- **DB migration** wrapped in explicit `BEGIN/COMMIT` with comment noting SQLite ALTER TABLE rollback limitations
- **health_status CHECK constraint** enforces `('healthy','degraded','offline','tampered')` at DB layer
- **Server-side validation** uses manual char-by-char checks (no regex dep):
  - Fingerprint: `v1:` prefix + 64 lowercase hex chars
  - MAC: 12 uppercase hex chars
  - Max 32 MACs (DoS prevention)
- **Validation failures** emit structured `tracing::warn!(agent_id, field, reason, ...)` — NOT silently discarded
- **Backward compat**: Old agents without `device_identity` heartbeat successfully via `#[serde(default)]`

### Tests Added

| Test | File | What |
|------|------|------|
| test_update_heartbeat_with_device_identity | agents.rs | Round-trip with all 5 fields |
| test_update_heartbeat_none_uses_defaults | agents.rs | None path sets empty defaults |
| test_mark_stale_offline_sets_health_status | agents.rs | Offline sweep updates health_status |
| test_agents_device_identity_columns | db/mod.rs | PRAGMA verifies all 5 columns exist |
| test_agents_device_identity_defaults | db/mod.rs | Default values on insert without new cols |
| test_agents_health_status_check_constraint | db/mod.rs | Invalid health_status rejected; all 4 valid accepted |
| test_heartbeat_request_with_device_identity | agent_registry.rs | Deserialize JSON with full identity |
| test_heartbeat_request_backward_compat | agent_registry.rs | Old JSON `{}` deserializes to None |
| test_agent_info_response_with_device_identity | agent_registry.rs | Serialize response with new fields |
| test_validate_device_identity_rejects_invalid_mac | agent_registry.rs | Malformed MAC → None |
| test_validate_device_identity_rejects_invalid_fingerprint | agent_registry.rs | Malformed fingerprint → None |
| test_validate_device_identity_rejects_too_many_macs | agent_registry.rs | 33 MACs → None |
| test_validate_device_identity_accepts_valid | agent_registry.rs | Valid identity passes |
| test_validate_device_identity_none_returns_none | agent_registry.rs | None input → None output |

### Quality Gates

- [x] cargo test -p dlp-server --lib: 603 passed, 0 failed, 3 ignored
- [x] cargo clippy --workspace -- -D warnings: clean
- [x] cargo fmt --check: clean
- [x] cargo build --workspace: compiles with zero errors

### Review Concerns Addressed

| Concern | Severity | Mitigation |
|---------|----------|------------|
| DB migration fragmentation | HIGH | Wrapped in explicit BEGIN/COMMIT transaction |
| Server-side validation | MEDIUM | Manual char validation for fingerprint and MAC format |
| Silent validation failures | MEDIUM | Structured tracing::warn! with agent_id, field, reason |
| health_status column integrity | LOW | CHECK constraint enforcing valid values |
