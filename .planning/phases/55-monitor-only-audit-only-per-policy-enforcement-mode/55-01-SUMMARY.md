# Plan 55-01 Summary: Core EnforcementMode Types and Schema Extension

**Phase:** 55-monitor-only-audit-only-per-policy-enforcement-mode  
**Plan:** 01 (Foundation)  
**Status:** Complete  
**Date:** 2026-05-29  

---

## Objective

Add the core `EnforcementMode` enum and extend the policy schema, audit event, and database layer so all downstream components have the shared types and storage they need for per-policy enforcement mode.

---

## Tasks Completed

### Task 1: Add EnforcementMode enum and extend Policy/EvaluateResponse in dlp-common

**Commit:** `5278f10`  
**Files:** `dlp-common/src/abac.rs`

- Added `EnforcementMode` enum with variants: `Audit`, `Block` (default), `AuditAndBlock`, `PerPolicy`
- `PerPolicy` is reserved for global override use only (system_kv setting)
- Added `#[serde(rename_all = "PascalCase")]` for consistent serialization
- Added helper methods: `is_blocking()`, `is_audit()`
- Added `compute_effective_mode(global_mode, policy_mode)` shared helper:
  - Returns `global_mode` when it is not `PerPolicy`
  - Returns `policy_mode` when global is `PerPolicy`
- Extended `Policy` struct with `#[serde(default)] pub enforcement_mode: EnforcementMode`
- Extended `EvaluateResponse` with:
  - `pub enforcement_mode: Option<EnforcementMode>`
  - `pub would_have_denied: bool`
- Added 7 unit tests covering serde round-trip, default behavior, backward compatibility, and `compute_effective_mode` logic

### Task 2: Extend AuditEvent with policy_mode and would_have_denied

**Commit:** `2f95773`  
**Files:** `dlp-common/src/audit.rs`

- Added `pub policy_mode: Option<String>` with `#[serde(skip_serializing_if = "Option::is_none")]`
- Added `pub would_have_denied: bool` with `#[serde(default)]`
- Added builder helper `with_policy_mode(mode: String) -> Self`
- Added builder helper `with_would_have_denied(flag: bool) -> Self`
- Updated `AuditEvent::new()` constructor to initialize new fields to `None` and `false`
- Added 3 unit tests for serde round-trip and backward compatibility

### Task 3: SQLite migration and PolicyRepository CRUD updates

**Commit:** Included in `5278f10` and `2f95773` (cascading fixes)  
**Files:** `dlp-server/src/db/mod.rs`, `dlp-server/src/db/repositories/policies.rs`

- Added migration in `run_migrations()`:
  - `ALTER TABLE policies ADD COLUMN enforcement_mode TEXT NOT NULL DEFAULT 'Block' CHECK(enforcement_mode IN ('Audit', 'Block', 'AuditAndBlock'))`
  - `INSERT OR IGNORE INTO system_kv (key, value) VALUES ('global_enforcement_mode', 'PerPolicy')`
- Extended `PolicyRow` with `pub enforcement_mode: String`
- Extended `PolicyUpdateRow` with `pub enforcement_mode: &'a str`
- Updated all `PolicyRepository` SQL:
  - `list()`: SELECT includes `enforcement_mode` column
  - `get_by_id()`: SELECT includes `enforcement_mode` column
  - `insert()`: VALUES includes `enforcement_mode` parameter
  - `update()`: SET includes `enforcement_mode = ?8`
- Added 5 unit tests:
  - `test_policy_row_enforcement_mode`
  - `test_policy_repository_crud_with_enforcement_mode`
  - `test_policy_repository_default_enforcement_mode` (migration idempotency)
  - `test_global_enforcement_mode_system_kv_seed`
  - `test_enforcement_mode_check_constraint`

---

## Cascading Updates to Downstream Components

The following files required updates due to new fields in shared types:

| File | Changes |
|------|---------|
| `dlp-server/src/policy_store.rs` | Added `parse_enforcement_mode()` helper; updated `deserialize_policy_row()` to populate `Policy.enforcement_mode`; updated `EvaluateResponse` construction to include `enforcement_mode` and `would_have_denied`; added `enforcement_mode: EnforcementMode::Block` to ~35 test Policy literals |
| `dlp-server/src/admin_api.rs` | Added `enforcement_mode: String` to `PolicyPayload` and `PolicyResponse` with `#[serde(default = "default_enforcement_mode")]`; added `default_enforcement_mode()` helper returning `"Block"`; updated all `PolicyRow` and `PolicyUpdateRow` struct literals |
| `dlp-server/src/alert_router.rs` | Added `policy_mode: None` and `would_have_denied: false` to all `AuditEvent` struct literals |

---

## Verification Results

| Check | Command | Result |
|-------|---------|--------|
| dlp-common enforcement_mode tests | `cargo test -p dlp-common -- enforcement_mode` | 7 passed |
| dlp-common audit_event tests | `cargo test -p dlp-common -- audit_event_policy_mode` | 3 passed |
| dlp-server policy repository tests | `cargo test -p dlp-server -- policies` | 9 passed |
| dlp-server full test suite | `cargo test -p dlp-server` | 551 passed, 3 ignored |
| dlp-common clippy | `cargo clippy -p dlp-common -- -D warnings` | Clean |
| dlp-server clippy | `cargo clippy -p dlp-server -- -D warnings` | Clean |

---

## Key Design Decisions

1. **Four variants, not three:** `PerPolicy` exists on the enum for use as the global override default, even though it is not a valid per-policy mode. This keeps the global and per-policy modes in the same type while the CHECK constraint prevents invalid database values.

2. **Block as default:** Both the serde default and the SQL DEFAULT are `Block`, ensuring existing deployments and deserialized JSON without the field behave safely (deny-by-default).

3. **String storage in DB, typed in code:** The database stores `enforcement_mode` as `TEXT` with a CHECK constraint, while the application layer parses it into the typed `EnforcementMode` enum. This provides type safety in Rust while maintaining SQLite simplicity.

4. **Backward compatibility:** All new fields use `#[serde(default)]` or `#[serde(skip_serializing_if = "Option::is_none")]`, ensuring old JSON payloads and audit events deserialize without errors.

---

## Artifacts Produced

- `dlp-common/src/abac.rs` — `EnforcementMode` enum, `compute_effective_mode()`, extended `Policy` and `EvaluateResponse`
- `dlp-common/src/audit.rs` — Extended `AuditEvent` with `policy_mode` and `would_have_denied`
- `dlp-server/src/db/mod.rs` — SQLite migration for `enforcement_mode` column and `global_enforcement_mode` system_kv seed
- `dlp-server/src/db/repositories/policies.rs` — Updated `PolicyRow`, `PolicyUpdateRow`, and all CRUD SQL
- `dlp-server/src/policy_store.rs` — `parse_enforcement_mode()` and evaluation integration
- `dlp-server/src/admin_api.rs` — API payload/response serde integration
- `dlp-server/src/alert_router.rs` — Audit event construction updates

---

## Threat Model Disposition

| Threat ID | Status | Notes |
|-----------|--------|-------|
| T-55-01 | Mitigated | Admin API requires JWT auth; only dlp-admin can modify policies |
| T-55-02 | Mitigated | Audit events emitted locally before network; offline queue persists |
| T-55-03 | Accepted | `policy_mode` is part of audit trail by design; contains no PII |
