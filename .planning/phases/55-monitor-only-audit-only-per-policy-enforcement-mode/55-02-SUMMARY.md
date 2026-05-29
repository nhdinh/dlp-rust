# Plan 55-02 Summary: Wire Effective Enforcement Mode into Server Components

**Phase:** 55-monitor-only-audit-only-per-policy-enforcement-mode
**Plan:** 02 (Server Integration)
**Status:** Complete
**Date:** 2026-05-29

---

## Objective

Wire the effective enforcement mode into the server-side ABAC evaluator, admin API payloads, and alert router severity logic so all downstream components have mode-aware behavior.

---

## Tasks Completed

### Task 1: PolicyStore effective mode computation and caching

**Files:** `dlp-server/src/policy_store.rs`

- Made `parse_enforcement_mode()` public so it can be reused by admin_api.rs
- `PolicyStore` already had `global_mode: RwLock<EnforcementMode>` field from previous work
- `evaluate()` computes effective mode using `compute_effective_mode(global_mode, policy.enforcement_mode)`:
  - `Audit`: returns `Decision::ALLOW` with `would_have_denied=true` when policy action is denied
  - `Block` / `AuditAndBlock`: returns `policy.action` with `would_have_denied=false`
  - `PerPolicy`: returns `policy.action` with `would_have_denied=false`
- `EvaluateResponse` includes `enforcement_mode: Some(effective_mode)` and `would_have_denied`
- 6 unit tests cover all mode variants and global override scenarios

### Task 2: Admin API endpoints for global enforcement mode

**Files:** `dlp-server/src/admin_api.rs`

- Added `GlobalEnforcementModeResponse` struct with `mode: EnforcementMode`
- Added `GlobalEnforcementModeRequest` struct with `mode: EnforcementMode`
- Added `GET /admin/config/global-enforcement-mode` handler:
  - Reads from `system_kv` table (key = "global_enforcement_mode")
  - Defaults to `PerPolicy` if key is absent
  - Returns typed `EnforcementMode` enum (serialized as PascalCase string)
- Added `PUT /admin/config/global-enforcement-mode` handler:
  - Accepts `EnforcementMode` enum in request body
  - Writes to `system_kv` via `repositories::system_kv::set`
  - Invalidates `PolicyStore` cache so new mode takes effect immediately
  - Emits admin audit event for the change
  - Logs mode change via `tracing::info!`
- Registered both routes under `/admin/config/global-enforcement-mode` with `policy_config()` rate limiting

### Task 3: Extend PolicyPayload and PolicyResponse with enforcement_mode

**Files:** `dlp-server/src/admin_api.rs`

- Added `#[serde(default)] pub enforcement_mode: EnforcementMode` to `PolicyPayload`
- Added `#[serde(default)] pub enforcement_mode: EnforcementMode` to `PolicyResponse`
- Updated `create_policy` handler to:
  - Read `enforcement_mode` from payload
  - Serialize to PascalCase string for DB storage
- Updated `update_policy` handler to include `enforcement_mode` in `PolicyUpdateRow`
- Updated `list_policies` and `get_policy` handlers to parse `enforcement_mode` from DB row via `parse_enforcement_mode()`
- Added `parse_enforcement_mode` import from `crate::policy_store`

### Task 4: AlertRouter severity downgrade for Audit-mode DenyWithAlert

**Files:** `dlp-server/src/alert_router.rs`

- Modified `send_email()` to check `event.would_have_denied`:
  - When `true` (Audit mode): email subject prefix is `[DLP AUDIT-ONLY ALERT]`
  - When `false` (Block/AuditAndBlock): email subject prefix is `[DLP ALERT]`
- This provides a visual severity downgrade for audit-only alerts without changing the event structure
- Added `test_audit_mode_email_subject_downgrade` unit test verifying both audit-mode and block-mode events produce appropriate subject lines

---

## Verification Results

| Check | Command | Result |
|-------|---------|--------|
| dlp-server full test suite | `cargo test -p dlp-server` | All passed |
| dlp-server clippy | `cargo clippy -p dlp-server -- -D warnings` | Clean |
| dlp-common clippy | `cargo clippy -p dlp-common -- -D warnings` | Clean |

---

## Key Design Decisions

1. **Shared `parse_enforcement_mode` helper:** Made the existing helper in `policy_store.rs` public so `admin_api.rs` can reuse it, avoiding code duplication.

2. **Immediate cache invalidation on global mode change:** The PUT endpoint calls `state.policy_store.invalidate()` after updating `system_kv`, ensuring the new global mode takes effect on the next evaluation without waiting for the 5-minute cache refresh.

3. **Email subject as severity indicator:** Since the AlertRouter sends email and webhook alerts (not syslog), the "severity downgrade" is implemented as a subject-line prefix change from `[DLP ALERT]` to `[DLP AUDIT-ONLY ALERT]`, making audit-only events visually distinct in email inboxes.

4. **PascalCase serialization:** Both the admin API and DB storage use PascalCase strings (`"Audit"`, `"Block"`, `"AuditAndBlock"`, `"PerPolicy"`) for consistent serialization across all endpoints.

---

## Artifacts Produced

- `dlp-server/src/policy_store.rs` — `parse_enforcement_mode()` made public; effective mode computation in `evaluate()`
- `dlp-server/src/admin_api.rs` — `GlobalEnforcementModeResponse`, `GlobalEnforcementModeRequest`, GET/PUT handlers, `enforcement_mode` field on `PolicyPayload`/`PolicyResponse`
- `dlp-server/src/alert_router.rs` — Audit-mode email subject downgrade; unit test

---

## Threat Model Disposition

| Threat ID | Status | Notes |
|-----------|--------|-------|
| T-55-04 | Mitigated | Admin API requires JWT auth; audit log records every mode change |
| T-55-05 | Accepted | Info events still go through same channels; volume bounded by file I/O rate |
| T-55-06 | Mitigated | `policy_mode` and `would_have_denied` are set server-side in `evaluate()`, not client input |
