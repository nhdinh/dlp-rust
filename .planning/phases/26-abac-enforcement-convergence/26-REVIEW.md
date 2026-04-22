---
phase: 26-abac-enforcement-convergence
reviewed: 2026-04-22T00:00:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - dlp-common/src/abac.rs
  - dlp-server/src/policy_store.rs
  - dlp-server/src/admin_api.rs
  - dlp-agent/src/usb_enforcer.rs
  - dlp-agent/src/interception/mod.rs
  - dlp-agent/src/lib.rs
  - dlp-agent/src/service.rs
findings:
  critical: 0
  warning: 4
  info: 3
  total: 7
status: issues_found
---

# Phase 26: Code Review Report

**Reviewed:** 2026-04-22
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

Phase 26 delivers the ABAC enforcement convergence: the `EvaluateRequest` → `AbacContext` conversion boundary (D-04), the `SourceApplication`/`DestinationApplication` condition evaluators in `PolicyStore`, and the `UsbEnforcer` pre-ABAC check wired into the interception event loop.

The code is well-structured and the security-critical paths (D-03 fail-closed, D-10 default-deny for unregistered USB devices) are correctly implemented and tested. No critical findings were identified.

Four warnings were found, covering a silent data-corruption path in the SIEM config GET handler, a logic gap in the `update_policy` path handler that is fragile against future route changes, a missing-mask gap in `GET /admin/siem-config` for `splunk_token` and `elk_api_key`, and a potential classification placeholder in USB audit events that could mislead downstream consumers. Three informational items are also noted.

---

## Warnings

### WR-01: `GET /admin/siem-config` returns plaintext SIEM credentials

**File:** `dlp-server/src/admin_api.rs:1018-1037`
**Issue:** The `get_siem_config_handler` returns `splunk_token` and `elk_api_key` in plaintext. The ME-01 mask-on-GET pattern applied to `smtp_password` and `webhook_secret` (lines 1103-1112) is not applied here. The file-level comment on line 7 acknowledges this as a TODO, but it represents a live security gap: any caller with a valid admin JWT can retrieve the raw Splunk HEC token and the ELK API key from the response body. In a Zero Trust / audit-focused DLP system, these are privileged credentials.
**Fix:** Apply the same sentinel pattern as `get_alert_config_handler`:
```rust
let splunk_token_out = if row.splunk_token.is_empty() {
    String::new()
} else {
    ALERT_SECRET_MASK.to_string()
};
let elk_api_key_out = if row.elk_api_key.is_empty() {
    String::new()
} else {
    ALERT_SECRET_MASK.to_string()
};
```
Mirror the `update_alert_config_handler` read-then-substitute pattern in the corresponding PUT handler to avoid overwriting stored values when the mask is echoed back. The existing TODO comment on line 7 should be converted to a tracked issue before shipping.

---

### WR-02: `update_policy` path extraction is fragile and silently falls through

**File:** `dlp-server/src/admin_api.rs:788-795`
**Issue:** The handler manually strips the policy ID from `req.uri().path()` using two `strip_prefix` calls. If a third route alias is added (e.g. `/v2/policies/{id}`) the `else` branch returns `AppError::BadRequest("invalid policy path")` rather than extracting the ID. More critically, the `policy_id.is_empty()` guard at line 796 returns a `BadRequest`, but a URL like `/policies/` would strip to an empty string and hit this branch — the axum router would normally reject such a request, but the manual path-parsing creates a redundant code path that duplicates router logic and is error-prone.
**Fix:** Use the axum `Path` extractor directly for both route aliases, or factor both `/policies/{id}` and `/admin/policies/{id}` into a shared inner function that takes an extracted `String` ID. This is the pattern already used in `delete_policy` (line 897) and `get_policy` (line 668):
```rust
async fn update_policy(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<PolicyResponse>, AppError> {
    // ...
}
```

---

### WR-03: Silent data loss when `conditions` JSON is malformed in list/get handlers

**File:** `dlp-server/src/admin_api.rs:642, 676`
**Issue:** In `list_policies` and `get_policy`, the DB-stored `conditions` column is deserialized with `unwrap_or(serde_json::Value::Null)`. If a row contains malformed JSON in its `conditions` column, the API silently returns `null` for that field instead of surfacing an error. A caller relying on the returned conditions to display or re-submit the policy would receive `null` and could inadvertently overwrite a partially-broken policy with an empty condition set, losing the original data silently.
**Fix:** Return an error rather than substituting `Null`:
```rust
let conditions: serde_json::Value = serde_json::from_str(&r.conditions)
    .map_err(|e| AppError::Internal(anyhow::anyhow!(
        "malformed conditions JSON for policy {}: {e}", r.id
    )))?;
```
The `load_from_db` path in `policy_store.rs` already uses the correct pattern (warn-and-skip), but the admin API read path should be strict to surface corruption.

---

### WR-04: USB audit event uses `Classification::T1` and `Action::WRITE` as hardcoded placeholders

**File:** `dlp-agent/src/interception/mod.rs:86-90`
**Issue:** When the `UsbEnforcer` denies an operation (pre-ABAC path, lines 79-119), the emitted `AuditEvent` hardcodes `Classification::T1` and `Action::WRITE` as placeholders because the classification and action have not yet been resolved at that point. The inline comment acknowledges this. However, the `BlockNotify` sent to the UI (line 104) also uses `classification: "T1"`, which means the user-facing popup will always show "T1" for USB-blocked events even when the actual file might be T3/T4. For a compliance/DLP system this could mislead audit reviewers who rely on classification labels to understand what was blocked.
**Fix:** Resolve the action before the USB check so it is available for the audit event. `PolicyMapper::action_for(&action)` (called at line 132) is a cheap, synchronous call with no side effects. Move the call above the USB check:
```rust
let abac_action = PolicyMapper::action_for(&action);

if let Some(ref enforcer) = usb_enforcer {
    if let Some(decision) = enforcer.check(&path, &action) {
        let audit_event = AuditEvent::new(
            EventType::Block,
            "SYSTEM".to_string(),
            "SYSTEM".to_string(),
            path.clone(),
            dlp_common::Classification::T1, // classification still placeholder
            abac_action,                     // action is now correct
            decision,
            // ...
        );
```
The classification cannot be resolved without a DB/cache lookup (deferred until the ABAC path), so `T1` there is an accepted limitation. At a minimum, add a structured field `usb_enforced: true` to the audit event so log consumers can filter and understand the context. For the `BlockNotify`, consider omitting the classification field or labelling it `"USB"` to avoid confusing the UI display.

---

## Info

### IN-01: Inconsistent naming — `PolicyCondition` operator strings not validated at ingestion

**File:** `dlp-server/src/admin_api.rs:697-778` / `dlp-server/src/policy_store.rs:248-255`
**Issue:** Operator strings (`"eq"`, `"ne"`, `"neq"`, `"contains"`, `"gt"`, `"lt"`, `"in"`, `"not_in"`) in policy conditions are free-form strings stored as JSON and only validated at evaluation time, where unknown operators silently return `false`. A misconfigured policy authored with `"neq"` on a `SourceApplication` condition (which only accepts `"eq"` / `"ne"`) would silently never match rather than failing loudly. The `MemberOf` evaluator accepts `"neq"` (line 295) but `app_identity_matches` accepts `"ne"` (line 330), creating two different spellings for the same semantic.
**Fix:** Consider validating operator strings against a per-condition allowlist at policy creation/update time, returning `BadRequest` if an unsupported operator is submitted. At minimum, document the supported operator matrix in the `PolicyCondition` doc comment.

---

### IN-02: `TrustTier` comparison allocates a `String` on every condition evaluation via `serde_json::to_string`

**File:** `dlp-server/src/policy_store.rs:344-347`
**Issue:** For every `AppField::TrustTier` condition evaluation, the code calls `serde_json::to_string(&app.trust_tier)`, allocates a `String`, then trims the quotes with `trim_matches('"').to_string()` — a second allocation. Since `AppTrustTier` serializes as `"trusted"`, `"untrusted"`, or `"unknown"` (confirmed in the endpoint module), a direct `match` on the enum is both allocation-free and more readable.
**Fix:**
```rust
AppField::TrustTier => {
    use dlp_common::endpoint::AppTrustTier;
    let tier_str = match app.trust_tier {
        AppTrustTier::Trusted   => "trusted",
        AppTrustTier::Untrusted => "untrusted",
        AppTrustTier::Unknown   => "unknown",
    };
    match op {
        "eq" => tier_str == value,
        "ne" => tier_str != value,
        _    => false,
    }
}
```
This also eliminates the `unwrap_or_default()` fallback that could silently produce an empty string on a hypothetical serialization failure.

---

### IN-03: TODO comment in production source

**File:** `dlp-server/src/admin_api.rs:7`
**Issue:** A `// TODO(followup): apply the same ME-01 mask-on-GET pattern to siem-config` comment exists at the module level. Per project coding standards (`9.14`), TODO comments should not be committed. This TODO describes the gap that WR-01 above covers.
**Fix:** Remove the comment and track the work item externally, or resolve it as part of the WR-01 fix.

---

_Reviewed: 2026-04-22_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
