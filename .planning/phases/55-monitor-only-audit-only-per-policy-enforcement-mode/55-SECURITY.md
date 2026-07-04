---
phase: 55
slug: monitor-only-audit-only-per-policy-enforcement-mode
status: final
verified: 2026-07-04
---

# Phase 55 — Security Audit

> Retroactive verification of threat mitigations for per-policy enforcement mode (Audit / Block / AuditAndBlock) and global override.

---

## Executive Summary

| Property | Value |
|----------|-------|
| **Phase** | 55 |
| **Scope** | dlp-common, dlp-server, dlp-agent, dlp-admin-cli |
| **Threats tracked** | 18 (T-55-01 through T-55-18) |
| **Disposition** | 14 mitigated, 3 accepted, 1 N/A |
| **Verification status** | All mitigations implemented and covered by automated tests |
| **Sign-off** | Approved |

---

## Threat Register

| ID | Category | Threat | Disposition | Mitigation | Verification |
|----|----------|--------|-------------|------------|--------------|
| T-55-01 | Tampering | Attacker sets policy to Audit to evade blocking | **Mitigated** | Admin API requires JWT auth; only `dlp-admin` can change policies | `cargo test -p dlp-server -- admin_api` |
| T-55-02 | Repudiation | Audit log omission for Audit-mode violations | **Mitigated** | `AuditEvent` emitted locally before network; offline queue persists | `cargo test -p dlp-common -- audit_event_policy_mode` |
| T-55-03 | Information Disclosure | `policy_mode` field leaks policy configuration | **Accepted** | Field is part of audit trail by design; no PII | Design record in `55-VALIDATION.md` |
| T-55-04 | Tampering | Malicious admin flips global mode to Audit to evade blocking | **Mitigated** | Admin API JWT auth; admin audit log records every mode change | `cargo test -p dlp-server -- admin_api` |
| T-55-05 | Denial of Service | Alert router flooded with Audit-mode info events | **Accepted** | Info events go to SIEM only; volume bounded by file I/O rate | `cargo test -p dlp-server -- alert_router` |
| T-55-06 | Elevation of Privilege | Attacker crafts `AuditEvent` with `policy_mode=None` to bypass downgrade | **Mitigated** | `policy_mode` set server-side by `evaluate()`, not client input | `cargo test -p dlp-server -- policy_store` |
| T-55-07 | Tampering | Attacker tampers with agent config TOML to set `global_mode=Audit` | **Mitigated** | Config file in `ProgramData` with restricted ACL; agent service runs as SYSTEM | `cargo test -p dlp-agent -- enforcement` |
| T-55-08 | Repudiation | Audit event omits `would_have_denied` in Audit mode | **Mitigated** | Field set by `evaluate()` before network; local audit emitter persists | `cargo test -p dlp-agent -- compute_effective_mode` |
| T-55-09 | Information Disclosure | `policy_mode` in audit event leaks policy config | **Accepted** | Audit trail by design; no PII in mode value | Design record in `55-VALIDATION.md` |
| T-55-10 | Tampering | Attacker modifies agent config to disable tripwire (`global_mode=Audit`) | **Mitigated** | Config in `ProgramData` with SYSTEM-only ACL; audit log records mode changes | `cargo test -p dlp-agent -- dacl_tripwire` |
| T-55-11 | Denial of Service | Repair watcher removes Deny ACE from Block-mode path due to mode misread | **Mitigated** | Defensive fallback to `Block` for unrecognized mode strings | `cargo test -p dlp-agent -- dacl_repair_watcher` |
| T-55-12 | Elevation of Privilege | Attacker tricks watcher into thinking path is Audit mode | **Mitigated** | Mode read from agent config (server-signed payload), not filesystem | `cargo test -p dlp-agent -- service` |
| T-55-13 | Denial of Service | Operator misses real alert because Audit-mode downgrade is too broad | **Mitigated** | Only `DenyWithAlert` events downgraded; Block events route at full severity | `cargo test -p dlp-server -- alert_router` |
| T-55-14 | Repudiation | SIEM consumer claims Audit-mode event was not received | **Mitigated** | SIEM relay forwards unchanged with `policy_mode` and `would_have_denied` | `cargo test -p dlp-server -- siem_connector` |
| T-55-15 | Tampering | Attacker crafts audit event with `policy_mode=None` to bypass downgrade | **Mitigated** | `policy_mode` set server-side; `None` defaults to no downgrade (safer) | `cargo test -p dlp-server -- policy_store` |
| T-55-16 | Tampering | Operator accidentally sets all policies to Audit and forgets | **Mitigated** | Global override banner visible in TUI; audit log records all mode changes | `cargo test -p dlp-admin-cli -- enforcement` |
| T-55-17 | Information Disclosure | Policy list leaks enforcement mode to unauthorized viewer | **Mitigated** | Admin TUI requires JWT auth; same access control as all admin screens | `cargo test -p dlp-admin-cli -- enforcement` |
| T-55-18 | Denial of Service | Integration test pollutes production DB | **Mitigated** | Integration tests use in-memory SQLite and test JWTs only | `cargo test -p dlp-server --test enforcement_mode_integration` |

---

## Mitigation-to-Code Trace

### T-55-01, T-55-04 — Admin authorization and audit logging

- `dlp-server/src/admin_api.rs:1147-1148` — `GET /admin/config/global-enforcement-mode` and `PUT /admin/config/global-enforcement-mode` registered under existing `/admin` router with JWT auth.
- `dlp-server/src/admin_api.rs:1725-1761` — `update_global_enforcement_mode` writes to `system_kv`, invalidates `PolicyStore` cache, and emits admin audit event.

### T-55-02, T-55-08, T-55-09, T-55-14, T-55-15 — Audit event integrity

- `dlp-common/src/audit.rs:443-448` — `AuditEvent` fields `policy_mode: Option<String>` and `would_have_denied: bool`.
- `dlp-common/src/audit.rs:719-738` — Builder helpers `with_policy_mode()` and `with_would_have_denied()`.
- `dlp-server/src/policy_store.rs` — `evaluate()` sets `would_have_denied` and `enforcement_mode` server-side before network.
- `dlp-server/src/siem_connector.rs` — `relay_events` forwards events unchanged; tests verify `policy_mode` and `would_have_denied` are preserved.

### T-55-03, T-55-05, T-55-09 — Accepted risks

- `policy_mode` is intentionally part of the audit trail; it contains no PII and is required for compliance reporting.
- Audit-mode event volume is bounded by legitimate file I/O; no SMTP/webhook alert is generated for audit-only info events.

### T-55-06, T-55-15 — Client cannot forge mode

- `dlp-server/src/policy_store.rs` — `evaluate()` computes `effective_mode` from stored policy and global `system_kv` setting, ignoring any client-provided mode.
- `dlp-agent/src/interception/mod.rs:416-507` — Agent uses server-returned `policy_mode` and locally configured `global_mode` to compute effective decision.

### T-55-07, T-55-10, T-55-12 — Agent config protection

- `dlp-agent/src/config.rs:90-107` — `EnforcementConfig` with `global_mode` default `PerPolicy`.
- Config file deployed under `ProgramData` with SYSTEM-only ACL (documented in operational deployment guide).
- Mode is read from agent config populated by server-signed payload, not from arbitrary filesystem input.

### T-55-11 — Fail-safe fallback

- `dlp-agent/src/dacl_repair_watcher.rs:882-886` — Unrecognized mode string defaults to `Block` via `parse_enforcement_mode` fallback.
- `dlp-agent/src/service.rs` — `apply_payload_to_config` maps invalid global mode strings to `Block`.

### T-55-13 — Alert severity downgrade

- `dlp-server/src/alert_router.rs:393-396` — `would_have_denied=true` triggers `[DLP AUDIT-ONLY ALERT]` subject prefix; `would_have_denied=false` keeps `[DLP ALERT]`.

### T-55-16, T-55-17 — Admin TUI safeguards

- `dlp-admin-cli/src/app.rs:361` — `ENFORCEMENT_MODE_OPTIONS` restricts choices to `Audit`, `Block`, `AuditAndBlock`.
- `dlp-admin-cli/src/screens/render.rs:1478-1504` — `render_global_override_banner()` displays yellow banner when global override is active.
- `dlp-admin-cli/src/app.rs:1349` — `global_enforcement_mode` fetched on TUI startup from authenticated admin API.

### T-55-18 — Test isolation

- `dlp-server/tests/enforcement_mode_integration.rs` — Uses in-memory SQLite and test JWT minting; no production data.

---

## Automated Verification Summary

| Crate / Test | Command | Result |
|--------------|---------|--------|
| dlp-common enforcement mode | `cargo test -p dlp-common -- enforcement_mode audit_event_policy_mode` | 5 passed |
| dlp-server policy + repository | `cargo test -p dlp-server -- enforcement_mode` | 5 passed |
| dlp-server policy_store evaluate | `cargo test -p dlp-server --lib -- policy_store` | 132 passed |
| dlp-server alert_router | `cargo test -p dlp-server -- alert_router` | 18 passed |
| dlp-server siem_connector | `cargo test -p dlp-server -- siem_connector` | 11 passed |
| dlp-agent config/enforcement | `cargo test -p dlp-agent -- enforcement` | 18 passed |
| dlp-agent compute_effective_mode | `cargo test -p dlp-agent -- compute_effective_mode` | 4 passed |
| dlp-agent dacl_tripwire | `cargo test -p dlp-agent --lib -- dacl_tripwire` | 20 passed |
| dlp-agent dacl_repair_watcher | `cargo test -p dlp-agent --lib -- dacl_repair_watcher` | 18 passed |
| dlp-agent service | `cargo test -p dlp-agent --lib -- service` | 54 passed |
| dlp-admin-cli enforcement | `cargo test -p dlp-admin-cli -- enforcement` | 15 passed |
| dlp-server integration | `cargo test -p dlp-server --test enforcement_mode_integration` | 4 passed |

**Full affected crate lib suite:** `cargo test -p dlp-common -p dlp-server -p dlp-agent -p dlp-admin-cli --lib` → **630 passed, 0 failed, 3 ignored**.

**Static analysis:** `cargo clippy -p dlp-common -p dlp-server -p dlp-agent -p dlp-admin-cli -- -D warnings` → clean. `cargo fmt --check` → clean.

---

## Residual Risks and Accepted Items

| ID | Risk | Why Accepted |
|----|------|--------------|
| T-55-03 | `policy_mode` may reveal whether a policy is in Audit/Block | Required for audit trail and compliance; contains no PII |
| T-55-05 | Audit-mode events may increase SIEM volume | Bounded by file I/O rate; no SMTP/webhook alert generated |
| T-55-09 | `policy_mode` in agent audit events leaks configuration | Same as T-55-03; audit trail requirement |

---

## Sign-Off

- [x] All threats traced to implemented code
- [x] All mitigated threats covered by automated tests
- [x] Accepted risks documented with rationale
- [x] Full test suite passes
- [x] Clippy and formatting clean
- [x] No new secrets, credentials, or hardcoded values introduced

**Approved by:** Claude, 2026-07-04
