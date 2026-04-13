# Phase 9: Admin Operation Audit Logging — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-14
**Phase:** 09-admin-operation-audit-logging
**Areas discussed:** Event detail level + action sub-types, Identity + query API, Password change scope

---

## Area A — Event Detail Level + Action Sub-Types

| Option | Description | Selected |
|--------|-------------|----------|
| Reuse AuditEvent, no Action mapping | Leave policy Action fields empty/default for admin ops | |
| Add admin variants to Action enum | Add policy.create, policy.update, etc. to Action enum in dlp-common/abac.rs | ✓ |
| Lightweight admin-only event struct | Separate struct from file AuditEvent | |

**User's choice:** B — Add admin variants to Action enum

**Notes:** Four admin variants added: `PolicyCreate`, `PolicyUpdate`, `PolicyDelete`, `PasswordChange`

| Decision field option | Description | Selected |
|-----------------------|-------------|----------|
| Decision::Allow | Consistent struct, action always succeeds | ✓ |
| Decision::ALLOW_WITH_ALERT | Marks admin ops as compliance-significant in SIEM routing | |
| New Decision::AdminAction variant | Explicit, unambiguous, but more changes to dlp-common | |

**User's choice:** A — Decision::Allow (recommended)

| Resource path format | Description | Selected |
|---------------------|-------------|----------|
| Type:identifier format | e.g. "policy:pii-block-v2", "password_change:admin@corp" | ✓ |
| admin:// URI scheme | e.g. "admin://policy/pii-block-v2" | |
| Structured fields | Separate fields — requires schema change | |

**User's choice:** A — Type:identifier format (recommended)

---

## Area B — Identity + Query API

| Option | Description | Selected |
|--------|-------------|----------|
| Filter existing endpoint | GET /audit/events with event_type=ADMIN_ACTION — minimal change | ✓ |
| Dedicated /admin/audit endpoint | New endpoint — cleaner separation but more surface area | |

**User's choice:** A — Filter existing endpoint (recommended)

| Admin identity option | Description | Selected |
|---------------------|-------------|----------|
| Username + SID | Pull admin_sid from admin_users table (DB lookup per operation) | ✓ |
| Username only | user_name from JWT is sufficient — no extra DB lookup | |

**User's choice:** A — Username + SID (recommended)

**Notes:** admin_users table currently has no SID column — add `user_sid TEXT NULL` in Phase 9. SID will be populated when AD/LDAP Phase 7 adds real identity resolution.

---

## Area C — Password Change Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Successes only | Log when password change succeeds — 401 already returned on failure | ✓ |
| Successes + failures | Log both — failed attempts are security-significant | |

**User's choice:** A — Successes only (recommended)

**Notes:** Failed attempts return HTTP 401 — already handled as authentication failures, not admin actions. Rate limiting (Phase 8) handles brute-force protection.

---

## Deferred Ideas

- Separate `GET /admin/audit/events` endpoint — not needed; existing filter works
- Failed password attempt logging — covered by Phase 7 rate limiting (R-07)
- Windows SID capture for admin users — Phase 7 AD/LDAP integration
