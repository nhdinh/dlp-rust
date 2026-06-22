---
phase: 28
slug: admin-tui-screens
status: verified
threats_open: 0
asvs_level: 1
created: "2026-04-22"
---

# Phase 28 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| HTTP client -> GET /admin/managed-origins | Unauthenticated; returns non-sensitive URL patterns only | Origin URL patterns (low sensitivity) |
| HTTP client -> POST/DELETE /admin/managed-origins | JWT-required; mutations are admin-only | Origin URL strings, UUIDs |
| TUI -> POST /admin/policies | PolicyCondition wire format must be valid for server to accept | Serialized ABAC conditions |
| TUI -> POST /admin/device-registry | JWT required; TUI sends credentials acquired at login | Device registration payload |
| TUI -> DELETE /admin/device-registry/{id} | JWT required; id is from GET response, not user input | Device UUID |
| Test harness -> admin_router | Isolated in-memory SQLite; no real server or credentials exposed | Test-only data |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-28-01-01 | Tampering | POST /admin/managed-origins body | mitigate | JSON body deserialized via serde; empty origin rejected by server validation | closed |
| T-28-01-02 | Elevation of Privilege | POST/DELETE without JWT | mitigate | protected_routes block applies `require_auth` middleware; returns 401 | closed |
| T-28-01-03 | Denial of Service | Unbounded origin list growth | accept | Admin-only write path; no anonymous write possible | closed |
| T-28-01-04 | Information Disclosure | GET returns full origin list unauthenticated | accept | Origin patterns are not secret; Phase 29 agent polls unauthenticated (D-08) | closed |
| T-28-02-01 | Tampering | build_condition AppField None path | mitigate | `field?` returns None and build_condition returns None, preventing malformed condition construction | closed |
| T-28-02-02 | Information Disclosure | AppField sub-step visible in TUI | accept | TUI is admin-only; login required before menu access | closed |
| T-28-03-01 | Tampering | VID/PID/serial text input | accept | Values are free-form strings matching USB device identifiers; server validates trust_tier via CHECK constraint | closed |
| T-28-03-02 | Elevation of Privilege | Device register without auth | mitigate | POST uses app.client which carries JWT from login session; unauthenticated POST returns 401 | closed |
| T-28-03-03 | Repudiation | Device registration not logged | accept | Phase 24 server handler logs via tracing; audit trail at server level | closed |
| T-28-04-01 | Tampering | AddManagedOrigin text input | mitigate | Empty input rejected in dispatch before POST; server validates UNIQUE constraint | closed |
| T-28-04-02 | Elevation of Privilege | Origin mutation without auth | mitigate | POST/DELETE use app.client JWT; server returns 401 if token missing or invalid | closed |
| T-28-04-03 | Denial of Service | Duplicate origin POST | accept | Server returns 409 Conflict; TUI shows error and reloads the list | closed |
| T-28-05-01 | Repudiation | Integration tests not covering 401/409 paths | mitigate | Tests explicitly assert 401 on no-JWT POST and 409 on duplicate origin | closed |
| T-28-05-02 | Information Disclosure | Test JWT secret in test file | accept | Same constant as device_registry_integration.rs (DEV_JWT_SECRET); test-only, never reaches production | closed |

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-28-01 | T-28-01-03 | Admin-only write path; no anonymous write possible | gsd-security-auditor | 2026-04-22 |
| R-28-02 | T-28-01-04 | Origin patterns are non-sensitive configuration data | gsd-security-auditor | 2026-04-22 |
| R-28-03 | T-28-02-02 | TUI requires login; admin-only surface | gsd-security-auditor | 2026-04-23 |
| R-28-04 | T-28-03-01 | USB VID/PID are public identifiers; CHECK constraint validates tier | gsd-security-auditor | 2026-04-23 |
| R-28-05 | T-28-03-03 | Server-level tracing provides audit trail | gsd-security-auditor | 2026-04-23 |
| R-28-06 | T-28-04-03 | 409 response is explicit and handled by TUI | gsd-security-auditor | 2026-04-23 |
| R-28-07 | T-28-05-02 | Test-only constant; isolated from production | gsd-security-auditor | 2026-04-23 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-03 | 14 | 14 | 0 | gsd-security-auditor |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-03
