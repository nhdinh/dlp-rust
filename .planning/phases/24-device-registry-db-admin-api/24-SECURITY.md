---
phase: 24
slug: device-registry-db-admin-api
status: verified
threats_open: 0
asvs_level: 1
created: 2026-04-22
---

# Phase 24 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| HTTP API → DB | Admin API writes device identity rows via JWT-gated endpoints | VID, PID, serial, trust_tier (non-credential metadata) |
| Agent → Server | dlp-agent polls GET /admin/device-registry for registry refresh | VID, PID, serial (public endpoint, no trust_tier exposed) |
| Cache → USB event | `REGISTRY_CACHE` consulted on USB arrival to determine trust tier | UsbTrustTier enum (Blocked/ReadOnly/FullAccess) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-24-01 | Tampering | `trust_tier` DB column | mitigate | `CHECK(trust_tier IN ('blocked','read_only','full_access'))` in DDL — `db/mod.rs:148` | closed |
| T-24-02 | Tampering | SQL injection via vid/pid/serial/description | mitigate | All SQL uses `params![]` positional binding; zero string interpolation — `repositories/device_registry.rs:96-104` | closed |
| T-24-03 | Elevation of Privilege | Duplicate device ghost entries | mitigate | `UNIQUE(vid,pid,serial)` + `ON CONFLICT DO UPDATE` preserves original UUID — `db/mod.rs:150`, `device_registry.rs:93-95` | closed |
| T-24-04 | Spoofing | POST/DELETE without JWT | mitigate | `require_auth` middleware on `protected_routes` → 401 — `admin_api.rs:573-581` | closed |
| T-24-05 | Tampering | `trust_tier` injection via POST body | mitigate | `VALID_TIERS` allowlist check → 422 before DB write; DB CHECK is second line — `admin_api.rs:1557-1564` | closed |
| T-24-06 | Information Disclosure | GET /admin/device-registry exposes device inventory | accept | Server localhost-only; additionally mitigated post-plan: `trust_tier` removed from public response (CR-01 fix, `PublicDeviceEntry` struct) | closed |
| T-24-07 | Denial of Service | Bulk POST inflating device_registry | accept | Rate limiter 100/min on `protected_routes` | closed |
| T-24-08 | Tampering | Stale cache after server update | accept | 30s poll interval acceptable for v0.6.0; Phase 26 to add version-gated refresh if needed | closed |
| T-24-09 | Denial of Service | Registry poll loop flooding server | mitigate | Fixed `REGISTRY_POLL_INTERVAL = 30s`; error path emits single `warn!` and retains stale cache — `device_registry.rs:27,112-115` | closed |
| T-24-10 | Elevation of Privilege | Unknown device treated as FullAccess | mitigate | `trust_tier_for` returns `UsbTrustTier::Blocked` (default deny) for unknown devices — `device_registry.rs:72` | closed |
| T-24-11 | Information Disclosure | `REGISTRY_CACHE` static readable from any code | accept | Cache holds VID/PID/serial/tier only — no credentials or user PII; read-only access pattern | closed |
| T-24-12 | Tampering | Test helpers exposing internal state | accept | `seed_for_test` gated behind `#[cfg(test)]`; not compiled into production binary | closed |

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-24-01 | T-24-06 | VID/PID/serial is non-credential device metadata. Server bound to localhost. `trust_tier` additionally removed from public response via CR-01 fix. | dlp-admin | 2026-04-22 |
| AR-24-02 | T-24-07 | Rate limiter (100/min) on protected_routes provides adequate DoS mitigation for v0.6.0 scope. | dlp-admin | 2026-04-22 |
| AR-24-03 | T-24-08 | 30s cache staleness is acceptable latency for Phase 24 scope. Phase 26 to add version-gated refresh. | dlp-admin | 2026-04-22 |
| AR-24-04 | T-24-11 | Cache contains no credentials or PII. Read-only access pattern presents no escalation path. | dlp-admin | 2026-04-22 |
| AR-24-05 | T-24-12 | `#[cfg(test)]` gate ensures test helper is stripped from production binary at compile time. | dlp-admin | 2026-04-22 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-04-22 | 12 | 12 | 0 | Claude (gsd-security-auditor) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-04-22
