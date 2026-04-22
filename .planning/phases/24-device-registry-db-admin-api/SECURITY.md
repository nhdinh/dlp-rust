---
phase: 24-device-registry-db-admin-api
audited_by: gsd-secure-phase
asvs_level: 1
date: 2026-04-22
verdict: SECURED
---

# Phase 24 Security Audit Report

## Summary

**Threats Closed:** 7/7
**Accepted Risks Logged:** 5
**Unregistered Flags:** 0

All seven `mitigate`-disposition threats from the Phase 24 threat register have verified code-level evidence. All five `accept`-disposition threats are dispositioned in the plan and referenced below.

---

## Threat Verification

| Threat ID | Category | Disposition | Evidence |
|-----------|----------|-------------|----------|
| T-24-01 | Tampering | mitigate | `dlp-server/src/db/mod.rs:148` — `CHECK(trust_tier IN ('blocked', 'read_only', 'full_access'))` in DDL |
| T-24-02 | Tampering | mitigate | `dlp-server/src/db/repositories/device_registry.rs:96-104` (`upsert` params![]), `:133-135` (`get_by_device_key` params![]), `:167` (`delete_by_id` params![id]). `list_all` uses `[]` (no user input). Zero string interpolation. |
| T-24-03 | Elevation of Privilege | mitigate | `dlp-server/src/db/mod.rs:150` — `UNIQUE(vid, pid, serial)` constraint; `device_registry.rs:93-95` — `ON CONFLICT(vid, pid, serial) DO UPDATE SET trust_tier = excluded.trust_tier, description = excluded.description` |
| T-24-04 | Spoofing | mitigate | `dlp-server/src/admin_api.rs:581` — `.layer(middleware::from_fn(admin_auth::require_auth))` wraps `protected_routes` containing POST `:573-574` and DELETE `:576-579` device-registry routes |
| T-24-05 | Tampering | mitigate | `dlp-server/src/admin_api.rs:1557-1564` — `VALID_TIERS` allowlist (`["blocked","read_only","full_access"]`) checked before DB write; returns `AppError::UnprocessableEntity` (422) on mismatch; DB CHECK constraint is second line of defense |
| T-24-09 | Denial of Service | mitigate | `dlp-agent/src/device_registry.rs:27` — `REGISTRY_POLL_INTERVAL = Duration::from_secs(30)` fixed interval; `:112-115` — error path: single `warn!` log, retain stale cache, no retry |
| T-24-10 | Elevation of Privilege | mitigate | `dlp-agent/src/device_registry.rs:72` — `.unwrap_or(UsbTrustTier::Blocked)` — any device not in registry returns Blocked (default deny) |

---

## Accepted Risks Log

| Threat ID | Category | Rationale |
|-----------|----------|-----------|
| T-24-06 | Information Disclosure | GET /admin/device-registry is unauthenticated; server is localhost-only. Additionally mitigated post-plan: `PublicDeviceEntry` response type (admin_api.rs:324-330) omits trust_tier, description, and created_at from the unauthenticated response, limiting enumeration of privileged devices. |
| T-24-07 | Denial of Service | Bulk POST DoS accepted; rate limiter (100/min via `default_config()` route_layer) applied to all protected_routes. Explicit acceptance recorded in 24-02-PLAN.md threat register. |
| T-24-08 | Information Disclosure (stale) | 30-second poll interval accepted as latency bound for v0.6.0. Documented in 24-03-PLAN.md and SUMMARY.md. |
| T-24-11 | Information Disclosure | REGISTRY_CACHE static contains only VID/PID/serial/tier — no credentials, no PII. Accepted in 24-03-PLAN.md. |
| T-24-12 | Information Disclosure | `seed_for_test` is always-compiled (#[doc(hidden)]); writes only to in-memory RwLock<HashMap>. No sensitive data. Accepted in 24-04-PLAN.md and 24-04-SUMMARY.md. |

---

## Unregistered Flags

None. All threat flags from SUMMARY.md ## Threat Flags sections map to registered threat IDs.

---

## Notes

- The `test-helpers` feature was removed in Plan 04 and `seed_for_test` made always-compiled. This is covered by the T-24-12 accepted disposition — no new threat surface.
- The three OnceLock statics in `dlp-agent/src/detection/usb.rs` (REGISTRY_CACHE, REGISTRY_CLIENT, REGISTRY_RUNTIME_HANDLE) contain no credentials or sensitive data; not a new threat surface per 24-03-SUMMARY.md.
- Release-mode UAT concern noted in 24-04-SUMMARY.md (optimization-dependent OnceLock initialization) is an operational quality issue, not a security threat. Not registered.
