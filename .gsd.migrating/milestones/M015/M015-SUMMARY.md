---
id: M015
title: "v0.3.0 Operational Hardening"
status: complete
completed_at: 2026-05-08T05:53:30.355Z
key_decisions:
  - Operator config (SIEM, alerts, agent config) lives in SQLite, not env vars — hot-reload + TUI manageable
  - AppState { db, siem } is canonical axum state for dlp-server handlers
  - Channel-based async for LDAP: background task owns connection; mpsc + oneshot serializes ops
  - Fail-open: empty groups on LDAP error, never block operations
  - Group cache keyed by caller_sid; username only for sAMAccountName filter
key_files:
  - dlp-common/src/ad_client.rs
  - dlp-server/src/rate_limiter.rs
  - dlp-server/src/db.rs
  - dlp-server/src/policy_store.rs
lessons_learned:
  - SQLite connection pool requires updating ALL handlers simultaneously — partial migration breaks compilation
  - Rate limiting middleware upgrade may require axum version bump (0.7→0.8)
  - PolicyStore cache invalidation must fire on EVERY mutation commit — easy to miss in new endpoints
  - Repository pattern should be introduced early — migrating 49 call sites is tedious but worthwhile
---

# M015: v0.3.0 Operational Hardening

**v0.3.0 Operational Hardening shipped with AD LDAP, rate limiting, audit logging, connection pool, and policy engine separation.**

## What Happened

v0.3.0 hardened the v0.2.0 foundation with Active Directory LDAP integration, rate limiting, admin audit logging, SQLite connection pooling, and policy engine separation with cache invalidation. All 10 requirements validated.

## Success Criteria Results

- AD LDAP integration working — PASS (S01)
- Rate limiting working — PASS (S02)
- Admin audit logging working — PASS (S03)
- SQLite connection pool working — PASS (S04)
- Policy engine separation working — PASS (S05)
- Repository refactor complete — PASS (S06)
- All 10 requirements validated — PASS (coverage audit)

## Definition of Done Results

All slices complete with verification evidence. All 10 requirements validated. Cross-slice integration verified. Milestone audit passed.

## Requirement Outcomes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| R-03 | validated | S05: Policy Engine Separation |
| R-05 | validated | S01: AD LDAP Integration |
| R-07 | validated | S02: Rate Limiting Middleware |
| R-09 | validated | S03: Admin Operation Audit Logging |
| R-10 | validated | S04: SQLite Connection Pool |

## Deviations

None.

## Follow-ups

None.
