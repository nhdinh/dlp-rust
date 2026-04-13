# Roadmap: DLP-RUST

## Milestones

- ✅ **v0.2.0 Feature Completion** — Phases 0.1–12 (shipped 2026-04-13)
- 🚧 **v0.3.0 Operational Hardening** — Phases 7–11 (planned)

## Progress

| Phase | Name | Milestone | Plans | Status | Completed |
|-------|------|-----------|-------|--------|----------|
| 0.1 | Fix clipboard monitoring runtime pipeline | v0.2.0 | — | Complete | 2026-04-10 |
| 1 | Fix integration tests | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 2 | Require JWT_SECRET in production | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 3 | Wire SIEM connector into server startup | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 3.1 | SIEM config in DB via dlp-admin-cli | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 4 | Wire alert router into server | v0.2.0 | 2/2 | Complete | 2026-04-11 |
| 04.1 | Full detection and intercept test suite | v0.2.0 | 3/3 | Complete | 2026-04-11 |
| 6 | Wire config push for agent config distribution | v0.2.0 | 2/2 | Complete | 2026-04-12 |
| 7 | Active Directory LDAP integration | v0.3.0 | 0/0 | Not started | — |
| 8 | Rate limiting middleware | v0.3.0 | 0/0 | Not started | — |
| 9 | Admin operation audit logging | v0.3.0 | 0/0 | Not started | — |
| 10 | SQLite connection pool | v0.3.0 | 0/0 | Not started | — |
| 11 | Policy Engine Separation | v0.3.0 | 0/0 | Not started | — |
| 12 | Comprehensive DLP Test Suite | v0.2.0 | 3/3 | Complete | 2026-04-13 |

## v0.3.0 — Operational Hardening (Planned)

<details>
<summary>🚧 v0.3.0 Operational Hardening (Phases 7–11) — archived at <code>.planning/milestones/v0.2.0-ROADMAP.md</code></summary>

Phase details for v0.2.0 are archived at `.planning/milestones/v0.2.0-ROADMAP.md`.

### Phase 7: Active Directory LDAP integration
**Requirement:** R-05
**Depends on:** Phase 2
**Files:** `dlp-agent/src/identity.rs`, `dlp-common/src/abac.rs`, new `dlp-agent/src/ad_client.rs`
**Description:** Implement LDAP client using `ldap3` crate. Query AD for user group membership, device trust level, and network location. Replace placeholder values in ABAC evaluation requests.
**UAT:** ABAC evaluation uses real AD group membership for policy decisions.

### Phase 8: Rate limiting middleware
**Requirement:** R-07
**Files:** `dlp-server/src/main.rs`, `dlp-server/Cargo.toml`
**Description:** Add tower-governor or custom rate limiting middleware. Apply to /auth/login (strict), heartbeat (moderate), event ingestion (per-agent).
**UAT:** Rapid-fire login attempts are throttled with 429 responses.

### Phase 9: Admin operation audit logging
**Requirement:** R-09
**Files:** `dlp-server/src/admin_api.rs`, `dlp-server/src/audit_store.rs`
**Description:** Emit audit events for policy CRUD and admin password changes. Store in audit_events table with EventType::AdminAction.
**UAT:** Policy create/update/delete appear as audit events queryable via GET /audit/events.

### Phase 10: SQLite connection pool
**Requirement:** R-10
**Files:** `dlp-server/src/db.rs`, `dlp-server/Cargo.toml`
**Description:** Replace Mutex<Connection> with r2d2-sqlite connection pool. Update all handlers to use pool.get() instead of conn().lock().
**UAT:** Concurrent API requests execute without serializing on a single mutex. Existing tests pass.

### Phase 11: Policy Engine Separation
**Requirement:** R-03
**Files:** `dlp-policy-engine/` (new crate), `dlp-server/src/main.rs`, `dlp-server/src/lib.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/src/db.rs`
**Description:** Architectural split: introduce a new `dlp-policy-engine` binary as the single source of truth for policies and admin operations. `dlp-server` is refactored to an evaluation replica — no admin API, local policy cache populated on startup and kept current via push from engine. `PolicySyncer` moved to engine side.
**UAT:** Policy changes made via `dlp-policy-engine` admin API propagate to `dlp-server` replicas.

</details>

---

_Archived milestone details: `.planning/milestones/v0.2.0-ROADMAP.md`_
