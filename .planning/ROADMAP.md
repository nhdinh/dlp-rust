# Roadmap: DLP-RUST

## Milestones

- ✅ **v0.2.0 Feature Completion** — Phases 0.1–12 (shipped 2026-04-13)
- ✅ **v0.3.0 Operational Hardening** — Phases 7–11 (shipped 2026-04-16)

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
| 7 | Active Directory LDAP integration | v0.3.0 | 3/3 | Complete | 2026-04-16 |
| 8 | Rate limiting middleware | v0.3.0 | 1/1 | Complete | 2026-04-15 |
| 9 | Admin operation audit logging | v0.3.0 | 2/2 | Complete | 2026-04-14 |
| 10 | SQLite connection pool | v0.3.0 | 1/1 | Complete | 2026-04-15 |
| 11 | Policy Engine Separation | v0.3.0 | 4/4 | Complete | 2026-04-16 |
| 12 | Comprehensive DLP Test Suite | v0.2.0 | 3/3 | Complete | 2026-04-13 |

## v0.3.0 — Operational Hardening (Shipped)

<details>
<summary>✅ v0.3.0 — archived at <code>.planning/milestones/v0.3.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.3.0-ROADMAP.md` and `.planning/milestones/v0.3.0-REQUIREMENTS.md`.
</details>

### Phase 99: Refactor DB layer to Repository + Unit of Work

**Goal:** Migrate all 49 `pool.get()` + raw SQL call sites in dlp-server into typed Repository structs under `db/repositories/`. All writes go through `UnitOfWork<'conn>` (RAII transaction). Three migration waves: (1) build db/ submodule, (2) migrate small modules, (3) migrate admin_api.rs.
**Requirements**: TBD
**Depends on:** Phase 10
**Plans:** 3/3 complete

Plans:
- [x] Plan 01 — Wave 1: Build db/ submodule (completed 2026-04-15)
- [x] Plan 02 — Wave 2: Migrate 23 call sites in 6 small handlers (completed 2026-04-15)
- [x] Plan 03 — Wave 3: Migrate admin_api.rs (completed 2026-04-15)

---

_Archived milestone details: `.planning/milestones/v0.2.0-ROADMAP.md`_
