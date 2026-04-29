# Roadmap: DLP-RUST

## Milestones

- v0.2.0 Feature Completion -- Phases 0.1-12 (shipped 2026-04-13)
- v0.3.0 Operational Hardening -- Phases 7-11 (shipped 2026-04-16)
- v0.4.0 Policy Authoring -- Phases 13-17 (shipped 2026-04-20)
- v0.5.0 Boolean Logic -- Phases 18-21 (shipped 2026-04-21)
- v0.6.0 Endpoint Hardening -- Phases 22-30 (shipped 2026-04-29)

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3, ...): Planned milestone work
- Decimal phases (e.g., 3.1, 04.1): Urgent insertions (marked with INSERTED)

Phase numbering is continuous across milestones -- never restarts.

## v0.5.0 - Boolean Logic (Shipped)

<details>
<summary>v0.5.0 - archived at <code>.planning/milestones/v0.5.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.5.0-ROADMAP.md` and `.planning/milestones/v0.5.0-REQUIREMENTS.md`. Boolean mode engine (ALL/ANY/NONE) + TUI picker + expanded operators (gt/lt/ne/contains) + in-place condition editing -- all 4 requirements (POLICY-09..12) delivered.
</details>

## v0.6.0 - Endpoint Hardening (Shipped)

<details>
<summary>v0.6.0 - archived at <code>.planning/milestones/v0.6.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.6.0-ROADMAP.md` and `.planning/milestones/v0.6.0-REQUIREMENTS.md`. Application-aware DLP (APP-01..06), Chrome Enterprise Connector browser boundary (BRW-01..03), USB device control with toast notification (USB-01..04), and Automated UAT Infrastructure (Phase 30) -- all 13 requirements delivered across 9 phases (22-30).
</details>

## Progress

| Phase | Name | Milestone | Plans | Status | Completed |
|-------|------|-----------|-------|--------|----------|
| 0.1 | Fix clipboard monitoring runtime pipeline | v0.2.0 | - | Complete | 2026-04-10 |
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
| 13 | Conditions Builder | v0.4.0 | 2/2 | Complete | 2026-04-17 |
| 14 | Policy Create | v0.4.0 | 2/2 | Complete | 2026-04-17 |
| 15 | Policy Edit + Delete | v0.4.0 | 1/1 | Complete | 2026-04-17 |
| 16 | Policy List + Simulate | v0.4.0 | 2/2 | Complete | 2026-04-20 |
| 17 | Import + Export | v0.4.0 | 2/2 | Complete | 2026-04-20 |
| 18 | Boolean Mode Engine + Wire Format | v0.5.0 | 2/2 | Complete | 2026-04-20 |
| 19 | Boolean Mode in TUI + Import/Export | v0.5.0 | 2/2 | Complete | 2026-04-21 |
| 20 | Operator Expansion | v0.5.0 | 2/2 | Complete | 2026-04-21 |
| 21 | In-Place Condition Editing | v0.5.0 | 1/1 | Complete | 2026-04-21 |
| 22 | dlp-common Foundation | v0.6.0 | 4/4 | Complete | 2026-04-22 |
| 23 | USB Enumeration in dlp-agent | v0.6.0 | 2/2 | Complete | 2026-04-22 |
| 24 | Device Registry DB + Admin API | v0.6.0 | 4/4 | Complete | 2026-04-22 |
| 25 | App Identity Capture in dlp-user-ui | v0.6.0 | 4/4 | Complete | 2026-04-22 |
| 26 | ABAC Enforcement Convergence | v0.6.0 | 5/5 | Complete | 2026-04-22 |
| 27 | USB Toast Notification | v0.6.0 | 2/2 | Complete | 2026-04-22 |
| 28 | Admin TUI Screens | v0.6.0 | 5/5 | Complete | 2026-04-29 |
| 29 | Chrome Enterprise Connector | v0.6.0 | 4/4 | Complete | 2026-04-29 |
| 30 | Automated UAT Infrastructure | v0.6.0 | 10/10 | Complete | 2026-04-29 |
| 99 | Refactor DB Layer to Repository + Unit of Work | v0.3.0 | 3/3 | Complete | 2026-04-15 |

## v0.3.0 - Operational Hardening (Shipped)

<details>
<summary>v0.3.0 - archived at <code>.planning/milestones/v0.3.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.3.0-ROADMAP.md` and `.planning/milestones/v0.3.0-REQUIREMENTS.md`.
</details>

## v0.4.0 - Policy Authoring (Shipped)

<details>
<summary>v0.4.0 - archived at <code>.planning/milestones/v0.4.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.4.0-ROADMAP.md` and `.planning/milestones/v0.4.0-REQUIREMENTS.md`. Full admin policy-authoring workflow: list, create, edit, delete, simulate, import, export -- all typed-form TUI screens, no raw JSON editing.
</details>

_Archived milestone details: `.planning/milestones/v0.2.0-ROADMAP.md` through `.planning/milestones/v0.6.0-ROADMAP.md`._
