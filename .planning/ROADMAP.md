# Roadmap: DLP-RUST

## Milestones

- ✅ **v0.2.0 Feature Completion** — Phases 0.1–12 (shipped 2026-04-13)
- ✅ **v0.3.0 Operational Hardening** — Phases 7–11 (shipped 2026-04-16)
- ✅ **v0.4.0 Policy Authoring** — Phases 13–17 (shipped 2026-04-20)
- 🚧 **v0.5.0 Boolean Logic** — Phases 18–21 (in progress)

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3, ...): Planned milestone work
- Decimal phases (e.g., 3.1, 04.1): Urgent insertions (marked with INSERTED)

Phase numbering is continuous across milestones — never restarts.

### 🚧 v0.5.0 Boolean Logic (In Progress)

**Milestone Goal:** Upgrade the ABAC engine and admin TUI from
implicit-AND-over-typed-conditions to flat boolean composition
(`ALL` / `ANY` / `NONE`) with expanded per-attribute operators
(`gt`, `lt`, `ne`, `contains`), and close the in-place
condition-editing gap left by Phase 13.

- [x] **Phase 18: Boolean Mode Engine + Wire Format** - `mode` column, `PolicyPayload`/`PolicyResponse` field, evaluator switch, `ALL` default for legacy policies (2026-04-20)
- [ ] **Phase 19: Boolean Mode in TUI + Import/Export** - mode picker in Create/Edit forms, mode round-trips through export/import
- [ ] **Phase 20: Operator Expansion** - per-attribute operator set in evaluator and conditions builder
- [ ] **Phase 21: In-Place Condition Editing** - re-enter the 3-step picker pre-filled, replace at original list position

Full phase details: `.planning/milestones/v0.5.0-ROADMAP.md`

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
| 13 | Conditions Builder | v0.4.0 | 2/2 | Complete | 2026-04-17 |
| 14 | Policy Create | v0.4.0 | 2/2 | Complete | 2026-04-17 |
| 15 | Policy Edit + Delete | v0.4.0 | 1/1 | Complete | 2026-04-17 |
| 16 | Policy List + Simulate | v0.4.0 | 2/2 | Complete | 2026-04-20 |
| 17 | Import + Export | v0.4.0 | 2/2 | Complete | 2026-04-20 |
| 18 | Boolean Mode Engine + Wire Format | v0.5.0 | 2/2 | Complete | 2026-04-20 |
| 19 | Boolean Mode in TUI + Import/Export | v0.5.0 | 0/TBD | Not started | - |
| 20 | Operator Expansion | v0.5.0 | 0/TBD | Not started | - |
| 21 | In-Place Condition Editing | v0.5.0 | 0/TBD | Not started | - |
| 99 | Refactor DB Layer to Repository + Unit of Work | v0.3.0 | 3/3 | Complete | 2026-04-15 |

## v0.3.0 — Operational Hardening (Shipped)

<details>
<summary>✅ v0.3.0 — archived at <code>.planning/milestones/v0.3.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.3.0-ROADMAP.md` and `.planning/milestones/v0.3.0-REQUIREMENTS.md`.
</details>

## v0.4.0 — Policy Authoring (Shipped)

<details>
<summary>✅ v0.4.0 — archived at <code>.planning/milestones/v0.4.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.4.0-ROADMAP.md` and `.planning/milestones/v0.4.0-REQUIREMENTS.md`. Full admin policy-authoring workflow: list, create, edit, delete, simulate, import, export — all typed-form TUI screens, no raw JSON editing.
</details>

_Archived milestone details: `.planning/milestones/v0.2.0-ROADMAP.md`, `.planning/milestones/v0.3.0-ROADMAP.md`, and `.planning/milestones/v0.4.0-ROADMAP.md`. Active milestone details: `.planning/milestones/v0.5.0-ROADMAP.md`._
