# Roadmap: DLP-RUST

## Milestones

- v0.2.0 Feature Completion -- Phases 0.1-12 (shipped 2026-04-13)
- v0.3.0 Operational Hardening -- Phases 7-11 (shipped 2026-04-16)
- v0.4.0 Policy Authoring -- Phases 13-17 (shipped 2026-04-20)
- v0.5.0 Boolean Logic -- Phases 18-21 (shipped 2026-04-21)
- v0.6.0 Endpoint Hardening -- Phases 22-30 (shipped 2026-04-29)
- v0.7.0 Disk Exfiltration Prevention -- Phases 33-38.2 (shipped 2026-05-06)
- v0.7.1 Operational Hardening -- Phases 38.3-38.6 (shipped 2026-05-06)
- v0.8.0 Application-Aware DLP -- Phases 39-42 (planning)

## Phase Numbering

- Integer phases (1, 2, 3, ...): Planned milestone work
- Decimal phases (e.g., 3.1, 04.1): Urgent insertions (marked with INSERTED)

Phase numbering is continuous across milestones -- never restarts.

## v0.8.0 - Application-Aware DLP (Planning)

### Phase 39: UWP App Identity
**Goal**: Agent can capture UWP application identity via AUMID for ABAC enforcement
**Depends on**: Phase 25 (App Identity Capture)
**Requirements**: APP-07
**Success Criteria** (what must be TRUE):
  1. Agent resolves UWP process identity to AUMID using `IShellItem::GetApplicationUserModelId` or equivalent Win32 API
  2. AUMID is captured as a first-class `source_application` / `destination_application` attribute alongside existing Win32 process identity
  3. UWP identity flows through the same ABAC evaluator without special-casing
**Plans**: TBD

### Phase 40: Drag-and-Drop Enforcement
**Goal**: Agent blocks or allows drag-and-drop operations based on source application identity and ABAC policy
**Depends on**: Phase 26 (ABAC Enforcement Convergence), Phase 39 (UWP App Identity)
**Requirements**: APP-08
**Success Criteria** (what must be TRUE):
  1. Agent intercepts OLE drag-and-drop operations (IDropTarget, DoDragDrop hooks) to identify source application
  2. Source application identity is resolved for both Win32 and UWP drag sources
  3. ABAC policy is evaluated before drop completes; denied drops are blocked with a toast notification
  4. Audit events include source_application, destination_application, and action fields for drag-and-drop blocks
**Plans**: TBD

### Phase 41: Browser Origin Clipboard Policies
**Goal**: Extend Chrome Enterprise Connector with origin-specific clipboard policies
**Depends on**: Phase 29 (Chrome Enterprise Connector)
**Requirements**: BRW-04
**Success Criteria** (what must be TRUE):
  1. Chrome Enterprise Connector messages include tab origin (URL / domain) for clipboard read/write operations
  2. ABAC evaluator supports `source_origin` and `destination_origin` as condition attributes
  3. Admin can author policies that allow/deny clipboard operations based on managed-origins list and specific URL patterns
  4. Paste from protected origin to unmanaged origin is blocked and audited with origin fields populated
**Plans**: 4 plans

Plans:
- [ ] 41-01-PLAN.md -- Add SourceOrigin/DestinationOrigin PolicyCondition variants, extend EvaluateRequest/AbacContext
- [x] 41-02-PLAN.md -- Add origin condition matching to ABAC evaluator
- [ ] 41-03-PLAN.md -- Wire Chrome handler to ABAC evaluator
- [ ] 41-04-PLAN.md -- Update TUI conditions builder with origin attributes

### Phase 42: Audit Enrichment — App Identity Fields
**Goal**: Close gaps in app identity fields across all interception paths
**Depends on**: Phase 25 (App Identity Capture), Phase 39 (UWP App Identity)
**Requirements**: AUDIT-04
**Success Criteria** (what must be TRUE):
  1. All audit events from file interception include `source_application` and `destination_application` fields where applicable
  2. All audit events from USB interception include device identity fields (VID, PID, serial, description)
  3. All audit events from clipboard interception include both source and destination application identity
  4. Audit schema is updated to guarantee non-null app identity fields; missing identity is flagged as AGENT-UNKNOWN with remediation path
**Plans**: TBD

## Archived Milestones

### v0.7.1 - Operational Hardening (Shipped)

<details>
<summary>v0.7.1 - archived at <code>.planning/milestones/v0.7.1-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.7.1-ROADMAP.md` and `.planning/milestones/v0.7.1-REQUIREMENTS.md`. AGENT-UNKNOWN remediation (AUDIT-05), per-user device registry (USB-06), wmi crate upgrade (TECH-01), disk enumeration error resilience (OP-01), structured USB logging (OP-02), agent config validation (OP-03), and graceful service shutdown (OP-04) — all 7 requirements delivered across 4 phases (38.3-38.6).

**Known gaps at v0.7.1 close:** None. All gaps closed via gap-closure commit.
</details>

### v0.7.0 - Disk Exfiltration Prevention (Shipped)

<details>
<summary>v0.7.0 - archived at <code>.planning/milestones/v0.7.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.7.0-ROADMAP.md` and `.planning/milestones/v0.7.0-REQUIREMENTS.md`. Disk enumeration (DISK-01/02), BitLocker verification (CRYPT-01/02), disk allowlist persistence (DISK-03), runtime disk enforcement (DISK-04/05), server-side disk registry (ADMIN-01..03), admin TUI disk registry (ADMIN-04), LDAP config TUI (ADMIN-05), and USB enforcement fix (PnP disable + Volume DACL deny-all) — all 15 requirements delivered across 8 phases (33-38.2).

**Known gaps at v0.7.0 close:**
- Phase 34 HUMAN-UAT (unencrypted disk warning — requires physical machine)
- Phase 38.2 HUMAN-UAT (drive-letter correlation — approved from prior session)
- AGENT-UNKNOWN remediation (split to Phase 38.3)
- USB-06 per-user device registry (deferred to v0.7.1)
- wmi crate upgrade (deferred to v0.7.1)
</details>

### v0.6.0 - Endpoint Hardening (Shipped)

<details>
<summary>v0.6.0 - archived at <code>.planning/milestones/v0.6.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.6.0-ROADMAP.md` and `.planning/milestones/v0.6.0-REQUIREMENTS.md`. Application-aware DLP (APP-01..06), Chrome Enterprise Connector browser boundary (BRW-01..03), USB device control with toast notification (USB-01..04), and Automated UAT Infrastructure (Phase 30) -- all 13 requirements delivered across 9 phases (22-30).
</details>

### v0.5.0 - Boolean Logic (Shipped)

<details>
<summary>v0.5.0 - archived at <code>.planning/milestones/v0.5.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.5.0-ROADMAP.md` and `.planning/milestones/v0.5.0-REQUIREMENTS.md`. Boolean mode engine (ALL/ANY/NONE) + TUI picker + expanded operators (gt/lt/ne/contains) + in-place condition editing -- all 4 requirements (POLICY-09..12) delivered.
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
| 33 | Disk Enumeration | v0.7.0 | 0/TBD | Complete | 2026-05-06 |
| 34 | BitLocker Verification | v0.7.0 | 5/5 | Complete | 2026-05-06 |
| 35 | Disk Allowlist Persistence | v0.7.0 | 2/2 | Complete | 2026-05-06 |
| 36 | Disk Enforcement | v0.7.0 | 3/3 | Complete | 2026-05-06 |
| 37 | Server-Side Disk Registry | v0.7.0 | 3/3 | Complete | 2026-05-06 |
| 38 | Admin TUI Disk Registry | v0.7.0 | 0/TBD | Complete | 2026-05-06 |
| 38.1 | LDAP Config TUI | v0.7.0 | 3/3 | Complete | 2026-05-06 |
| 38.2 | USB Enforcement Fix | v0.7.0 | 3/3 | Complete | 2026-05-06 |
| 38.3 | AGENT-UNKNOWN Remediation | v0.7.1 | 1/1 | Complete | 2026-05-06 |
| 38.4 | Per-User Device Registry | v0.7.1 | 3/3 | Complete | 2026-05-06 |
| 38.5 | WMI Crate Upgrade | v0.7.1 | 1/1 | Complete | 2026-05-06 |
| 38.6 | Operational Hardening Bundle | v0.7.1 | 2/2 | Complete | 2026-05-06 |
| 39 | UWP App Identity | v0.8.0 | 0/TBD | Not started | - |
| 40 | Drag-and-Drop Enforcement | v0.8.0 | 0/TBD | Not started | - |
| 41 | Browser Origin Clipboard Policies | v0.8.0 | 4/4 | Planned | - |
| 42 | Audit Enrichment — App Identity Fields | v0.8.0 | 0/TBD | Not started | - |

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

_Archived milestone details: `.planning/milestones/v0.2.0-ROADMAP.md` through `.planning/milestones/v0.7.0-ROADMAP.md`._
