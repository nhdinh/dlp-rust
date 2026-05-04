# Roadmap: DLP-RUST

## Milestones

- v0.2.0 Feature Completion -- Phases 0.1-12 (shipped 2026-04-13)
- v0.3.0 Operational Hardening -- Phases 7-11 (shipped 2026-04-16)
- v0.4.0 Policy Authoring -- Phases 13-17 (shipped 2026-04-20)
- v0.5.0 Boolean Logic -- Phases 18-21 (shipped 2026-04-21)
- v0.6.0 Endpoint Hardening -- Phases 22-30 (shipped 2026-04-29)
- v0.7.0 Disk Exfiltration Prevention -- Phases 33-38 (in progress)

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

## v0.7.0 - Disk Exfiltration Prevention (In Progress)

**Milestone Goal:** Prevent data exfiltration via unregistered fixed disks by establishing an install-time disk allowlist with encryption verification.

- [ ] **Phase 33: Disk Enumeration** - Agent discovers and accurately classifies all fixed disks with device identity and bus type
- [ ] **Phase 34: BitLocker Verification** - Agent verifies BitLocker encryption status for each enumerated fixed disk
- [ ] **Phase 35: Disk Allowlist Persistence** - Agent persists disk allowlist to TOML and loads it across restarts
- [x] **Phase 36: Disk Enforcement** - Agent blocks I/O to unregistered fixed disks and handles device arrivals/removals (Complete 2026-05-04)
- [ ] **Phase 37: Server-Side Disk Registry** - Admin can centrally manage disk allowlist via REST API
- [ ] **Phase 38: Admin TUI Disk Registry** - Admin can manage disk registry through the interactive TUI

## Phase Details

### Phase 33: Disk Enumeration
**Goal**: Agent can discover and accurately classify all fixed disks with device identity and bus type
**Depends on**: Nothing (first phase of v0.7.0)
**Requirements**: DISK-01, DISK-02, AUDIT-01
**Success Criteria** (what must be TRUE):
  1. Agent enumerates all fixed disks at install time or first startup, capturing device instance ID, bus type, model, and drive letter
  2. Agent correctly distinguishes USB-bridged SATA/NVMe enclosures from genuine internal disks via IOCTL_STORAGE_QUERY_PROPERTY or PnP tree walk
  3. Disk discovery events are emitted with full identity (instance_id, bus_type, model, drive_letter) and timestamp
**Plans**: TBD

### Phase 34: BitLocker Verification
**Goal**: Agent can verify encryption status of all enumerated fixed disks
**Depends on**: Phase 33
**Requirements**: CRYPT-01, CRYPT-02
**Success Criteria** (what must be TRUE):
  1. Agent queries BitLocker encryption status via WMI Win32_EncryptableVolume for each enumerated fixed disk
  2. Unencrypted disks are flagged in the audit log with a warning severity; admin decides allow/block via allowlist (not hard-coded block)
  3. Encryption status is available for admin review via audit events
**Plans**: 5 plans

Plans:
- [x] 34-01-PLAN.md -- Workspace dependency bump + EncryptionStatus/EncryptionMethod enums + DiskIdentity fields
- [x] 34-02-PLAN.md -- AgentConfig [encryption] TOML section with clamped recheck_interval
- [x] 34-03-PLAN.md -- EncryptionChecker module: trait, WMI/Registry backends, orchestration loop
- [x] 34-04-PLAN.md -- Service wiring: singleton registration + spawn_encryption_check_task in service.rs
- [x] 34-05-PLAN.md -- Integration test scaffolding + validation doc sign-off

### Phase 35: Disk Allowlist Persistence
**Goal**: Agent persists the disk allowlist and loads it across restarts
**Depends on**: Phase 33
**Requirements**: DISK-03
**Success Criteria** (what must be TRUE):
  1. Agent writes enumerated disks to [disk_allowlist] section in agent-config.toml with device instance ID as canonical key
  2. Agent loads the allowlist from TOML at startup into an in-memory RwLock cache
  3. Drive letter is stored as informational metadata only; device instance ID is the canonical identity key
**Plans**: 2 plans

Plans:
- [x] 35-01-PLAN.md -- AgentConfig.disk_allowlist field + TOML roundtrip tests
- [x] 35-02-PLAN.md -- spawn_disk_enumeration_task pre-load + merge + non-fatal persist; service.rs Arc<RwLock<AgentConfig>> wiring

### Phase 36: Disk Enforcement
**Goal**: Agent blocks I/O to unregistered fixed disks and handles device arrivals/removals
**Depends on**: Phase 35
**Requirements**: DISK-04, DISK-05, AUDIT-02
**Success Criteria** (what must be TRUE):
  1. Agent blocks FileAction::Create / Write / Move to unregistered fixed disks at runtime via pre-ABAC enforcement in run_event_loop
  2. Agent handles WM_DEVICECHANGE DBT_DEVICEARRIVAL / DBT_DEVICEREMOVECOMPLETE for GUID_DEVINTERFACE_DISK to detect new fixed disk arrivals and removals
  3. Disk block events include disk identity fields (instance_id, bus_type, model, drive_letter) when an unregistered fixed disk is blocked
  4. Agent evaluates newly arrived disks against the allowlist and blocks or allows based on registration status
**Plans**: 3 plans

Plans:
- [x] 36-01-PLAN.md -- AuditEvent.blocked_disk field + with_blocked_disk builder (AUDIT-02)
- [x] 36-02-PLAN.md -- DiskEnforcer module: compound allowlist check + 30s toast cooldown + DISK-04 unit tests
- [x] 36-03-PLAN.md -- device_watcher.rs refactor + disk::on_disk_arrival/removal + run_event_loop / service.rs wiring (DISK-04, DISK-05, AUDIT-02)

### Phase 37: Server-Side Disk Registry
**Goal**: Admin can centrally manage disk allowlist across the fleet via REST API
**Depends on**: Phase 34
**Requirements**: ADMIN-01, ADMIN-02, ADMIN-03, AUDIT-03
**Success Criteria** (what must be TRUE):
  1. Server stores disk registry in SQLite with agent_id, instance_id, bus_type, encrypted, model, and registered_at columns
  2. Admin can list all registered disks across the fleet via GET /admin/disk-registry
  3. Admin can add a disk to the allowlist via POST /admin/disk-registry
  4. Admin can remove a disk from the allowlist via DELETE /admin/disk-registry/{id}
  5. Admin override actions (add/remove disk from registry) are emitted as EventType::AdminAction audit events
**Plans**: TBD

### Phase 38: Admin TUI Disk Registry
**Goal**: Admin can manage disk registry through the interactive TUI
**Depends on**: Phase 37
**Requirements**: ADMIN-04
**Success Criteria** (what must be TRUE):
  1. Admin can navigate to a "Disk Registry" screen under the System menu in dlp-admin-cli
  2. Admin can view all registered disks in a scrollable table with identity and encryption status
  3. Admin can add a new disk entry through a structured form
  4. Admin can remove a disk entry with a confirmation prompt
**Plans**: TBD
**UI hint**: yes

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
| 33 | Disk Enumeration | v0.7.0 | 0/TBD | Not started | - |
| 34 | BitLocker Verification | v0.7.0 | 5/5 | Planned | - |
| 35 | Disk Allowlist Persistence | v0.7.0 | 0/2 | Planned | - |
| 36 | Disk Enforcement | v0.7.0 | 0/3 | Planned | - |
| 37 | Server-Side Disk Registry | v0.7.0 | 0/TBD | Not started | - |
| 38 | Admin TUI Disk Registry | v0.7.0 | 0/TBD | Not started | - |

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
