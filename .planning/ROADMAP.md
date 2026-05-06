# Roadmap: DLP-RUST

## Milestones

- v0.2.0 Feature Completion -- Phases 0.1-12 (shipped 2026-04-13)
- v0.3.0 Operational Hardening -- Phases 7-11 (shipped 2026-04-16)
- v0.4.0 Policy Authoring -- Phases 13-17 (shipped 2026-04-20)
- v0.5.0 Boolean Logic -- Phases 18-21 (shipped 2026-04-21)
- v0.6.0 Endpoint Hardening -- Phases 22-30 (shipped 2026-04-29)
- v0.7.0 Disk Exfiltration Prevention -- Phases 33-38 (shipped 2026-05-06)
- v0.8.0 Application-Aware DLP -- Phases 39-42 (planning)

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

## v0.7.0 - Disk Exfiltration Prevention (Shipped)

<details>
<summary>v0.7.0 - archived at <code>.planning/milestones/v0.7.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.7.0-ROADMAP.md` and `.planning/milestones/v0.7.0-REQUIREMENTS.md`. Disk enumeration (DISK-01/02), BitLocker verification (CRYPT-01/02), disk allowlist persistence (DISK-03), runtime disk enforcement (DISK-04/05), server-side disk registry (ADMIN-01..03), admin TUI disk registry (ADMIN-04), LDAP config TUI (ADMIN-05), and USB enforcement fix (PnP disable + Volume DACL deny-all) — all 15 requirements delivered across 8 phases (33-38.2).

**Known gaps at close:** Phase 34 HUMAN-UAT (unencrypted disk warning — requires physical machine); Phase 38.2 HUMAN-UAT (drive-letter correlation — approved from prior session).
</details>

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
**Plans**: TBD

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
**Plans**: 3 plans

Plans:
- [x] 37-01-PLAN.md -- dlp-common Action enum extension + disk_registry table DDL + DiskRegistryRepository (pure INSERT, no upsert)
- [x] 37-02-PLAN.md -- Admin REST handlers (GET/POST/DELETE), AUDIT-03 events, AgentConfigPayload disk_allowlist propagation
- [x] 37-03-PLAN.md -- Agent live reload: AgentConfigPayload mirror + config_poll_loop merge into DiskEnumerator.instance_id_map

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

### Phase 38.1: LDAP Config TUI (INSERTED)
**Goal**: Admin can configure Active Directory connection parameters through the interactive TUI
**Depends on**: Phase 7 (LDAP backend already complete)
**Requirements**: ADMIN-05
**Success Criteria** (what must be TRUE):
  1. Admin can navigate to an "LDAP Config" screen under the System menu in dlp-admin-cli
  2. Admin can view and edit all five LDAP connection parameters: `ldap_url`, `base_dn`, `require_tls`, `cache_ttl_secs`, `vpn_subnets`
  3. Admin can save the configuration via `PUT /admin/ldap-config`; a success or error status message is displayed
  4. The `cache_ttl_secs` field rejects values outside [60, 3600] with an inline error
  5. The `require_tls` field renders as a boolean toggle (`[x]` / `[ ]`)
**Plans**: 3 plans

Plans:
- [x] 38.1-01-PLAN.md -- Screen::LdapConfig variant + LDAP_ROW_COUNT/SAVE/BACK constants in app.rs
- [x] 38.1-02-PLAN.md -- dispatch.rs: LDAP_KEYS + helpers + action_load/save_ldap_config + handle_ldap_config family + SystemMenu expansion + handle_event arm
- [x] 38.1-03-PLAN.md -- render.rs: LDAP_FIELD_LABELS + is_ldap_bool/numeric + draw_ldap_config + SystemMenu label expansion + draw_screen arm + manual TUI checkpoint

### Phase 38.2: USB Enforcement Fix — Blocked Device I/O (INSERTED)
**Goal**: Fix the USB enforcement gap where registered blocked devices log DENY decisions but writes still succeed. Ensure DeviceController::disable_usb_device fires at PnP level for all registered blocked USB devices, preventing file I/O before it reaches the filesystem.
**Depends on**: Phase 31
**Requirements**: USB-03
**Success Criteria** (what must be TRUE):
  1. When a USB device registered with trust_tier=blocked is plugged in, DeviceController::disable_usb_device is called synchronously in the arrival handler
  2. The device is disabled at the PnP level (CM_Disable_DevNode with CM_DISABLE_ABSOLUTE) before any file I/O can reach the volume
  3. File writes to the blocked device fail with an OS-level access-denied error instead of succeeding silently
  4. Audit BLOCK/DENY events still fire as before, but now reflect actual enforcement rather than audit-only observation
**Plans**: 3 plans in 2 waves

Plans:
- [x] 38.2-01-PLAN.md -- Add `set_volume_deny_all` to `DeviceController`, wire into `apply_tier_enforcement` for Blocked tier (DACL defense-in-depth layer)
- [x] 38.2-02-PLAN.md -- Fix WR-01 race in `usb.rs` + fix startup enforcement gap (`scan_existing_usb_identities`)
- [x] 38.2-03-PLAN.md -- Fix drive-letter mislabel in `dlp-common/src/disk.rs` (proper instance_id-to-drive-letter correlation)

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
| 37 | Server-Side Disk Registry | v0.7.0 | 0/3 | Planned | - |
| 38 | Admin TUI Disk Registry | v0.7.0 | 0/TBD | Not started | - |
| 38.1 | LDAP Config TUI | v0.7.0 | 0/3 | Planned | - |
| 38.2 | USB Enforcement Fix | v0.7.0 | 3/3 | Planned | - |
| 39 | UWP App Identity | v0.8.0 | 0/TBD | Not started | - |
| 40 | Drag-and-Drop Enforcement | v0.8.0 | 0/TBD | Not started | - |
| 41 | Browser Origin Clipboard Policies | v0.8.0 | 0/TBD | Not started | - |
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

_Archived milestone details: `.planning/milestones/v0.2.0-ROADMAP.md` through `.planning/milestones/v0.6.0-ROADMAP.md`._
