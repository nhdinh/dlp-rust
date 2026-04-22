# Roadmap: DLP-RUST

## Milestones

- ✅ **v0.2.0 Feature Completion** — Phases 0.1–12 (shipped 2026-04-13)
- ✅ **v0.3.0 Operational Hardening** — Phases 7–11 (shipped 2026-04-16)
- ✅ **v0.4.0 Policy Authoring** — Phases 13–17 (shipped 2026-04-20)
- ✅ **v0.5.0 Boolean Logic** — Phases 18–21 (shipped 2026-04-21)
- 🚧 **v0.6.0 Endpoint Hardening** — Phases 22–29 (in progress)

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3, ...): Planned milestone work
- Decimal phases (e.g., 3.1, 04.1): Urgent insertions (marked with INSERTED)

Phase numbering is continuous across milestones — never restarts.

## v0.5.0 — Boolean Logic (Shipped)

<details>
<summary>✅ v0.5.0 — archived at <code>.planning/milestones/v0.5.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.5.0-ROADMAP.md` and `.planning/milestones/v0.5.0-REQUIREMENTS.md`. Boolean mode engine (ALL/ANY/NONE) + TUI picker + expanded operators (gt/lt/ne/contains) + in-place condition editing — all 4 requirements (POLICY-09..12) delivered.
</details>

## 🚧 v0.6.0 — Endpoint Hardening (In Progress)

**Milestone Goal:** Extend the enforcement layer with application identity, browser boundary control, and USB device control — all surfaced as first-class ABAC subject attributes.

**Requirements:** APP-01..06, BRW-01..03, USB-01..04 (13 requirements total)

### Phase Summary

- [x] **Phase 22: dlp-common Foundation** — New shared types (AppIdentity, DeviceIdentity, UsbTrustTier, SignatureState) that gate all three tracks (complete 2026-04-22)
- [x] **Phase 23: USB Enumeration in dlp-agent** — Agent captures VID/PID/Serial/description on USB arrival via SetupDi; no enforcement yet (complete 2026-04-22)
- [ ] **Phase 24: Device Registry DB + Admin API** — device_registry table, trust-tier CRUD endpoints, agent polling for registry state
- [ ] **Phase 25: App Identity Capture in dlp-user-ui** — Source and destination process identity resolved at clipboard time; Authenticode verification; audit event fields populated
- [ ] **Phase 26: ABAC Enforcement Convergence** — Evaluator enforces app-identity and USB trust-tier conditions; USB I/O enforcement hot path in file_monitor.rs
- [ ] **Phase 27: USB Toast Notification** — User toast on USB block via Pipe 2 + winrt-notification in dlp-user-ui
- [ ] **Phase 28: Admin TUI Screens** — App identity condition picker, Device Registry screen, managed-origins screen in dlp-admin-cli
- [ ] **Phase 29: Chrome Enterprise Connector** — Named-pipe server in dlp-agent; protobuf decode; browser clipboard block + audit

## Phase Details

### Phase 22: dlp-common Foundation
**Goal**: All three enforcement tracks share a stable, versioned set of common types so downstream crates can build without re-defining wire formats
**Depends on**: Phase 21 (previous milestone complete)
**Requirements**: (infrastructure — no single-req mapping; gates APP-01..06, BRW-01..03, USB-01..04)
**Success Criteria** (what must be TRUE):
  1. `AppIdentity` struct (image_path, publisher, trust_tier, signature_state) exists in dlp-common and compiles in all five crates
  2. `DeviceIdentity` struct (vid, pid, serial, description) and `UsbTrustTier` enum exist in dlp-common and are serializable via serde
  3. `AbacContext` carries `source_application: Option<AppIdentity>` and `destination_application: Option<AppIdentity>` fields with `#[serde(default)]`
  4. `AuditEvent` wire format includes app identity and device identity optional fields with `#[serde(default)]` — no deserialization breaks on old events
  5. Pipe 3 `ClipboardAlert` and Pipe 2 message types carry the new fields with `#[serde(default)]`; workspace compiles with zero warnings
**Plans**: 4 plans
Plans:
- [x] 22-01-PLAN.md - endpoint.rs new types (AppIdentity, DeviceIdentity, UsbTrustTier, AppTrustTier, SignatureState) + lib.rs re-exports
- [x] 22-02-PLAN.md - abac.rs (EvaluateRequest fields + new AbacContext) and audit.rs (AuditEvent fields + three builder methods)
- [x] 22-03-PLAN.md - Pipe3UiMsg::ClipboardAlert extended in dlp-agent + dlp-user-ui IPC messages.rs (mirrored)
- [x] 22-04-PLAN.md - Cross-type integration test + workspace zero-warning verification gate + human checkpoint

### Phase 23: USB Enumeration in dlp-agent
**Goal**: The agent reliably detects USB device arrival and captures device identity; the information is logged and ready for enforcement without any behavior change to existing flows
**Depends on**: Phase 22
**Requirements**: USB-01
**Success Criteria** (what must be TRUE):
  1. Plugging a USB mass-storage device causes the agent to log VID, PID, serial number, and description at INFO level within one second of arrival
  2. Devices without a serial number (e.g., generic USB hubs) are captured with serial = "(none)" rather than panicking or silently skipping
  3. Existing file interception and clipboard flows are unaffected — all pre-Phase-23 tests still pass
**Plans**: 2 plans
Plans:
- [x] 23-01-PLAN.md - Pure-Rust UsbDetector.device_identities field + parse_usb_device_path helper + identity accessor + Win32_Devices_DeviceAndDriverInstallation feature flag
- [x] 23-02-PLAN.md - GUID_DEVINTERFACE_USB_DEVICE const + second RegisterDeviceNotificationW call + WM_DEVICECHANGE arm in usb_wndproc + SetupDi description fetch + human checkpoint

### Phase 24: Device Registry DB + Admin API
**Goal**: The server persists a trust-tier registry for USB devices and exposes a JWT-protected admin API for device management so agents can query registered device trust tiers
**Depends on**: Phase 22
**Requirements**: USB-02
**Success Criteria** (what must be TRUE):
  1. `GET /admin/device-registry` returns a JSON list of all registered devices with VID, PID, serial, description, and trust_tier
  2. `POST /admin/device-registry` registers a new device entry; `DELETE /admin/device-registry/{id}` removes it — both require JWT auth
  3. Trust tier values `blocked`, `read_only`, and `full_access` are enforced by a DB CHECK constraint; invalid tier values are rejected with 422
  4. Agent can query the registry endpoint and cache results in `RwLock<HashMap>` indexed by device key (vid+pid+serial)
**Plans**: TBD

### Phase 25: App Identity Capture in dlp-user-ui
**Goal**: Users' clipboard actions carry source and destination process identity so the system knows which application produced or consumed clipboard content, with publisher verified against Authenticode
**Depends on**: Phase 22
**Requirements**: APP-01, APP-02, APP-05, APP-06
**Success Criteria** (what must be TRUE):
  1. When the user pastes into an application, `dlp-user-ui` resolves the foreground window to a full image path and publisher via `QueryFullProcessImageNameW` + `WinVerifyTrust`
  2. When clipboard content changes, `GetClipboardOwner` is called synchronously inside the `WM_CLIPBOARDUPDATE` handler (not deferred) — source identity is populated before the source window can close
  3. Authenticode publisher extraction runs in `spawn_blocking` with a per-process-path cache; the UI message pump is never blocked by CRL network calls
  4. A clipboard block audit event contains non-empty `source_application` and `destination_application` fields with image_path, publisher, and signature_state populated
  5. Renaming a signed binary still produces the correct publisher (signature verified from file, not from process name)
**Plans**: TBD
**UI hint**: yes

### Phase 26: ABAC Enforcement Convergence
**Goal**: The policy evaluator enforces decisions based on application identity and USB device trust tier so clipboard and file operations are blocked or allowed based on which app and which device are involved
**Depends on**: Phase 23, Phase 24, Phase 25
**Requirements**: APP-03, USB-03
**Success Criteria** (what must be TRUE):
  1. A policy with a `source_application` or `destination_application` condition (publisher eq / image_path eq / trust_tier eq) is evaluated correctly — matching policies block or allow clipboard events as authored
  2. A USB device registered as `blocked` causes all I/O to that device to be denied; file read attempts return an error to the user
  3. A USB device registered as `read_only` allows file reads and denies file writes to that device
  4. Device trust tier enforcement uses the in-memory `RwLock<HashMap>` cache; registry updates (from Phase 24 API) invalidate and refresh the cache without agent restart
**Plans**: TBD

### Phase 27: USB Toast Notification
**Goal**: Users receive an immediate, informative toast notification when a USB device is blocked so they understand why the device is not working
**Depends on**: Phase 26
**Requirements**: USB-04
**Success Criteria** (what must be TRUE):
  1. When a USB device is blocked by the agent, `dlp-user-ui` displays a Windows toast notification within two seconds containing the device name and a brief policy explanation
  2. The notification correctly identifies the device by its description (not just VID/PID)
  3. Toast delivery reuses the existing `winrt-notification` integration — no new notification library is added
**Plans**: TBD
**UI hint**: yes

### Phase 28: Admin TUI Screens
**Goal**: Administrators can manage USB device trust tiers, managed web origins, and author app-identity policy conditions through the TUI without touching the API directly
**Depends on**: Phase 24, Phase 26
**Requirements**: APP-04, BRW-02
**Success Criteria** (what must be TRUE):
  1. The TUI presents a Device Registry screen where the admin can list registered devices, register a new device (entering VID, PID, serial, description, and trust tier), and delete an existing entry
  2. The TUI presents a Managed Origins screen where the admin can list, add, and remove trusted web domains — changes persist via the admin API and hot-reload without server restart
  3. The TUI conditions builder's attribute picker includes `source_application` and `destination_application` as selectable attributes with publisher, image_path, and trust_tier sub-pickers — no raw JSON entry required
  4. All three new screens follow the existing ratatui TUI conventions (keyboard nav, Esc to cancel, confirmation on destructive actions)
**Plans**: TBD
**UI hint**: yes

### Phase 29: Chrome Enterprise Connector
**Goal**: Chrome browser clipboard events are intercepted and evaluated by the DLP system so paste operations from managed origins to unmanaged destinations are blocked at the browser level
**Depends on**: Phase 28
**Requirements**: BRW-01, BRW-03
**Success Criteria** (what must be TRUE):
  1. `dlp-agent` starts a named-pipe server at `\\.\pipe\brcm_chrm_cas` and registers in HKLM so Chrome detects it as a Content Analysis agent on startup
  2. Chrome sends a clipboard scan request to the pipe when the user pastes; the agent decodes the protobuf frame and resolves source and destination origins from the request
  3. Pasting from a managed/protected origin (in the managed-origins list) to an unmanaged origin results in a BLOCK response returned to Chrome — the paste is prevented inside the browser
  4. A block event produces an audit entry with `source_origin` and `destination_origin` fields visible in the audit log
**Plans**: TBD

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
| 19 | Boolean Mode in TUI + Import/Export | v0.5.0 | 2/2 | Complete | 2026-04-21 |
| 20 | Operator Expansion | v0.5.0 | 2/2 | Complete | 2026-04-21 |
| 21 | In-Place Condition Editing | v0.5.0 | 1/1 | Complete | 2026-04-21 |
| 22 | dlp-common Foundation | v0.6.0 | 4/4 | Complete | 2026-04-22 |
| 23 | USB Enumeration in dlp-agent | v0.6.0 | 0/2 | Planned | - |
| 24 | Device Registry DB + Admin API | v0.6.0 | TBD | Not started | - |
| 25 | App Identity Capture in dlp-user-ui | v0.6.0 | TBD | Not started | - |
| 26 | ABAC Enforcement Convergence | v0.6.0 | TBD | Not started | - |
| 27 | USB Toast Notification | v0.6.0 | TBD | Not started | - |
| 28 | Admin TUI Screens | v0.6.0 | TBD | Not started | - |
| 29 | Chrome Enterprise Connector | v0.6.0 | TBD | Not started | - |
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
