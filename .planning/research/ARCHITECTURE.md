# Architecture: v0.6.0 Endpoint Hardening Integration

**Project:** dlp-rust
**Milestone:** v0.6.0 — Application-Aware DLP, Browser Boundary, USB Device Control
**Researched:** 2026-04-21
**Confidence:** HIGH (derived directly from codebase + SEED files)

---

## 1. Baseline Architecture (what exists today)

```
[User Session]                        [Session 0 / SYSTEM]
 dlp-user-ui                           dlp-agent (Windows Service)
   clipboard_monitor.rs                  detection/usb.rs       (WM_DEVICECHANGE pump)
   dialogs/clipboard.rs                  detection/network_share.rs
   ipc/pipe3.rs (client)                 interception/file_monitor.rs
   notifications.rs                      ipc/pipe3.rs (server)
        |                                      |
        | Pipe 3 (UI->Agent)                   | HTTP POST /audit/events
        v                                      v
   Pipe3UiMsg::ClipboardAlert          dlp-server (axum 0.8)
                                          policy_store.rs (PolicyStore::evaluate)
                                          audit_store.rs
                                          admin_api.rs
                                          alert_router.rs
                                          siem_connector.rs
                                          db/ (SQLite)

[Admin Terminal]
 dlp-admin-cli (ratatui TUI)
   SystemMenu -> SiemConfig, AlertConfig, ...
   PolicyMenu -> PolicyCreate, PolicyEdit, PolicyList, PolicySimulate
   HTTP -> dlp-server admin API
```

**Current `Pipe3UiMsg` variants:** `HealthPong`, `UiReady`, `UiClosing`, `ClipboardAlert`

**Current `PolicyCondition` variants:** `Classification`, `MemberOf`, `DeviceTrust`, `NetworkLocation`, `AccessContext`

**Current `AuditEvent` fields relevant to v0.6.0:** `application_path: Option<String>`, `application_hash: Option<String>` — both always `None` on the clipboard path today.

**Current `AbacContext` / `EvaluateRequest`:** No process-level attributes. No device-identity attributes. No origin attributes.

---

## 2. Per-Crate Impact Table

### dlp-common (shared types — all other crates depend on this)

| Component | Status | Change |
|-----------|--------|--------|
| `abac::AppIdentity` struct | NEW | `canonical_path: String`, `publisher: Option<String>`, `signature_state: SignatureState`, `aumid: Option<String>` |
| `abac::SignatureState` enum | NEW | `Signed`, `Unsigned`, `Invalid`, `Unknown` — anti-spoofing carrier |
| `abac::DeviceIdentity` struct | NEW | `vid: u16`, `pid: u16`, `serial: Option<String>`, `description: String`, `trust_tier: UsbTrustTier` |
| `abac::UsbTrustTier` enum | NEW | `Blocked`, `ReadOnly`, `FullAccess` |
| `abac::PolicyCondition` enum | MODIFIED | Add variants: `SourceApplication { op, publisher/path }`, `DestinationApplication { op, publisher/path }`, `UsbDevice { op, vid/pid/trust_tier }`, `SourceOrigin { op, value }`, `DestinationOrigin { op, value }` |
| `abac::EvaluateRequest` | MODIFIED | Add `source_application: Option<AppIdentity>`, `destination_application: Option<AppIdentity>`, `device: Option<DeviceIdentity>`, `source_origin: Option<String>`, `destination_origin: Option<String>` |
| `audit::AuditEvent` | MODIFIED | Add `source_application: Option<AppIdentity>`, `destination_application: Option<AppIdentity>`, `device: Option<DeviceIdentity>`, `source_origin: Option<String>`, `destination_origin: Option<String>` |
| `audit::AuditEvent::with_app_identity()` | NEW | Builder method for source+destination |
| `audit::AuditEvent::with_device()` | NEW | Builder method for device fields |
| IPC messages (`ipc::messages`) | MODIFIED | `Pipe3UiMsg::ClipboardAlert` gains `source_application: Option<AppIdentity>`, `destination_application: Option<AppIdentity>` |

**Why dlp-common first:** Every crate (`dlp-agent`, `dlp-user-ui`, `dlp-server`, `dlp-admin-cli`) imports from `dlp-common`. Any new type must live here before downstream code can compile. This is the mandatory Phase 1 output.

---

### dlp-user-ui (user session, Win32 clipboard APIs)

| Component | Status | Change |
|-----------|--------|--------|
| `clipboard_monitor::handle_clipboard_change` | MODIFIED | Call `GetClipboardOwner()` -> resolve PID -> `QueryFullProcessImageNameW` -> capture `AppIdentity` as `source_application` BEFORE reading clipboard text (race window: owner may close) |
| `clipboard_monitor::classify_and_alert` | MODIFIED | Accept `source_application: Option<AppIdentity>` and pass to `send_clipboard_alert` |
| NEW `detection/app_identity.rs` | NEW | `resolve_pid_to_identity(hwnd: HWND) -> Option<AppIdentity>`: `GetWindowThreadProcessId` -> `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` -> `QueryFullProcessImageNameW` -> optional `WinVerifyTrust` for signature state |
| NEW `detection/destination_app.rs` | NEW | `capture_destination() -> Option<AppIdentity>`: `GetForegroundWindow()` -> `GetWindowThreadProcessId` -> `resolve_pid_to_identity`. Called at paste time (before `WM_CLIPBOARDUPDATE` is handled). |
| `ipc/pipe3.rs::send_clipboard_alert` | MODIFIED | Add `source_application` and `destination_application` parameters; include in `Pipe3UiMsg::ClipboardAlert` |

**Session-0 constraint enforced:** `GetForegroundWindow` and `GetClipboardOwner` are per-user-session Win32 calls. They MUST remain in `dlp-user-ui`. They cannot move to `dlp-agent` (Session 0 has no interactive window station).

**Destination capture timing note:** There is no `WM_PASTE` message available OS-wide. The destination process is captured at `WM_CLIPBOARDUPDATE` time as "the currently focused window when data was placed on clipboard" — this is a best-effort capture that can race if the user switches focus mid-copy. Document this limitation explicitly.

---

### dlp-agent (Session 0 Windows Service)

| Component | Status | Change |
|-----------|--------|--------|
| `ipc/messages::Pipe3UiMsg::ClipboardAlert` | MODIFIED | New fields `source_application`, `destination_application` (in dlp-common but reflected here in the handler) |
| `ipc/pipe3.rs::route` (ClipboardAlert branch) | MODIFIED | Extract `source_application` and `destination_application` from message; populate `AuditEvent` via new `with_app_identity()` builder; include in `EvaluateRequest` for ABAC evaluation |
| `detection/usb.rs::UsbDetector` | MODIFIED | On `DBT_DEVICEARRIVAL`: call `SetupDiGetClassDevsW` / `SetupDiEnumDeviceInfo` / `SetupDiGetDeviceRegistryPropertyW` to capture VID, PID, Serial, Description; lookup against device registry cache; populate `DeviceIdentity`; store in `Arc<RwLock<HashMap<char, DeviceIdentity>>>` keyed by drive letter |
| NEW `detection/device_registry_cache.rs` | NEW | In-memory cache of `HashMap<(u16,u16,String), UsbTrustTier>` keyed by (VID, PID, Serial). Hot-reloaded when server signals config change. Mirrors the `network_share.rs` RwLock whitelist pattern. |
| `interception/file_monitor.rs` | MODIFIED | On write operations to a USB drive: look up drive letter -> `DeviceIdentity` -> `UsbTrustTier`; if `ReadOnly`, deny writes; if `Blocked`, deny all I/O; populate `EvaluateRequest.device` before policy evaluation |
| `audit_emitter.rs` | MODIFIED | Populate `device` field on USB block events from cached `DeviceIdentity` |
| `ipc/messages::Pipe2AgentMsg` | MODIFIED | Add `UsbBlockNotify { device_description, vid, pid, trust_tier, policy_name }` variant for structured toast payload |

**USB device identity enumeration stays in dlp-agent** because the `WM_DEVICECHANGE` pump and `SetupDi*` enumeration already reside there. The UI only receives the block toast (Pipe 2 -> `notifications.rs`).

---

### dlp-server (axum HTTP server)

| Component | Status | Change |
|-----------|--------|--------|
| `db/mod.rs::init_tables` | MODIFIED | Add `device_registry` and `managed_origins` tables (see schema below) |
| `db/mod.rs::run_migrations` | MODIFIED | `ALTER TABLE audit_events ADD COLUMN ...` for new fields on existing deployments |
| NEW `db/repositories/device_registry.rs` | NEW | CRUD for `device_registry` — mirrors `siem_config.rs` / `alert_router_config.rs` pattern |
| NEW `db/repositories/managed_origins.rs` | NEW | CRUD for `managed_origins` table |
| `admin_api.rs` | MODIFIED | Add device-registry routes and managed-origins routes (see API routes below) |
| NEW `chrome_connector.rs` | NEW | `POST /browser/chrome-connector/scan` endpoint — accepts Chrome Enterprise Connector DLP scan payload; evaluates against managed-origins list; returns allow/block decision; emits audit event |
| `policy_store.rs::evaluate` | MODIFIED | Handle new `PolicyCondition` variants (`SourceApplication`, `DestinationApplication`, `UsbDevice`, `SourceOrigin`, `DestinationOrigin`) in the evaluator match arm |
| `audit_store.rs` | MODIFIED | Persist new `AuditEvent` fields (source_application, destination_application, device) as nullable JSON columns |

---

### dlp-admin-cli (ratatui TUI)

| Component | Status | Change |
|-----------|--------|--------|
| `screens/dispatch.rs::handle_system_menu` | MODIFIED | Add entries 5 = "Device Registry", 6 = "Managed Origins" (currently has 5 entries indexed 0-4; index 4 exits to main menu — shift exit to index 6) |
| NEW `screens/device_registry.rs` | NEW | List registered devices (VID/PID/Serial/Trust Tier), Add / Edit / Remove screens. Mirrors `screens/siem_config.rs` / `screens/alert_config.rs` pattern. Uses generic `get::<serde_json::Value>` client calls. |
| NEW `screens/managed_origins.rs` | NEW | List managed origins (domain, classification scope), Add / Remove screens. Same pattern. |
| `screens/mod.rs` | MODIFIED | Add `Screen::DeviceRegistry { .. }` and `Screen::ManagedOrigins { .. }` variants |
| `screens/render.rs` | MODIFIED | Add render arms for the two new screen variants |
| `screens/dispatch.rs` (ConditionsBuilder) | MODIFIED | Add `SourceApplication`, `DestinationApplication`, `UsbDevice` condition types to the `ConditionsBuilder` picker list (APP-04). |

---

## 3. New IPC Messages

### Pipe3UiMsg (UI -> Agent, `dlp-common::ipc::messages`)

```rust
// MODIFIED variant — additive, backward-compatible with #[serde(default)] on new fields
ClipboardAlert {
    session_id: u32,
    classification: String,
    preview: String,
    text_length: usize,
    // NEW in v0.6.0:
    source_application: Option<AppIdentity>,
    destination_application: Option<AppIdentity>,
},
```

### Pipe2AgentMsg (Agent -> UI, `dlp-common::ipc::messages`)

```rust
// NEW variant for structured USB block notification
UsbBlockNotify {
    device_description: String,
    vid: u16,
    pid: u16,
    trust_tier: String,
    policy_name: String,
},
```

Recommendation: add `UsbBlockNotify` as a typed variant rather than reusing the generic `Toast` variant. It keeps the notification structured so `notifications.rs` can render a richer toast with device identity details rather than parsing a freeform string body.

### No new pipe is needed
The three-pipe architecture is sufficient. All new message types fit within existing pipe directions:
- App identity flows UI -> Agent on Pipe 3 (existing direction of ClipboardAlert)
- USB toast flows Agent -> UI on Pipe 2 (existing direction of Toast)
- Chrome Connector is HTTP (not IPC) — handled by dlp-server directly

---

## 4. New Database Tables

### `device_registry`
```sql
CREATE TABLE IF NOT EXISTS device_registry (
    vid           INTEGER NOT NULL,
    pid           INTEGER NOT NULL,
    serial        TEXT    NOT NULL DEFAULT '',
    description   TEXT    NOT NULL DEFAULT '',
    manufacturer  TEXT    NOT NULL DEFAULT '',
    trust_tier    TEXT    NOT NULL DEFAULT 'blocked'
                  CHECK (trust_tier IN ('blocked', 'read_only', 'full_access')),
    owner_user    TEXT,
    registered_at TEXT    NOT NULL,
    expires_at    TEXT,
    registered_by TEXT    NOT NULL DEFAULT 'admin',
    PRIMARY KEY (vid, pid, serial)
);
```

No single-row constraint — this is a multi-row registry. No `INSERT OR IGNORE` seed needed.

### `managed_origins`
```sql
CREATE TABLE IF NOT EXISTS managed_origins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    added_at    TEXT NOT NULL,
    added_by    TEXT NOT NULL DEFAULT 'admin'
);
```

### Migration for `audit_events`
```sql
-- Run in run_migrations() -- idempotent, guarded by duplicate-column check
ALTER TABLE audit_events ADD COLUMN source_application TEXT;
ALTER TABLE audit_events ADD COLUMN destination_application TEXT;
ALTER TABLE audit_events ADD COLUMN device_info TEXT;
ALTER TABLE audit_events ADD COLUMN source_origin TEXT;
ALTER TABLE audit_events ADD COLUMN destination_origin TEXT;
```
Store as nullable JSON text. Consistent with the existing pattern of storing `conditions` in `policies` as JSON text.

---

## 5. New Admin API Routes

All routes follow existing patterns: JWT-protected under the admin auth layer, JSON body, same `AppState` extractor.

### Device Registry
```
GET    /admin/device-registry                      -> list all registered devices
POST   /admin/device-registry                      -> register a new device
PUT    /admin/device-registry/:vid/:pid/:serial    -> update trust_tier or metadata
DELETE /admin/device-registry/:vid/:pid/:serial    -> remove device registration
```

### Managed Origins (Browser Boundary)
```
GET    /admin/managed-origins          -> list all managed web origins
POST   /admin/managed-origins          -> add an origin (body: domain, description)
DELETE /admin/managed-origins/:id      -> remove an origin
```

### Chrome Enterprise Connector
```
POST   /browser/chrome-connector/scan  -> Chrome Enterprise DLP scan endpoint
```

Chrome Connector does NOT use the admin JWT (Chrome submits its own connector token). It is a separate router branch with its own shared-secret middleware. The connector secret is stored in a new single-row config table or as an entry in `agent_credentials`.

---

## 6. Data Flow Diagrams

### SEED-001: App-Aware Clipboard Flow (v0.6.0)

```
[User copies text in Word]
        |
        | WM_CLIPBOARDUPDATE fires in dlp-user-ui message loop
        v
clipboard_monitor::handle_clipboard_change(session_id, last_hash)
        |
        |-- GetClipboardOwner() -> source HWND
        |-- GetWindowThreadProcessId(source_hwnd) -> source PID
        |-- OpenProcess + QueryFullProcessImageNameW -> source image path
        |-- WinVerifyTrust -> signature state
        |-- AppIdentity { canonical_path, publisher, signature_state }
        |                            = source_application
        |
        |-- GetForegroundWindow() -> destination HWND (current focused window)
        |-- GetWindowThreadProcessId(dest_hwnd) -> destination PID
        |-- OpenProcess + QueryFullProcessImageNameW -> dest image path
        |-- WinVerifyTrust -> signature state
        |                            = destination_application
        |
        |-- read_clipboard() -> text content
        |-- classify_text(text) -> Classification (T1..T4)
        |
        | [if T2+]
        v
pipe3::send_clipboard_alert(session_id, tier, preview, text_len,
                             source_application, destination_application)
        |
        | Pipe 3 (UI -> Agent, JSON frame)
        v
dlp-agent ipc/pipe3.rs::route(Pipe3UiMsg::ClipboardAlert { ... })
        |
        |-- Build EvaluateRequest {
        |       action: PASTE,
        |       resource.classification: tier,
        |       source_application: ...,
        |       destination_application: ...,
        |   }
        |-- POST /evaluate -> dlp-server PolicyStore::evaluate()
        |       PolicyCondition::SourceApplication match
        |       PolicyCondition::DestinationApplication match
        |-- Decision: ALLOW / DENY / DenyWithAlert
        |
        |-- Build AuditEvent with source_application, destination_application
        |-- POST /audit/events -> dlp-server
        |
        | [if DENY]
        v
Pipe 2: Toast -> dlp-user-ui -> notifications.rs -> Win32 balloon
```

---

### SEED-002: Chrome Enterprise Connector Flow (v0.6.0 Path B only)

```
[User pastes in Chrome tab]
        |
        | Chrome Enterprise Connector intercepts paste event
        | Chrome POSTs to configured DLP scan endpoint
        v
dlp-server POST /browser/chrome-connector/scan
        |
        |-- Parse Chrome DLP scan payload:
        |       { content_type, content, source_url, destination_url }
        |-- Lookup source_url against managed_origins table
        |-- Lookup destination_url against managed_origins table
        |-- classify_text(content) -> Classification
        |-- Build EvaluateRequest {
        |       action: PASTE,
        |       source_origin: source_url host,
        |       destination_origin: destination_url host,
        |       resource.classification: tier,
        |   }
        |-- PolicyStore::evaluate() -> Decision
        |-- Build AuditEvent with source_origin, destination_origin
        |-- store_events_sync(event)
        |-- Return { action: "block" | "allow" } to Chrome
        v
Chrome honors the response (blocks or allows the paste)
```

This flow is entirely server-side. No agent involvement. No Pipe IPC. Chrome blocks synchronously while awaiting the server response.

---

### SEED-003: USB Device Identity Flow (v0.6.0)

```
[User inserts USB drive]
        |
        | WM_DEVICECHANGE / DBT_DEVICEARRIVAL fires in dlp-agent message pump
        v
detection/usb.rs::on_drive_arrival(drive_letter)
        |
        |-- SetupDiGetClassDevsW(GUID_DEVINTERFACE_DISK)
        |-- SetupDiEnumDeviceInfo -> enumerate device instances
        |-- SetupDiGetDeviceRegistryPropertyW(SPDRP_HARDWAREID) -> "USB\VID_xxxx&PID_yyyy"
        |-- Parse VID, PID
        |-- SetupDiGetDeviceRegistryPropertyW(SPDRP_SERIALNUMBER) -> serial
        |-- SetupDiGetDeviceRegistryPropertyW(SPDRP_DEVICEDESC) -> description
        |-- Lookup (VID, PID, Serial) in device_registry_cache
        |       -> UsbTrustTier: Blocked | ReadOnly | FullAccess | Unknown (default=Blocked)
        |
        |-- Store DeviceIdentity in Arc<RwLock<HashMap<char, DeviceIdentity>>>
        |
        | [if Blocked or Unknown]
        |-- Pipe 2: UsbBlockNotify { description, vid, pid, trust_tier: "blocked", ... }
        |        -> dlp-user-ui notifications.rs -> Toast to user
        |-- Emit AuditEvent { event_type: Block, device: DeviceIdentity, ... }
        |
        | [if ReadOnly or FullAccess]
        |-- Drive is allowed to mount
        v
[User writes to USB drive]
        |
        | NtWriteFile / NtCreateFile interception in file_monitor.rs
        v
interception/file_monitor.rs::on_write_attempt(path, classification)
        |
        |-- Extract drive letter from path
        |-- Lookup drive letter in device_identity_map -> DeviceIdentity
        |-- Build EvaluateRequest { device: DeviceIdentity, action: WRITE, ... }
        |-- PolicyStore::evaluate() -> Decision
        |
        | [if ReadOnly tier AND write operation]
        |-- Decision = DENY (trust tier overrides policy for writes)
        |-- Emit AuditEvent with device fields
        |-- Pipe 2: UsbBlockNotify -> dlp-user-ui -> Toast
        |
        v
AuditEvent -> dlp-server -> SIEM relay + alert_router
```

---

## 7. Component Boundaries Summary

```
                     dlp-common (shared types — Phase 22 foundation)
                    /      |      |      \
         dlp-agent    dlp-user-ui  dlp-server  dlp-admin-cli
              |             |           |
              +---Pipe3---->+           |
              |<---Pipe2----+           |
              |                        |
              +---HTTP /evaluate------->|
              +---HTTP /audit/events--->|
                                        |
              dlp-admin-cli ---HTTP admin API---+

New in v0.6.0:
  dlp-user-ui:   adds detection/app_identity.rs, detection/destination_app.rs
  dlp-agent:     adds detection/device_registry_cache.rs
  dlp-server:    adds chrome_connector.rs, db/repositories/device_registry.rs,
                 db/repositories/managed_origins.rs
  dlp-admin-cli: adds screens/device_registry.rs, screens/managed_origins.rs
```

---

## 8. Recommended Phase Build Order

The dependency graph mandates this sequence. Each phase produces output the next phase consumes.

```
Phase 22: dlp-common type foundation
  - New: AppIdentity, SignatureState, DeviceIdentity, UsbTrustTier structs
  - Modified: PolicyCondition (5 new variants), EvaluateRequest (5 new fields),
              AuditEvent (5 new fields + builders), Pipe3UiMsg::ClipboardAlert (2 new fields),
              Pipe2AgentMsg::UsbBlockNotify (new variant)
  - Output: all shared types compile; all downstream crates see new types
  - Must come BEFORE: all of 23, 24, 25, 26, 27, 28, 29

Phase 23: USB device identity enumeration  [dlp-agent, SEED-003 Phase A]
  - Modified: detection/usb.rs -- SetupDi enumeration on DBT_DEVICEARRIVAL
  - New: detection/device_registry_cache.rs -- Arc<RwLock<HashMap>> keyed by drive letter
  - Output: agent captures and logs VID/PID/Serial/Description; no enforcement change yet
  - Depends on: Phase 22
  - Can run in parallel with: Phase 24, Phase 25

Phase 24: Device registry DB + admin API  [dlp-server, SEED-003 Phase B]
  - New: device_registry table, db/repositories/device_registry.rs
  - New: GET/POST/PUT/DELETE /admin/device-registry routes in admin_api.rs
  - Output: server stores and serves device registry over API
  - Depends on: Phase 22
  - Can run in parallel with: Phase 23, Phase 25

Phase 25: App identity capture in clipboard monitor  [dlp-user-ui, SEED-001]
  - New: detection/app_identity.rs -- Win32 process identity resolution
  - New: detection/destination_app.rs -- GetForegroundWindow capture
  - Modified: clipboard_monitor.rs -- capture source + destination at WM_CLIPBOARDUPDATE
  - Modified: ipc/pipe3.rs::send_clipboard_alert -- include AppIdentity fields
  - Output: ClipboardAlert IPC messages now carry source_application + destination_application
  - Depends on: Phase 22 (AppIdentity type)
  - Can run in parallel with: Phase 23, Phase 24

Phase 26: ABAC enforcement -- app identity + USB read-only  [dlp-agent + dlp-server]
  - Modified: ipc/pipe3.rs::route(ClipboardAlert) -- build EvaluateRequest with app identity
  - Modified: interception/file_monitor.rs -- USB trust tier enforcement at I/O time
  - Modified: detection/usb.rs -- consult device_registry_cache; send UsbBlockNotify via Pipe 2
  - Modified: policy_store.rs::evaluate -- handle SourceApplication, DestinationApplication,
              UsbDevice, SourceOrigin, DestinationOrigin condition variants
  - Audit events populated: source_application, destination_application, device fields
  - Output: ABAC decisions use app identity and USB device identity (APP-01/02/03, USB-03)
  - Depends on: Phase 22, 23, 24, 25 (all must complete before integration phase)

Phase 27: User notifications for USB blocks  [dlp-user-ui, SEED-003 Phase E]
  - Modified: notifications.rs -- handle Pipe2AgentMsg::UsbBlockNotify, render structured toast
  - Output: User sees Toast when USB is blocked with device description and policy name (USB-04)
  - Depends on: Phase 22 (UsbBlockNotify variant), Phase 26 (agent emits the message)

Phase 28: Admin TUI screens  [dlp-admin-cli, SEED-003 Phase C + SEED-001 APP-04]
  - New: screens/device_registry.rs -- list/add/edit/remove devices with trust tier
  - New: screens/managed_origins.rs -- list/add/remove managed web origins
  - Modified: screens/dispatch.rs::handle_system_menu -- add entries 5 and 6
  - Modified: screens/mod.rs, screens/render.rs -- new Screen variants
  - Modified: ConditionsBuilder picker -- add SourceApplication, DestinationApplication,
              UsbDevice condition types (APP-04)
  - Output: Admin can author device-aware and app-aware policies in TUI
  - Depends on: Phase 24 (server API must exist); Phase 26 (conditions must evaluate)

Phase 29: Chrome Enterprise Connector  [dlp-server, SEED-002 Path B]
  - New: chrome_connector.rs -- POST /browser/chrome-connector/scan
  - New: managed_origins table, db/repositories/managed_origins.rs
  - Modified: admin_api.rs -- GET/POST/DELETE /admin/managed-origins routes
  - Modified: policy_store.rs::evaluate -- SourceOrigin, DestinationOrigin condition evaluation
  - Output: Chrome Enterprise customers can block paste into unmanaged origins (BRW-01/02/03)
  - Depends on: Phase 22 (origin types), Phase 28 (admin can manage origins list)
  - Note: Can be parallelized with Phase 27-28 on the server side; sequence after Phase 26
    to avoid shipping browser enforcement before OS-level app enforcement is proven
```

### Build Order Summary (dependency graph)

```
Phase 22 (dlp-common foundation)
  |
  +---> Phase 23 (USB enumeration, dlp-agent)     \
  |                                                |
  +---> Phase 24 (device registry DB, dlp-server) +---> Phase 26 (ABAC enforcement) ---> Phase 27 (toast)
  |                                                |                                  \
  +---> Phase 25 (app identity, dlp-user-ui)      /                                   --> Phase 28 (TUI)
                                                                                                |
                                                                                                v
                                                                                       Phase 29 (Chrome connector)
```

Phases 23, 24, and 25 can be developed in parallel after Phase 22 lands (different crates). Phase 26 is the convergence point. Phases 27 and 28 can also overlap since they target different crates. Phase 29 sequences after Phase 28.

---

## 9. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| `AppIdentity` lives in `dlp-common`, not `dlp-user-ui` | `dlp-agent` must receive it over Pipe 3 and embed it in `EvaluateRequest`; keeping it in common avoids a crate cycle |
| Source app captured at `WM_CLIPBOARDUPDATE`, not at paste time | `GetClipboardOwner()` returns the window that called `SetClipboardData`; that window may have closed by paste time (SEED-001 risk 3 — ownership race) |
| Destination app captured at same `WM_CLIPBOARDUPDATE` moment | `GetForegroundWindow()` at change time approximates paste destination; better than no capture; documented as best-effort |
| USB device registry in server DB, NOT agent TOML | Operator-config-in-DB pattern (established v0.3.0, enforced by project memory). Hot-reload without restart. TUI-manageable. |
| USB trust tier enforcement: I/O-time, not mount-time | Mount-time blocking requires a filesystem filter driver (major new subsystem). I/O-time reuses existing `file_monitor.rs` detour. Documented as limitation (drive letter appears, writes fail). |
| Chrome Connector as Path B first | Path B ships in one phase with no browser extension. Path A (native extension) is a separate milestone. Path B delivers immediate value for enterprise Chrome/Edge customers. |
| `UsbBlockNotify` as typed Pipe 2 variant | Allows `notifications.rs` to render a structured toast with device name, VID/PID, and policy name rather than parsing a freeform generic Toast body string. |
| All new dlp-common types ship in one phase (Phase 22) | One breaking change across all crates instead of sequential partial breakage. Downstream crates update in the same PR window. |

---

## 10. Anti-Spoofing (APP-06)

`WinVerifyTrust` (Authenticode) verification lives in `detection/app_identity.rs` in `dlp-user-ui`. It is the only viable defense against a renamed binary attack (e.g., `notepad.exe` renamed to `excel.exe`). The `SignatureState` enum carries this into `AppIdentity`. Policy conditions can express "publisher = Microsoft Corporation AND signature_state = Signed". Without this field, an attacker can bypass an allowlist by renaming their binary. The initial Phase 25 implementation may mark `SignatureState::Unknown` while the Win32 verification call is wired up; the policy evaluator should treat `Unknown` as `Unsigned` for safety.

---

## 11. Gaps and Open Questions for Phase Planning

1. **Destination app capture accuracy:** `GetForegroundWindow()` at copy time is a proxy for paste destination. A user who copies, then switches windows, then pastes defeats this. The correct fix is hooking `WM_PASTE` globally via `WH_CALLWNDPROC` (requires DLL injection — significant complexity). Document the limitation; defer global paste hook to a future milestone.

2. **UWP app identity:** `QueryFullProcessImageNameW` returns a generic host process path for packaged apps. AUMID resolution requires `GetApplicationUserModelId` via COM. Phase 25 should return `canonical_path` as the host path with `aumid: None`; add a follow-up issue for UWP-specific resolution.

3. **Browser origin coverage gap:** SEED-001 detects "this is chrome.exe" at the process level. SEED-002 Path B (Chrome Connector) detects "this paste came from origin X" but only when the IT admin has configured Chrome Enterprise policy. Unmanaged Chrome instances are handled only by the coarse "destination = browser process" SEED-001 policy. Phase 29 should document this coverage boundary.

4. **USB mount-time vs I/O-time trade-off:** Architecture here assumes I/O-time enforcement (lower risk, reuses existing infrastructure). If mount-time blocking is required, a kernel-mode filter driver phase is needed and is out of scope for v0.6.0.

5. **`audit_events` schema growth:** Five new nullable columns added via migration. This is acceptable technical debt for v0.6.0 given the existing precedent. Long-term, a `audit_event_metadata` key-value side table may be preferable.

6. **Chrome Connector shared secret storage:** The connector token that Chrome sends for authentication needs a storage home. Options: (a) new single-row `chrome_connector_config` table, (b) entry in existing `agent_credentials` table (key = "chrome_connector_secret"). Option (b) avoids a new table and follows an existing pattern.
