# Technology Stack — v0.8.0 Application-Aware DLP

**Project:** dlp-rust
**Milestone:** v0.8.0 — UWP App Identity, Drag-and-Drop Enforcement, Browser Origin Policies
**Researched:** 2026-05-06
**Scope:** NEW capabilities only — UWP AUMID resolution, OLE drag-and-drop interception, Chrome Enterprise Connector origin enrichment.
Existing capabilities (axum 0.8, rusqlite, ratatui, windows 0.62, prost, JWT, r2d2) are NOT re-researched.

---

## Verdict

Zero new external crates required. All v0.8.0 features are built on existing stack:
- `windows` crate 0.62 (already upgraded in v0.7.1) — `GetApplicationUserModelIdFromWindow`, COM `IDropTarget`
- `prost` + `protobuf` (existing) — Chrome Enterprise Connector message schema extension
- Existing named-pipe IPC, ABAC evaluator, audit pipeline

The `windows` crate already has all needed feature flags enabled from prior phases.

---

## Capability 1: UWP AUMID Resolution

**Crate:** `windows` (existing, no new feature flags needed)

**API surface in `windows::Win32::UI::Shell`:**
- `GetApplicationUserModelIdFromWindow` — resolves HWND to AUMID string for UWP apps
- `IShellItem` + `GetApplicationUserModelId` — alternative via COM for process tokens

**Why no new crate:** The Windows 0.62 crate already exposes `GetApplicationUserModelIdFromWindow` under `Win32::UI::Shell`. This is a single function call, not a subsystem.

**Where this code lives:** Extension to `dlp-agent/src/detection/app_identity.rs` (existing). AUMID resolution is a fallback when `QueryFullProcessImageNameW` returns `ApplicationFrameHost.exe` or `WWAHost.exe`.

**Confidence:** HIGH — `GetApplicationUserModelIdFromWindow` is a stable Win32 API since Windows 8. Used extensively in Windows shell and taskbar pinning.

---

## Capability 2: OLE Drag-and-Drop Interception

**Crate:** `windows` (existing, COM support already enabled)

**API surface:**
- `IDropTarget` — COM interface to implement custom drop target
- `RegisterDragDrop` — registers a window as a drop target
- `RevokeDragDrop` — unregisters
- `DoDragDrop` — initiates drag operation (for source-side interception)
- `WindowFromPoint` — identifies destination window at drop time
- `GetWindowThreadProcessId` → `OpenProcess` → `QueryFullProcessImageNameW` — destination app identity

**Implementation strategy:**
1. Install a global `IDropTarget` hook or message hook that intercepts `WM_DROPFILES` / `WM_COPYDATA` / OLE drag messages
2. At drop time, identify source app (from drag data object) and destination app (from `WindowFromPoint`)
3. Evaluate ABAC policy before allowing `Drop()` to proceed
4. If denied, return `DROPEFFECT_NONE` and emit audit event

**Where this code lives:** New module `dlp-agent/src/interception/drag_drop.rs`. Integrates into existing `InterceptionEngine` event loop.

**Confidence:** MEDIUM-HIGH — OLE drag-and-drop is well-documented COM, but implementing `IDropTarget` in Rust requires manual vtable construction (unsafe). The `windows-rs` crate provides `implement` macro for COM interfaces but `IDropTarget` is complex (4 methods + base `IUnknown`).

---

## Capability 3: Chrome Enterprise Connector Origin Enrichment

**Crate:** `prost` (existing) — protobuf schema extension

**Schema changes:**
- Extend the Chrome Content Analysis `ContentAnalysisRequest` proto handling to read `destination_url` field (if present in Chrome's message)
- Add `source_origin` and `destination_origin` fields to `AbacContext`
- Add `source_origin` and `destination_origin` to `AuditEvent`

**No new crates needed:** The existing `prost` codegen and protobuf frame protocol from Phase 29 handle all messaging. This is a schema extension, not a new subsystem.

**Where this code lives:**
- `dlp-agent/src/chrome/` — extend request dispatch to extract origin fields
- `dlp-common/src/abac.rs` — add origin attributes to `AbacContext`
- `dlp-common/src/audit.rs` — add origin fields to `AuditEvent`
- `dlp-server/src/admin_api.rs` — extend managed-origins API if needed

**Confidence:** HIGH — protobuf schema extension is trivial. The harder part is Chrome version compatibility (see Pitfalls).

---

## Summary: Dependency Delta for v0.8.0

### `Cargo.toml` workspace — no changes needed

### `dlp-agent/Cargo.toml`

No changes. All APIs (`GetApplicationUserModelIdFromWindow`, `IDropTarget`, `RegisterDragDrop`) are available in the existing `windows` crate feature set.

### `dlp-user-ui/Cargo.toml`

No changes. Drag-and-drop source detection runs in `dlp-agent` (SYSTEM session monitors all sessions via global hooks).

### `dlp-common/Cargo.toml`

No new dependencies. Add `aumid: Option<String>` to `AppIdentity`, add origin fields to `AbacContext` and `AuditEvent`.

### `dlp-server/Cargo.toml`

No new dependencies. Extend managed-origins table if origin policies require new storage.

---

## What NOT to Add

| Rejected option | Reason |
|----------------|--------|
| `uwp` crate | No actively maintained Rust crate for UWP APIs. Direct Win32 calls are simpler. |
| `ole-automation` crate | Overkill — `windows` crate COM support is sufficient. |
| Chrome extension (Path A from SEED-002) | v0.8.0 extends existing Chrome Enterprise Connector (Path B). Native extension is v0.9.0+ scope. |
| `webbrowser` crate | Not needed — we don't open URLs, we read origin fields from Chrome's protobuf messages. |
| Separate `dlp-drag-drop` crate | Overkill — drag-drop is a single module (~300 lines) in `dlp-agent`. |
| `raw-cpuid` / `cpu-features` | Not relevant — no CPU-dependent features in v0.8.0. |

---

## Key Integration Points

| New capability | Lives in | Communicates with |
|---------------|----------|-------------------|
| UWP AUMID resolution | `dlp-agent/src/detection/app_identity.rs` (extend) | `AppIdentity` struct, ABAC evaluator |
| Drag-and-drop interception | `dlp-agent/src/interception/drag_drop.rs` (new) | `InterceptionEngine`, `UsbEnforcer`-style block result, audit emitter |
| Chrome origin enrichment | `dlp-agent/src/chrome/` (extend) | `AbacContext` (origin attributes), `AuditEvent` |
| Admin origin management | `dlp-admin-cli/src/screens/` (extend) | Managed-origins API from Phase 28 |

---

## Confidence Assessment

| Area | Confidence | Reason |
|------|------------|--------|
| `GetApplicationUserModelIdFromWindow` API | HIGH | Stable since Windows 8; well-documented |
| `IDropTarget` COM in Rust | MEDIUM-HIGH | `windows-rs` `implement` macro supports COM; `IDropTarget` is 4 methods |
| Chrome origin field availability | MEDIUM | Depends on Chrome version; `destination_url` may not be in all requests |
| Protobuf schema extension | HIGH | `prost` handles this trivially |
| ABAC origin attribute integration | HIGH | Follows existing pattern from Phase 26 (app identity conditions) |

---

## Sources

- [GetApplicationUserModelIdFromWindow — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-getapplicationusermodelfromwindow)
- [Application User Model ID — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/shell/app-ids)
- [IDropTarget interface — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nn-oleidl-idroptarget)
- [RegisterDragDrop — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/ole2/nf-ole2-registerdragdrop)
- [Chrome Enterprise Connector Protocol — Google](https://chromeenterprise.google/policies/#OnTextEnteredEnterpriseConnector)
- [windows-rs COM implement macro — GitHub](https://github.com/microsoft/windows-rs)
