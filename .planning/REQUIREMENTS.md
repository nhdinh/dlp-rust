# REQUIREMENTS.md — v0.6.0 Endpoint Hardening

**Milestone:** v0.6.0  
**Status:** Active  
**Created:** 2026-04-22  

---

## Milestone Requirements

### Application-Aware DLP (SEED-001)

- [ ] **APP-01**: Agent captures destination process image path and publisher at paste time — `GetForegroundWindow` → `GetWindowThreadProcessId` → `QueryFullProcessImageNameW` in `dlp-user-ui` (user session only)
- [ ] **APP-02**: Agent captures source process identity at clipboard-change time — `GetClipboardOwner` called synchronously inside `WM_CLIPBOARDUPDATE` handler before source window closes
- [x] **APP-03**: Evaluator enforces allow/deny decisions based on `source_application` and `destination_application` ABAC attributes — `AbacContext` gains both fields; `PolicyStore::evaluate` honors them
- [ ] **APP-04**: Admin can author app-identity conditions in TUI using a structured picker (publisher, image path, trust tier) — no raw JSON
- [ ] **APP-05**: Audit events include `source_application` and `destination_application` fields populated on clipboard block
- [ ] **APP-06**: Authenticode publisher extraction via `WinVerifyTrust` prevents renamed-binary bypass — result cached per process path, non-blocking (routed through `spawn_blocking`)

### Browser Boundary (SEED-002)

- [ ] **BRW-01**: `dlp-agent` registers as a Chrome Content Analysis agent — named-pipe server at `\\.\pipe\brcm_chrm_cas` with protobuf frame serialization; Chrome POSTs clipboard scan events to it
- [ ] **BRW-02**: Admin can manage the managed-origins list (trusted web domains) via TUI screen and admin API — DB-backed, hot-reload, same pattern as SIEM/alert config
- [ ] **BRW-03**: Paste from a managed/protected origin to an unmanaged origin is blocked; audit event emitted with `source_origin` and `destination_origin` fields

### USB Device Control (SEED-003)

- [ ] **USB-01**: Agent captures VID, PID, Serial Number, and device description on `DBT_DEVICEARRIVAL` via `SetupDiGetClassDevsW` / `SetupDiGetDeviceInstanceIdW`
- [ ] **USB-02**: Admin can register and deregister USB devices with a trust tier (`blocked` / `read_only` / `full_access`) via TUI screen and admin API (`GET/POST/DELETE /admin/device-registry`)
- [ ] **USB-03**: Agent enforces trust tier at I/O level: `blocked` denies all access; `read_only` allows reads and denies writes — trust tier cached in `RwLock<HashMap>` per device, invalidated on removal or registry update
- [ ] **USB-04**: User receives a toast notification on USB block containing the device name and policy explanation — runs in `dlp-user-ui` (user session), reuses `winrt-notification`

---

## Future Requirements (deferred)

- SEED-002 Path A: Native browser extension (Chrome/Edge Manifest V3) — full browser tab-level origin control; depends on Path B (BRW-01..03) being proven first
- APP-07: UWP app identity via AUMID (`IShellItem` / `GetApplicationUserModelId`) — deferred; sparse Rust docs, needs separate spike
- USB-05: Audit events include device identity fields (VID, PID, serial, description) on block — deferred to post-USB-03
- USB-06: Per-user device registry (owner_user column) — deferred; per-machine registry sufficient for v0.6.0
- POLICY-F4: TOML export format — blocked by `toml` crate incompatibility with `#[serde(tag)]` `PolicyCondition`
- POLICY-F5: Batch import endpoint — reduces cache invalidations on bulk import
- POLICY-F6: Typed `Decision` action field — eliminates silent `_ => DENY` fallback

---

## Out of Scope

- Mount-time USB blocking (requires kernel filter driver — out of scope per CLAUDE.md)
- Drag-and-drop interception — different Win32 API surface, separate feature
- macOS/Linux device control — Windows-only per project scope
- Browser extension build toolchain (Path A) — v0.6.0 ships Path B (Chrome Enterprise Connector) only
- Edge for Business / Purview integration — separate integration track
- Self-service device registration workflow (user-requests-IT approval) — IT-driven only in v0.6.0

---

## Traceability

| REQ-ID | Phase | Status |
|--------|-------|--------|
| APP-01 | Phase 25 | Pending |
| APP-02 | Phase 25 | Pending |
| APP-03 | Phase 26 | Complete |
| APP-04 | Phase 28 | Pending |
| APP-05 | Phase 25 | Pending |
| APP-06 | Phase 25 | Pending |
| BRW-01 | Phase 29 | Pending |
| BRW-02 | Phase 28 | Pending |
| BRW-03 | Phase 29 | Pending |
| USB-01 | Phase 23 | Pending |
| USB-02 | Phase 24 | Pending |
| USB-03 | Phase 26 | Pending |
| USB-04 | Phase 27 | Pending |
