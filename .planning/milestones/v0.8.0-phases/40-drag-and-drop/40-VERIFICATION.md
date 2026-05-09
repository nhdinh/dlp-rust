---
phase: 40
status: verified
verified_at: "2026-05-07"
---

# Phase 40 Verification: Drag-and-Drop Enforcement

## Plans Completed

| Plan | Status | Evidence |
|------|--------|----------|
| 40-01 | Complete | Action::DRAG_DROP, Pipe3UiMsg::DragDropAlert, Win32_System_Ole feature, serde round-trip tests |
| 40-02 | Complete | Full app identity resolution pipeline (Win32 + UWP AUMID) ported to dlp-agent, 13 tests |
| 40-03 | Complete | DragDropEnforcer with WH_GETMESSAGE hook, ABAC evaluation, toast + audit on block, 14 tests |
| 40-04 | Complete | Service lifecycle wiring (install/uninstall), drag-drop audit app identity integration tests |

## Requirements Addressed

- **APP-08**: Agent intercepts drag-and-drop operations (WH_GETMESSAGE hook on WM_DROPFILES)
- **APP-08.1**: Source application identity resolved for both Win32 and UWP drag sources
- **APP-08.2**: ABAC policy evaluated before drop completes; denied drops blocked with toast notification
- **APP-08.3**: Audit events include source_application, destination_application, and action fields

## Acceptance Criteria Verification

### 40-01

- [x] `Action::DRAG_DROP` exists and serializes to `"DRAG_DROP"`
- [x] `Pipe3UiMsg::DragDropAlert` exists with all fields
- [x] `Win32_System_Ole` feature enabled in `dlp-agent/Cargo.toml`
- [x] All match arms covering `Action` and `Pipe3UiMsg` include new variants
- [x] Serde round-trip tests pass for both new variants

### 40-02

- [x] `AUTHENTICODE_CACHE` caches WinVerifyTrust results per image path
- [x] `hwnd_to_image_path()` resolves HWND to owning process image path
- [x] `resolve_app_identity()` populates `aumid`, `package_family_name`, `is_uwp` fields
- [x] `resolve_uwp_identity()` uses `GetApplicationUserModelId` via process handle
- [x] 13 unit tests pass (cache hit, UWP detection, publisher extraction, etc.)

### 40-03

- [x] `DragDropEnforcer` installs `WH_GETMESSAGE` hook on dedicated thread
- [x] `hook_procedure()` intercepts `WM_DROPFILES` and consumes blocked messages
- [x] `process_wm_dropfiles()` resolves source + destination `AppIdentity`
- [x] `evaluate_drag_drop()` builds `EvaluateRequest` with `Action::DRAG_DROP`
- [x] Blocked drops emit `AuditEvent` with `EventType::Block` and app identity fields
- [x] Toast sent via `Pipe2AgentMsg::Toast` on block
- [x] 14 unit tests pass (allow-by-default, deny untrusted, hook lifecycle)

### 40-04

- [x] `service.rs` calls `init_drag_drop_emit_context()` during startup
- [x] `service.rs` calls `install_drag_drop_hook()` after reporting RUNNING
- [x] `service.rs` calls `uninstall_drag_drop_hook()` during graceful shutdown
- [x] Drag-drop audit event includes `source_application` and `destination_application`
- [x] AGENT-UNKNOWN sentinel applied when app identity is missing

## Global Verification

- [x] `cargo check --all` passes
- [x] `cargo clippy --all -- -D warnings` passes
- [x] `cargo test -p dlp-agent --lib` passes (327 tests)
- [x] `cargo test -p dlp-common --lib` passes (131+ tests)

## Blockers

None.
