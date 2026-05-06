# Phase 40: Drag-and-Drop Enforcement — Context

**Gathered:** 2026-05-07
**Status:** Ready for planning
**Source:** ROADMAP + existing research synthesis

<domain>
## Phase Boundary

Phase 40 implements OLE drag-and-drop interception in the DLP agent. When a user drags sensitive data from a protected app to an unmanaged app, the agent must:
1. Detect the drag-and-drop operation
2. Identify the source application (Win32 or UWP)
3. Evaluate ABAC policy before the drop completes
4. Block denied drops with a toast notification
5. Emit an audit event with source/destination application identity

**Out of scope:** Rich-text/image drag-and-drop (niche formats), per-app grace periods, Electron-specific detection.
</domain>

<decisions>
## Implementation Decisions

### Approach: Global message hook for WM_DROPFILES (primary) + IDropTarget hook (fallback)
- **Rationale:** `WM_DROPFILES` is simpler than full OLE COM interception. It covers file drag-and-drop. For text drag-and-drop, we hook `IDropTarget::Drop()` on the destination window.
- **Locked decision:** Use `SetWindowsHookEx` with `WH_GETMESSAGE` to intercept `WM_DROPFILES` and `WM_COPYDATA` globally.

### Source Application Resolution
- **Locked decision:** Use `GetWindowThreadProcessId` on the drag source window, then `OpenProcess` + `GetModuleFileNameExW` for Win32, or `GetApplicationUserModelId` for UWP (same pipeline as clipboard monitor, but in dlp-agent).
- The `resolve_app_identity` pattern from `dlp-user-ui` will be ported to `dlp-agent/src/detection/app_identity.rs`.

### Thread Safety
- **Critical:** Returning `DROPEFFECT_NONE` from `IDropTarget::Drop` on the wrong thread hangs Explorer.
- **Locked decision:** Evaluation runs synchronously on the calling thread (fast path: cache + ABAC evaluate is sub-millisecond). If async is needed, return `DROPEFFECT_COPY` immediately and block the actual drop via a separate mechanism.

### Audit Event Schema
- **Locked decision:** Reuse existing `AuditEvent` with `source_application` and `destination_application` fields. No new schema changes.
- Action type: `Action::DragDrop` (new variant in `dlp-common::abac::Action`).

### IPC Integration
- **Locked decision:** Add `Pipe3AgentMsg::DragDropAlert` variant for UI notifications. Reuse existing Pipe 3 infrastructure.

### Windows Crate
- **Locked decision:** dlp-agent already uses `windows` 0.62. Add `Win32_System_Ole` feature for `IDropTarget`, `RegisterDragDrop`, `DoDragDrop`, `RevokeDragDrop`.
</decisions>

<canonical_refs>
## Canonical References

- `.planning/REQUIREMENTS.md` — APP-08 requirements
- `.planning/research/SUMMARY.md` — v0.8.0 research summary
- `.planning/research/STACK.md` — Stack decisions for OLE drag-and-drop
- `.planning/research/PITFALLS.md` — Critical pitfalls (Explorer thread blocking)
- `dlp-user-ui/src/detection/app_identity.rs` — App identity resolution pattern to port
- `dlp-agent/src/interception/mod.rs` — InterceptionEngine event loop
- `dlp-agent/src/audit_emitter.rs` — Audit emission pipeline
- `dlp-common/src/abac.rs` — Action enum, ABAC types
</canonical_refs>

<specifics>
## Specific Ideas

### New Files
- `dlp-agent/src/interception/drag_drop.rs` — DragDropEnforcer module

### Modified Files
- `dlp-agent/src/interception/mod.rs` — Add drag_drop check to event loop
- `dlp-agent/Cargo.toml` — Add `Win32_System_Ole` feature
- `dlp-common/src/abac.rs` — Add `Action::DragDrop` variant
- `dlp-agent/src/ipc/messages.rs` — Add `Pipe3AgentMsg::DragDropAlert`
- `dlp-agent/src/detection/app_identity.rs` — Port resolve_app_identity from dlp-user-ui

### API Surface
- `DragDropEnforcer::new()` — Create enforcer with policy store reference
- `DragDropEnforcer::install_hook()` — Install global message hook
- `DragDropEnforcer::uninstall_hook()` — Remove hook
- `DragDropEnforcer::evaluate_drop(source_app, dest_app, data) -> Decision`
</specifics>

<deferred>
## Deferred Ideas

- Rich-text / image drag-and-drop formats (v0.9.0+)
- Per-app grace period for drag-and-drop (operational convenience)
- Source-side interception (hooking `DoDragDrop`) — harder, less value
</deferred>
