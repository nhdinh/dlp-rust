---
phase: 40-drag-and-drop
plan: 40-04
subsystem: dlp-agent
tags: [integration, service-lifecycle, audit, drag-drop]
dependency_graph:
  requires: [40-03]
  provides: []
  affects: [dlp-agent/service.rs, dlp-agent/audit_emitter.rs]
tech-stack:
  added: []
  patterns: [service startup/shutdown hook wiring, test capture sink]
key-files:
  created: []
  modified:
    - dlp-agent/src/service.rs
    - dlp-agent/src/audit_emitter.rs
decisions:
  - "Drag-drop hook wired directly in service.rs rather than InterceptionEngine — InterceptionEngine is Clone+file-monitor specific, drag-drop has independent thread lifecycle"
metrics:
  duration: "~20 minutes"
  completed_date: "2026-05-07"
---

# Phase 40 Plan 04: Integration Summary

**One-liner:** Wired DragDropEnforcer into the agent service lifecycle (install on startup, uninstall on shutdown) and added integration tests verifying drag-drop audit events carry app identity fields.

## What Was Built

### service.rs — Lifecycle Integration

- **Startup**: `init_drag_drop_emit_context(audit_ctx.clone())` called after clipboard emit context init; `install_drag_drop_hook(1)` called after service reports RUNNING. Failure is logged but non-fatal (warn + continue without drag-drop enforcement).
- **Shutdown**: `uninstall_drag_drop_hook()` called before file monitor stop in the graceful shutdown sequence.

### audit_emitter.rs — Integration Tests

Two tests added (327 total lib tests):

- `test_drag_drop_audit_event_has_app_identity` — Builds a drag-drop `AuditEvent` with `Action::DRAG_DROP`, populates source/destination `AppIdentity`, calls `emit_audit`, and verifies both identities survive emission with correct fields.
- `test_drag_drop_audit_event_applies_agent_unknown_when_missing` — Verifies AUDIT-05 sentinel behavior: when source/destination app identity is `None`, `emit_audit` replaces both with `AGENT-UNKNOWN`.

## Deviations from Plan

1. **No InterceptionEngine modifications** — The plan called for adding `drag_drop: Option<DragDropEnforcer>` to `InterceptionEngine`, but `InterceptionEngine` is `Clone` and dispatched to a blocking file-monitor thread. `DragDropEnforcer` has its own independent thread lifecycle with `start()`/`stop()`. Wiring directly in `service.rs` is cleaner and matches the existing pattern (clipboard listener, session monitor, etc. all managed directly by `run_service`).

2. **No UI changes needed** — The plan mentioned adding `Pipe3AgentMsg::DragDropAlert` handling in `dlp-user-ui/src/main.rs`, but `Pipe3UiMsg::DragDropAlert` is a UI→agent message (like `ClipboardAlert`). The drag-drop detection happens in the agent, not the UI. The agent already sends toast notifications via `Pipe2AgentMsg::Toast` (implemented in 40-03). No UI-side work was required.

3. **No new `emit_drag_drop_event()` function** — The plan called for adding a dedicated emitter function, but `drag_drop.rs::process_wm_dropfiles()` already builds and emits the `AuditEvent` directly via `DRAG_DROP_EMIT_CONTEXT` + `emit_audit()`. The existing `emit_audit()` helper with AGENT-UNKNOWN sentinel coverage (AUDIT-05) handles all cases.

## Self-Check: PASSED

- [x] `service.rs` calls `init_drag_drop_emit_context()` during startup
- [x] `service.rs` calls `install_drag_drop_hook()` after reporting RUNNING
- [x] `service.rs` calls `uninstall_drag_drop_hook()` during graceful shutdown
- [x] Drag-drop audit event includes `source_application` and `destination_application`
- [x] AGENT-UNKNOWN sentinel applied when app identity is missing
- [x] `cargo check --all` passes
- [x] `cargo clippy --all -- -D warnings` passes
- [x] `cargo test -p dlp-agent --lib` passes (327 tests)
