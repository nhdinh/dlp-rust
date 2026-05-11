# Phase 42: Audit Enrichment - App Identity Fields - Context

**Gathered:** 2026-05-07
**Status:** Ready for planning
**Mode:** Infrastructure (gap closure)

<domain>
## Phase Boundary

Close gaps in app identity fields across all interception paths. The AuditEvent schema already has the fields (source_application, destination_application, device_identity, source_origin, destination_origin). This phase ensures every audit emission point populates these fields where applicable, with AGENT-UNKNOWN as the fallback for unresolvable identity.

</domain>

<decisions>
## Implementation Decisions

### Gap Coverage
- **File interception**: source_application from process PID via GetModuleFileNameExW; destination_application from target path owner (or None for file writes)
- **USB interception**: device_identity already populated by Phase 26/27; verify it is present on all USB block events
- **Clipboard interception**: source_application and destination_application from SessionIdentityMap or drag-drop context; already partially done in Phase 40
- **Chrome clipboard**: source_origin and destination_origin already populated by Phase 41

### AGENT-UNKNOWN Fallback
- Missing source_application → AGENT-UNKNOWN sentinel (per AUDIT-05, Phase 38.3)
- Missing destination_application → AGENT-UNKNOWN sentinel
- Missing device_identity → None (not all events involve USB devices)

### Claude's Discretion
- Specific helper functions for audit enrichment are at Claude's discretion — follow existing patterns in audit_emitter.rs

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AuditEvent::with_source_application()`, `with_destination_application()` builder methods
- `dlp_common::endpoint::agent_unknown_app()` for the AGENT-UNKNOWN sentinel
- `audit_emitter::get_application_metadata(pid)` for Win32 process image path
- `SessionIdentityMap` for resolving interactive users per session
- `AppIdentity` struct with name, path, aumid fields

### Established Patterns
- Audit events are emitted via `emit_audit(&ctx, &mut event)` which fills agent_id, session_id, user_sid, user_name
- Builder pattern for AuditEvent: `.with_*()` methods add optional fields
- AGENT-UNKNOWN fallback is applied at emission time, not construction time

### Integration Points
- `interception/mod.rs` — file event loop emits audit events for file operations
- `interception/drag_drop.rs` — drag-and-drop events emit audit events
- `clipboard/listener.rs` — clipboard events emit audit events
- `detection/usb.rs` / `usb_enforcer.rs` — USB block events emit audit events
- `chrome/handler.rs` — Chrome clipboard block events emit audit events

</code_context>

<specifics>
## Specific Ideas

No specific requirements — follow existing audit enrichment patterns. Ensure every `AuditEvent::new()` call site that represents an interception event checks whether source_application/destination_application/device_identity should be populated.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
