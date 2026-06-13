# Cross-AI Review: Phase 68.1 Plans

## Plan 01: Server ingest response + synthetic event relay

### Summary
This plan is well-scoped and directly maps to DEVICE-05 and TAMPER-03. It uses additive, backward-compatible JSON fields for the server-to-agent tamper signal and folds synthetic `ChainBreakDetected` events into the existing SIEM/syslog forwarding path rather than creating a separate routing pipeline. The division of work between `dlp-server` and `dlp-agent` is clear, and the test matrix covers the key response cases.

### Strengths
- Additive `#[serde(default)]` fields minimize deployment-order risk between server and agents.
- Appending synthetic events to the relay/syslog lists before spawning background tasks keeps the forwarding path unified and auditable.
- Threat model correctly identifies tampering, information disclosure, DoS, and spoofing concerns.
- Unit tests cover the three critical server-response cases (no break, break for this agent, break for another agent).

### Concerns
- **MEDIUM**: `tamper_detected_for_agent: Option<String>` is an awkward contract. The agent already knows its own identity, so returning its ID forces an unnecessary comparison. A `bool` (`tamper_detected`) is simpler and less error-prone. If the intent is to return an opaque reason/agent ID, the field name should make that explicit.
- **MEDIUM**: The plan does not explicitly state that synthetic `ChainBreakDetected` events must be persisted to the audit store before they are relayed. If the refactored `spawn_blocking` returns a `Vec<AuditEvent>` that is only forwarded, the audit trail could omit the synthetic event. Ensure persistence happens first, then forwarding.
- **LOW**: The server struct is named `IngestEventsResponse` while the agent struct is `IngestResponse`; aligning names would reduce confusion.
- **LOW**: Tests are described only for SIEM relay reachability. Coverage should explicitly verify the encrypted syslog queue as well, since TAMPER-03 requires both destinations.

### Suggestions
- Rename the server response field to `tamper_detected: bool` or, if a string is truly required, use `affected_agent_id: Option<String>`.
- Add a task or assertion that synthetic events are written to the audit store before being added to `relay_events` and `syslog_events`.
- Add an integration test that asserts the same synthetic event reaches both SIEM and syslog queues.
- Consider returning `chain_break_count` only when `tamper_detected` is `true` to reduce the information-disclosure surface.

### Risk Assessment
**LOW-MEDIUM**. The core approach is sound, but the response-field ergonomics and the persistence-before-relay ordering need clarification to avoid a silent audit-trail gap.

---

## Plan 02: Agent health wiring

### Summary
This is a minimal, high-precision plan that removes hardcoded `DeviceHealthStatus::default()` values from ABAC `Subject` construction and replaces them with live `current_health()`. It correctly identifies the three injection points and includes a verification step to ensure no defaults remain. The performance and concurrency impact is negligible.

### Strengths
- Very small blast radius: three call sites and a grep verification.
- Reuses the existing `current_health()` abstraction, so no new state machine is introduced.
- Atomic load is O(1) and non-blocking, satisfying the DoS/performance threat model.
- Verification via grep prevents regressions.

### Concerns
- **MEDIUM**: The plan satisfies success criterion #3 (carry live health in `EvaluateRequest`), but it does not verify that any ABAC policies actually act on `DeviceHealthStatus::Tampered`. If no rules reference the health attribute, the change has no enforcement effect. The phase should either confirm existing policies use health or add a documented sample/default rule.
- **MEDIUM**: The behavior of `current_health()` during agent startup or before the first heartbeat is not discussed. If it can transiently return `Tampered`, legitimate operations could be denied. Verify that health transitions are deterministic and only changed by a confirmed chain break or by Phase 64 recovery logic.
- **LOW**: No tests are described for the ABAC `Subject` health value. Add unit tests asserting that `to_subject()`, `to_subject_with_ad()`, and the no-AD fallback all carry `current_health()`.

### Suggestions
- Add a task to verify or add ABAC policy rules that deny sensitive actions when health is `Tampered`; otherwise document that policy authoring is the operator's responsibility.
- Add unit tests for the three `Subject` construction paths that assert the health field equals `current_health()`.
- Document the startup/transient state of `current_health()` so future maintainers understand when `Tampered` can legitimately appear.

### Risk Assessment
**MEDIUM**. The code change is trivial, but the realized security value depends entirely on upstream ABAC policies and the correctness of the health state machine, both of which are assumed rather than verified here.

---

## Plan 03: Admin TUI Audit Integrity screen

### Summary
The UI plan is comprehensive and follows the established `BypassAlertList` pattern, giving the implementation a clear shape across screen, dispatch, render, client, and app layers. Key bindings, pagination, and filter support are all specified, and unit tests target the right interaction paths. However, the plan assumes the server-side `GET /admin/audit/integrity` endpoint already exists without verifying it, which is a blocking gap.

### Strengths
- Follows a proven pattern (`BypassAlertList`), promoting consistency and reuse.
- Covers the full TUI stack: screen module, app state, dispatch handlers, renderer, and API client.
- Unit tests target meaningful interactions: Esc routing, Enter-to-detail, and pagination.
- Threat model correctly notes that the screen is read-only and that pagination mitates DoS.

### Concerns
- **HIGH**: The plan does not include creating or verifying the `GET /admin/audit/integrity` server endpoint. If the endpoint is absent, the screen cannot function. The scope should explicitly include server-side endpoint implementation or a hard dependency/verification task confirming it exists.
- **MEDIUM**: "Update `SystemMenu` to 15 items" risks degrading the menu UX. There is no discussion of grouping, scrolling, or whether the existing widget handles 15 items cleanly.
- **MEDIUM**: The response schema for `/admin/audit/integrity` is not defined. Without knowing the fields (e.g., `agent_id`, `chain_status`, `break_count`, `last_verified_at`), the client and render tests may be shallow or misaligned with the server.
- **LOW**: `AuditIntegrityFilter` semantics are not specified; clarify whether filtering is server-side (query parameters) or client-side.
- **LOW**: Loading, error, and empty states are mentioned only as string constants; handlers should ensure these states are wired correctly.

### Suggestions
- Expand the plan's scope to include the server endpoint, or add a explicit prerequisite task to confirm the endpoint exists and returns the expected schema.
- Define the endpoint response type before writing the client/render code, and add a client deserialization test against a mocked JSON body.
- Verify the `SystemMenu` widget supports 15 items; if not, introduce grouping or a scrollable list.
- Document whether filtering is applied by the server or the TUI.

### Risk Assessment
**MEDIUM-HIGH**. The UI implementation is well-structured, but the missing endpoint dependency is a blocking risk that could leave the screen non-functional even after all listed tasks are complete.

---

## Overall Phase Observations

- **Dependency ordering**: Plan 01's server-side response changes should land before Plan 01's agent-side caller changes are validated end-to-end. Plan 03 cannot be considered complete until the server endpoint dependency is resolved.
- **End-to-end traceability**: Success criteria #1 requires a cross-component path (server detects break → response → agent calls `report_tamper_detected()` → health transition → `DeviceHealthChange` event). None of the plans include an end-to-end integration test for this full chain; adding one would significantly reduce regression risk.
- **Policy enforcement gap**: The phase closes the wiring gap for tamper detection, but the actual ABAC enforcement of a `Tampered` state depends on policies that are not explicitly addressed. Consider a follow-up task or acceptance criterion to validate that at least one default policy denies high-risk actions when health is `Tampered`.
