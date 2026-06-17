# Review Report: Phase 53.1 Close Gap ETW-03 (Post-Revision)

**Reviewer:** Codex CLI (o4-mini via autonomous review pipeline)  
**Scope reviewed:** `53.1-CONTEXT.md`, `53.1-RESEARCH.md`, `53.1-PATTERNS.md`, `53.1-VALIDATION.md`, `53.1-00-PLAN.md`, `53.1-01-PLAN.md`, `53.1-02-PLAN.md`, `53.1-03-PLAN.md`  
**Previous review:** REVIEWS.md v1 (3 HIGH, 6 MEDIUM, 2 LOW concerns)  
**Review focus:** Verify resolution of previous HIGH concerns, identify new issues, assess readiness for execution.

**Verdict:** All 3 previous HIGH concerns are resolved. The plans are now architecturally sound and ready for execution with minor LOW-severity polish items.

---

## Previous HIGH Concern Resolution

### REVIEW-H-01: Existing HookRequest Clients Will Break — RESOLVED

**Previous issue:** Plan 02 changed agent deserialization from `HookRequest` directly to `IpcEnvelope`, but the existing hook DLL/client helper still serialized raw `HookRequest` bytes. Normal classification frames would fail `bincode::deserialize::<IpcEnvelope>` and be dropped.

**Resolution verification:** Plan 02 Task 2 (lines 128-151) now explicitly requires a legacy fallback:
- Attempt `bincode::deserialize::<IpcEnvelope>(&frame)` first
- If Err, try `bincode::deserialize::<HookRequest>(&frame)` as legacy fallback
- Legacy `HookRequest` responses are serialized as raw `HookResponse` (NOT envelope-wrapped) for backward compatibility
- Test 3 in the task behavior explicitly mocks a legacy raw `HookRequest` frame and asserts fallback handling
- The success criteria (line 217-225) explicitly state "Legacy raw `HookRequest` frames are still handled (backward compatibility during transition)"

**Status:** Resolved. The protocol migration path is now explicit and safe.

---

### REVIEW-H-02: BypassAlert Uses a Helper That Waits for a Response — RESOLVED

**Previous issue:** Plan 03 said bypass alerts are fire-and-send but the current `send_raw_request` writes a frame and then reads a response. The agent's Plan 02 routes `BypassAlert` without writing a response, creating a deadlock risk.

**Resolution verification:** Plan 03 Task 1 (lines 73-96) adds a new `send_raw_oneway` helper:
- Connects to pipe, writes payload, closes handle immediately via `unsafe { CloseHandle(pipe) }`
- Explicitly "NOT call `read_frame` — this is the key difference from `send_raw_request`"
- Hardcoded 50ms connection timeout (no misleading read timeout parameter)
- Plan 03 Task 2 (lines 116-118) updates `emit_bypass_alert` to use `send_raw_oneway` instead of `send_raw_request`
- The threat model (T-53.1-07) explicitly mitigates: "send_raw_oneway does not wait for a response, avoiding deadlock with the agent"

**Status:** Resolved. The one-way helper eliminates the deadlock risk.

---

### REVIEW-H-03: Hook-Derived Alerts Are Planned With Empty Attribution and Routing Fields — RESOLVED

**Previous issue:** Plan 03 kept hook-emitted fields such as `agent_id`, `image_path`, `severity`, and `correlation_reason` empty, while Plan 02 said `submit_bypass_alert` must not enrich the alert. This left incomplete alerts for SIEM routing and deduplication.

**Resolution verification:** Plan 02 Task 1 (lines 84-115) now requires explicit agent-side enrichment in `submit_bypass_alert`:
- `alert.agent_id = self.agent_id.clone()` (the agent's own ID)
- `alert.severity = self.severity_for_alert(alert.reason, &alert.file_path)` (with default "crit" for HookOverwritten/PatchRaced)
- `alert.correlation_reason = format!("Hook self-reported: {:?}", alert.reason)` (descriptive text)
- `alert.image_path = self.get_image_path_for_pid(alert.pid).await` (best-effort PID-to-image lookup)
- The must_haves truth (line 25) explicitly states: "Hook-derived alerts are enriched by the agent with agent_id, severity, correlation_reason, and best-effort image_path from PID before batching"
- Test 5-8 in Task 1 behavior verify enrichment assertions
- The success criteria (line 221) state: "`BypassCorrelator::submit_bypass_alert` accepts a pre-constructed `BypassAlert`, enriches agent_id/severity/correlation_reason/image_path, and batches it without ETW correlation"

**Status:** Resolved. Hook-derived alerts are now enriched before batching.

---

## New Findings

### LOW Rust Idioms: `build_bypass_alert_envelope` Leaves Most Fields Empty

**Files:** `53.1-03-PLAN.md` lines 110-113

**Issue:** The pure helper constructs a `BypassAlert` with `agent_id=empty`, `image_path=empty`, `file_path=empty`, `operation=empty`, `severity=empty`, `correlation_reason=empty`. This is correct because the hook DLL cannot populate these fields — the agent enriches them. However, the plan does not document this design rationale inline.

**Why it matters:** A future maintainer may see the empty fields and think the helper is incomplete, potentially "fixing" it by adding enrichment logic to the hook DLL (which runs in an injected process and should not perform lookups).

**Suggestion:** Add a doc comment on `build_bypass_alert_envelope` explaining: "Hook DLL intentionally leaves agent-side fields empty; the agent's `submit_bypass_alert` enriches them. This keeps the hook DLL minimal and avoids PID lookups in an injected process."

---

### LOW Documentation: `VolumeClassQuery` Routing Test Is Vague

**Files:** `53.1-02-PLAN.md` lines 125-126; `53.1-VALIDATION.md` line 52

**Issue:** Plan 02 Task 2 behavior says "Mock a pipe with IpcPayloadV1::VolumeClassQuery — assert it is routed to the existing volume-class handler if implemented; if not, log at debug level and continue." The test does not specify what "routed to existing volume-class handler" means in practice — is there a handler function to call? A channel to send on? The validation map references `cargo test -p dlp-agent hook_ipc -- --test-threads=1` but does not name a specific test.

**Why it matters:** If `VolumeClassQuery` is not yet implemented in the agent, the test may pass vacuously (just checking that a debug log is emitted). If it IS implemented, the test needs to verify the actual routing path.

**Suggestion:** Add a pre-execution check in the task action: "Before writing the VolumeClassQuery test, search the agent codebase for an existing `handle_volume_class_query` or similar function. If found, verify the test calls it. If not found, document that the debug-log-and-continue path is the expected behavior."

---

### LOW Completeness: `get_image_path_for_pid` Helper Is Not Defined in Plan 02

**Files:** `53.1-02-PLAN.md` lines 103-104

**Issue:** The enrichment action references `self.get_image_path_for_pid(alert.pid).await` as a best-effort lookup, but this method is not defined in the plan. The bypass correlator may not already have this helper.

**Why it matters:** If the method does not exist, compilation will fail during execution. If it does exist, the plan should reference where it lives.

**Suggestion:** Add a pre-task note: "Verify `get_image_path_for_pid` exists on `BypassCorrelator` or add it as a private helper. If unavailable, use `String::new()` as fallback and log a warning."

---

### LOW Testability: `send_raw_oneway` Test Does Not Prove It Never Reads

**Files:** `53.1-03-PLAN.md` lines 76-80

**Issue:** The planned test for `send_raw_oneway` verifies it "connects to the pipe, writes the payload, and closes the handle without calling read_frame." However, proving a negative (that a function never calls something) is difficult in unit tests without mocking the Windows API or intercepting `read_frame` calls.

**Why it matters:** A regression could reintroduce a read call inside `send_raw_oneway` and the test might not catch it if the read happens to time out or return an error.

**Suggestion:** Use a mock pipe handle or a test spy that records all API calls. Alternatively, add a code review checklist item: "Verify `send_raw_oneway` contains no `read_frame` call before committing." The threat model already mitigates this at design time (T-53.1-07).

---

## Dimension Review

| Dimension | Assessment |
| --- | --- |
| Correctness | All previous protocol migration and deadlock concerns are resolved. Legacy fallback is explicit. One-way helper is clean. |
| Security | Agent enrichment ensures alerts have attribution before batching. Pipe ACL and typed deserialization remain appropriate. No new disclosure paths. |
| Completeness | All planned behaviors have corresponding tests. Minor gaps: `get_image_path_for_pid` helper existence, `VolumeClassQuery` test specificity. |
| Nyquist compliance | Wave 0 red-state semantics are now explicit and correct. Stubs are behind `#[cfg(test)]`. Validation map covers all review concerns. Validation commands use `rg` instead of `grep`. |
| Testability | Pure helper `build_bypass_alert_envelope` is directly testable. `send_raw_oneway` has a negative-test challenge but is mitigated by design. |
| Dependencies | No new packages. Channel semantics are now specified (`crossbeam_channel::unbounded()`). |
| Rust idioms | `spawn_blocking` is mentioned for the bypass channel consumer. Minor gap: blocking `recv` pattern is still used for consistency with existing ETW/process channels. |
| Integration | Highest-risk area is now well-managed: protocol compatibility, response/no-response contract, service wiring documented with TODO, volume-class handling has a clear fallback. |

---

## Recommended Remediation Order

1. **LOW:** Add doc comment on `build_bypass_alert_envelope` explaining why hook-side fields are intentionally empty.
2. **LOW:** Verify `get_image_path_for_pid` exists on `BypassCorrelator` before execution, or add a fallback.
3. **LOW:** Clarify `VolumeClassQuery` test behavior — document whether a handler exists or the debug-log path is expected.
4. **LOW:** Add code review checklist for `send_raw_oneway` to ensure no `read_frame` call is introduced.

---

## Severity Summary

| Severity | Count | Notes |
| --- | ---:|:--- |
| HIGH | 0 | All 3 previous HIGH concerns (H-01, H-02, H-03) are fully resolved. |
| MEDIUM | 0 | All 6 previous MEDIUM concerns are resolved. |
| LOW | 4 | Documentation clarity, helper existence verification, test specificity, negative-test challenge. |

---

## Overall Recommendation

**Approve for execution.** The revised plans correctly address all three previous HIGH blockers:

1. **Protocol migration** is safe: the agent tries `IpcEnvelope` first, then falls back to legacy `HookRequest`.
2. **Deadlock risk** is eliminated: `send_raw_oneway` writes and closes without reading a response.
3. **Alert attribution** is complete: the agent enriches hook-derived alerts with `agent_id`, `severity`, `correlation_reason`, and best-effort `image_path` before batching.

The 4 remaining LOW items are polish and documentation improvements that can be addressed during execution or in a quick pre-execution pass. They do not block implementation.

The Nyquist compliance is solid: Wave 0 has explicit red-state semantics, all tasks have automated verification, and the validation map covers every review concern. The phase is well-bounded and ready to execute.
