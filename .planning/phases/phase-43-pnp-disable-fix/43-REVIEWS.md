---
phase: 43
reviewers: [claude, opencode]
reviewed_at: 2026-05-07T00:00:00Z
plans_reviewed: [43-01-PLAN.md, 43-02-PLAN.md, 43-03-PLAN.md, 43-04-PLAN.md, 43-05-PLAN.md]
---

# Cross-AI Plan Review -- Phase 43

## Claude Review

### Plan 43-01: Exact Path Matching for SetupDi Description Lookup

**Summary:** Solid plan that correctly pivots `setupdi_description_for_device` from imprecise instance-ID reshaping to exact device interface path matching via `SetupDiGetDeviceInterfaceDetailW`. The fallback to VID+PID+serial preserves the startup scan path (D-09), and the proven pattern from `disk.rs:705-756` is appropriately reused.

**Strengths:**
- Correctly identifies the root cause of false-positive matches (Bluetooth vs SanDisk)
- Reuses the verified `SetupDiGetDeviceInterfaceDetailW` buffer sizing pattern from `disk.rs`
- Preserves backward-compatible fallback for startup scan where `dbcc_name` is unavailable
- Safety valve (`index > 1024`) prevents runaway enumeration loops

**Concerns:**
- **MEDIUM -- Test mock feasibility:** The "mocked SetupDi enumeration" test (Task 1, step 5b) is underspecified. Mocking `SetupDiGetDeviceInterfaceDetailW` requires either function interposition (complex on Windows) or a test-only trait injection that doesn't exist in the current codebase. The plan hints at "conditional compilation to inject a test mock" without detailing the injection mechanism. This test may need to be Windows-only integration or compile-time signature validation.
- **LOW -- Case sensitivity:** The plan mentions "case-insensitive comparison recommended" but doesn't explicitly specify the comparison implementation. Windows device paths can differ in case; `eq_ignore_ascii_case` or `to_lowercase()` should be mandated.
- **LOW -- Resource cleanup:** The plan correctly mentions `SetupDiDestroyDeviceInfoList(hdev)` but should also verify the buffer is dropped properly (the `vec![0u8; required_size as usize]` pattern is fine, but worth calling out).

**Suggestions:**
- Replace the mocked enumeration test with two simpler tests: (1) a Windows-only test that calls the function with a known-real path and asserts it doesn't crash/panic, and (2) a compile-time signature test on non-Windows. Full behavioral mocking is likely not worth the infrastructure cost.
- Explicitly mandate `device_path.eq_ignore_ascii_case(&returned_path)` or `to_lowercase()` comparison in the implementation.

---

### Plan 43-02: Server-Side Config Storage and Admin API

**Summary:** Well-structured plan that extends the existing single-row config table pattern with three new USB columns. Enum validation in the PUT handler addresses a key security concern, and the `run_alter` migration approach is idempotent and safe for existing deployments.

**Strengths:**
- Idempotent `run_alter` migration correctly handles both fresh and upgraded databases
- Enum value validation in `update_global_agent_config_handler` prevents invalid config injection (T-43-03)
- Adds fields to `AgentConfigOverrideRow` for future per-agent support without blocking current implementation
- `serde(default = "...")` with named functions provides clean backward compatibility

**Concerns:**
- **MEDIUM -- Incomplete override wiring:** The plan adds fields to `AgentConfigOverrideRow` and mentions updating `get_override`/`upsert_override`, but the agent-facing `get_agent_config_for_agent` handler (line ~1404) must implement the merge logic: "if override exists, use override values; otherwise fall back to global row values." The plan mentions this but doesn't show the actual code. If the existing handler already has a merge pattern, it needs explicit extension for the three new fields.
- **LOW -- Validation ordering:** The empty-string check followed by enum validation is redundant -- empty strings will fail the enum check anyway. The empty-string checks can be removed to simplify the handler.
- **LOW -- Default value drift risk:** The default values are defined in three places: (1) `run_alter` DEFAULT clauses, (2) `default_*()` functions in admin_api.rs, (3) agent-side `default_*()` functions in server_client.rs (plan 43-03). Any future change must update all three. Consider a shared constants crate or at least a cross-plan validation note.

**Suggestions:**
- In the `get_agent_config_for_agent` handler update, explicitly show the conditional merge logic for the three new fields.
- Remove redundant empty-string validation; the enum validation is sufficient.
- Add a comment block in each file referencing the other locations where defaults are defined, to prevent drift.

---

### Plan 43-03: Agent-Side Config Pipeline Wiring

**Summary:** Clean, minimal plan that wires the three USB config fields through the existing agent config pipeline. The diff/apply pattern in `service.rs` is correctly extended without introducing lock-order issues.

**Strengths:**
- `Option<String>` on `AgentConfig` (agent-side) vs `String` on `AgentConfigPayload` (server-side) is the correct separation -- the agent applies server values
- `#[serde(default = "...")]` on payload fields ensures backward compatibility with older servers
- No changes needed to `config_poll_loop` -- the existing log + persist pipeline handles new fields automatically
- Lock-order invariant (T-37-13) is respected -- USB fields need no deferred merge

**Concerns:**
- **LOW -- Config value logging:** The threat model (T-43-08) claims "logs field names only, never values," but `apply_payload_to_config` logs `info!(fields = ?changed_fields, ...)`. The `changed_fields` vector contains field names as `&'static str`, not values -- this is correct. However, verify that no debug-format logging of the full `AgentConfig` happens elsewhere after this change.
- **LOW -- None vs Some("") edge case:** The diff logic `cfg.usb_blocked_failure_mode.as_deref() != Some(&payload.usb_blocked_failure_mode)` will treat `None` vs `Some("")` as different and apply an empty string. The server-side validation prevents empty strings, so this shouldn't occur, but a defense-in-depth check on the agent side (skip apply if payload string is empty) would be safer.

**Suggestions:**
- Add an agent-side guard in `apply_payload_to_config`: skip applying USB fields if the payload value is empty, preserving the previous config value. This defends against a compromised or buggy server sending empty strings.

---

### Plan 43-04: Enforcement Behavior

**Summary:** The most complex plan in the phase, correctly implementing the three failure mode semantics, retry logic, and policy-aware tier resolution. The distinction between "Hard error" (both layers must succeed) and "Retry then error" (PnP only must succeed) is correctly captured per the cross-AI review consensus.

**Strengths:**
- Clear separation of retry logic into `disable_usb_device_with_retry` -- the primitive `disable_usb_device` remains unchanged
- "Retry then error" correctly checks only PnP success, not DACL (per D-01 / review consensus)
- Structured logging with `vid`, `pid`, `serial`, `drive`, `tier` spans provides excellent auditability
- `(none)` serial policy check happens before registry cache lookup, avoiding unnecessary work

**Concerns:**
- **HIGH -- Blocking sleep in retry loop:** `std::thread::sleep` in `disable_usb_device_with_retry` will block the calling thread. If this is called from an async context (e.g., within a tokio task), it blocks the async runtime. The plan should specify that this method must be called from `tokio::task::spawn_blocking` or document that the caller is responsible for offloading. The `dlp-agent` runs as a Windows service with both sync and async code paths -- verify which path calls this.
- **MEDIUM -- Config read on every enforcement call:** `get_usb_failure_mode()`, `get_none_serial_policy()`, and `get_startup_resolution_mode()` each acquire the global config mutex on every call. In `apply_blocked_enforcement`, `get_usb_failure_mode()` is called once per blocked device. In `resolve_tier_from_registry`, `get_none_serial_policy()` is called once per device resolution. This is likely acceptable for USB hot-plug rates, but if startup scan processes many devices, the repeated mutex acquisitions add up. Consider passing config by reference into these functions rather than reading the global on each call.
- **MEDIUM -- `with_config` helper not verified:** The plan adds `with_config` to `service.rs` if it doesn't exist, but doesn't verify whether this helper introduces any lock contention with the existing `CONFIG` static. The `CONFIG` is a `parking_lot::Mutex` inside a `OnceLock` -- read locks are fast, but the helper should be verified to not conflict with the write lock in `config_poll_loop`.
- **LOW -- Retry delay hardcoding:** The retry delay (100ms) and count (2 retries = 3 total attempts) are hardcoded. The config only controls whether retry mode is active, not the parameters. This is acceptable per D-01 but reduces flexibility.

**Suggestions:**
- Document the thread-blocking nature of `disable_usb_device_with_retry` and require it be called from a blocking thread if used in async contexts. Consider renaming to `disable_usb_device_with_retry_blocking` to make this explicit.
- Pass config values into `apply_blocked_enforcement` and `resolve_tier_from_registry` by parameter rather than reading globals inside them. This makes the functions more testable and avoids mutex churn.
- Consider making retry count and delay configurable in a future phase, but document the hardcoded values clearly.

---

### Plan 43-05: Admin TUI USB Enforcement Settings Screen

**Summary:** Straightforward TUI screen addition that follows the existing config screen pattern faithfully. The shared constants module (`usb_enforcement.rs`) is a good DRY improvement over prior screens.

**Strengths:**
- New `usb_enforcement.rs` constants module eliminates magic strings and index values across render.rs and dispatch.rs
- Picker-only input (no free text) prevents invalid values at the UI layer (T-43-12)
- Save sends full payload to existing `PUT /admin/agent-config` -- no new API endpoint needed
- Esc returns to SystemMenu with correct `selected: 5` index

**Concerns:**
- **MEDIUM -- Full config overwrite on save (T-43-13):** The save action sends the entire `config` JSON object (which was fetched from `GET /admin/agent-config`) to `PUT /admin/agent-config`. This is the existing pattern for all config screens, but it creates a TOCTOU risk: if another admin or process changes a different field (e.g., `heartbeat_interval_secs`) between load and save, the USB Enforcement screen will overwrite it with the stale value. The server-side validation rejects invalid enum values but doesn't reject stale data for other fields.
- **LOW -- Array padding in options:** `USB_ENFORCEMENT_OPTIONS[1]` (startup resolution) has only 2 valid values but is declared as `[&str; 3]` with an empty third element: `["Volume GUID resolution", "VID/PID/serial fallback", ""]`. The `.filter(|s| !s.is_empty())` handles this, but an enum or const slice approach would be cleaner.

**Suggestions:**
- Consider a "merge and save" approach where the TUI fetches fresh config before save, patches only the USB fields, then sends the merged payload. Alternatively, document this as a known limitation of the existing pattern.
- Replace `[[&str; 3]; 3]` with `[&[&str]; 3]` to avoid the empty-string padding hack: `USB_ENFORCEMENT_OPTIONS: &[&[&str]] = &[&["Hard error", "Warning only", "Retry then error"], &["Volume GUID resolution", "VID/PID/serial fallback"], ...]`.

---

### Cross-Cutting Issues (Claude)

1. **Plan 43-04 Depends on `with_config` -- Verify Existence:** Plan 43-04 assumes a `with_config` helper exists (or will be added) in `service.rs`. If this helper is being added as part of this plan, ensure it doesn't conflict with existing config access patterns. The plan should explicitly state whether `with_config` is new or already exists.

2. **Test Coverage Gaps:** The plans specify many new tests, but some are difficult to implement meaningfully:
   - `test_setupdi_description_exact_path_mocked` (43-01) -- mocking SetupDi is hard
   - `test_apply_blocked_enforcement_hard_error_mode` (43-04) -- requires mocking `DeviceController` and global config
   For 43-04 specifically, consider extracting the failure mode decision logic into a pure function that takes `failure_mode: &str, pnp_ok: bool, dacl_ok: bool` and returns `Result<(), String>`. This would be trivially unit-testable without mocking.

3. **Enum Value Consistency:** The string enum values ("Hard error", "Warning only", etc.) are defined in:
   - `run_alter` DEFAULT clauses (43-02)
   - Server `default_*()` functions (43-02)
   - Agent `default_*()` functions (43-03)
   - TUI `USB_ENFORCEMENT_OPTIONS` arrays (43-05)
   - Match arms in `apply_blocked_enforcement` (43-04)
   Any typo or inconsistency will cause runtime failures. **Strongly recommend** defining these as shared constants in `dlp-common` and importing them everywhere. At minimum, add a cross-plan verification step.

4. **Wave Dependencies:** The dependency graph is sound:
   - Wave 1: 43-01 (SetupDi) and 43-02 (server config) -- parallel, no interdependency
   - Wave 2: 43-03 (agent wiring) -- depends on 43-02 for server-side schema
   - Wave 3: 43-04 (enforcement) and 43-05 (TUI) -- parallel, both depend on 43-03
   However, 43-04 technically also depends on 43-01 because `setupdi_description_for_device` is used in the hot-plug path, and 43-01's exact matching may affect the `dbcc_name` resolution path that 43-04's retry logic exercises. The dependency graph doesn't capture this -- it should be noted as a soft dependency.

---

### Risk Assessment (Claude)

**Overall Risk: MEDIUM**

**Justification:**
- **LOW risk areas:** Database migration (idempotent `run_alter`), config pipeline wiring (proven pattern), TUI screen (straightforward pattern reuse)
- **MEDIUM risk areas:** Win32 API refactoring (43-01) -- exact path matching is correct in theory but subtle buffer sizing and case sensitivity issues could slip through; enforcement behavior (43-04) -- the retry logic's blocking sleep and config mutex access patterns need careful verification; full-config overwrite in TUI (43-05) -- existing pattern bug, not new
- **HIGH risk areas:** None individually, but the interaction between retry logic + failure mode + (none) serial policy creates a complex state space that is under-tested. The plans specify ~10 new tests but several depend on mocking Windows APIs or global state, which may not be feasible.

**Mitigation:**
- Extract the failure mode decision logic into a pure function for unit testing.
- Run integration tests on a real Windows machine with actual USB hardware after wave 3.
- Add a cross-plan enum value consistency check before execution.

---

## OpenCode Review

### Plan 43-01: Exact Path Matching for SetupDi Description Lookup

**Summary:** Sound refactoring of `setupdi_description_for_device` to eliminate false-positive matches. Follows the proven `disk.rs:705-756` pattern exactly. Fallback preserves VID+PID+serial for startup scan per D-09.

**Strengths:**
- Proven pattern reuse from `disk.rs` (`SetupDiGetDeviceInterfaceDetailW` buffer sizing, two-call pattern) -- already validated against real hardware
- `SP_DEVINFO_DATA` obtained from `SetupDiGetDeviceInterfaceDetailW` via `Some(&mut devinfo)` avoids a second enumeration pass -- efficient
- Fallback to VID+PID+serial when exact path fails (required for startup scan per D-09)
- Safety valve `index > 1024` in threat model prevents infinite enumeration loops

**Concerns:**
- **MEDIUM:** Case-insensitive path comparison is "recommended" but not implemented in the code listing. Windows `dbcc_name` paths from `WM_DEVICECHANGE` and `SetupDiGetDeviceInterfaceDetailW` may differ in casing (e.g., `USB#VID_0781` vs `USB#vid_0781`). Should use `eq_ignore_ascii_case` explicitly.
- **MEDIUM:** The mocked SetupDi test is inherently fragile -- mocking native FFI calls requires conditional compilation or link-time substitution. The plan acknowledges this but doesn't specify whether the test will actually run on CI (Windows-only) or be a compile-time check. If the mock requires test-only helper functions, these must NOT leak into release builds.
- **LOW:** The safety valve (`index > 1024`) appears only in the threat model but is not referenced in the task action code. Should be documented in the function body as a guard against runaway enumeration.

**Suggestions:**
1. Enforce `eq_ignore_ascii_case` in the code, not just a comment
2. Document the safety valve index cap explicitly in the function logic (e.g., `if index > 1024 { break; }`)
3. Clarify test strategy: compile-only `#[cfg(not(windows))]` + Windows-only integration test with real SetupDi, not a mock

---

### Plan 43-02: Server-Side Config Storage and Admin API

**Summary:** Clean extension of the existing SQLite config + admin API pattern. Uses `run_alter` migrations (idempotent), `#[serde(default)]` for backward compat, and enum validation in PUT handler. Properly adds override row fields for future per-agent support.

**Strengths:**
- `run_alter` migration with duplicate-column swallowing -- correct idempotency pattern
- Enum value validation in PUT handler (`USB_FAILURE_MODES.contains()`) prevents garbage from reaching the DB -- addresses T-43-03
- Override row fields added preemptively for future per-agent support without breaking existing code
- Serde defaults match the SQLite column defaults -- consistent

**Concerns:**
- **MEDIUM:** Partial update concern -- TUI fetches full config, modifies only USB fields, then PUTs the entire payload. If a different admin modified another field between GET and PUT, those changes are silently overwritten. This is a pre-existing design flaw in the config API (not introduced by this plan), but the plan could acknowledge it.
- **LOW:** The validation constants (`USB_FAILURE_MODES`, etc.) are defined inline in `admin_api.rs`, creating a DRY violation with the TUI constants in plan 43-05. Since they're in different binaries (server vs. admin-cli), this is acceptable -- but adding a comment cross-referencing the TUI constants would help future maintainers.
- **LOW:** The plan adds fields to `AgentConfigOverrideRow` but the `get_agent_config_for_agent` handler description says "if override exists, use override values; otherwise fall back to global row values" -- this requires the override table to have these columns even if per-agent override is never used. The migration only adds columns to `global_agent_config`, not `agent_config_overrides`. This is a gap: the override table schema is NOT migrated in the plan's Task 1.

**Suggestions:**
1. Add `run_alter` migrations for the `agent_config_overrides` table too, or explicitly document that the override path for USB fields is deferred
2. Add a note about the partial-update risk (pre-existing) for future API redesign

---

### Plan 43-03: Agent-Side Config Pipeline Wiring

**Summary:** Straightforward wiring of three `Option<String>` fields through the agent config pipeline. Follows existing patterns exactly -- no surprises.

**Strengths:**
- `#[serde(default)]` on `Option<String>` handles both missing and null JSON correctly
- `as_deref()` comparison pattern is idiomatic and correct for `Option<String>` vs `&str`
- No changes needed to `config_poll_loop` -- the integration point (`apply_payload_to_config`) is properly extended
- Default functions on `AgentConfigPayload` match server-side defaults -- no drift risk

**Concerns:**
- **MEDIUM:** The plan states "older agents ignore unknown fields; older servers trigger defaults" -- this is correct for the agent->server direction, but what about a NEW agent on an OLD server that doesn't have the DB columns yet? The server would serialize `AgentConfigPayload` without USB fields, the `#[serde(default)]` handles them... but the `apply_payload_to_config` diff would see `cfg.usb_blocked_failure_mode = None` and `payload.usb_blocked_failure_mode = "Warning only"` (from default), triggering a spurious config change. This is harmless but will log a "config updated" message on every poll cycle against an old server. Suggest a `None` guard: skip diff if payload value matches the hardcoded default.
- **LOW:** Test `test_agent_config_usb_fields_deserialize` parses TOML with `usb_blocked_failure_mode = "Hard error"` -- but TOML deserializes `Option<String>` via `#[serde(default)]` correctly. Good test coverage.

**Suggestions:**
1. Add a guard in `apply_payload_to_config`: if USB field in cfg is `None` and payload value equals the system default, skip the diff to avoid spurious "config changed" logs against older servers

---

### Plan 43-04: Enforcement Behavior

**Summary:** The core enforcement fixes -- retry logic, failure mode semantics, (none) serial policy, startup resolution mode. Well-structured with proper separation between PnP and DACL concerns. The "Retry then error" semantic correctly checks PnP-only (per cross-AI review consensus).

**Strengths:**
- `disable_usb_device_with_retry` is clean -- retains the original `disable_usb_device` as primitive, retry added as separate method
- "Retry then error" checks only `!pnp_ok` per review consensus -- DACL is correctly defense-in-depth
- Structured logging with proper fields (vid, pid, serial, drive, tier) follows project standards
- `with_config` helper is simple and reusable -- doesn't introduce new lock-ordering concerns
- Fallthrough for "Allow unregistered" to normal registry lookup is semantically correct

**Concerns:**
- **HIGH:** `std::thread::sleep(Duration::from_millis(retry_delay_ms))` inside `disable_usb_device_with_retry` blocks the calling thread. If `apply_blocked_enforcement` is called from a tokio async context (likely, since USB detection runs alongside the async config poll loop), this will block the entire worker thread for up to 300ms (3 retries x 100ms). This could starve other tasks. Should use `tokio::time::sleep` or document that the hot-plug path is intentionally synchronous (the USB arrival handler runs on a dedicated thread).
- **MEDIUM:** The "Volume GUID resolution" startup mode logs a warning and falls back -- but the admin selected this option in the TUI expecting it to work. The warning only appears once per startup scan, and the admin may never see it. Consider logging at WARN every config apply, or better, validate at config-set time that this mode is not yet implemented and reject it in the PUT handler (return `AppError::BadRequest`).
- **MEDIUM:** "Port-based disambiguation" for (none) serial policy is defined as an enum value but explicitly deferred. If an admin selects it, the code falls through to normal registry lookup (same as "Allow unregistered"). The deploy comment says "deferred (complex Win32 API)" -- this is fine, but the TUI should mark it as NOT IMPLEMENTED to avoid admin confusion.
- **LOW:** `get_usb_failure_mode()` returns `"Warning only"` on config unavailability. If the config mutex is poisoned or `OnceLock` isn't initialized, the system silently falls back to the weakest enforcement mode. Consider logging a warning on fallback.

**Suggestions:**
1. **CRITICAL:** Replace `std::thread::sleep` with a non-blocking alternative, or document that `disable_usb_device_with_retry` must only be called from a blocking context
2. Reject unimplemented startup modes in the server PUT handler (add "Volume GUID resolution" to a validation block that returns 400)
3. Either remove "Port-based disambiguation" from the picker or mark it "(not implemented)" in the display
4. Log a warning when returning the fallback default ("Warning only") due to config unavailability

---

### Plan 43-05: Admin TUI USB Enforcement Settings Screen

**Summary:** Clean TUI screen following the established SIEM/LDAP config patterns. Shared constants module (`usb_enforcement.rs`) properly addresses DRY. Picker cycling is correctly implemented.

**Strengths:**
- Shared constants module avoids the DRY violation that would come from duplicating field names and options across render.rs and dispatch.rs
- Picker cycling correctly filters empty strings from options (handles the `"Volume GUID resolution"` row having only 2 options in a 3-slot array)
- Save sends full payload to PUT endpoint -- consistent with other config screens
- SystemMenu integration correctly shifts Back from index 5 to index 6

**Concerns:**
- **MEDIUM:** The "Port-based disambiguation" picker value is included but explicitly marked as "deferred (complex Win32 API)" in the research doc. Admins who select it will see no behavioral change and no feedback. Suggest either: (a) exclude it from the picker, or (b) display a status message "Port-based disambiguation: NOT YET IMPLEMENTED" when selected.
- **MEDIUM:** The save handler uses `app.client.put::<serde_json::Value, _>("admin/agent-config", &payload)` which sends the ENTIRE payload (all fields from the GET response, not just USB fields). If the GET response included other fields the admin didn't mean to change, the PUT overwrites them. This is the existing TUI pattern across all config screens, but it's a pre-existing risk worth noting.
- **LOW:** `USB_ENFORCEMENT_OPTIONS` uses `[[&str; 3]; 3]` with empty strings for the 2-option row. The `filter(|s| !s.is_empty())` handles this correctly, but it's a subtle invariant. A `Vec<Vec<&str>>` would be more self-documenting.
- **LOW:** Hint text for the hint area at `inner.y + inner.height.saturating_sub(1)` may overlap with the last list item. The `inner` rect from the block doesn't include the border, so this should be safe, but worth verifying during implementation.

**Suggestions:**
1. Remove "Port-based disambiguation" from the picker options, or add a "(NOT IMPLEMENTED)" suffix in the display
2. Consider using `Vec<Vec<&str>>` for `USB_ENFORCEMENT_OPTIONS` to make the variable-length picker rows self-documenting

---

### Risk Assessment (OpenCode)

**Overall Risk: MEDIUM**

**Justification:** The plans are well-structured, follow established codebase patterns, and correctly address the core requirements (USB-07, USB-08, USB-09). The dependency ordering between waves is correct. However, the **HIGH concern** in Plan 43-04 (`std::thread::sleep` in an async context) is a genuine runtime risk that could cause task starvation or watchdog timeouts in the agent service. All other concerns are medium or low and relate to edge cases or incomplete features.

**Key Recommendations: Must-Fix**
1. **Plan 43-04:** Replace `thread::sleep` with tokio-compatible sleep, or explicitly document the threading model and add a blocking annotation
2. **Plan 43-04:** Reject unimplemented "Volume GUID resolution" mode at config-set time (server-side PUT validation)
3. **Plan 43-01:** Use `eq_ignore_ascii_case` explicitly for path comparison
4. **Plan 43-05:** Remove "Port-based disambiguation" from picker if not implemented, or mark it clearly

**Key Recommendations: Should-Fix**
5. **Plan 43-03:** Add `None` guard in `apply_payload_to_config` to avoid spurious "config changed" logs against older servers
6. **Plan 43-02:** Add migration for `agent_config_overrides` table, or explicitly document that per-agent USB override is deferred
7. **Plan 43-04:** Log a warning when falling back to default failure mode due to config unavailability

---

## Consensus Summary

### Agreed Strengths
- Both reviewers agree the plans are well-structured, follow established codebase patterns, and correctly address the three requirements (USB-07, USB-08, USB-09)
- Dependency ordering across 3 waves is sound
- `run_alter` migrations are idempotent and safe
- Enum validation in PUT handler prevents garbage config injection
- Shared constants module (`usb_enforcement.rs`) is a good DRY improvement
- Backward compatibility via `#[serde(default)]` is correctly applied
- "Retry then error" correctly checks PnP-only (not DACL) per review consensus

### Agreed Concerns (Highest Priority)
1. **HIGH -- Blocking sleep in retry loop (43-04):** Both reviewers flag `std::thread::sleep` in `disable_usb_device_with_retry` as a genuine runtime risk. If called from a tokio async context, it blocks the worker thread for up to 300ms. Must either use non-blocking sleep, document the blocking requirement, or rename the method to make the blocking nature explicit.
2. **MEDIUM -- Case-insensitive path comparison (43-01):** Both reviewers note the plan mentions case-insensitive comparison but doesn't mandate the implementation. Windows device paths can differ in casing.
3. **MEDIUM -- Mocked test feasibility (43-01):** Both reviewers question whether the mocked SetupDi enumeration test is practical. Suggest Windows-only integration test or compile-time signature validation instead.
4. **MEDIUM -- Incomplete override wiring (43-02):** The migration adds columns to `global_agent_config` but not to `agent_config_overrides`. The override path for USB fields needs either migration or explicit deferral documentation.
5. **MEDIUM -- Spurious config change logs (43-03):** New agent against old server will log "config updated" on every poll cycle because `None` vs default value triggers a diff. Suggest a `None` guard.
6. **MEDIUM -- Enum value consistency across plans:** String enum values are defined in 5+ locations (DB defaults, server defaults, agent defaults, TUI options, match arms). Any inconsistency causes runtime failures. Both reviewers recommend shared constants in `dlp-common`.
7. **MEDIUM -- Unimplemented options exposed in UI (43-04/43-05):** "Volume GUID resolution" and "Port-based disambiguation" are defined but not implemented. Both reviewers recommend either rejecting at config-set time or marking in the UI.

### Divergent Views
- **Claude** rates overall risk as MEDIUM with no individual HIGH concerns, but notes the interaction between retry logic + failure mode + (none) serial policy creates a complex under-tested state space.
- **OpenCode** rates overall risk as MEDIUM but explicitly elevates the `thread::sleep` concern to HIGH, calling it a "genuine runtime risk that could cause task starvation or watchdog timeouts."
- **Claude** suggests extracting failure mode decision logic into a pure function for testability; **OpenCode** focuses on fixing the blocking sleep directly.
- **Claude** flags the `with_config` helper's lock contention as a MEDIUM concern; **OpenCode** considers it simple and reusable with no new lock-ordering concerns.

---

## Action Items for Planner

1. **Address HIGH concern:** Document or fix the blocking sleep in `disable_usb_device_with_retry` (Plan 43-04)
2. **Address MEDIUM concerns:**
   - Mandate `eq_ignore_ascii_case` in Plan 43-01
   - Replace mocked SetupDi test with Windows-only integration test in Plan 43-01
   - Add `agent_config_overrides` migration or explicit deferral note in Plan 43-02
   - Add `None` guard in `apply_payload_to_config` in Plan 43-03
   - Create shared enum constants in `dlp-common` and reference across all plans
   - Reject unimplemented modes at server PUT validation in Plan 43-04
   - Mark "Port-based disambiguation" as not implemented in TUI (Plan 43-05)
3. **Cross-plan verification:** Add a pre-execution step to verify enum value consistency across all 5 plans
