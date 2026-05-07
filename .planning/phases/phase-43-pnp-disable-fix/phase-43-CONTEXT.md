# Phase 43: USB Enforcement Fix — PnP Disable Actually Works - Context

**Gathered:** 2026-05-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix `DeviceController::disable_usb_device` to use real CM instance IDs resolved via SetupDi; surface hard failures when enforcement fails. Covers USB-07 (CM instance ID resolution), USB-08 (description matching fix), and USB-09 (hard failure surfacing).

Phase 43 closes the enforcement gap identified in the debug session `usb-deny-logged-but-write-succeeds.md`: the agent was emitting audit BLOCK events but writes were still succeeding because the PnP disable path was silently failing, leaving only the audit-only `notify`-based file watcher as enforcement.

</domain>

<decisions>
## Implementation Decisions

### Hard Failure Semantics (USB-09)
- **D-01:** Runtime-configurable failure mode for Blocked-tier enforcement. Three options stored in operator config (SQLite):
  - `Hard error` — Return Err when EITHER PnP disable OR DACL deny-all fails
  - `Warning only` (default) — Current behavior: return Ok if at least one layer succeeds
  - `Retry then error` — Retry PnP disable up to 3 times with 100ms backoff, then fail hard if PnP STILL fails. DACL is defense-in-depth, NOT a substitute for PnP success.
- **D-02:** The config key is `usb_blocked_failure_mode` (string enum). Default: `"Warning only"`.
- **D-03:** Admin sets this via dlp-server admin API (`POST /admin/config`) and TUI. Agent polls the config on its normal refresh interval.

### Startup Scan Resolution
- **D-04:** Runtime-configurable startup scan strategy. Two options stored in operator config:
  - `Volume GUID resolution` — Query volume GUID for each blocked drive, construct dbcc_name-like path, use `CM_Get_Device_Interface_PropertyW` primary resolution
  - `VID/PID/serial fallback` (default) — Keep current `enumerate_connected_usb_devices()` + `find_instance_id_by_vid_pid_serial` fallback
- **D-05:** The config key is `usb_startup_resolution_mode` (string enum). Default: `"VID/PID/serial fallback"`.

### (none) Serial Handling
- **D-06:** Runtime-configurable policy for devices without serial descriptors. Three options stored in operator config:
  - `Always Blocked` (default) — Treat all `(none)` serial devices as Blocked tier regardless of registry
  - `Port-based disambiguation` — Use USB hub port number to distinguish identical VID+PID devices
  - `Allow unregistered` — Current behavior: fall through to unregistered audit-only path
- **D-07:** The config key is `usb_none_serial_policy` (string enum). Default: `"Always Blocked"`.

### Description Matching Precision (USB-08)
- **D-08:** Hot-plug path: use exact device interface path (`dbcc_name`) for `setupdi_description_for_device` matching instead of reshaping instance ID to parse VID/PID/serial.
- **D-09:** Startup scan path: keep existing VID+PID+serial fallback since no `dbcc_name` is available.
- **D-10:** Refactor `setupdi_description_for_device` to accept the full device interface path and match SetupDi entries by their actual interface path. Only fall back to VID+PID+serial matching when the exact path match fails.

### Admin Config Wire-Up
- **D-11:** All three runtime-configurable options (`usb_blocked_failure_mode`, `usb_startup_resolution_mode`, `usb_none_serial_policy`) are stored in the existing SQLite operator config table (same pattern as SIEM config, alert routing config, agent config).
- **D-12:** Admin TUI gets a new "USB Enforcement Settings" screen (or adds to existing System Config screen) with three picker fields.
- **D-13:** Agent reads these configs from its normal server poll and passes them to `DeviceController` / `UsbDetector` at enforcement time.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Debug Sessions
- `.planning/debug/usb-deny-logged-but-write-succeeds.md` — Root cause: notify-based watcher is audit-only, cannot block I/O. PnP disable was the intended real enforcement but was silently failing.
- `.planning/debug/usb-not-triggering-enforcement.md` — Prior fix: HWND thread-affinity violation in device watcher.

### Requirements
- `.planning/REQUIREMENTS.md` — USB-07, USB-08, USB-09 requirements

### Existing Code
- `dlp-agent/src/device_controller.rs` — `DeviceController` with `disable_usb_device`, `enable_usb_device`, `set_volume_readonly`, `set_volume_deny_all`, `restore_volume_acl`
- `dlp-agent/src/detection/usb.rs` — `UsbDetector`, `apply_tier_enforcement`, `apply_blocked_enforcement`, startup scan, arrival/removal handlers
- `dlp-common/src/usb.rs` — `parse_usb_device_path`, `setupdi_description_for_device`, `resolve_instance_id_from_dbcc_name`, `find_instance_id_by_vid_pid_serial`, `enumerate_connected_usb_devices`

### State & Project
- `.planning/STATE.md` — Prior decisions, including Phase 38.2 enforcement scope and tier-change semantics
- `.planning/PROJECT.md` — Architecture, tech stack, key design decisions

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DeviceController` (dlp-agent/src/device_controller.rs:72) — Already has disable/enable/DACL methods. Needs config injection for failure mode.
- `UsbDetector` (dlp-agent/src/detection/usb.rs:51) — Already has blocked_drives, device_identities, pending_identity. Needs config for (none) serial policy.
- Operator config pattern — `dlp-server/src/config_store.rs` or similar already stores SIEM/alert/agent config. Reuse for the three new USB config keys.
- Admin TUI config screens — Pattern exists for LDAP config (Phase 38.1), SIEM config, alert config. Reuse for USB enforcement settings.

### Established Patterns
- Config polling: agent polls server for config updates on regular interval. New USB configs flow through existing pipeline.
- `apply_tier_enforcement` (usb.rs:557) — Central dispatch for Blocked/ReadOnly/FullAccess. This is where failure mode config is read.
- `apply_blocked_enforcement` (usb.rs:660) — Where PnP disable + DACL deny-all are called. This is where retry logic and failure mode decisions are applied.
- `setupdi_description_for_device` (dlp-common/src/usb.rs:109) — Currently matches by reshaped instance ID. Needs exact path matching for hot-plug.

### Integration Points
- Agent startup: `scan_existing_usb_identities` (usb.rs:110) → reads `usb_startup_resolution_mode` config
- Hot-plug arrival: `on_usb_device_arrival` (usb.rs:843) → uses exact path matching for description
- Blocked enforcement: `apply_blocked_enforcement` (usb.rs:660) → reads `usb_blocked_failure_mode` config
- (none) serial: `find_instance_id_by_vid_pid_serial` (dlp-common/src/usb.rs:507) and `resolve_tier_from_registry` (usb.rs:594) → reads `usb_none_serial_policy` config
- Admin API: Add `GET/POST /admin/config/usb-enforcement` endpoints or extend existing config endpoints
- Admin TUI: Add USB enforcement settings to existing system config screen or new sub-screen

</code_context>

<specifics>
## Specific Ideas

- The debug session `usb-deny-logged-but-write-succeeds.md` identified that `notify`-based file watcher cannot block I/O. The real fix is making PnP disable work reliably.
- Three new SQLite config keys: `usb_blocked_failure_mode`, `usb_startup_resolution_mode`, `usb_none_serial_policy`.
- Exact path matching for `setupdi_description_for_device`: match SetupDi entries by their actual `SPDRP_DEVICEINTERFACE` path instead of reshaping instance ID.
- Retry logic: 3 attempts with 100ms exponential backoff for `CM_Disable_DevNode` when "Retry then error" mode is selected.
</specifics>

<deferred>
## Deferred Ideas

- Mount-time blocking (DISK-F1) — Phase 44
- Grace period / quarantine (DISK-F2) — Phase 45
- Replacing `notify`-based file watcher with actual I/O interception (minifilter or API hooking) — debug session recommended but deferred as out of scope for v0.8.1
- USB hub topology query for port-based disambiguation — complex Win32 API surface, deferred unless "Port-based disambiguation" policy is selected

</deferred>

---

*Phase: 43-USB Enforcement Fix — PnP Disable Actually Works*
*Context gathered: 2026-05-07*
