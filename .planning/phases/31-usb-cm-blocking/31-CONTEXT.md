# Phase 31: USB CM Device Blocking — Context

**Gathered:** 2026-04-29
**Status:** Ready for planning
**Source:** UAT gap closure from Phase 26 (Test 4 failed — USB I/O not blocked)

---

<domain>
## Phase Boundary

Phase 26's `UsbEnforcer` evaluates policy against USB devices but cannot prevent I/O because the `notify` crate is a passive watcher (observes changes AFTER they occur). This phase replaces the passive evaluation with active device control using Windows Configuration Manager APIs.

Two issues to fix:
1. **USB I/O not blocked** — `notify`-based interception cannot prevent file operations
2. **No toast notification** — `dlp-user-ui.exe` not found at service startup, so no UI connects to Pipe 2

</domain>

<decisions>
## Implementation Decisions

### USB Blocking Mechanism
- **Blocked**: `CM_Disable_DevNode` — disables device in Device Manager, all I/O stops immediately
- **ReadOnly**: Volume DACL modification — strip `WRITE`/`DELETE` ACEs, reads allowed
- **FullAccess**: `CM_Enable_DevNode` + restore original DACL

### Why CM_* over alternatives
- **Chosen**: CM_Disable_DevNode — native Windows API, no driver, reversible, stops ALL I/O
- **Rejected**: API Hooking (EDR flags, HVCI breaks it); Volume Lock (per-handle only); Group Policy (static, not dynamic); Reparse Points (fragile)

### Architecture
- Hook into existing `usb_wndproc` DBT_DEVICEARRIVAL / DBT_DEVICEREMOVECOMPLETE
- Device controller module: `dlp-agent/src/device_controller.rs`
- DACL backup stored in-memory (lost on restart — acceptable for DLP)

### Toast Notification Fix
- Add startup check in `service.rs` that logs `WARN` when `dlp-user-ui.exe` is not found
- Check both same-directory and `DLP_UI_BINARY` env var

### Prerequisites
- Agent runs as LocalSystem (already true)
- Link against `cfgmgr32.lib` and `advapi32.lib`

</decisions>

<canonical_refs>
## Canonical References

- `dlp-agent/src/detection/usb.rs` — USB notification window, `usb_wndproc`, `on_usb_device_arrival`
- `dlp-agent/src/usb_enforcer.rs` — `UsbEnforcer::check()`, trust tier evaluation
- `dlp-agent/src/interception/mod.rs` — `run_event_loop`, USB pre-ABAC check
- `dlp-agent/src/service.rs` — Service startup, UI binary resolution, `resolve_ui_binary()`
- `dlp-agent/src/ui_spawner.rs` — UI process spawning, `spawn_ui_in_session()`
- `.planning/phases/26-abac-enforcement-convergence/26-04-SUMMARY.md` — UsbEnforcer implementation
- `.planning/phases/26-abac-enforcement-convergence/26-UAT.md` — UAT gaps (Test 4)

</canonical_refs>

<specifics>
## Specific Requirements

### Device Controller API
```rust
pub fn disable_usb_device(vid: &str, pid: &str, serial: &str) -> Result<()>
pub fn enable_usb_device(vid: &str, pid: &str, serial: &str) -> Result<()>
pub fn set_volume_readonly(drive_letter: char) -> Result<()>
pub fn restore_volume_acl(drive_letter: char) -> Result<()>
```

### DACL Manipulation
- Query existing DACL via `GetFileSecurity`
- Remove `FILE_GENERIC_WRITE` / `DELETE` ACEs for `Everyone` / `Authenticated Users`
- Apply modified DACL via `SetFileSecurity`
- Store original DACL in-memory for restore

### Integration Points
- `usb_wndproc` on `DBT_DEVICEARRIVAL`: call device controller after trust tier lookup
- `usb_wndproc` on `DBT_DEVICEREMOVECOMPLETE`: restore device if needed
- `UsbEnforcer::check()`: remove `Decision::DENY` return for Blocked/ReadOnly (now handled at device level)

</specifics>

<deferred>
## Deferred Ideas

- Kernel minifilter driver (overkill for this use case)
- Persistent DACL backup across restarts (not needed — devices are rescanned on startup)
- Per-user USB blocking (out of scope — device-level is correct for DLP)

</deferred>
