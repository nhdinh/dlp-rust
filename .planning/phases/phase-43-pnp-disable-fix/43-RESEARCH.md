# Phase 43: USB Enforcement Fix — PnP Disable Actually Works - Research

**Researched:** 2026-05-07
**Domain:** Windows PnP / SetupDi / Configuration Manager APIs (Rust `windows` crate 0.62)
**Confidence:** HIGH

## Summary

Phase 43 fixes the critical enforcement gap where `DeviceController::disable_usb_device` silently fails because it passes an incorrect CM instance ID to `CM_Disable_DevNode`. The root cause (documented in `usb-deny-logged-but-write-succeeds.md`) is that the `notify`-based file watcher is audit-only — it cannot block I/O. Real enforcement must happen at the PnP level via `CM_Disable_DevNode`, but this requires resolving the actual CM instance ID from the device interface path (`dbcc_name`) using `CM_Get_Device_Interface_PropertyW` with `DEVPKEY_Device_InstanceId`.

This phase also fixes `setupdi_description_for_device` which currently matches devices by reshaping instance IDs and parsing VID/PID/serial, causing it to return the wrong device description (e.g., Bluetooth instead of SanDisk). The fix uses exact device interface path matching via `SetupDiGetDeviceInterfaceDetailW`.

Finally, the phase introduces three runtime-configurable operator settings (stored in SQLite, exposed via admin API/TUI, polled by agents) to control failure mode semantics, startup scan resolution, and `(none)` serial handling.

**Primary recommendation:** Implement exact-path SetupDi matching for description lookup, ensure `CM_Get_Device_Interface_PropertyW` is the primary instance ID resolution path, and wire the three new config keys through the existing server-agent config pipeline.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| CM instance ID resolution | Agent (Win32 API call) | — | `CM_Get_Device_Interface_PropertyW` runs on the agent using the `dbcc_name` from `WM_DEVICECHANGE` |
| SetupDi description matching | Agent (Win32 API call) | — | `SetupDiGetClassDevsW` + `SetupDiGetDeviceInterfaceDetailW` enumeration on agent |
| PnP disable/enable | Agent (Win32 API call) | — | `CM_Disable_DevNode` / `CM_Enable_DevNode` are agent-side CM API calls |
| Volume DACL manipulation | Agent (Win32 API call) | — | `SetFileSecurityW` on volume root, agent-side |
| Failure mode config storage | API/Backend (SQLite) | — | Single-row config table in dlp-server, same pattern as SIEM/alert config |
| Admin config UI | Admin CLI (ratatui TUI) | — | New screen variant in existing TUI dispatch pattern |
| Agent config polling | Agent (HTTP client) | — | Existing `config_poll_loop` in `service.rs` fetches from `/agent-config/{id}` |
| Config propagation | API/Backend (axum) | — | `GET/PUT /admin/agent-config` endpoints serve config to agents |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows` crate | 0.62 | Win32 API bindings (`CM_*`, `SetupDi*`, `DEVPKEY_*`) | Already in use across dlp-agent and dlp-common; `#[cfg(windows)]` gated |
| `parking_lot` | 0.12 | `Mutex`, `RwLock` for `UsbDetector` / `DeviceController` | Project standard; faster than std sync primitives |
| `tracing` | 0.1 | Structured logging with spans | Project standard per CLAUDE.md |
| `thiserror` | 1 | Custom error types (`DeviceControllerError`, `UsbResolutionError`) | Project standard |
| `serde` + `serde_json` | 1 | Config serialization, API payloads | Project standard |
| `rusqlite` | (via workspace) | SQLite config storage in dlp-server | Already used for all config tables |
| `axum` | 0.7 | Admin API endpoints | Project standard for dlp-server |
| `ratatui` | (via workspace) | Admin TUI screens | Project standard for dlp-admin-cli |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `tokio` | 1 (full) | Async runtime for config polling, API handlers | Already in use; no change needed |
| `reqwest` | 0.12 | Agent HTTP client for config fetch | Already in `dlp-agent` Cargo.toml |

### Installation
No new dependencies required. All libraries are already in the workspace.

**Version verification:** `windows` crate 0.62 is current in the codebase. No upgrade needed.

## Architecture Patterns

### System Architecture Diagram

```
Admin TUI (ratatui)          dlp-server (axum)              dlp-agent (Windows Service)
      |                              |                                |
      |  PUT /admin/agent-config     |                                |
      |----------------------------->|                                |
      |                              |  SQLite: global_agent_config   |
      |                              |  (single-row, id=1)            |
      |                              |                                |
      |                              |<-------------------------------|
      |                              |  GET /agent-config/{id}        |
      |                              |  (polls every N seconds)       |
      |                              |                                |
      |                              |  Returns: AgentConfigPayload   |
      |                              |  (with new usb_* fields)       |
      |                              |                                |
      |                              |----------------------------->  |
      |                              |                                |  config_poll_loop
      |                              |                                |  applies to AgentConfig
      |                              |                                |
      |                              |                                |  WM_DEVICECHANGE
      |                              |                                |  (dbcc_name arrives)
      |                              |                                |
      |                              |                                |  resolve_instance_id_from_dbcc_name
      |                              |                                |  -> CM_Get_Device_Interface_PropertyW
      |                              |                                |  -> DEVPKEY_Device_InstanceId
      |                              |                                |
      |                              |                                |  CM_Locate_DevNodeW(instance_id)
      |                              |                                |  CM_Disable_DevNode(dev_inst, ABSOLUTE)
      |                              |                                |
      |                              |                                |  [Fallback] SetupDi enumeration
      |                              |                                |  find_instance_id_by_vid_pid_serial
```

### Recommended Project Structure (no new crates)

```
dlp-common/src/usb.rs          — resolve_instance_id_from_dbcc_name, setupdi_description_for_device,
                                   find_instance_id_by_vid_pid_serial (modified)
dlp-agent/src/device_controller.rs — DeviceController::disable_usb_device, enable_usb_device (modified)
dlp-agent/src/detection/usb.rs     — UsbDetector, apply_tier_enforcement, apply_blocked_enforcement (modified)
dlp-agent/src/config.rs            — AgentConfig extended with usb_* fields
dlp-agent/src/server_client.rs     — AgentConfigPayload extended with usb_* fields
dlp-agent/src/service.rs           — apply_payload_to_config extended
dlp-server/src/db/mod.rs           — global_agent_config table schema extended (migration)
dlp-server/src/db/repositories/agent_config.rs — GlobalAgentConfigRow extended
dlp-server/src/admin_api.rs        — AgentConfigPayload extended, handlers updated
dlp-admin-cli/src/app.rs           — Screen enum extended (UsbEnforcementConfig)
dlp-admin-cli/src/screens/render.rs — draw_usb_enforcement_config
dlp-admin-cli/src/screens/dispatch.rs — handle_usb_enforcement_config
```

### Pattern 1: Exact Path Matching in SetupDi
**What:** Match a `dbcc_name` device interface path against SetupDi entries by comparing the actual interface path returned by `SetupDiGetDeviceInterfaceDetailW`, not by reshaping instance IDs.
**When to use:** Hot-plug path where `dbcc_name` is available from `WM_DEVICECHANGE`.
**Example:**
```rust
// Source: dlp-common/src/disk.rs (existing pattern in codebase)
// SetupDiGetDeviceInterfaceDetailW is already used in disk.rs:705-756

// Enumerate GUID_DEVINTERFACE_USB_DEVICE interfaces.
// For each interface, call SetupDiGetDeviceInterfaceDetailW to get the path.
// Compare the path directly to the incoming dbcc_name.
// On match, read SPDRP_FRIENDLYNAME / SPDRP_DEVICEDESC for description.
```

### Pattern 2: Single-Row SQLite Config Table
**What:** Store operator-configurable settings in a single-row table with `CHECK (id = 1)` and seed row `INSERT OR IGNORE`.
**When to use:** All global operator settings (SIEM, alert, LDAP, agent config, and now USB enforcement).
**Example:**
```rust
// Source: dlp-server/src/db/repositories/siem_config.rs (existing pattern)
CREATE TABLE IF NOT EXISTS usb_enforcement_config (
    id                           INTEGER PRIMARY KEY CHECK (id = 1),
    usb_blocked_failure_mode     TEXT NOT NULL DEFAULT 'Warning only',
    usb_startup_resolution_mode  TEXT NOT NULL DEFAULT 'VID/PID/serial fallback',
    usb_none_serial_policy       TEXT NOT NULL DEFAULT 'Always Blocked',
    updated_at                   TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO usb_enforcement_config (id) VALUES (1);
```

### Pattern 3: Agent Config Polling Pipeline
**What:** Server stores config in SQLite; admin updates via PUT `/admin/agent-config`; agent polls via GET `/agent-config/{id}`; agent applies diff in `config_poll_loop`.
**When to use:** Any runtime-configurable agent behavior.
**Example:**
```rust
// Source: dlp-agent/src/service.rs:396-499 (existing pattern)
// AgentConfigPayload carries new fields from server.
// apply_payload_to_config diffs and applies.
// Changed fields are written back to TOML for persistence.
```

### Anti-Patterns to Avoid
- **Reshaping instance IDs for matching:** The current `setupdi_description_for_device` reshapes `USB\VID_X&PID_Y\SERIAL` into `\\?\USB#VID_X&PID_Y#SERIAL#` to reuse `parse_usb_device_path`. This is imprecise — multiple devices can share VID+PID. Use exact interface path matching instead.
- **Silent failure in enforcement:** The current `apply_blocked_enforcement` returns `Ok(())` when one of PnP disable or DACL deny-all succeeds. Per USB-09, this must be configurable — and in "Hard error" mode, must return `Err` when either fails.
- **Adding columns to existing single-row tables via ALTER TABLE:** The `global_agent_config` table already exists. Adding USB columns via `run_alter` migration is the correct pattern (used for `excluded_paths` and `ldap_config`). Do NOT create a separate table unless the user explicitly requested it (D-11 says "stored in the existing SQLite operator config table").

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Win32 CM API bindings | Custom FFI | `windows` crate 0.62 | Already integrated; handles wide strings, newtypes, safety |
| SQLite config storage | Custom file format | Existing `global_agent_config` table + `AgentConfigRepository` | Pattern proven across SIEM, alert, LDAP configs |
| Config diff/apply logic | Custom merge | Existing `apply_payload_to_config` in `service.rs` | Already handles disk_allowlist merge with lock-order invariants |
| Admin TUI form screens | Custom widget | Existing `draw_siem_config` / `draw_alert_config` pattern | ratatui List + form field navigation is already implemented |
| HTTP config polling | Custom protocol | Existing `fetch_agent_config` + `config_poll_loop` | Agent already polls server on heartbeat interval |

**Key insight:** The existing config pipeline (server SQLite → admin API → agent poll → apply → TOML persist) is a mature pattern. The three new USB config keys should flow through this same pipeline, not a parallel one.

## Runtime State Inventory

This phase modifies code paths but does NOT rename or rebrand any runtime entities. No data migration is required.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | `device_registry` table stores `(vid, pid, serial, trust_tier)` — no instance IDs stored | None — instance ID is resolved at runtime |
| Live service config | dlp-server SQLite has `global_agent_config` single row; new columns added via `run_alter` migration | Migration: `ALTER TABLE global_agent_config ADD COLUMN ...` |
| OS-registered state | Windows Task Scheduler: dlp-agent service (name unchanged) | None |
| Secrets/env vars | No secrets reference USB config keys | None |
| Build artifacts | None affected | None |

**Nothing found in category:** Stored data — no instance IDs are persisted; they are resolved at enforcement time from the live PnP tree.

## Common Pitfalls

### Pitfall 1: `CM_Get_Device_Interface_PropertyW` Returns CR_NO_SUCH_VALUE
**What goes wrong:** The `dbcc_name` path from `WM_DEVICECHANGE` may not be registered as a device interface by the time the arrival handler runs, causing `CM_Get_Device_Interface_PropertyW` to fail.
**Why it happens:** Race condition between device driver installation and the arrival notification.
**How to avoid:** The existing fallback (`find_instance_id_by_vid_pid_serial` via SetupDi enumeration) handles this. Ensure the fallback is still available and logged.
**Warning signs:** Log line: "CM_Get_Device_Interface_PropertyW failed — falling back to SetupDi enumeration"

### Pitfall 2: `SetupDiGetDeviceInterfaceDetailW` Buffer Sizing
**What goes wrong:** The first call to `SetupDiGetDeviceInterfaceDetailW` with `None` buffer returns `required_size` in bytes, but `SP_DEVICE_INTERFACE_DETAIL_DATA_W` has a `cbSize` field that must be set correctly.
**Why it happens:** The `windows` crate's `SP_DEVICE_INTERFACE_DETAIL_DATA_W` has `cbSize: u32` followed by `DevicePath: [u16; 1]` (flexible array). The buffer must be sized to `required_size` bytes, and `cbSize` must be set to `size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>()`.
**How to avoid:** Follow the exact pattern in `dlp-common/src/disk.rs:705-756` which already does this correctly.
**Warning signs:** `ERROR_INSUFFICIENT_BUFFER` on second call, or garbage path data.

### Pitfall 3: Config Column Addition Idempotency
**What goes wrong:** Adding a new column to `global_agent_config` via `ALTER TABLE` in `run_migrations` fails on fresh databases because the column was already added in `init_tables`.
**Why it happens:** `init_tables` runs before `run_migrations`. If the `CREATE TABLE` already includes the new column, the `ALTER TABLE` will fail with "duplicate column name".
**How to avoid:** Use the existing `run_alter` helper in `dlp-server/src/db/mod.rs` which catches and ignores duplicate column errors. OR, add the columns to `init_tables` and skip the migration. The `run_alter` pattern is safer for existing deployments.
**Warning signs:** Migration panic on first startup after upgrade.

### Pitfall 4: AgentConfigPayload Backward Compatibility
**What goes wrong:** Older agents polling a newer server receive JSON with unknown `usb_*` fields and fail to deserialize.
**Why it happens:** `AgentConfigPayload` uses `serde(deserialize)` without `default` for new fields.
**How to avoid:** Mark all new fields with `#[serde(default)]` so older agents ignore them. The server must also handle older agents that do not send the new fields in PUT requests.
**Warning signs:** Agent config poll fails with deserialization error; agent falls back to defaults.

### Pitfall 5: Lock-Order Inversion in Config Apply
**What goes wrong:** `apply_payload_to_config` acquires the config mutex, then `merge_disk_allowlist_into_map` acquires `instance_id_map.write()`. If USB config changes also need to access `UsbDetector` locks, a deadlock could occur.
**Why it happens:** T-37-13 established that config mutex must be released BEFORE acquiring `instance_id_map.write()`. The same invariant applies to any new lock interactions.
**How to avoid:** USB config fields are simple string values — no deferred merge needed. The config mutex is sufficient. Do not introduce cross-lock dependencies.
**Warning signs:** Agent hangs during config poll; watchdog timeout.

## Code Examples

### Verified Pattern: SetupDiGetDeviceInterfaceDetailW (from disk.rs)
```rust
// Source: dlp-common/src/disk.rs:705-756 (existing verified pattern)
fn get_device_interface_path(
    hdev: HDEVINFO,
    interface_data: &SP_DEVICE_INTERFACE_DATA,
) -> Option<String> {
    let mut required: u32 = 0;
    let _ = unsafe {
        SetupDiGetDeviceInterfaceDetailW(hdev, interface_data, None, 0, Some(&mut required), None)
    };
    if required == 0 { return None; }

    let mut buf = vec![0u8; required as usize];
    let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
    unsafe { (*detail).cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32; }

    let ok = unsafe {
        SetupDiGetDeviceInterfaceDetailW(hdev, interface_data, Some(detail), required, None, None)
    };
    if ok.is_err() { return None; }

    let path_wide: Vec<u16> = unsafe {
        std::slice::from_raw_parts(
            (*detail).DevicePath.as_ptr(),
            (required as usize - std::mem::size_of::<u32>()) / 2,
        )
    }
    .iter()
    .copied()
    .take_while(|&w| w != 0)
    .collect();
    Some(String::from_utf16_lossy(&path_wide))
}
```

### Verified Pattern: CM_Get_Device_Interface_PropertyW (from usb.rs)
```rust
// Source: dlp-common/src/usb.rs:426-486 (existing verified pattern)
pub fn resolve_instance_id_from_dbcc_name(dbcc_name: &str) -> Result<String, UsbResolutionError> {
    if !dbcc_name.starts_with(r"\?\USB#") {
        return Err(UsbResolutionError::ConfigManager(0x00000013));
    }
    let mut wide_path: Vec<u16> = dbcc_name.encode_utf16().collect();
    wide_path.push(0);

    let mut required_size: u32 = 0;
    let mut property_type = DEVPROPTYPE(0);

    let cr = unsafe {
        CM_Get_Device_Interface_PropertyW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            &DEVPKEY_Device_InstanceId,
            &mut property_type,
            None,
            &mut required_size,
            0,
        )
    };
    if cr != CR_BUFFER_SMALL && cr != CR_SUCCESS {
        return Err(UsbResolutionError::ConfigManager(cr.0));
    }

    let mut buffer: Vec<u16> = vec![0; (required_size as usize / 2) + 1];
    let cr = unsafe {
        CM_Get_Device_Interface_PropertyW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            &DEVPKEY_Device_InstanceId,
            &mut property_type,
            Some(buffer.as_mut_ptr() as *mut u8),
            &mut required_size,
            0,
        )
    };
    if cr != CR_SUCCESS {
        return Err(UsbResolutionError::ConfigManager(cr.0));
    }
    if property_type != DEVPROP_TYPE_STRING {
        return Err(UsbResolutionError::ConfigManager(0x00000013));
    }

    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16(&buffer[..len])
        .map_err(|_e| UsbResolutionError::ConfigManager(0x0000000D))
}
```

### Verified Pattern: Single-Row Config Repository (from siem_config.rs)
```rust
// Source: dlp-server/src/db/repositories/siem_config.rs (existing verified pattern)
pub struct SiemConfigRepository;
impl SiemConfigRepository {
    pub fn get(pool: &Pool) -> rusqlite::Result<SiemConfigRow> {
        let conn = pool.get().map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT splunk_url, ... FROM siem_config WHERE id = 1",
            [],
            |row| { Ok(SiemConfigRow { ... }) }
        )
    }
    pub fn update(uow: &UnitOfWork<'_>, record: &SiemConfigRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "UPDATE siem_config SET ... WHERE id = 1",
            params![...]
        )?;
        Ok(())
    }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Reshaped instance ID matching for description | Exact `dbcc_name` path matching via `SetupDiGetDeviceInterfaceDetailW` | Phase 43 (this phase) | Eliminates false-positive device description matches |
| Silent fallback on PnP disable failure | Configurable hard failure / warning / retry | Phase 43 (this phase) | Operator can choose enforcement strictness |
| VID/PID/serial fallback only for startup scan | Primary `CM_Get_Device_Interface_PropertyW` + fallback | Phase 38.2 | More reliable instance ID resolution for hot-plug |

**Deprecated/outdated:**
- `setupdi_description_for_device` matching by reshaped instance ID: imprecise, causes Bluetooth/SanDisk confusion. Replace with exact path matching.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `global_agent_config` table is the correct place for USB enforcement settings (per D-11) | Standard Stack | If wrong, config would be in a separate table requiring new repository and API endpoints — more complex but not blocking |
| A2 | `windows` crate 0.62 includes `SetupDiGetDeviceInterfaceDetailW` and `SP_DEVICE_INTERFACE_DETAIL_DATA_W` | Code Examples | Verified: already imported in `dlp-common/src/disk.rs`. If missing, would need feature flag adjustment |
| A3 | `AgentConfigPayload` on the agent side can be extended with `#[serde(default)]` without breaking older servers | Common Pitfalls | If wrong, agent config poll deserialization fails. Mitigation: test with old server JSON |
| A4 | The admin TUI "System" menu has room for a 4th config screen (USB Enforcement Settings) | Architecture Patterns | If wrong, could add to existing screen or create submenu. Not blocking |

## Open Questions

1. **Should USB enforcement config be per-agent override or global-only?**
   - What we know: `global_agent_config` is global; `agent_config_overrides` is per-agent. D-11 says "stored in the existing SQLite operator config table (same pattern as SIEM config, alert routing config, agent config)". SIEM/alert are global-only. Agent config supports both global and per-agent override.
   - What's unclear: Whether per-agent USB policy variation is operationally useful.
   - Recommendation: Start with global-only (single `global_agent_config` column additions). Per-agent override can be added later if needed.

2. **How should "Retry then error" mode interact with the DACL fallback?**
   - What we know: D-01 says retry PnP disable up to 3 times with 100ms backoff, then fail hard. But DACL deny-all is always attempted as defense-in-depth.
   - What's unclear: If PnP disable fails after 3 retries but DACL succeeds, does "Retry then error" still return Err?
   - Recommendation: Yes — "Retry then error" means the PnP layer MUST succeed. DACL is defense-in-depth, not a substitute. If PnP fails after retries, return Err regardless of DACL outcome.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows SDK (CM_* APIs) | PnP disable/enable | ✓ | (system) | — |
| `windows` crate 0.62 | Win32 bindings | ✓ | 0.62 | — |
| SQLite | Config storage | ✓ | (bundled via rusqlite) | — |
| Rust toolchain | Compilation | ✓ | (edition 2021) | — |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None — see Wave 0 |
| Quick run command | `cargo test -p dlp-common usb` |
| Full suite command | `cargo test --all` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| USB-07 | `resolve_instance_id_from_dbcc_name` returns correct instance ID for a real USB path | unit (Windows-only) | `cargo test -p dlp-common test_resolve_instance_id` | ✅ existing |
| USB-07 | `disable_usb_device` calls `CM_Disable_DevNode` with resolved instance ID | integration (compile-time) | `cargo test -p dlp-agent test_disable_usb_device_signature` | ✅ existing |
| USB-08 | `setupdi_description_for_device` matches exact path, not reshaped ID | unit (Windows-only) | New test needed | ❌ Wave 0 |
| USB-09 | `apply_blocked_enforcement` returns Err when both PnP and DACL fail in "Hard error" mode | unit | New test needed | ❌ Wave 0 |
| USB-09 | Config enum serde round-trips correctly | unit | New test needed | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-common` + `cargo test -p dlp-agent`
- **Per wave merge:** `cargo test --all`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `dlp-common/src/usb.rs` — test for exact-path `setupdi_description_for_device` matching
- [ ] `dlp-agent/src/detection/usb.rs` — test for `apply_blocked_enforcement` failure mode semantics
- [ ] `dlp-agent/src/config.rs` — test for USB config field defaults and serde
- [ ] `dlp-server/src/admin_api.rs` — test for extended `AgentConfigPayload` serde with new fields

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | NTFS DACL + PnP disable = defense-in-depth |
| V5 Input Validation | yes | `dbcc_name` prefix validation in `resolve_instance_id_from_dbcc_name` (already implemented: `starts_with(r"\?\USB#")`) |
| V6 Cryptography | no | — |

### Known Threat Patterns for Windows PnP Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Race condition: device removed between resolution and disable | Denial of Service | `CR_NO_SUCH_DEVNODE` handled gracefully; returns `Ok(())` with warning |
| Malformed `dbcc_name` injection | Tampering | Prefix validation rejects non-USB paths before CM API call |
| TOCTOU on config change | Tampering | Config diff applied atomically inside mutex; no external state read after check |
| Silent enforcement failure | Elevation of Privilege | USB-09 hard failure mode surfaces errors to caller for audit |

## Sources

### Primary (HIGH confidence)
- `dlp-common/src/usb.rs` — `resolve_instance_id_from_dbcc_name`, `find_instance_id_by_vid_pid_serial`, `setupdi_description_for_device` (existing implementation)
- `dlp-agent/src/device_controller.rs` — `DeviceController::disable_usb_device`, `enable_usb_device` (existing implementation)
- `dlp-agent/src/detection/usb.rs` — `apply_tier_enforcement`, `apply_blocked_enforcement` (existing implementation)
- `dlp-common/src/disk.rs` — `get_device_interface_path` using `SetupDiGetDeviceInterfaceDetailW` (proven pattern)
- `dlp-server/src/db/repositories/siem_config.rs` — single-row config repository pattern
- `dlp-server/src/db/repositories/agent_config.rs` — `GlobalAgentConfigRow` / `AgentConfigRepository` pattern
- `dlp-agent/src/service.rs` — `config_poll_loop`, `apply_payload_to_config` pattern
- `dlp-admin-cli/src/screens/dispatch.rs` / `render.rs` — TUI screen dispatch and render patterns

### Secondary (MEDIUM confidence)
- `.planning/debug/usb-deny-logged-but-write-succeeds.md` — root cause analysis
- `.planning/phases/phase-43-pnp-disable-fix/phase-43-CONTEXT.md` — user decisions from discuss-phase
- Microsoft Learn: `CM_Get_Device_Interface_PropertyW` documentation (verified via training knowledge, not live fetch)

### Tertiary (LOW confidence)
- None — all claims verified against codebase.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in workspace, no new dependencies
- Architecture: HIGH — existing patterns (config pipeline, SetupDi enumeration, CM APIs) are well-established in codebase
- Pitfalls: HIGH — debug session and prior phases documented the exact failure modes

**Research date:** 2026-05-07
**Valid until:** 2026-06-07 (stable Windows APIs, low churn risk)
