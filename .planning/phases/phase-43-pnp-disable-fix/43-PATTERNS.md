# Phase 43: USB Enforcement Fix — PnP Disable Actually Works - Pattern Map

**Mapped:** 2026-05-07
**Files analyzed:** 12
**Analogs found:** 12 / 12

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-common/src/usb.rs` | utility | transform | `dlp-common/src/disk.rs` | role-match |
| `dlp-agent/src/device_controller.rs` | service | request-response | `dlp-agent/src/device_controller.rs` (self) | exact |
| `dlp-agent/src/detection/usb.rs` | component | event-driven | `dlp-agent/src/detection/usb.rs` (self) | exact |
| `dlp-agent/src/config.rs` | config | CRUD | `dlp-agent/src/config.rs` (self) | exact |
| `dlp-agent/src/server_client.rs` | service | request-response | `dlp-agent/src/server_client.rs` (self) | exact |
| `dlp-agent/src/service.rs` | service | event-driven | `dlp-agent/src/service.rs` (self) | exact |
| `dlp-server/src/db/mod.rs` | config | CRUD | `dlp-server/src/db/mod.rs` (self) | exact |
| `dlp-server/src/db/repositories/agent_config.rs` | repository | CRUD | `dlp-server/src/db/repositories/agent_config.rs` (self) | exact |
| `dlp-server/src/admin_api.rs` | controller | request-response | `dlp-server/src/admin_api.rs` (self) | exact |
| `dlp-admin-cli/src/app.rs` | component | request-response | `dlp-admin-cli/src/app.rs` (self) | exact |
| `dlp-admin-cli/src/screens/render.rs` | component | request-response | `dlp-admin-cli/src/screens/render.rs` (self) | exact |
| `dlp-admin-cli/src/screens/dispatch.rs` | component | request-response | `dlp-admin-cli/src/screens/dispatch.rs` (self) | exact |

## Pattern Assignments

### `dlp-common/src/usb.rs` (utility, transform)

**Analog:** `dlp-common/src/disk.rs` (lines 705-756)

**Imports pattern** (lines 10-23):
```rust
#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_IDW, CM_Get_Parent, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    SETUP_DI_REGISTRY_PROPERTY, SP_DEVINFO_DATA,
};
#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_Interface_PropertyW, CR_BUFFER_SMALL, CR_SUCCESS,
};
#[cfg(windows)]
use windows::Win32::Devices::Properties::{
    DEVPKEY_Device_InstanceId, DEVPROPTYPE, DEVPROP_TYPE_STRING,
};
```

**SetupDiGetDeviceInterfaceDetailW pattern** (disk.rs:705-756):
```rust
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

**Core pattern - exact path matching for `setupdi_description_for_device`**:
Refactor `setupdi_description_for_device` (usb.rs:109) to enumerate `GUID_DEVINTERFACE_USB_DEVICE` interfaces, call `SetupDiGetDeviceInterfaceDetailW` for each, compare the returned path directly to the incoming `dbcc_name`, and on match read `SPDRP_FRIENDLYNAME` / `SPDRP_DEVICEDESC`. Only fall back to VID+PID+serial matching when exact path match fails.

**Error handling pattern** (usb.rs:385-407):
```rust
#[derive(Debug)]
#[cfg(windows)]
pub enum UsbResolutionError {
    ConfigManager(u32),
    Win32(windows::core::Error),
}

#[cfg(windows)]
impl std::fmt::Display for UsbResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbResolutionError::ConfigManager(cr) => {
                write!(f, "Configuration Manager error: {cr:#010x}")
            }
            UsbResolutionError::Win32(e) => write!(f, "Win32 error: {e}"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for UsbResolutionError {}
```

---

### `dlp-agent/src/device_controller.rs` (service, request-response)

**Analog:** `dlp-agent/src/device_controller.rs` (self)

**Imports pattern** (lines 22-42):
```rust
use std::collections::HashMap;
use parking_lot::Mutex;
use tracing::{error, info, warn};

#[cfg(windows)]
use dlp_common::usb::{find_instance_id_by_vid_pid_serial, resolve_instance_id_from_dbcc_name};

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Disable_DevNode, CM_Enable_DevNode, CM_Locate_DevNodeW, CM_LOCATE_DEVNODE_NORMAL,
};
```

**Error type pattern** (lines 44-62):
```rust
#[derive(Debug, thiserror::Error)]
pub enum DeviceControllerError {
    #[error("invalid device instance ID encoding")]
    InvalidInstanceId,
    #[error("Configuration Manager error: {0:#010x}")]
    ConfigManager(u32),
    #[error("Win32 error: {0}")]
    Win32(#[from] windows::core::Error),
    #[error("security descriptor error: {0}")]
    SecurityDescriptor(String),
    #[error("failed to access volume: {0}")]
    VolumeAccess(String),
}
```

**Core PnP disable pattern** (lines 111-190):
```rust
pub fn disable_usb_device(
    &self,
    dbcc_name: &str,
    identity: &dlp_common::DeviceIdentity,
) -> Result<(), DeviceControllerError> {
    let instance_id = match resolve_instance_id_from_dbcc_name(dbcc_name) {
        Ok(id) => id,
        Err(e) => {
            warn!(...);
            match find_instance_id_by_vid_pid_serial(...) {
                Ok(id) => id,
                Err(e2) => {
                    error!(...);
                    return Err(Self::map_resolution_error(e2));
                }
            }
        }
    };

    let wide: Vec<u16> = instance_id.encode_utf16().chain(std::iter::once(0)).collect();
    let mut dev_inst: u32 = 0;
    let cr = unsafe {
        CM_Locate_DevNodeW(&mut dev_inst, windows::core::PCWSTR(wide.as_ptr()), CM_LOCATE_DEVNODE_NORMAL)
    };

    if cr.0 != 0 {
        const CR_NO_SUCH_DEVNODE: u32 = 0x0000000D;
        if cr.0 == CR_NO_SUCH_DEVNODE {
            warn!(...);
            return Ok(());
        }
        return Err(DeviceControllerError::ConfigManager(cr.0));
    }

    const CM_DISABLE_ABSOLUTE: u32 = 0x00000001;
    let cr = unsafe { CM_Disable_DevNode(dev_inst, CM_DISABLE_ABSOLUTE) };
    if cr.0 != 0 {
        return Err(DeviceControllerError::ConfigManager(cr.0));
    }
    info!(...);
    Ok(())
}
```

**Retry logic to add** (new pattern, no direct analog):
When `usb_blocked_failure_mode` is `"Retry then error"`, wrap the `CM_Disable_DevNode` call in a retry loop: 3 attempts with 100ms exponential backoff between attempts. Only return `Err` after all 3 attempts fail.

---

### `dlp-agent/src/detection/usb.rs` (component, event-driven)

**Analog:** `dlp-agent/src/detection/usb.rs` (self)

**Core enforcement pattern** (lines 660-782):
```rust
fn apply_blocked_enforcement(
    letter: char,
    identity: &DeviceIdentity,
    dbcc_name: &str,
    controller: &crate::device_controller::DeviceController,
    owner_sid: &Option<String>,
    owner_user: &Option<String>,
) -> Result<(), String> {
    // Layer 1: PnP disable (primary enforcement).
    let pnp_result = controller.disable_usb_device(dbcc_name, identity);
    let pnp_ok = pnp_result.is_ok();
    if let Err(ref e) = pnp_result {
        error!(...);
    }

    // Layer 2: DACL deny-all (defense-in-depth fallback — always attempt).
    let dacl_result = controller.set_volume_deny_all(letter);
    let dacl_ok = dacl_result.is_ok();
    if let Err(ref e) = dacl_result {
        error!(...);
    }

    log_blocked_outcome(letter, identity, pnp_ok, dacl_ok, owner_sid, owner_user, &pnp_result, &dacl_result)
}
```

**Failure mode decision pattern to add** (new):
Read `usb_blocked_failure_mode` from config (passed into `UsbDetector` or read from global config). Three modes:
- `"Hard error"`: Return `Err` when EITHER PnP disable OR DACL deny-all fails.
- `"Warning only"` (default): Return `Ok(())` if at least one layer succeeds (current behavior).
- `"Retry then error"`: Retry PnP disable up to 3 times with 100ms backoff, then apply "Hard error" semantics.

**Startup scan pattern** (lines 110-188):
```rust
pub fn scan_existing_usb_identities(&self) {
    let identities = enumerate_connected_usb_devices();
    // ... for each identity, reconcile with unmapped drives
    if let Err(e) = apply_tier_enforcement(letter, &identity, "") {
        warn!(drive = %letter, error = %e, "tier enforcement failed during startup scan");
    }
}
```

**Startup resolution mode to add** (new):
Read `usb_startup_resolution_mode` config. Two modes:
- `"Volume GUID resolution"`: Query volume GUID for each blocked drive, construct dbcc_name-like path, use `CM_Get_Device_Interface_PropertyW` primary resolution.
- `"VID/PID/serial fallback"` (default): Keep current `enumerate_connected_usb_devices()` + `find_instance_id_by_vid_pid_serial` fallback.

**(none) serial policy to add** (new):
Read `usb_none_serial_policy` config. Three modes:
- `"Always Blocked"` (default): Treat all `(none)` serial devices as Blocked tier regardless of registry.
- `"Port-based disambiguation"`: Use USB hub port number (deferred — complex Win32 API).
- `"Allow unregistered"`: Current behavior — fall through to unregistered audit-only path.

---

### `dlp-agent/src/config.rs` (config, CRUD)

**Analog:** `dlp-agent/src/config.rs` (self)

**Config struct extension pattern** (lines 113-197):
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub monitored_paths: Vec<String>,
    // ... existing fields ...
    #[serde(default)]
    pub ldap_config: Option<crate::server_client::LdapConfigPayload>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(skip)]
    pub machine_name: Option<String>,
}
```

**New fields to add** (following existing `#[serde(default)]` pattern):
```rust
/// USB enforcement failure mode (USB-09).
#[serde(default)]
pub usb_blocked_failure_mode: Option<String>,
/// USB startup scan resolution strategy (USB-07).
#[serde(default)]
pub usb_startup_resolution_mode: Option<String>,
/// Policy for USB devices without serial descriptors (USB-08).
#[serde(default)]
pub usb_none_serial_policy: Option<String>,
```

**Test pattern** (lines 541-553):
```rust
#[test]
fn test_agent_config_new_fields_deserialize() {
    let toml_str = "heartbeat_interval_secs = 60\noffline_cache_enabled = false\n";
    let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
    assert_eq!(config.heartbeat_interval_secs, Some(60u64));
    assert_eq!(config.offline_cache_enabled, Some(false));
}
```

---

### `dlp-agent/src/server_client.rs` (service, request-response)

**Analog:** `dlp-agent/src/server_client.rs` (self)

**Payload struct extension pattern** (lines 118-139):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    pub monitored_paths: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub offline_cache_enabled: bool,
    pub ldap_config: Option<LdapConfigPayload>,
    #[serde(default)]
    pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
}
```

**New fields to add** (following `#[serde(default)]` for backward compat):
```rust
/// USB enforcement failure mode (USB-09). Default: "Warning only".
#[serde(default)]
pub usb_blocked_failure_mode: String,
/// USB startup scan resolution strategy (USB-07). Default: "VID/PID/serial fallback".
#[serde(default)]
pub usb_startup_resolution_mode: String,
/// Policy for USB devices without serial descriptors (USB-08). Default: "Always Blocked".
#[serde(default)]
pub usb_none_serial_policy: String,
```

**Critical:** Mark all new fields with `#[serde(default)]` so older agents polling a newer server ignore unknown fields (Pitfall 4 from RESEARCH.md).

---

### `dlp-agent/src/service.rs` (service, event-driven)

**Analog:** `dlp-agent/src/service.rs` (self)

**Config diff/apply pattern** (lines 276-332):
```rust
fn apply_payload_to_config(
    cfg: &mut crate::config::AgentConfig,
    payload: &crate::server_client::AgentConfigPayload,
) -> (Vec<&'static str>, DiskMergeData) {
    let mut changed_fields: Vec<&'static str> = Vec::new();
    // ...
    if cfg.monitored_paths != payload.monitored_paths {
        changed_fields.push("monitored_paths");
        cfg.monitored_paths = payload.monitored_paths.clone();
    }
    // ... disk_allowlist with deferred merge
    (changed_fields, disk_merge_data)
}
```

**New diff fields to add** (simple string comparisons, no deferred merge needed):
```rust
if cfg.usb_blocked_failure_mode.as_deref() != Some(&payload.usb_blocked_failure_mode) {
    changed_fields.push("usb_blocked_failure_mode");
    cfg.usb_blocked_failure_mode = Some(payload.usb_blocked_failure_mode.clone());
}
if cfg.usb_startup_resolution_mode.as_deref() != Some(&payload.usb_startup_resolution_mode) {
    changed_fields.push("usb_startup_resolution_mode");
    cfg.usb_startup_resolution_mode = Some(payload.usb_startup_resolution_mode.clone());
}
if cfg.usb_none_serial_policy.as_deref() != Some(&payload.usb_none_serial_policy) {
    changed_fields.push("usb_none_serial_policy");
    cfg.usb_none_serial_policy = Some(payload.usb_none_serial_policy.clone());
}
```

**Lock-order invariant** (lines 255-261, 423-435):
Config mutex is acquired INSIDE `apply_payload_to_config`, then released BEFORE any `instance_id_map.write()` call. USB config fields are simple strings — no cross-lock dependencies needed.

---

### `dlp-server/src/db/mod.rs` (config, CRUD)

**Analog:** `dlp-server/src/db/mod.rs` (self)

**Table creation pattern** (lines 210-218):
```rust
CREATE TABLE IF NOT EXISTS global_agent_config (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    monitored_paths         TEXT NOT NULL DEFAULT '[]',
    excluded_paths          TEXT NOT NULL DEFAULT '[]',
    heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
    offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
    updated_at              TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO global_agent_config (id) VALUES (1);
```

**Migration pattern** (lines 271-303):
```rust
pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN excluded_paths TEXT NOT NULL DEFAULT '[]'",
        "excluded_paths",
        "global_agent_config",
    )?;
    // ...
}

fn run_alter(conn: &SqliteConn, sql: &str, column: &str, table: &str) -> anyhow::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains(&format!("duplicate column name: {column}")) => Ok(()),
        Err(e) => Err(e).context(format!("running migration: add {column} column to {table}")),
    }
}
```

**New columns to add** (via `run_alter` in `run_migrations`, NOT in `init_tables` — per D-11, add to existing table):
```rust
run_alter(
    conn,
    "ALTER TABLE global_agent_config ADD COLUMN usb_blocked_failure_mode TEXT NOT NULL DEFAULT 'Warning only'",
    "usb_blocked_failure_mode",
    "global_agent_config",
)?;
run_alter(
    conn,
    "ALTER TABLE global_agent_config ADD COLUMN usb_startup_resolution_mode TEXT NOT NULL DEFAULT 'VID/PID/serial fallback'",
    "usb_startup_resolution_mode",
    "global_agent_config",
)?;
run_alter(
    conn,
    "ALTER TABLE global_agent_config ADD COLUMN usb_none_serial_policy TEXT NOT NULL DEFAULT 'Always Blocked'",
    "usb_none_serial_policy",
    "global_agent_config",
)?;
```

**Pitfall avoidance:** Do NOT add these columns to `init_tables` `CREATE TABLE` — that would cause `run_alter` to see "duplicate column name" on fresh databases. The `run_alter` helper already swallows this error, but the cleaner pattern is: add columns via `run_alter` only, and let `init_tables` remain unchanged for existing deployments.

---

### `dlp-server/src/db/repositories/agent_config.rs` (repository, CRUD)

**Analog:** `dlp-server/src/db/repositories/agent_config.rs` (self) and `siem_config.rs`

**Row struct pattern** (lines 15-26):
```rust
#[derive(Debug, Clone)]
pub struct GlobalAgentConfigRow {
    pub monitored_paths: String,
    pub excluded_paths: String,
    pub heartbeat_interval_secs: i64,
    pub offline_cache_enabled: i64,
    pub updated_at: String,
}
```

**New fields to add**:
```rust
pub usb_blocked_failure_mode: String,
pub usb_startup_resolution_mode: String,
pub usb_none_serial_policy: String,
```

**Repository get pattern** (lines 60-78):
```rust
pub fn get_global(pool: &Pool) -> rusqlite::Result<GlobalAgentConfigRow> {
    let conn = pool.get().map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.query_row(
        "SELECT monitored_paths, excluded_paths, heartbeat_interval_secs, \
         offline_cache_enabled, updated_at \
         FROM global_agent_config WHERE id = 1",
        [],
        |row| {
            Ok(GlobalAgentConfigRow {
                monitored_paths: row.get(0)?,
                excluded_paths: row.get(1)?,
                heartbeat_interval_secs: row.get(2)?,
                offline_cache_enabled: row.get(3)?,
                updated_at: row.get(4)?,
            })
        },
    )
}
```

**Repository update pattern** (lines 91-110):
```rust
pub fn update_global(uow: &UnitOfWork<'_>, record: &GlobalAgentConfigRow) -> rusqlite::Result<()> {
    uow.tx.execute(
        "UPDATE global_agent_config SET \
         monitored_paths = ?1, excluded_paths = ?2, \
         heartbeat_interval_secs = ?3, \
         offline_cache_enabled = ?4, updated_at = ?5 \
         WHERE id = 1",
        params![
            record.monitored_paths,
            record.excluded_paths,
            record.heartbeat_interval_secs,
            record.offline_cache_enabled,
            record.updated_at,
        ],
    )?;
    Ok(())
}
```

---

### `dlp-server/src/admin_api.rs` (controller, request-response)

**Analog:** `dlp-server/src/admin_api.rs` (self)

**Payload struct pattern** (lines 268-283):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    pub monitored_paths: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub offline_cache_enabled: bool,
    pub ldap_config: Option<LdapConfigPayload>,
    #[serde(default)]
    pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
}
```

**New fields to add** (server-side mirror of agent payload):
```rust
#[serde(default = "default_usb_blocked_failure_mode")]
pub usb_blocked_failure_mode: String,
#[serde(default = "default_usb_startup_resolution_mode")]
pub usb_startup_resolution_mode: String,
#[serde(default = "default_usb_none_serial_policy")]
pub usb_none_serial_policy: String,
```
With default functions:
```rust
fn default_usb_blocked_failure_mode() -> String { "Warning only".to_string() }
fn default_usb_startup_resolution_mode() -> String { "VID/PID/serial fallback".to_string() }
fn default_usb_none_serial_policy() -> String { "Always Blocked".to_string() }
```

**Handler GET pattern** (lines 1533-1551):
```rust
async fn get_global_agent_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AgentConfigRepository::get_global(&pool).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AgentConfigPayload {
        monitored_paths: serde_json::from_str(&row.monitored_paths).unwrap_or_default(),
        excluded_paths: serde_json::from_str(&row.excluded_paths).unwrap_or_default(),
        heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs).unwrap_or(30),
        offline_cache_enabled: row.offline_cache_enabled != 0,
        disk_allowlist: Vec::new(),
    }))
}
```

**Handler PUT pattern** (lines 1562-1597):
```rust
async fn update_global_agent_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AgentConfigPayload>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    if payload.heartbeat_interval_secs < 10 {
        return Err(AppError::BadRequest("heartbeat_interval_secs must be >= 10".to_string()));
    }
    // ... build row, update via repository, return payload
}
```

**Agent-facing GET pattern** (lines 1404-1527):
The `get_agent_config_for_agent` handler must also include the new USB fields when building the `AgentConfigPayload` from the global row or override row.

---

### `dlp-admin-cli/src/app.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/app.rs` (self)

**Screen enum pattern** (lines 436-540):
```rust
#[derive(Debug, Clone)]
pub enum Screen {
    MainMenu { selected: usize },
    // ...
    SiemConfig {
        config: serde_json::Value,
        selected: usize,
        editing: bool,
        buffer: String,
    },
    AlertConfig {
        config: serde_json::Value,
        selected: usize,
        editing: bool,
        buffer: String,
    },
    LdapConfig {
        config: serde_json::Value,
        selected: usize,
        editing: bool,
        buffer: String,
    },
    // ...
}
```

**New screen variant to add**:
```rust
/// USB enforcement settings form.
///
/// Navigable list of 5 rows (3 picker fields + Save + Back).
/// Row 0: usb_blocked_failure_mode (picker: "Hard error", "Warning only", "Retry then error")
/// Row 1: usb_startup_resolution_mode (picker: "Volume GUID resolution", "VID/PID/serial fallback")
/// Row 2: usb_none_serial_policy (picker: "Always Blocked", "Port-based disambiguation", "Allow unregistered")
/// Row 3 = [ Save ], Row 4 = [ Back ].
UsbEnforcementConfig {
    config: serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: String,
},
```

---

### `dlp-admin-cli/src/screens/render.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/render.rs` (self)

**Screen dispatch pattern** (lines 33-283):
```rust
fn draw_screen(app: &App, frame: &mut Frame, area: Rect) {
    match &app.screen {
        Screen::MainMenu { selected } => { draw_menu(...); }
        Screen::SiemConfig { config, selected, editing, buffer } => {
            draw_siem_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::AlertConfig { config, selected, editing, buffer } => {
            draw_alert_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::LdapConfig { config, selected, editing, buffer } => {
            draw_ldap_config(frame, area, config, *selected, *editing, buffer);
        }
        // ...
    }
}
```

**Menu draw pattern** (used by all config screens):
```rust
fn draw_menu(frame: &mut Frame, area: Rect, title: &str, items: &[&str], selected: usize) {
    // ... ratatui List with Block::default().title(title).borders(Borders::ALL)
}
```

**New render arm to add**:
```rust
Screen::UsbEnforcementConfig { config, selected, editing, buffer } => {
    draw_usb_enforcement_config(frame, area, config, *selected, *editing, buffer);
}
```

**System menu extension** (lines 84-99):
```rust
Screen::SystemMenu { selected } => {
    draw_menu(
        frame, area, "System",
        &["Server Status", "Agent List", "SIEM Config", "Alert Config", "LDAP Config", "Back"],
        *selected,
    );
}
```
Add "USB Enforcement" at index 5, shift "Back" to index 6.

---

### `dlp-admin-cli/src/screens/dispatch.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/dispatch.rs` (self)

**Event dispatch pattern** (lines 30-58):
```rust
pub fn handle_event(app: &mut App, event: AppEvent) {
    let key = match event { /* ... */ };
    match &app.screen {
        Screen::MainMenu { .. } => handle_main_menu(app, key),
        Screen::SiemConfig { .. } => handle_siem_config(app, key),
        Screen::AlertConfig { .. } => handle_alert_config(app, key),
        Screen::LdapConfig { .. } => handle_ldap_config(app, key),
        // ...
    }
}
```

**Config screen handler pattern** (lines 993-1007):
```rust
fn handle_siem_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::SiemConfig { selected, editing, .. } => (*selected, *editing),
        _ => return,
    };
    if editing {
        handle_siem_config_editing(app, key, selected);
    } else {
        handle_siem_config_nav(app, key, selected);
    }
}
```

**Save action pattern** (lines 975-990):
```rust
fn action_save_siem_config(app: &mut App) {
    let config = match &app.screen {
        Screen::SiemConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client.put::<serde_json::Value, _>("admin/siem-config", &config),
    ) {
        Ok(_) => {
            app.set_status("SIEM config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 2 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}
```

**New handler to add**:
```rust
fn handle_usb_enforcement_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::UsbEnforcementConfig { selected, editing, .. } => (*selected, *editing),
        _ => return,
    };
    if editing {
        handle_usb_enforcement_editing(app, key, selected);
    } else {
        handle_usb_enforcement_nav(app, key, selected);
    }
}
```

**System menu navigation** (lines 199-222):
```rust
fn handle_system_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::SystemMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 6, key.code),
        KeyCode::Enter => match *selected {
            0 => action_server_status(app),
            1 => action_agent_list(app),
            2 => action_siem_config(app),
            3 => action_alert_config(app),
            4 => action_ldap_config(app),
            5 => app.screen = Screen::MainMenu { selected: 2 },
            _ => {}
        },
        // ...
    }
}
```
Add index 5 for USB Enforcement, shift Back to index 6, update `nav(selected, 7, key.code)`.

---

## Shared Patterns

### Authentication
**Source:** `dlp-server/src/admin_api.rs` (router setup)
**Apply to:** All new dlp-server admin API endpoints
All `/admin/*` routes are already behind authentication middleware in the `admin_router` function. No change needed for new endpoints.

### Error Handling
**Source:** `dlp-server/src/admin_api.rs` (AppError enum)
**Apply to:** All dlp-server handler modifications
```rust
pub enum AppError {
    Database(rusqlite::Error),
    BadRequest(String),
    Internal(anyhow::Error),
    // ...
}
```

### Config Diff/Apply Pipeline
**Source:** `dlp-agent/src/service.rs` (lines 396-499)
**Apply to:** Agent config polling for new USB fields
The existing `config_poll_loop` + `apply_payload_to_config` pattern handles all config updates. USB config fields are simple strings — no deferred merge needed. Add three `if` comparisons to `apply_payload_to_config` and the fields flow through the existing pipeline automatically.

### Single-Row SQLite Config Table
**Source:** `dlp-server/src/db/repositories/siem_config.rs`
**Apply to:** dlp-server repository and migration
All global operator settings use the single-row pattern with `CHECK (id = 1)` and `INSERT OR IGNORE INTO ... VALUES (1)`.

### TUI Config Screen Pattern
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` (SIEM/Alert/LDAP handlers)
**Apply to:** New USB Enforcement config screen
All config screens follow the same pattern:
1. `Screen::XxxConfig { config: serde_json::Value, selected: usize, editing: bool, buffer: String }`
2. `handle_xxx_config` splits on `editing` → `handle_xxx_editing` or `handle_xxx_nav`
3. `action_save_xxx_config` does `app.client.put("admin/xxx-config", &config)`
4. Esc returns to `SystemMenu` with appropriate `selected` index

### Serde Default for Backward Compatibility
**Source:** `dlp-agent/src/server_client.rs` (AgentConfigPayload)
**Apply to:** All new payload fields on both server and agent
```rust
#[serde(default)]
pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
```
This pattern ensures older agents/servers ignore unknown fields instead of failing deserialization.

### `#[cfg(windows)]` Gating
**Source:** `dlp-common/src/usb.rs`, `dlp-agent/src/device_controller.rs`
**Apply to:** All Win32 API calls
All Windows-only functions are gated behind `#[cfg(windows)]`. On non-Windows targets, public APIs return safe defaults (empty strings, empty vectors, `Ok(())`).

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| None | — | — | All files have strong analogs in the existing codebase |

---

## Metadata

**Analog search scope:**
- `dlp-common/src/` (usb.rs, disk.rs)
- `dlp-agent/src/` (device_controller.rs, detection/usb.rs, config.rs, server_client.rs, service.rs)
- `dlp-server/src/` (db/mod.rs, db/repositories/agent_config.rs, db/repositories/siem_config.rs, admin_api.rs)
- `dlp-admin-cli/src/` (app.rs, screens/render.rs, screens/dispatch.rs)

**Files scanned:** 12 primary analogs + supporting grep results
**Pattern extraction date:** 2026-05-07
