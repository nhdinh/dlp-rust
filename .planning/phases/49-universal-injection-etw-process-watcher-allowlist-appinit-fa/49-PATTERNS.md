# Phase 49: Universal Injection — Pattern Map

**Mapped:** 2026-05-19
**Files analyzed:** 9
**Analogs found:** 9 / 9

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-agent/src/process_watcher.rs` | service | event-driven | `dlp-agent/src/service.rs` sync-client watcher thread | role-match |
| `dlp-agent/src/universal_injector.rs` | service | event-driven | `dlp-agent/src/service.rs` sync-client watcher loop | role-match |
| `dlp-agent/src/process_registry.rs` | model | state-machine | `dlp-agent/src/approval_cache.rs` | role-match |
| `dlp-agent/src/allowlist.rs` | utility | transform | `dlp-agent/src/detection/app_identity.rs` extract_publisher | role-match |
| `dlp-agent/src/appinit.rs` | utility | file-I/O | `dlp-agent/src/chrome/registry.rs` | partial-match |
| `dlp-agent/src/service.rs` | service | request-response | `dlp-agent/src/service.rs` run_loop_init | exact |
| `dlp-server/src/admin_api.rs` | controller | request-response | `dlp-server/src/admin_api.rs` policy CRUD | exact |
| `dlp-server/src/db/mod.rs` | config | CRUD | `dlp-server/src/db/mod.rs` existing tables | exact |
| `dlp-admin-cli/src/app.rs` | component | request-response | `dlp-admin-cli/src/screens/usb_enforcement.rs` | role-match |

## Pattern Assignments

### `dlp-agent/src/process_watcher.rs` (service, event-driven)

**Analog:** `dlp-agent/src/service.rs` lines 998-1090 (sync-client watcher thread)

**Imports pattern** (from service.rs context):
```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
```

**Thread spawn pattern** (lines 1020-1089):
```rust
let shutdown_flag = Arc::new(AtomicBool::new(false));
let flag_clone = Arc::clone(&shutdown_flag);

let handle = std::thread::Builder::new()
    .name("sync-client-watcher".into())
    .spawn(move || {
        info!("sync-client watcher thread started");
        loop {
            if flag_clone.load(Ordering::Relaxed) {
                info!("sync-client watcher: shutdown signal received — exiting");
                break;
            }
            // ... work ...
            std::thread::sleep(Duration::from_secs(30));
        }
    })
    .expect("failed to spawn sync-client watcher thread");
```

**Error handling pattern** (lines 1046-1078):
```rust
match watcher_injector.inject(pid) {
    Ok(()) => {
        info!(pid, exe, "sync-client watcher: hook injected successfully");
    }
    Err(e) => {
        warn!(pid, exe, error = %e, "sync-client watcher: injection failed");
    }
}
```

---

### `dlp-agent/src/universal_injector.rs` (service, event-driven)

**Analog:** `dlp-agent/src/service.rs` sync-client watcher loop + `dlp-agent/src/hook_injector.rs`

**Injection orchestration pattern** (from service.rs lines 1037-1078):
```rust
let pids = crate::cloud_enforcer::enumerate_sync_client_pids();
for (pid, exe) in pids {
    match crate::hook_injector::HookInjector::is_module_loaded(pid, "dlp_hook_dll.dll") {
        Ok(false) => {
            match watcher_injector.inject(pid) {
                Ok(()) => { info!(...); }
                Err(e) => { warn!(...); }
            }
        }
        Ok(true) => { trace!(...); }
        Err(e) => { warn!(...); }
    }
}
```

**HookInjector reuse** (from hook_injector.rs lines 63-137):
```rust
pub struct HookInjector {
    dll_path_x64: PathBuf,
    dll_path_x86: Option<PathBuf>,
}

impl HookInjector {
    pub fn new(dll_path_x64: impl Into<PathBuf>, dll_path_x86: Option<PathBuf>) -> Self { ... }
    pub fn inject(&self, pid: u32) -> Result<(), HookError> { ... }
    pub fn is_module_loaded(pid: u32, module_name: &str) -> Result<bool, HookError> { ... }
}
```

**Error type pattern** (from hook_injector.rs lines 24-61):
```rust
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("target PID {pid} not found or access denied")]
    AccessDenied { pid: u32 },
    #[error("remote thread creation failed for PID {pid}: {detail}")]
    RemoteThreadFailed { pid: u32, detail: String },
    #[error("injection into PID {pid} failed with exit code {exit_code}")]
    InjectionFailed { pid: u32, exit_code: u32 },
    // ...
}
```

---

### `dlp-agent/src/process_registry.rs` (model, state-machine)

**Analog:** `dlp-agent/src/approval_cache.rs` (DashMap + Arc pattern)

**DashMap pattern** (from approval_cache.rs lines 30-70):
```rust
use std::sync::Arc;
use dashmap::DashMap;

#[derive(Debug, Clone)]
pub struct ApprovalCache {
    pub cache: Arc<DashMap<String, CachedApproval>>,
    verifying_key: Arc<std::sync::RwLock<Option<ed25519_dalek::VerifyingKey>>>,
}

impl ApprovalCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            verifying_key: Arc::new(std::sync::RwLock::new(None)),
        }
    }
}
```

**State enum pattern** (derive Debug, Clone, PartialEq per D-08):
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessState {
    Discovered,
    Skipped(AllowlistReason),
    Injected { arch: String, timestamp: std::time::Instant },
    Exited,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AllowlistReason {
    SelfProcess,
    Avedr,
    SystemCritical,
    Ppl,
    WoW64,
    OperatorDefined,
}
```

---

### `dlp-agent/src/allowlist.rs` (utility, transform)

**Analog:** `dlp-agent/src/detection/app_identity.rs` lines 239-350 (extract_publisher)

**Authenticode signer extraction pattern** (lines 239-280):
```rust
#[cfg(windows)]
fn extract_publisher(image_path: &str) -> String {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
        CERT_FIND_SUBJECT_NAME, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING,
        X509_ASN_ENCODING,
    };
    // Step 1: CryptQueryObject
    // Step 2: CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)
    // Step 3: CertFindCertificateInStore
    // Step 4: CertGetNameStringW(CERT_NAME_SIMPLE_DISPLAY_TYPE)
}
```

**Allowlist matching pattern** (TOML config section):
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UniversalInjectionConfig {
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowlistEntry {
    pub path: Option<String>,
    pub cert_subject: Option<String>,
    pub description: String,
    pub category: AllowlistCategory,
}
```

---

### `dlp-agent/src/appinit.rs` (utility, file-I/O)

**Analog:** `dlp-agent/src/chrome/registry.rs` (registry read patterns)

**Registry read pattern** (from RESEARCH.md Pattern 7):
```rust
use windows::Win32::System::Registry::{
    RegOpenKeyExW, RegQueryValueExW, RegCloseKey,
    HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, REG_DWORD,
};

const APPINIT_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
const APPINIT_DLLS_VALUE: &str = "AppInit_DLLs";
const LOAD_APPINIT_VALUE: &str = "LoadAppInit_DLLs";
const REQUIRE_SIGNED_VALUE: &str = "RequireSignedAppInit_DLLs";
```

**Secure Boot detection pattern** (from RESEARCH.md Pattern 6):
```rust
use windows::Win32::System::Firmware::GetFirmwareEnvironmentVariable;

fn is_secure_boot_enabled() -> Option<bool> {
    let mut value: u32 = 0;
    let result = unsafe {
        GetFirmwareEnvironmentVariable(
            windows::core::w!("SecureBoot"),
            &windows::core::GUID::from_u128(0x8be4df6193ca11d2aa0d00e098032b8c),
            Some(&mut value as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if result == 0 { return None; }
    Some(value != 0)
}
```

---

### `dlp-agent/src/service.rs` modifications (service, request-response)

**Analog:** `dlp-agent/src/service.rs` lines 819-1193 (run_loop_init)

**Subsystem initialization pattern** (lines 975-996):
```rust
let hook_injector_opt: Option<crate::hook_injector::HookInjector> =
    if agent_config.cloud_hook_enabled.unwrap_or(false) {
        let dll_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("dlp_hook_dll.dll")))
            .unwrap_or_else(|| std::path::PathBuf::from("dlp_hook_dll.dll"));
        let injector = crate::hook_injector::HookInjector::new(&dll_path, Some(dll_path_x86));
        info!(..., "hook injector constructed");
        Some(injector)
    } else {
        info!("cloud hook disabled — skipping HookInjector");
        None
    };
```

**RunLoopContext extension pattern** (lines 666-738):
```rust
struct RunLoopContext {
    file_handle: tokio::task::JoinHandle<()>,
    // ... existing fields ...
    hook_injector: Option<crate::hook_injector::HookInjector>,
    sync_watcher_shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    sync_watcher_handle: Option<std::thread::JoinHandle<()>>,
    // ADD for Phase 49:
    // process_watcher_shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    // process_watcher_handle: Option<std::thread::JoinHandle<()>>,
    // process_registry: Arc<crate::process_registry::ProcessRegistry>,
}
```

**Config poll integration pattern** (lines 561-664):
```rust
async fn config_poll_loop(
    server_client: crate::server_client::ServerClient,
    config: Arc<parking_lot::Mutex<crate::config::AgentConfig>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // Apply payload diff, merge into config, save to TOML
    let (changed_fields, disk_merge_data) = {
        let mut cfg = config.lock();
        apply_payload_to_config(&mut cfg, &payload)
    };
}
```

---

### `dlp-server/src/admin_api.rs` modifications (controller, request-response)

**Analog:** `dlp-server/src/admin_api.rs` lines 1048-1204 (policy CRUD)

**Router registration pattern** (lines 844-1013):
```rust
pub fn admin_router(state: Arc<AppState>) -> Router {
    let public_routes = Router::new()
        .route("/health", get(health))
        // ...
        .route("/admin/device-registry", get(list_device_registry_handler));

    let protected_routes = Router::new()
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/{id}", get(get_policy).put(update_policy).delete(delete_policy))
        // ADD for Phase 49:
        // .route("/admin/allowlist", get(list_allowlist).post(create_allowlist_entry))
        // .route("/admin/allowlist/{id}", get(get_allowlist_entry).put(update_allowlist_entry).delete(delete_allowlist_entry))
        .route_layer(default_config())
        .layer(middleware::from_fn(admin_auth::require_auth));

    public_routes.merge(protected_routes).with_state(state)
}
```

**CRUD handler pattern** (lines 1049-1109):
```rust
async fn list_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PolicyResponse>>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let db_rows = PolicyRepository::list(&pool).map_err(AppError::Database)?;
        let policies: Vec<PolicyResponse> = db_rows.into_iter().map(|r| { ... }).collect();
        Ok(policies)
    }).await.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    Ok(Json(rows))
}
```

**Request/response types pattern** (lines 112-178):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub mode: PolicyMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    // ...
    pub version: i64,
    pub updated_at: String,
}
```

---

### `dlp-server/src/db/mod.rs` modifications (config, CRUD)

**Analog:** `dlp-server/src/db/mod.rs` lines 73-427 (init_tables)

**Table creation pattern** (lines 147-168):
```rust
CREATE TABLE IF NOT EXISTS device_registry (
    id          TEXT PRIMARY KEY,
    vid         TEXT NOT NULL,
    pid         TEXT NOT NULL,
    serial      TEXT NOT NULL,
    owner_sid   TEXT,
    owner_user  TEXT,
    description TEXT NOT NULL DEFAULT '',
    trust_tier  TEXT NOT NULL CHECK(trust_tier IN ('blocked', 'read_only', 'full_access')),
    created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_registry_unique
    ON device_registry(vid, pid, serial, COALESCE(owner_sid, ''));
```

**Migration pattern** (lines 433-504):
```rust
pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN usb_blocked_failure_mode TEXT NOT NULL DEFAULT 'Warning only'",
        "usb_blocked_failure_mode",
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

**For Phase 49 allowlist_entries table** (add to init_tables):
```sql
CREATE TABLE IF NOT EXISTS allowlist_entries (
    id          TEXT PRIMARY KEY,
    path        TEXT,
    cert_subject TEXT,
    description TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL CHECK(category IN ('self', 'avedr', 'system_critical', 'operator_defined')),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_allowlist_category ON allowlist_entries(category);
```

---

### `dlp-admin-cli/src/app.rs` modifications (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/usb_enforcement.rs` + `dlp-admin-cli/src/screens/print_config.rs`

**Screen enum addition pattern** (from app.rs lines 663-709):
```rust
/// USB enforcement settings form.
/// Navigable list of 5 rows (3 picker fields + Save + Back).
UsbEnforcementConfig {
    config: serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: String,
},
/// Cloud sync hook configuration form.
CloudConfig {
    config: serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: String,
},
/// Print spooler interception configuration form.
PrintConfig {
    config: serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: String,
},
```

**Screen constants module pattern** (from usb_enforcement.rs):
```rust
/// JSON keys for the USB enforcement config form, indexed by row.
pub const USB_ENFORCEMENT_KEYS: [&str; 3] = [
    "usb_blocked_failure_mode",
    "usb_startup_resolution_mode",
    "usb_none_serial_policy",
];

/// Value options for each picker field, indexed by row.
pub const USB_ENFORCEMENT_OPTIONS: &[&[&str]] = &[
    &["Hard error", "Warning only", "Retry then error"],
    &["VID/PID/serial fallback"],
    &["Always Blocked", "Allow unregistered"],
];

pub const USB_ENFORCEMENT_SAVE_ROW: usize = 3;
pub const USB_ENFORCEMENT_BACK_ROW: usize = 4;
pub const USB_ENFORCEMENT_ROW_COUNT: usize = 5;
pub const USB_ENFORCEMENT_LABELS: [&str; 3] =
    ["Failure Mode", "Startup Resolution", "(none) Serial Policy"];
```

**Dispatch handler pattern** (from dispatch.rs lines 1794-1807):
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

**Render dispatch pattern** (from render.rs lines 174-180):
```rust
Screen::UsbEnforcementConfig { config, selected, editing, buffer } => {
    draw_usb_enforcement_config(frame, area, config, *selected, *editing, buffer);
}
```

---

## Shared Patterns

### Error Handling (thiserror)
**Source:** `dlp-agent/src/hook_injector.rs` lines 24-61
**Apply to:** All new agent modules
```rust
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("target PID {pid} not found or access denied")]
    AccessDenied { pid: u32 },
    #[error("remote thread creation failed for PID {pid}: {detail}")]
    RemoteThreadFailed { pid: u32, detail: String },
    #[error("injection into PID {pid} failed with exit code {exit_code}")]
    InjectionFailed { pid: u32, exit_code: u32 },
}
```

### DashMap + Arc for Shared State
**Source:** `dlp-agent/src/approval_cache.rs` lines 50-70
**Apply to:** `process_registry.rs`
```rust
use std::sync::Arc;
use dashmap::DashMap;

pub struct ProcessRegistry {
    states: Arc<DashMap<u32, ProcessState>>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self { states: Arc::new(DashMap::new()) }
    }
}
```

### TOML Config Section with serde
**Source:** `dlp-agent/src/config.rs` lines 91-101
**Apply to:** `AgentConfig` extension for `[universal_injection]`
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub recheck_interval_secs: Option<u64>,
}
```

### AgentConfigPayload Mirror Type
**Source:** `dlp-agent/src/server_client.rs` lines 122-192
**Apply to:** Add allowlist fields to `AgentConfigPayload`
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    // ... existing fields ...
    #[serde(default)]
    pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
    // ADD: #[serde(default)] pub allowlist_entries: Vec<AllowlistEntry>,
}
```

### Repository Pattern
**Source:** `dlp-server/src/db/repositories/device_registry.rs` lines 35-120
**Apply to:** `dlp-server/src/db/repositories/allowlist.rs`
```rust
pub struct DeviceRegistryRepository;

impl DeviceRegistryRepository {
    pub fn list_all(pool: &Pool) -> rusqlite::Result<Vec<DeviceRegistryRow>> { ... }
    pub fn upsert(uow: &UnitOfWork<'_>, row: &DeviceRegistryRow) -> rusqlite::Result<()> { ... }
}
```

### Config Poll Diff/Merge
**Source:** `dlp-agent/src/service.rs` lines 359-496
**Apply to:** Extend `apply_payload_to_config` with allowlist diff
```rust
fn apply_payload_to_config(
    cfg: &mut crate::config::AgentConfig,
    payload: &crate::server_client::AgentConfigPayload,
) -> (Vec<&'static str>, DiskMergeData) {
    let mut changed_fields: Vec<&'static str> = Vec::new();
    if cfg.monitored_paths != payload.monitored_paths {
        changed_fields.push("monitored_paths");
        cfg.monitored_paths = payload.monitored_paths.clone();
    }
    // ADD: allowlist diff logic
}
```

### TUI Screen Registration
**Source:** `dlp-admin-cli/src/screens/mod.rs`
**Apply to:** Add `allowlist` module
```rust
mod approvals;
mod cloud_config;
mod dispatch;
mod labels;
mod print_config;
mod render;
mod syslog_config;
mod usb_enforcement;
// ADD: mod allowlist;
```

---

## No Analog Found

No files with no close match — all Phase 49 files have clear analogs in the codebase.

## Metadata

**Analog search scope:**
- `dlp-agent/src/` — hook_injector.rs, service.rs, engine_client.rs, config.rs, approval_cache.rs, server_client.rs, detection/app_identity.rs
- `dlp-server/src/` — admin_api.rs, db/mod.rs, db/repositories/device_registry.rs
- `dlp-admin-cli/src/` — app.rs, screens/dispatch.rs, screens/render.rs, screens/usb_enforcement.rs, screens/print_config.rs, screens/cloud_config.rs, screens/mod.rs

**Files scanned:** 15
**Pattern extraction date:** 2026-05-19
