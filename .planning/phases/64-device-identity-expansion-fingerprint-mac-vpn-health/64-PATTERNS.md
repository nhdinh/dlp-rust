# Phase 64: Device Identity Expansion — Pattern Map

**Mapped:** 2026-06-06
**Files analyzed:** 10
**Analogs found:** 10 / 10

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dlp-common/src/endpoint.rs` (extend) | model | transform | `dlp-common/src/endpoint.rs` (existing `AppIdentity`, `DeviceIdentity`) | exact |
| `dlp-common/src/abac.rs` (extend) | model | transform | `dlp-common/src/abac.rs` (existing `DeviceTrust`, `NetworkLocation`) | exact |
| `dlp-agent/src/device_identity.rs` | service | file-I/O | `dlp-common/src/ad_client.rs` (`get_device_trust`, `find_local_ipv4_sync`) | role-match |
| `dlp-agent/src/server_client.rs` (extend) | service | request-response | `dlp-agent/src/server_client.rs` (existing `send_heartbeat`) | exact |
| `dlp-agent/src/service.rs` (extend) | service | event-driven | `dlp-agent/src/service.rs` (heartbeat loop) | exact |
| `dlp-server/src/agent_registry.rs` (extend) | controller | request-response | `dlp-server/src/agent_registry.rs` (existing `heartbeat`) | exact |
| `dlp-server/src/db/mod.rs` (extend) | migration | batch | `dlp-server/src/db/mod.rs` (existing `run_migrations`) | exact |
| `dlp-server/src/db/repositories/agents.rs` (extend) | repository | CRUD | `dlp-server/src/db/repositories/agents.rs` (existing `AgentRepository`) | exact |
| `dlp-server/src/policy_store.rs` (extend) | service | request-response | `dlp-server/src/policy_store.rs` (existing `condition_matches`) | exact |
| `dlp-common/src/lib.rs` (extend) | config | transform | `dlp-common/src/lib.rs` (existing re-exports) | exact |

## Pattern Assignments

### `dlp-common/src/endpoint.rs` (model, transform)

**Analog:** `dlp-common/src/endpoint.rs` (existing `DeviceIdentity`, `AppIdentity`)

**New type pattern** (lines 89-147 for struct style, lines 28-78 for enum style):
```rust
// Existing struct pattern (AppIdentity, line 89):
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppIdentity {
    pub image_path: String,
    pub publisher: String,
    pub trust_tier: AppTrustTier,
    pub signature_state: SignatureState,
    pub aumid: Option<String>,
    pub package_family_name: Option<String>,
    pub is_uwp: bool,
}

// Existing enum pattern (UsbTrustTier, line 68):
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UsbTrustTier {
    #[default]
    Blocked,
    ReadOnly,
    FullAccess,
}
```

**Action:** Add `EndpointIdentity` struct and `DeviceHealthStatus` enum following the same patterns:
- Struct: `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]` + `#[serde(default)]`
- Enum: `#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]` + `#[serde(rename_all = "snake_case")]`
- Default variant marked with `#[default]`

---

### `dlp-common/src/abac.rs` (model, transform)

**Analog:** `dlp-common/src/abac.rs` (existing `DeviceTrust`, `NetworkLocation`, `PolicyCondition`)

**Enum pattern** (lines 207-234):
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum DeviceTrust {
    Managed,
    #[default]
    Unmanaged,
    Compliant,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum NetworkLocation {
    Corporate,
    CorporateVpn,
    Guest,
    #[default]
    Unknown,
}
```

**PolicyCondition variant pattern** (lines 555-565):
```rust
/// Match by device trust level.
DeviceTrust {
    #[serde(rename = "op")]
    op: String,
    value: DeviceTrust,
},
/// Match by network location.
NetworkLocation {
    #[serde(rename = "op")]
    op: String,
    value: NetworkLocation,
},
```

**Action:** Add `DeviceHealthStatus` enum with `#[serde(rename_all = "snake_case")]` and add `DeviceHealth` variant to `PolicyCondition` following the `DeviceTrust`/`NetworkLocation` pattern.

---

### `dlp-agent/src/device_identity.rs` (service, file-I/O)

**Analog:** `dlp-common/src/ad_client.rs` (`get_device_trust`, `find_local_ipv4_sync`)

**Windows API wrapper pattern** (lines 590-618):
```rust
#[cfg(windows)]
pub fn get_device_trust() -> crate::DeviceTrust {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetGetJoinInformation, NETSETUP_JOIN_STATUS,
    };
    unsafe {
        let mut name_buf = PWSTR::null();
        let mut status = NETSETUP_JOIN_STATUS::default();
        NetGetJoinInformation(None, &mut name_buf, &mut status);
        let is_domain_joined = !name_buf.is_null() && status == NETSETUP_JOIN_STATUS(3);
        if !name_buf.is_null() {
            let _ = NetApiBufferFree(Some(name_buf.as_ptr() as *const _));
        }
        if is_domain_joined { crate::DeviceTrust::Managed } else { crate::DeviceTrust::Unmanaged }
    }
}

#[cfg(not(windows))]
pub fn get_device_trust() -> crate::DeviceTrust {
    crate::DeviceTrust::Unknown
}
```

**GetAdaptersAddresses pattern** (lines 673-723):
```rust
#[cfg(windows)]
fn find_local_ipv4_sync() -> Option<std::net::IpAddr> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let family = AF_INET.0 as u32;
    let flags = GAA_FLAG_INCLUDE_PREFIX;

    unsafe {
        let mut buf_size: u32 = 0;
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut buf_size);
        if buf_size == 0 {
            return None;
        }

        let layout = std::alloc::Layout::from_size_align(buf_size as usize, 1).expect("valid layout");
        let buf = std::alloc::alloc(layout) as *mut IP_ADAPTER_ADDRESSES_LH;

        if GetAdaptersAddresses(family, flags, None, Some(&mut *buf), &mut buf_size) != 0 {
            std::alloc::dealloc(buf as *mut u8, layout);
            return None;
        }

        let mut curr = buf;
        while !curr.is_null() {
            let addr = &*curr;
            // ... process adapter ...
            curr = addr.Next;
        }

        std::alloc::dealloc(buf as *mut u8, layout);
        None
    }
}
```

**Action:** Create new module with:
1. `collect_mac_addresses()` — uses `GetAdaptersAddresses` with `AF_UNSPEC` (IPv4+IPv6), extracts `PhysicalAddress`, sorts results
2. `detect_vpn_active()` — uses `GetAdaptersAddresses` checking `IfType == IF_TYPE_TUNNEL` (131) and description keywords
3. `get_domain_joined()` — wraps `NetGetJoinInformation` (reuse pattern from `ad_client.rs`)
4. `compute_fingerprint()` — SHA-256 of hostname + sorted MACs + OS version + install date
5. `read_fingerprint_from_registry()` / `write_fingerprint_to_registry()` — HKLM read/write
6. All functions gated with `#[cfg(windows)]` / `#[cfg(not(windows))]` for test compatibility

---

### `dlp-agent/src/server_client.rs` (service, request-response)

**Analog:** `dlp-agent/src/server_client.rs` (existing `send_heartbeat`)

**Heartbeat payload pattern** (lines 443-463):
```rust
pub async fn send_heartbeat(&self) -> Result<(), ServerClientError> {
    let url = format!("{}/agents/{}/heartbeat", self.base_url, self.agent_id);

    let payload = serde_json::json!({
        "status": "healthy",
    });

    let resp = self.client.post(&url).json(&payload).send().await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(ServerClientError::ServerError { status, body });
    }

    debug!(agent_id = %self.agent_id, "heartbeat sent");
    Ok(())
}
```

**Action:** Extend `send_heartbeat` to accept an `Option<EndpointIdentity>` parameter and include it in the JSON payload:
```rust
let payload = serde_json::json!({
    "status": "healthy",
    "device_identity": device_identity,
});
```

---

### `dlp-agent/src/service.rs` (service, event-driven)

**Analog:** `dlp-agent/src/service.rs` (heartbeat loop, config poll loop)

**Global state pattern** (lines 45-68):
```rust
static CONFIG: std::sync::OnceLock<std::sync::Arc<parking_lot::Mutex<crate::config::AgentConfig>>> =
    std::sync::OnceLock::new();

pub fn with_config<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&crate::config::AgentConfig) -> R,
{
    CONFIG.get().map(|arc| {
        let cfg = arc.lock();
        f(&cfg)
    })
}
```

**Action:** Add a global `OnceLock` for `EndpointIdentity` (or a `Mutex<EndpointIdentity>`) that is populated at service startup. The heartbeat loop reads this state and passes it to `send_heartbeat()`. Health status transitions are synchronized through this shared state.

---

### `dlp-server/src/agent_registry.rs` (controller, request-response)

**Analog:** `dlp-server/src/agent_registry.rs` (existing `heartbeat` handler)

**Request/response type pattern** (lines 40-67):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfoResponse {
    pub agent_id: String,
    pub hostname: String,
    pub ip: String,
    pub os_version: String,
    pub agent_version: String,
    pub last_heartbeat: String,
    pub status: String,
    pub registered_at: String,
}
```

**Handler pattern with spawn_blocking** (lines 143-169):
```rust
pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(_payload): Json<HeartbeatRequest>,
) -> Result<StatusCode, AppError> {
    let now = Utc::now().to_rfc3339();
    let id = agent_id.clone();
    let pool = Arc::clone(&state.pool);

    let rows_updated = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        let rows = AgentRepository::update_heartbeat(&uow, &id, &now).map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows_updated == 0 {
        return Err(AppError::NotFound(format!(
            "agent {agent_id} not registered"
        )));
    }

    Ok(StatusCode::NO_CONTENT)
}
```

**Action:**
1. Extend `HeartbeatRequest` with `#[serde(default)] pub device_identity: Option<EndpointIdentity>`
2. Extend `AgentInfoResponse` with fingerprint, mac_addresses, vpn_state, domain_joined, health_status fields
3. Update `heartbeat` handler to pass `device_identity` fields to `AgentRepository::update_heartbeat`

---

### `dlp-server/src/db/mod.rs` (migration, batch)

**Analog:** `dlp-server/src/db/mod.rs` (existing `run_migrations`)

**Migration pattern** (lines 546-850):
```rust
pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
    run_alter(
        conn,
        "ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL DEFAULT 'ALL'",
        "mode",
        "policies",
    )?;
    // ... more migrations ...
    Ok(())
}

fn run_alter(conn: &SqliteConn, sql: &str, column: &str, table: &str) -> anyhow::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(e)
            if e.to_string()
                .contains(&format!("duplicate column name: {column}")) =>
        {
            Ok(())
        }
        Err(e) => Err(e).context(format!("running migration: add {column} column to {table}")),
    }
}
```

**Action:** Add Phase 64 migration entries to `run_migrations` for `agents` table columns:
```rust
run_alter(
    conn,
    "ALTER TABLE agents ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''",
    "fingerprint",
    "agents",
)?;
run_alter(
    conn,
    "ALTER TABLE agents ADD COLUMN mac_addresses TEXT NOT NULL DEFAULT '[]'",
    "mac_addresses",
    "agents",
)?;
run_alter(
    conn,
    "ALTER TABLE agents ADD COLUMN vpn_active INTEGER NOT NULL DEFAULT 0",
    "vpn_active",
    "agents",
)?;
run_alter(
    conn,
    "ALTER TABLE agents ADD COLUMN domain_joined INTEGER NOT NULL DEFAULT 0",
    "domain_joined",
    "agents",
)?;
run_alter(
    conn,
    "ALTER TABLE agents ADD COLUMN health_status TEXT NOT NULL DEFAULT 'healthy'",
    "health_status",
    "agents",
)?;
```

---

### `dlp-server/src/db/repositories/agents.rs` (repository, CRUD)

**Analog:** `dlp-server/src/db/repositories/agents.rs` (existing `AgentRow`, `AgentRepository`)

**Row struct pattern** (lines 14-32):
```rust
#[derive(Debug, Clone)]
pub struct AgentRow {
    pub agent_id: String,
    pub hostname: String,
    pub ip: String,
    pub os_version: String,
    pub agent_version: String,
    pub last_heartbeat: String,
    pub status: String,
    pub registered_at: String,
}
```

**Repository method pattern** (lines 160-171):
```rust
pub fn update_heartbeat(
    uow: &UnitOfWork<'_>,
    agent_id: &str,
    heartbeat: &str,
) -> rusqlite::Result<usize> {
    let rows = uow.tx.execute(
        "UPDATE agents SET last_heartbeat = ?1, status = 'online' \
         WHERE agent_id = ?2",
        params![heartbeat, agent_id],
    )?;
    Ok(rows)
}
```

**Action:**
1. Extend `AgentRow` with `fingerprint`, `mac_addresses`, `vpn_active`, `domain_joined`, `health_status` fields
2. Update `list`, `get_by_id`, `upsert` SQL and row mapping
3. Update `update_heartbeat` to accept and persist the new device identity fields

---

### `dlp-server/src/policy_store.rs` (service, request-response)

**Analog:** `dlp-server/src/policy_store.rs` (existing `condition_matches`)

**Condition match pattern** (lines 402-442):
```rust
fn condition_matches(
    condition: &PolicyCondition,
    ctx: &AbacContext,
    resource: &dlp_common::abac::Resource,
) -> bool {
    match condition {
        PolicyCondition::DeviceTrust { op, value } => {
            compare_op(op, &ctx.subject.device_trust, value)
        }
        PolicyCondition::NetworkLocation { op, value } => {
            compare_op(op, &ctx.subject.network_location, value)
        }
        // ... other variants ...
    }
}
```

**Action:** Add `DeviceHealth` variant handling in `condition_matches`:
```rust
PolicyCondition::DeviceHealth { op, value } => {
    compare_op(op, &ctx.subject.device_health, value)
}
```

---

### `dlp-common/src/lib.rs` (config, transform)

**Analog:** `dlp-common/src/lib.rs` (existing re-exports)

**Re-export pattern** (lines 35-36):
```rust
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier};
```

**Action:** Add re-exports for new types:
```rust
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, DeviceHealthStatus, EndpointIdentity, SignatureState, UsbTrustTier};
```

---

## Shared Patterns

### Windows API `#[cfg(windows)]` Gating
**Source:** `dlp-common/src/ad_client.rs` (lines 590-618, 673-723)
**Apply to:** `dlp-agent/src/device_identity.rs`
```rust
#[cfg(windows)]
pub fn collect_mac_addresses() -> Vec<String> { /* Windows API calls */ }

#[cfg(not(windows))]
pub fn collect_mac_addresses() -> Vec<String> {
    Vec::new()
}
```

### Registry Read/Write
**Source:** `dlp-agent/src/appinit.rs` (lines 33-130)
**Apply to:** `dlp-agent/src/device_identity.rs` (fingerprint persistence)
```rust
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_SZ,
};

let mut hkey = windows::Win32::System::Registry::HKEY::default();
let result = unsafe {
    RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        windows::core::w!(r"SOFTWARE\DLP\Agent"),
        None,
        KEY_READ,
        &mut hkey,
    )
};
```

### Serde Default + Skip
**Source:** `dlp-agent/src/server_client.rs` (lines 922-924 in `ServerApprovalEntry`)
**Apply to:** All new optional fields in heartbeat payloads
```rust
#[serde(default)]
pub device_fingerprint: Option<String>,
```

### Error Handling with `anyhow`
**Source:** `dlp-agent/src/appinit.rs` (lines 33-47)
**Apply to:** `dlp-agent/src/device_identity.rs`
```rust
pub fn read_appinit_state() -> anyhow::Result<AppInitState> {
    // ...
    if result.is_err() {
        return Err(anyhow::anyhow!("RegOpenKeyExW failed: {:?}", result));
    }
    // ...
}
```

### SQLite Migration Idempotency
**Source:** `dlp-server/src/db/mod.rs` (lines 852-864)
**Apply to:** Phase 64 `agents` table column additions
```rust
fn run_alter(conn: &SqliteConn, sql: &str, column: &str, table: &str) -> anyhow::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(e)
            if e.to_string()
                .contains(&format!("duplicate column name: {column}")) =>
        {
            Ok(())
        }
        Err(e) => Err(e).context(format!("running migration: add {column} column to {table}")),
    }
}
```

### Axum Handler with `spawn_blocking`
**Source:** `dlp-server/src/agent_registry.rs` (lines 143-169)
**Apply to:** Extended `heartbeat` handler
```rust
pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<StatusCode, AppError> {
    let pool = Arc::clone(&state.pool);
    let rows_updated = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        // ... DB operations ...
        uow.commit().map_err(AppError::from)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    // ...
}
```

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| (none) | — | — | All files have strong analogs in the codebase |

## Metadata

**Analog search scope:** `dlp-common/src/`, `dlp-agent/src/`, `dlp-server/src/`
**Files scanned:** 10 primary + 2 supporting
**Pattern extraction date:** 2026-06-06

### Key Patterns Identified

1. **All Windows API calls use `#[cfg(windows)]` / `#[cfg(not(windows))]` gating** — ensures tests compile and run on non-Windows platforms
2. **Registry operations use raw `windows` crate APIs** (not `winreg`) — consistent with `appinit.rs` pattern
3. **All serde types use `#[serde(default)]` for backward compatibility** — old payloads deserialize without new fields
4. **SQLite migrations are idempotent via `run_alter` helper** — duplicate column errors are swallowed
5. **Server DB writes go through `UnitOfWork` + `spawn_blocking`** — never block the async reactor
6. **ABAC `PolicyCondition` variants follow `compare_op` pattern** — scalar equality/inequality matching
7. **Agent global state uses `OnceLock<Arc<Mutex<T>>>`** — pattern from `service.rs` CONFIG static
