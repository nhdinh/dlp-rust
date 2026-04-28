# Phase 29: Chrome Enterprise Connector - Pattern Map

**Mapped:** 2026-04-29
**Files analyzed:** 14
**Analogs found:** 12 / 14

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-agent/src/chrome/mod.rs` | module | config | `dlp-agent/src/lib.rs` module declarations | exact |
| `dlp-agent/src/chrome/proto.rs` | model | transform | RESEARCH.md prost-build example | research-pattern |
| `dlp-agent/src/chrome/frame.rs` | utility | streaming | `dlp-agent/src/ipc/frame.rs` | exact |
| `dlp-agent/src/chrome/handler.rs` | service | request-response | `dlp-agent/src/ipc/pipe1.rs` dispatch + `device_registry.rs` cache lookup | exact |
| `dlp-agent/src/chrome/cache.rs` | service | CRUD | `dlp-agent/src/device_registry.rs` | exact |
| `dlp-agent/src/chrome/registry.rs` | utility | config | `dlp-agent/src/password_stop.rs` lines 675-729 | exact |
| `dlp-agent/proto/content_analysis.proto` | config | static | RESEARCH.md proto example | research-pattern |
| `dlp-agent/build.rs` | config | build | `dlp-user-ui/build.rs` + RESEARCH.md | exact |
| `dlp-agent/Cargo.toml` | config | config | existing Cargo.toml deps section | exact |
| `dlp-agent/src/lib.rs` | config | config | existing lib.rs module declarations | exact |
| `dlp-agent/src/service.rs` | service | event-driven | existing service.rs spawn patterns | exact |
| `dlp-common/src/audit.rs` | model | transform | existing `AuditEvent` optional field pattern | exact |
| `dlp-agent/src/server_client.rs` | service | request-response | existing `fetch_device_registry()` pattern | exact |
| `dlp-agent/tests/chrome_pipe.rs` | test | request-response | `dlp-agent/tests/device_registry_cache.rs` | role-match |

## Pattern Assignments

### `dlp-agent/src/chrome/mod.rs` (module, config)

**Analog:** `dlp-agent/src/lib.rs` lines 25-84

**Module declaration pattern** (lines 25-84):
```rust
pub mod config;

#[cfg(windows)]
pub mod service;

#[cfg(windows)]
pub mod ipc;

pub mod device_registry;
```

**Pattern to copy:** Add `pub mod chrome;` after the `device_registry` declaration (line 81-82). The `chrome` module should NOT be gated with `#[cfg(windows)]` because the protobuf types and cache are platform-agnostic (only the pipe server and registry writer are Windows-specific, and those are gated internally).

---

### `dlp-agent/src/chrome/proto.rs` (model, transform)

**Analog:** RESEARCH.md Pattern 2 (prost-build)

**Generated code inclusion pattern**:
```rust
// The generated file is placed in OUT_DIR by prost-build.
include!(concat!(env!("OUT_DIR"), "/content_analysis.sdk.rs"));
```

**Pattern to copy:** Single-line `include!` macro pointing to the OUT_DIR. The actual `.proto` file lives at `dlp-agent/proto/content_analysis.proto` and is compiled by `build.rs`. No hand-written Rust types — all types are generated from the proto definition.

---

### `dlp-agent/src/chrome/frame.rs` (utility, streaming)

**Analog:** `dlp-agent/src/ipc/frame.rs`

**Imports pattern** (lines 1-13):
```rust
use anyhow::{Context, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
```

**Core frame read pattern** (lines 19-38):
```rust
pub fn read_frame(pipe: HANDLE) -> Result<Vec<u8>> {
    let mut length_buf = [0u8; 4];
    read_exact(pipe, &mut length_buf).context("read frame length")?;

    let payload_len = u32::from_le_bytes(length_buf) as usize;

    const MAX_PAYLOAD: usize = 67_108_864;
    if payload_len > MAX_PAYLOAD {
        return Err(anyhow::anyhow!(
            "frame payload too large: {} bytes (max 64 MiB)",
            payload_len
        ));
    }

    let mut payload = vec![0u8; payload_len];
    read_exact(pipe, &mut payload).context("read frame payload")?;
    Ok(payload)
}
```

**Core frame write pattern** (lines 44-53):
```rust
pub fn write_frame(pipe: HANDLE, payload: &[u8]) -> Result<()> {
    let length_buf = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &length_buf).context("write frame length")?;
    write_all(pipe, payload).context("write frame payload")?;
    flush(pipe).context("flush frame")?;
    Ok(())
}
```

**read_exact / write_all / flush helpers** (lines 56-137): Copy verbatim from `ipc/frame.rs`. These handle Win32 `ReadFile`/`WriteFile` partial read/write edge cases.

**Adaptation for Chrome:** The Chrome frame module uses the EXACT same `[4-byte LE length][payload]` format as the IPC frame module. The only difference is the payload is protobuf bytes instead of JSON UTF-8. The `read_exact`/`write_all`/`flush` helpers are identical. Use a smaller `MAX_PAYLOAD` (4 MiB instead of 64 MiB) per RESEARCH.md security guidance.

---

### `dlp-agent/src/chrome/handler.rs` (service, request-response)

**Analog 1:** `dlp-agent/src/ipc/pipe1.rs` — accept loop and client handling
**Analog 2:** `dlp-agent/src/device_registry.rs` — cache lookup pattern

**Pipe server accept loop pattern** (from `pipe1.rs` lines 125-148):
```rust
fn accept_loop(first_pipe: HANDLE) -> Result<()> {
    let mut pipe = first_pipe;
    loop {
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            let win32_code = (e.code().0 as u32) & 0xFFFF;
            if win32_code != 535 {
                warn!(win32_code, "ConnectNamedPipe failed — recycling pipe");
                let _ = unsafe { CloseHandle(pipe) };
                pipe = create_pipe()?;
                continue;
            }
            debug!("ConnectNamedPipe: client already connected (535)");
        }

        info!(pipe = CHROME_PIPE_NAME, "client connected to Chrome pipe");
        let _ = handle_client(pipe);
        pipe = create_pipe()?;
    }
}
```

**Client handle pattern** (from `pipe1.rs` lines 182-218, adapted):
```rust
fn handle_client(pipe: HANDLE) -> Result<()> {
    loop {
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "Chrome pipe: read error — disconnecting");
                break;
            }
        };

        // Decode protobuf request
        let request = match prost::Message::decode(&*frame) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Chrome pipe: malformed protobuf — closing connection");
                break;
            }
        };

        let response = dispatch_request(request, &cache);

        // Encode protobuf response
        let mut response_bytes = Vec::new();
        if let Err(e) = prost::Message::encode(&response, &mut response_bytes) {
            warn!(error = %e, "Chrome pipe: failed to encode response");
            break;
        }

        if let Err(e) = write_frame(pipe, &response_bytes) {
            debug!(error = %e, "Chrome pipe: write error — disconnecting");
            break;
        }
    }

    cleanup_pipe(pipe)?;
    Ok(())
}
```

**Decision dispatch pattern** (from RESEARCH.md D-06):
```rust
fn dispatch_request(
    request: ContentAnalysisRequest,
    cache: &ManagedOriginsCache,
) -> ContentAnalysisResponse {
    let mut response = ContentAnalysisResponse {
        request_token: request.request_token.clone(),
        ..Default::default()
    };

    // Only process clipboard paste events
    let is_clipboard = request.reason == Some(1); // CLIPBOARD_PASTE = 1
    if !is_clipboard {
        response.results.push(make_result_allow());
        return response;
    }

    let source_url = request.request_data.as_ref().and_then(|d| d.url.as_ref());
    let source_origin = source_url.and_then(|u| to_origin(u));

    let should_block = source_origin.as_ref().map_or(false, |origin| {
        cache.is_managed(origin)
    });

    if should_block {
        response.results.push(make_result_block());
        // Emit audit event with source_origin
        emit_chrome_block_audit(&source_origin, None);
    } else {
        response.results.push(make_result_allow());
    }

    response
}
```

**create_pipe pattern** (from `pipe1.rs` lines 152-179):
```rust
fn create_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> = CHROME_PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    let sec = super::pipe_security::PipeSecurity::new().context("pipe security descriptor")?;

    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            pipe_mode(),
            NUM_INSTANCES,
            65536, 65536, 5000,
            Some(sec.as_ptr()),
        )
    };

    if pipe.is_invalid() {
        return Err(anyhow::anyhow!("CreateNamedPipeW returned INVALID_HANDLE_VALUE"));
    }
    Ok(pipe)
}
```

**pipe_mode pattern** (from `pipe1.rs` lines 101-104):
```rust
fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}
```

**Constants**:
```rust
const CHROME_PIPE_NAME: &str = r"\\.\pipe\brcm_chrm_cas";
const NUM_INSTANCES: u32 = 4;
```

---

### `dlp-agent/src/chrome/cache.rs` (service, CRUD)

**Analog:** `dlp-agent/src/device_registry.rs`

**Imports pattern** (lines 14-24):
```rust
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

#[cfg(windows)]
use crate::server_client::ServerClient;
```

**Cache struct pattern** (from `device_registry.rs` lines 38-42, adapted):
```rust
#[derive(Debug, Default)]
pub struct ManagedOriginsCache {
    cache: RwLock<HashSet<String>>,
}
```

**Constructor and lookup pattern** (from `device_registry.rs` lines 44-73, adapted):
```rust
impl ManagedOriginsCache {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_managed(&self, origin: &str) -> bool {
        self.cache.read().contains(origin)
    }
}
```

**Refresh pattern** (from `device_registry.rs` lines 84-117, adapted):
```rust
#[cfg(windows)]
impl ManagedOriginsCache {
    pub async fn refresh(&self, client: &ServerClient) {
        match client.fetch_managed_origins().await {
            Ok(origins) => {
                let new_set: HashSet<String> = origins.into_iter().map(|o| o.origin).collect();
                *self.cache.write() = new_set;
                debug!(count = new_set.len(), "managed origins cache refreshed");
            }
            Err(e) => {
                warn!(error = %e, "managed origins refresh failed — retaining stale cache");
            }
        }
    }
}
```

**Poll task spawn pattern** (from `device_registry.rs` lines 136-163, adapted):
```rust
#[cfg(windows)]
impl ManagedOriginsCache {
    pub fn spawn_poll_task(
        self_arc: Arc<Self>,
        client: ServerClient,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        const POLL_INTERVAL: Duration = Duration::from_secs(30);

        tokio::spawn(async move {
            self_arc.refresh(&client).await;
            info!("managed origins cache: initial refresh complete");

            let mut interval = tokio::time::interval(POLL_INTERVAL);
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        self_arc.refresh(&client).await;
                    }
                    _ = shutdown.changed() => {
                        info!("managed origins poll task shutting down");
                        return;
                    }
                }
            }
        })
    }
}
```

**Test seed helper** (from `device_registry.rs` lines 183-188, adapted):
```rust
#[doc(hidden)]
pub fn seed_for_test(&self, origin: &str) {
    self.cache.write().insert(origin.to_string());
}
```

---

### `dlp-agent/src/chrome/registry.rs` (utility, config)

**Analog:** `dlp-agent/src/password_stop.rs` lines 675-729

**HKLM write pattern** (from `password_stop.rs` lines 675-729, adapted):
```rust
#[cfg(windows)]
pub fn register_agent() -> anyhow::Result<()> {
    if std::env::var("DLP_SKIP_CHROME_REG").is_ok_and(|v| v == "1") {
        info!("Chrome registry registration skipped (DLP_SKIP_CHROME_REG=1)");
        return Ok(());
    }

    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_WRITE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const REG_KEY_PATH: &str = r"SOFTWARE\Google\Chrome\3rdparty\cas_agents";
    const REG_VALUE_NAME: &str = "pipe_name";
    const PIPE_NAME: &str = r"\\.\pipe\brcm_chrm_cas";

    unsafe {
        let subkey_wide: Vec<u16> = REG_KEY_PATH.encode_utf16().chain(std::iter::once(0)).collect();
        let name_wide: Vec<u16> = REG_VALUE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let value_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let value_bytes: &[u8] =
            std::slice::from_raw_parts(value_wide.as_ptr().cast(), value_wide.len() * 2);

        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if result.is_err() {
            warn!("RegCreateKeyExW failed for HKLM\\{}: {:?} — continuing without registration", REG_KEY_PATH, result);
            return Ok(()); // Non-fatal: do not block service startup
        }

        let result = RegSetValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            0,
            REG_SZ,
            Some(value_bytes),
        );
        let _ = RegCloseKey(hkey);

        if result.is_err() {
            warn!("RegSetValueExW failed for Chrome pipe name: {:?} — continuing without registration", result);
            return Ok(());
        }
    }

    info!("Chrome Content Analysis agent registered in HKLM");
    Ok(())
}
```

**Key adaptation points:**
- Use `warn!` + `return Ok(())` on failure (never fail service startup)
- Check `DLP_SKIP_CHROME_REG=1` env var for tests
- Use `REG_SZ` for string value
- Convert UTF-16 string to byte slice for `RegSetValueExW`

---

### `dlp-agent/build.rs` (config, build)

**Analog:** `dlp-user-ui/build.rs` + RESEARCH.md Pattern 2

**prost-build pattern** (from RESEARCH.md):
```rust
fn main() {
    println!("cargo:rerun-if-changed=proto/content_analysis.proto");
    prost_build::compile_protos(
        &["proto/content_analysis.proto"],
        &["proto/"],
    ).expect("protobuf compilation failed");
}
```

**Key requirements:**
- Add `cargo:rerun-if-changed` so proto edits trigger rebuilds
- Path is relative to crate root: `proto/content_analysis.proto`
- The generated module name is derived from the package name in the proto file

---

### `dlp-agent/Cargo.toml` (config, config)

**Dependencies to add** (from RESEARCH.md Standard Stack):
```toml
[dependencies]
# Add these lines:
prost = "0.14"
bytes = "1"

[build-dependencies]
# Add these lines:
prost-build = "0.14"
```

**Pattern:** Add `prost` and `bytes` to `[dependencies]`, `prost-build` to `[build-dependencies]`. No version workspace aliases exist for these crates — use explicit versions.

---

### `dlp-agent/src/lib.rs` (config, config)

**Module declaration pattern** (from existing lib.rs lines 78-84):
```rust
pub mod device_registry;

#[cfg(windows)]
pub mod usb_enforcer;
```

**Addition needed:**
```rust
pub mod chrome;
```

Insert after `pub mod device_registry;` (line 81). The `chrome` module is NOT gated with `#[cfg(windows)]` because `chrome::cache` and `chrome::proto` are platform-agnostic. Only `chrome::handler` (pipe server) and `chrome::registry` (HKLM writes) use `#[cfg(windows)]` internally.

---

### `dlp-agent/src/service.rs` (service, event-driven)

**Analog:** Existing `service.rs` spawn patterns for IPC servers and registry cache

**Chrome pipe thread spawn pattern** (from `service.rs` lines 124-130, adapted):
```rust
// ── Start IPC pipe servers ────────────────────────────────────
crate::ipc::start_all()?;
info!("IPC pipe servers started");

// ── Start Chrome Content Analysis pipe server ────────────────
// Spawn as a dedicated std::thread (NOT a tokio task) because
// ConnectNamedPipeW and ReadFile block the calling thread.
let chrome_handle = std::thread::Builder::new()
    .name("chrome-pipe".into())
    .spawn(|| {
        if let Err(e) = crate::chrome::handler::serve() {
            error!(error = %e, "Chrome pipe server exited with error");
        }
    })
    .context("failed to spawn Chrome pipe thread")?;
info!(thread_id = ?chrome_handle.thread().id(), "Chrome pipe server started");
```

**Chrome HKLM registration pattern** (insert after `harden_agent_process()` call, around line 106):
```rust
// Register as Chrome Content Analysis agent in HKLM.
// Non-fatal: if the registry write fails, the agent still starts.
if let Err(e) = crate::chrome::registry::register_agent() {
    warn!(error = %e, "Chrome HKLM registration failed — continuing");
}
```

**ManagedOriginsCache setup pattern** (from `service.rs` lines 425-448, adapted):
```rust
// ── Managed origins cache (D-02) ──────────────────────────────
let origins_cache = Arc::new(crate::chrome::cache::ManagedOriginsCache::new());
let (origins_shutdown_tx, origins_shutdown_rx) = tokio::sync::watch::channel(false);
let _origins_poll_handle = if let Some(ref sc) = server_client {
    Some(
        crate::chrome::cache::ManagedOriginsCache::spawn_poll_task(
            Arc::clone(&origins_cache),
            sc.clone(),
            origins_shutdown_rx,
        ),
    )
} else {
    drop(origins_shutdown_rx);
    None
};
```

**Shutdown cleanup pattern** (from `service.rs` lines 650-655, adapted):
```rust
// Stop the managed origins poll task.
let _ = origins_shutdown_tx.send(true);
if let Some(h) = _origins_poll_handle {
    let _ = h.await;
}
```

---

### `dlp-common/src/audit.rs` (model, transform)

**Analog:** Existing `AuditEvent` optional field pattern (Phase 22 fields)

**New field pattern** (from `audit.rs` lines 159-167, adapted):
```rust
/// Resolved identity of the application that initiated the operation
/// (populated by Phase 25 for clipboard events).
#[serde(skip_serializing_if = "Option::is_none")]
pub source_application: Option<AppIdentity>,
/// Resolved identity of the destination application (e.g. the paste target).
#[serde(skip_serializing_if = "Option::is_none")]
pub destination_application: Option<AppIdentity>,
/// USB device identity for block events involving removable storage
/// (populated by Phase 26/27 on USB blocks).
#[serde(skip_serializing_if = "Option::is_none")]
pub device_identity: Option<DeviceIdentity>,
```

**Fields to add** (after `device_identity`, before the closing brace of the struct):
```rust
/// Source origin URL for Chrome Content Analysis clipboard events
/// (populated by Phase 29 Chrome Enterprise Connector).
#[serde(skip_serializing_if = "Option::is_none")]
pub source_origin: Option<String>,
/// Destination origin URL for Chrome Content Analysis clipboard events
/// (populated by Phase 29 Chrome Enterprise Connector).
#[serde(skip_serializing_if = "Option::is_none")]
pub destination_origin: Option<String>,
```

**Builder method pattern** (from `audit.rs` lines 277-293, adapted):
```rust
/// Sets the source origin for Chrome Content Analysis events.
pub fn with_source_origin(mut self, origin: Option<String>) -> Self {
    self.source_origin = origin;
    self
}

/// Sets the destination origin for Chrome Content Analysis events.
pub fn with_destination_origin(mut self, origin: Option<String>) -> Self {
    self.destination_origin = origin;
    self
}
```

**Default initialization** (from `audit.rs` lines 218-220, adapted):
Add to `AuditEvent::new()`:
```rust
source_origin: None,
destination_origin: None,
```

**Test pattern** (from `audit.rs` lines 377-401, adapted):
Add assertions in `test_skip_serializing_none_fields`:
```rust
assert!(!json.contains("\"source_origin\":null"));
assert!(!json.contains("\"destination_origin\":null"));
```

Add a backward-compat test (from `audit.rs` lines 512-533, adapted):
```rust
#[test]
fn test_audit_event_backward_compat_missing_origin_fields() {
    let legacy = r#"{ ... same as existing test ... }"#;
    let event: AuditEvent = serde_json::from_str(legacy).unwrap();
    assert!(event.source_origin.is_none());
    assert!(event.destination_origin.is_none());
}
```

---

### `dlp-agent/src/server_client.rs` (service, request-response)

**Analog:** Existing `fetch_device_registry()` method (lines 379-402)

**New method pattern** (adapted from `fetch_device_registry`):
```rust
/// Fetches the managed origins list from `GET /admin/managed-origins`.
///
/// Returns a JSON array of [`ManagedOriginEntry`] objects. The endpoint is
/// unauthenticated — agents do not send a JWT (D-06 from 28-CONTEXT.md).
///
/// # Errors
///
/// Returns [`ServerClientError::Http`] if the HTTP request fails.
/// Returns [`ServerClientError::ServerError`] if the response status is not 2xx.
pub async fn fetch_managed_origins(
    &self,
) -> Result<Vec<ManagedOriginEntry>, ServerClientError> {
    let url = format!("{}/admin/managed-origins", self.base_url);
    let response = self
        .client
        .get(&url)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(ServerClientError::ServerError { status, body });
    }
    let entries = response
        .json::<Vec<ManagedOriginEntry>>()
        .await
        .map_err(ServerClientError::Http)?;
    Ok(entries)
}
```

**New type** (after `DeviceRegistryEntry`, following same pattern):
```rust
/// A single entry from the `GET /admin/managed-origins` response.
///
/// Matches the `ManagedOriginResponse` shape returned by `dlp-server`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ManagedOriginEntry {
    /// Server-generated UUID for the origin row.
    pub id: String,
    /// The origin pattern string (e.g., "https://sharepoint.com").
    pub origin: String,
}
```

**Test pattern** (adapted from `test_fetch_device_registry_unreachable_server`):
```rust
#[tokio::test]
async fn test_fetch_managed_origins_unreachable_server() {
    let client = unreachable_client();
    let result = client.fetch_managed_origins().await;
    assert!(result.is_err(), "unreachable server must return Err");
}
```

---

### `dlp-agent/tests/chrome_pipe.rs` (test, request-response)

**Analog:** `dlp-agent/tests/device_registry_cache.rs`

**Pattern to follow:** Use the `#[test]` attribute, `cargo test` framework. Create a mock `ManagedOriginsCache`, seed it with test origins, and verify the decision logic. For pipe-level tests, use a mock pipe client that writes a protobuf frame and reads the response.

---

## Shared Patterns

### Authentication / Authorization
**Source:** `dlp-agent/src/ipc/pipe_security.rs`
**Apply to:** `chrome/handler.rs` (pipe creation)
```rust
let sec = super::pipe_security::PipeSecurity::new().context("pipe security descriptor")?;
```
The Chrome pipe should reuse the same `PipeSecurity` DACL (Authenticated Users read/write, SYSTEM/Admin full control). Chrome runs as the interactive user and needs to connect to the SYSTEM-owned pipe.

### Error Handling
**Source:** `dlp-agent/src/ipc/pipe1.rs` lines 128-139
**Apply to:** All Chrome pipe operations
```rust
if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
    let win32_code = (e.code().0 as u32) & 0xFFFF;
    if win32_code != 535 {
        warn!(win32_code, "ConnectNamedPipe failed — recycling pipe");
        // cleanup and recreate
    }
}
```
Pattern: Extract Win32 error code with `(e.code().0 as u32) & 0xFFFF`, compare against known constants (535 = ERROR_PIPE_CONNECTED, which is success), log with `warn!`, recycle pipe on real errors.

### Logging / Tracing
**Source:** `dlp-agent/src/service.rs` lines 71-75
**Apply to:** All new Chrome modules
```rust
use tracing::{debug, error, info, warn};
// All entry points log at info! level
// All errors log at warn! or error! level
// All debug data logs at debug! level
```

### Env Var Test Overrides
**Source:** `dlp-agent/src/service.rs` lines 1009-1013
**Apply to:** `chrome/registry.rs`
```rust
if std::env::var("DLP_SKIP_CHROME_REG").is_ok_and(|v| v == "1") {
    info!("Chrome registry registration skipped (DLP_SKIP_CHROME_REG=1)");
    return Ok(());
}
```
Consistent with existing `DLP_SKIP_IPC`, `DLP_SKIP_HARDENING` pattern.

### Audit Emission
**Source:** `dlp-agent/src/audit_emitter.rs` lines 269-299
**Apply to:** `chrome/handler.rs` (on BLOCK decision)
```rust
pub fn emit_audit(ctx: &EmitContext, event: &mut AuditEvent) {
    event.agent_id.clone_from(&ctx.agent_id);
    event.session_id = ctx.session_id;
    // ... identity fill ...
    if let Err(e) = EMITTER.emit(event) {
        error!(error = %e, "audit emission failed -- event dropped");
    }
    if let Some(buffer) = AUDIT_BUFFER.get() {
        buffer.enqueue(event.clone());
    }
}
```

### Shutdown Signaling
**Source:** `dlp-agent/src/service.rs` lines 495-500
**Apply to:** `chrome/cache.rs` poll task
```rust
let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
// Spawn task with shutdown_rx
// On shutdown: shutdown_tx.send(true)
// Task uses: tokio::select! { _ = interval.tick() => ..., _ = shutdown.changed() => return }
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `dlp-agent/proto/content_analysis.proto` | config | static | Vendored proto file — no existing proto in codebase; use RESEARCH.md example |

---

## Metadata

**Analog search scope:** `dlp-agent/src/`, `dlp-common/src/`, `dlp-server/src/`, `dlp-user-ui/`
**Files scanned:** 12
**Pattern extraction date:** 2026-04-29

**Key design decisions captured:**
1. Chrome pipe server runs on dedicated `std::thread` (NOT tokio task) — same pattern as P1/P2/P3
2. `ManagedOriginsCache` mirrors `DeviceRegistryCache` exactly: `RwLock<HashSet<String>>`, 30s poll, `spawn_poll_task`
3. HKLM registration is best-effort (warn + continue on failure) with `DLP_SKIP_CHROME_REG=1` test override
4. Audit fields use `#[serde(skip_serializing_if = "Option::is_none")]` + builder methods — identical to Phase 22 pattern
5. Frame protocol reuses `ipc/frame.rs` exactly — only `MAX_PAYLOAD` differs (4 MiB vs 64 MiB)
6. `server_client.rs` adds `fetch_managed_origins()` following the exact pattern of `fetch_device_registry()`
7. `build.rs` uses `prost-build` with `cargo:rerun-if-changed` — no existing build.rs in dlp-agent, pattern from dlp-user-ui + RESEARCH.md
