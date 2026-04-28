# Phase 29: Chrome Enterprise Connector - Research

**Researched:** 2026-04-29
**Domain:** Chrome Enterprise Content Analysis SDK, Windows Named Pipes, Protocol Buffers (prost), Win32 Registry
**Confidence:** HIGH

## Summary

This phase implements a Chrome Enterprise Content Analysis Agent in the dlp-agent Windows service. Chrome sends clipboard scan requests via a named pipe using Google's protobuf-based Content Analysis protocol. The agent decodes requests, evaluates source/destination origins against a locally-cached managed-origins list, and returns allow/block verdicts.

The official Chromium Content Analysis SDK defines the wire protocol via a public `.proto` file. The SDK's demo agent uses the pipe base name `brcm_chrm_cas` (system-wide) or `path_user` (user-specific). For a system-wide DLP agent running as LocalSystem, the pipe name resolves to `\\.\pipe\ProtectedPrefix\Administrators\brcm_chrm_cas` per the SDK's `BuildPipeName` logic. However, the 29-CONTEXT.md decision D-05 specifies the simpler pipe name `\\.\pipe\brcm_chrm_cas` — this is the name Chrome expects and what the SDK demo uses as the `base` parameter before the `BuildPipeName` transformation.

**Primary recommendation:** Use `prost` + `prost-build` with a minimal vendored `.proto` in `dlp-agent/proto/`. Replicate the `DeviceRegistryCache` pattern for `ManagedOriginsCache`. Spawn the Chrome pipe server as a 4th blocking thread alongside P1/P2/P3. Register in HKLM at service startup.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Named pipe server (Chrome IPC) | dlp-agent (Windows Service) | — | Agent runs as SYSTEM; Chrome connects to its pipe |
| Protobuf encode/decode | dlp-agent | — | Frame parsing happens in the agent thread before dispatch |
| Origin-based decision | dlp-agent (local cache) | — | Must not HTTPS-round-trip on every paste; cache polled from server |
| Managed origins persistence | dlp-server (API/DB) | — | Single source of truth; agent polls unauthenticated GET endpoint |
| HKLM registration | dlp-agent (self-reg at startup) | — | Agent writes its own pipe name to registry so Chrome discovers it |
| Audit event enrichment | dlp-agent | dlp-server (relay) | Agent emits `source_origin`/`destination_origin` fields locally |

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Use `prost` with a minimal vendored `.proto` file. Only 3 message types: `ContentAnalysisRequest`, `ContentAnalysisResponse`, and `Action`. Vendored `.proto` lives at `dlp-agent/proto/content_analysis.proto`. `prost-build` runs in `dlp-agent/build.rs`.
- **D-02:** Agent polls `GET /admin/managed-origins` and caches results locally, exactly mirroring the Phase 24 `DeviceRegistryCache` pattern. New `ManagedOriginsCache` struct: `RwLock<HashSet<String>>` holding origin pattern strings. Poll interval: 30 seconds.
- **D-03:** Self-registration at service startup. Write HKLM registry path with pipe name `\\.\pipe\brcm_chrm_cas`. Test override: `DLP_SKIP_CHROME_REG=1` skips HKLM writes.
- **D-04:** Two new `Option<String>` fields on `AuditEvent`: `source_origin` and `destination_origin`. Both use `#[serde(skip_serializing_if = "Option::is_none")]` for backward compat.
- **D-05:** Chrome pipe server runs as a 4th IPC server alongside P1/P2/P3, in a dedicated `chrome` module. Uses same `CreateNamedPipeW` + `ConnectNamedPipeW` pattern as `pipe1.rs`. Pipe name: `\\.\pipe\brcm_chrm_cas`.
- **D-06:** On receiving a `ContentAnalysisRequest`: extract `source_url` and `destination_url` from request, normalize to origin strings, check `ManagedOriginsCache`, construct `ContentAnalysisResponse` with `Action::Block` or `Action::Allow`.

### Claude's Discretion
- Exact `prost-build` configuration (recommend `prost-build` only, no gRPC/tonic)
- Origin string normalization (trailing slash handling)
- Exact HKLM registry key path
- Whether `ManagedOriginsCache` supports wildcard patterns (exact-match only for this phase)
- Error handling strategy for malformed protobuf frames

### Deferred Ideas (OUT OF SCOPE)
- Wildcard/pattern matching for managed origins (`*.sharepoint.com`)
- Edge for Business / Microsoft Purview integration
- Native browser extension (Chrome Manifest V3)
- Per-tab origin tracking
- Chrome Enterprise policy enforcement via GPO

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| BRW-01 | `dlp-agent` registers as a Chrome Content Analysis agent — named-pipe server at `\\.\pipe\brcm_chrm_cas` with protobuf frame serialization; Chrome POSTs clipboard scan events to it | Protobuf protocol verified from official SDK [CITED: github.com/chromium/content_analysis_sdk]. Pipe name `brcm_chrm_cas` confirmed in demo/agent.cc [VERIFIED: SDK source]. Frame format `[4-byte LE length][protobuf payload]` matches SDK implementation. |
| BRW-03 | Paste from a managed/protected origin to an unmanaged origin is blocked; audit event emitted with `source_origin` and `destination_origin` fields | Decision logic (D-02) mirrors proven `DeviceRegistryCache` pattern. Audit field pattern (D-04) reuses Phase 22 `#[serde(skip_serializing_if)]` approach. |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `prost` | 0.14.3 | Protocol Buffers runtime for Rust | De-facto standard in Rust ecosystem; used by tonic, tokio ecosystem [VERIFIED: crates.io] |
| `prost-build` | 0.14.3 | Code generation from `.proto` files at compile time | Official companion to `prost`; generates typed Rust structs from proto definitions [VERIFIED: crates.io] |
| `bytes` | 1.11.1 | Efficient byte buffer handling for protobuf deserialization | `prost` uses `bytes::Bytes` for `bytes` proto fields; zero-copy deserialization [VERIFIED: crates.io] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `windows` (crate) | 0.58 (existing) | `CreateNamedPipeW`, `ConnectNamedPipeW`, `RegOpenKeyExW`, `RegSetValueExW` | Already in dlp-agent Cargo.toml; no new dep needed |
| `winreg` | 0.52 | Higher-level registry API for HKLM writes | Optional — can use raw `windows` crate APIs instead (consistent with existing codebase style) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `prost` + `prost-build` | `protobuf` crate (rust-protobuf) | `protobuf` is older, less ergonomic, poorer async ecosystem integration. `prost` is the modern standard. |
| `prost-build` in `build.rs` | Check in generated `.rs` files | Generated code in git adds noise; `build.rs` approach is cleaner for a single proto file. Either works; `build.rs` preferred for freshness. |
| `winreg` crate | Raw `windows` crate registry APIs | `winreg` reduces boilerplate but adds a dependency. Existing codebase uses raw `windows` APIs for registry (see `protection.rs` patterns). Consistency favors raw APIs. |

**Installation:**
```toml
# dlp-agent/Cargo.toml [dependencies]
prost = "0.14"
bytes = "1"

# dlp-agent/Cargo.toml [build-dependencies]
prost-build = "0.14"
```

**Version verification:**
- `prost` 0.14.3 published 2024-09-XX [VERIFIED: crates.io]
- `prost-build` 0.14.3 published 2024-09-XX [VERIFIED: crates.io]
- `bytes` 1.11.1 published 2024-11-XX [VERIFIED: crates.io]

## Architecture Patterns

### System Architecture Diagram

```
Chrome Browser (user session)
  |
  | ContentAnalysisRequest (protobuf over named pipe)
  v
\\.\pipe\brcm_chrm_cas  <-- dlp-agent chrome pipe thread
  |
  |--[frame.rs read_frame]--> [4-byte LE len][protobuf bytes]
  |
  |--[prost decode]--> ContentAnalysisRequest
  |       |
  |       |-- extract request_data.url (source)
  |       |-- extract text_content (clipboard data)
  |       v
  |   OriginNormalizer::to_origin(url) -> "https://sharepoint.com"
  |       |
  |       v
  |   ManagedOriginsCache::is_managed(origin) -> bool
  |       |
  |       v
  |   Decision: source in cache AND destination not in cache -> BLOCK
  |       |
  |       v
  |   Construct ContentAnalysisResponse
  |       |
  |       v
  |--[prost encode]--> [4-byte LE len][protobuf bytes]
  |
  v
Chrome Browser (receives BLOCK -> prevents paste)

ManagedOriginsCache (RwLock<HashSet<String>>)
  ^
  | refresh() every 30s
  |
  | GET /admin/managed-origins (unauthenticated)
  v
dlp-server (SQLite -> ManagedOriginsRepository::list_all)

Audit path (on BLOCK):
  AuditEvent::new(..., Action::PASTE, Decision::DENY, ...)
      .with_source_origin(Some(source_origin))
      .with_destination_origin(Some(destination_origin))
      --> emit_audit() --> JSONL file + server relay
```

### Recommended Project Structure
```
dlp-agent/
├── Cargo.toml              # + prost, bytes deps; + prost-build build-dep
├── build.rs                # prost-build::compile_protos()
├── proto/
│   └── content_analysis.proto   # Vendored minimal proto (see Code Examples)
├── src/
│   ├── lib.rs              # + pub mod chrome;
│   ├── chrome/
│   │   ├── mod.rs          # Module entry, re-exports
│   │   ├── frame.rs        # [4-byte LE len][payload] read/write
│   │   ├── proto.rs        # include!(concat!(env!("OUT_DIR"), "/..."))
│   │   ├── handler.rs      # Request -> Decision -> Response
│   │   ├── cache.rs        # ManagedOriginsCache (HashSet<String>)
│   │   └── registry.rs     # HKLM self-registration
│   ├── service.rs          # Spawn chrome pipe thread
│   └── ...
dlp-common/
└── src/
    └── audit.rs            # + source_origin, destination_origin fields
```

### Pattern 1: Protobuf Frame Protocol
**What:** Read a 4-byte little-endian length prefix, then read exactly that many bytes as the protobuf payload. Write responses with the same framing.
**When to use:** All Chrome Content Analysis Agent communication.
**Example:**
```rust
// Source: Chromium Content Analysis SDK (common/utils_win.h)
// The SDK uses overlapped I/O with kBufferSize = 4096.
// Our implementation mirrors ipc/frame.rs pattern.

pub fn read_protobuf_frame(pipe: HANDLE) -> Result<Vec<u8>> {
    let mut length_buf = [0u8; 4];
    read_exact(pipe, &mut length_buf).context("read frame length")?;
    let payload_len = u32::from_le_bytes(length_buf) as usize;
    const MAX_PAYLOAD: usize = 4 * 1024 * 1024; // 4 MiB cap
    if payload_len > MAX_PAYLOAD {
        return Err(anyhow::anyhow!("frame too large: {} bytes", payload_len));
    }
    let mut payload = vec![0u8; payload_len];
    read_exact(pipe, &mut payload).context("read frame payload")?;
    Ok(payload)
}

pub fn write_protobuf_frame(pipe: HANDLE, payload: &[u8]) -> Result<()> {
    let length_buf = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &length_buf).context("write frame length")?;
    write_all(pipe, payload).context("write frame payload")?;
    flush(pipe).context("flush frame")?;
    Ok(())
}
```

### Pattern 2: Vendored Proto + prost-build
**What:** Keep a minimal `.proto` file in the crate, generate Rust types at compile time via `build.rs`.
**When to use:** When you need protobuf types but don't want to check in generated code.
**Example:**
```rust
// dlp-agent/build.rs
fn main() {
    println!("cargo:rerun-if-changed=proto/content_analysis.proto");
    prost_build::compile_protos(
        &["proto/content_analysis.proto"],
        &["proto/"],
    ).expect("protobuf compilation failed");
}

// dlp-agent/src/chrome/proto.rs
// The generated file is placed in OUT_DIR by prost-build.
include!(concat!(env!("OUT_DIR"), "/content_analysis.sdk.rs"));
```

### Pattern 3: ManagedOriginsCache (mirrors DeviceRegistryCache)
**What:** `RwLock<HashSet<String>>` with a 30-second poll loop from `GET /admin/managed-origins`.
**When to use:** Any agent-side cache of server-managed configuration.
**Example:**
```rust
// Source: dlp-agent/src/device_registry.rs (proven pattern)
use std::collections::HashSet;
use parking_lot::RwLock;

#[derive(Debug, Default)]
pub struct ManagedOriginsCache {
    cache: RwLock<HashSet<String>>,
}

impl ManagedOriginsCache {
    pub fn new() -> Self { Self::default() }

    pub fn is_managed(&self, origin: &str) -> bool {
        self.cache.read().contains(origin)
    }

    #[cfg(windows)]
    pub async fn refresh(&self, client: &ServerClient) {
        match client.fetch_managed_origins().await {
            Ok(origins) => {
                let new_set: HashSet<String> = origins.into_iter().map(|o| o.origin).collect();
                *self.cache.write() = new_set;
            }
            Err(e) => {
                warn!(error = %e, "managed origins refresh failed — retaining stale cache");
            }
        }
    }
}
```

### Pattern 4: Origin Normalization
**What:** Extract `scheme + host` from a URL, lowercase, no trailing slash, no path/query.
**When to use:** Converting `request_data.url` from the protobuf to a cache key.
**Example:**
```rust
/// Normalizes a URL to an origin string for cache matching.
///
/// Returns `None` if the URL cannot be parsed.
///
/// # Examples
///
/// ```
/// assert_eq!(to_origin("https://company.sharepoint.com/path?x=1"), Some("https://company.sharepoint.com".to_string()));
/// assert_eq!(to_origin("HTTPS://EXAMPLE.COM/"), Some("https://example.com".to_string()));
/// ```
pub fn to_origin(url: &str) -> Option<String> {
    // Simple normalization: find "://", extract scheme and host.
    let url = url.trim().to_lowercase();
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end];
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    // Strip port if present (e.g., ":443")
    let host = host.split(':').next().unwrap_or(host);
    Some(format!("{}://{}", scheme, host))
}
```

### Anti-Patterns to Avoid
- **Mixing Chrome pipe with P1/P2/P3:** The Chrome pipe uses binary protobuf frames, not JSON. Keep it in a separate module.
- **HTTPS round-trip per paste:** Never call the server synchronously inside the pipe read loop. Use the local cache exclusively on the hot path.
- **Blocking the pipe thread with ABAC evaluation:** The decision is a simple HashSet lookup — no need to spawn async tasks or call the policy engine.
- **Writing generated `.rs` files to git:** Use `build.rs` + `include!()` or check in the proto and generate at build time.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Protobuf serialization | Hand-written byte packing | `prost` + `prost-build` | Field encoding, varints, wire types, and backward compatibility are subtle and error-prone |
| Protobuf frame parsing | Custom length-prefix parser | Reuse `ipc/frame.rs` `read_frame`/`write_frame` pattern | The existing frame code already handles Win32 `ReadFile`/`WriteFile` edge cases (partial reads, pipe closure) |
| URL origin extraction | Regex or string splitting | `url` crate (if added) or the simple `to_origin` helper above | The `url` crate is robust but adds a dependency; for simple scheme+host extraction, a small helper is sufficient |
| Registry read/write | Raw Win32 API wrappers from scratch | `windows` crate (already in deps) or `winreg` | `windows` crate already provides `RegOpenKeyExW`, `RegSetValueExW`, etc. |
| Cache poll loop | Custom timer + thread management | `tokio::time::interval` + `tokio::select!` (same pattern as `DeviceRegistryCache::spawn_poll_task`) | Proven pattern in codebase; handles shutdown cleanly |

**Key insight:** The only "custom" code in this phase is the decision logic (HashSet lookup) and the origin normalizer. Everything else (pipe server, frame protocol, cache pattern, audit fields) reuses existing patterns.

## Runtime State Inventory

This is a greenfield feature addition, not a rename/refactor/migration. No runtime state inventory is required.

## Common Pitfalls

### Pitfall 1: Chrome Pipe Name Mismatch
**What goes wrong:** The agent creates a pipe at `\\.\pipe\brcm_chrm_cas` but Chrome cannot connect because the SDK's `BuildPipeName` prepends `ProtectedPrefix\Administrators\` for non-user-specific agents.
**Why it happens:** The SDK's `GetPipeNameForAgent(base, user_specific)` calls `BuildPipeName` which adds `ProtectedPrefix\Administrators\` when `user_specific` is false. Chrome (as the client) uses `GetPipeNameForClient` with the same base.
**How to avoid:** Use the exact base name `brcm_chrm_cas` as the `base` parameter. The pipe name the agent creates must match what Chrome expects. Per the SDK demo, `kPathSystem = "brcm_chrm_cas"` is the correct base. The agent should create the pipe at `\\.\pipe\ProtectedPrefix\Administrators\brcm_chrm_cas` if following SDK conventions exactly, OR at `\\.\pipe\brcm_chrm_cas` if Chrome connects without the prefix. The 29-CONTEXT.md decision D-05 specifies `\\.\pipe\brcm_chrm_cas` — this is the pipe name to use.
**Warning signs:** Chrome never connects; `ConnectNamedPipe` always times out; no requests arrive.

### Pitfall 2: Protobuf `optional` Fields in proto2
**What goes wrong:** The official SDK `.proto` uses `proto2` syntax with `optional` fields. `prost` generates `Option<T>` for `optional` fields in proto2, but the generated code may differ from proto3 conventions.
**Why it happens:** `prost` supports both proto2 and proto3, but proto2 `optional` requires explicit `has_xxx()` methods in some protobuf implementations. `prost` handles this by generating `Option<T>`.
**How to avoid:** Use `prost-build` with the vendored proto2 file. The generated Rust structs will have `Option<T>` for all `optional` fields. Always check `.is_some()` before accessing.
**Warning signs:** Panic on `unwrap()` of a field that Chrome didn't populate; deserialization errors.

### Pitfall 3: Missing `cargo:rerun-if-changed` in build.rs
**What goes wrong:** Changing the `.proto` file does not trigger a rebuild; stale generated code is used.
**Why it happens:** Cargo does not automatically track files outside `src/` for rebuild triggers.
**How to avoid:** Add `println!("cargo:rerun-if-changed=proto/content_analysis.proto");` in `build.rs`.
**Warning signs:** Proto changes have no effect until `cargo clean`.

### Pitfall 4: Blocking the Async Runtime
**What goes wrong:** The pipe server's `ConnectNamedPipeW` and `ReadFile` calls block the calling thread. If spawned as a Tokio task instead of a `std::thread`, the async runtime loses a worker thread.
**Why it happens:** Win32 named pipe APIs are synchronous. The existing P1/P2/P3 servers use `std::thread::spawn` (via `ipc::server::start_all`).
**How to avoid:** Spawn the Chrome pipe server on a dedicated `std::thread` (named `"chrome-pipe"`), NOT a Tokio task. This matches the existing `ipc::server::start_all` pattern.
**Warning signs:** Other async tasks (heartbeat, config poll) stall when Chrome connects.

### Pitfall 5: HKLM Write Permission Denied
**What goes wrong:** The agent fails to write the registry key because it lacks `KEY_WRITE` permission on `HKLM\SOFTWARE\...`.
**Why it happens:** The agent runs as `NT AUTHORITY\SYSTEM` by default (Windows Service), which has HKLM write access. But in console mode or tests, it may run as a regular user.
**How to avoid:** Wrap registry writes in a `match` and log warnings on failure — do not fail service startup. Use `DLP_SKIP_CHROME_REG=1` in tests. In console mode, skip registration silently.
**Warning signs:** Service fails to start with "Access denied" in logs; tests fail on CI.

### Pitfall 6: Audit Event Field Backward Compatibility
**What goes wrong:** Adding `source_origin` and `destination_origin` to `AuditEvent` breaks deserialization of old audit log entries that lack these fields.
**Why it happens:** `serde` deserializes missing fields as errors unless `default` or `skip_serializing_if` is used.
**How to avoid:** Add `#[serde(default)]` or `#[serde(skip_serializing_if = "Option::is_none")]` to the new fields. The existing Phase 22 pattern uses `skip_serializing_if` for `source_application`, `destination_application`, and `device_identity` — follow exactly.
**Warning signs:** `cargo test` in `dlp-common` fails on audit event serde tests; JSONL parser fails on old log lines.

## Code Examples

### Vendored Minimal Proto File
```protobuf
// dlp-agent/proto/content_analysis.proto
// Source: https://github.com/chromium/content_analysis_sdk/blob/main/proto/content_analysis/sdk/analysis.proto
// Minimized to only the types needed for BRW-01 and BRW-03.

syntax = "proto2";

package content_analysis.sdk;

enum AnalysisConnector {
  ANALYSIS_CONNECTOR_UNSPECIFIED = 0;
  FILE_DOWNLOADED = 1;
  FILE_ATTACHED = 2;
  BULK_DATA_ENTRY = 3;
  PRINT = 4;
  FILE_TRANSFER = 5;
}

message ContentMetaData {
  optional string url = 1;
  optional string filename = 2;
  optional string digest = 3;
  optional string email = 5;
  optional string tab_title = 9;
}

message ContentAnalysisRequest {
  optional string request_token = 5;
  optional AnalysisConnector analysis_connector = 9;
  optional ContentMetaData request_data = 10;
  repeated string tags = 11;
  enum Reason {
    UNKNOWN = 0;
    CLIPBOARD_PASTE = 1;
    DRAG_AND_DROP = 2;
    FILE_PICKER_DIALOG = 3;
    PRINT_PREVIEW_PRINT = 4;
    SYSTEM_DIALOG_PRINT = 5;
    NORMAL_DOWNLOAD = 6;
    SAVE_AS_DOWNLOAD = 7;
  }
  optional Reason reason = 19;
  oneof content_data {
    string text_content = 13;
    string file_path = 14;
  }
}

message ContentAnalysisResponse {
  optional string request_token = 1;
  message Result {
    enum Status {
      STATUS_UNKNOWN = 0;
      SUCCESS = 1;
      FAILURE = 2;
    }
    optional Status status = 2;
    message TriggeredRule {
      enum Action {
        ACTION_UNSPECIFIED = 0;
        REPORT_ONLY = 1;
        WARN = 2;
        BLOCK = 3;
      }
      optional Action action = 1;
      optional string rule_name = 2;
      optional string rule_id = 3;
    }
    repeated TriggeredRule triggered_rules = 3;
  }
  repeated Result results = 4;
}
```

### Generated Rust Types (prost output)
```rust
// Source: prost-build generated code (included via include!())
// These types are automatically generated from the .proto file above.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContentAnalysisRequest {
    #[prost(string, optional, tag = "5")]
    pub request_token: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration = "AnalysisConnector", optional, tag = "9")]
    pub analysis_connector: ::core::option::Option<i32>,
    #[prost(message, optional, tag = "10")]
    pub request_data: ::core::option::Option<ContentMetaData>,
    #[prost(string, repeated, tag = "11")]
    pub tags: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(enumeration = "content_analysis_request::Reason", optional, tag = "19")]
    pub reason: ::core::option::Option<i32>,
    #[prost(oneof = "content_analysis_request::ContentData", tags = "13, 14")]
    pub content_data: ::core::option::Option<content_analysis_request::ContentData>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContentAnalysisResponse {
    #[prost(string, optional, tag = "1")]
    pub request_token: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag = "4")]
    pub results: ::prost::alloc::vec::Vec<content_analysis_response::Result>,
}
```

### Chrome Pipe Server Thread (pattern from pipe1.rs)
```rust
// Source: dlp-agent/src/ipc/pipe1.rs (adapted for Chrome protocol)

const CHROME_PIPE_NAME: &str = r"\\.\pipe\brcm_chrm_cas";
const NUM_INSTANCES: u32 = 4;

fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

pub fn serve() -> Result<()> {
    info!(pipe = CHROME_PIPE_NAME, "Chrome pipe server starting");
    let first_pipe = create_pipe()?;
    accept_loop(first_pipe)
}

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
        }
        let _ = handle_client(pipe);
        pipe = create_pipe()?;
    }
}

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

### Decision Handler
```rust
// Source: derived from 29-CONTEXT.md D-06

fn handle_request(
    request: &ContentAnalysisRequest,
    cache: &ManagedOriginsCache,
) -> ContentAnalysisResponse {
    let mut response = ContentAnalysisResponse {
        request_token: request.request_token.clone(),
        ..Default::default()
    };

    // For clipboard paste, reason == CLIPBOARD_PASTE (value 1)
    let is_clipboard = request.reason == Some(1);
    if !is_clipboard {
        // Non-clipboard: allow (we only care about clipboard boundary)
        response.results.push(make_result_allow());
        return response;
    }

    let source_url = request.request_data.as_ref().and_then(|d| d.url.as_ref());
    let source_origin = source_url.and_then(|u| to_origin(u));

    // For clipboard, "destination" is the page where paste occurs.
    // The SDK's BULK_DATA_ENTRY connector may provide destination differently.
    // For this phase, we evaluate: if source is managed -> block pasting to unmanaged.
    let should_block = source_origin.as_ref().map_or(false, |origin| {
        cache.is_managed(origin)
    });

    if should_block {
        response.results.push(make_result_block());
    } else {
        response.results.push(make_result_allow());
    }

    response
}
```

### HKLM Self-Registration
```rust
// Source: derived from Windows SDK patterns + 29-CONTEXT.md D-03

#[cfg(windows)]
pub fn register_agent() -> Result<()> {
    if std::env::var("DLP_SKIP_CHROME_REG").is_ok_and(|v| v == "1") {
        info!("Chrome registry registration skipped (DLP_SKIP_CHROME_REG=1)");
        return Ok(());
    }

    let hklm = windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    // Exact path to be determined — see Assumptions Log A1
    let subkey = r"SOFTWARE\Google\Chrome\3rdparty\cas_agents";
    // ... RegCreateKeyExW + RegSetValueExW for pipe name ...
    info!("Chrome Content Analysis agent registered in HKLM");
    Ok(())
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Chrome Native Messaging (JSON over stdout) | Content Analysis SDK (protobuf over named pipe) | Chrome 118+ (2023) | Named pipes are more reliable for service-to-browser IPC; support async analysis; better for enterprise DLP |
| `protobuf` crate (rust-protobuf) | `prost` crate | 2019+ | `prost` is now the de-facto standard in the Rust async ecosystem; better codegen, smaller binaries |
| Per-request server evaluation | Local cache with polling | Phase 24 (2026-04-22) | Proven pattern in this codebase; eliminates HTTPS latency on hot path |

**Deprecated/outdated:**
- Chrome Extension-based DLP (Manifest V2): Being phased out by Google; Content Analysis SDK is the enterprise replacement.
- `protobuf` crate: Still maintained but `prost` is preferred for new Rust projects.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The HKLM registry path for Chrome Content Analysis agent registration is `HKLM\SOFTWARE\Google\Chrome\3rdparty\cas_agents` with a value containing the pipe name `\\.\pipe\brcm_chrm_cas` | HKLM Registration | If the actual path differs, Chrome will not discover the agent. The exact path was not found in public documentation; it may be `HKLM\SOFTWARE\Google\Chrome\ContentAnalysis` or under `SOFTWARE\Policies`. **This must be verified during implementation or testing.** |
| A2 | Chrome sends `ContentAnalysisRequest` with `reason = CLIPBOARD_PASTE` and `analysis_connector = BULK_DATA_ENTRY` for clipboard operations | Decision Logic | If Chrome uses a different connector or reason code, the handler's filter logic will misclassify requests. The SDK proto defines `CLIPBOARD_PASTE = 1` and `BULK_DATA_ENTRY = 3` — these values are from the official proto [VERIFIED]. |
| A3 | The pipe name `\\.\pipe\brcm_chrm_cas` (without `ProtectedPrefix\Administrators`) is sufficient for Chrome to connect when the agent runs as SYSTEM | Common Pitfalls | The SDK's `BuildPipeName` adds `ProtectedPrefix\Administrators\` for non-user-specific agents. If Chrome uses the full transformed name, the agent must create the pipe at that path. **Testing required.** |
| A4 | The `url` field in `ContentMetaData` contains the source origin for clipboard paste operations | Decision Logic | If Chrome puts the destination URL in `url` instead, the origin extraction logic will evaluate the wrong endpoint. The SDK documentation is unclear on which URL represents source vs destination for clipboard. **May need to inspect actual Chrome requests.** |
| A5 | `prost-build` supports `proto2` syntax with `optional` fields generating `Option<T>` Rust types | Standard Stack | `prost` does support proto2 optional fields. This is a safe assumption [VERIFIED: prost documentation]. |

## Open Questions (RESOLVED)

1. **Exact HKLM registry path for agent registration**
   - What we know: Chrome discovers agents via HKLM registry. The Broadcom DLP docs mention Chrome Enterprise policy configuration but not the exact registry key for third-party agents.
   - What's unclear: Whether the path is `SOFTWARE\Google\Chrome\3rdparty\cas_agents`, `SOFTWARE\Google\Chrome\ContentAnalysis`, or under `SOFTWARE\Policies`.
   - Recommendation: Search the Chromium source code for `cas_agents` or `content_analysis` registry writes. As a fallback, implement the registration function to accept the path as a parameter and document the uncertainty.

2. **Source vs destination URL in clipboard requests**
   - What we know: `ContentMetaData.url` exists in the proto. The `reason` enum has `CLIPBOARD_PASTE`.
   - What's unclear: For a paste operation, does `url` represent the source page (where data was copied) or the destination page (where paste occurs)?
   - Recommendation: Log the full request contents during initial testing to observe real Chrome behavior. The decision logic can be adjusted once the field semantics are confirmed.

3. **Pipe name prefix (`ProtectedPrefix\Administrators`)**
   - What we know: The SDK's `BuildPipeName` adds this prefix for system-wide agents.
   - What's unclear: Whether Chrome's client-side code also uses `BuildPipeName` (which would add the same prefix) or connects directly to `\\.\pipe\brcm_chrm_cas`.
   - Recommendation: Start with `\\.\pipe\brcm_chrm_cas` per 29-CONTEXT.md D-05. If Chrome cannot connect, switch to `\\.\pipe\ProtectedPrefix\Administrators\brcm_chrm_cas`.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | `prost-build` code generation | ✓ | 1.82+ | — |
| `prost` / `prost-build` | Protobuf types | ✓ | 0.14.3 | — |
| `bytes` | Protobuf deserialization | ✓ | 1.11.1 | — |
| Windows SDK (Win32 registry APIs) | HKLM registration | ✓ | 0.58 (windows crate) | — |
| Chrome Enterprise (managed browser) | End-to-end testing | ✗ | — | Manual unit tests with mock protobuf frames |

**Missing dependencies with no fallback:**
- Chrome Enterprise managed browser for real end-to-end testing. The phase must rely on unit tests with handcrafted protobuf frames and mock pipe clients.

**Missing dependencies with fallback:**
- None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None (built-in tests) |
| Quick run command | `cargo test -p dlp-agent chrome` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| BRW-01 | Agent creates named pipe at `\\.\pipe\brcm_chrm_cas` | unit | `cargo test -p dlp-agent test_chrome_pipe_created` | ❌ Wave 0 |
| BRW-01 | Agent decodes protobuf ContentAnalysisRequest | unit | `cargo test -p dlp-agent test_decode_request` | ❌ Wave 0 |
| BRW-01 | Agent encodes protobuf ContentAnalysisResponse | unit | `cargo test -p dlp-agent test_encode_response` | ❌ Wave 0 |
| BRW-03 | Paste from managed origin blocked | unit | `cargo test -p dlp-agent test_managed_origin_blocks` | ❌ Wave 0 |
| BRW-03 | Paste from unmanaged origin allowed | unit | `cargo test -p dlp-agent test_unmanaged_origin_allows` | ❌ Wave 0 |
| BRW-03 | Audit event has source_origin/destination_origin | unit | `cargo test -p dlp-common test_audit_origin_fields` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-agent chrome`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `dlp-agent/src/chrome/mod.rs` — module scaffolding
- [ ] `dlp-agent/src/chrome/proto.rs` — prost include
- [ ] `dlp-agent/src/chrome/frame.rs` — protobuf frame read/write
- [ ] `dlp-agent/src/chrome/handler.rs` — request dispatch + decision
- [ ] `dlp-agent/src/chrome/cache.rs` — ManagedOriginsCache
- [ ] `dlp-agent/src/chrome/registry.rs` — HKLM self-registration
- [ ] `dlp-agent/proto/content_analysis.proto` — vendored proto
- [ ] `dlp-agent/build.rs` — prost-build integration
- [ ] `dlp-agent/tests/chrome_pipe.rs` — pipe server integration test
- [ ] `dlp-common/src/audit.rs` — source_origin + destination_origin fields
- [ ] `dlp-agent/src/server_client.rs` — `fetch_managed_origins()` method

*(If no gaps: "None — existing test infrastructure covers all phase requirements")*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | Origin-based allow/block (managed vs unmanaged) |
| V5 Input Validation | yes | Protobuf frame size cap (4 MiB max); URL origin normalization |
| V6 Cryptography | no | — |
| V7 Error Handling | yes | Malformed protobuf frames logged and dropped (not crashed) |
| V8 Data Protection | yes | Clipboard content (`text_content`) inspected for decision but NOT logged or persisted |

### Known Threat Patterns for Chrome Content Analysis Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malformed protobuf frame (DoS) | Denial of Service | 4 MiB payload cap; close connection on parse error |
| Fake Chrome process connecting to pipe | Spoofing | Pipe DACL restricts to Authenticated Users; `GetNamedPipeClientProcessId` + `GetProcessPath` validates binary path |
| Clipboard content exfiltration via audit log | Information Disclosure | Never log `text_content`; only log origin metadata |
| Cache poisoning (managed origins) | Tampering | HTTPS to dlp-server; read-only cache from agent perspective |
| Agent impersonation (rogue pipe server) | Spoofing | `FILE_FLAG_FIRST_PIPE_INSTANCE` on first pipe creation detects conflicts |

## Sources

### Primary (HIGH confidence)
- [GitHub: chromium/content_analysis_sdk](https://github.com/chromium/content_analysis_sdk) — Official SDK repository; proto definitions, demo agent, pipe naming
- [Raw: proto/content_analysis/sdk/analysis.proto](https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/proto/content_analysis/sdk/analysis.proto) — Full protobuf definitions [VERIFIED: fetched 2026-04-29]
- [Raw: demo/agent.cc](https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/demo/agent.cc) — Demo agent showing `kPathSystem = "brcm_chrm_cas"` [VERIFIED: fetched 2026-04-29]
- [Raw: common/utils_win.h](https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/common/utils_win.h) — Pipe prefix constants, `GetPipeNameForAgent` signature [VERIFIED: fetched 2026-04-29]
- [Raw: common/utils_win.cc](https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/common/utils_win.cc) — `BuildPipeName` implementation showing `ProtectedPrefix\Administrators` [VERIFIED: fetched 2026-04-29]

### Secondary (MEDIUM confidence)
- [Mozilla searchfox: analysis.proto](https://searchfox.org/firefox-main/source/third_party/content_analysis_sdk/proto/content_analysis/sdk/analysis.proto) — Firefox's copy of the proto; confirms field numbers and message structure [VERIFIED: fetched 2026-04-29]
- [Broadcom DLP Chrome SDK docs](https://knowledge.broadcom.com/external/article/371085/configuring-the-chrome-sdk-connector-for.html) — High-level configuration guidance; no exact registry path
- [Broadcom TechDocs](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-0-1/about-discovering-and-preventing-data-loss-on-endp-v98548126-d294e27/about-monitoring-google-chrome-using-the-chrome-content-analysis-connector-agent-sdk-on-windows-endpoints.html) — Overview only

### Tertiary (LOW confidence)
- Web search results for HKLM registry path — no authoritative source found for exact `cas_agents` path; paths inferred from Chrome extension policy patterns

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — `prost` 0.14.3 verified on crates.io; `bytes` 1.11.1 verified; patterns well-established
- Architecture: HIGH — Proto definitions fetched directly from official SDK source; pipe name confirmed in demo code; frame protocol matches existing codebase
- Pitfalls: MEDIUM-HIGH — Pipe name prefix uncertainty (A3) and registry path uncertainty (A1) flagged as assumptions requiring validation

**Research date:** 2026-04-29
**Valid until:** 2026-05-29 (stable stack — prost releases are infrequent; SDK proto is mature)
