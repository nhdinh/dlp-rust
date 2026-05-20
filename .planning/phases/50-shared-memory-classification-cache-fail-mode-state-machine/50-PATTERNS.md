# Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine - Pattern Map

**Mapped:** 2026-05-20
**Files analyzed:** 11
**Analogs found:** 11 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-hook-dll/src/classification_cache.rs` (NEW) | utility | request-response | `dlp-agent/src/cache.rs` | role-match |
| `dlp-hook-dll/src/fail_mode.rs` (NEW) | state-machine | event-driven | `dlp-agent/src/cache.rs` `fail_closed_response` | partial-match |
| `dlp-hook-dll/src/allowlist.rs` (NEW) | utility | request-response | `dlp-agent/src/allowlist.rs` | role-match |
| `dlp-agent/src/classification_cache.rs` (NEW) | service | CRUD | `dlp-agent/src/cache.rs` | exact |
| `dlp-common/src/hook_ipc.rs` (EXTEND) | model | request-response | `dlp-common/src/hook_ipc.rs` (self) | exact |
| `dlp-hook-dll/src/lib.rs` (EXTEND) | component | event-driven | `dlp-hook-dll/src/lib.rs` (self) | exact |
| `dlp-hook-dll/src/trampolines.rs` (EXTEND) | component | request-response | `dlp-hook-dll/src/trampolines.rs` (self) | exact |
| `dlp-agent/src/service.rs` (EXTEND) | service | event-driven | `dlp-agent/src/service.rs` (self) | exact |
| `dlp-hook-dll/src/perf_telemetry.rs` (NEW) | utility | batch | `dlp-hook-dll/src/pipe_client.rs` thread_local pattern | partial-match |
| `dlp-hook-dll/src/background_thread.rs` (NEW) | component | event-driven | `dlp-agent/src/hook_injector.rs` `WaitForSingleObject` usage | partial-match |
| `dlp-agent/src/cache_pusher.rs` (NEW) | service | pub-sub | `dlp-agent/src/engine_client.rs` config polling | partial-match |

## Pattern Assignments

### `dlp-hook-dll/src/classification_cache.rs` (utility, request-response)

**Analog:** `dlp-agent/src/cache.rs`

**Imports pattern** (lines 1-15):
```rust
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use dlp_common::{Classification, Decision, EvaluateResponse};
use parking_lot::RwLock;
use tracing::debug;
```

**Core FNV-1a pattern** (lines 152-161):
```rust
/// Fowler-Noll-Vo (FNV-1a) hash for strings -- fast, well-distributed.
fn hash_str(s: &str) -> u64 {
    // FNV-1a 64-bit
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
```

**TTL eviction pattern** (lines 20-30, 80-101):
```rust
#[derive(Debug)]
struct CacheEntry {
    response: EvaluateResponse,
    expires_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

// In get():
// Remove expired entries lazily on access.
guard.retain(|_, entry| !entry.is_expired());
guard.remove(&key).filter(|e| !e.is_expired()).map(|e| { ... })
```

**Thread-local buffer pattern** (from `dlp-hook-dll/src/pipe_client.rs`, lines 17-25):
```rust
thread_local! {
    /// Pre-allocated 4 KiB buffer reused per thread for pipe serialization.
    pub static PIPE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}
```

**Key insight for DLL cache:** The agent's `Cache` uses `RwLock<HashMap>` for thread-safe in-process caching. The DLL's shared-memory cache is read-only (no locks), using atomic version word + double-buffering. Copy the FNV-1a implementation exactly; adapt the TTL check to use wall-clock seconds (not `Instant`) for cross-process comparability.

---

### `dlp-hook-dll/src/fail_mode.rs` (state-machine, event-driven)

**Analog:** `dlp-agent/src/cache.rs` `fail_closed_response` + `dlp-common/src/classification.rs`

**Fail-closed pattern** (lines 172-190):
```rust
pub fn fail_closed_response(classification: Classification) -> EvaluateResponse {
    if classification.is_sensitive() {
        EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: None,
            reason: "Fail-closed: no cached decision for sensitive resource".to_string(),
        }
    } else {
        EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "Cache miss: default allow for non-sensitive resource".to_string(),
        }
    }
}
```

**Classification sensitivity check** (lines 34-36):
```rust
pub fn is_sensitive(self) -> bool {
    matches!(self, Self::T3 | Self::T4)
}
```

**Atomic counter pattern** (from `dlp-hook-dll/src/lib.rs`, lines 91):
```rust
static INITIALISED: AtomicBool = AtomicBool::new(false);
```

**Key insight:** The fail-mode state machine uses atomic `u8` for state + atomic `u32` for failure counters. State transitions are deterministic and idempotent. The asymmetric fail logic (T3/T4 closed, T1/T2 open) is already implemented in `fail_closed_response` -- adapt to return `Option<DenyReturn>` instead of `EvaluateResponse`.

---

### `dlp-hook-dll/src/allowlist.rs` (utility, request-response)

**Analog:** `dlp-agent/src/allowlist.rs`

**Prefix matching pattern** (lines 296-305):
```rust
fn prefix_match_directory_boundary(prefix: &str, path: &str) -> bool {
    let prefix_norm = prefix.trim_end_matches('\\').to_lowercase();
    let path_norm = path.to_lowercase();
    if let Some(rest) = path_norm.strip_prefix(&prefix_norm) {
        // After prefix, must be either empty (exact dir) or start with \\.
        rest.is_empty() || rest.starts_with('\\')
    } else {
        false
    }
}
```

**System-critical path check** (lines 166-195):
```rust
fn check_system_critical(&self, image_path: &str) -> Option<AllowlistCategory> {
    let path = Path::new(image_path);
    let basename = path.file_name()?.to_str()?;
    let parent = path.parent()?;
    let parent_str = parent.to_str()?.to_lowercase();

    // Must be in a trusted Windows directory.
    let is_trusted_dir = parent_str.contains("\\windows\\system32")
        || parent_str.contains("\\windows\\syswow64")
        || parent_str.contains("\\windows\\winsxs")
        || parent_str.ends_with("\\windows");

    if !is_trusted_dir {
        return None;
    }
    // ... critical_names check ...
}
```

**Key insight:** The DLL allowlist is simpler than the agent's -- no signer caching, no Authenticode. Hardcoded static arrays of path prefixes (System32, WinSxS, etc.) plus a shared-memory operator extension array. Use `eq_ignore_ascii_case` for Windows path comparison (from agent allowlist, line 121).

---

### `dlp-agent/src/classification_cache.rs` (service, CRUD)

**Analog:** `dlp-agent/src/cache.rs`

**RwLock-protected HashMap pattern** (lines 46-75):
```rust
pub struct Cache {
    inner: RwLock<HashMap<CacheKey, CacheEntry>>,
    ttl: Duration,
}

impl Cache {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            ttl,
        }
    }
}
```

**Insert/get pattern** (lines 80-117):
```rust
pub fn get(&self, resource_path: &str, user_sid: &str) -> Option<EvaluateResponse> {
    let key = CacheKey { ... };
    let mut guard = self.inner.write();
    guard.retain(|_, entry| !entry.is_expired());
    guard.remove(&key).filter(|e| !e.is_expired()).map(|e| e.response)
}

pub fn insert(&self, resource_path: &str, user_sid: &str, response: EvaluateResponse) {
    let key = CacheKey { ... };
    let entry = CacheEntry {
        response,
        expires_at: Instant::now().checked_add(self.ttl).unwrap(),
    };
    self.inner.write().insert(key, entry);
}
```

**Key insight:** The agent-side `ClassificationCache` owns the shared memory. It uses `parking_lot::RwLock` for cache rebuild (not hot path). On policy change, rebuild the entire cache in the inactive buffer, then atomic flip. Pre-populate T3/T4 Protected Path roots at startup.

---

### `dlp-common/src/hook_ipc.rs` (EXTEND) (model, request-response)

**Analog:** `dlp-common/src/hook_ipc.rs` (self)

**Existing serde struct pattern** (lines 6-32):
```rust
use serde::{Deserialize, Serialize};

/// Request sent by the hook DLL to the agent for classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookRequest {
    pub path: String,
    pub action: String,
}

/// Response returned by the agent to the hook DLL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookResponse {
    pub decision: crate::Decision,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandleHookRequest {
    pub handle_value: u64,
    pub action: String,
    pub pid: u32,
}
```

**Key insight:** Add `cache_version: u64` to `HookRequest`, add `cache_hint: Option<(PathBuf, Tier, u32)>` and `cache_version: u64` to `HookResponse`. Add `HookOp` enum for operation type. Use additive fields to maintain backward compatibility with existing bincode serialization.

---

### `dlp-hook-dll/src/lib.rs` (EXTEND) (component, event-driven)

**Analog:** `dlp-hook-dll/src/lib.rs` (self)

**DllMain pattern** (lines 406-417):
```rust
#[unsafe(no_mangle)]
extern "system" fn DllMain(_inst: isize, reason: u32, _reserved: usize) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;
    if reason == DLL_PROCESS_ATTACH {
        init();
    } else if reason == DLL_PROCESS_DETACH {
        UnhookAll();
    }
    1
}
```

**Static mut original pointer pattern** (lines 120-134):
```rust
/// Original `CreateFileW` pointer saved before patching.
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_CREATE_FILE_W: Option<
    unsafe extern "system" fn(...) -> HANDLE,
> = None;
```

**Module declaration pattern** (lines 48-52):
```rust
mod crash_guard;
mod fail_closed;
mod pe_utils;
mod pipe_client;
pub mod trampolines;
```

**Classification helper pattern** (lines 548-561):
```rust
pub(crate) fn classify_path(
    path: &str,
    action: &str,
    pipe_name: &str,
) -> Result<Decision, pipe_client::PipeError> {
    let req = HookRequest {
        path: path.to_string(),
        action: action.to_string(),
    };
    let resp = pipe_client::send_request(pipe_name, &req, 50)?;
    Ok(resp.decision)
}
```

**Key insight:** Add `mod classification_cache; mod fail_mode; mod allowlist; mod perf_telemetry; mod background_thread;` after existing modules. In `DllMain`, after `init()`, add shared-memory mapping (`OpenFileMappingW` + `MapViewOfFile`). Store cache header pointer as `static mut CACHE_HEADER: Option<*const CacheHeader> = None;`. Defer background thread creation to first hook call (avoid DllMain loader lock deadlock).

---

### `dlp-hook-dll/src/trampolines.rs` (EXTEND) (component, request-response)

**Analog:** `dlp-hook-dll/src/trampolines.rs` (self)

**classify_and_log_path pattern** (lines 31-74):
```rust
fn classify_and_log_path(
    path: &str,
    action: &str,
    fn_name: &str,
) -> Option<crate::fail_closed::DenyReturn> {
    let path_hash = crate::hash_path(path);
    let start = std::time::Instant::now();

    let decision = crate::classify_path(path, action, crate::DEFAULT_PIPE_NAME);
    let latency = start.elapsed();

    match decision {
        Ok(crate::Decision::ALLOW) | Ok(crate::Decision::AllowWithLog) => {
            // ... log ALLOW ...
            None
        }
        Ok(d) if d.is_denied() => {
            // ... log DENY ...
            Some(crate::fail_closed::DenyReturn::BoolFalse)
        }
        _ => {
            // ... log DENY(fail-closed) ...
            Some(crate::fail_closed::DenyReturn::BoolFalse)
        }
    }
}
```

**Trampoline guard nesting pattern** (lines 144-209):
```rust
crate::crash_guard::guard_trampoline(
    "CreateFileW",
    || {
        crate::crash_guard::with_reentrancy_guard(
            || {
                let path = crate::pcwstr_to_string(lpfilename);
                if let Some(_deny) = classify_and_log_path(&path, "CREATE", "CreateFileW") {
                    return crate::fail_closed!(InvalidHandleValue);
                }
                // ... call original ...
            },
            || { /* fallback */ },
        )
    },
    || { /* panic fallback */ },
)
```

**Key insight:** Modify `classify_and_log_path` to insert cache lookup BEFORE `classify_path`:
1. Check allowlist first (fastest path)
2. Check shared-memory cache (second fastest)
3. If cache hit on T3/T4 + write op -> deny immediately (skip pipe)
4. If cache hit on T1/T2 -> allow immediately (skip pipe)
5. If cache miss/expired -> fall through to existing pipe logic
6. On pipe success, store `cache_hint` in thread-local LRU

---

### `dlp-agent/src/service.rs` (EXTEND) (service, event-driven)

**Analog:** `dlp-agent/src/service.rs` (self)

**Service startup subsystem pattern** (lines 224-288):
```rust
// Start the health monitor first
let health_handle = crate::health_monitor::start();
info!(thread_id = ?health_handle.thread().id(), "health monitor started");

// Start IPC pipe servers
crate::ipc::start_all()?;
info!("IPC pipe servers started");

// Start Chrome Content Analysis pipe server
let chrome_handle = std::thread::Builder::new()
    .name("chrome-pipe".into())
    .spawn(|| { ... })
    .context("failed to spawn Chrome pipe thread")?;

// Start the session monitor
let session_handle = crate::session_monitor::start();
```

**Global OnceLock pattern** (lines 45-68):
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

**Key insight:** Add `ClassificationCache` initialization after `init_agent_db()` and before IPC pipe servers start. The cache must be created and pre-populated before any DLL connects. Add a background cache maintenance thread (or integrate with existing config poll loop) to rebuild on policy changes. Use `crossbeam-channel` for cache delta notifications (already in Cargo.toml from Phase 49).

---

### `dlp-hook-dll/src/perf_telemetry.rs` (NEW) (utility, batch)

**Analog:** `dlp-hook-dll/src/pipe_client.rs` (thread_local pattern)

**Thread-local pattern** (lines 17-25):
```rust
thread_local! {
    pub static PIPE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}
```

**Key insight:** Use thread-local storage for latency histogram buckets (array of atomic counters). Measure with `QueryPerformanceCounter` before/after cache lookup. Emit aggregated telemetry every 1000 calls via pipe. No allocations in hot path -- pre-allocated buckets.

---

### `dlp-hook-dll/src/background_thread.rs` (NEW) (component, event-driven)

**Analog:** `dlp-agent/src/hook_injector.rs` (WaitForSingleObject usage)

**WaitForSingleObject pattern** (lines 299):
```rust
let wait_result = unsafe { WaitForSingleObject(thread, 10_000) };
if wait_result != WAIT_OBJECT_0 { ... }
```

**Key insight:** Spawn thread on first hook call (NOT from DllMain). Use `CreateEventW` for shutdown signal. Loop: `WaitForSingleObject(shutdown_event, 100)` -- if timeout, check if ISOLATED state, then poll atomic version word. If version > last_seen, signal RESYNC transition via atomic state update.

---

### `dlp-agent/src/cache_pusher.rs` (NEW) (service, pub-sub)

**Analog:** `dlp-agent/src/engine_client.rs` (config polling pattern)

**Key insight:** Subscribe to policy_store changes via existing config poll mechanism. On change, rebuild shared-memory cache, atomic flip. Debounce rapid changes with 500ms timer. No direct analog -- planner should use RESEARCH.md Pattern 1 (double-buffered atomic flip) as primary reference.

## Shared Patterns

### Authentication / Security
**Source:** `dlp-agent/src/hook_ipc.rs` (pipe security)
**Apply to:** `dlp-agent/src/classification_cache.rs`
```rust
let sec = PipeSecurity::new().context("pipe security descriptor")?;
```
Shared memory should use equivalent security descriptor: `D:(A;;GA;;;SY)(A;;GR;;;AU)` -- SYSTEM has generic all, Authenticated Users have generic read.

### Error Handling
**Source:** `dlp-hook-dll/src/pipe_client.rs`
**Apply to:** All hook DLL new modules
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum PipeError {
    ConnectionRefused,
    Timeout,
    Malformed,
    Win32(u32),
}

impl std::fmt::Display for PipeError { ... }
impl std::error::Error for PipeError {}
```

### Thread-Local Pre-allocated Buffers
**Source:** `dlp-hook-dll/src/pipe_client.rs`
**Apply to:** `classification_cache.rs`, `perf_telemetry.rs`
```rust
thread_local! {
    pub static PIPE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}
```

### Atomic State Management
**Source:** `dlp-hook-dll/src/lib.rs`
**Apply to:** `fail_mode.rs`, `background_thread.rs`
```rust
use std::sync::atomic::{AtomicBool, Ordering};
static INITIALISED: AtomicBool = AtomicBool::new(false);
// Usage:
if INITIALISED.swap(true, Ordering::SeqCst) { return; }
```

### Windows API String Conversion
**Source:** `dlp-hook-dll/src/lib.rs`
**Apply to:** All DLL modules that touch Windows APIs
```rust
let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
unsafe { OutputDebugStringW(PCWSTR::from_raw(wide.as_ptr())) };
```

### Test Pattern
**Source:** `dlp-hook-dll/src/lib.rs` tests
**Apply to:** All new modules
```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Arrange-Act-Assert pattern
    #[test]
    fn test_something() { ... }
}
```

### Doc Comment Pattern
**Source:** `dlp-agent/src/cache.rs`
**Apply to:** All public items in new modules
```rust
/// Looks up a cached decision.
///
/// Returns `Some(response)` if the entry exists and is not expired.
/// Returns `None` if the entry is absent or expired.
/// Expired entries are lazily removed.
pub fn get(&self, resource_path: &str, user_sid: &str) -> Option<EvaluateResponse> { ... }
```

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| None | -- | -- | All files have at least partial analogs |

## Metadata

**Analog search scope:**
- `dlp-hook-dll/src/*.rs`
- `dlp-agent/src/*.rs`
- `dlp-common/src/*.rs`

**Files scanned:** 11
**Pattern extraction date:** 2026-05-20

**Key conventions to follow:**
1. All new modules MUST have `#[cfg(test)]` modules with Arrange-Act-Assert pattern
2. Hook DLL uses `std::sync::atomic` (not `parking_lot`) -- no external deps in DLL
3. Agent uses `parking_lot::RwLock` for cache rebuild (not hot path)
4. Windows path comparison is case-insensitive (`eq_ignore_ascii_case`)
5. Thread-local pre-allocated buffers for zero-allocation hot path
6. `tracing::error!` / `tracing::warn!` / `tracing::info!` for logging (not `println!`)
7. Doc comments for all public functions, structs, enums, methods
8. `#[repr(C)]` for all shared-memory structs (architecture-agnostic layout)
9. `u64` for all offsets/sizes in shared memory (not `usize`)
10. Never call `CreateThread` from `DllMain` -- defer to first hook call
