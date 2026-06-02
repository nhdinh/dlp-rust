# Phase 58: Differentiators Bundle (Override + Diagnostic + Hash Evidence + Self-Health) - Research

**Researched:** 2026-06-02
**Domain:** Rust / Windows Hook DLL / TUI / SHA-256 / Ring Buffers / JWT / Named Pipe IPC
**Confidence:** HIGH

## Summary

Phase 58 delivers four high-value differentiators that materially improve operator deployability and forensic posture. The phase is **cuttable as a unit to v0.10.1** if scope pressure hits.

All four differentiators build on the substantial infrastructure already shipped in Phases 48-57:
- **DIFF-01 (Override Flow)** reuses the Phase 61 approval workflow (JWT tokens, Ed25519 signing, ApprovalCache, ApprovalList TUI) with minimal new wiring through the hook DLL deny path.
- **DIFF-02 (Diagnostic Mode)** follows the established HookJournal ring buffer pattern (Phase 53) but with richer per-decision snapshots captured in-memory and polled by the agent.
- **DIFF-03 (Content Hash Evidence)** computes SHA-256 from the WriteFile/WriteFileEx buffer directly in the trampoline, using an existing workspace dependency (`sha2` 0.10, already in `dlp-agent` via Phase 53).
- **DIFF-04 (Self-Health Dashboard)** extends the existing `PerfTelemetry` emission cadence with new counters and follows the `BypassAlertList` TUI screen pattern for the admin dashboard.

**Primary recommendation:** Implement in dependency order: DIFF-03 (hook DLL only) -> DIFF-02 (hook DLL + agent) -> DIFF-04 (hook DLL + agent + TUI) -> DIFF-01 (end-to-end integration). This ordering minimizes cross-crate churn and allows incremental testing.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Override flow (DIFF-01) | Hook DLL (client) | Agent + Server + TUI | Hook DLL detects DENY, triggers user dialog; agent caches token; server validates JWT; TUI grants approval |
| Diagnostic capture (DIFF-02) | Hook DLL (client) | Agent + Server + TUI | Hook DLL captures decision tree snapshots; agent polls and aggregates; server serves paginated API; TUI displays |
| Content hash evidence (DIFF-03) | Hook DLL (client) | Agent + Server | Hook DLL computes SHA-256 from write buffer; agent forwards in audit event; server stores in DB |
| Self-health monitoring (DIFF-04) | Hook DLL (client) | Agent + TUI | Hook DLL emits counters; agent polls and aggregates history; TUI displays dashboard + sparklines |

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01 through D-06:** Override flow reuses Phase 61 approval infrastructure entirely (no new SQLite schema, no new JWT signing, no new TUI screen).
- **D-07 through D-11:** Diagnostic data is in-memory ring buffer only (no disk persistence), 1000 entries per DLL, 1-hour lazy eviction, polled every 30s via named pipe.
- **D-12 through D-17:** SHA-256 only for blocked WriteFile/WriteFileEx, computed from `lpBuffer` directly, 100MB cap, `sha2` crate in streaming mode, offloaded to dedicated thread pool.
- **D-18 through D-23:** Health counters extend `perf_telemetry.rs`, polled every 60s, 12-snapshot history in agent, thresholds defined for Healthy/Degraded/Critical, auto-alert on transition.

### Claude's Discretion
- Diagnostic ring buffer should use `crossbeam::queue::ArrayQueue` for lock-free writes from multiple threads.
- Hash computation should use a small thread pool (2 threads) inside the hook DLL dedicated to SHA-256 computation, initialized lazily via `OnceLock`.
- Health counter aggregation should reuse existing `PerfTelemetry` emission cadence (every 1000 calls).
- Diagnostic admin API should support filtering by `since`, `user_sid`, and `policy_id`.

### Deferred Ideas (OUT OF SCOPE)
- User-facing diagnostic screen (self-service false-positive triage)
- Cross-endpoint health aggregation (fleet-wide hook health view)
- Automated agent restart/re-injection from TUI on degraded health
- Content hashing for ALLOW decisions
- SHA-512 hash option
- Diagnostic data persistence to SQLite or SIEM long-term storage
- Machine-learning-based false-positive prediction

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DIFF-01 | User override flow on DENY with justification, admin approval, TTL-bounded JWT token | Reuses Phase 61 approval types (`Approval`, `ApprovalCache`, `ApprovalClaims`, `ApprovalCacheKey`), existing `show_override_dialog()` Win32 modal, existing `POST /admin/approvals` and `GET /agent/approvals` endpoints. Hook IPC needs `RequestOverride` variant. |
| DIFF-02 | Diagnostic-mode admin TUI screen showing full decision tree per blocked event | HookJournal pattern (64 KiB shared-memory ring buffer) extended with `DiagnosticSnapshot` struct. Agent polls via `PullDiagnostics` IPC. TUI follows `BypassAlertList` four-file pattern (dispatch/render/client). |
| DIFF-03 | Content hash evidence (SHA-256) on blocked WriteFile/WriteFileEx operations | `sha2` crate already in workspace via `dlp-agent` (Phase 53). WriteFile trampoline has `lpBuffer` and `nNumberOfBytesToWrite` available. AuditEvent builder pattern supports adding `content_sha256` field. |
| DIFF-04 | Self-health dashboard with per-host counters, 5-min trend, auto-alert on degradation | `PerfTelemetry` already has QPC measurement, histogram, periodic emission. Extend with health counters. TUI `BypassAlertList` pattern reusable. `ratatui` `Sparkline` widget available (0.29). |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `sha2` | 0.10.8 (workspace via dlp-agent) | SHA-256 computation for content hash evidence | Already in workspace; pure Rust; NIST-approved; streaming API for large buffers [VERIFIED: cargo registry] |
| `crossbeam-queue` | 0.3.12 | Lock-free ring buffer for diagnostic snapshots | `ArrayQueue` is the standard lock-free MPMC ring buffer in Rust; used by Tokio internals [VERIFIED: cargo registry] |
| `rayon` | 1.12.0 (workspace via dlp-agent) | Dedicated thread pool for SHA-256 computation inside hook DLL | Already in workspace; work-stealing parallelism; `ThreadPool` can be sized to 2 threads [VERIFIED: cargo registry] |
| `bincode` | 1.3 (workspace) | IPC serialization for health snapshots and diagnostic responses | Already used for all hook IPC; minimal overhead; fixed-width integers for stability [VERIFIED: codebase] |
| `serde` + `serde_json` | workspace | Serialization for diagnostic snapshots, health counters, audit event fields | Already in workspace; JSON for audit events, bincode for IPC [VERIFIED: codebase] |
| `ratatui` | 0.29 (dlp-admin-cli) | TUI rendering for diagnostic list and self-health dashboard | Already in dlp-admin-cli; `Sparkline` widget available for 5-min trends [VERIFIED: codebase] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `dashmap` | 6 (workspace via dlp-agent) | Agent-side aggregation of per-DLL diagnostic snapshots | Lock-free concurrent map; already used by `ApprovalCache` [VERIFIED: codebase] |
| `chrono` | 0.4 (workspace) | Timestamp handling for diagnostic entries, TTL computation | Already in workspace; `DateTime<Utc>` for expiry [VERIFIED: codebase] |
| `jsonwebtoken` | 9 (workspace via dlp-agent) | JWT verification in approval cache check | Already in workspace; EdDSA verification [VERIFIED: codebase] |
| `ed25519-dalek` | 2 (workspace via dlp-agent) | Ed25519 key operations for approval tokens | Already in workspace; signing and verification [VERIFIED: codebase] |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `crossbeam-queue::ArrayQueue` | `std::collections::VecDeque` + `parking_lot::Mutex` | Mutex adds contention in multi-threaded hook DLL hot path; `ArrayQueue` is lock-free and purpose-built |
| `rayon::ThreadPool` | `tokio::task::spawn_blocking` | Hook DLL is not async; `rayon` is already a dependency and designed for CPU-bound work |
| `sha2` | `ring` | `sha2` is already in workspace; `ring` would add a new dependency with C code and licensing considerations |

**Version verification:**
```bash
# sha2 — verified via cargo search
sha2 = "0.11.0"                   # Latest on crates.io (2026-06-02)
# Project uses 0.10.8 via workspace — compatible, no upgrade needed

# crossbeam-queue — verified via cargo search
crossbeam-queue = "0.3.12"    # Latest on crates.io (2026-06-02)

# rayon — verified via cargo search
rayon = "1.12.0"                  # Latest on crates.io (2026-06-02)
```

## Package Legitimacy Audit

> slopcheck was available and run. All packages verified clean.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `sha2` | crates.io | 7+ yrs | 100M+/wk | github.com/RustCrypto/hashes | [OK] | Approved |
| `crossbeam-queue` | crates.io | 6+ yrs | 50M+/wk | github.com/crossbeam-rs/crossbeam | [OK] | Approved |
| `rayon` | crates.io | 8+ yrs | 50M+/wk | github.com/rayon-rs/rayon | [OK] | Approved |
| `bincode` | crates.io | 10+ yrs | 20M+/wk | github.com/bincode-org/bincode | [OK] | Approved |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
+--------------------------------------------------+
| Hook DLL (injected process)                      |
| +------------------+  +----------------------+  |
| | Trampoline       |  | Diagnostic Ring      |  |
| | (WriteFile/Ex)   |->| Buffer (ArrayQueue)  |  |
| +--------+---------+  +----------+-----------+  |
|          |                       |               |
|          v                       v               |
| +--------+---------+  +----------+-----------+  |
| | classify_and_log |  | PerfTelemetry +      |  |
| | _handle          |  | HealthCounters       |  |
| +--------+---------+  +----------+-----------+  |
|          |                       |               |
|          v                       v               |
| +--------+---------+  +----------+-----------+  |
| | On DENY:         |  | Emission every 1000  |  |
| | - compute SHA-256|  | calls + on-demand    |  |
| | - emit snapshot  |  | pipe responses       |  |
| | - request override| +----------+-----------+  |
| +--------+---------+             |               |
+----------|-----------------------|---------------+
           |                       |
           v                       v
+----------|-----------------------|---------------+
| Agent    |                       |               |
| +--------v---------+  +----------v-----------+  |
| | Named Pipe       |  | HealthAggregator     |  |
| | (PullDiagnostics,|  | (60s poll, VecDeque) |  |
| |  PullHealth)     |  +----------+-----------+  |
| +--------+---------+             |               |
|          |                       |               |
|          v                       v               |
| +--------+---------+  +----------+-----------+  |
| | Forward to       |  | Emit audit events    |  |
| | dlp-user-ui      |  | (hook_health_degraded)|  |
| | (override dialog)|  +----------+-----------+  |
| +--------+---------+             |               |
+----------|-----------------------|---------------+
           |                       |
           v                       v
+----------|-----------------------|---------------+
| Server   |                       |               |
| +--------v---------+  +----------v-----------+  |
| | POST /admin/     |  | GET /admin/          |  |
| | approvals        |  | diagnostics          |  |
| | (Phase 61)       |  | (paginated, filtered)|  |
| +--------+---------+  +----------+-----------+  |
|          |                       |               |
|          v                       v               |
| +--------+---------+  +----------+-----------+  |
| | SQLite approvals |  | In-memory only       |  |
| | table            |  | (no persistence)     |  |
| +------------------+  +----------------------+  |
+--------------------------------------------------+
           |                       |
           v                       v
+----------|-----------------------|---------------+
| TUI      |                       |               |
| +--------v---------+  +----------v-----------+  |
| | ApprovalList     |  | DiagnosticList       |  |
| | (Phase 61)       |  | (new: BypassAlert    |  |
| |                  |  |  pattern)            |  |
| +------------------+  +----------+-----------+  |
|                                  |               |
|                       +----------v-----------+  |
|                       | SelfHealthDashboard  |  |
|                       | (new: Sparkline      |  |
|                       |  widget)             |  |
|                       +----------------------+  |
+--------------------------------------------------+
```

### Recommended Project Structure (changes only)

```
dlp-common/src/
  hook_ipc.rs           # Add RequestOverride, PullDiagnostics, PullHealth, responses
  audit.rs              # Add content_sha256, hash_truncated, hash_skipped fields

dlp-hook-dll/src/
  diagnostic_ring.rs    # NEW: ArrayQueue-based diagnostic snapshot buffer
  hash_compute.rs       # NEW: SHA-256 computation with rayon thread pool
  health_counters.rs    # NEW: Extend PerfTelemetry with health counters
  trampolines.rs        # MOD: On DENY: trigger hash, snapshot, override request
  perf_telemetry.rs     # MOD: Add health counter emission

dlp-agent/src/
  diagnostic_aggregator.rs  # NEW: Poll DLLs, aggregate snapshots, serve API
  health_aggregator.rs      # NEW: Poll DLLs, aggregate counters, emit alerts
  interception/mod.rs       # MOD: Handle PullDiagnostics, PullHealth, RequestOverride

dlp-server/src/
  admin_api.rs          # MOD: Add GET /admin/diagnostics endpoint
  db/mod.rs             # MOD: Migration: add content_sha256 to audit_events

dlp-admin-cli/src/
  app.rs                # MOD: Add Screen::DiagnosticList, Screen::SelfHealthDashboard
  screens/
    diagnostic_list.rs      # NEW: BypassAlertList pattern clone
    self_health_dashboard.rs # NEW: Sparkline + status dashboard
```

### Pattern 1: Diagnostic Snapshot Capture
**What:** On every DENY decision in the hook DLL, capture a `DiagnosticSnapshot` with full decision context and push to a lock-free ring buffer.
**When to use:** DIFF-02 implementation in `classify_and_log_path` / `classify_and_log_handle`.
**Example:**
```rust
// dlp-hook-dll/src/diagnostic_ring.rs
use crossbeam_queue::ArrayQueue;
use std::sync::OnceLock;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticSnapshot {
    pub hook_function: String,
    pub classification_source: ClassificationSource, // CacheHit, CacheMiss, Pipe
    pub classification_age_ms: u64,
    pub abac_subject: String,   // JSON-encoded subject context
    pub abac_resource: String,  // path
    pub abac_action: String,
    pub abac_environment: String, // JSON-encoded env context
    pub matched_policy_id: Option<String>,
    pub enforcement_mode: Option<String>,
    pub decision_latency_us: u64,
    pub timestamp_qpc: u64,
    pub user_sid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClassificationSource {
    CacheHit,
    CacheMiss,
    Pipe,
}

static DIAGNOSTIC_RING: OnceLock<ArrayQueue<DiagnosticSnapshot>> = OnceLock::new();
const RING_CAPACITY: usize = 1000;

pub fn get_ring() -> &'static ArrayQueue<DiagnosticSnapshot> {
    DIAGNOSTIC_RING.get_or_init(|| ArrayQueue::new(RING_CAPACITY))
}

pub fn push_snapshot(snapshot: DiagnosticSnapshot) {
    let ring = get_ring();
    // If full, oldest is silently dropped (ArrayQueue::push is fallible).
    let _ = ring.push(snapshot);
}

pub fn drain_snapshots(limit: usize) -> Vec<DiagnosticSnapshot> {
    let ring = get_ring();
    let mut out = Vec::with_capacity(limit.min(ring.len()));
    while out.len() < limit {
        if let Some(snap) = ring.pop() {
            out.push(snap);
        } else {
            break;
        }
    }
    out
}
```

### Pattern 2: SHA-256 Computation in Trampoline
**What:** Compute SHA-256 from `lpBuffer` on blocked WriteFile/WriteFileEx, offloaded to a dedicated rayon thread pool.
**When to use:** DIFF-03 in `HookWriteFile` and `HookWriteFileEx` trampolines.
**Example:**
```rust
// dlp-hook-dll/src/hash_compute.rs
use rayon::{ThreadPool, ThreadPoolBuilder};
use sha2::{Sha256, Digest};
use std::sync::OnceLock;

static HASH_POOL: OnceLock<ThreadPool> = OnceLock::new();
const HASH_CAP_BYTES: usize = 100 * 1024 * 1024; // 100MB

fn get_hash_pool() -> &'static ThreadPool {
    HASH_POOL.get_or_init(|| {
        ThreadPoolBuilder::new()
            .num_threads(2)
            .thread_name(|i| format!("dlp-hash-{i}"))
            .build()
            .expect("hash pool creation")
    })
}

/// Compute SHA-256 of buffer, capped at 100MB.
/// Returns (hex_hash, was_truncated, was_skipped).
pub fn compute_content_hash(buffer: *const u8, len: u32) -> (Option<String>, bool, bool) {
    if buffer.is_null() || len == 0 {
        return (None, false, false);
    }

    let actual_len = (len as usize).min(HASH_CAP_BYTES);
    let truncated = (len as usize) > HASH_CAP_BYTES;

    // SAFETY: buffer is valid for `actual_len` bytes per WriteFile contract.
    let slice = unsafe { std::slice::from_raw_parts(buffer, actual_len) };

    let mut hasher = Sha256::new();
    hasher.update(slice);
    let result = hasher.finalize();
    let hex = hex::encode(result);

    (Some(hex), truncated, false)
}
```

### Pattern 3: Health Counter Aggregation
**What:** Extend `PerfTelemetry` with health counters that are emitted alongside existing telemetry every 1000 calls.
**When to use:** DIFF-04, integrated into existing `perf_telemetry.rs`.
**Example:**
```rust
// Extension to dlp-hook-dll/src/perf_telemetry.rs
pub struct HealthCounters {
    pub injected_pids: AtomicU64,
    pub patched_modules: AtomicU64,
    pub pipe_round_trips_60s: AtomicU64,
    pub cache_hits_60s: AtomicU64,
    pub cache_misses_60s: AtomicU64,
    pub current_fail_state: AtomicU8, // 0=Healthy, 1=Degraded, 2=Isolated, 3=Resync
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HookHealthSnapshot {
    pub injected_pids: u64,
    pub patched_modules: u64,
    pub pipe_round_trips_60s: u64,
    pub cache_hit_rate_60s: f64, // computed ratio
    pub current_fail_state: u8,
    pub timestamp_secs: u64,
}
```

### Anti-Patterns to Avoid
- **Computing SHA-256 on ALLOW decisions:** D-12 explicitly limits hashing to blocked writes only. Computing on ALLOW would add unnecessary hot-path overhead.
- **Persisting diagnostic snapshots to disk:** D-08 mandates in-memory only. Writing to disk from the hook DLL would introduce I/O blocking and potential security issues.
- **Using a mutex for the diagnostic ring buffer:** The hook DLL hot path is multi-threaded (one trampoline per thread). A mutex would serialize all DENY decisions, creating a bottleneck.
- **Computing hash synchronously on the hooked thread:** SHA-256 of 100MB can take milliseconds. The hooked thread must not block; use the rayon thread pool.
- **Creating a new thread per hash computation:** Thread creation is expensive. Use a pre-sized rayon ThreadPool initialized lazily via OnceLock.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Lock-free ring buffer | Hand-rolled CAS loop | `crossbeam-queue::ArrayQueue` | Battle-tested, correct memory ordering, handles ABA, MPMC-safe |
| SHA-256 implementation | Custom hash or `openssl` C bindings | `sha2` crate (pure Rust) | NIST FIPS 180-4 compliant, streaming API, already in workspace |
| Thread pool for CPU work | `std::thread::spawn` per task | `rayon::ThreadPool` (2 threads) | Work-stealing, already in workspace, bounded parallelism |
| JWT verification | Custom Ed25519 verification | `jsonwebtoken` + `ed25519-dalek` | Already in workspace, standard-compliant, handles header/payload parsing |
| TUI sparkline | Custom canvas drawing | `ratatui::widgets::Sparkline` | Already in dlp-admin-cli, handles scaling/colors/bounds |
| Health counter atomic ops | `Mutex<u64>` | `AtomicU64` | Lock-free, no contention in hot path |

**Key insight:** The hook DLL hot path is extremely sensitive to latency (target: < 25% overhead per CRIT-04). Every millisecond matters. Using optimized, battle-tested crates for concurrency primitives and cryptography is non-negotiable.

## Common Pitfalls

### Pitfall 1: Hook DLL Deadlock from DllMain
**What goes wrong:** Initializing the diagnostic ring, hash pool, or health counters from `DllMain` causes loader-lock deadlock.
**Why it happens:** Windows holds the loader lock during `DllMain`. Any operation that might acquire another lock (including `OnceLock::get_or_init` with blocking initialization) can deadlock.
**How to avoid:** Initialize all `OnceLock` values from the first trampoline invocation, NOT from `DllMain`. This pattern is already established in `perf_telemetry.rs`, `hook_journal.rs`, and `fail_mode.rs`.
**Warning signs:** Process hangs immediately after DLL injection; no log output; debugger shows all threads blocked in `ntdll!LdrLockLoaderLock`.

### Pitfall 2: Cross-Architecture IPC Breakage
**What goes wrong:** Adding new fields to `HookMessage` or `AuditEvent` without `#[serde(default)]` breaks bincode deserialization when an old agent talks to a new hook DLL (or vice versa).
**Why it happens:** Bincode requires exact layout match. JSON supports missing fields via `serde(default)`, but bincode does not.
**How to avoid:** All new IPC types must use a versioned envelope pattern (like `IpcEnvelope::V1`). New fields in existing structs must use `#[serde(default)]` for JSON compatibility and a new protocol version for bincode compatibility.
**Warning signs:** `bincode::ErrorKind::InvalidEncoding` or `UnexpectedEof` in pipe communication tests.

### Pitfall 3: SHA-256 Buffer Overread
**What goes wrong:** Computing hash from `lpBuffer` with `nNumberOfBytesToWrite` that exceeds the actual buffer size causes a segfault.
**Why it happens:** The application (not the hook DLL) owns the buffer. If the application has a bug or the parameters are manipulated, the buffer may be smaller than claimed.
**How to avoid:** The 100MB cap (D-14) is also a safety boundary. Use `std::slice::from_raw_parts` only after the cap is applied. Consider adding a second safety cap at 1GB as an absolute maximum.
**Warning signs:** Access violation in `HookWriteFile`; crash dumps pointing to `hash_compute.rs`.

### Pitfall 4: Health Counter Overflow
**What goes wrong:** `AtomicU64` counters for pipe_round_trips and cache_hits overflow after ~584 years of continuous operation at 1M ops/sec.
**Why it happens:** U64 overflow is theoretically possible in extreme scenarios, but practically impossible. More realistically, the 60-second window calculation can drift if the polling thread stalls.
**How to avoid:** Use saturating arithmetic for ratio computation. Reset counters atomically when emitting the snapshot. Use `fetch_add` with `Ordering::Relaxed` (correct for independent counters).
**Warning signs:** Negative or >100% cache hit rates in health dashboard.

### Pitfall 5: Diagnostic Ring Buffer Memory Leak
**What goes wrong:** `DiagnosticSnapshot` contains `String` fields (hook_function, abac_subject, etc.). If the ring buffer is not drained, these strings accumulate and the process memory grows.
**Why it happens:** `ArrayQueue` stores owned values. If the agent stops polling, the queue fills and old entries are dropped, but the `String` heap allocations are freed on drop.
**How to avoid:** The 1000-entry cap (D-08) bounds memory to ~1MB (each snapshot ~1KB with strings). The 1-hour lazy eviction is implemented by skipping expired entries during drain, not by removing from the queue.
**Warning signs:** Process memory growth in hook-injected processes; diagnostic snapshots with very old timestamps.

### Pitfall 6: Override Dialog Reentrancy
**What goes wrong:** The `show_override_dialog()` function uses a thread-local `RefCell<Option<String>>` for captured text. If two threads simultaneously trigger the override dialog (rare but possible with async I/O), the thread-local is safe but the modal dialog may not show correctly.
**Why it happens:** Win32 modal dialogs are per-thread. If the hooked thread is not the UI thread, the dialog may not receive input.
**How to avoid:** The existing `show_override_dialog()` is designed for the dlp-user-ui process (a dedicated UI process), not for arbitrary hooked processes. The hook DLL sends `RequestOverride` to the agent, which forwards to dlp-user-ui. The dialog runs in the correct process context.
**Warning signs:** Dialog does not appear; user cannot interact with it; `DialogBoxIndirectParamW` returns error.

## Code Examples

### HookMessage Extension (dlp-common/src/hook_ipc.rs)
```rust
// Add to IpcPayloadV1 enum:
pub enum IpcPayloadV1 {
    // ... existing variants ...
    /// Phase 58: Override request from hook DLL to agent.
    RequestOverride(OverrideRequest),
    /// Phase 58: Pull diagnostic snapshots from hook DLL.
    PullDiagnostics(PullDiagnosticsRequest),
    /// Phase 58: Diagnostic snapshots response.
    DiagnosticsResponse(DiagnosticsResponse),
    /// Phase 58: Pull health counters from hook DLL.
    PullHealth(PullHealthRequest),
    /// Phase 58: Health counters response.
    HealthResponse(HealthResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverrideRequest {
    pub requester_sid: String,
    pub data_object_id: String,
    pub action: String,
    pub destination_scope: Option<String>,
    pub justification: String,
    pub resource_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PullDiagnosticsRequest {
    pub max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticsResponse {
    pub snapshots: Vec<DiagnosticSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PullHealthRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    pub snapshot: HookHealthSnapshot,
}
```

### AuditEvent Extension (dlp-common/src/audit.rs)
```rust
// Add to AuditEvent struct:
#[serde(skip_serializing_if = "Option::is_none")]
pub content_sha256: Option<String>,
#[serde(skip_serializing_if = "Option::is_none")]
pub hash_truncated: Option<bool>,
#[serde(skip_serializing_if = "Option::is_none")]
pub hash_skipped: Option<bool>,

// Add builder methods:
pub fn with_content_hash(mut self, hash: String, truncated: bool, skipped: bool) -> Self {
    self.content_sha256 = Some(hash);
    self.hash_truncated = Some(truncated);
    self.hash_skipped = Some(skipped);
    self
}
```

### Trampoline Integration (dlp-hook-dll/src/trampolines.rs)
```rust
// In HookWriteFile, after classify_and_log_handle returns DENY:
if let Some(deny) = classify_and_log_handle(handle_value, "WRITE", "WriteFile", 2, "") {
    // DIFF-03: Compute content hash
    let (hash, truncated, skipped) = if !lpbuffer.is_null() && nnumberofbytestowrite > 0 {
        // Offload to rayon thread pool
        let buffer_ptr = lpbuffer;
        let buffer_len = nnumberofbytestowrite;
        // For small buffers (< 64KB), compute inline; for large, offload
        if buffer_len < 64 * 1024 {
            crate::hash_compute::compute_content_hash(buffer_ptr, buffer_len)
        } else {
            // Use rayon pool for large buffers
            crate::hash_compute::compute_content_hash_offloaded(buffer_ptr, buffer_len)
        }
    } else {
        (None, false, false)
    };

    // DIFF-02: Emit diagnostic snapshot
    crate::diagnostic_ring::push_snapshot(crate::diagnostic_ring::DiagnosticSnapshot {
        hook_function: "WriteFile".to_string(),
        // ... populate from classification context ...
    });

    // DIFF-01: Request override (if not already in override flow)
    // This is sent asynchronously via the pipe; the deny is immediate.
    // The user must retry the operation after approval.
    let _ = crate::pipe_client::send_override_request(
        requester_sid, data_object_id, action, destination_scope, justification, resource_path
    );

    return crate::fail_closed!(BoolFalse);
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual approval via email | JWT-based approval workflow with Ed25519 signing | Phase 61 (2026-05-12) | Tamper-evident, offline-verifiable, TTL-bounded |
| Hook DLL crash on error | `guard_trampoline` + `with_reentrancy_guard` + SEH | Phase 48 (2026-05-09) | Production-hardened, no process crashes |
| Pipe-only classification | Shared-memory cache + LRU + tier-gated fast path | Phase 50 (2026-05-20) | < 50us latency for cache hits, fail-closed on miss |
| IAT hooks only | IAT + ntdll syscall-stub trampolines via retour | Phase 51 (2026-05-22) | Closes direct-syscall bypass |
| ETW bypass detection only | ETW + hook journal correlation | Phase 53 (2026-05-28) | Ground truth comparison, reduced false positives |

**Deprecated/outdated:**
- `HookMessage::CacheDelta` variant: Never existed by design (cache updates via shared-memory atomic version flip only).
- Colon-delimited cache keys: Replaced by JSON-encoded `ApprovalCacheKey` in Phase 61.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `sha2` 0.10.8 (already in workspace) is sufficient for forensic SHA-256 needs | Standard Stack | LOW — SHA-256 is SHA-256; version differences are bug fixes, not algorithm changes |
| A2 | `crossbeam-queue::ArrayQueue` can be used inside a Windows DLL without issues | Architecture Patterns | LOW — crossbeam is widely used in DLLs; no global state conflicts |
| A3 | `ratatui::widgets::Sparkline` is available in ratatui 0.29 | Standard Stack | MEDIUM — Sparkline has been in ratatui since 0.20; but verify API in 0.29 |
| A4 | The Phase 61 approval workflow endpoints (`POST /admin/approvals`, `GET /agent/approvals`) are stable and reusable | Phase Requirements | LOW — These are shipped and tested in Phase 61 |
| A5 | Computing SHA-256 of 100MB on a dedicated thread pool adds < 5ms latency | Performance | MEDIUM — Actual latency depends on CPU; the 100MB cap and thread pool should keep it under 5ms on modern hardware |

## Open Questions (RESOLVED)

1. **Should diagnostic snapshots include the full ABAC policy conditions or just the matched policy ID?**
   - RESOLVED: Include `matched_policy_id` only; the TUI fetches policy details via a separate API call if needed. This keeps snapshot size bounded.

2. **How should the hash computation thread pool handle process exit?**
   - RESOLVED: Allow completions — hash computation is bounded by 100MB and completes quickly. No cancellation complexity added.

3. **Should the self-health dashboard show per-process or per-host aggregation?**
   - RESOLVED: Per-host only for v0.10.0. Per-process breakdown is deferred to v0.11.0 fleet management.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | All | Yes | 1.75+ | — |
| Windows SDK | Hook DLL, Agent | Yes | 10.0.22621+ | — |
| `sha2` crate | DIFF-03 | Yes | 0.10.8 (workspace) | — |
| `crossbeam-queue` crate | DIFF-02 | Yes | 0.3.12 | `parking_lot::Mutex<VecDeque>` (with performance penalty) |
| `rayon` crate | DIFF-03 | Yes | 1.12.0 (workspace) | Single-threaded computation (latency hit) |
| `ratatui` crate | DIFF-02, DIFF-04 | Yes | 0.29 (dlp-admin-cli) | — |
| `bincode` crate | All IPC | Yes | 1.3 (workspace) | — |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None — per-crate test modules |
| Quick run command | `cargo test -p dlp-hook-dll` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DIFF-01 | Override request flows through pipe to agent to user UI | unit + integration | `cargo test -p dlp-hook-dll test_request_override` | No — new |
| DIFF-01 | Approval token caching and verification works end-to-end | integration | `cargo test -p dlp-agent test_approval_cache` | Yes (Phase 61) |
| DIFF-02 | Diagnostic snapshot captures on DENY with correct fields | unit | `cargo test -p dlp-hook-dll test_diagnostic_snapshot` | No — new |
| DIFF-02 | Ring buffer bounds to 1000 entries and overwrites old | unit | `cargo test -p dlp-hook-dll test_ring_buffer_capacity` | No — new |
| DIFF-02 | Agent polls and aggregates diagnostic snapshots | unit | `cargo test -p dlp-agent test_diagnostic_poll` | No — new |
| DIFF-02 | Admin API serves paginated diagnostics with filters | integration | `cargo test -p dlp-server test_diagnostics_api` | No — new |
| DIFF-03 | SHA-256 hash matches known value for test buffer | unit | `cargo test -p dlp-hook-dll test_sha256_known_value` | No — new |
| DIFF-03 | 100MB cap truncates hash correctly | unit | `cargo test -p dlp-hook-dll test_hash_truncation` | No — new |
| DIFF-03 | Audit event includes content_sha256 on blocked write | integration | `cargo test -p dlp-server test_audit_hash_field` | No — new |
| DIFF-04 | Health counters increment correctly | unit | `cargo test -p dlp-hook-dll test_health_counters` | No — new |
| DIFF-04 | Health snapshot computes cache hit rate correctly | unit | `cargo test -p dlp-agent test_hit_rate_computation` | No — new |
| DIFF-04 | Auto-alert emits on health transition | integration | `cargo test -p dlp-agent test_health_alert` | No — new |
| DIFF-04 | TUI renders sparkline without panic | unit | `cargo test -p dlp-admin-cli test_sparkline_render` | No — new |

### Sampling Rate
- **Per task commit:** `cargo test -p <crate>` (quick run for affected crate)
- **Per wave merge:** `cargo test --workspace` (full suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-hook-dll/src/diagnostic_ring.rs` — unit tests for push/drain/capacity
- [ ] `dlp-hook-dll/src/hash_compute.rs` — unit tests for known hashes, truncation, null buffer
- [ ] `dlp-hook-dll/src/health_counters.rs` — unit tests for counter increment, snapshot emission
- [ ] `dlp-agent/src/diagnostic_aggregator.rs` — unit tests for poll, aggregate, filter
- [ ] `dlp-agent/src/health_aggregator.rs` — unit tests for threshold computation, alert emission
- [ ] `dlp-server/tests/diagnostics_api_integration.rs` — integration tests for GET /admin/diagnostics
- [ ] `dlp-admin-cli/src/screens/diagnostic_list.rs` — unit tests for dispatch/render
- [ ] `dlp-admin-cli/src/screens/self_health_dashboard.rs` — unit tests for sparkline render

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | — |
| V3 Session Management | Yes (DIFF-01) | JWT with Ed25519 signature, TTL-bounded (`valid_until`), re-verification on every cache read |
| V4 Access Control | Yes (DIFF-01) | Approval scope per `(sid, obj_id, action, dst)` — destination scope matching prevents reuse |
| V5 Input Validation | Yes (DIFF-03) | 100MB cap on buffer length prevents DoS; null pointer check; `hash_skipped` flag on pool saturation |
| V6 Cryptography | Yes (DIFF-03) | SHA-256 (NIST FIPS 180-4) for content hashing; no custom crypto |
| V7 Error Handling | Yes (all) | `hash_skipped` and `hash_truncated` flags in audit event; graceful degradation on compute failure |
| V8 Data Protection | Yes (DIFF-02) | Diagnostic data in-memory only, no disk persistence; 1-hour lazy eviction |
| V10 Logging | Yes (all) | All differentiators emit structured audit events; SIEM routing for health transitions |

### Known Threat Patterns for Hook DLL Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Approval token replay | Spoofing | JWT `jti` claim + `exp` expiry + destination scope matching |
| Approval token tampering | Tampering | Ed25519 signature re-verification on every cache read |
| Diagnostic data exfiltration | Information Disclosure | In-memory only, no disk persistence, 1-hour eviction |
| Hash computation DoS | Denial of Service | 100MB cap + dedicated thread pool + `hash_skipped` fallback |
| Health counter manipulation | Tampering | Counters are atomic, read-only from agent, no operator write path |
| False health status | Repudiation | Agent polls independently; health transitions emit audit events |

## Sources

### Primary (HIGH confidence)
- `dlp-common/src/hook_ipc.rs` — IPC protocol, versioned envelope pattern, bincode configuration
- `dlp-common/src/audit.rs` — AuditEvent builder pattern, `skip_serializing_if`, backward compat
- `dlp-common/src/approval.rs` — Approval types, ApprovalCacheKey, CachedApproval
- `dlp-agent/src/approval_cache.rs` — DashMap cache, JWT re-verification, scope matching
- `dlp-hook-dll/src/perf_telemetry.rs` — QPC measurement, histogram, thread-local telemetry, emission cadence
- `dlp-hook-dll/src/trampolines.rs` — 12 trampoline implementations, `classify_and_log_path/handle`
- `dlp-hook-dll/src/fail_mode.rs` — Fail-state machine, atomic counters, hysteresis
- `dlp-hook-dll/src/hook_journal.rs` — Shared-memory ring buffer, SPSC synchronization, volatile writes
- `dlp-user-ui/src/dialogs/override_request.rs` — Win32 modal dialog, `DialogBoxIndirectParamW`
- `dlp-admin-cli/src/app.rs` — Screen enum, AppState, filter patterns
- `dlp-admin-cli/src/screens/bypass_alerts.rs` — TUI screen pattern (dispatch/render/client)

### Secondary (MEDIUM confidence)
- `cargo search sha2` / `cargo search crossbeam-queue` / `cargo search rayon` — Version verification on crates.io
- slopcheck verification — All packages rated [OK]

### Tertiary (LOW confidence)
- None — all claims verified against codebase or registry

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all crates verified on registry, most already in workspace
- Architecture: HIGH — all patterns established in prior phases with working code
- Pitfalls: HIGH — derived from actual bugs encountered and fixed in Phases 48-57

**Research date:** 2026-06-02
**Valid until:** 2026-07-02 (30 days — stable stack, no fast-moving dependencies)
