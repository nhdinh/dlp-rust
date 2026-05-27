# Phase 53: ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring - Research

**Researched:** 2026-05-27
**Domain:** Windows ETW Kernel-File telemetry, user-mode hook bypass detection, shared-memory ring buffers, real-time event correlation
**Confidence:** HIGH

## Summary

Phase 53 turns hook-vs-ETW divergence into auditable `BypassAlert` events routed through SIEM and the alert router. It delivers: (1) an ETW Kernel-File consumer via `ferrisetw` 1.2.0 mirroring the existing ProcessWatcher pattern, (2) a per-process shared-memory hook journal ring buffer written by the DLL before returning classification decisions, (3) a bypass correlator that matches ETW events against journal entries within +/-5 ms QPC tolerance, (4) server-side bypass alert storage with admin API endpoints, and (5) SIEM + alert router wiring using existing transport infrastructure.

The hardest technical problem is the correlation algorithm: ETW provides kernel `FILE_OBJECT` pointers and 100ns timestamps, while the hook DLL operates on `HANDLE` values and `QueryPerformanceCounter` timestamps. The solution (per CONTEXT.md D-05) correlates by `(pid, path_hash, op, ts_qpc)` using FNV-1a 64-bit hashing of normalized paths -- the same normalization and hash function used by the classification cache. This avoids expensive `NtQuerySystemInformation(SystemHandleInformation)` lookups while maintaining stable semantic identity across the user/kernel boundary.

**Primary recommendation:** Implement `etw_kernel_file.rs` and `bypass_correlator.rs` in `dlp-agent/src/`, `hook_journal.rs` in `dlp-hook-dll/src/`, extend `BypassReason` in `dlp-common`, and add `bypass_alerts` table + repository + admin API routes in `dlp-server`. All patterns are proven in the codebase.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| ETW Kernel-File consumption | API / Backend (agent service) | -- | ETW consumer runs in agent SYSTEM service; kernel delivers events to user-mode callback |
| Hook journal ring buffer | Browser / Client (hook DLL) | -- | Shared memory created by DLL, read by agent; producer is in-process hook trampoline |
| Bypass correlation | API / Backend (agent service) | -- | Correlator runs in agent; has access to all process journals + ETW event stream |
| Bypass alert storage | API / Backend (dlp-server) | -- | SQLite table, repository, REST endpoints on server |
| SIEM relay / alert routing | API / Backend (dlp-server) | -- | Reuses existing `siem_connector::relay` and `alert_router::send` |
| Admin TUI bypass feed | Browser / Client (admin CLI) | -- | Phase 54 -- polling `GET /admin/bypass-alerts` |

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Hook DLL creates journal shared memory lazily on first hook invocation. Name: `Global\DlpHookJournal_<pid>`.
- **D-02:** Agent discovers journals via ProcessWatcher process creation events. 5-second retry loop for journal open.
- **D-03:** 5-second grace period on process exit before unmapping journal handle.
- **D-04:** Journal layout: 64 KiB total, 48-byte entries, ~1365 entries. Header: `version: u32` + `write_index: u32`. Entry: `JournalEntry { seq: u64, handle_value: u64, op: u8, path_hash: u64, ts_qpc: u64 }`.
- **D-05:** Correlation uses `(pid, path_hash, op, ts_qpc)` as composite key. NOT `file_object`.
- **D-06:** `path_hash` is FNV-1a 64-bit of normalized path. Same normalization as classification cache.
- **D-07:** `op` is compact enum (`Create = 1`, `Write = 2`, `Delete = 3`, `SetInfo = 4`).
- **D-08:** +/-5 ms QPC tolerance. QPC frequency calibrated at startup. ETW 100ns timestamps converted to QPC units.
- **D-09:** Best-effort correlation. False negatives are primary concern.
- **D-10:** Severity mapping: `NoHookJournal` on protected path -> `crit`; `NoHookJournal` elsewhere -> `warn`; `OpMismatch` -> `warn`; `HookOverwritten` -> `crit`; `PatchRaced` -> `info`.
- **D-11:** `crit` severity triggers alert router + SIEM; `warn`/`info` go to SIEM only.
- **D-12:** Agent reads `Global\DlpAllowlistCache` shared memory. Re-reads every 30 seconds.
- **D-13:** Pre-correlation filtering drops allowlisted PIDs. Tracked in `HashSet<u32>` with 60-second TTL.
- **D-14:** Hardcoded emergency filter for `System`, `Registry`, `smss.exe`, `csrss.exe`, `lsass.exe`.
- **D-15:** ETW consumer mirrors ProcessWatcher architecture: dedicated OS thread, `ferrisetw` blocking trace loop, `crossbeam::bounded` channel to tokio task. Buffer config: 256 KB x 200.
- **D-16:** Consumer-side keyword filter: `CREATE | WRITE | DELETE_PATH | OP_END` + `TRACE_LEVEL_INFORMATION`. System32/WinSxS filter in tokio task.
- **D-17:** Lost-event monitoring via `Microsoft-Windows-Kernel-EventTracing/Admin` Event ID 2. Test-time verification only.
- **D-18:** ETW consumer gated by `enable_ntdll_patching` flag. When off, correlator runs in reduced mode (info-only alerts).
- **D-19:** `POST /audit/bypass` accepts batch of max 100 alerts. Agent flushes every 5 seconds or when batch full.
- **D-20:** `GET /admin/bypass-alerts` supports `since`, `severity`, `acknowledged`, `limit` (default 50, max 500), `offset`.
- **D-21:** `POST /admin/bypass-alerts/:id/ack` requires admin JWT. Idempotent.
- **D-22:** `bypass_alerts` table schema matches ARCHITECTURE.md exactly. `image_sha256` nullable, populated lazily.
- **D-23:** Journal write happens BEFORE returning decision in every trampoline.
- **D-24:** Single non-atomic entry write followed by `Release` store of `write_index`. Consumer reads `write_index` with `Acquire`.
- **D-25:** If journal creation fails, hook DLL silently continues without journaling.

### Claude's Discretion
- Lazy journal creation chosen over agent pre-creation to avoid races.
- HANDLE value stored instead of FILE_OBJECT because user-mode cannot access kernel FILE_OBJECT directly.
- Path-hash correlation chosen over FILE_OBJECT correlation because path is the stable semantic identifier.
- Shared-memory allowlist reuse chosen over separate agent allowlist to minimize config drift.
- Batch ingest (100 alerts) chosen over per-alert POST to reduce server load.
- `enable_ntdll_patching` flag reused as ETW consumer gate to simplify operator rollout.
- 5-second grace period on process exit chosen to capture trailing ETW events without handle leaks.

### Deferred Ideas (OUT OF SCOPE)
- Admin TUI Bypass Alerts screen (Phase 54 -- UX-02)
- Admin TUI Protected Paths screen (Phase 54 -- UX-01)
- Monitor-only / audit-only mode awareness in bypass alerts (Phase 55)
- SD/optical/virtual drive volume-class filtering (Phase 56)
- Automatic remediation of bypassed operations
- ML-based false-positive suppression
- Real-time bypass alert streaming via WebSocket

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ETW-01 | Real-time `Microsoft-Windows-Kernel-File` consumer via `ferrisetw` 1.2.0; 256 KB x 200 buffers; CREATE/WRITE/DELETE_PATH/OP_END keywords; TRACE_LEVEL_INFORMATION; consumer-side System32/WinSxS filter | `ferrisetw` 1.2.0 `KernelTrace` + `Provider` with kernel provider GUID `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`; event IDs 12/16/18/30; `FileName` field extraction via `Parser::try_parse`; mirrors `process_watcher.rs` exactly |
| ETW-02 | Hook-DLL journal ring buffer (`Global\DlpHookJournal_<pid>`, 64 KiB shared mapping, SPSC); entry written BEFORE decision so denials are journaled | `CreateFileMappingW` + `MapViewOfFile` pattern from `classification_cache.rs`; `PAGE_READWRITE` for DLL, `FILE_MAP_READ` for agent; `Release`/`Acquire` via `write_index` |
| ETW-03 | Bypass correlator: for each ETW event, lookup `(pid, path_hash, op)` in matching process's journal within +/-5 ms QPC tolerance; absence -> `BypassAlert`; allowlisted PIDs dropped pre-correlation | FNV-1a 64-bit `dlp_common::fnv1a_64()`; path normalization from `classification_cache::normalize_path`; `QueryPerformanceFrequency` calibration; linear scan of ring buffer entries within tolerance window |
| ETW-04 | `bypass_alerts` SQLite table + repository + `POST /audit/bypass` (agent->server batch ingest) + `GET /admin/bypass-alerts` (admin TUI feed) + `POST /admin/bypass-alerts/:id/ack` | Repository pattern from `protected_paths.rs`; admin API CRUD pattern from `admin_api.rs`; JWT auth via `admin_auth` middleware |
| ETW-05 | Bypass alerts route through existing SIEM relay (`siem_connector::relay`) and alert router (`alert_router::send` when `severity >= ALERT`); no new outbound transport | `SiemConnector::relay_events()` accepts `Vec<AuditEvent>`; `AlertRouter::send_alert()` takes `&AuditEvent`; both already support hot-reload config |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `ferrisetw` | 1.2.0 [VERIFIED: cargo registry] | ETW consumer API (`KernelTrace`, `Provider`, `EventRecord`, `SchemaLocator`, `Parser`) | Project standard per ETW-01 spec; already used by `process_watcher.rs` (Phase 49) |
| `crossbeam-channel` | 0.5.15 [VERIFIED: cargo registry] | Bounded channel between ETW thread and tokio task | Already in `dlp-agent/Cargo.toml`; proven in ProcessWatcher |
| `dashmap` | 6.1.0 [VERIFIED: cargo registry] | Lock-free concurrent HashMap for per-PID journal handles + image SHA-256 cache | Already in `dlp-agent/Cargo.toml` (used by `approval_cache.rs`) |
| `windows` | 0.62 [VERIFIED: cargo registry] | Win32 API bindings (`CreateFileMappingW`, `MapViewOfFile`, `OpenFileMappingW`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`) | Already in workspace with required features enabled |
| `thiserror` | workspace | Error type definitions | Project standard |
| `tracing` | workspace | Structured logging | Project standard |
| `serde` | workspace | JSON serialization for bypass alert batch ingest | Project standard |
| `chrono` | 0.4 [VERIFIED: cargo registry] | Timestamp handling for bypass alerts | Already in workspace |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `parking_lot` | 0.12.5 [VERIFIED: cargo registry] | `Mutex`/`RwLock` for journal reader state and allowlist cache access | When std sync primitives are insufficient; already in workspace |
| `retour` | 0.4.0-alpha.4 [VERIFIED: cargo registry] | Already used for ntdll trampolines in Phase 51 | No new dependency |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `ferrisetw` | Raw ETW APIs via `windows::Win32::System::Diagnostics::Etw` | `ferrisetw` provides safe Rust abstractions, `SchemaLocator`, `Parser`. CONTEXT.md D-15 locks `ferrisetw`. |
| `crossbeam-channel` | `tokio::sync::mpsc` | `crossbeam` works across `std::thread` -> tokio boundary without runtime dependency on ETW thread. CONTEXT.md D-15 locks `crossbeam`. |
| Path-hash correlation | FILE_OBJECT correlation via `NtQuerySystemInformation` | FILE_OBJECT resolution is expensive (O(n) handle table walk), complex, and unreliable. Path hash is stable and cheap. CONTEXT.md D-05 locks path-hash. |
| Separate agent allowlist | Reuse shared-memory allowlist | Zero config drift, same source as hook DLL. CONTEXT.md D-12 locks shared-memory reuse. |

**Installation:**
```bash
# All dependencies already present in workspace:
# ferrisetw = "1.2.0"  (in dlp-agent/Cargo.toml)
# crossbeam-channel = "0.5"  (in dlp-agent/Cargo.toml)
# dashmap = "6"  (in dlp-agent/Cargo.toml)
# windows = "0.62"  (in dlp-agent/Cargo.toml)
# parking_lot = "0.12"  (workspace)
# chrono = "0.4"  (workspace)
```

**Version verification:**
- `ferrisetw`: 1.2.0 (current on crates.io, confirmed 2026-05-27)
- `crossbeam-channel`: 0.5.15 (in Cargo.lock, confirmed)
- `dashmap`: 6.1.0 (in Cargo.lock, confirmed)
- `parking_lot`: 0.12.5 (in Cargo.lock, confirmed)
- `windows`: 0.62 (in Cargo.lock, confirmed)

## Package Legitimacy Audit

> slopcheck was unavailable for direct invocation at research time. All packages below were verified via `cargo search` against crates.io registry.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `ferrisetw` | crates.io | 3+ yrs | High | github.com/n4r1b/ferrisetw | N/A (cargo search verified) | Approved |
| `crossbeam-channel` | crates.io | 6+ yrs | Very High | github.com/crossbeam-rs/crossbeam | N/A (cargo search verified) | Approved |
| `dashmap` | crates.io | 5+ yrs | Very High | github.com/xacrimon/dashmap | N/A (cargo search verified) | Approved |
| `parking_lot` | crates.io | 7+ yrs | Very High | github.com/Amanieu/parking_lot | N/A (cargo search verified) | Approved |
| `retour` | crates.io | 4+ yrs | Moderate | github.com/Hpmason/retour-rs | N/A (cargo search verified) | Approved |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

*All packages above are already in the workspace Cargo.lock and have been used in prior phases. No new external dependencies are introduced by Phase 53.*

## Architecture Patterns

### System Architecture Diagram

```
[Process creates/opens/writes/deletes file]
  |
  v
[Hook DLL trampoline (user.exe address space)]
  |-- (1) classify_and_log_path/classify_and_log_handle
  |-- (2) journal_write() -> Global\DlpHookJournal_<pid>
  |       BEFORE returning decision
  |
  v
[ETW Kernel-File Provider (kernel)]
  |-- Event ID 12 (Create), 16 (Write), 18 (Delete), 30 (Rename)
  |-- FileName field, FILE_OBJECT pointer, timestamp (100ns)
  |
  v
[ETW Kernel-File Consumer -- dedicated OS thread]
  |-- ferrisetw blocking trace loop
  |-- Keyword filter: CREATE|WRITE|DELETE_PATH|OP_END
  |-- try_send() to crossbeam channel (bounded, 1024)
  |
  v
crossbeam::channel (bounded, 1024)
  |
  v
[Tokio Task -- Bypass Correlator]
  |-- recv() ETW event
  |-- Pre-filter: allowlisted PID? -> drop
  |-- Normalize FileName -> FNV-1a 64-bit hash
  |-- Map ETW opcode/keyword to op enum
  |-- Convert ETW timestamp to QPC units
  |-- Open/read Global\DlpHookJournal_<pid>
  |-- Search entries where |entry.ts_qpc - event_ts_qpc| <= 5ms_in_qpc
  |-- Match on (path_hash == entry.path_hash AND op == entry.op)
  |-- No match -> construct BypassAlert
  |-- Severity mapping based on reason + protected path check
  |
  +-- Match found, same op -> nothing to do
  +-- Match found, different op -> info alert (OpMismatch)
  +-- No match -> warn/crit alert (NoHookJournal)
  |
  v
[Batch Flush Task]
  |-- Accumulate alerts in Vec (max 100)
  |-- Flush every 5 seconds OR when batch full
  |-- POST /audit/bypass -> dlp-server
  |
  v
[dlp-server]
  |-- bypass_alerts repository INSERT
  |-- siem_connector::relay() (existing pipeline)
  |-- alert_router::send() if severity == crit
  |
  v
[Admin CLI]
  |-- GET /admin/bypass-alerts (poll)
  |-- POST /admin/bypass-alerts/:id/ack
```

### Recommended Project Structure

```
dlp-agent/src/
├── etw_kernel_file.rs      # ETW Kernel-File consumer (mirrors process_watcher.rs)
├── bypass_correlator.rs    # Correlation engine + alert batching + flush task
└── lib.rs                  # add: pub mod etw_kernel_file; pub mod bypass_correlator;

dlp-hook-dll/src/
├── hook_journal.rs         # Shared-memory journal creation + write functions
├── trampolines.rs          # add journal_write() call before returning
└── lib.rs                  # add: mod hook_journal;

dlp-common/src/
├── hook_ipc.rs             # extend BypassReason with NoHookJournal, OpMismatch
└── audit.rs                # add BypassAlertDetected event type

dlp-server/src/
├── db/mod.rs               # add bypass_alerts table to init_tables()
├── db/repositories/
│   └── bypass_alerts.rs    # BypassAlertsRepository (list, insert, ack)
├── admin_api.rs            # add /admin/bypass-alerts routes
├── lib.rs                  # add bypass_alerts to AppState
└── main.rs                 # wire bypass_alerts repository into AppState
```

### Pattern 1: ETW Consumer Thread + Channel (ProcessWatcher Pattern)
**What:** Dedicated OS thread runs `ferrisetw` blocking trace loop. Events pushed through `crossbeam::bounded` to tokio task.
**When to use:** Any ETW consumer in the agent. Already proven for ProcessWatcher.
**Example:**
```rust
// Source: dlp-agent/src/process_watcher.rs (verified in codebase)
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{KernelTrace, LoggingMode, TraceProperties, TraceTrait};
use ferrisetw::EventRecord;

let process_provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
    .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
        if record.event_id() != 1 { return; }
        let parser = ferrisetw::parser::Parser::create(record, &schema);
        let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
        // ... push to channel
    })
    .build();

let props = TraceProperties {
    buffer_size: 256,        // 256 KB
    min_buffer: 200,
    max_buffer: 200,
    flush_timer: Duration::from_secs(1),
    log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE
        | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
};
```

### Pattern 2: Shared-Memory SPSC Ring Buffer
**What:** Single-producer (hook DLL) single-consumer (agent) ring buffer via Windows named file mapping.
**When to use:** Per-process high-throughput event streaming across process boundaries with minimal latency.
**Example:**
```rust
// Source: classification_cache.rs + CONTEXT.md D-24
#[repr(C)]
pub struct JournalHeader {
    pub version: u32,
    pub write_index: u32,  // monotonic, wraps via modulo
}

#[repr(C, align(8))]
pub struct JournalEntry {
    pub seq: u64,
    pub handle_value: u64,
    pub op: u8,
    pub _pad: [u8; 7],
    pub path_hash: u64,
    pub ts_qpc: u64,
}

// Producer (hook DLL):
// 1. Write entry at write_index % capacity
// 2. std::sync::atomic::fence(Ordering::Release)
// 3. Store write_index + 1 with Ordering::Release

// Consumer (agent):
// 1. Load write_index with Ordering::Acquire
// 2. Read entries between last_read_index and write_index
// 3. Update last_read_index
```

### Pattern 3: Repository Pattern for SQLite CRUD
**What:** Stateless struct with associated functions taking `&Pool` or `&UnitOfWork`.
**When to use:** All new database entities in dlp-server.
**Example:**
```rust
// Source: dlp-server/src/db/repositories/protected_paths.rs (verified)
pub struct ProtectedPathsRepository;

impl ProtectedPathsRepository {
    pub fn list_all(pool: &Pool) -> rusqlite::Result<Vec<ProtectedPathRow>> { ... }
    pub fn insert(uow: &UnitOfWork, row: &ProtectedPathRow) -> rusqlite::Result<()> { ... }
    pub fn update(uow: &UnitOfWork, row: &ProtectedPathRow) -> rusqlite::Result<usize> { ... }
    pub fn delete_by_id(uow: &UnitOfWork, id: &str) -> rusqlite::Result<usize> { ... }
}
```

### Anti-Patterns to Avoid
- **FILE_OBJECT-based correlation:** Do NOT attempt to resolve HANDLE to FILE_OBJECT via `NtQuerySystemInformation`. It is O(n) over the system handle table, requires `SYSTEM_INFORMATION_CLASS` structures that vary by Windows version, and is unnecessary when path-hash correlation works. [CITED: CONTEXT.md D-05]
- **Agent pre-creating journals:** Do NOT create journals from the agent on injection. The agent doesn't know when the DLL is loaded or if the process will ever make a hooked I/O call. Lazy creation by the DLL avoids races and wasted memory. [CITED: CONTEXT.md D-01]
- **Blocking ETW callback:** Do NOT perform correlation work inside the ETW callback. The callback runs on the ETW consumer thread; any blocking operation stalls event delivery and can cause buffer overflow / event loss. [CITED: process_watcher.rs review fix]
- **Per-alert HTTP POST:** Do NOT send one HTTP request per bypass alert. At high event rates this will overwhelm the server and network. Batch to 100 alerts with 5-second flush. [CITED: CONTEXT.md D-19]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| ETW event parsing | Raw ETW API structs | `ferrisetw::Parser::try_parse` | `SchemaLocator` + `Parser` handle schema resolution, field extraction, and type conversion safely |
| Cross-thread channel | `std::sync::mpsc` | `crossbeam::bounded` | `crossbeam` is faster, supports bounded backpressure, and works across std::thread/tokio boundaries |
| Concurrent PID map | `std::sync::Mutex<HashMap>` | `DashMap<u32, JournalHandle>` | Lock-free reads/writes; already used by approval_cache.rs |
| Image SHA-256 caching | Re-hash on every alert | `DashMap<String, String>` cache | SHA-256 of executable is expensive; cache path->hash with TTL |
| QPC frequency calibration | Re-read on every event | Read once at startup, store as `i64` | `QueryPerformanceFrequency` is constant for system lifetime |
| Path normalization | Custom string manipulation | Reuse `classification_cache::normalize_path` | Same normalization guarantees hash consistency between DLL and correlator |

**Key insight:** The classification cache already solved the hard problems (path normalization, FNV-1a hashing, shared-memory layout). Reuse those solutions rather than building parallel implementations that could drift.

## Runtime State Inventory

This phase does NOT involve rename/refactor/migration. It is a greenfield addition of new components. No runtime state inventory required.

## Common Pitfalls

### Pitfall 1: ETW Event Loss Under Load
**What goes wrong:** At high file-I/O rates (>10,000 events/sec), the ETW buffer fills faster than the consumer thread drains it. Events are dropped silently.
**Why it happens:** Default buffer sizes are too small, or the tokio task is CPU-starved and cannot keep up with the crossbeam channel.
**How to avoid:** Use 256 KB x 200 buffers (52 MB total) as specified. Monitor `Microsoft-Windows-Kernel-EventTracing/Admin` Event ID 2 for lost events. If lost events detected during stress testing, increase buffer count or size. The correlator tokio task should be spawned on a dedicated thread if CPU contention is observed.
**Warning signs:** `overflow_count` increasing on ProcessWatcher; `warn!` logs about channel full; stress test shows fewer ETW events than expected file operations.

### Pitfall 2: QPC Timestamp Skew Between User and Kernel
**What goes wrong:** ETW timestamps are in 100ns units from a different clock source than `QueryPerformanceCounter`. The conversion factor may drift slightly, causing correlation misses at the edge of the 5ms window.
**Why it happens:** ETW uses the system performance counter but may have a different epoch or scaling factor than the user-mode QPC.
**How to avoid:** Calibrate by reading both ETW timestamp and QPC simultaneously at startup. Compute `qpc_freq` once. Convert ETW timestamps using `etw_ts_qpc = etw_timestamp * qpc_freq / 10_000_000`. The 5ms tolerance window absorbs minor drift.
**Warning signs:** Correlation rate drops below 95% during stress test; alerts spike for operations that should have been journaled.

### Pitfall 3: PID Reuse Causing False Correlations
**What goes wrong:** A process exits, its PID is reused by a new process, and the agent still has the old journal mapped. ETW events from the new process are correlated against the old journal.
**Why it happens:** Windows reuses PIDs aggressively. The agent's 5-second grace period may overlap with PID reuse.
**How to avoid:** Store `creation_time` from ProcessWatcher alongside the journal handle. On each correlation, verify the process creation time matches. If mismatch, close the old journal and attempt to open the new one. The `ProcessEvent` from ProcessWatcher includes `creation_time`.
**Warning signs:** Correlation matches for operations that the new process never performed; alerts for paths the new process never touched.

### Pitfall 4: Journal Memory Leak on Process Exit
**What goes wrong:** The agent never unmaps journal handles, leaking memory and file mapping objects.
**Why it happens:** Process exit detection (via ProcessWatcher heartbeat timeout) may miss short-lived processes. The grace period may never trigger.
**How to avoid:** Implement a periodic sweep (every 60 seconds) that calls `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` on all tracked PIDs. If `OpenProcess` fails with ERROR_INVALID_PARAMETER, the PID is dead -- unmap the journal and remove from tracking. This is the same pattern used by ProcessWatcher's cleanup sweep.
**Warning signs:** Handle count in agent process grows monotonically; memory usage increases over time.

### Pitfall 5: Path Normalization Mismatch Between DLL and Correlator
**What goes wrong:** The hook DLL normalizes paths one way, the correlator normalizes them differently. The FNV-1a hashes don't match, causing false bypass alerts.
**Why it happens:** The correlator might not strip NT prefixes, handle UNC paths, or apply case-folding identically to the DLL.
**How to avoid:** Extract `normalize_path` from `classification_cache.rs` into `dlp-common` as a shared function. Both DLL and correlator call the same function. The function is already well-tested with 20+ test cases covering NT prefixes, UNC, ADS, volume GUIDs, 8.3 names, etc.
**Warning signs:** 100% bypass alert rate for certain paths; hash mismatch between DLL log and correlator log.

### Pitfall 6: Allowlist Cache Stale After Config Update
**What goes wrong:** The agent's allowlist cache is stale because it only re-reads every 30 seconds. A newly allowlisted process still generates bypass alerts.
**Why it happens:** The shared-memory allowlist is updated by the agent's config poll loop, but the correlator's in-memory `HashSet<u32>` of allowlisted PIDs is only refreshed every 30 seconds.
**How to avoid:** The 30-second refresh is acceptable -- bypass alerts for allowlisted processes are low-severity and self-resolving. Document this behavior. Do NOT add a notification mechanism; the complexity outweighs the benefit for a defense-in-depth layer.
**Warning signs:** Brief spike of bypass alerts for allowlisted processes after config change; alerts stop after 30 seconds.

## Code Examples

### ETW Kernel-File Event Parsing
```rust
// Source: ProcessWatcher pattern + ferrisetw 1.2.0 docs
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::EventRecord;

// Microsoft-Windows-Kernel-File provider GUID
const KERNEL_FILE_PROVIDER: &str = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}";

fn parse_kernel_file_event(record: &EventRecord, schema_locator: &SchemaLocator) -> Option<EtwFileEvent> {
    // Event IDs we care about: 12=Create, 16=Write, 18=Delete, 30=Rename
    let event_id = record.event_id();
    if ![12u16, 16, 18, 30].contains(&event_id) {
        return None;
    }
    
    let schema = schema_locator.event_schema(record).ok()?;
    let parser = ferrisetw::parser::Parser::create(record, &schema);
    
    let pid: u32 = parser.try_parse("ProcessId").unwrap_or(0);
    let file_name: String = parser.try_parse("FileName").unwrap_or_default();
    let file_object: u64 = parser.try_parse("FileObject").unwrap_or(0);
    let timestamp: u64 = record.timestamp(); // 100ns units
    
    let op = match event_id {
        12 => FileOp::Create,
        16 => FileOp::Write,
        18 => FileOp::Delete,
        30 => FileOp::SetInfo, // Rename
        _ => return None,
    };
    
    Some(EtwFileEvent { pid, file_name, file_object, timestamp, op })
}
```

### Journal Write in Hook DLL
```rust
// Source: CONTEXT.md D-23 + D-24 + classification_cache.rs patterns
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

static JOURNAL: OnceLock<Option<HookJournal>> = OnceLock::new();

pub fn journal_write(handle_value: u64, op: FileOp, path: &str, ts_qpc: u64) {
    let journal = match JOURNAL.get_or_init(|| unsafe { HookJournal::try_init() }) {
        Some(j) => j,
        None => return, // D-25: silent continue on failure
    };
    
    let path_hash = dlp_common::fnv1a_64(path.as_bytes());
    let op_byte = op as u8;
    
    // Write entry
    let write_index = journal.header.write_index.load(Ordering::Relaxed);
    let capacity = journal.capacity;
    let entry = &journal.entries[write_index as usize % capacity];
    
    // SAFETY: SPSC -- only producer writes here
    unsafe {
        std::ptr::write_volatile(&entry.seq, journal.next_seq);
        std::ptr::write_volatile(&entry.handle_value, handle_value);
        std::ptr::write_volatile(&entry.op, op_byte);
        std::ptr::write_volatile(&entry.path_hash, path_hash);
        std::ptr::write_volatile(&entry.ts_qpc, ts_qpc);
    }
    
    journal.next_seq += 1;
    // Release store publishes the entry to the consumer
    journal.header.write_index.store(write_index.wrapping_add(1), Ordering::Release);
}
```

### Bypass Correlator Core Loop
```rust
// Source: CONTEXT.md D-08 + D-09
pub fn correlate_etw_event(
    &self,
    event: &EtwFileEvent,
    journals: &DashMap<u32, JournalReader>,
) -> Option<BypassAlert> {
    // Pre-filter: allowlisted PID
    if self.is_allowlisted(event.pid) {
        return None;
    }
    
    // Normalize path and compute hash
    let normalized = normalize_path(&event.file_name)?;
    let path_hash = dlp_common::fnv1a_64(normalized.as_bytes());
    let op = FileOp::from_etw(event.event_id);
    
    // Convert ETW timestamp to QPC units
    let event_ts_qpc = event.timestamp * self.qpc_freq / 10_000_000;
    let tolerance_qpc = 5_000_000i64 * self.qpc_freq / 1_000_000_000; // 5ms in QPC
    
    // Lookup journal for this PID
    let reader = journals.get(&event.pid)?;
    
    // Search entries within tolerance window
    let match_result = reader.search(|entry| {
        let ts_diff = if entry.ts_qpc > event_ts_qpc {
            entry.ts_qpc - event_ts_qpc
        } else {
            event_ts_qpc - entry.ts_qpc
        };
        if ts_diff > tolerance_qpc as u64 {
            return false;
        }
        entry.path_hash == path_hash && entry.op == op as u8
    });
    
    match match_result {
        Some(entry) if entry.op == op as u8 => None, // Matched -- no bypass
        Some(_) => Some(BypassAlert::new(
            event.pid,
            BypassReason::OpMismatch,
            // ...
        )),
        None => Some(BypassAlert::new(
            event.pid,
            BypassReason::NoHookJournal,
            // ...
        )),
    }
}
```

### Bypass Alert Batch Ingest (Server)
```rust
// Source: admin_api.rs pattern + siem_connector.rs pattern
async fn bypass_batch_handler(
    State(state): State<Arc<AppState>>,
    Json(batch): Json<BypassAlertBatch>,
) -> Result<StatusCode, AppError> {
    // Validate agent_id matches JWT claim
    // ...
    
    for alert in batch.alerts {
        // Insert into bypass_alerts table
        BypassAlertsRepository::insert(&state.pool, &alert)?;
        
        // Route to SIEM
        let audit_event = alert.to_audit_event();
        state.siem.relay_event(&audit_event).await.ok(); // best-effort
        
        // Route to alert router if crit
        if alert.severity == Severity::Crit {
            state.alert.send_alert(&audit_event).await.ok(); // best-effort
        }
    }
    
    Ok(StatusCode::OK)
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Raw ETW Win32 API | `ferrisetw` safe Rust wrapper | Phase 49 (2026-05-19) | Eliminates unsafe ETW struct parsing; schema auto-resolution |
| Per-process named pipe for cache | Shared-memory classification cache | Phase 50 (2026-05-20) | Sub-50us lookups; eliminates pipe storm |
| IAT patching only | IAT + ntdll syscall-stub trampolines | Phase 51 (2026-05-22) | Closes direct-syscall bypass |
| No bypass detection | ETW Kernel-File + hook journal correlation | Phase 53 (now) | Defense-in-depth: detects what hooks miss |

**Deprecated/outdated:**
- FILE_OBJECT-based correlation: Rejected in favor of path-hash correlation (D-05). FILE_OBJECT resolution is too expensive and unreliable in user mode.
- Agent pre-creating journals: Rejected in favor of DLL lazy creation (D-01). Avoids injection-time races.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `ferrisetw` 1.2.0 supports `Microsoft-Windows-Kernel-File` provider with event IDs 12/16/18/30 and `FileName` field extraction | Standard Stack | If unsupported, would need raw ETW API fallback; HIGH impact but LOW risk (ferrisetw is a general ETW wrapper) |
| A2 | ETW `FileName` field contains the full normalized NT path (e.g., `\Device\HarddiskVolume1\Windows\System32\file.txt`) | Correlation Key | If ETW provides DOS paths or partial paths, normalization must handle additional cases; MEDIUM risk |
| A3 | `QueryPerformanceCounter` and ETW timestamps are monotonic and derived from the same hardware counter on modern Windows | QPC Calibration | If different sources, the conversion factor approach fails; LOW risk (both use HPET/tsc on Win10+) |
| A4 | A 64 KiB ring buffer (~1365 entries) is sufficient for 5ms of I/O at peak rates | Journal Sizing | If insufficient, entries will be overwritten before correlation; MEDIUM risk -- can increase size if stress test shows loss |
| A5 | The `windows` crate `CreateFileMappingW`/`MapViewOfFile` APIs are sufficient for cross-architecture (x64 agent, x86 DLL) shared memory | Shared Memory | If not, would need architecture-specific layout padding; LOW risk (both use same `repr(C)` layout) |

## Open Questions

1. **ETW FileName field format on different Windows versions**
   - What we know: ETW Kernel-File provides `FileName` as a string. On Win10+ it is typically an NT path.
   - What's unclear: Whether Win11 24H2 or Server 2025 changes the format.
   - Recommendation: Implement normalization to handle both NT paths (`\Device\HarddiskVolume1\...`) and DOS paths (`C:\...`). The existing `normalize_path` function already strips NT prefixes.

2. **Stress test fixture for 10,000 events/sec**
   - What we know: The project has integration test patterns (e.g., `ntdll_chaos_test.rs` with 1000 threads).
   - What's unclear: Whether a pure Rust stress test can generate 10,000 file I/O ops/sec without being CPU-bound itself.
   - Recommendation: Use `rayon` parallel file creation in a temp directory. Measure correlation rate and alert volume. Mark test `#[ignore]` for manual execution.

3. **Lost-event monitoring during stress test**
   - What we know: `Microsoft-Windows-Kernel-EventTracing/Admin` Event ID 2 signals lost events.
   - What's unclear: Whether `ferrisetw` exposes this provider or if a separate trace session is needed.
   - Recommendation: Research `ferrisetw` provider registration for `Microsoft-Windows-Kernel-EventTracing`. If not supported, document manual verification procedure using `logman` or `xperf`.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows 10/11 | ETW Kernel-File provider | Yes (dev host) | 11 24H2 | -- |
| `SeSystemProfilePrivilege` | ETW real-time trace | Yes (agent runs as SYSTEM) | -- | -- |
| `ferrisetw` 1.2.0 | ETW consumer | Yes (in Cargo.toml) | 1.2.0 | Raw ETW APIs (high complexity) |
| `crossbeam-channel` | ETW->tokio event flow | Yes (in Cargo.toml) | 0.5.15 | `tokio::sync::mpsc` (requires runtime on ETW thread) |
| `dashmap` | Concurrent PID tracking | Yes (in Cargo.toml) | 6.1.0 | `parking_lot::RwLock<HashMap>` |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None -- inline `#[cfg(test)]` modules |
| Quick run command | `cargo test -p dlp-agent etw_kernel_file` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ETW-01 | ETW consumer starts, parses Event ID 12/16/18/30, extracts FileName | unit | `cargo test -p dlp-agent etw_kernel_file::tests::parse_events` | No -- Wave 0 |
| ETW-01 | Buffer config 256KBx200, no lost events at 10K evt/sec | integration (#[ignore]) | `cargo test -p dlp-agent --features integration-tests etw_stress` | No -- Wave 0 |
| ETW-02 | Journal creation, write, read roundtrip | unit | `cargo test -p dlp-hook-dll hook_journal::tests::roundtrip` | No -- Wave 0 |
| ETW-02 | SPSC correctness: no torn reads, no data races | unit | `cargo test -p dlp-hook-dll hook_journal::tests::spsc_correctness` | No -- Wave 0 |
| ETW-03 | Correlation match: same pid/path/op within 5ms -> no alert | unit | `cargo test -p dlp-agent bypass_correlator::tests::correlation_match` | No -- Wave 0 |
| ETW-03 | Correlation miss: no journal entry -> bypass alert | unit | `cargo test -p dlp-agent bypass_correlator::tests::correlation_miss` | No -- Wave 0 |
| ETW-03 | Allowlist pre-filter: allowlisted PID -> no alert | unit | `cargo test -p dlp-agent bypass_correlator::tests::allowlist_filter` | No -- Wave 0 |
| ETW-04 | bypass_alerts table schema, insert, list, ack | unit | `cargo test -p dlp-server bypass_alerts_repository` | No -- Wave 0 |
| ETW-04 | POST /audit/bypass batch ingest, agent_id validation | integration | `cargo test -p dlp-server bypass_batch_ingest` | No -- Wave 0 |
| ETW-04 | GET /admin/bypass-alerts pagination, filtering | integration | `cargo test -p dlp-server bypass_alerts_query` | No -- Wave 0 |
| ETW-05 | crit severity -> alert_router::send called | unit | `cargo test -p dlp-server bypass_alert_routing` | No -- Wave 0 |
| ETW-05 | warn severity -> SIEM relay only, no alert router | unit | `cargo test -p dlp-server bypass_siem_only` | No -- Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-agent -p dlp-hook-dll -p dlp-server --lib`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-agent/src/etw_kernel_file.rs` -- ETW consumer module
- [ ] `dlp-agent/src/bypass_correlator.rs` -- Correlation engine
- [ ] `dlp-hook-dll/src/hook_journal.rs` -- Journal ring buffer
- [ ] `dlp-common/src/hook_ipc.rs` -- Extend BypassReason
- [ ] `dlp-common/src/audit.rs` -- Add BypassAlertDetected event type
- [ ] `dlp-server/src/db/repositories/bypass_alerts.rs` -- Repository
- [ ] `dlp-server/src/admin_api.rs` -- Add /admin/bypass-alerts routes
- [ ] `dlp-server/src/db/mod.rs` -- Add bypass_alerts table

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | -- |
| V3 Session Management | No | -- |
| V4 Access Control | Yes | JWT auth on admin endpoints; agent_id validation on POST /audit/bypass |
| V5 Input Validation | Yes | Path normalization rejects ADS, volume GUIDs, 8.3 names; batch size capped at 100 |
| V6 Cryptography | No | -- |
| V7 Error Handling | Yes | Silent continue on journal creation failure (D-25); no sensitive data in bypass alerts |
| V8 Data Protection | Yes | `image_sha256` is metadata only; no file content in alerts |
| V10 Malicious Code | Yes | ETW consumer runs as SYSTEM; hook journal is writeable only by DLL in target process |

### Known Threat Patterns for ETW Bypass Detection Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Attacker unloads hook DLL to evade journaling | Tampering | ETW Kernel-File still sees the I/O; correlator emits NoHookJournal alert |
| Attacker patches ntdll directly (bypassing our trampoline) | Tampering | ETW Kernel-File sees the syscall; correlator detects missing journal entry |
| Attacker floods ETW with benign I/O to hide malicious I/O | Denial of Service | Batch ingest + SQLite backpressure; alert router rate limiting |
| Attacker injects fake bypass alerts via POST /audit/bypass | Spoofing | Agent JWT validation + agent_id claim verification |
| Agent process killed to stop correlation | Denial of Service | DACL tripwire (Phase 52) still protects T3/T4 paths at NTFS level |
| Journal shared memory tampered by target process | Tampering | Agent opens with FILE_MAP_READ only; DLL writes with PAGE_READWRITE |

## Sources

### Primary (HIGH confidence)
- `dlp-agent/src/process_watcher.rs` -- Complete `ferrisetw` 1.2.0 ETW consumer with crossbeam channel, bounded queue, overflow handling, heartbeat health. Verified by direct read.
- `dlp-common/src/hook_ipc.rs` -- `BypassAlert` struct, `BypassReason` enum (Phase 51). Verified by direct read.
- `dlp-server/src/alert_router.rs` -- `send_alert` pattern with SMTP + webhook. Verified by direct read.
- `dlp-server/src/admin_api.rs` -- Admin API CRUD route pattern. Verified by direct read.
- `dlp-server/src/db/mod.rs` -- `init_tables()` and `run_migrations()` patterns. Verified by direct read.
- `dlp-server/src/db/repositories/protected_paths.rs` -- Repository pattern for reference. Verified by direct read.
- `dlp-hook-dll/src/classification_cache.rs` -- Shared-memory creation pattern, path normalization, FNV-1a hashing. Verified by direct read.
- `dlp-hook-dll/src/trampolines.rs` -- File-I/O trampoline bodies. Verified by direct read.
- `dlp-server/src/siem_connector.rs` -- `relay_events` pattern. Verified by direct read.
- `dlp-common/src/hash.rs` -- `fnv1a_64` implementation. Verified by direct read.
- `.planning/research/ARCHITECTURE.md` -- Bypass correlator architecture, bypass_alerts table schema, ETW consumer design. Verified by direct read.
- `.planning/phases/53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring/53-CONTEXT.md` -- All locked decisions D-01 through D-25. Verified by direct read.

### Secondary (MEDIUM confidence)
- `ferrisetw` 1.2.0 crates.io documentation -- General ETW consumer API patterns. Verified via `cargo search`.
- Microsoft Learn -- ETW Kernel-File provider event IDs and field definitions. [CITED: docs.microsoft.com/windows/win32/etw/kernel-file]

### Tertiary (LOW confidence)
- Windows Internals 7th Ed -- ETW buffer management and event loss semantics. Training data reference; not verified in this session.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all libraries already in workspace, proven in prior phases
- Architecture: HIGH -- all patterns exist in codebase (ProcessWatcher, classification cache, repository pattern, admin API)
- Pitfalls: MEDIUM-HIGH -- based on codebase review and Windows ETW operational experience; some edge cases (QPC skew, PID reuse) require empirical validation

**Research date:** 2026-05-27
**Valid until:** 2026-06-27 (30 days for stable stack)

---

## RESEARCH COMPLETE

**Phase:** 53 - ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring
**Confidence:** HIGH

### Key Findings
1. All required libraries (`ferrisetw`, `crossbeam-channel`, `dashmap`, `windows`) are already in the workspace and proven in prior phases (49, 50, 51).
2. The ProcessWatcher pattern (`dlp-agent/src/process_watcher.rs`) is a complete, working template for the ETW Kernel-File consumer -- same thread + channel + tokio task architecture, same buffer config (256 KB x 200).
3. The classification cache (`dlp-hook-dll/src/classification_cache.rs`) provides reusable path normalization and FNV-1a 64-bit hashing -- the correlator must use the exact same functions to ensure hash consistency.
4. The repository pattern (`protected_paths.rs`) and admin API pattern (`admin_api.rs`) provide complete templates for the server-side bypass alert storage and endpoints.
5. The SIEM connector and alert router already accept `AuditEvent` and support hot-reload config -- no new transport infrastructure is needed.

### File Created
`.planning/phases/53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring/53-RESEARCH.md`

### Confidence Assessment
| Area | Level | Reason |
|------|-------|--------|
| Standard Stack | HIGH | All libraries already in workspace, verified via cargo search |
| Architecture | HIGH | All patterns proven in codebase (ProcessWatcher, cache, repo, API) |
| Pitfalls | MEDIUM-HIGH | Based on codebase + Windows ETW experience; QPC skew and PID reuse need empirical validation |

### Open Questions
1. ETW `FileName` field format consistency across Windows versions -- handle both NT and DOS paths in normalization.
2. Stress test fixture design for 10,000 events/sec -- use `rayon` parallel file I/O, mark `#[ignore]`.
3. `ferrisetw` support for `Microsoft-Windows-Kernel-EventTracing/Admin` lost-event provider -- may need manual `logman` verification.

### Ready for Planning
Research complete. Planner can now create PLAN.md files. The hardest technical problem (correlation by path-hash across user/kernel boundary) has a proven solution: reuse the classification cache's normalization and FNV-1a hashing, with QPC frequency calibration for timestamp alignment.
